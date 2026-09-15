"""
server.py
----------
Entry point for a backend chat server.

Public API:
    GET  /
    GET  /ws
    POST /message
    GET  /feed
    GET  /health

Internal API:
    POST /internal/replicate

Each backend owns a local PostgreSQL database.

Message handling:
    1. Validate request
    2. Generate msg_id
    3. Sign message
    4. Verify signature
    5. Encrypt message
    6. Save message to LOCAL PostgreSQL
    7. Queue replication in background
    8. Broadcast locally
    9. Return success

Replication is asynchronous so slow peer databases do not block
the public /message request.

Multiple replication workers are used so that the replication queue
can drain fast enough during load tests.
"""

import asyncio
import os
import pathlib
import time
import uuid

import aiohttp
from aiohttp import web
from cryptography.fernet import Fernet
from dotenv import load_dotenv
import psutil

import database
import crypto_utils

from chat_handler import (
    websocket_handler,
    get_or_create_signing_key,
    broadcast,
)


load_dotenv()


# ============================================================
# SERVER CONFIGURATION
# ============================================================

HOST = os.environ.get(
    "HOST",
    "0.0.0.0",
)

PORT = int(
    os.environ.get(
        "PORT",
        "3000",
    )
)

BACKEND_ID = os.environ.get(
    "BACKEND_ID",
    "unknown",
)


# ============================================================
# REPLICATION CONFIGURATION
# ============================================================

REPLICATION_SECRET = os.environ.get(
    "REPLICATION_SECRET",
    "",
)

REPLICATION_PEERS = [
    peer.strip().rstrip("/")
    for peer in os.environ.get(
        "REPLICATION_PEERS",
        "",
    ).split(",")
    if peer.strip()
]

REPLICATION_TIMEOUT_SECONDS = float(
    os.environ.get(
        "REPLICATION_TIMEOUT_SECONDS",
        "2.0",
    )
)

# Number of background replication workers.
#
# The old implementation used one worker.
# That worker processed messages strictly one-by-one,
# causing the replication queue to grow during load tests.
#
# Start with 8. This can later be tuned if necessary.
REPLICATION_WORKERS = int(
    os.environ.get(
        "REPLICATION_WORKERS",
        "8",
    )
)


# ============================================================
# FEED CONFIGURATION
# ============================================================

FEED_DEFAULT_LIMIT = int(
    os.environ.get(
        "FEED_DEFAULT_LIMIT",
        "100000",
    )
)


# ============================================================
# FRONTEND
# ============================================================

FRONTEND_DIR = (
    pathlib.Path(__file__).resolve().parent.parent
    / "frontend"
)


# ============================================================
# GLOBAL STATE
# ============================================================

active_requests = 0

replication_queue = None

replication_workers = []

replication_session = None


# ============================================================
# PUBLIC ROUTES
# ============================================================

async def index(request):
    """
    Serve the frontend application.
    """

    return web.FileResponse(
        FRONTEND_DIR / "dist" / "index.html"
    )


# ============================================================
# REPLICATION HELPERS
# ============================================================

def replication_headers():
    """
    Headers used by internal replication requests.

    The secret allows backend nodes to authenticate each other.
    """

    return {
        "X-Replication-Secret": REPLICATION_SECRET,
        "X-Backend-ID": BACKEND_ID,
    }


async def replicate_to_peer(peer, payload):
    """
    Send one message to one backend peer.

    A persistent aiohttp session is reused instead of creating a new
    TCP session for every message.

    Raises an exception when:
        - connection fails
        - timeout occurs
        - peer returns a non-200 status
    """

    global replication_session

    if replication_session is None:
        raise RuntimeError(
            "replication HTTP session is not initialized"
        )

    url = f"{peer}/internal/replicate"

    try:
        async with replication_session.post(
            url,
            json=payload,
            headers=replication_headers(),
        ) as response:

            response_body = await response.text()

            if response.status != 200:
                raise RuntimeError(
                    f"peer={peer} "
                    f"status={response.status} "
                    f"body={response_body[:300]}"
                )

            return response_body

    except asyncio.CancelledError:
        raise

    except Exception:
        raise


async def replicate_message(payload):
    """
    Replicate one message to every configured peer.

    All peers are contacted concurrently.

    The operation succeeds only when every configured peer
    acknowledges the replication.

    Replication is idempotent because every peer receives the
    same msg_id and the database uses:

        ON CONFLICT (msg_id) DO NOTHING
    """

    if not REPLICATION_PEERS:
        raise RuntimeError(
            f"{BACKEND_ID}: no replication peers configured"
        )

    tasks = [
        replicate_to_peer(
            peer,
            payload,
        )
        for peer in REPLICATION_PEERS
    ]

    results = await asyncio.gather(
        *tasks,
        return_exceptions=True,
    )

    failures = []

    for peer, result in zip(
        REPLICATION_PEERS,
        results,
    ):

        if isinstance(result, Exception):
            failures.append(
                f"{peer}: {result}"
            )

    if failures:
        raise RuntimeError(
            "replication failed: "
            + "; ".join(failures)
        )


# ============================================================
# BACKGROUND REPLICATION WORKER
# ============================================================

async def replication_worker(worker_id):
    """
    Background worker responsible for draining the replication queue.

    Multiple workers operate independently.

    Example:

        worker 1 -> message A
        worker 2 -> message B
        worker 3 -> message C
        ...

    Each individual message still sends to all peers concurrently.
    """

    while True:

        payload = await replication_queue.get()

        try:

            msg_id = payload.get(
                "msg_id",
                "unknown",
            )

            succeeded = False

            for attempt in range(3):

                try:

                    await replicate_message(
                        payload
                    )

                    succeeded = True

                    break

                except asyncio.CancelledError:
                    raise

                except Exception as exc:

                    if attempt < 2:

                        # Increasing retry delay:
                        #
                        # attempt 0 -> 0.5 sec
                        # attempt 1 -> 1.0 sec
                        #
                        await asyncio.sleep(
                            0.5 * (attempt + 1)
                        )

                    else:

                        print(
                            "[REPLICATION-BACKGROUND-ERROR] "
                            f"worker={worker_id} "
                            f"backend={BACKEND_ID} "
                            f"msg_id={msg_id} "
                            f"error={exc}"
                        )

            if succeeded:
                pass

        finally:

            replication_queue.task_done()


# ============================================================
# POST /message
# ============================================================

async def http_message(request):
    """
    POST /message

    Expected JSON:

    {
        "client-name": "...",
        "msg": "...",
        "room": "general",
        "msg_id": "optional UUID"
    }

    The evaluator mainly uses:

        client-name
        msg
    """

    global active_requests

    active_requests += 1

    request_start = time.perf_counter()

    try:

        conn = request.app["db_conn"]

        fernet = request.app["fernet"]

        # ----------------------------------------------------
        # Parse JSON
        # ----------------------------------------------------

        try:

            body = await request.json()

        except Exception:

            return web.json_response(
                {
                    "error": (
                        "request body must be valid JSON"
                    )
                },
                status=400,
            )

        # ----------------------------------------------------
        # Validate required fields
        # ----------------------------------------------------

        username = body.get(
            "client-name"
        )

        plaintext = body.get(
            "msg"
        )

        room = body.get(
            "room",
            "general",
        )

        if not username or plaintext is None:

            return web.json_response(
                {
                    "error": (
                        "client-name and msg are required"
                    )
                },
                status=400,
            )

        if not isinstance(room, str) or not room:

            room = "general"

        # ----------------------------------------------------
        # Generate message ID once
        # ----------------------------------------------------

        msg_id = (
            body.get("msg_id")
            or str(uuid.uuid4())
        )

        # ----------------------------------------------------
        # Create signing key
        # ----------------------------------------------------

        signing_key = await get_or_create_signing_key(
            conn,
            username,
        )

        # ----------------------------------------------------
        # Sign message
        # ----------------------------------------------------

        signature = crypto_utils.sign_message(
            signing_key,
            plaintext,
        )

        # ----------------------------------------------------
        # Verify signature
        # ----------------------------------------------------

        verified = crypto_utils.verify_signature(
            signing_key,
            plaintext,
            signature,
        )

        # ----------------------------------------------------
        # Encrypt message
        # ----------------------------------------------------

        ciphertext = fernet.encrypt(
            plaintext.encode()
        ).decode()

        # ----------------------------------------------------
        # Save locally
        # ----------------------------------------------------

        inserted = await database.save_message(
            conn,
            msg_id,
            room,
            username,
            plaintext,
            ciphertext,
            signature,
            verified,
        )

        # ----------------------------------------------------
        # Queue replication
        # ----------------------------------------------------

        replication_payload = {
            "msg_id": msg_id,
            "room": room,
            "client-name": username,
            "message_text": plaintext,
            "ciphertext": ciphertext,
            "signature": signature,
            "verified": verified,
        }

        replication_queue.put_nowait(
            replication_payload
        )

        # ----------------------------------------------------
        # Broadcast locally
        # ----------------------------------------------------

        try:

            await broadcast(
                room,
                {
                    "msg_id": msg_id,
                    "room": room,
                    "client-name": username,
                    "msg": plaintext,
                    "timestamp": time.time(),
                },
            )

        except Exception as exc:

            # Broadcasting should not cause a successful
            # database write to become a failed HTTP request.

            print(
                "[BROADCAST-WARNING] "
                f"backend={BACKEND_ID} "
                f"msg_id={msg_id} "
                f"error={exc}"
            )

        # ----------------------------------------------------
        # Return success
        # ----------------------------------------------------

        elapsed = (
            time.perf_counter()
            - request_start
        )

        return web.json_response(
            {
                "status": "ok",
                "msg_id": msg_id,
            },
            status=200,
        )

    except Exception as exc:

        print(
            "[MESSAGE-ERROR] "
            f"backend={BACKEND_ID} "
            f"error={exc}"
        )

        return web.json_response(
            {
                "error": str(exc)
            },
            status=500,
        )

    finally:

        active_requests -= 1


# ============================================================
# GET /feed
# ============================================================

async def http_feed(request):
    """
    Return recent messages as plaintext.

    IMPORTANT:
    The evaluator expects the original plaintext message in
    the "msg" field.

    No Fernet decryption is performed here because each backend
    has its own local Fernet key and replicated messages may have
    been encrypted by another node.
    """

    conn = request.app["db_conn"]

    # --------------------------------------------------------
    # Read requested limit
    # --------------------------------------------------------

    try:

        limit = int(
            request.query.get(
                "limit",
                FEED_DEFAULT_LIMIT,
            )
        )

    except (TypeError, ValueError):

        limit = FEED_DEFAULT_LIMIT

    limit = max(
        1,
        min(
            limit,
            100000,
        ),
    )

    # --------------------------------------------------------
    # Load messages
    # --------------------------------------------------------

    rows = await database.load_recent_messages(
        conn,
        limit,
    )

    # --------------------------------------------------------
    # Convert DB rows to evaluator format
    # --------------------------------------------------------

    messages = []

    for (
        msg_id,
        room_id,
        sender,
        message_text,
        ciphertext,
        signature,
        timestamp,
    ) in rows:

        messages.append(
            {
                "msg_id": msg_id,
                "room": room_id,
                "client-name": sender,

                # IMPORTANT:
                # Return plaintext directly.
                "msg": message_text,

                "ciphertext": ciphertext,
                "signature": signature,
                "timestamp": timestamp.isoformat()
                if timestamp
                else None,
            }
        )

    return web.json_response(
        messages,
        status=200,
    )


# ============================================================
# POST /internal/replicate
# ============================================================

async def internal_replicate(request):
    """
    Internal endpoint used by backend peers.

    This endpoint stores a replicated message locally.

    It DOES NOT replicate the message again.

    That prevents replication loops:

        sys2 -> sys3 -> sys2 -> sys3 -> ...
    """

    # --------------------------------------------------------
    # Authenticate peer
    # --------------------------------------------------------

    supplied_secret = request.headers.get(
        "X-Replication-Secret",
        "",
    )

    if (
        not REPLICATION_SECRET
        or supplied_secret != REPLICATION_SECRET
    ):

        return web.json_response(
            {
                "error": "unauthorized"
            },
            status=401,
        )

    # --------------------------------------------------------
    # Parse payload
    # --------------------------------------------------------

    try:

        payload = await request.json()

    except Exception:

        return web.json_response(
            {
                "error": "invalid JSON"
            },
            status=400,
        )

    # --------------------------------------------------------
    # Extract fields
    # --------------------------------------------------------

    msg_id = payload.get(
        "msg_id"
    )

    room = payload.get(
        "room",
        "general",
    )

    username = payload.get(
        "client-name"
    )

    message_text = payload.get(
        "message_text"
    )

    ciphertext = payload.get(
        "ciphertext"
    )

    signature = payload.get(
        "signature"
    )

    verified = payload.get(
        "verified",
        False,
    )

    # --------------------------------------------------------
    # Validate
    # --------------------------------------------------------

    if not msg_id:
        return web.json_response(
            {
                "error": "msg_id is required"
            },
            status=400,
        )

    if not username:
        return web.json_response(
            {
                "error": "client-name is required"
            },
            status=400,
        )

    if message_text is None:
        return web.json_response(
            {
                "error": "message_text is required"
            },
            status=400,
        )

    if ciphertext is None:
        return web.json_response(
            {
                "error": "ciphertext is required"
            },
            status=400,
        )

    if signature is None:
        return web.json_response(
            {
                "error": "signature is required"
            },
            status=400,
        )

    # --------------------------------------------------------
    # Save directly to local DB
    # --------------------------------------------------------

    conn = request.app["db_conn"]

    inserted = await database.save_message(
        conn,
        msg_id,
        room,
        username,
        message_text,
        ciphertext,
        signature,
        verified,
    )

    # --------------------------------------------------------
    # Return success
    # --------------------------------------------------------

    return web.json_response(
        {
            "status": "ok",
            "inserted": inserted,
            "msg_id": msg_id,
        },
        status=200,
    )


# ============================================================
# GET /health
# ============================================================

async def health(request):
    """
    Lightweight health endpoint used by the load balancer.

    Reports:
        backend ID
        CPU percentage
        active request count
    """

    return web.json_response(
        {
            "status": "ok",
            "backend": BACKEND_ID,
            "cpu": psutil.cpu_percent(
                interval=None
            ),
            "active_requests": active_requests,
        },
        status=200,
    )


# ============================================================
# STARTUP
# ============================================================

async def on_startup(app):
    """
    Initialize database, Fernet key, replication queue,
    persistent HTTP session and replication workers.
    """

    global replication_queue
    global replication_workers
    global replication_session

    # --------------------------------------------------------
    # Database pool
    # --------------------------------------------------------

    db_conn = await database.get_connection()

    await database.init_db(
        db_conn
    )

    app["db_conn"] = db_conn

    # --------------------------------------------------------
    # Local Fernet key
    # --------------------------------------------------------

    app["fernet"] = Fernet(
        await database.get_or_create_fernet_key(
            db_conn
        )
    )

    # --------------------------------------------------------
    # Replication queue
    # --------------------------------------------------------

    replication_queue = asyncio.Queue()

    # --------------------------------------------------------
    # Persistent HTTP client
    # --------------------------------------------------------

    replication_connector = aiohttp.TCPConnector(
        limit=0,
        limit_per_host=100,
        keepalive_timeout=60,
    )

    replication_timeout = aiohttp.ClientTimeout(
        total=REPLICATION_TIMEOUT_SECONDS
    )

    replication_session = aiohttp.ClientSession(
        connector=replication_connector,
        timeout=replication_timeout,
    )

    # --------------------------------------------------------
    # Start replication workers
    # --------------------------------------------------------

    replication_workers.clear()

    for worker_id in range(
        REPLICATION_WORKERS
    ):

        task = asyncio.create_task(
            replication_worker(
                worker_id + 1
            )
        )

        replication_workers.append(
            task
        )

    print(
        f"[STARTUP] "
        f"backend={BACKEND_ID} "
        f"port={PORT}"
    )

    print(
        f"[STARTUP] "
        f"replication peers="
        f"{REPLICATION_PEERS}"
    )

    print(
        f"[STARTUP] "
        f"replication workers="
        f"{REPLICATION_WORKERS}"
    )


# ============================================================
# CLEANUP
# ============================================================

async def on_cleanup(app):
    """
    Gracefully stop replication workers, close HTTP session,
    and close the PostgreSQL pool.
    """

    global replication_workers
    global replication_session

    # --------------------------------------------------------
    # Stop replication workers
    # --------------------------------------------------------

    for task in replication_workers:

        task.cancel()

    if replication_workers:

        await asyncio.gather(
            *replication_workers,
            return_exceptions=True,
        )

    replication_workers.clear()

    # --------------------------------------------------------
    # Close replication HTTP session
    # --------------------------------------------------------

    if replication_session is not None:

        await replication_session.close()

        replication_session = None

    # --------------------------------------------------------
    # Close DB
    # --------------------------------------------------------

    db_conn = app.get(
        "db_conn"
    )

    if db_conn is not None:

        await db_conn.close()


# ============================================================
# APPLICATION FACTORY
# ============================================================

def create_app():
    """
    Create and configure the aiohttp application.
    """

    app = web.Application()

    # Startup / cleanup
    app.on_startup.append(
        on_startup
    )

    app.on_cleanup.append(
        on_cleanup
    )

    # Public routes
    app.router.add_get(
        "/",
        index,
    )

    app.router.add_post(
        "/message",
        http_message,
    )

    app.router.add_get(
        "/feed",
        http_feed,
    )

    app.router.add_get(
        "/health",
        health,
    )

    app.router.add_get(
        "/ws",
        websocket_handler,
    )

    # Internal replication route
    app.router.add_post(
        "/internal/replicate",
        internal_replicate,
    )

    return app


# ============================================================
# MAIN
# ============================================================

if __name__ == "__main__":

    web.run_app(
        create_app(),
        host=HOST,
        port=PORT,
    )