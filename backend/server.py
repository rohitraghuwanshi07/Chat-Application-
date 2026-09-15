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

Architecture:
    - Each backend owns a local PostgreSQL database.
    - /message persists locally first.
    - Replication happens asynchronously.
    - Multiple replication workers drain the replication queue.
    - A persistent aiohttp session is reused for peer replication.
    - Replication is idempotent through msg_id.
    - /feed returns plaintext message text directly for the Lab 6
      evaluator.
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
    get_verifier_public_key,
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
        "4000",
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
# PUBLIC INDEX
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
    Headers used for backend-to-backend replication.
    """

    return {
        "X-Replication-Secret": REPLICATION_SECRET,
        "X-Backend-ID": BACKEND_ID,
    }


async def replicate_to_peer(
    peer,
    payload,
):
    """
    Send one message to one peer.

    Uses the shared persistent aiohttp session.

    Raises an exception if the peer:
        - cannot be reached,
        - times out,
        - or returns a non-200 status.
    """

    global replication_session

    if replication_session is None:
        raise RuntimeError(
            "replication HTTP session is not initialized"
        )

    url = (
        f"{peer}/internal/replicate"
    )

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


async def replicate_message(payload):
    """
    Replicate one message to every configured peer.

    All peers are contacted concurrently.

    The operation is considered successful only when all
    configured peers acknowledge it.

    The same msg_id is sent to every peer, so duplicate
    deliveries are harmless because save_message() uses:

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
        if isinstance(
            result,
            Exception,
        ):
            failures.append(
                f"{peer}: {result}"
            )

    if failures:
        raise RuntimeError(
            "replication failed: "
            + "; ".join(failures)
        )


# ============================================================
# REPLICATION WORKER
# ============================================================

async def replication_worker(
    worker_id,
):
    """
    Drain the replication queue.

    Multiple workers operate concurrently.

    Each worker takes one message at a time and retries failed
    replication up to three times.
    """

    while True:

        payload = await replication_queue.get()

        try:

            msg_id = payload.get(
                "msg_id",
                "unknown",
            )

            replicated = False

            for attempt in range(3):

                try:

                    await replicate_message(
                        payload
                    )

                    replicated = True

                    break

                except asyncio.CancelledError:
                    raise

                except Exception as exc:

                    if attempt < 2:

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

            if not replicated:
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

    The evaluator primarily sends:

    {
        "client-name": "...",
        "msg": "..."
    }
    """

    global active_requests

    active_requests += 1

    request_start = time.perf_counter()

    try:

        conn = request.app["db_conn"]

        fernet = request.app["fernet"]

        # ----------------------------------------------------
        # Parse request JSON
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
        # Extract fields
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

        if not isinstance(
            room,
            str,
        ) or not room:

            room = "general"

        # ----------------------------------------------------
        # Generate msg_id once
        # ----------------------------------------------------

        msg_id = (
            body.get("msg_id")
            or str(uuid.uuid4())
        )

        # ----------------------------------------------------
        # Get signing key
        #
        # This uses the EXISTING chat_handler implementation.
        # ----------------------------------------------------

        private_key = (
            await get_or_create_signing_key(
                conn,
                username,
            )
        )

        # ----------------------------------------------------
        # Sign plaintext
        # ----------------------------------------------------

        signature = crypto_utils.sign_text(
            private_key,
            plaintext,
        )

        # ----------------------------------------------------
        # Verify signature
        # ----------------------------------------------------

        public_key = (
            await get_verifier_public_key(
                conn,
                username,
            )
        )

        verified = (
            crypto_utils.verify_signature(
                public_key,
                plaintext,
                signature,
            )
        )

        # ----------------------------------------------------
        # Encrypt message for storage
        # ----------------------------------------------------

        ciphertext = (
            crypto_utils.encrypt_text(
                fernet,
                plaintext,
            )
        )

        # ----------------------------------------------------
        # LOCAL DATABASE INSERT
        #
        # This is the persistence point for /message.
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
        # QUEUE REPLICATION
        #
        # Important:
        # We do NOT wait for peers here.
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
        # Local WebSocket broadcast
        # ----------------------------------------------------

        try:

            await broadcast(
                room,
                {
                    "type": "message",
                    "msg_id": msg_id,
                    "user": username,
                    "text": plaintext,
                    "verified": verified,
                },
            )

        except Exception as exc:

            print(
                "[BROADCAST-WARNING] "
                f"backend={BACKEND_ID} "
                f"msg_id={msg_id} "
                f"error={exc}"
            )

        # ----------------------------------------------------
        # Return success
        # ----------------------------------------------------

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
    Return recent messages.

    IMPORTANT:
    The Lab 6 evaluator expects plaintext in "msg".

    Therefore message_text is returned directly.

    ciphertext is retained in the response for compatibility,
    but the evaluator should use "msg".
    """

    conn = request.app["db_conn"]

    # --------------------------------------------------------
    # Parse limit
    # --------------------------------------------------------

    try:

        limit = int(
            request.query.get(
                "limit",
                FEED_DEFAULT_LIMIT,
            )
        )

    except (
        TypeError,
        ValueError,
    ):

        limit = FEED_DEFAULT_LIMIT

    limit = max(
        1,
        min(
            limit,
            100000,
        ),
    )

    # --------------------------------------------------------
    # Read database
    # --------------------------------------------------------

    rows = (
        await database.load_recent_messages(
            conn,
            limit,
        )
    )

    # --------------------------------------------------------
    # Build evaluator response
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
                # plaintext is what Lab 6 checks.
                "msg": message_text,

                "ciphertext": ciphertext,
                "signature": signature,

                "timestamp": (
                    timestamp.isoformat()
                    if timestamp
                    else None
                ),
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
    Receive a replicated message from another backend.

    This endpoint ONLY writes to the local database.

    It does NOT enqueue another replication operation.

    Therefore:

        sys2 -> sys3

    stops there rather than becoming:

        sys2 -> sys3 -> sys2 -> sys3 -> ...
    """

    # --------------------------------------------------------
    # Verify replication secret
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
    # Parse JSON
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
    # Extract data
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
    # Validate required fields
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
                "error": (
                    "client-name is required"
                )
            },
            status=400,
        )

    if message_text is None:

        return web.json_response(
            {
                "error": (
                    "message_text is required"
                )
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
    # Save locally
    #
    # DO NOT enqueue another replication.
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
    Health endpoint used by the load balancer.
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
    Initialize:

        PostgreSQL pool
        database tables
        Fernet key
        replication queue
        persistent HTTP session
        replication workers
    """

    global replication_queue
    global replication_workers
    global replication_session

    # --------------------------------------------------------
    # PostgreSQL
    # --------------------------------------------------------

    db_conn = await database.get_connection()

    await database.init_db(
        db_conn
    )

    app["db_conn"] = db_conn

    # --------------------------------------------------------
    # Fernet
    # --------------------------------------------------------

    fernet_key = (
        await database.get_or_create_fernet_key(
            db_conn
        )
    )

    app["fernet"] = Fernet(
        fernet_key
    )

    # --------------------------------------------------------
    # Replication queue
    # --------------------------------------------------------

    replication_queue = asyncio.Queue()

    # --------------------------------------------------------
    # Persistent HTTP connection pool
    # --------------------------------------------------------

    connector = aiohttp.TCPConnector(
        limit=0,
        limit_per_host=100,
        keepalive_timeout=60,
    )

    timeout = aiohttp.ClientTimeout(
        total=REPLICATION_TIMEOUT_SECONDS
    )

    replication_session = (
        aiohttp.ClientSession(
            connector=connector,
            timeout=timeout,
        )
    )

    # --------------------------------------------------------
    # Start workers
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

    # --------------------------------------------------------
    # Startup diagnostics
    # --------------------------------------------------------

    print(
        f"[STARTUP] backend={BACKEND_ID}"
    )

    print(
        f"[STARTUP] host={HOST}"
    )

    print(
        f"[STARTUP] port={PORT}"
    )

    print(
        f"[STARTUP] replication_peers="
        f"{REPLICATION_PEERS}"
    )

    print(
        f"[STARTUP] replication_workers="
        f"{REPLICATION_WORKERS}"
    )

    print(
        f"[STARTUP] replication_timeout="
        f"{REPLICATION_TIMEOUT_SECONDS}s"
    )


# ============================================================
# CLEANUP
# ============================================================

async def on_cleanup(app):
    """
    Stop replication workers and close network/database
    resources.
    """

    global replication_workers
    global replication_session

    # --------------------------------------------------------
    # Stop workers
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
    # Close HTTP session
    # --------------------------------------------------------

    if replication_session is not None:

        await replication_session.close()

        replication_session = None

    # --------------------------------------------------------
    # Close PostgreSQL
    # --------------------------------------------------------

    db_conn = app.get(
        "db_conn"
    )

    if db_conn is not None:

        await db_conn.close()


# ============================================================
# APPLICATION
# ============================================================

def create_app():
    """
    Create aiohttp application.
    """

    app = web.Application()

    # Lifecycle
    app.on_startup.append(
        on_startup
    )

    app.on_cleanup.append(
        on_cleanup
    )

    # Public API
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

    # Internal replication
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