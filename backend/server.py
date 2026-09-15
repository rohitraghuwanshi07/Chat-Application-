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

Messages are persisted locally first. Replication to the other backend
nodes happens asynchronously in the background so slow replication peers
do not block the public /message request.
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


HOST = os.environ.get("HOST", "0.0.0.0")
PORT = int(os.environ.get("PORT", "3000"))

BACKEND_ID = os.environ.get("BACKEND_ID", "unknown")

REPLICATION_SECRET = os.environ.get("REPLICATION_SECRET", "")

REPLICATION_PEERS = [
    peer.strip().rstrip("/")
    for peer in os.environ.get("REPLICATION_PEERS", "").split(",")
    if peer.strip()
]

REPLICATION_TIMEOUT_SECONDS = float(
    os.environ.get("REPLICATION_TIMEOUT_SECONDS", "2.0")
)

FEED_DEFAULT_LIMIT = int(
    os.environ.get("FEED_DEFAULT_LIMIT", "100000")
)

FRONTEND_DIR = (
    pathlib.Path(__file__).resolve().parent.parent / "frontend"
)

active_requests = 0

# Background replication queue.
replication_queue = None


async def index(request):
    return web.FileResponse(
        FRONTEND_DIR / "dist" / "index.html"
    )


def replication_headers():
    return {
        "X-Replication-Secret": REPLICATION_SECRET,
        "X-Backend-ID": BACKEND_ID,
    }


async def replicate_to_peer(peer, payload):
    """
    Send one message to another backend's internal replication endpoint.

    Raises an exception if the peer cannot be reached or returns a
    non-success HTTP status.
    """
    url = f"{peer}/internal/replicate"

    timeout = aiohttp.ClientTimeout(
        total=REPLICATION_TIMEOUT_SECONDS
    )

    async with aiohttp.ClientSession(timeout=timeout) as session:
        async with session.post(
            url,
            json=payload,
            headers=replication_headers(),
        ) as response:

            response_body = await response.text()

            if response.status != 200:
                raise RuntimeError(
                    f"peer={peer} status={response.status} "
                    f"body={response_body[:300]}"
                )

            return response_body


async def replicate_message(payload):
    """
    Replicate one message to every configured peer.

    All configured peers must acknowledge the message for this
    replication attempt to be considered successful.

    This function runs in the background and does not block the
    public /message request.
    """
    if not REPLICATION_PEERS:
        raise RuntimeError(
            f"{BACKEND_ID}: no replication peers configured"
        )

    tasks = [
        replicate_to_peer(peer, payload)
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
            "replication failed: " + "; ".join(failures)
        )


async def replication_worker():
    """
    Background worker that processes queued replication jobs.

    The local database insert is the persistence point for /message.

    Replication to peer backends happens asynchronously so slow peers
    do not block the public request.

    Each message gets up to three replication attempts.
    """
    while True:
        payload = await replication_queue.get()

        try:
            for attempt in range(3):
                try:
                    await replicate_message(payload)

                    print(
                        f"[REPLICATION-OK] "
                        f"backend={BACKEND_ID} "
                        f"msg_id={payload.get('msg_id')} "
                        f"attempt={attempt + 1}"
                    )

                    break

                except Exception as exc:
                    if attempt == 2:
                        print(
                            f"[REPLICATION-BACKGROUND-ERROR] "
                            f"backend={BACKEND_ID} "
                            f"msg_id={payload.get('msg_id')} "
                            f"error={exc}"
                        )
                    else:
                        await asyncio.sleep(
                            0.5 * (attempt + 1)
                        )

        finally:
            replication_queue.task_done()


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
    """
    global active_requests

    active_requests += 1
    request_start = time.perf_counter()

    try:
        conn = request.app["db_conn"]
        fernet = request.app["fernet"]

        try:
            body = await request.json()
        except Exception:
            return web.json_response(
                {
                    "error": "request body must be valid JSON"
                },
                status=400,
            )

        username = body.get("client-name")
        plaintext = body.get("msg")
        room = body.get("room", "general")

        if not username or plaintext is None:
            return web.json_response(
                {
                    "error": "client-name and msg are required"
                },
                status=400,
            )

        if not isinstance(room, str) or not room:
            room = "general"

        # Generate the message ID exactly once.
        #
        # The same ID is stored locally and sent to every replica.
        msg_id = body.get("msg_id") or str(uuid.uuid4())

        # ---------------------------------------------------------
        # 1. Generate signature
        # ---------------------------------------------------------
        t = time.perf_counter()

        private_key = await get_or_create_signing_key(
            conn,
            username,
        )

        key_time = time.perf_counter() - t

        # ---------------------------------------------------------
        # 2. Sign + verify
        # ---------------------------------------------------------
        t = time.perf_counter()

        signature = crypto_utils.sign_text(
            private_key,
            plaintext,
        )

        public_key = private_key.public_key()

        verified = crypto_utils.verify_signature(
            public_key,
            plaintext,
            signature,
        )

        crypto_time = time.perf_counter() - t

        # ---------------------------------------------------------
        # 3. Encrypt
        # ---------------------------------------------------------
        t = time.perf_counter()

        ciphertext = crypto_utils.encrypt_text(
            fernet,
            plaintext,
        )

        encryption_time = time.perf_counter() - t

        # ---------------------------------------------------------
        # 4. Save locally
        # ---------------------------------------------------------
        t = time.perf_counter()

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

        db_save_time = time.perf_counter() - t

        # ---------------------------------------------------------
        # 5. Queue replication in the background
        # ---------------------------------------------------------
        replication_payload = {
            "msg_id": msg_id,
            "room": room,
            "client-name": username,
            "message_text": plaintext,
            "ciphertext": ciphertext,
            "signature": signature,
            "verified": verified,
        }

        t = time.perf_counter()

        replication_queue.put_nowait(
            replication_payload
        )

        replication_time = time.perf_counter() - t

        # ---------------------------------------------------------
        # 6. Broadcast locally
        # ---------------------------------------------------------
        await broadcast(
            room,
            {
                "type": "message",
                "user": username,
                "text": plaintext,
                "verified": verified,
            },
        )

        total_time = time.perf_counter() - request_start

        print(
            f"[MESSAGE] "
            f"backend={BACKEND_ID} "
            f"user={username} "
            f"msg_id={msg_id} "
            f"inserted={inserted} "
            f"key={key_time:.4f}s "
            f"crypto={crypto_time:.4f}s "
            f"encrypt={encryption_time:.4f}s "
            f"save={db_save_time:.4f}s "
            f"queue={replication_time:.6f}s "
            f"total={total_time:.4f}s"
        )

        return web.json_response(
            {
                "status": "ok",
                "msg_id": msg_id,
            }
        )

    finally:
        active_requests -= 1


async def http_replicate(request):
    """
    POST /internal/replicate

    This endpoint is used only between backend nodes.

    It saves the replicated message locally and broadcasts it to local
    WebSocket clients.

    IMPORTANT:
    It does NOT replicate the message further.
    """

    expected_secret = REPLICATION_SECRET

    if not expected_secret:
        return web.json_response(
            {
                "error": "replication is not configured"
            },
            status=503,
        )

    supplied_secret = request.headers.get(
        "X-Replication-Secret",
        "",
    )

    if supplied_secret != expected_secret:
        return web.json_response(
            {
                "error": "unauthorized"
            },
            status=401,
        )

    try:
        body = await request.json()
    except Exception:
        return web.json_response(
            {
                "error": "invalid JSON"
            },
            status=400,
        )

    required_fields = [
        "msg_id",
        "room",
        "client-name",
        "message_text",
        "ciphertext",
        "signature",
        "verified",
    ]

    missing = [
        field
        for field in required_fields
        if field not in body
    ]

    if missing:
        return web.json_response(
            {
                "error": "missing fields",
                "fields": missing,
            },
            status=400,
        )

    conn = request.app["db_conn"]

    inserted = await database.save_message(
        conn,
        body["msg_id"],
        body["room"],
        body["client-name"],
        body["message_text"],
        body["ciphertext"],
        body["signature"],
        bool(body["verified"]),
    )

    # Only broadcast if this was actually a new local message.
    #
    # Duplicate replication should not cause duplicate WebSocket events.
    if inserted:
        await broadcast(
            body["room"],
            {
                "type": "message",
                "user": body["client-name"],
                "text": body["message_text"],
                "verified": bool(body["verified"]),
            },
        )

    return web.json_response(
        {
            "status": "ok",
            "inserted": inserted,
            "msg_id": body["msg_id"],
        }
    )


async def http_feed(request):
    """
    GET /feed

    Optional query parameter:
        ?limit=1000

    The public URL remains /feed.

    The response contains the newest messages from THIS backend's
    local PostgreSQL database.
    """
    conn = request.app["db_conn"]

    raw_limit = request.query.get(
        "limit",
        str(FEED_DEFAULT_LIMIT),
    )

    try:
        limit = int(raw_limit)
    except ValueError:
        limit = FEED_DEFAULT_LIMIT

    limit = max(
        1,
        min(limit, 100000),
    )

    rows = await database.load_recent_messages(
        conn,
        limit,
    )

    # Return the original plaintext message in the public feed.
    out = []

    for (
        msg_id,
        room_id,
        sender,
        message_text,
        ciphertext,
        signature,
        ts,
    ) in reversed(rows):

        out.append(
            {
                "msg_id": msg_id,
                "room": room_id,
                "client-name": sender,
                "msg": message_text,
                "time": str(ts),
            }
        )

    return web.json_response(out)


async def health(request):
    """
    Polled by the load balancer.
    """
    return web.json_response(
        {
            "cpu": psutil.cpu_percent(interval=None),
            "mem": psutil.virtual_memory().percent,
            "active_requests": active_requests,
            "status": "ok",
            "backend_id": BACKEND_ID,
        }
    )


async def on_startup(app):
    """
    Initialize the local database and background replication worker.
    """
    global replication_queue

    pool = await database.get_connection()

    await database.init_db(pool)

    app["db_conn"] = pool

    fernet_key = await database.get_or_create_fernet_key(
        pool
    )

    app["fernet"] = Fernet(fernet_key)

    # Initialize the replication queue.
    replication_queue = asyncio.Queue()

    # Start exactly one replication worker per backend process.
    app["replication_worker"] = asyncio.create_task(
        replication_worker()
    )


async def on_cleanup(app):
    """
    Stop the background replication worker and then close the
    database connection pool.
    """
    worker = app.get("replication_worker")

    if worker:
        worker.cancel()

        try:
            await worker
        except asyncio.CancelledError:
            pass

    await app["db_conn"].close()


def create_app():
    app = web.Application()

    app.on_startup.append(on_startup)
    app.on_cleanup.append(on_cleanup)

    # Public API
    app.router.add_get(
        "/",
        index,
    )

    app.router.add_get(
        "/ws",
        websocket_handler,
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

    # Internal replication API
    app.router.add_post(
        "/internal/replicate",
        http_replicate,
    )

    app.router.add_static(
        "/assets/",
        FRONTEND_DIR / "dist" / "assets",
    )

    return app


if __name__ == "__main__":
    web.run_app(
        create_app(),
        host=HOST,
        port=PORT,
    )