"""
server.py
----------
Entry point for a backend chat server.

Lab 6 optimized architecture:

    POST /message
        |
        +--> local PostgreSQL INSERT
        |
        +--> update in-memory feed cache
        |
        +--> enqueue replication
        |
        +--> return 200 immediately

Replication happens asynchronously in background workers.

GET /feed is served from the in-memory feed cache so that the
leaderboard's persistence scan is cheap.

Public API:
    GET  /
    GET  /ws
    POST /message
    GET  /feed
    GET  /health

Internal API:
    POST /internal/replicate
"""

import asyncio
import os
import pathlib
import time
import uuid
import json

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
# Configuration
# ============================================================

HOST = os.environ.get("HOST", "0.0.0.0")
PORT = int(os.environ.get("PORT", "4000"))
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

REPLICATION_WORKERS = int(
    os.environ.get("REPLICATION_WORKERS", "8")
)

FEED_DEFAULT_LIMIT = int(
    os.environ.get("FEED_DEFAULT_LIMIT", "100000")
)

FRONTEND_DIR = (
    pathlib.Path(__file__).resolve().parent.parent
    / "frontend"
)


# ============================================================
# Runtime state
# ============================================================

active_requests = 0

replication_queue = None
replication_workers = []

replication_session = None


# ============================================================
# In-memory feed cache
# ============================================================
#
# Key:
#     msg_id
#
# Value:
#     dictionary in exactly the same shape that /feed returns.
#
# This is NOT the persistence layer.
#
# PostgreSQL remains the durable local store.
# The cache is only the fast read path for /feed.
#
# Because replication also updates this cache, it gradually
# converges as the cluster converges.
# ============================================================

feed_cache = {}

# Protect cache modifications/reads from concurrent async tasks.
feed_cache_lock = asyncio.Lock()


async def cache_message(message):
    """
    Add/update one message in the in-memory feed cache.
    """
    msg_id = message.get("msg_id")

    if not msg_id:
        return

    async with feed_cache_lock:
        feed_cache[msg_id] = message


async def cache_message_if_new(message):
    """
    Add a message only if it is not already present.

    This is useful for replicated messages.
    """
    msg_id = message.get("msg_id")

    if not msg_id:
        return

    async with feed_cache_lock:
        if msg_id not in feed_cache:
            feed_cache[msg_id] = message


async def get_cached_feed(limit):
    """
    Return the newest cached messages.

    We sort by timestamp descending.

    The cache dictionary is keyed by msg_id, so replicated
    duplicates cannot create duplicate feed entries.
    """

    async with feed_cache_lock:
        messages = list(feed_cache.values())

    messages.sort(
        key=lambda item: (
            str(item.get("timestamp") or ""),
            str(item.get("msg_id") or ""),
        ),
        reverse=True,
    )

    return messages[:limit]


async def preload_feed_cache(conn):
    """
    Load existing PostgreSQL messages into memory at startup.

    This makes the cache useful even after a backend restart.
    """

    global feed_cache

    try:
        rows = await database.load_recent_messages(
            conn,
            FEED_DEFAULT_LIMIT,
        )

        loaded = {}

        for (
            msg_id,
            room_id,
            sender,
            message_text,
            ciphertext,
            signature,
            timestamp,
        ) in rows:

            loaded[msg_id] = {
                "msg_id": msg_id,
                "room": room_id,
                "client-name": sender,
                "msg": message_text,
                "ciphertext": ciphertext,
                "signature": signature,
                "timestamp": (
                    timestamp.isoformat()
                    if timestamp
                    else None
                ),
            }

        async with feed_cache_lock:
            feed_cache = loaded

        print(
            f"[FEED-CACHE] backend={BACKEND_ID} "
            f"preloaded={len(loaded)}"
        )

    except Exception as exc:
        print(
            f"[FEED-CACHE-WARNING] "
            f"backend={BACKEND_ID} "
            f"error={exc}"
        )


# ============================================================
# Public frontend
# ============================================================

async def index(request):
    return web.FileResponse(
        FRONTEND_DIR / "dist" / "index.html"
    )


# ============================================================
# Replication
# ============================================================

def replication_headers():
    return {
        "X-Replication-Secret": REPLICATION_SECRET,
        "X-Backend-ID": BACKEND_ID,
    }


async def replicate_to_peer(peer, payload):
    """
    Send one message to one peer.

    This function is only used by background workers.
    It is NEVER awaited from /message.
    """

    global replication_session

    if replication_session is None:
        raise RuntimeError(
            "replication HTTP session is not initialized"
        )

    url = f"{peer}/internal/replicate"

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
    Replicate one message to all configured peers.

    This runs only in background workers.
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
            "replication failed: "
            + "; ".join(failures)
        )


async def replication_worker(worker_id):
    """
    Background replication worker.

    Important:
        A replication failure here NEVER changes the response
        that was already returned by /message.
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
                            0.25 * (attempt + 1)
                        )

                    else:

                        print(
                            "[REPLICATION-BACKGROUND-ERROR] "
                            f"worker={worker_id} "
                            f"backend={BACKEND_ID} "
                            f"msg_id={msg_id} "
                            f"error={exc}"
                        )

            if replicated:
                pass

        finally:
            replication_queue.task_done()


# ============================================================
# POST /message
# ============================================================

async def http_message(request):

    global active_requests

    active_requests += 1

    try:

        conn = request.app["db_conn"]
        fernet = request.app["fernet"]

        # ----------------------------------------------------
        # Parse request
        # ----------------------------------------------------

        try:
            body = await request.json()

        except Exception:
            return web.json_response(
                {
                    "error":
                    "request body must be valid JSON"
                },
                status=400,
            )

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
                    "error":
                    "client-name and msg are required"
                },
                status=400,
            )

        if not isinstance(room, str) or not room:
            room = "general"

        msg_id = (
            body.get("msg_id")
            or str(uuid.uuid4())
        )

        # ----------------------------------------------------
        # Cryptographic processing
        # ----------------------------------------------------

        private_key = await get_or_create_signing_key(
            conn,
            username,
        )

        signature = crypto_utils.sign_text(
            private_key,
            plaintext,
        )

        public_key = await get_verifier_public_key(
            conn,
            username,
        )

        verified = crypto_utils.verify_signature(
            public_key,
            plaintext,
            signature,
        )

        ciphertext = crypto_utils.encrypt_text(
            fernet,
            plaintext,
        )

        # ----------------------------------------------------
        # CRITICAL PATH:
        #
        # Only local persistence is awaited.
        #
        # We DO NOT await replication.
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
        # Build feed representation immediately.
        # ----------------------------------------------------

        timestamp = time.time()

        feed_message = {
            "msg_id": msg_id,
            "room": room,
            "client-name": username,
            "msg": plaintext,
            "ciphertext": ciphertext,
            "signature": signature,
            "timestamp": timestamp,
        }

        # ----------------------------------------------------
        # Update local memory cache.
        #
        # Even if PostgreSQL says duplicate, the cache is
        # harmlessly refreshed.
        # ----------------------------------------------------

        await cache_message(
            feed_message
        )

        # ----------------------------------------------------
        # Queue replication.
        #
        # put_nowait() does not wait for peers.
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
        # WebSocket broadcast is also best-effort.
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
        # IMPORTANT:
        #
        # Return immediately after local persistence +
        # cache update + replication enqueue.
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
    # FAST PATH:
    #
    # No PostgreSQL query.
    # --------------------------------------------------------

    messages = await get_cached_feed(
        limit
    )

    return web.json_response(
        messages,
        status=200,
    )


# ============================================================
# POST /internal/replicate
# ============================================================

async def internal_replicate(request):

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

    try:

        payload = await request.json()

    except Exception:

        return web.json_response(
            {
                "error": "invalid JSON"
            },
            status=400,
        )

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

    if not msg_id:

        return web.json_response(
            {
                "error":
                "msg_id is required"
            },
            status=400,
        )

    if not username:

        return web.json_response(
            {
                "error":
                "client-name is required"
            },
            status=400,
        )

    if message_text is None:

        return web.json_response(
            {
                "error":
                "message_text is required"
            },
            status=400,
        )

    if ciphertext is None:

        return web.json_response(
            {
                "error":
                "ciphertext is required"
            },
            status=400,
        )

    if signature is None:

        return web.json_response(
            {
                "error":
                "signature is required"
            },
            status=400,
        )

    conn = request.app["db_conn"]

    # --------------------------------------------------------
    # Persist replicated message locally.
    # --------------------------------------------------------

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
    # Update this backend's feed cache.
    #
    # IMPORTANT:
    # This is what makes eventual consistency visible through
    # /feed without querying PostgreSQL.
    # --------------------------------------------------------

    timestamp = time.time()

    feed_message = {
        "msg_id": msg_id,
        "room": room,
        "client-name": username,
        "msg": message_text,
        "ciphertext": ciphertext,
        "signature": signature,
        "timestamp": timestamp,
    }

    await cache_message(
        feed_message
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

    queue_size = (
        replication_queue.qsize()
        if replication_queue is not None
        else 0
    )

    async with feed_cache_lock:
        cache_size = len(feed_cache)

    return web.json_response(
        {
            "status": "ok",
            "backend": BACKEND_ID,
            "cpu": psutil.cpu_percent(
                interval=None
            ),
            "active_requests": active_requests,
            "replication_queue": queue_size,
            "feed_cache_size": cache_size,
        },
        status=200,
    )


# ============================================================
# Startup
# ============================================================

async def on_startup(app):

    global replication_queue
    global replication_workers
    global replication_session

    # --------------------------------------------------------
    # Database
    # --------------------------------------------------------

    db_conn = await database.get_connection()

    await database.init_db(
        db_conn
    )

    app["db_conn"] = db_conn

    # --------------------------------------------------------
    # Encryption key
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
    # Preload existing messages into feed cache.
    # --------------------------------------------------------

    await preload_feed_cache(
        db_conn
    )

    # --------------------------------------------------------
    # Replication queue
    # --------------------------------------------------------

    replication_queue = asyncio.Queue()

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
    # Background replication workers
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

    print(
        f"[STARTUP] feed_cache_size="
        f"{len(feed_cache)}"
    )


# ============================================================
# Cleanup
# ============================================================

async def on_cleanup(app):

    global replication_workers
    global replication_session

    # Cancel workers.

    for task in replication_workers:
        task.cancel()

    if replication_workers:

        await asyncio.gather(
            *replication_workers,
            return_exceptions=True,
        )

    replication_workers.clear()

    # Close HTTP session.

    if replication_session is not None:

        await replication_session.close()

        replication_session = None

    # Close DB.

    db_conn = app.get(
        "db_conn"
    )

    if db_conn is not None:

        await db_conn.close()


# ============================================================
# App
# ============================================================

def create_app():

    app = web.Application()

    app.on_startup.append(
        on_startup
    )

    app.on_cleanup.append(
        on_cleanup
    )

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

    app.router.add_post(
        "/internal/replicate",
        internal_replicate,
    )

    return app


# ============================================================
# Main
# ============================================================

if __name__ == "__main__":

    web.run_app(
        create_app(),
        host=HOST,
        port=PORT,
    )