import asyncio
import os
import pathlib
from aiohttp import web
from cryptography.fernet import Fernet

import database
import crypto_utils
import replication
from chat_handler import websocket_handler



@web.middleware
async def admission_middleware(request, handler):
    # WebSockets are long-lived connections, so they need a separate
    # message-level policy rather than consuming one HTTP slot forever.
    if request.path in ("/ws", "/health"):
        return await handler(request)

    app = request.app
    max_inflight = app["max_inflight"]
    active = app["active_requests"]

    # aiohttp runs application code on one event loop thread, and there is
    # no await between this check and increment, so admission is atomic for
    # this process. Requests beyond the cap are rejected immediately rather
    # than waiting in an unbounded application-side queue.
    if active >= max_inflight:
        return web.json_response(
            {"error": "backend busy, retry shortly"},
            status=503,
            headers={"Retry-After": "1"},
        )

    app["active_requests"] = active + 1
    try:
        return await handler(request)
    finally:
        app["active_requests"] -= 1

FRONTEND_DIR = pathlib.Path(__file__).resolve().parent.parent / "frontend"


async def index(request):
    return web.FileResponse(FRONTEND_DIR / "dist" / "index.html")

async def health(request):
    return web.Response(text="ok")

# Room used for messages that come in through the plain REST API below,
# as opposed to the websocket chat, which is scoped per-room by the
# client. Kept separate from "general" so REST traffic doesn't mix with
# websocket chat traffic unless you want it to.
REST_ROOM = "rest-feed"


async def submit_message(request):
    """POST /message -- accepts client-name and msg, stores the message.

    Accepts either querystring params (?client-name=...&msg=...) or a
    form-encoded / JSON POST body, so it works with simple curl calls,
    HTML forms, or JSON clients without the caller needing to know which
    one this expects.

    An optional "message-id" field can also be supplied by the caller --
    if the same message-id is sent twice (e.g. a retried request after a
    dropped connection), the dedup in database.save_message guarantees
    the second attempt is a safe no-op, not a duplicate entry.
    """
    data = {}
    if request.can_read_body:
        try:
            if request.content_type == "application/json":
                data = await request.json()
            else:
                data = dict(await request.post())
        except Exception:
            data = {}

    client_name = request.query.get("client-name") or data.get("client-name")
    msg = request.query.get("msg") or data.get("msg")
    message_id = request.query.get("message-id") or data.get("message-id")

    if not client_name or not msg:
        return web.json_response(
            {"error": "both client-name and msg are required"}, status=400
        )

    pool = request.app["db_conn"]
    fernet = request.app["fernet"]

    ciphertext = crypto_utils.encrypt_text(fernet, msg)
    message_id, inserted = await database.run_async(
        database.save_message,
        pool, REST_ROOM, client_name, ciphertext, "", False, message_id,
    )

    if inserted:
        # Fire-and-forget: replicate to peer backends so their LOCAL
        # Valkey also has this message. Doesn't block this response.
        asyncio.create_task(replication.fanout({
            "message_id": message_id, "room": REST_ROOM, "sender": client_name,
            "ciphertext": ciphertext, "signature": "", "verified": False,
        }))

    return web.json_response({
        "message-id": message_id,
        "client-name": client_name,
        "msg": msg,
        "inserted": inserted,  # False means this exact message-id was already stored
    })


async def replicate_in(request):
    """POST /replicate -- internal route. A peer backend calls this to
    tell us to apply a message it already accepted, so our own local
    Valkey stays in sync. This never fans out further (flat, one-hop
    topology) -- the originating backend already told every peer
    directly, so there's nothing more to forward."""
    payload = await request.json()
    pool = request.app["db_conn"]
    await database.run_async(
        database.save_message,
        pool, payload["room"], payload["sender"], payload["ciphertext"],
        payload.get("signature", ""), payload.get("verified", False),
        payload["message_id"],
    )
    return web.json_response({"ok": True})


def _build_feed_sync(pool, fernet):
    """Runs entirely inside a worker thread: query + decrypt + build the
    JSON-ready list, all in one blocking call."""
    rows = database.load_all_messages(pool)
    feed = []
    for message_id, sender, ciphertext, room_id, timestamp in rows:
        plaintext = crypto_utils.decrypt_text(fernet, ciphertext)
        feed.append({
            "message-id": message_id,
            "client-name": sender,
            "msg": plaintext if plaintext is not None else "[unreadable -- storage was tampered with]",
            "room": room_id,
            "timestamp": str(timestamp),
        })
    return feed


async def get_feed(request):
    """GET /feed -- returns every stored message, oldest first, as JSON.
    Reads entirely from THIS backend's local Valkey -- no network hop,
    no shared bottleneck, since every backend holds the full dataset
    via replication.py's fan-out."""
    pool = request.app["db_conn"]
    fernet = request.app["fernet"]
    feed = await database.run_async(_build_feed_sync, pool, fernet)
    return web.json_response(feed)


async def on_startup(app):
    """Creates the single shared replication ClientSession for this
    process's lifetime. Must happen before any fanout() call -- see
    replication.py for why a shared session (vs. one per message)
    matters under load."""
    replication.init_session()


async def on_cleanup(app):
    """Closes the shared replication session's connections cleanly on
    shutdown, so sockets aren't leaked."""
    await replication.close_session()


def create_app():
    app = web.Application(middlewares=[admission_middleware])
    app["max_inflight"] = int(os.environ.get("MAX_INFLIGHT", "100"))
    app["active_requests"] = 0

    pool = database.get_pool()
    database.init_db(pool)  # one-time, at startup -- fine to block briefly here
    app["db_conn"] = pool

    encryption_key = crypto_utils.load_or_create_encryption_key()
    app["fernet"] = Fernet(encryption_key)

    app.router.add_get("/", index)
    app.router.add_get("/ws", websocket_handler)
    app.router.add_static("/assets/", FRONTEND_DIR / "dist" / "assets")
    app.router.add_get("/health", health)
    app.router.add_post("/message", submit_message)
    app.router.add_get("/feed", get_feed)
    app.router.add_post("/replicate", replicate_in)

    app.on_startup.append(on_startup)
    app.on_cleanup.append(on_cleanup)

    return app


if __name__ == "__main__":
    web.run_app(create_app(), host="0.0.0.0", port=4000)