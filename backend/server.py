import pathlib
from aiohttp import web
from cryptography.fernet import Fernet

import database
import crypto_utils
from chat_handler import websocket_handler

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
    dropped connection), the database's unique constraint on message_id
    guarantees the second attempt is a safe no-op, not a duplicate row.
    If omitted, the server generates a fresh one, so retries are only
    dedup-safe when the caller supplies its own message-id.
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

    conn = request.app["db_conn"]
    fernet = request.app["fernet"]

    ciphertext = crypto_utils.encrypt_text(fernet, msg)
    # No signature for REST-submitted messages -- there's no client-side
    # signing key involved here, only the websocket chat clients do that.
    message_id, inserted = database.save_message(
        conn, REST_ROOM, client_name, ciphertext,
        signature="", verified_at_insert=False, message_id=message_id,
    )

    return web.json_response({
        "message-id": message_id,
        "client-name": client_name,
        "msg": msg,
        "inserted": inserted,  # False means this exact message-id was already stored
    })


async def get_feed(request):
    """GET /feed -- returns every stored message, oldest first, as JSON."""
    conn = request.app["db_conn"]
    fernet = request.app["fernet"]

    feed = []
    for message_id, sender, ciphertext, room_id, timestamp in database.load_all_messages(conn):
        plaintext = crypto_utils.decrypt_text(fernet, ciphertext)
        feed.append({
            "message-id": message_id,
            "client-name": sender,
            "msg": plaintext if plaintext is not None else "[unreadable -- storage was tampered with]",
            "room": room_id,
            "timestamp": str(timestamp),
        })

    return web.json_response(feed)


def create_app():
    app = web.Application()

    conn = database.get_connection()
    database.init_db(conn)
    app["db_conn"] = conn

    encryption_key = crypto_utils.load_or_create_encryption_key()
    app["fernet"] = Fernet(encryption_key)

    app.router.add_get("/", index)
    app.router.add_get("/ws", websocket_handler)
    app.router.add_static("/assets/", FRONTEND_DIR / "dist" / "assets")
    app.router.add_get("/health", health)
    app.router.add_post("/message", submit_message)
    app.router.add_get("/feed", get_feed)

    return app


if __name__ == "__main__":
    web.run_app(create_app(), host="0.0.0.0", port=4000)
