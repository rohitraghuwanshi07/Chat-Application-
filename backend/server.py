"""
server.py
----------
Entry point. Run with:
    cd backend
    export CHAT_DB_HOST=<external postgres host>
    export CHAT_DB_USER=chatuser CHAT_DB_PASS=... CHAT_DB_NAME=chatdb
    python3 server.py
"""
import pathlib
import uuid
from aiohttp import web
from cryptography.fernet import Fernet
import psutil

import database
import crypto_utils
from chat_handler import (
    websocket_handler, get_or_create_signing_key,
    get_verifier_public_key, broadcast,
)
import os
from dotenv import load_dotenv

load_dotenv()

HOST = os.environ.get("HOST", "0.0.0.0")
PORT = int(os.environ.get("PORT", "3000"))

FRONTEND_DIR = pathlib.Path(__file__).resolve().parent.parent / "frontend"
active_requests = 0

async def index(request):
    return web.FileResponse(FRONTEND_DIR / "dist" / "index.html")


async def http_message(request):
    """POST /message  { "client-name": "...", "msg": "..." }"""
    global active_requests
    active_requests += 1
    try:
        conn = request.app["db_conn"]
        fernet = request.app["fernet"]
        body = await request.json()
        username = body.get("client-name")
        plaintext = body.get("msg")
        room = body.get("room", "general")
        if not username or plaintext is None:
            return web.json_response({"error": "client-name and msg are required"}, status=400)

        msg_id = body.get("msg_id") or str(uuid.uuid4())
        private_key = await get_or_create_signing_key(conn, username)
        signature = crypto_utils.sign_text(private_key, plaintext)
        public_key = await get_verifier_public_key(conn, username)
        verified = crypto_utils.verify_signature(public_key, plaintext, signature)
        ciphertext = crypto_utils.encrypt_text(fernet, plaintext)

        await database.save_message(conn, msg_id, room, username, ciphertext, signature, verified)
        await broadcast(room, {"type": "message", "user": username, "text": plaintext, "verified": verified})

        return web.json_response({"status": "ok", "msg_id": msg_id})
    finally:
        active_requests -= 1


async def http_feed(request):
    """GET /feed -- all messages, decrypted."""
    conn = request.app["db_conn"]
    fernet = request.app["fernet"]
    rows = await database.load_all_messages(conn)
    out = []
    for msg_id, room_id, sender, ciphertext, signature, ts in rows:
        plaintext = crypto_utils.decrypt_text(fernet, ciphertext)
        out.append({"msg_id": msg_id, "room": room_id, "client-name": sender, "msg": plaintext, "time": str(ts)})
    return web.json_response(out)


async def health(request):
    """Polled by the load balancer."""
    return web.json_response({
        "cpu": psutil.cpu_percent(interval=0.1),
        "mem": psutil.virtual_memory().percent,
        "active_requests": active_requests,
        "status": "ok",
    })


async def on_startup(app):
    pool = await database.get_connection()
    await database.init_db(pool)
    app["db_conn"] = pool
    fernet_key = await database.get_or_create_fernet_key(pool)
    app["fernet"] = Fernet(fernet_key)


async def on_cleanup(app):
    await app["db_conn"].close()


def create_app():
    app = web.Application()
    app.on_startup.append(on_startup)
    app.on_cleanup.append(on_cleanup)

    app.router.add_get("/", index)
    app.router.add_get("/ws", websocket_handler)
    app.router.add_post("/message", http_message)
    app.router.add_get("/feed", http_feed)
    app.router.add_get("/health", health)
    app.router.add_static("/assets/", FRONTEND_DIR / "dist" / "assets")

    return app


if __name__ == "__main__":
    web.run_app(create_app(), host=HOST, port=PORT)