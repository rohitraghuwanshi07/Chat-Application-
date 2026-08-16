"""
server.py
----------
Entry point. This is the ONLY file you run. It just wires the pieces
together:

    database.py       -> where messages/keys are stored
    crypto_utils.py    -> signing + encryption
    chat_handler.py     -> live websocket behavior
    frontend/           -> the static HTML/CSS/JS the browser loads

Run with:
    cd backend
    python3 server.py

Then open http://localhost:3210 in a browser (open it twice / in two
tabs to chat with "yourself").
"""

import pathlib
from aiohttp import web
from cryptography.fernet import Fernet

import database
import crypto_utils
from chat_handler import websocket_handler

FRONTEND_DIR = pathlib.Path(__file__).resolve().parent.parent / "frontend"


async def index(request):
    return web.FileResponse(FRONTEND_DIR / "index.html")


def create_app():
    app = web.Application()

    conn = database.get_connection()
    database.init_db(conn)
    app["db_conn"] = conn

    encryption_key = crypto_utils.load_or_create_encryption_key()
    app["fernet"] = Fernet(encryption_key)

    app.router.add_get("/", index)
    app.router.add_get("/ws", websocket_handler)
    app.router.add_static("/static/", FRONTEND_DIR / "static")

    return app


if __name__ == "__main__":
    web.run_app(create_app(), host="0.0.0.0", port=3210)
