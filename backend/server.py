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

    return app


if __name__ == "__main__":
    web.run_app(create_app(), host="0.0.0.0", port=4000)
