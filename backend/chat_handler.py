"""
chat_handler.py
-----------------
Live WebSocket behavior: rooms, broadcasting, and the
sign -> verify -> encrypt -> save pipeline for each message.
All DB calls are async (asyncpg pool underneath).
"""
import uuid
from datetime import datetime
from aiohttp import web, WSMsgType
from cryptography.fernet import Fernet

import crypto_utils
import database

rooms = {}
signing_keys = {}


async def get_or_create_signing_key(conn, username):
    """Checks the shared DB first, so every backend node reuses the
    same keypair for a user instead of minting a new one."""
    if username in signing_keys:
        return signing_keys[username]

    row = await database.load_signing_key(conn, username)
    if row:
        _, private_pem = row
        private_key = crypto_utils.pem_to_private_key(private_pem)
    else:
        private_key, public_key = crypto_utils.generate_signing_keypair()
        await database.save_signing_key(
            conn, username,
            crypto_utils.public_key_to_pem(public_key),
            crypto_utils.private_key_to_pem(private_key),
        )

    signing_keys[username] = private_key
    return private_key


async def get_verifier_public_key(conn, username):
    row = await database.load_signing_key(conn, username)
    if not row:
        return None
    public_pem, _ = row
    return crypto_utils.pem_to_public_key(public_pem)


async def broadcast(room, payload, exclude=None):
    dead_clients = []
    for client in list(rooms.get(room, {})):
        if client is not exclude:
            try:
                await client.send_json(payload)
            except Exception:
                dead_clients.append(client)
    for dead in dead_clients:
        rooms.get(room, {}).pop(dead, None)


async def build_history_payloads(conn, fernet: Fernet, room_id):
    rows = await database.load_room_messages(conn, room_id)
    payloads = []

    for sender, ciphertext, signature, timestamp in rows:
        plaintext = crypto_utils.decrypt_text(fernet, ciphertext)

        if plaintext is None:
            payloads.append({
                "type": "message", "user": sender,
                "text": "[message unreadable -- storage was tampered with]",
                "time": str(timestamp), "verified": False,
            })
            continue

        public_key = await get_verifier_public_key(conn, sender)
        verified_now = crypto_utils.verify_signature(public_key, plaintext, signature)
        payloads.append({
            "type": "message", "user": sender, "text": plaintext,
            "time": str(timestamp), "verified": verified_now,
        })

    return payloads


async def websocket_handler(request):
    conn = request.app["db_conn"]
    fernet = request.app["fernet"]

    ws = web.WebSocketResponse()
    await ws.prepare(request)

    username = request.query.get("name", "Anonymous")
    room = request.query.get("room", "general")

    rooms.setdefault(room, {})[ws] = username
    await get_or_create_signing_key(conn, username)

    print(f"[{room}] {username} joined. Total in room: {len(rooms[room])}")
    await broadcast(room, {"type": "system", "text": f"{username} joined the room"})

    for old_payload in await build_history_payloads(conn, fernet, room):
        await ws.send_json(old_payload)

    try:
        async for msg in ws:
            if msg.type == WSMsgType.TEXT:
                timestamp = datetime.now().strftime("%H:%M:%S")
                plaintext = msg.data
                msg_id = str(uuid.uuid4())

                private_key = signing_keys[username]
                signature = crypto_utils.sign_text(private_key, plaintext)

                public_key = await get_verifier_public_key(conn, username)
                verified = crypto_utils.verify_signature(public_key, plaintext, signature)

                ciphertext = crypto_utils.encrypt_text(fernet, plaintext)
                await database.save_message(conn, msg_id, room, username, ciphertext, signature, verified)

                print(f"[{room}] {username} ({timestamp}): signed & encrypted, verified={verified}")

                await broadcast(room, {
                    "type": "message", "user": username, "text": plaintext,
                    "time": timestamp, "verified": verified,
                })
    finally:
        rooms.get(room, {}).pop(ws, None)
        print(f"[{room}] {username} left. Total in room: {len(rooms.get(room, {}))}")
        await broadcast(room, {"type": "system", "text": f"{username} left the room"})

    return ws