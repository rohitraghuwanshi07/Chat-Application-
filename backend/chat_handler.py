"""
chat_handler.py
-----------------
The live part of the app: who is connected to which room, sending a
message to everyone in that room, and the pipeline a new chat message
goes through before it's saved:

    plaintext  --sign-->  signature
    plaintext  --encrypt-->  ciphertext
    (ciphertext, signature)  --saved to DB--

And in reverse, when history loads:

    ciphertext  --decrypt-->  plaintext
    (plaintext, signature)  --verify-->  True/False "verified" badge
"""

from datetime import datetime
from aiohttp import web, WSMsgType
from cryptography.fernet import Fernet

import crypto_utils
import database

# rooms = { room_name: { websocket_object: username } }
rooms = {}

# In-memory only, per server process: username -> Ed25519PrivateKey.
# LAB-SCOPE NOTE: the server signs on behalf of each connected user, so
# private keys live only in server RAM and are never written to disk.
# (A production system would generate/hold private keys on the client,
# e.g. in the browser, so the server could never forge a signature.)
signing_keys = {}


def get_or_create_signing_key(conn, username):
    """First time we see `username`, generate them a key pair and save
    the PUBLIC half permanently. Every later message from that name
    reuses the same key pair for this server run."""
    if username in signing_keys:
        return signing_keys[username]

    private_key, public_key = crypto_utils.generate_signing_keypair()
    signing_keys[username] = private_key
    database.save_public_key(conn, username, crypto_utils.public_key_to_pem(public_key))
    return private_key


def get_verifier_public_key(conn, username):
    pem = database.load_public_key(conn, username)
    return crypto_utils.pem_to_public_key(pem) if pem else None


async def broadcast(room, payload, exclude=None):
    """Sends `payload` to every client in `room`. If sending to a client
    fails (their connection is dying), we don't let that crash delivery
    to everyone else -- we just clean that client up afterwards."""
    dead_clients = []
    for client in list(rooms.get(room, {})):
        if client is not exclude:
            try:
                await client.send_json(payload)
            except Exception:
                dead_clients.append(client)
    for dead in dead_clients:
        rooms.get(room, {}).pop(dead, None)


def build_history_payloads(conn, fernet: Fernet, room_id):
    """
    Loads every stored message for a room and, for EACH ONE, decrypts it
    and re-checks its signature RIGHT NOW rather than trusting whatever
    was saved at insert time. This is what makes tamper detection show
    up even after a server restart: if a row was edited directly in the
    database, this re-check will now disagree with the original result.
    """
    rows = database.load_room_messages(conn, room_id)
    payloads = []

    for sender, ciphertext, signature, timestamp in rows:
        plaintext = crypto_utils.decrypt_text(fernet, ciphertext)

        if plaintext is None:
            # Fernet's own integrity check caught corruption before we
            # even got to look at the Ed25519 signature.
            payloads.append({
                "type": "message", "user": sender,
                "text": "[message unreadable -- storage was tampered with]",
                "time": timestamp, "verified": False,
            })
            continue

        public_key = get_verifier_public_key(conn, sender)
        verified_now = crypto_utils.verify_signature(public_key, plaintext, signature)
        payloads.append({
            "type": "message", "user": sender, "text": plaintext,
            "time": timestamp, "verified": verified_now,
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
    get_or_create_signing_key(conn, username)

    print(f"[{room}] {username} joined. Total in room: {len(rooms[room])}")
    await broadcast(room, {"type": "system", "text": f"{username} joined the room"})

    # Send this client the room's history, decrypted + re-verified live.
    for old_payload in build_history_payloads(conn, fernet, room):
        await ws.send_json(old_payload)

    try:
        async for msg in ws:
            if msg.type == WSMsgType.TEXT:
                timestamp = datetime.now().strftime("%H:%M:%S")
                plaintext = msg.data

                private_key = signing_keys[username]
                signature = crypto_utils.sign_text(private_key, plaintext)

                public_key = get_verifier_public_key(conn, username)
                verified = crypto_utils.verify_signature(public_key, plaintext, signature)

                ciphertext = crypto_utils.encrypt_text(fernet, plaintext)
                database.save_message(conn, room, username, ciphertext, signature, verified)

                print(f"[{room}] {username} ({timestamp}): signed & encrypted, verified={verified}")

                # Live broadcast carries PLAINTEXT (these clients are
                # already inside an authenticated live session) -- only
                # what touches the DATABASE is encrypted.
                await broadcast(room, {
                    "type": "message", "user": username, "text": plaintext,
                    "time": timestamp, "verified": verified,
                })
    finally:
        rooms.get(room, {}).pop(ws, None)
        print(f"[{room}] {username} left. Total in room: {len(rooms.get(room, {}))}")
        await broadcast(room, {"type": "system", "text": f"{username} left the room"})

    return ws
