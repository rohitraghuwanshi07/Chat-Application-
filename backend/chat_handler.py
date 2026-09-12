"""
chat_handler.py
-----------------
The live part of the app: who is connected to which room, sending a
message to everyone in that room, and the pipeline a new chat message
goes through before it's saved:

    plaintext + signature  <-- arrives from the client, already signed
    plaintext  --encrypt-->  ciphertext
    (ciphertext, signature)  --saved to DB--

And in reverse, when history loads:

    ciphertext  --decrypt-->  plaintext
    (plaintext, signature)  --verify-->  True/False "verified" badge

CHANGED: signing keys are no longer generated or held by the server.
Each browser generates its own Ed25519 keypair (see
frontend/src/lib/identity.js), signs its own messages, and sends its
public key once at connect time. The server's job shrank to exactly
what it should be: verify a signature it was given, never produce one.
"""

import json
import uuid
from datetime import datetime
from aiohttp import web, WSMsgType
from cryptography.fernet import Fernet

import crypto_utils
import database

# rooms = { room_name: { websocket_object: username } }
rooms = {}


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

    for message_id, sender, ciphertext, signature, timestamp in rows:
        plaintext = crypto_utils.decrypt_text(fernet, ciphertext)

        if plaintext is None:
            # Fernet's own integrity check caught corruption before we
            # even got to look at the Ed25519 signature.
            payloads.append({
                "type": "message", "user": sender,
                "text": "[message unreadable -- storage was tampered with]",
                "time": timestamp, "verified": False, "message_id": message_id,
            })
            continue

        public_key = get_verifier_public_key(conn, sender)
        verified_now = crypto_utils.verify_signature(public_key, plaintext, signature)
        payloads.append({
            "type": "message", "user": sender, "text": plaintext,
            "time": timestamp, "verified": verified_now, "message_id": message_id,
        })

    return payloads


async def websocket_handler(request):
    conn = request.app["db_conn"]
    fernet = request.app["fernet"]

    ws = web.WebSocketResponse()
    await ws.prepare(request)

    username = request.query.get("name", "Anonymous")
    room = request.query.get("room", "general")
    pubkey_pem = request.query.get("pubkey")

    rooms.setdefault(room, {})[ws] = username

    # The client generated its own keypair and is telling us its public
    # half. We just store whatever we're given (no first-write-wins
    # check -- impersonation-by-name is a known, separate limitation of
    # this app having no login system, left as out of scope for now).
    # An old client that doesn't send ?pubkey= simply won't verify --
    # there's no server-side key to fall back to signing with anymore.
    if pubkey_pem:
        database.save_public_key(conn, username, pubkey_pem)

    print(f"[{room}] {username} joined. Total in room: {len(rooms[room])}")
    await broadcast(room, {"type": "system", "text": f"{username} joined the room"})

    # Send this client the room's history, decrypted + re-verified live.
    for old_payload in build_history_payloads(conn, fernet, room):
        await ws.send_json(old_payload)

    try:
        async for msg in ws:
            if msg.type == WSMsgType.TEXT:
                timestamp = datetime.now().strftime("%H:%M:%S")

                # The client sends {"text": ..., "message_id": ..., "signature": ...}.
                # message_id: see the dedup note above.
                # signature: computed by the CLIENT over `text` with its
                # own private key (see frontend/src/lib/identity.js) --
                # the server never signs, only verifies. Plain-text
                # frames or a missing signature (old clients, tools like
                # tamper_demo) verify as False rather than crashing.
                try:
                    parsed = json.loads(msg.data)
                    plaintext = parsed["text"]
                    message_id = parsed.get("message_id") or str(uuid.uuid4())
                    signature = parsed.get("signature", "")
                except (json.JSONDecodeError, TypeError, KeyError):
                    plaintext = msg.data
                    message_id = str(uuid.uuid4())
                    signature = ""

                public_key = get_verifier_public_key(conn, username)
                verified = crypto_utils.verify_signature(public_key, plaintext, signature)

                ciphertext = crypto_utils.encrypt_text(fernet, plaintext)
                message_id, inserted = database.save_message(
                    conn, room, username, ciphertext, signature, verified, message_id
                )

                if not inserted:
                    # Duplicate: same message_id already stored (a retry
                    # that actually landed the first time, e.g. the
                    # connection dropped before the sender saw the ack).
                    # Don't re-broadcast to the whole room -- everyone
                    # else already got it -- but DO echo it back to just
                    # this sender so their retry is confirmed/cleared.
                    print(f"[{room}] {username} ({timestamp}): duplicate message_id={message_id}, ignored")
                    await ws.send_json({
                        "type": "message", "user": username, "text": plaintext,
                        "time": timestamp, "verified": verified, "message_id": message_id,
                    })
                    continue

                print(f"[{room}] {username} ({timestamp}): signed & encrypted, verified={verified}")

                # Live broadcast carries PLAINTEXT (these clients are
                # already inside an authenticated live session) -- only
                # what touches the DATABASE is encrypted.
                await broadcast(room, {
                    "type": "message", "user": username, "text": plaintext,
                    "time": timestamp, "verified": verified, "message_id": message_id,
                })
    except Exception as e:
        print(f"[{room}] {username} connection ERRORED: {e!r}")
    finally:
        print(f"[{room}] {username} loop ended. ws.closed={ws.closed} "
              f"close_code={ws.close_code} exception={ws.exception()!r}")
        rooms.get(room, {}).pop(ws, None)
        print(f"[{room}] {username} left. Total in room: {len(rooms.get(room, {}))}")
        await broadcast(room, {"type": "system", "text": f"{username} left the room"})
    return ws
