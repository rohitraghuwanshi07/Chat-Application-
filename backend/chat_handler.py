"""
chat_handler.py
-----------------
The live part of the app: who is connected to which room, sending a
message to everyone in that room, and the pipeline a new chat message
goes through before it's saved:

    plaintext + signature  <-- arrives from the client, already signed
    plaintext  --encrypt-->  ciphertext
    (ciphertext, signature)  --saved to local Valkey--
    new (non-duplicate) message --> fanned out to peer backends too

And in reverse, when history loads:

    ciphertext  --decrypt-->  plaintext
    (plaintext, signature)  --verify-->  True/False "verified" badge

CHANGED: signing keys are no longer generated or held by the server.
Each browser generates its own Ed25519 keypair (see
frontend/src/lib/identity.js), signs its own messages, and sends its
public key once at connect time. The server's job shrank to exactly
what it should be: verify a signature it was given, never produce one.

CHANGED (Valkey + active-active): `pool` everywhere below is a Valkey
connection pool (see database.py) for THIS backend's own local
instance. Every database.* call is wrapped in `await
database.run_async(...)` to keep it off the event loop, and every
newly-saved (non-duplicate) message is fanned out to peer backends
(see replication.py) so they end up holding the same data locally too.
"""

import json
import uuid
import asyncio
from datetime import datetime
from aiohttp import web, WSMsgType
from cryptography.fernet import Fernet

import crypto_utils
import database
import replication

# rooms = { room_name: { websocket_object: username } }
rooms = {}


async def get_verifier_public_key(pool, username):
    pem = await database.run_async(database.load_public_key, pool, username)
    return crypto_utils.pem_to_public_key(pem) if pem else None


async def broadcast(room, payload, exclude=None):
    """Send to room members concurrently so one slow websocket cannot
    serialize delivery to every other client."""
    clients = [c for c in list(rooms.get(room, {})) if c is not exclude]
    if not clients:
        return

    results = await asyncio.gather(
        *(client.send_json(payload) for client in clients),
        return_exceptions=True,
    )
    room_clients = rooms.get(room, {})
    for client, result in zip(clients, results):
        if isinstance(result, Exception):
            room_clients.pop(client, None)


async def build_history_payloads(pool, fernet: Fernet, room_id):
    """
    Loads every stored message for a room and, for EACH ONE, decrypts it
    and re-checks its signature RIGHT NOW rather than trusting whatever
    was saved at insert time. This is what makes tamper detection show
    up even after a server restart: if a row was edited directly in the
    database, this re-check will now disagree with the original result.
    """
    rows, signers = await database.run_async(database.load_room_messages_with_signers, pool, room_id)
    payloads = []

    for message_id, sender, ciphertext, signature, timestamp in rows:
        plaintext = crypto_utils.decrypt_text(fernet, ciphertext)

        if plaintext is None:
            payloads.append({
                "type": "message", "user": sender,
                "text": "[message unreadable -- storage was tampered with]",
                "time": timestamp, "verified": False, "message_id": message_id,
            })
            continue

        pem = signers.get(sender)
        public_key = crypto_utils.pem_to_public_key(pem) if pem else None
        verified_now = crypto_utils.verify_signature(public_key, plaintext, signature)
        payloads.append({
            "type": "message", "user": sender, "text": plaintext,
            "time": timestamp, "verified": verified_now, "message_id": message_id,
        })

    return payloads


async def websocket_handler(request):
    pool = request.app["db_conn"]
    fernet = request.app["fernet"]

    ws = web.WebSocketResponse()
    await ws.prepare(request)

    username = request.query.get("name", "Anonymous")
    room = request.query.get("room", "general")
    pubkey_pem = request.query.get("pubkey")

    rooms.setdefault(room, {})[ws] = username

    if pubkey_pem:
        await database.run_async(database.save_public_key, pool, username, pubkey_pem)

    verifier_pem = pubkey_pem or await database.run_async(database.load_public_key, pool, username)
    verifier_public_key = crypto_utils.pem_to_public_key(verifier_pem) if verifier_pem else None

    print(f"[{room}] {username} joined. Total in room: {len(rooms[room])}")
    await broadcast(room, {"type": "system", "text": f"{username} joined the room"})

    history = await build_history_payloads(pool, fernet, room)
    for old_payload in history:
        await ws.send_json(old_payload)

    try:
        async for msg in ws:
            if msg.type == WSMsgType.TEXT:
                timestamp = datetime.now().strftime("%H:%M:%S")

                try:
                    parsed = json.loads(msg.data)
                    plaintext = parsed["text"]
                    message_id = parsed.get("message_id") or str(uuid.uuid4())
                    signature = parsed.get("signature", "")
                except (json.JSONDecodeError, TypeError, KeyError):
                    plaintext = msg.data
                    message_id = str(uuid.uuid4())
                    signature = ""

                verified = crypto_utils.verify_signature(verifier_public_key, plaintext, signature)

                ciphertext = crypto_utils.encrypt_text(fernet, plaintext)
                message_id, inserted = await database.run_async(
                    database.save_message,
                    pool, room, username, ciphertext, signature, verified, message_id,
                )

                if not inserted:
                    await ws.send_json({
                        "type": "message", "user": username, "text": plaintext,
                        "time": timestamp, "verified": verified, "message_id": message_id,
                    })
                    continue

                # New (non-duplicate) message -- fan it out to peer
                # backends so their local Valkey ends up with it too.
                asyncio.create_task(replication.fanout({
                    "message_id": message_id, "room": room, "sender": username,
                    "ciphertext": ciphertext, "signature": signature, "verified": verified,
                }))


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
