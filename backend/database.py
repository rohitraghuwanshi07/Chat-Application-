"""
database.py
------------
Storage layer, now backed by Valkey (a Redis-protocol-compatible,
in-memory store) instead of Postgres.

WHY THIS CHANGED (previous version was pooled Postgres):
Postgres, even pooled, is still one disk-backed engine and one network
hop away from every backend. For a write-once/read-many workload like
this chat app (messages are immutable once written; /feed and history
loads are read far more often than /message writes), the real fix is
giving every backend its own full LOCAL copy of the data, so reads
never leave the machine. See replication.py for the other half of this
(how each backend's writes reach its peers).

CONNECTS TO A LOCAL VALKEY INSTANCE:
Each backend machine should run its own `valkey-server` on localhost.
There's no cross-machine DB traffic here at all -- only the small
HTTP fan-out in replication.py crosses machines.

DATA MODEL:
- "messages" is a single Redis STREAM (an append-only log) holding
  every message from every room, in insertion order.
- "seen_ids" is a SET used purely for O(1) atomic dedup: SADD returns
  0 if the message_id was already present, which is what makes
  duplicate inserts (from retries, or from replication.py re-applying
  a fan-out) a safe no-op instead of a duplicate entry.
- "signers" is a HASH of username -> public key PEM.
"""

import os
import time
import uuid
import asyncio
import redis

DB_HOST = os.environ.get("DB_HOST", "localhost")
DB_PORT = int(os.environ.get("DB_PORT", "6379"))


def get_pool():
    """Creates the connection pool for this backend process. Call once
    at startup and pass the returned pool into every function below."""
    return redis.ConnectionPool(
        host=DB_HOST,
        port=DB_PORT,
        decode_responses=True,
        max_connections=50,
    )


def _client(pool):
    # Cheap: just wraps the shared pool, doesn't open a new connection.
    return redis.Redis(connection_pool=pool)


async def run_async(func, *args):
    """Runs a blocking function in a worker thread so it never blocks
    the asyncio event loop. Usage:
        await database.run_async(database.save_message, pool, ...)
    Valkey/Redis calls are extremely fast (in-memory, sub-millisecond),
    but we keep this pattern for consistency and safety under load.
    """
    loop = asyncio.get_running_loop()
    return await loop.run_in_executor(None, func, *args)


def init_db(pool):
    """No schema to create -- Redis/Valkey structures spring into
    existence on first write. Just confirm we can actually reach it."""
    _client(pool).ping()


def save_message(pool, room_id, sender, ciphertext, signature, verified_at_insert, message_id=None):
    """Saves a message with deduplication by message_id.
    Returns (message_id, inserted).

    SADD is atomic and returns 0 if the id was already a member of the
    set -- that's the entire dedup mechanism, no locks needed. This is
    also what makes replication.py's fan-out safe to apply twice.
    """
    if not message_id:
        message_id = str(uuid.uuid4())

    r = _client(pool)
    added = r.sadd("seen_ids", message_id)
    if not added:
        return message_id, False

    r.xadd("messages", {
        "message_id": message_id,
        "room": room_id,
        "sender": sender,
        "ciphertext": ciphertext,
        "signature": signature,
        "verified": "1" if verified_at_insert else "0",
        "ts": time.time(),
    })
    return message_id, True


def load_room_messages(pool, room_id):
    """Returns (message_id, sender, ciphertext, signature, timestamp)
    for every message in a room, oldest first."""
    r = _client(pool)
    rows = []
    for _stream_id, fields in r.xrange("messages"):
        if fields.get("room") == room_id:
            rows.append((
                fields["message_id"], fields["sender"], fields["ciphertext"],
                fields["signature"], fields["ts"],
            ))
    return rows


def load_all_messages(pool):
    """Returns (message_id, sender, ciphertext, room_id, timestamp) for
    EVERY message across ALL rooms, oldest first. Used by /feed."""
    r = _client(pool)
    rows = []
    for _stream_id, fields in r.xrange("messages"):
        rows.append((
            fields["message_id"], fields["sender"], fields["ciphertext"],
            fields["room"], fields["ts"],
        ))
    return rows


def save_public_key(pool, username, public_key_pem):
    _client(pool).hset("signers", username, public_key_pem)


def load_public_key(pool, username):
    return _client(pool).hget("signers", username)
