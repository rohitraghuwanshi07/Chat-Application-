"""
database.py
------------
Storage layer, backed by Valkey (a Redis-protocol-compatible,
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

CHANGED (perf fix): run_async() used to hand every blocking call to
`loop.run_in_executor(None, ...)`, which uses asyncio's DEFAULT
executor -- sized `min(32, os.cpu_count() + 4)` by Python, so often as
few as 8-12 worker threads. Every database call the app makes
(save_message on every websocket/REST message, load_public_key on
every message, AND the O(n) full-history scan behind GET /feed) all
funneled through that same tiny pool. Under load-test concurrency
(hundreds of in-flight requests, per the load balancer's
-max-inflight-per-backend), requests queued behind a handful of
threads and per-request latency climbed past the load balancer's
backend-timeout, which is what was producing the timeouts and 502s.

Redis/Valkey calls themselves are sub-millisecond, so threads -- not
Redis connections -- were the scarce resource. The fix is a dedicated,
larger executor (sized to comfortably cover the load balancer's
per-backend concurrency cap) plus a matching Redis connection pool
size so threads never queue waiting on a connection either.
"""

import os
import time
import uuid
import asyncio
import redis
from concurrent.futures import ThreadPoolExecutor

DB_HOST = os.environ.get("DB_HOST", "localhost")
DB_PORT = int(os.environ.get("DB_PORT", "6379"))

# How many blocking DB calls this backend can run in parallel. Set this
# to comfortably cover whatever -max-inflight-per-backend the load
# balancer is configured with (default 500 in cmd/loadbalancer), so a
# full burst of concurrent requests never queues up behind a
# too-small pool. Override via env var if you tune the LB's flag.
DB_WORKERS = int(os.environ.get("DB_WORKERS", "64"))

# A dedicated executor, NOT asyncio's default one. Every database.*
# call below goes through this pool via run_async(), instead of
# competing with (and being capped by) whatever else in the process
# might also be using loop.run_in_executor(None, ...).
_EXECUTOR = ThreadPoolExecutor(max_workers=DB_WORKERS, thread_name_prefix="db")


def get_pool():
    """Creates the connection pool for this backend process. Call once
    at startup and pass the returned pool into every function below.

    max_connections is matched to DB_WORKERS so a worker thread is
    never left waiting for a free Redis connection on top of waiting
    for a free worker thread -- that would just move the bottleneck
    instead of removing it.
    """
    return redis.ConnectionPool(
        host=DB_HOST,
        port=DB_PORT,
        decode_responses=True,
        max_connections=DB_WORKERS,
    )


def _client(pool):
    # Cheap: just wraps the shared pool, doesn't open a new connection.
    return redis.Redis(connection_pool=pool)


async def run_async(func, *args):
    """Runs a blocking function in the dedicated DB thread pool so it
    never blocks the asyncio event loop. Usage:
        await database.run_async(database.save_message, pool, ...)
    """
    loop = asyncio.get_running_loop()
    return await loop.run_in_executor(_EXECUTOR, func, *args)


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
    EVERY message across ALL rooms, oldest first. Used by /feed.

    NOTE: this is O(n) over every message ever stored, on every call,
    including a decrypt of each one in server.py's caller. That's a
    separate scaling concern from the thread-pool fix above -- it's
    fine at this run's message volumes, but if /feed keeps getting
    called under sustained heavy write load as the dataset grows, it
    will eventually become the next bottleneck and is worth caching or
    paginating.
    """
    r = _client(pool)
    rows = []
    for _stream_id, fields in r.xrange("messages"):
        rows.append((
            fields["message_id"], fields["sender"], fields["ciphertext"],
            fields["room"], fields["ts"],
        ))
    return rows


def load_room_messages_with_signers(pool, room_id):
    """Load a room's messages and all signer public keys in one Redis worker
    operation, avoiding one HGET per historical message."""
    r = _client(pool)
    rows = []
    for _stream_id, fields in r.xrange("messages"):
        if fields.get("room") == room_id:
            rows.append((
                fields["message_id"], fields["sender"], fields["ciphertext"],
                fields["signature"], fields["ts"],
            ))
    return rows, r.hgetall("signers")


def save_public_key(pool, username, public_key_pem):
    _client(pool).hset("signers", username, public_key_pem)


def load_public_key(pool, username):
    return _client(pool).hget("signers", username)