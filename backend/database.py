"""
database.py
------------
Async Postgres client (asyncpg + connection pool) talking to an
EXTERNALLY hosted database -- not one of your 4 allotted containers.
asyncpg is used (not psycopg2) because psycopg2 is blocking: a
blocking DB call inside an aiohttp handler freezes the entire event
loop for every other concurrent request on that node. asyncpg is
non-blocking and pools connections, which matters once your load
generator ramps concurrency.
"""
import os
import asyncpg
from dotenv import load_dotenv
from cryptography.fernet import Fernet

load_dotenv()

DB_HOST = os.environ.get("CHAT_DB_HOST")
DB_PORT = int(os.environ.get("CHAT_DB_PORT", "5432"))
DB_NAME = os.environ.get("CHAT_DB_NAME")
DB_USER = os.environ.get("CHAT_DB_USER")
DB_PASS = os.environ.get("CHAT_DB_PASS")


async def get_connection():
    """Returns a connection POOL (kept as 'conn' for call-site
    compatibility with the rest of the app)."""
    return await asyncpg.create_pool(
        host=DB_HOST, port=DB_PORT, database=DB_NAME,
        user=DB_USER, password=DB_PASS,
        min_size=2, max_size=10,
    )


async def init_db(pool):
    async with pool.acquire() as conn:
        await conn.execute("""
        CREATE TABLE IF NOT EXISTS messages (
            id                  SERIAL PRIMARY KEY,
            msg_id              TEXT UNIQUE NOT NULL,
            room_id             TEXT NOT NULL,
            sender              TEXT NOT NULL,
            ciphertext          TEXT NOT NULL,
            signature           TEXT NOT NULL,
            timestamp           TIMESTAMP DEFAULT now(),
            verified_at_insert  BOOLEAN NOT NULL
        )
        """)
        await conn.execute("""
        CREATE TABLE IF NOT EXISTS signers (
            username         TEXT PRIMARY KEY,
            public_key_pem   TEXT NOT NULL,
            private_key_pem  TEXT NOT NULL
        )
        """)
        await conn.execute("""
        CREATE TABLE IF NOT EXISTS server_secret (
            id INT PRIMARY KEY DEFAULT 1,
            fernet_key TEXT NOT NULL
        )
        """)
        await conn.execute("CREATE INDEX IF NOT EXISTS idx_messages_room ON messages(room_id)")


async def save_message(pool, msg_id, room_id, sender, ciphertext, signature, verified_at_insert):
    """Idempotent insert -- duplicate msg_id is silently ignored."""
    async with pool.acquire() as conn:
        await conn.execute(
            """
            INSERT INTO messages (msg_id, room_id, sender, ciphertext, signature, verified_at_insert)
            VALUES ($1, $2, $3, $4, $5, $6)
            ON CONFLICT (msg_id) DO NOTHING
            """,
            msg_id, room_id, sender, ciphertext, signature, verified_at_insert,
        )


async def load_room_messages(pool, room_id):
    async with pool.acquire() as conn:
        rows = await conn.fetch(
            "SELECT sender, ciphertext, signature, timestamp FROM messages WHERE room_id = $1 ORDER BY id",
            room_id,
        )
        return [(r["sender"], r["ciphertext"], r["signature"], r["timestamp"]) for r in rows]


async def load_all_messages(pool):
    async with pool.acquire() as conn:
        rows = await conn.fetch(
            "SELECT msg_id, room_id, sender, ciphertext, signature, timestamp FROM messages ORDER BY id"
        )
        return [
            (r["msg_id"], r["room_id"], r["sender"], r["ciphertext"], r["signature"], r["timestamp"])
            for r in rows
        ]


async def save_signing_key(pool, username, public_key_pem, private_key_pem):
    async with pool.acquire() as conn:
        await conn.execute(
            """
            INSERT INTO signers (username, public_key_pem, private_key_pem)
            VALUES ($1, $2, $3)
            ON CONFLICT (username) DO NOTHING
            """,
            username, public_key_pem, private_key_pem,
        )


async def load_signing_key(pool, username):
    """Returns (public_key_pem, private_key_pem) or None."""
    async with pool.acquire() as conn:
        row = await conn.fetchrow(
            "SELECT public_key_pem, private_key_pem FROM signers WHERE username = $1", username
        )
        return (row["public_key_pem"], row["private_key_pem"]) if row else None


async def get_or_create_fernet_key(pool):
    """One shared Fernet key for the whole cluster, stored in the DB
    instead of a local file -- so every backend node can decrypt
    every other node's ciphertext."""
    async with pool.acquire() as conn:
        row = await conn.fetchrow("SELECT fernet_key FROM server_secret WHERE id = 1")
        if row:
            return row["fernet_key"].encode()

        key = Fernet.generate_key()
        await conn.execute(
            "INSERT INTO server_secret (id, fernet_key) VALUES (1, $1) ON CONFLICT (id) DO NOTHING",
            key.decode(),
        )
        # Re-fetch in case two nodes started at the same instant and raced.
        row = await conn.fetchrow("SELECT fernet_key FROM server_secret WHERE id = 1")
        return row["fernet_key"].encode()