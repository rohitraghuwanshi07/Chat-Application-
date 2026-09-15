"""
database.py
------------
Async PostgreSQL client using asyncpg and a local connection pool.

Each backend node has its own local PostgreSQL database.

The application layer is responsible for replicating messages between
backend nodes.
"""

import os

import asyncpg
from dotenv import load_dotenv
from cryptography.fernet import Fernet


load_dotenv()

DB_HOST = os.environ.get("CHAT_DB_HOST", "127.0.0.1")
DB_PORT = int(os.environ.get("CHAT_DB_PORT", "5432"))
DB_NAME = os.environ.get("CHAT_DB_NAME", "chatdb")
DB_USER = os.environ.get("CHAT_DB_USER", "chatuser")
DB_PASS = os.environ.get("CHAT_DB_PASS")


async def get_connection():
    """Create and return the PostgreSQL connection pool."""
    return await asyncpg.create_pool(
        host=DB_HOST,
        port=DB_PORT,
        database=DB_NAME,
        user=DB_USER,
        password=DB_PASS,
        min_size=2,
        max_size=10,
    )


async def init_db(pool):
    """Create all application tables and indexes if they do not exist."""
    async with pool.acquire() as conn:
        await conn.execute(
            """
            CREATE TABLE IF NOT EXISTS messages (
                id                  SERIAL PRIMARY KEY,
                msg_id              TEXT UNIQUE NOT NULL,
                room_id             TEXT NOT NULL,
                sender              TEXT NOT NULL,
                ciphertext          TEXT NOT NULL,
                signature            TEXT NOT NULL,
                timestamp            TIMESTAMP DEFAULT now(),
                verified_at_insert  BOOLEAN NOT NULL
            )
            """
        )

        await conn.execute(
            """
            CREATE TABLE IF NOT EXISTS signers (
                username         TEXT PRIMARY KEY,
                public_key_pem   TEXT NOT NULL,
                private_key_pem  TEXT NOT NULL
            )
            """
        )

        await conn.execute(
            """
            CREATE TABLE IF NOT EXISTS server_secret (
                id INT PRIMARY KEY DEFAULT 1,
                fernet_key TEXT NOT NULL
            )
            """
        )

        await conn.execute(
            """
            CREATE INDEX IF NOT EXISTS idx_messages_room
            ON messages(room_id)
            """
        )

        await conn.execute(
            """
            CREATE INDEX IF NOT EXISTS idx_messages_timestamp
            ON messages(timestamp DESC)
            """
        )

        await conn.execute(
            """
            CREATE INDEX IF NOT EXISTS idx_messages_room_timestamp
            ON messages(room_id, timestamp DESC)
            """
        )


async def save_message(
    pool,
    msg_id,
    room_id,
    sender,
    ciphertext,
    signature,
    verified_at_insert,
):
    """
    Idempotently insert a message.

    Returns True if this call inserted the message and False if the
    message already existed.
    """
    async with pool.acquire() as conn:
        result = await conn.execute(
            """
            INSERT INTO messages (
                msg_id,
                room_id,
                sender,
                ciphertext,
                signature,
                verified_at_insert
            )
            VALUES ($1, $2, $3, $4, $5, $6)
            ON CONFLICT (msg_id) DO NOTHING
            """,
            msg_id,
            room_id,
            sender,
            ciphertext,
            signature,
            verified_at_insert,
        )

    return result == "INSERT 0 1"


async def load_room_messages(pool, room_id, limit=1000):
    """Load the newest messages for one room."""
    limit = max(1, min(int(limit), 5000))

    async with pool.acquire() as conn:
        rows = await conn.fetch(
            """
            SELECT
                sender,
                ciphertext,
                signature,
                timestamp
            FROM messages
            WHERE room_id = $1
            ORDER BY timestamp DESC, id DESC
            LIMIT $2
            """,
            room_id,
            limit,
        )

        return [
            (
                r["sender"],
                r["ciphertext"],
                r["signature"],
                r["timestamp"],
            )
            for r in rows
        ]


async def load_recent_messages(pool, limit=1000):
    """
    Load the newest messages from the local database.

    The limit prevents /feed from materializing an unbounded number of
    rows in backend memory.
    """
    limit = max(1, min(int(limit), 5000))

    async with pool.acquire() as conn:
        rows = await conn.fetch(
            """
            SELECT
                msg_id,
                room_id,
                sender,
                ciphertext,
                signature,
                timestamp
            FROM messages
            ORDER BY timestamp DESC, id DESC
            LIMIT $1
            """,
            limit,
        )

        return [
            (
                r["msg_id"],
                r["room_id"],
                r["sender"],
                r["ciphertext"],
                r["signature"],
                r["timestamp"],
            )
            for r in rows
        ]


async def load_all_messages(pool):
    """
    Compatibility helper.

    New code should prefer load_recent_messages() so that /feed does
    not create an unbounded memory allocation.
    """
    async with pool.acquire() as conn:
        rows = await conn.fetch(
            """
            SELECT
                msg_id,
                room_id,
                sender,
                ciphertext,
                signature,
                timestamp
            FROM messages
            ORDER BY id
            """
        )

        return [
            (
                r["msg_id"],
                r["room_id"],
                r["sender"],
                r["ciphertext"],
                r["signature"],
                r["timestamp"],
            )
            for r in rows
        ]


async def save_signing_key(pool, username, public_key_pem, private_key_pem):
    async with pool.acquire() as conn:
        await conn.execute(
            """
            INSERT INTO signers (
                username,
                public_key_pem,
                private_key_pem
            )
            VALUES ($1, $2, $3)
            ON CONFLICT (username) DO NOTHING
            """,
            username,
            public_key_pem,
            private_key_pem,
        )


async def load_signing_key(pool, username):
    """Return (public_key_pem, private_key_pem) or None."""
    async with pool.acquire() as conn:
        row = await conn.fetchrow(
            """
            SELECT public_key_pem, private_key_pem
            FROM signers
            WHERE username = $1
            """,
            username,
        )

        return (
            (row["public_key_pem"], row["private_key_pem"])
            if row
            else None
        )


async def get_or_create_fernet_key(pool):
    """
    Get or create the Fernet key stored in this backend's database.

    NOTE:
    With per-node databases, this creates one key per node. The current
    /feed implementation returns the stored ciphertext directly, so
    replication does not require cross-node Fernet decryption.
    """
    async with pool.acquire() as conn:
        row = await conn.fetchrow(
            """
            SELECT fernet_key
            FROM server_secret
            WHERE id = 1
            """
        )

        if row:
            return row["fernet_key"].encode()

        key = Fernet.generate_key()

        await conn.execute(
            """
            INSERT INTO server_secret (id, fernet_key)
            VALUES (1, $1)
            ON CONFLICT (id) DO NOTHING
            """,
            key.decode(),
        )

        row = await conn.fetchrow(
            """
            SELECT fernet_key
            FROM server_secret
            WHERE id = 1
            """
        )

        return row["fernet_key"].encode()