"""
database.py
------------
Async PostgreSQL client using asyncpg and a local connection pool.

Each backend node has its own local PostgreSQL database.

The application layer is responsible for replicating messages
between backend nodes.
"""

import os

import asyncpg
from dotenv import load_dotenv
from cryptography.fernet import Fernet


load_dotenv()


# ============================================================
# DATABASE CONFIGURATION
# ============================================================

DB_HOST = os.environ.get(
    "CHAT_DB_HOST",
    "127.0.0.1",
)

DB_PORT = int(
    os.environ.get(
        "CHAT_DB_PORT",
        "5432",
    )
)

DB_NAME = os.environ.get(
    "CHAT_DB_NAME",
    "chatdb",
)

DB_USER = os.environ.get(
    "CHAT_DB_USER",
    "chatuser",
)

DB_PASS = os.environ.get(
    "CHAT_DB_PASS"
)


# ============================================================
# CONNECTION POOL
# ============================================================

async def get_connection():
    """
    Create and return the PostgreSQL connection pool.

    Each backend has its own local PostgreSQL instance.
    """

    return await asyncpg.create_pool(
        host=DB_HOST,
        port=DB_PORT,
        database=DB_NAME,
        user=DB_USER,
        password=DB_PASS,

        # Small minimum pool avoids unnecessary idle
        # PostgreSQL connections.
        min_size=5,

        # Allows concurrent HTTP requests and replication
        # operations to use separate DB connections.
        max_size=20,
    )


# ============================================================
# DATABASE INITIALIZATION
# ============================================================

async def init_db(pool):
    """
    Create application tables and indexes if they do not exist.
    """

    async with pool.acquire() as conn:

        # ----------------------------------------------------
        # Messages
        # ----------------------------------------------------

        await conn.execute(
            """
            CREATE TABLE IF NOT EXISTS messages (
                id                  SERIAL PRIMARY KEY,
                msg_id              TEXT UNIQUE NOT NULL,
                room_id             TEXT NOT NULL,
                sender              TEXT NOT NULL,
                ciphertext          TEXT NOT NULL,
                message_text        TEXT,
                signature            TEXT NOT NULL,
                timestamp           TIMESTAMP DEFAULT now(),
                verified_at_insert  BOOLEAN NOT NULL
            )
            """
        )

        # ----------------------------------------------------
        # Migration for existing installations
        # ----------------------------------------------------

        await conn.execute(
            """
            ALTER TABLE messages
            ADD COLUMN IF NOT EXISTS message_text TEXT
            """
        )

        # ----------------------------------------------------
        # Signers
        # ----------------------------------------------------

        await conn.execute(
            """
            CREATE TABLE IF NOT EXISTS signers (
                username         TEXT PRIMARY KEY,
                public_key_pem   TEXT NOT NULL,
                private_key_pem  TEXT NOT NULL
            )
            """
        )

        # ----------------------------------------------------
        # Server secret
        # ----------------------------------------------------

        await conn.execute(
            """
            CREATE TABLE IF NOT EXISTS server_secret (
                id INT PRIMARY KEY DEFAULT 1,
                fernet_key TEXT NOT NULL
            )
            """
        )

        # ----------------------------------------------------
        # Indexes
        # ----------------------------------------------------

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
            CREATE INDEX IF NOT EXISTS
            idx_messages_room_timestamp
            ON messages(room_id, timestamp DESC)
            """
        )


# ============================================================
# SAVE MESSAGE
# ============================================================

async def save_message(
    pool,
    msg_id,
    room_id,
    sender,
    message_text,
    ciphertext,
    signature,
    verified_at_insert,
):
    """
    Idempotently insert a message.

    Returns:

        True
            if this call inserted the message.

        False
            if msg_id already existed.

    This is important for replication because the same message
    may arrive more than once.
    """

    async with pool.acquire() as conn:

        result = await conn.execute(
            """
            INSERT INTO messages (
                msg_id,
                room_id,
                sender,
                message_text,
                ciphertext,
                signature,
                verified_at_insert
            )
            VALUES (
                $1,
                $2,
                $3,
                $4,
                $5,
                $6,
                $7
            )
            ON CONFLICT (msg_id)
            DO NOTHING
            """,
            msg_id,
            room_id,
            sender,
            message_text,
            ciphertext,
            signature,
            verified_at_insert,
        )

    return result == "INSERT 0 1"


# ============================================================
# LOAD ROOM MESSAGES
# ============================================================

async def load_room_messages(
    pool,
    room_id,
    limit=1000,
):
    """
    Load the newest messages for one room.
    """

    limit = max(
        1,
        min(
            int(limit),
            5000,
        ),
    )

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
                row["sender"],
                row["ciphertext"],
                row["signature"],
                row["timestamp"],
            )
            for row in rows
        ]


# ============================================================
# LOAD RECENT MESSAGES
# ============================================================

async def load_recent_messages(
    pool,
    limit=1000,
):
    """
    Load the newest messages from the local database.

    The limit prevents /feed from materializing an unbounded
    number of rows in backend memory.
    """

    limit = max(
        1,
        min(
            int(limit),
            100000,
        ),
    )

    async with pool.acquire() as conn:

        rows = await conn.fetch(
            """
            SELECT
                msg_id,
                room_id,
                sender,
                message_text,
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
                row["msg_id"],
                row["room_id"],
                row["sender"],
                row["message_text"],
                row["ciphertext"],
                row["signature"],
                row["timestamp"],
            )
            for row in rows
        ]


# ============================================================
# LOAD ALL MESSAGES
# ============================================================

async def load_all_messages(pool):
    """
    Compatibility helper.

    New code should prefer load_recent_messages().
    """

    async with pool.acquire() as conn:

        rows = await conn.fetch(
            """
            SELECT
                msg_id,
                room_id,
                sender,
                message_text,
                ciphertext,
                signature,
                timestamp
            FROM messages
            ORDER BY id
            """
        )

        return [
            (
                row["msg_id"],
                row["room_id"],
                row["sender"],
                row["message_text"],
                row["ciphertext"],
                row["signature"],
                row["timestamp"],
            )
            for row in rows
        ]


# ============================================================
# SIGNING KEYS
# ============================================================

async def save_signing_key(
    pool,
    username,
    public_key_pem,
    private_key_pem,
):
    """
    Save a user's signing keys if they do not already exist.
    """

    async with pool.acquire() as conn:

        await conn.execute(
            """
            INSERT INTO signers (
                username,
                public_key_pem,
                private_key_pem
            )
            VALUES (
                $1,
                $2,
                $3
            )
            ON CONFLICT (username)
            DO NOTHING
            """,
            username,
            public_key_pem,
            private_key_pem,
        )


async def load_signing_key(
    pool,
    username,
):
    """
    Return:

        (public_key_pem, private_key_pem)

    or:

        None
    """

    async with pool.acquire() as conn:

        row = await conn.fetchrow(
            """
            SELECT
                public_key_pem,
                private_key_pem
            FROM signers
            WHERE username = $1
            """,
            username,
        )

        if not row:
            return None

        return (
            row["public_key_pem"],
            row["private_key_pem"],
        )


# ============================================================
# FERNET KEY
# ============================================================

async def get_or_create_fernet_key(pool):
    """
    Get or create the Fernet key stored in this backend's
    local database.

    Each backend therefore owns its own local Fernet key.

    /feed uses message_text directly, so cross-node replication
    does not require decrypting another node's ciphertext.
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

        # ----------------------------------------------------
        # Generate new key
        # ----------------------------------------------------

        key = Fernet.generate_key()

        await conn.execute(
            """
            INSERT INTO server_secret (
                id,
                fernet_key
            )
            VALUES (
                1,
                $1
            )
            ON CONFLICT (id)
            DO NOTHING
            """,
            key.decode(),
        )

        # ----------------------------------------------------
        # Read actual stored key
        # ----------------------------------------------------

        row = await conn.fetchrow(
            """
            SELECT fernet_key
            FROM server_secret
            WHERE id = 1
            """
        )

        return row["fernet_key"].encode()