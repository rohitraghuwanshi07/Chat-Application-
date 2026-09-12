"""
database.py
------------
ONLY job: talk to SQLite. Nothing in here knows about encryption or
signatures -- it just stores and retrieves whatever strings it's given.

WHY SEPARATE FILE:
If you ever swap SQLite for PostgreSQL/MySQL, this is the only file
you'd need to touch. Nothing else in the app cares how storage works.
"""

import sqlite3

DB_PATH = "chat.db"


def get_connection():
    """Opens (or creates) chat.db and returns a connection to it."""
    return sqlite3.connect(DB_PATH, check_same_thread=False)


def init_db(conn):
    """Creates the two tables we need, if they don't already exist."""

    # `ciphertext` -- NOT `message` -- because we never store plaintext.
    conn.execute("""
    CREATE TABLE IF NOT EXISTS messages (
        id                  INTEGER PRIMARY KEY AUTOINCREMENT,
        message_id          TEXT UNIQUE,
        room_id             TEXT NOT NULL,
        sender              TEXT NOT NULL,
        ciphertext          TEXT NOT NULL,
        signature           TEXT NOT NULL,
        timestamp           DATETIME DEFAULT CURRENT_TIMESTAMP,
        verified_at_insert  BOOLEAN NOT NULL
    )
    """)

    # Migration for existing DBs that do not yet have message_id column
    cursor = conn.execute("PRAGMA table_info(messages)")
    columns = [row[1] for row in cursor.fetchall()]
    if "message_id" not in columns:
        conn.execute("ALTER TABLE messages ADD COLUMN message_id TEXT")
        conn.execute("CREATE UNIQUE INDEX IF NOT EXISTS idx_messages_message_id ON messages(message_id)")

    # One row per username: their permanent PUBLIC key. Private keys are
    # never written here -- see crypto_utils.py for why.
    conn.execute("""
    CREATE TABLE IF NOT EXISTS signers (
        username        TEXT PRIMARY KEY,
        public_key_pem  TEXT NOT NULL
    )
    """)
    conn.commit()


def save_message(conn, room_id, sender, ciphertext, signature, verified_at_insert, message_id=None):
    """Saves a message with deduplication by message_id.
    Returns (message_id, inserted).
    """
    if not message_id:
        import uuid
        message_id = str(uuid.uuid4())

    cursor = conn.execute(
        """
        INSERT OR IGNORE INTO messages (message_id, room_id, sender, ciphertext, signature, verified_at_insert)
        VALUES (?, ?, ?, ?, ?, ?)
        """,
        (message_id, room_id, sender, ciphertext, signature, verified_at_insert),
    )
    conn.commit()
    inserted = cursor.rowcount > 0
    return message_id, inserted


def load_room_messages(conn, room_id):
    """Returns (message_id, sender, ciphertext, signature, timestamp) for every
    message in a room, oldest first."""
    cursor = conn.execute(
        """
        SELECT COALESCE(message_id, CAST(id AS TEXT)), sender, ciphertext, signature, timestamp
        FROM messages
        WHERE room_id = ?
        ORDER BY id
        """,
        (room_id,),
    )
    return cursor.fetchall()


def save_public_key(conn, username, public_key_pem):
    conn.execute(
        """
        INSERT INTO signers (username, public_key_pem) VALUES (?, ?)
        ON CONFLICT(username) DO UPDATE SET public_key_pem = excluded.public_key_pem
        """,
        (username, public_key_pem),
    )
    conn.commit()


def load_public_key(conn, username):
    row = conn.execute(
        "SELECT public_key_pem FROM signers WHERE username = ?",
        (username,),
    ).fetchone()
    return row[0] if row else None
