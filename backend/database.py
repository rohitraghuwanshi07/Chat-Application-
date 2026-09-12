"""
database.py
------------
ONLY job: talk to PostgreSQL. Nothing in here knows about encryption or
signatures -- it just stores and retrieves whatever strings it's given.

This is the plain/basic Postgres version: one connection, no pooling,
no replicas, no sharding. It exists to prove the migration works before
adding any performance optimizations.

WHY SEPARATE FILE:
Everything else in the app (server.py, chat_handler.py) only calls the
functions below -- it never talks to the database directly. That's why
swapping SQLite for PostgreSQL only required editing this one file.

CONNECTION:
Set these via environment variables (all have local defaults so it
runs out of the box against a local Postgres install):

    DB_HOST      (default: localhost)
    DB_PORT      (default: 5432)
    DB_NAME      (default: chatdb)
    DB_USER      (default: postgres)
    DB_PASSWORD  (default: postgres)
"""

import os
import uuid
import psycopg2
import psycopg2.extras

DB_HOST = "10.1.75.79"
DB_PORT = "3214"
DB_NAME = "chatdb"
DB_USER = "chatuser"
DB_PASSWORD = "password"


def get_connection():
    """Opens a connection to the shared Postgres database."""
    return psycopg2.connect(
        host=DB_HOST,
        port=DB_PORT,
        dbname=DB_NAME,
        user=DB_USER,
        password=DB_PASSWORD,
    )


def init_db(conn):
    """Creates the two tables we need, if they don't already exist."""

    cursor = conn.cursor()

    # `ciphertext` -- NOT `message` -- because we never store plaintext.
    cursor.execute("""
    CREATE TABLE IF NOT EXISTS messages (
        id                  SERIAL PRIMARY KEY,
        message_id          TEXT UNIQUE,
        room_id             TEXT NOT NULL,
        sender              TEXT NOT NULL,
        ciphertext          TEXT NOT NULL,
        signature           TEXT NOT NULL,
        timestamp           TIMESTAMPTZ DEFAULT NOW(),
        verified_at_insert  BOOLEAN NOT NULL
    )
    """)

    # One row per username: their permanent PUBLIC key. Private keys are
    # never written here -- see crypto_utils.py for why.
    cursor.execute("""
    CREATE TABLE IF NOT EXISTS signers (
        username        TEXT PRIMARY KEY,
        public_key_pem  TEXT NOT NULL
    )
    """)

    conn.commit()
    cursor.close()


def save_message(conn, room_id, sender, ciphertext, signature, verified_at_insert, message_id=None):
    """Saves a message with deduplication by message_id.
    Returns (message_id, inserted).

    ON CONFLICT DO NOTHING is what guarantees no duplicate rows even if
    the same message_id is sent twice (retry, reconnect, etc.) -- the
    database enforces this, not the application.
    """
    if not message_id:
        message_id = str(uuid.uuid4())

    cursor = conn.cursor()
    cursor.execute(
        """
        INSERT INTO messages (message_id, room_id, sender, ciphertext, signature, verified_at_insert)
        VALUES (%s, %s, %s, %s, %s, %s)
        ON CONFLICT (message_id) DO NOTHING
        """,
        (message_id, room_id, sender, ciphertext, signature, verified_at_insert),
    )
    conn.commit()
    inserted = cursor.rowcount > 0
    cursor.close()
    return message_id, inserted


def load_room_messages(conn, room_id):
    """Returns (message_id, sender, ciphertext, signature, timestamp) for every
    message in a room, oldest first."""
    cursor = conn.cursor()
    cursor.execute(
        """
        SELECT COALESCE(message_id, CAST(id AS TEXT)), sender, ciphertext, signature, timestamp
        FROM messages
        WHERE room_id = %s
        ORDER BY id
        """,
        (room_id,),
    )
    rows = cursor.fetchall()
    cursor.close()
    return rows


def save_public_key(conn, username, public_key_pem):
    cursor = conn.cursor()
    cursor.execute(
        """
        INSERT INTO signers (username, public_key_pem) VALUES (%s, %s)
        ON CONFLICT (username) DO UPDATE SET public_key_pem = EXCLUDED.public_key_pem
        """,
        (username, public_key_pem),
    )
    conn.commit()
    cursor.close()


def load_public_key(conn, username):
    cursor = conn.cursor()
    cursor.execute(
        "SELECT public_key_pem FROM signers WHERE username = %s",
        (username,),
    )
    row = cursor.fetchone()
    cursor.close()
    return row[0] if row else None