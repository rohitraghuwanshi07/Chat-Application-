"""
tamper_demo.py
Course: CS559 -- Computer System Design

A tiny standalone script for DEMONSTRATING tamper detection (Lab 4).

What it does:
    Connects to chat.db, finds the most recently stored message, and
    overwrites its `message` column with a modified version -- WITHOUT
    touching the `signature` column. This simulates an attacker (or a
    bug, or database corruption) changing a stored message after it was
    signed.

How to use it for your screenshots / demo video:
    1. Run the chat server and send a few messages normally.
    2. Stop the server (Ctrl+C).
    3. Run:  python3 tamper_demo.py
    4. Start the server again:  python3 combined_server.py
    5. Open the chat and join the same room the tampered message was in.
       The tampered message will load from history showing "unverified"
       (red badge), while every untouched message still shows "verified"
       (green badge) -- proving the signature check catches the change.

Run with:
    python3 tamper_demo.py
"""

import sqlite3

DB_PATH = "chat.db"
TAMPER_PREFIX = "[TAMPERED] "


def main():
    conn = sqlite3.connect(DB_PATH)

    row = conn.execute(
        """
        SELECT id, room_id, sender, message
        FROM messages
        ORDER BY id DESC
        LIMIT 1
        """
    ).fetchone()

    if row is None:
        print("No messages found in chat.db. Send a message in the chat first.")
        conn.close()
        return

    msg_id, room_id, sender, original_text = row

    if original_text.startswith(TAMPER_PREFIX):
        print(f"Message id {msg_id} already looks tampered. Nothing to do.")
        conn.close()
        return

    tampered_text = TAMPER_PREFIX + original_text

    conn.execute(
        "UPDATE messages SET message = ? WHERE id = ?",
        (tampered_text, msg_id),
    )
    conn.commit()
    conn.close()

    print("Tamper applied.")
    print(f"  Row id:      {msg_id}")
    print(f"  Room:        {room_id}")
    print(f"  Sender:      {sender}")
    print(f"  Before:      {original_text}")
    print(f"  After:       {tampered_text}")
    print()
    print("Signature was left untouched, so this row will now fail live")
    print("verification. Restart the server and rejoin that room to see it.")


if __name__ == "__main__":
    main()