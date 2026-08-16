"""
tamper_demo.py
----------------
A standalone script for DEMONSTRATING requirement 4 (tamper detection).

THREAT MODEL: someone with access to chat.db AND server_secret.key (e.g.
a stolen backup) can decrypt and even re-encrypt a message. What they
CANNOT do is produce a valid new signature for their edited text,
because signing private keys only ever exist in the server's memory
while it's running -- never on disk. So the OLD signature stays in the
row, now describing text that no longer matches it.

How to use it for your demo/screenshots:
    1. Run the server, send a few chat messages normally.
    2. Stop the server (Ctrl+C).
    3. Run:  python3 tamper_demo.py
    4. Start the server again:  python3 server.py
    5. Open the chat, join the same room the tampered message was in.
       That message now shows "unverified" (red), everything else
       still shows "verified" (green).
"""

import sqlite3
from cryptography.fernet import Fernet

import crypto_utils

DB_PATH = "chat.db"
TAMPER_PREFIX = "[TAMPERED] "


def main():
    key = crypto_utils.load_or_create_encryption_key()
    fernet = Fernet(key)

    conn = sqlite3.connect(DB_PATH)
    row = conn.execute(
        "SELECT id, room_id, sender, ciphertext FROM messages ORDER BY id DESC LIMIT 1"
    ).fetchone()

    if row is None:
        print("No messages found in chat.db. Send a message in the chat first.")
        conn.close()
        return

    msg_id, room_id, sender, ciphertext = row
    plaintext = crypto_utils.decrypt_text(fernet, ciphertext)

    if plaintext is None:
        print("Could not decrypt that message -- it's already corrupted.")
        conn.close()
        return

    if plaintext.startswith(TAMPER_PREFIX):
        print(f"Message id {msg_id} already looks tampered. Nothing to do.")
        conn.close()
        return

    tampered_plaintext = TAMPER_PREFIX + plaintext
    # The "attacker" re-encrypts so the row still decrypts cleanly --
    # but the signature stored alongside it still belongs to the
    # ORIGINAL text, so verification of the new text will fail.
    tampered_ciphertext = crypto_utils.encrypt_text(fernet, tampered_plaintext)

    conn.execute("UPDATE messages SET ciphertext = ? WHERE id = ?", (tampered_ciphertext, msg_id))
    conn.commit()
    conn.close()

    print("Tamper applied.")
    print(f"  Row id:  {msg_id}")
    print(f"  Room:    {room_id}")
    print(f"  Sender:  {sender}")
    print(f"  Before:  {plaintext}")
    print(f"  After:   {tampered_plaintext}")
    print()
    print("The stored signature was left untouched -- it still matches only")
    print("the ORIGINAL text. Restart the server and rejoin that room to see")
    print("this message flip to 'unverified'.")


if __name__ == "__main__":
    main()
