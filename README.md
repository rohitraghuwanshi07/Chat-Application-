markdown
# Secure Persistent Group Chat

A real-time WebSocket group chat application, extended with persistent storage, encryption, and cryptographic message signing/verification.

**Course:** CS559 — Computer System Design
**Assignment:** Secure Persistent Group Chat

---

## Tech Stack

| Part | Technology |
|---|---|
| Backend | Python 3, `aiohttp` (WebSocket + HTTP server in one process) |
| Database | SQLite (`chat.db`) |
| Encryption | Symmetric encryption (Fernet/AES) — messages stored as ciphertext, never plaintext |
| Integrity | HMAC — detects tampering of stored messages |
| Signing | Asymmetric key pairs (per sender) — every message is signed and verified |
| Frontend | HTML, CSS, JavaScript (no framework) |

---

## Features

- ✅ Real-time group chat over WebSockets, multiple rooms supported
- ✅ Messages persisted in a SQLite database
- ✅ New users receive full chat history for the room they join
- ✅ Messages are stored as **ciphertext**, never as plaintext
- ✅ Every stored message carries a **signature** and is verified on insert
- ✅ **Tamper detection:** if a message is altered directly in the database, re-verification on the next load flags it as **unverified**
- ✅ Usernames shown with every message
- ✅ Join / leave notifications
- ✅ Graceful handling of client disconnections

---

## How to Run

1. Install dependencies:
```bash
   pip install aiohttp cryptography
```

2. Start the server:
```bash
   python3 combined_server.py
```
   Server runs on `http://0.0.0.0:3302` by default.

3. Open in a browser:
http://localhost:3302
   or from another device on the same network:
http://<server-ip>:3302

4. Enter a username and room name, then join. Open the same link in another tab/device with the same room name to chat with others in real time.

---

## Database Schema

```sql
CREATE TABLE messages (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    room_id TEXT,
    sender TEXT,
    ciphertext TEXT,
    signature TEXT,
    timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
    verified_at_insert BOOLEAN
);

CREATE TABLE signers (
    username TEXT PRIMARY KEY,
    public_key_pem TEXT
);
```

- `messages.ciphertext` — the encrypted message content (never stored as plaintext)
- `messages.signature` — the sender's digital signature over the original message
- `messages.verified_at_insert` — whether the signature was valid at the time the message was saved
- `signers.public_key_pem` — each user's public key, used to re-verify their messages later

---

## Verifying Tamper Detection Yourself

1. Send a message in the chat.
2. Inspect the database directly:
```bash
   sqlite3 chat.db "SELECT id, sender, ciphertext FROM messages ORDER BY id DESC LIMIT 1;"
```
3. Tamper with that row's `ciphertext` directly in the database (bypassing the app).
4. Rejoin the same room in the browser — the tampered message will now show as **unverified**, while untouched messages still show **signed**.

---

## Client URL (Live Testing)
http://10.1.75.51:3302

**SSH access to the hosting machine:**
```bash
ssh -p 2302 student@10.1.75.51
```

> Note: The client URL is only reachable while the server is actively running on the lab machine, and requires being on the same network. Contact the group if it appears unreachable.

---

## Known Limitation: Non-Repudiation

Private signing keys are currently generated and held **server-side** (per username, in server memory), not inside each client's browser. This means the system provides strong **tamper-evidence** (proven in the tamper-detection demo above) and correctly demonstrates asymmetric signing/verification, but does **not** provide full **non-repudiation** against a malicious server, since the server itself holds every user's private key. A true non-repudiation guarantee would require client-side key generation (e.g. via the browser's WebCrypto API). This is a deliberate, documented simplification for the scope of this assignment.

---

## Group Members

| S.No. | Name | Roll Number |
|---|---|---|
| 1 | Lakshay Gupta | 12341300 |
| 2 | Kabeer Vijay More | 12341030 |
| 3 | Rathod Chetan Kumar | 12341750 |
| 4 | Rohit Raghuwanshi | 12341820 |
