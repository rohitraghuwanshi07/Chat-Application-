# Real-Time Group Chat -- CS559 Lab 4

## Requirements checklist

| # | Requirement | Where it's satisfied |
|---|---|---|
| 1 | Messages stored in a database | `backend/database.py` (SQLite `messages` table) |
| 2 | User receives previous chat history | `chat_handler.build_history_payloads()`, sent right after joining |
| 3 | Messages not stored as plaintext | `crypto_utils.encrypt_text/decrypt_text` (Fernet/AES) -- DB column is `ciphertext`, never `message` |
| 4 | System detects modification of a stored message | Signature is re-checked live on every history load, see `verify_signature()` and `tamper_demo.py` |
| 5 | Each sender has a signing key pair | `crypto_utils.generate_signing_keypair()`, one Ed25519 pair per username |
| 6 | Messages contain a sender signature, and it's verified | `sign_text()` / `verify_signature()` in `chat_handler.py` |

## Project layout

```
websocket-chat-app/
├── backend/
│   ├── server.py          entry point -- run this
│   ├── chat_handler.py    websocket connections, broadcasting, sign+encrypt pipeline
│   ├── crypto_utils.py    signing (Ed25519) + encryption at rest (Fernet)
│   ├── database.py        SQLite storage, no crypto knowledge
│   ├── tamper_demo.py     script to simulate/demo an attack for grading
│   └── requirements.txt
└── frontend/               React app (Vite)
    ├── index.html
    ├── package.json
    ├── vite.config.js
    └── src/
        ├── main.jsx
        ├── App.jsx
        ├── index.css
        ├── hooks/useChatSocket.js   all websocket connection logic
        └── components/
            ├── JoinScreen.jsx
            ├── ChatRoom.jsx
            ├── MessageList.jsx
            ├── Message.jsx           renders the signature verification chip
            └── MessageInput.jsx
```

## Running it

You need the backend running AND the frontend built/served. Two ways:

### Option A -- production style (one server, one port)

```bash
# 1. Build the React app into static files
cd frontend
npm install
npm run build      # outputs frontend/dist/

# 2. Run the backend, which serves that build
cd ../backend
pip install -r requirements.txt
python3 server.py
```

Open `http://localhost:3210`.

### Option B -- frontend dev mode (hot reload while you edit React code)

```bash
# terminal 1: backend
cd backend
pip install -r requirements.txt
python3 server.py

# terminal 2: frontend dev server
cd frontend
npm install
npm run dev
```

Open `http://localhost:5173`. Vite proxies `/ws` traffic to the backend
on `:3210` (see `vite.config.js`) so the React code never hardcodes a
backend URL -- it always just connects to its own origin.

Open two browser tabs to chat with yourself.

The first backend run creates two files inside `backend/`:
- `chat.db` -- the SQLite database (encrypted message bodies)
- `server_secret.key` -- the encryption key. **Never commit this file.**
  If you lose it, every stored message becomes permanently undecryptable
  (that's the point of encryption).

## Demoing tamper detection

```bash
# 1. run server, send a couple of messages, then Ctrl+C
cd backend
python3 tamper_demo.py
python3 server.py
```

Rejoin the same room -- the tampered message shows a red "unverified"
badge, everything else still shows green "verified".

## Concepts, briefly

- **Signing (Ed25519)** proves *who* sent a message and that the exact
  text hasn't changed since they sent it. It does **not** hide content.
- **Encryption (Fernet)** hides content from anyone reading the raw
  database file. It does **not** prove who wrote something.
  You need both to satisfy every requirement -- that's why there are
  two different keys in this system (per-user signing keys, one
  server-wide encryption key).
