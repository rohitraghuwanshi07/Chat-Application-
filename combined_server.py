"""
Real-Time Group Chat Application (WebSockets)
Course: CS559 -- Computer System Design

A single Python file that does two jobs:
 1. Serves the frontend web page (HTML + CSS + JS) at "/"
 2. Handles live WebSocket chat connections and message broadcasting at "/ws"

Implementations in this version (Lab 4 - Part 5 & 6):
 - Each sender gets an Ed25519 signing key pair the first time they're seen.
   Public keys are stored permanently in the "signers" table. Private keys
   are kept in memory only (server-side), since the server signs on behalf
   of each connected user for this lab.
 - Every message is signed right after it's received, and the signature is
   verified immediately using the sender's stored public key. The
   "verified" flag travels with the message (live broadcast + stored in DB).
 - When chat history is loaded, every old message is RE-verified live
   against its stored signature and public key. If a message was tampered
   with in the database after being signed, verification will now fail,
   even though the "verified" column in the DB might still say 1 (True)
   from when it was originally saved. This is how tamper detection is
   demonstrated.

Run with:
    python3 combined_server.py

The server listens on 0.0.0.0:3210 by default.
"""

from aiohttp import web, WSMsgType
from datetime import datetime
import sqlite3
import base64

from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)
from cryptography.hazmat.primitives import serialization
from cryptography.exceptions import InvalidSignature

# rooms = { room_name: { websocket_connection: username } }
rooms = {}

# --- Persistence: SQLite database setup ---
conn = sqlite3.connect("chat.db", check_same_thread=False)
conn.execute("""
CREATE TABLE IF NOT EXISTS messages (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    room_id TEXT,
    sender TEXT,
    message TEXT,
    timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
    signature TEXT,
    verified BOOLEAN
)
""")

# NEW: table storing each sender's public key permanently. Private keys
# are never written to disk -- only kept in memory in `signing_keys` below.
conn.execute("""
CREATE TABLE IF NOT EXISTS signers (
    username TEXT PRIMARY KEY,
    public_key_pem TEXT
)
""")
conn.commit()


# ---------------------------------------------------------------------
# Digital signature helpers (Part 5 & 6)
# ---------------------------------------------------------------------

# In-memory map: username -> Ed25519PrivateKey object.
# This is intentionally NOT persisted to disk. If the server restarts,
# a returning username with an existing row in `signers` keeps their old
# public key (so their past messages still verify), but the server will
# no longer be able to *sign new* messages as that exact keypair unless
# we regenerate -- see get_or_create_signing_key() below for the policy
# used here.
signing_keys = {}


def _pubkey_to_pem(public_key: Ed25519PublicKey) -> str:
    pem_bytes = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    return pem_bytes.decode("utf-8")


def _pem_to_pubkey(pem_str: str) -> Ed25519PublicKey:
    return serialization.load_pem_public_key(pem_str.encode("utf-8"))


def get_or_create_signing_key(username):
    
    if username in signing_keys:
        return signing_keys[username]

    private_key = Ed25519PrivateKey.generate()
    public_key = private_key.public_key()
    signing_keys[username] = private_key

    conn.execute(
        """
        INSERT INTO signers(username, public_key_pem) VALUES (?, ?)
        ON CONFLICT(username) DO UPDATE SET public_key_pem = excluded.public_key_pem
        """,
        (username, _pubkey_to_pem(public_key)),
    )
    conn.commit()

    return private_key


def get_stored_public_key(username):
    """Loads a username's public key from the `signers` table, or None."""
    cursor = conn.execute(
        "SELECT public_key_pem FROM signers WHERE username = ?",
        (username,),
    )
    row = cursor.fetchone()
    if row is None:
        return None
    return _pem_to_pubkey(row[0])


def sign_message(username, text):
    """Signs `text` with `username`'s private key. Returns base64 signature."""
    private_key = get_or_create_signing_key(username)
    signature_bytes = private_key.sign(text.encode("utf-8"))
    return base64.b64encode(signature_bytes).decode("ascii")


def verify_message(username, text, signature_b64):
    """
    Verifies that `signature_b64` is a valid Ed25519 signature of `text`
    under `username`'s stored public key. Returns True/False -- never
    raises, so a tampered/garbage signature just fails verification
    instead of crashing anything that calls this.
    """
    if not signature_b64:
        return False

    public_key = get_stored_public_key(username)
    if public_key is None:
        return False

    try:
        signature_bytes = base64.b64decode(signature_b64)
        public_key.verify(signature_bytes, text.encode("utf-8"))
        return True
    except (InvalidSignature, ValueError):
        return False


# ---------------------------------------------------------------------
# Persistence helpers
# ---------------------------------------------------------------------

def save_message(room_id, sender, message, signature, verified):
    conn.execute(
        """
        INSERT INTO messages(room_id, sender, message, signature, verified)
        VALUES (?, ?, ?, ?, ?)
        """,
        (room_id, sender, message, signature, verified)
    )
    conn.commit()


def get_history(room_id):
    """
    Returns all stored messages for a room, ordered oldest-first, each
    re-verified LIVE against the stored signature and the sender's
    current public key (rather than trusting the stored `verified`
    column). This is what makes tamper detection visible: if a row's
    `message` text is edited directly in the database after being
    signed, this live re-check will now return False even though the
    original `verified` value saved at insert time was True.
    """
    cursor = conn.execute(
        """
        SELECT sender, message, timestamp, signature
        FROM messages
        WHERE room_id = ?
        ORDER BY id
        """,
        (room_id,)
    )
    rows = cursor.fetchall()

    history = []
    for sender, message, timestamp, signature in rows:
        verified_now = verify_message(sender, message, signature)
        history.append({
            "user": sender,
            "text": message,
            "time": timestamp,
            "verified": verified_now,
        })
    return history


HTML_PAGE = """
<!DOCTYPE html>
<html>
<head>
<title>WebSocket Chat</title>
<style>
  * { box-sizing: border-box; }
  body {
    font-family: -apple-system, "Segoe UI", Roboto, sans-serif;
    background: #f0f2f5;
    margin: 0;
    display: flex;
    justify-content: center;
    align-items: center;
    height: 100vh;
  }
  #setup {
    background: white;
    padding: 32px;
    border-radius: 12px;
    box-shadow: 0 4px 20px rgba(0,0,0,0.1);
    width: 320px;
    text-align: center;
  }
  #setup h2 { margin-top: 0; color: #1a1a1a; }
  #setup input {
    width: 100%;
    padding: 10px;
    margin: 8px 0;
    border: 1px solid #ddd;
    border-radius: 6px;
    font-size: 14px;
  }
  #setup button {
    width: 100%;
    padding: 10px;
    margin-top: 8px;
    background: #4f46e5;
    color: white;
    border: none;
    border-radius: 6px;
    font-size: 14px;
    cursor: pointer;
  }
  #setup button:hover { background: #4338ca; }

  #chatbox {
    display: none;
    background: white;
    width: 400px;
    height: 560px;
    border-radius: 12px;
    box-shadow: 0 4px 20px rgba(0,0,0,0.1);
    flex-direction: column;
    overflow: hidden;
  }
  #chat-header {
    background: #4f46e5;
    color: white;
    padding: 14px 16px;
    font-weight: 600;
  }
  #messages {
    list-style: none;
    margin: 0;
    padding: 12px;
    flex: 1;
    overflow-y: auto;
    background: #fafafa;
  }
  #messages li {
    margin-bottom: 10px;
    padding: 8px 12px;
    border-radius: 10px;
    background: #e5e7eb;
    max-width: 80%;
    font-size: 14px;
    word-wrap: break-word;
  }
  #messages li.me {
    background: #4f46e5;
    color: white;
    margin-left: auto;
    text-align: right;
  }
  #messages li.system {
    background: transparent;
    color: #888;
    font-size: 12px;
    text-align: center;
    max-width: 100%;
  }
  .meta {
    display: block;
    font-size: 10px;
    opacity: 0.7;
    margin-top: 3px;
  }
  .sig-badge {
    display: inline-block;
    font-size: 10px;
    margin-left: 6px;
    font-weight: 600;
  }
  .sig-ok { color: #16a34a; }
  li.me .sig-ok { color: #bbf7d0; }
  .sig-bad { color: #dc2626; }
  li.me .sig-bad { color: #fecaca; }
  #input-row {
    display: flex;
    padding: 10px;
    border-top: 1px solid #eee;
  }
  #msg {
    flex: 1;
    padding: 10px;
    border: 1px solid #ddd;
    border-radius: 6px;
    font-size: 14px;
  }
  #input-row button {
    margin-left: 8px;
    padding: 10px 16px;
    background: #4f46e5;
    color: white;
    border: none;
    border-radius: 6px;
    cursor: pointer;
  }
</style>
</head>
<body>

  <div id="setup">
    <h2>Join Chat</h2>
    <input id="username" placeholder="Your name">
    <input id="room" placeholder="Room name (e.g. friends)">
    <button onclick="joinChat()">Join Chat</button>
  </div>

  <div id="chatbox">
    <div id="chat-header">Room: <span id="roomLabel"></span></div>
    <ul id="messages"></ul>
    <div id="input-row">
      <input id="msg" placeholder="Type a message..." onkeydown="if(event.key==='Enter') send()">
      <button onclick="send()">Send</button>
    </div>
  </div>

<script>
  let ws;
  let myName;

  function joinChat() {
    myName = document.getElementById("username").value.trim();
    const room = document.getElementById("room").value.trim() || "general";
    if (!myName) return alert("Please enter your name");

    document.getElementById("setup").style.display = "none";
    document.getElementById("chatbox").style.display = "flex";
    document.getElementById("roomLabel").textContent = room;

    const proto = location.protocol === "https:" ? "wss" : "ws";
    ws = new WebSocket(proto + "://" + location.host + "/ws?name=" + encodeURIComponent(myName) + "&room=" + encodeURIComponent(room));

    ws.onmessage = (event) => {
      const data = JSON.parse(event.data);
      addMessage(data);
    };
  }

  function addMessage(data) {
    const li = document.createElement("li");
    if (data.type === "system") {
      li.className = "system";
      li.textContent = data.text;
    } else {
      li.className = data.user === myName ? "me" : "";

      let sigHtml = "";
      if (data.verified === true) {
        sigHtml = '<span class="sig-badge sig-ok">&#10003; verified</span>';
      } else if (data.verified === false) {
        sigHtml = '<span class="sig-badge sig-bad">&#9888; unverified</span>';
      }

      li.innerHTML = (data.user !== myName ? "<b>" + data.user + "</b><br>" : "") +
                     data.text +
                     '<span class="meta">' + data.time + sigHtml + '</span>';
    }
    document.getElementById("messages").appendChild(li);
    document.getElementById("messages").scrollTop = document.getElementById("messages").scrollHeight;
  }

  function send() {
    const input = document.getElementById("msg");
    if (input.value.trim() !== "") {
      ws.send(input.value);
      input.value = "";
    }
  }
</script>
</body>
</html>
"""


async def index(request):
    """Serves the frontend HTML page."""
    return web.Response(text=HTML_PAGE, content_type="text/html")


async def broadcast(room, payload, exclude=None):
    """
    Sends `payload` to every client currently connected to `room`,
    except the one passed as `exclude` (used to avoid echoing a
    system message back to the person who triggered it, if needed).

    If a client's connection is in the process of closing, sending
    to it will raise an exception. Instead of letting that crash the
    whole broadcast (and take down messages meant for everyone else),
    we catch it, mark that client as dead, and clean it up afterwards.
    This is what makes disconnect handling graceful under real
    multi-user conditions, not just when a single user leaves at a time.
    """
    dead_clients = []
    for client in list(rooms.get(room, {})):
        if client != exclude:
            try:
                await client.send_json(payload)
            except Exception:
                dead_clients.append(client)

    for dead in dead_clients:
        if dead in rooms.get(room, {}):
            del rooms[room][dead]


async def websocket_handler(request):
    ws = web.WebSocketResponse()
    await ws.prepare(request)

    username = request.query.get("name", "Anonymous")
    room = request.query.get("room", "general")

    if room not in rooms:
        rooms[room] = {}
    rooms[room][ws] = username

    # Make sure this user has a signing key pair (generates one on first
    # sight of this username; reuses it for the rest of this server run).
    get_or_create_signing_key(username)

    print(f"[{room}] {username} joined. Total in room: {len(rooms[room])}")

    await broadcast(room, {
        "type": "system",
        "text": f"{username} joined the room"
    })

    # NEW: send this joining client the room's chat history, with every
    # message re-verified live against its stored signature.
    for old_message in get_history(room):
        await ws.send_json({
            "type": "message",
            "user": old_message["user"],
            "text": old_message["text"],
            "time": old_message["time"],
            "verified": old_message["verified"],
        })

    try:
        async for msg in ws:
            if msg.type == WSMsgType.TEXT:
                timestamp = datetime.now().strftime("%H:%M:%S")

                # NEW: sign the message right after receiving it, then
                # verify it immediately using the sender's stored public
                # key. In normal operation this will always be True --
                # it only becomes False later if the stored row is
                # tampered with directly in the database.
                signature = sign_message(username, msg.data)
                verified = verify_message(username, msg.data, signature)

                payload = {
                    "type": "message",
                    "user": username,
                    "text": msg.data,
                    "time": timestamp,
                    "verified": verified
                }
                print(f"[{room}] {username} ({timestamp}): {msg.data} "
                      f"[signed, verified={verified}]")
                save_message(room, username, msg.data, signature, verified)
                await broadcast(room, payload)
    finally:
        # Runs no matter how the connection ends (tab closed, browser
        # crashed, network dropped) -- this is our graceful
        # disconnect handling.
        if room in rooms and ws in rooms[room]:
            del rooms[room][ws]
            print(f"[{room}] {username} left. Total in room: {len(rooms[room])}")
            await broadcast(room, {
                "type": "system",
                "text": f"{username} left the room"
            })

    return ws


app = web.Application()
app.router.add_get("/", index)
app.router.add_get("/ws", websocket_handler)

if __name__ == "__main__":
    web.run_app(app, host="0.0.0.0", port=3210)