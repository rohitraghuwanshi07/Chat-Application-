"""
Real-Time Group Chat Application (WebSockets)
Course: CS559 -- Computer System Design

A single Python file that does two jobs:
 1. Serves the frontend web page (HTML + CSS + JS) at "/"
 2. Handles live WebSocket chat connections and message broadcasting at "/ws"

Run with:
    python3 combined_server.py

The server listens on 0.0.0.0:3210 by default.
"""

from aiohttp import web, WSMsgType
from datetime import datetime
import sqlite3
import base64
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
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
    timestamp DATETIME DEFAULT CURRENT_TIMESTAMP
)
""")
conn.commit()


def save_message(room_id, sender, message):
    conn.execute(
        """
        INSERT INTO messages(room_id, sender, message)
        VALUES (?, ?, ?)
        """,
        (room_id, sender, message)
    )
    conn.commit()


def get_history(room_id, limit=50):
    """Returns the last `limit` messages for a room, oldest first,
    so a newly-joined user can see what was said before they arrived."""
    cur = conn.execute(
        """
        SELECT sender, message, timestamp FROM messages
        WHERE room_id = ?
        ORDER BY id DESC LIMIT ?
        """,
        (room_id, limit)
    )
    rows = cur.fetchall()
    rows.reverse()  # oldest first, so they display in the right order
    history = []
    for sender, message, ts in rows:
        # timestamp is stored as full "YYYY-MM-DD HH:MM:SS"; just show the time part
        time_only = ts.split(" ")[1] if " " in ts else ts
        history.append({
            "type": "message",
            "user": sender,
            "text": message,
            "time": time_only,
            "verified": None  # historical messages weren't signed in this session, so no badge
        })
    return history


# ---------------------------------------------------------------
# SIGNING KEYS
# ---------------------------------------------------------------
# Each connected user gets their own Ed25519 key pair the moment
# they join. The private key is used to *sign* every message they
# send; the public key is used to *verify* that signature, proving
# the message genuinely came from them and was not altered.
#
# client_keys[ws]    -> that connection's private key (used to sign)
# client_pubkeys[ws] -> that connection's public key (used to verify)
client_keys = {}
client_pubkeys = {}

def generate_keypair():
    """Creates a new Ed25519 private/public key pair for a user."""
    private_key = Ed25519PrivateKey.generate()
    public_key = private_key.public_key()
    return private_key, public_key

def sign_message(private_key, text):
    """Signs the message text with the sender's private key.
    Returns the signature, base64-encoded so it can be sent as JSON."""
    signature = private_key.sign(text.encode("utf-8"))
    return base64.b64encode(signature).decode("utf-8")

def verify_message(public_key, text, signature_b64):
    """Checks that `signature_b64` really was produced by the holder
    of `public_key` signing exactly this `text`. Returns True/False."""
    try:
        signature = base64.b64decode(signature_b64)
        public_key.verify(signature, text.encode("utf-8"))
        return True
    except (InvalidSignature, Exception):
        return False

def public_key_fingerprint(public_key):
    """A short, human-readable stand-in for the full public key,
    just so the UI/logs can show 'which key' sent a message."""
    raw = public_key.public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw
    )
    return base64.b64encode(raw).decode("utf-8")[:12]

# ---------------------------------------------------------------

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
  .verified {
    color: #22c55e;
    font-weight: 600;
  }
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
      const badge = data.verified ? ' <span class="verified">&#10003; verified</span>' : "";
      li.innerHTML = (data.user !== myName ? "<b>" + data.user + "</b><br>" : "") +
                     data.text +
                     '<span class="meta">' + data.time + badge + '</span>';
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

    # Give this user their own signing key pair for this session
    private_key, public_key = generate_keypair()
    client_keys[ws] = private_key
    client_pubkeys[ws] = public_key

    print(f"[{room}] {username} joined. Total in room: {len(rooms[room])}")
    print(f"[{room}] {username}'s public key fingerprint: {public_key_fingerprint(public_key)}")

    # Send this user the previous chat history for the room (only to them,
    # not broadcast to everyone else, since they're the only one who needs it)
    for old_message in get_history(room):
        await ws.send_json(old_message)

    await broadcast(room, {
        "type": "system",
        "text": f"{username} joined the room"
    })

    try:
        async for msg in ws:
            if msg.type == WSMsgType.TEXT:
                timestamp = datetime.now().strftime("%H:%M:%S")

                # Sign this message with the sender's private key
                signature = sign_message(private_key, msg.data)

                # Verify it right away using their public key -- this is
                # the same check any recipient could independently perform
                # to confirm the message is genuine and unaltered.
                is_verified = verify_message(public_key, msg.data, signature)
                if not is_verified:
                    print(f"[{room}] WARNING: signature verification FAILED for a message from {username} -- message dropped")
                    continue  # don't broadcast or save a message that fails verification

                payload = {
                    "type": "message",
                    "user": username,
                    "text": msg.data,
                    "time": timestamp,
                    "signature": signature,
                    "key_fingerprint": public_key_fingerprint(public_key),
                    "verified": is_verified
                }
                print(f"[{room}] {username} ({timestamp}): {msg.data}  [signature verified: {is_verified}]")
                save_message(room, username, msg.data)
                await broadcast(room, payload)
    finally:
        # Runs no matter how the connection ends (tab closed, browser
        # crashed, network dropped) -- this is our graceful
        # disconnect handling.
        client_keys.pop(ws, None)
        client_pubkeys.pop(ws, None)

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
