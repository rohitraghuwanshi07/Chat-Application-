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
      li.innerHTML = (data.user !== myName ? "<b>" + data.user + "</b><br>" : "") +
                     data.text +
                     '<span class="meta">' + data.time + '</span>';
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

    print(f"[{room}] {username} joined. Total in room: {len(rooms[room])}")

    await broadcast(room, {
        "type": "system",
        "text": f"{username} joined the room"
    })

    try:
        async for msg in ws:
            if msg.type == WSMsgType.TEXT:
                timestamp = datetime.now().strftime("%H:%M:%S")
                payload = {
                    "type": "message",
                    "user": username,
                    "text": msg.data,
                    "time": timestamp
                }
                print(f"[{room}] {username} ({timestamp}): {msg.data}")
                save_message(room, username, msg.data)
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
