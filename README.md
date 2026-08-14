# Real-Time Group Chat Application (WebSockets)

**Course:** CS559 -- Computer System Design
**Assignment:** Real-time Group Chat Application using WebSockets

A simple, real-time group chat app built to understand how WebSockets work. One backend server handles everyone's messages, and any number of people can open the same web page (on their own device) to join the chat.

---

## Tech Stack

| Part | Technology |
|---|---|
| Backend | Python 3, [`aiohttp`](https://docs.aiohttp.org/) (handles both the web page and the WebSocket connections in one process) |
| Frontend | Plain HTML, CSS, and JavaScript (no framework) |
| Protocol | WebSocket (`ws://` / `wss://`) |
| Deployment | Hosted on our allotted lab machine; made publicly reachable using [ngrok](https://ngrok.com) |

---

## How to Run

1. **Install the one dependency:**
   ```bash
   pip install aiohttp
   ```

2. **Start the server:**
   ```bash
   python3 combined_server.py
   ```
   By default it listens on `http://0.0.0.0:3210`.

3. **Open it in a browser:**
   ```
   http://localhost:3210
   ```
   (or `http://<your-machine-ip>:3210` from another device on the same network)

4. **Join the chat:**
   - Enter a username and a room name, then click **Join Chat**.
   - Open the same link in another tab, another browser, or another device, using the **same room name**, to chat with someone else.
   - Any number of people can join the same room -- every message is broadcast to everyone currently in that room.

### Making it reachable outside your local network (optional)

If your server's network blocks direct incoming connections (which is common on shared/lab machines), you can expose it publicly using `ngrok`:

```bash
ngrok http 3210
```

This gives you a public HTTPS link that forwards straight to your server, without needing to open any port on your machine's firewall.

---

## Features Implemented

- ✅ Real-time message broadcasting to everyone in the same chat room
- ✅ Usernames shown with every message
- ✅ Join / leave notifications
- ✅ Graceful handling of client disconnections (a closed tab, lost connection, or crashed browser never crashes the server or affects other users)
- ✅ **Bonus:** Timestamps on every message
- ✅ **Bonus:** Separate chat rooms (users only see messages from people in the same room)

---

## How It Works

1. A user opens the web page and enters a username and room name.
2. The browser opens a WebSocket connection to the server (a one-time "handshake" after which the connection stays open in both directions).
3. The server keeps a list of everyone currently connected, grouped by room.
4. When someone sends a message, the server immediately forwards ("broadcasts") it to everyone else in the same room.
5. If someone disconnects -- for any reason -- the server removes them from the list and lets everyone else in the room know.

No page reloads, no polling, no repeated "any new messages?" requests -- the server pushes updates the instant they happen.

---

## Project Structure

```
.
├── combined_server.py   # The entire backend + frontend (single file)
└── README.md            # This file
```

The frontend HTML/CSS/JS is embedded directly inside `combined_server.py` and served at `/` -- there are no separate static files to manage.

---

## Client URL (for testing)

A live instance of this app (running on our allotted lab machine) can be tested here:

```
https://dipping-quizzical-ellipse.ngrok-free.dev
```

> Note: ngrok's free tier shows a one-time "Visit Site" confirmation page to new visitors -- this is normal, just click through it to reach the chat.
> This link only works while our server and ngrok tunnel are actively running on the lab machine.

---

## Group Members

| S.No. | Name | Roll Number |
|---|---|---|
| 1 | Rohit Raghuwanshi| 12341820 |
| 2 | | |
| 3 | | |
| 4 | | |

---

## Note on Use of AI Tools

An AI assistant (Claude, by Anthropic) was used during this project for:
- Debugging help while setting up the server, SSH connection, and networking
- Formatting this README and the accompanying PDF report

The application design, coding decisions, testing, and final approach were all done by the group.
