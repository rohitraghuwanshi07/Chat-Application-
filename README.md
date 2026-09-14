# Secure Persistent Group Chat

A real-time WebSocket group chat application with persistent storage, encryption, and message signing/verification. This was extended in a second phase to add a proper load balancer and distributed backend with replication.

**Course:** CS559 — Computer System Design  
**Assignment:** Secure Persistent Group Chat

---

## What Changed Since the Last Submission

The original version used a single Python backend with SQLite. That worked fine for the basic assignment, but we wanted to try making it more "production-like" (or at least something that doesn't fall over if two people send messages at the same time). So we made some fairly big changes:

- **SQLite → Valkey**: We replaced the SQLite database with Valkey, which is basically Redis but open source. Each backend now runs its own local Valkey instance instead of all sharing one database over the network.
- **Single backend → Multiple backends with a load balancer**: We wrote a load balancer in Go (`main.go`) that sits in front of the Python backends and distributes traffic using round-robin.
- **Added replication**: When one backend saves a message, it fires off HTTP requests to all the other backends so they save it too. This way every backend has the full dataset locally and reads are always fast.

---

## Tech Stack

| Part | Technology |
|---|---|
| Load Balancer | Go (written from scratch using `net/http` and `httputil.ReverseProxy`) |
| Backend | Python 3, `aiohttp` (WebSocket + HTTP server) |
| Database | Valkey (Redis-compatible in-memory store, one per backend) |
| Encryption | Symmetric encryption (Fernet/AES) — messages are never stored as plaintext |
| Integrity | HMAC — detects tampering of stored messages |
| Signing | Asymmetric key pairs (per sender) — messages are signed and verified |
| Frontend | HTML, CSS, JavaScript (no framework) |

---

## Architecture Overview

```
Client Browser
      |
      v
  Load Balancer (Go, port 5000)
  /lb/health, /lb/status, /lb/metrics
      |
      |  round-robin
      |
  +---+---+---+
  |           |
Backend 1   Backend 2  ...
(Python)    (Python)
  |           |
Valkey      Valkey
(local)     (local)
      \   /
   replication.py
   (HTTP fan-out)
```

Every backend has its own Valkey running on localhost. When a message comes in, the backend that receives it saves it to its own Valkey and then immediately sends a copy to all the other backends (`POST /replicate`). So they all stay in sync. Reads always come from local memory, which is much faster than going to a shared database over the network.

---

## Data Model (Valkey / Redis)

Since we moved away from SQLite, there's no SQL schema anymore. Instead, we use three Redis data structures:

### `messages` — Redis Stream

This is basically an append-only log of every message from every room.

Each entry in the stream has these fields:

| Field | What it stores |
|---|---|
| `message_id` | A UUID that uniquely identifies this message (used for deduplication) |
| `room` | Which chat room the message belongs to |
| `sender` | The username of the person who sent it |
| `ciphertext` | The encrypted message content (never stored as plaintext) |
| `signature` | The sender's digital signature over the original message |
| `verified` | `"1"` if the signature was valid when the message was saved, `"0"` otherwise |
| `ts` | Unix timestamp of when the message was saved |

---

### `seen_ids` — Redis SET

This is just a set of all `message_id` values that have already been saved. We use it purely for deduplication.

When a message comes in, we do `SADD seen_ids <message_id>`. If `SADD` returns `0`, it means we already have this message (maybe from a retry or a replication fan-out that arrived twice), so we skip it. This makes duplicate inserts a safe no-op, which is important because the replication system can theoretically deliver the same message more than once.

---

### `signers` — Redis HASH

A simple mapping of `username → public_key_pem`. Each user's public key is stored here so we can re-verify their message signatures later (for the tamper detection demo).

---

## API Endpoints

The backend exposes these routes:

| Method | Path | What it does |
|---|---|---|
| `GET` | `/` | Serves the frontend (index.html) |
| `GET` | `/ws` | WebSocket connection for real-time chat |
| `GET` | `/health` | Health check (the load balancer polls this) |
| `POST` | `/message` | Submit a message via REST (used for load testing) |
| `GET` | `/feed` | Get all stored messages as JSON (decrypted) |
| `POST` | `/replicate` | Internal — peer backends call this to push a message |

The load balancer also has its own monitoring endpoints:

| Method | Path | What it does |
|---|---|---|
| `GET` | `/lb/health` | Is the load balancer itself alive |
| `GET` | `/lb/status` | Per-backend health and in-flight request count |
| `GET` | `/lb/metrics` | Request counters and latency percentiles (p50, p95, p99) |

---

## How to Run

### 1. Start Valkey on each backend machine

```bash
valkey-server --daemonize yes
```

Or just use Redis if Valkey isn't installed — it's the same protocol.

### 2. Start the Python backend on each machine

```bash
pip install -r backend/requirements.txt
python backend/server.py
# runs on port 4000 by default
```

You can also set some environment variables:

```bash
DB_HOST=localhost          # where Valkey is running (default: localhost)
DB_PORT=6379               # Valkey port (default: 6379)
DB_WORKERS=64              # thread pool size for blocking DB calls
MAX_INFLIGHT=100           # max concurrent HTTP requests this backend will accept
```

### 3. Start the Go load balancer on the main machine

```bash
go run ./main.go \
    -listen :5000 \
    -backends http://SYS2:4000,http://SYS3:4000,http://SYS4:4000
```

Other flags:

```
-health-interval   1s     # how often to probe /health on each backend
-backend-timeout   10s    # per-request timeout for backend calls
```

---

## Verifying Tamper Detection

This still works the same as before, just the commands are different since it's Valkey now.

1. Send a message in the chat.
2. Connect to Valkey on one of the backends:
```bash
redis-cli
> XRANGE messages - + COUNT 1
```
3. Manually delete and re-add the message with a modified `ciphertext` field using `XDEL` and `XADD`.
4. Rejoin the same room in the browser — the tampered message will show as **unverified** while untouched messages still show **signed**.

---

## Known Limitation: Non-Repudiation

Same as before. Private signing keys are generated and stored server-side (in Valkey, per username), not in the client's browser. This means the system correctly demonstrates asymmetric signing and tamper detection, but doesn't provide true non-repudiation against a malicious server, because the server holds everyone's private keys. A proper fix would require client-side key generation using something like the browser's WebCrypto API. We're aware of this — it's a deliberate simplification for the assignment scope.

---

## Client URL (Live Testing)

http://10.1.75.51:5000

> Note: This is only reachable if the server is actively running on the lab machine and you're on the same network. If it's not responding, contact the group.

---

## Group Members

| S.No. | Name | Roll Number |
|---|---|---|
| 1 | Lakshay Gupta | 12341300 |
| 2 | Kabeer Vijay More | 12341030 |
| 3 | Rathod Chetan Kumar | 12341750 |
| 4 | Rohit Raghuwanshi | 12341820 |
