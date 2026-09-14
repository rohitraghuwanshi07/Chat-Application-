"""
replication.py
----------------
Tiny "active-active" fan-out for the local Valkey instances.
 
CHANGED (backpressure fix): every accepted message used to spawn an
independent asyncio.create_task(fanout(...)) with no limit on how many
could be in flight at once. Under load, if a peer was even briefly slow
to respond, fanout tasks (each holding a message's ciphertext/signature
in memory until it times out) piled up faster than they drained -- a
classic unbounded backlog. That's what was driving memory from ~56MB to
the container's ~512MB cap over a few minutes: not a leak in the usual
sense, but a queue with no ceiling.
 
Two changes fix this:
  1. A semaphore caps how many fanout operations can be in flight at
     once. Once full, new fanout calls skip immediately (logged, not
     queued) instead of adding to the backlog -- a peer being briefly
     behind should mean "slightly stale," never "unbounded memory
     growth."
  2. Peers are contacted concurrently (asyncio.gather) instead of one
     after another, and the timeout is shorter, so each fanout call
     resolves quickly either way instead of tying up memory for up to
     4+ seconds per message under a sequential loop.
"""
 
import asyncio
import aiohttp
 
PEERS = [
    "http://172.17.0.xx:4000",
    "http://172.17.0.xx:4000",
]
 
# Shorter per-peer timeout: on a local/fast network, 2s was generous
# enough to let slow peers hold a fanout call open for a long time.
_FANOUT_TIMEOUT = aiohttp.ClientTimeout(total=1)
 
# Hard cap on concurrent fanout operations. Tune this against your own
# machine's memory budget -- 200 is a conservative starting point for
# a container with a few hundred MB to spare after the app itself.
_MAX_CONCURRENT_FANOUTS = 200
_fanout_semaphore = asyncio.Semaphore(_MAX_CONCURRENT_FANOUTS)
 
_session: aiohttp.ClientSession | None = None
 
# Visibility: how many fanouts we've had to skip because we were
# already at capacity. If this climbs during a run, peers are falling
# behind and it's worth knowing, even though it no longer costs memory.
_skipped_count = 0
 
 
def init_session():
    global _session
    _session = aiohttp.ClientSession(timeout=_FANOUT_TIMEOUT)
 
 
async def close_session():
    global _session
    if _session is not None:
        await _session.close()
        _session = None
 
 
async def _send_to_peer(peer: str, payload: dict):
    try:
        async with _session.post(f"{peer}/replicate", json=payload) as resp:
            await resp.read()
    except Exception as e:
        print(f"[replicate] failed to reach {peer}: {e!r}")
 
 
async def fanout(payload: dict):
    """Fire-and-forget, but bounded: if we're already at
    _MAX_CONCURRENT_FANOUTS in-flight fanout operations, this call
    drops immediately instead of adding to an unbounded backlog.
    """
    global _skipped_count
 
    if _session is None:
        print("[replicate] no session initialized -- did server.py call "
              "replication.init_session() on startup?")
        return
 
    if _fanout_semaphore.locked():
        _skipped_count += 1
        if _skipped_count % 100 == 1:  # don't spam the log
            print(f"[replicate] at capacity ({_MAX_CONCURRENT_FANOUTS} "
                  f"in-flight), skipped {_skipped_count} fanouts so far")
        return
 
    async with _fanout_semaphore:
        # Contact all peers concurrently instead of one after another --
        # bounds worst-case time per fanout to ~_FANOUT_TIMEOUT, not
        # _FANOUT_TIMEOUT * len(PEERS).
        await asyncio.gather(
            *(_send_to_peer(peer, payload) for peer in PEERS),
            return_exceptions=True,
        )