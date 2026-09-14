"""
replication.py
----------------
Tiny "active-active" fan-out for the local Valkey instances.

Valkey (like Postgres, like Dragonfly) only does primary->replica
replication out of the box -- not true multi-master. But this app's
data doesn't need real multi-master conflict resolution: messages are
immutable and uniquely keyed by message_id, so two backends can never
disagree about what a given message_id means. That means a much
simpler trick works fine:

  1. A backend saves a NEW message to its own local Valkey.
  2. It fires this same message at its peer backends' /replicate route.
  3. Each peer applies it to ITS OWN local Valkey via the exact same
     save_message() dedup path -- so applying it twice, out of order,
     or after a delay is always a safe no-op.

End result: every backend ends up holding the full dataset, so /feed
and room-history reads are always 100% local -- no network hop, no
shared bottleneck, and read throughput scales linearly as you add more
backends.

EDIT PEERS BELOW -- list this machine's OTHER backends, not itself.
Example for Sys2 (leave Sys2 itself out of its own list):
    PEERS = ["http://SYS3:4000", "http://SYS4:4000"]

CHANGED (perf fix): fanout() used to open a brand-new
aiohttp.ClientSession -- and therefore brand-new TCP connections to
every peer -- on EVERY SINGLE MESSAGE. Under load that meant hundreds
of fresh connection setups per second on top of the actual traffic,
which is what was starving the backends and causing them to time out
reaching each other. Now there's exactly ONE session, created once at
app startup (see server.py's on_startup/on_cleanup hooks) and reused
by every call, so peer connections are pooled and kept warm instead of
being rebuilt from scratch each time.
"""

import aiohttp

PEERS = [
    "http://172.17.0.xx:4000",
    "http://172.17.0.xx:4000",
]

_FANOUT_TIMEOUT = aiohttp.ClientTimeout(total=2)

# Set once by init_session() at app startup. Deliberately module-level
# (rather than passed through every call site) so existing callers of
# fanout(payload) don't need to change.
_session: aiohttp.ClientSession | None = None


def init_session():
    """Creates the single shared ClientSession used by every fanout()
    call for the lifetime of the process. Must be called once, from an
    async context, before the first fanout() call -- server.py does
    this in an on_startup hook. Reusing one session means peer
    connections are pooled and kept alive instead of being opened and
    torn down for every message."""
    global _session
    _session = aiohttp.ClientSession(timeout=_FANOUT_TIMEOUT)


async def close_session():
    """Cleanly closes the shared session's connections. Call this from
    an on_cleanup hook so the process doesn't leak sockets on shutdown."""
    global _session
    if _session is not None:
        await _session.close()
        _session = None


async def fanout(payload: dict):
    """Fire-and-forget: tells every peer to apply this same message
    locally. Never raises -- a peer being briefly unreachable just
    means it's slightly behind until the next successful fan-out; it
    never fails the original request that's already been saved and
    answered locally.

    Uses the shared module-level session (see init_session()) instead
    of creating a new one per call.
    """
    if _session is None:
        # init_session() wasn't called -- fail loudly in the log so this
        # doesn't silently no-op replication, but don't raise (fan-out
        # must never break the caller's already-completed request).
        print("[replicate] no session initialized -- did server.py call "
              "replication.init_session() on startup?")
        return

    for peer in PEERS:
        try:
            async with _session.post(f"{peer}/replicate", json=payload) as resp:
                await resp.read()
        except Exception as e:
            print(f"[replicate] failed to reach {peer}: {e!r}")