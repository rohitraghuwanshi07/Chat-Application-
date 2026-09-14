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
"""

import aiohttp

PEERS = [
    # "http://SYS3:4000",
    # "http://SYS4:4000",
]

_FANOUT_TIMEOUT = aiohttp.ClientTimeout(total=2)


async def fanout(payload: dict):
    """Fire-and-forget: tells every peer to apply this same message
    locally. Never raises -- a peer being briefly unreachable just
    means it's slightly behind until the next successful fan-out; it
    never fails the original request that's already been saved and
    answered locally."""
    async with aiohttp.ClientSession(timeout=_FANOUT_TIMEOUT) as session:
        for peer in PEERS:
            try:
                async with session.post(f"{peer}/replicate", json=payload) as resp:
                    await resp.read()
            except Exception as e:
                print(f"[replicate] failed to reach {peer}: {e!r}")
