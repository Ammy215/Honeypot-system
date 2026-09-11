"""
Opt-in timing log for the dashboard. Enable with DASHBOARD_PERF_LOG=true.

Answers, from the running server rather than from impressions:
  - is a cached read a HIT or a MISS, and what did it cost?
  - which calls actually go to the network, and for how long?

Off by default and near-free when off (one boolean check). When on, lines go
to stderr as

    PERF sensor_status          MISS   271.4 ms
    PERF sensor_status          HIT      0.1 ms
    PERF db overview._load              498.2 ms

The HIT/MISS distinction works because a st.cache_data body only executes on a
miss: the cached function calls note_miss(), and the thin wrapper around it
reads that flag. The flag is thread-local, so concurrent sessions — and reads
overlapped by data.concurrently() — cannot mark each other's calls.
"""

import logging
import threading
import time

import config

ENABLED = config.DASHBOARD_PERF_LOG

logger = logging.getLogger("honeyshield.perf")
_local = threading.local()

if ENABLED and not logger.handlers:
    _handler = logging.StreamHandler()
    _handler.setFormatter(logging.Formatter("%(asctime)s PERF %(message)s"))
    logger.addHandler(_handler)
    logger.setLevel(logging.INFO)
    logger.propagate = False


def begin() -> None:
    """Call before invoking a cached function whose hit/miss should be logged."""
    _local.miss = False


def note_miss() -> None:
    """Call as the first line of a cached function's body."""
    _local.miss = True


def record(name: str, started: float) -> None:
    """Log a cached call as HIT or MISS, with its wall time."""
    if ENABLED:
        ms = (time.perf_counter() - started) * 1000
        state = "MISS" if getattr(_local, "miss", False) else "HIT "
        logger.info(f"{name:<24} {state} {ms:8.1f} ms")


def network(label: str, started: float) -> None:
    """Log a real network round trip."""
    if ENABLED:
        logger.info(f"db {label:<30} {(time.perf_counter() - started) * 1000:8.1f} ms")
