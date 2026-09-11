"""
One event loop for the whole dashboard process.

WHY THIS EXISTS — the bug it fixes
Streamlit pages are plain synchronous scripts, so every async database call
needs a sync bridge. The obvious bridge is `asyncio.run(...)` at each call
site, and that is what the dashboard originally did. It is silently wrong
here: `asyncio.run` creates a *new* event loop, runs the coroutine, then
closes it. An asyncpg Pool binds to the loop that created it, so the pool
built during login (in one throwaway loop) could never be used by any later
page query (in a different throwaway loop). Every page failed with
"cannot perform operation: another operation is in progress" — after login,
against Postgres, on every page. It went unnoticed because the login page
itself only calls `db.connect()` and renders a form; the failure begins at
the first query, which is the first thing that happens *after* a successful
login.

The fix is to own exactly one loop for the process lifetime, on a background
daemon thread, and marshal every coroutine onto it. The pool is then always
used on the loop that created it.

Do not reintroduce `asyncio.run` in dashboard code. Use `run()` below.
"""

import asyncio
import threading
import time
from typing import Any, Coroutine

from dashboard import perf
from database.db_async import db

# 120s: generous for a cold Supabase project waking from idle-pause, which
# takes ~2min and is a real condition on the free tier — not a hang.
DEFAULT_TIMEOUT = 120.0

_loop: asyncio.AbstractEventLoop | None = None
_thread: threading.Thread | None = None
_lock = threading.Lock()


def _ensure_loop() -> asyncio.AbstractEventLoop:
    """Return the process-wide loop, starting its thread on first use."""
    global _loop, _thread

    if _loop is not None and not _loop.is_closed():
        return _loop

    # Streamlit runs each script in its own thread, so two page loads can race
    # here on a cold process; the lock makes loop creation happen exactly once.
    with _lock:
        if _loop is not None and not _loop.is_closed():
            return _loop

        loop = asyncio.new_event_loop()
        thread = threading.Thread(
            target=loop.run_forever,
            name="honeyshield-dashboard-loop",
            daemon=True,  # never block interpreter exit
        )
        thread.start()
        _loop, _thread = loop, thread

    return _loop


def run(coro: Coroutine[Any, Any, Any], timeout: float = DEFAULT_TIMEOUT) -> Any:
    """
    Run `coro` on the dashboard's single event loop and return its result.

    Also connects the database pool if it isn't up yet. That guard matters
    because Streamlit lets you land directly on a page — a bookmark, a browser
    refresh, a rerun — without the login script having run in this process, so
    "login connected it already" is not a safe assumption. `db.connect()` is
    idempotent, so the common case costs one attribute check.
    """
    loop = _ensure_loop()
    started = time.perf_counter()

    async def _with_connection():
        await db.connect()
        return await coro

    future = asyncio.run_coroutine_threadsafe(_with_connection(), loop)
    try:
        return future.result(timeout)
    finally:
        # Every database round trip in the console passes through here, and
        # cached reads only reach it on a miss — so with DASHBOARD_PERF_LOG on,
        # this line is the complete record of what actually hit the network.
        perf.network(getattr(coro, "__qualname__", "coroutine"), started)
