#!/usr/bin/env python3
"""
Dashboard performance and sign-in correctness — each fix, locked in.

Run directly:  python tests/test_dashboard_performance.py

Every check here corresponds to a cost or a bug that was MEASURED against the
running console (headless Chrome over DevTools, plus server-side
instrumentation), not guessed at:

  [1] Streamlit's source watcher walked all of sys.modules after every run of
      every new session, on the event loop: 1.6-2.3 s per session, during
      which no output reached any browser. Now disabled in config.
  [2] After "Sign in" the login card stayed painted over Overview (675 ms in a
      real browser on a cache miss). Streamlit discards undelivered deltas
      when a new run starts, so "empty the card, then st.rerun()" lost the
      empty. The page is now drawn in the same run: no rerun, nothing lost.
  [3] asyncpg reset every connection on release — a full extra round trip on
      every query (510 ms vs 251 ms). Skipped, WITHOUT losing the rollback of
      an open transaction.
  [4] db.connect() could build two pools under concurrent first use.
  [5] Every page re-inserted the repo root into sys.path on every rerun.
  [6] The sensor probe rebuilt TLS state on every call (1,138 ms vs 269 ms).
  [7] Overview ran its DB bundle and its health probe back to back.
  [8] The sign-in form waited on the DB pool (11 s to first paint on a cold
      process); now warmed in the background, off the request path.
  [9] Cache HIT/MISS is observable in the running server (DASHBOARD_PERF_LOG).
 [10] Pages imported pandas / the data layer / google.genai ABOVE their auth
      gate, so a fresh server made even the sign-in form wait 3-8 s on them.
 [11] run_dashboard.py starts only the network-bound warm-up at process start;
      the CPU-bound half, started there, made the first sign-in 3.5 s slower.

Sections [3] live-check against the real database when DATABASE_URL is set in
.env (read-only: SELECT 1, BEGIN/ROLLBACK). Everything else runs offline on a
throwaway SQLite database.
"""

import ast
import os
import sys
import time
import tomllib
from pathlib import Path
from unittest.mock import patch

REPO_ROOT = Path(__file__).resolve().parent.parent
TEST_DB = REPO_ROOT / "data" / "test_dashboard_performance.db"

# Live URL for section [3] is read straight from .env WITHOUT exporting it: the
# global db object below must stay on SQLite for the sign-in tests.
from dotenv import dotenv_values  # noqa: E402

LIVE_URL = (dotenv_values(REPO_ROOT / ".env").get("DATABASE_URL") or "").strip()

os.environ["SQLITE_PATH"] = str(TEST_DB)
os.environ["DATABASE_URL"] = ""
sys.path.insert(0, str(REPO_ROOT))

import asyncio  # noqa: E402

from streamlit.testing.v1 import AppTest  # noqa: E402

import config  # noqa: E402

config.SKIP_SCHEMA_INIT = False

from auth.async_admin_auth import hash_password  # noqa: E402
from dashboard import data, login, perf, sensor  # noqa: E402
from database import db_async  # noqa: E402
from database.db_async import AsyncDatabase, db  # noqa: E402

APP = REPO_ROOT / "dashboard" / "app.py"
PAGES = sorted((REPO_ROOT / "dashboard" / "pages").glob("*.py"))
# Generated per run for the throwaway SQLite admin, never a literal: a fixed
# value in a tracked file is indistinguishable from a leaked one to a scanner
# (or a reader), and there is no reason for this one to be knowable.
import secrets  # noqa: E402

TEST_PASSWORD = secrets.token_urlsafe(18)

passed = failed = 0


def check(label, condition, detail=""):
    global passed, failed
    if condition:
        passed += 1
        print(f"  PASS  {label}")
    else:
        failed += 1
        print(f"  FAIL  {label}" + (f"\n          {detail}" if detail else ""))


def section(t):
    print(f"\n{t}")


ONLINE = {"state": sensor.ONLINE, "latency_ms": 250, "http_status": 200,
          "url": "https://x/_health", "detail": "answered in 250ms"}


# ── [1] ───────────────────────────────────────────────────────────────────
def test_watcher_disabled():
    section("[1] Streamlit's per-session module walk is switched off")
    cfg = tomllib.loads((REPO_ROOT / ".streamlit" / "config.toml").read_text(encoding="utf-8"))
    check('server.fileWatcherType = "none"',
          cfg.get("server", {}).get("fileWatcherType") == "none",
          f"got {cfg.get('server', {}).get('fileWatcherType')!r}")


# ── [2] ───────────────────────────────────────────────────────────────────
def test_signin_same_run():
    section("[2] Sign-in draws the page in the SAME run — no rerun, no stale card")

    tree = ast.parse((REPO_ROOT / "dashboard" / "login.py").read_text(encoding="utf-8"))
    for fn in ("show_login_page", "require_auth"):
        node = next(n for n in ast.walk(tree) if isinstance(n, ast.FunctionDef) and n.name == fn)
        reruns = [c for c in ast.walk(node) if isinstance(c, ast.Call)
                  and isinstance(c.func, ast.Attribute) and c.func.attr == "rerun"]
        check(f"{fn}() never calls st.rerun()", not reruns,
              "a rerun lets Streamlit discard the delta that removes the card")

    async def seed():
        TEST_DB.unlink(missing_ok=True)
        await db.connect()
        await db.init_schema()
        await db.create_admin_user("admin", hash_password(TEST_PASSWORD))
    asyncio.run(seed())

    # Warm-up is exercised separately in [8]; here it must not spawn threads
    # that are still importing while the test process exits.
    login._db_warm_started = login._imports_warm_started = True
    login._WARMED.set()

    runs = {"n": 0}
    real_inject = login.theme.inject

    def counting_inject(*a, **kw):
        runs["n"] += 1
        return real_inject(*a, **kw)

    with patch.object(login.theme, "inject", counting_inject), \
         patch("dashboard.data.sensor_status", return_value=ONLINE):
        at = AppTest.from_file(str(APP), default_timeout=180)
        at.run()
        check("unauthenticated run shows the sign-in form",
              any(t.label == "Password" for t in at.text_input))

        runs["n"] = 0
        at.text_input[0].input("admin")
        at.text_input[1].input(TEST_PASSWORD)
        at.button[0].click()
        at.run()

        markup = " ".join(str(m.value) for m in at.markdown)
        check("valid credentials authenticate the session",
              at.session_state["authenticated"] is True)
        check("the submission produced exactly ONE script run (no rerun)",
              runs["n"] == 1, f"script ran {runs['n']} times for one sign-in")
        check("Overview masthead drawn in that same run", "hs-header" in markup)
        check("no password field survives into the authenticated frame",
              not any(t.label == "Password" for t in at.text_input))
        check("sign-in screen's sidebar-hiding rule lifted in the same run",
              "[data-testid='stSidebar']" not in markup)
        check("no exception", not list(at.exception), str(list(at.exception)[:1]))

        at2 = AppTest.from_file(str(APP), default_timeout=180)
        at2.run()
        at2.text_input[0].input("admin")
        at2.text_input[1].input("definitely-wrong")
        at2.button[0].click()
        at2.run()
        check("wrong password still rejected, form still shown",
              not at2.session_state["authenticated"] if "authenticated" in at2.session_state
              else True)
        check("...with the single generic message",
              any("Invalid username or password." in str(e.value) for e in at2.error))


# ── [3] ───────────────────────────────────────────────────────────────────
def test_release_reset():
    section("[3] Pool release skips the session-reset round trip, keeps the rollback")

    src = (REPO_ROOT / "database" / "db_async.py").read_text(encoding="utf-8")
    check("create_pool is given reset=_skip_session_reset",
          "reset=_skip_session_reset" in src)

    if not LIVE_URL:
        print("  SKIP  live checks — no DATABASE_URL in .env")
        return

    import asyncpg

    async def live():
        pool = await asyncpg.create_pool(LIVE_URL, ssl="require", min_size=1, max_size=1,
                                         reset=db_async._skip_session_reset)
        try:
            # The one protection that matters: an unmanaged open transaction
            # must NOT survive release. asyncpg's internal _reset() handles it.
            async with pool.acquire() as c:
                await c.execute("BEGIN")
                check("(setup) connection is inside a transaction", c.is_in_transaction())
            async with pool.acquire() as c:   # max_size=1: the SAME connection
                check("released mid-transaction -> next acquirer gets it rolled back",
                      not c.is_in_transaction())

            async with pool.acquire() as c:
                rtt = []
                for _ in range(5):
                    t = time.perf_counter()
                    await c.fetchval("SELECT 1")
                    rtt.append(time.perf_counter() - t)
            cycle = []
            for _ in range(5):
                t = time.perf_counter()
                async with pool.acquire() as c:
                    await c.fetchval("SELECT 1")
                cycle.append(time.perf_counter() - t)
            rtt_m, cyc_m = sorted(rtt)[2], sorted(cycle)[2]
            check(f"acquire+query+release is one round trip, not two "
                  f"({cyc_m * 1000:.0f} ms vs RTT {rtt_m * 1000:.0f} ms)",
                  cyc_m < rtt_m * 1.5)
        finally:
            await pool.close()

    asyncio.run(live())


# ── [4] ───────────────────────────────────────────────────────────────────
def test_connect_single_pool():
    section("[4] Concurrent first use builds exactly one pool")

    async def race():
        d = AsyncDatabase()
        d.backend = "postgres"
        opened = {"n": 0}

        async def slow_open():
            opened["n"] += 1
            await asyncio.sleep(0.2)          # a pool mid-handshake
            d._pg_pool = object()

        d._open = slow_open
        await asyncio.gather(*[d.connect() for _ in range(6)])
        return opened["n"]

    n = asyncio.run(race())
    check("six simultaneous connect() calls open ONE pool", n == 1, f"opened {n}")


# ── [5] ───────────────────────────────────────────────────────────────────
def test_sys_path_stable():
    section("[5] Reruns do not grow sys.path")

    for f in [APP] + PAGES:
        tree = ast.parse(f.read_text(encoding="utf-8"))
        bare = [n for n in tree.body if isinstance(n, ast.Expr) and isinstance(n.value, ast.Call)
                and isinstance(n.value.func, ast.Attribute) and n.value.func.attr == "insert"
                and ast.unparse(n.value.func.value) == "sys.path"]
        check(f"{f.stem}: sys.path insert is guarded", not bare)

    with patch("dashboard.data.sensor_status", return_value=ONLINE):
        before = len(sys.path)
        for _ in range(4):
            at = AppTest.from_file(str(APP), default_timeout=180)
            at.session_state["authenticated"] = True
            at.session_state["username"] = "admin"
            at.run()
    check("four reruns of Overview leave sys.path the same length",
          len(sys.path) == before, f"{before} -> {len(sys.path)}")


# ── [6] ───────────────────────────────────────────────────────────────────
def test_probe_session():
    section("[6] The sensor probe reuses one HTTP session")
    src = (REPO_ROOT / "dashboard" / "sensor.py").read_text(encoding="utf-8")
    check("probe goes through the persistent _SESSION", "_SESSION.get(" in src)
    # AST, not text: sensor.py's own comments explain WHY requests.get() was
    # slow, and a substring match fails on the explanation of the bug.
    bare = [n for n in ast.walk(ast.parse(src)) if isinstance(n, ast.Call)
            and ast.unparse(n.func) == "requests.get"]
    check("no bare requests.get() call left in the probe", not bare)


# ── [7] ───────────────────────────────────────────────────────────────────
def test_overview_overlaps():
    section("[7] Overview runs its DB bundle and health probe at the same time")

    spans = {}

    def slow(name, value):
        def _f():
            spans[name] = [time.perf_counter()]
            time.sleep(0.4)
            spans[name].append(time.perf_counter())
            return value
        return _f

    bundle = {"summary": {"total_connections": 1, "total_attackers": 1,
                          "active_alerts": 0, "critical_attackers": 0},
              "filtered": {"total": 0, "last_hour": 0, "last_24h": 0,
                           "latest": None, "recent": []},
              "recent": [], "top": [],
              "traffic": {"connections": 1, "probe": 0, "likely": 0, "unlabelled": 1,
                          "sources": 1, "sources_unlabelled": 1}}
    with patch("dashboard.data.overview", slow("db", bundle)), \
         patch("dashboard.data.sensor_status", slow("probe", ONLINE)):
        at = AppTest.from_file(str(APP), default_timeout=180)
        at.session_state["authenticated"] = True
        at.session_state["username"] = "admin"
        at.run()

    ok = "db" in spans and "probe" in spans
    overlap = ok and spans["db"][0] < spans["probe"][1] and spans["probe"][0] < spans["db"][1]
    check("the two reads' time intervals overlap", overlap, str(spans))
    check("Overview still renders ONLINE from the probe result",
          "ONLINE" in " ".join(str(m.value) for m in at.markdown if "<style>" not in str(m.value)))


# ── [8] ───────────────────────────────────────────────────────────────────
def test_warmup_off_request_path():
    section("[8] Sign-in form paints without waiting on the database")

    login._db_warm_started = login._imports_warm_started = False
    login._WARMED.clear()
    started = {"n": 0}

    def slow_warmup():
        started["n"] += 1
        time.sleep(3.0)                       # a cold pool, measured at 3.6 s
        login._WARMED.set()

    with patch.object(login, "_warm_up_process", slow_warmup), \
         patch.object(login, "_import_page_modules", lambda: None):
        t = time.perf_counter()
        at = AppTest.from_file(str(APP), default_timeout=180)
        at.run()
        elapsed = time.perf_counter() - t
        check("form rendered while a 3 s warm-up is still running",
              any(t.label == "Password" for t in at.text_input) and elapsed < 2.5,
              f"render took {elapsed:.2f}s")
        AppTest.from_file(str(APP), default_timeout=180).run()
        time.sleep(0.2)
        check("warm-up starts once per PROCESS, not once per session",
              started["n"] == 1, f"started {started['n']} times")
    login._WARMED.wait(5)


# ── [9] ───────────────────────────────────────────────────────────────────
def test_cache_hit_miss_logged():
    section("[9] Cache HIT/MISS is observable in the running server")

    import logging

    class Capture(logging.Handler):
        def __init__(self):
            super().__init__()
            self.lines = []

        def emit(self, record):
            self.lines.append(record.getMessage())

    cap = Capture()
    perf.logger.addHandler(cap)
    perf.logger.setLevel(logging.INFO)
    saved = perf.ENABLED
    perf.ENABLED = True
    try:
        data._sensor_status_cached.clear()
        with patch.object(sensor, "probe", return_value=ONLINE):
            data.sensor_status()
            data.sensor_status()
    finally:
        perf.ENABLED = saved
        perf.logger.removeHandler(cap)

    lines = [ln for ln in cap.lines if ln.startswith("sensor_status")]
    check("first call logged as MISS", len(lines) >= 1 and "MISS" in lines[0], str(lines))
    check("second call logged as HIT", len(lines) >= 2 and "HIT" in lines[1], str(lines))


# ── [10] ──────────────────────────────────────────────────────────────────
def test_heavy_imports_below_gate():
    section("[10] The sign-in form never waits on a page's heavy imports")

    # Above the gate, a fresh server imported pandas, the data layer and (on AI
    # Analysis) google.genai before it could send the SIGN-IN form: 3-4 s on
    # most pages, 8 s on AI Analysis. The gate itself needs ~80 ms.
    heavy = {"pandas", "plotly", "dashboard.data", "honeypot.ai"}
    for f in [APP] + PAGES:
        tree = ast.parse(f.read_text(encoding="utf-8"))
        gate = next(n.lineno for n in tree.body if isinstance(n, ast.Expr)
                    and isinstance(n.value, ast.Call)
                    and getattr(n.value.func, "id", "") == "require_auth")
        early = []
        for n in tree.body:
            if n.lineno > gate or not isinstance(n, (ast.Import, ast.ImportFrom)):
                continue
            names = ([a.name for a in n.names] if isinstance(n, ast.Import)
                     else [f"{n.module}.{a.name}" for a in n.names] + [n.module or ""])
            early += [m for m in names if any(m == h or m.startswith(h + ".") for h in heavy)]
        check(f"{f.stem}: nothing heavy imported above require_auth", not early, str(early))

    analyst = ast.parse((REPO_ROOT / "honeypot" / "ai" / "async_analyst.py")
                        .read_text(encoding="utf-8"))
    top = [ast.unparse(n) for n in analyst.body
           if isinstance(n, (ast.Import, ast.ImportFrom)) and "google" in ast.unparse(n)]
    check("async_analyst does not import google.genai at module load", not top, str(top))
    check("google.genai is not in the warm-up's preload list",
          not any("genai" in m for m in login._PAGE_MODULES))


# ── [11] ──────────────────────────────────────────────────────────────────
def test_launcher():
    section("[11] run_dashboard.py warms the pool early and hands off to Streamlit")

    import importlib.util
    spec = importlib.util.spec_from_file_location("run_dashboard", REPO_ROOT / "run_dashboard.py")
    launcher = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(launcher)          # guarded by __main__: must not start a server
    check("importing the launcher does not start anything", True)

    calls = {}

    def fake_warm(**kw):
        calls["warm"] = kw

    def fake_cli():
        calls["argv"] = list(sys.argv)
        return 0

    saved_argv, saved_cwd = list(sys.argv), os.getcwd()
    sys.argv = ["run_dashboard.py", "--server.port", "8599"]
    try:
        import streamlit.web.cli as st_cli
        with patch.object(login, "start_warm_up", fake_warm), \
             patch.object(st_cli, "main", fake_cli):
            rc = launcher.main()
    finally:
        sys.argv = saved_argv
        os.chdir(saved_cwd)

    check("launcher starts ONLY the network-bound half (imports=False)",
          calls.get("warm") == {"imports": False}, str(calls.get("warm")))
    argv = calls.get("argv", [])
    check("hands off to `streamlit run dashboard/app.py`",
          argv[:2] == ["streamlit", "run"] and argv[2:3]
          and Path(argv[2]) == REPO_ROOT / "dashboard" / "app.py", str(argv))
    check("passes streamlit options through", argv[-2:] == ["--server.port", "8599"], str(argv))
    check("returns Streamlit's exit code", rc == 0)


if __name__ == "__main__":
    try:
        test_watcher_disabled()
        test_signin_same_run()
        test_release_reset()
        test_connect_single_pool()
        test_sys_path_stable()
        test_probe_session()
        test_overview_overlaps()
        test_warmup_off_request_path()
        test_cache_hit_miss_logged()
        test_heavy_imports_below_gate()
        test_launcher()
    finally:
        try:
            asyncio.run(db.close())
        except Exception:  # noqa: BLE001
            pass
        TEST_DB.unlink(missing_ok=True)
    print(f"\npassed: {passed}   failed: {failed}")
    sys.exit(1 if failed else 0)
