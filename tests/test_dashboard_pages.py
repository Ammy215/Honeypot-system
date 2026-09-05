"""
Dashboard render + event-loop regression tests.

Run directly:  python tests/test_dashboard_pages.py

Two things are covered, and the second is the reason this file exists.

1. Every dashboard page renders without raising, via Streamlit's AppTest —
   headless, no browser. This is the check that was missing when the
   cross-event-loop bug shipped: each page's queries worked fine in isolation,
   but no test ever executed a page the way Streamlit actually does.

2. The cross-loop failure mode itself, pinned directly. The dashboard used
   asyncio.run() at every call site, which builds and closes a fresh event
   loop per call. asyncpg pools bind to their creating loop, so the pool built
   during login was unusable by every later query — "cannot perform operation:
   another operation is in progress" on every page, after login, against
   Postgres. dashboard/async_bridge.py fixes this by owning one loop for the
   process; these tests fail if anyone reverts to per-call asyncio.run().

Needs a reachable database (DATABASE_URL in .env). Read-only apart from the
login-attempt counters that authenticate() maintains, which are not touched
here — no page performs a write on load.
"""

import ast
import asyncio
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from dotenv import load_dotenv

load_dotenv(ROOT / ".env")

from streamlit.testing.v1 import AppTest

from dashboard import async_bridge
from database.db_async import db

PAGES = sorted((ROOT / "dashboard" / "pages").glob("*.py"))
APP = ROOT / "dashboard" / "app.py"

passed = 0
failed = 0


def check(label: str, condition: bool, detail: str = "") -> None:
    global passed, failed
    if condition:
        passed += 1
        print(f"  PASS  {label}")
    else:
        failed += 1
        print(f"  FAIL  {label}" + (f"\n          {detail}" if detail else ""))


# ── 1. Regression: no asyncio.run() anywhere in dashboard code ─────────────
def test_no_asyncio_run_in_dashboard():
    print("\n[1] no per-call asyncio.run() in dashboard/")
    offenders = []
    for f in [APP] + [ROOT / "dashboard" / "login.py"] + PAGES:
        # Parse rather than grep: these files *document* the asyncio.run()
        # pitfall in their docstrings, and a text search cannot tell an
        # explanation of the bug from a reintroduction of it.
        tree = ast.parse(f.read_text(encoding="utf-8"))
        for node in ast.walk(tree):
            if (
                isinstance(node, ast.Call)
                and isinstance(node.func, ast.Attribute)
                and node.func.attr == "run"
                and isinstance(node.func.value, ast.Name)
                and node.func.value.id == "asyncio"
            ):
                offenders.append(f"{f.name}:{node.lineno}")
    check(
        "no dashboard file calls asyncio.run()",
        not offenders,
        f"offenders: {offenders} — use dashboard.async_bridge.run() instead; "
        f"asyncio.run() closes the loop the asyncpg pool is bound to",
    )


# ── 2. Regression: the bridge reuses one loop across calls ────────────────
def test_bridge_reuses_one_loop():
    print("\n[2] bridge keeps a single event loop across calls")

    async def which_loop():
        return id(asyncio.get_running_loop())

    a = async_bridge.run(which_loop())
    b = async_bridge.run(which_loop())
    c = async_bridge.run(which_loop())
    check("three separate run() calls share one loop", a == b == c,
          f"loop ids: {a}, {b}, {c}")

    async def loop_is_open():
        return not asyncio.get_running_loop().is_closed()

    check("loop stays open between calls", async_bridge.run(loop_is_open()))


# ── 3. Regression: the exact failure mode, end to end ─────────────────────
def test_pool_survives_across_calls():
    """
    The precise bug: connect in one call, query in a later, separate call.
    Under the old asyncio.run() pattern this raised InterfaceError every time.
    """
    print("\n[3] pool built in one call is usable by a later call")

    async_bridge.run(db.connect())          # call 1 — builds the pool
    pool_after_connect = db._pg_pool

    try:
        first = async_bridge.run(db.summary_counts())   # call 2 — different call
        second = async_bridge.run(db.summary_counts())  # call 3
        check("query succeeds in a later run() call", isinstance(first, dict))
        check("and again in a third call", isinstance(second, dict))
        check("same pool object reused, not rebuilt",
              db._pg_pool is pool_after_connect)
    except Exception as exc:  # noqa: BLE001 — reporting, not swallowing
        check("query succeeds in a later run() call", False,
              f"{type(exc).__name__}: {exc}")


# ── 4. Regression: connect() is idempotent ────────────────────────────────
def test_connect_is_idempotent():
    print("\n[4] db.connect() is idempotent")
    async_bridge.run(db.connect())
    pool = db._pg_pool
    async_bridge.run(db.connect())
    async_bridge.run(db.connect())
    check("repeated connect() keeps the same pool", db._pg_pool is pool)


# ── 5. Every page renders ─────────────────────────────────────────────────
def render(path: Path, authenticated: bool = True) -> AppTest:
    at = AppTest.from_file(str(path), default_timeout=180)
    if authenticated:
        at.session_state["authenticated"] = True
        at.session_state["username"] = "admin"
    at.run()
    return at


def test_pages_render():
    print("\n[5] every page renders while authenticated")
    for path in [APP] + PAGES:
        try:
            at = render(path)
            exceptions = list(at.exception)
            check(
                f"{path.name} renders",
                not exceptions,
                "; ".join(e.message for e in exceptions) if exceptions else "",
            )
        except Exception as exc:  # noqa: BLE001
            check(f"{path.name} renders", False, f"{type(exc).__name__}: {exc}")


def test_pages_gate_on_auth():
    print("\n[6] every page shows login when unauthenticated")
    for path in [APP] + PAGES:
        try:
            at = render(path, authenticated=False)
            titles = [t.value for t in at.title]
            check(
                f"{path.name} gates on auth",
                any("Login" in t for t in titles) and not list(at.exception),
                f"titles={titles} exceptions={[e.message for e in at.exception]}",
            )
        except Exception as exc:  # noqa: BLE001
            check(f"{path.name} gates on auth", False, f"{type(exc).__name__}: {exc}")


def test_live_feed_shows_filtered_panel():
    print("\n[7] Live Feed renders the filtered-traffic panel")
    live = next(p for p in PAGES if "Live_Feed" in p.name)
    at = render(live)
    labels = [m.label for m in at.metric]
    for expected in ("Filtered (total)", "Last hour", "Last 24h", "Most recent"):
        check(f"metric present: {expected}", expected in labels, f"got {labels}")
    check("subheader present", "Filtered Traffic" in [s.value for s in at.subheader])


if __name__ == "__main__":
    print("=" * 70)
    print("Dashboard render + event-loop regression tests")
    print("=" * 70)

    test_no_asyncio_run_in_dashboard()
    test_bridge_reuses_one_loop()
    test_pool_survives_across_calls()
    test_connect_is_idempotent()
    test_pages_render()
    test_pages_gate_on_auth()
    test_live_feed_shows_filtered_panel()

    print("\n" + "=" * 70)
    print(f"passed: {passed}   failed: {failed}")
    print("=" * 70)
    sys.exit(1 if failed else 0)
