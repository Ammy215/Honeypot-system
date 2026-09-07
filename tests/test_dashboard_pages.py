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


def check_true(label: str, condition: bool, detail: str = "") -> None:
    check(label, bool(condition), detail)


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


# Match the rendered elements, not the stylesheet: the injected CSS names
# every class, so a substring check against class names alone always matches.
HEADER_DIV = '<div class="hs-header">'
LOGIN_DIV = '<div class="hs-auth">'


def theme_nav_targets():
    """The nav entries the design system declares."""
    from dashboard import theme
    return theme.NAV


def _markup(at) -> str:
    """All markdown emitted by a run, so we can assert on design-system markers."""
    return " ".join(str(m.value) for m in at.markdown)


def test_pages_gate_on_auth():
    print("\n[6] every page shows login when unauthenticated")
    for path in [APP] + PAGES:
        try:
            at = render(path, authenticated=False)
            markup = _markup(at)
            # The login screen renders the brand block; an authenticated page
            # renders the page masthead. Asserting on both directions catches a
            # page that renders its content *and* a login form.
            gated = HEADER_DIV not in markup and LOGIN_DIV in markup
            check(
                f"{path.name} gates on auth",
                gated and not list(at.exception),
                f"login_brand={LOGIN_DIV in markup} "
                f"page_header={HEADER_DIV in markup} "
                f"exceptions={[e.message for e in at.exception]}",
            )
        except Exception as exc:  # noqa: BLE001
            check(f"{path.name} gates on auth", False, f"{type(exc).__name__}: {exc}")


def test_login_form_is_usable():
    print("\n[6b] the login screen actually renders a usable form")
    at = render(APP, authenticated=False)
    check_true(f"two inputs, username + password (got {len(at.text_input)})",
               len(at.text_input) == 2)
    check_true("a submit control exists", len(at.button) >= 1)
    check_true("no data is rendered before login", len(at.dataframe) == 0)

    # Streamlit's built-in page menu must be OFF at config level, not merely
    # hidden by CSS: the frontend paints it as soon as the browser connects,
    # before any script output exists, so an injected stylesheet always loses
    # that race and the raw menu flashes on the login screen.
    cfg = (ROOT / ".streamlit" / "config.toml").read_text(encoding="utf-8")
    check_true("built-in page nav disabled in config.toml",
               "showSidebarNavigation = false" in cfg)

    # And the replacement nav must not appear until authenticated.
    before = len(at.get("page_link"))
    check_true(f"no nav links before login (got {before})", before == 0)
    after = len(render(APP, authenticated=True).get("page_link"))
    check_true(f"nav links appear once authenticated (got {after}, "
               f"expected >= {len(theme_nav_targets())})",
               after >= len(theme_nav_targets()))


def test_live_feed_shows_filtered_panel():
    print("\n[7] Live Feed renders the filtered-traffic panel")
    live = next(p for p in PAGES if "Live_Feed" in p.name)
    at = render(live)
    markup = _markup(at)
    # KPIs render through the design system rather than st.metric, so assert on
    # the emitted markup instead of widget labels.
    for expected in ("Filtered total", "Last hour", "Last 24h", "Most recent"):
        check_true(f"KPI present: {expected}", expected in markup)
    check_true("section heading present", "Filtered traffic" in markup)
    check_true("KPI cards use the design system", "hs-kpi" in markup)


def test_pages_read_through_the_cache():
    """
    Pages must read via dashboard/data.py, never by awaiting db.* directly.

    The database is a remote pooler with a ~200ms+ round-trip floor, and
    Streamlit re-executes the whole script on every interaction. A page that
    calls bridge_run(db.something()) pays that latency again on every click,
    which is exactly the regression that made Overview take 4.3 seconds. Writes
    are exempt — they must not be cached.
    """
    print("\n[9] pages read through the cached data layer")
    WRITES = {"acknowledge_alert", "generate_attacker_report"}
    offenders = []
    for f in [APP] + PAGES:
        tree = ast.parse(f.read_text(encoding="utf-8"))
        for node in ast.walk(tree):
            if not (isinstance(node, ast.Call)
                    and isinstance(node.func, ast.Name)
                    and node.func.id == "bridge_run" and node.args):
                continue
            inner = node.args[0]
            name = getattr(inner.func, "attr", getattr(inner.func, "id", "")) \
                if isinstance(inner, ast.Call) else ""
            if name not in WRITES:
                offenders.append(f"{f.name}:{node.lineno} -> {name or '?'}")
    check("no page awaits a read query directly", not offenders,
          f"offenders: {offenders} — route reads through dashboard/data.py")


def test_data_layer_is_concurrent_and_cached():
    print("\n[10] the data layer gathers and caches")
    src = (ROOT / "dashboard" / "data.py").read_text(encoding="utf-8")
    tree = ast.parse(src)

    cached, gathering = set(), set()
    for node in ast.walk(tree):
        if isinstance(node, ast.FunctionDef):
            for dec in node.decorator_list:
                target = dec.func if isinstance(dec, ast.Call) else dec
                if getattr(target, "attr", "") == "cache_data":
                    cached.add(node.name)
        if isinstance(node, ast.Attribute) and node.attr == "gather":
            gathering.add(True)

    # Every page bundle must be cached.
    for fn in ("overview", "live_feed", "analytics", "alerts", "hunting_context"):
        check_true(f"{fn}() is cached", fn in cached, f"cached: {sorted(cached)}")
    check_true("multi-query bundles use asyncio.gather", bool(gathering))

    # summary_counts must be a single statement, not a loop of four.
    db_src = (ROOT / "database" / "db_async.py").read_text(encoding="utf-8")
    body = db_src.split("async def summary_counts", 1)[1].split("async def", 1)[0]
    check("summary_counts issues one SELECT", body.count("SELECT COUNT(*)"), 4)
    check_true("…combined into a single statement (not four fetches)",
               body.count("fetchrow") <= 1 and "for key, q in" not in body)

    # Threat Hunting must count, not download, the credential corpus.
    check_true("count_login_attempts exists", "async def count_login_attempts" in db_src)
    hunting = next(p for p in PAGES if "Threat_Hunting" in p.name).read_text(encoding="utf-8")
    check_true("hunting sizes the corpus without fetching 500 rows",
               'search_login_attempts("", limit=500)' not in hunting)


def test_pages_use_theme_components():
    """
    Pages compose the design system; they do not hand-roll equivalents.

    Each of these has a theme.py counterpart, and calling the Streamlit
    primitive directly bypasses the shared styling — which is how a page ends
    up looking like a different application. The point of the design system is
    that changing it once changes everything.
    """
    print("\n[11] pages use theme components, not raw primitives")
    BANNED = {
        "plotly_chart": "theme.plot()",
        "dataframe": "theme.table()",
        "metric": "theme.kpis()",
    }
    offenders = []
    for f in [APP] + PAGES:
        tree = ast.parse(f.read_text(encoding="utf-8"))
        for node in ast.walk(tree):
            if (isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute)
                    and isinstance(node.func.value, ast.Name)
                    and node.func.value.id == "st" and node.func.attr in BANNED):
                offenders.append(f"{f.name}:{node.lineno} st.{node.func.attr} "
                                 f"-> use {BANNED[node.func.attr]}")
    check("no page calls a styled primitive directly", not offenders,
          "; ".join(offenders))

    # Markdown sub-headings bypass the type scale; theme.subsection() exists.
    heading_offenders = []
    for f in [APP] + PAGES:
        for i, line in enumerate(f.read_text(encoding="utf-8").splitlines(), 1):
            if "st.markdown(" in line and ("#####" in line or "####" in line):
                heading_offenders.append(f"{f.name}:{i}")
    check("no page uses markdown sub-headings", not heading_offenders,
          f"{heading_offenders} — use theme.subsection()")


def test_design_system_applied():
    print("\n[8] the design system is applied on every page")
    for path in [APP] + PAGES:
        at = render(path)
        markup = _markup(at)
        check_true(f"{path.name} injects theme CSS", HEADER_DIV in markup and "--accent" in markup)


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
    test_login_form_is_usable()
    test_live_feed_shows_filtered_panel()
    test_pages_read_through_the_cache()
    test_data_layer_is_concurrent_and_cached()
    test_pages_use_theme_components()
    test_design_system_applied()

    print("\n" + "=" * 70)
    print(f"passed: {passed}   failed: {failed}")
    print("=" * 70)
    sys.exit(1 if failed else 0)
