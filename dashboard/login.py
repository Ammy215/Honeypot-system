"""
Admin login and the shared page shell for the HoneyShield v2 dashboard.

Single admin account, argon2-hashed, lockout after repeated failures
(auth/async_admin_auth.py). Session state is Streamlit's own per-browser-
session store — nothing is written to disk or exposed to the client.
"""

import importlib
import logging
import sys
import threading
import time
from pathlib import Path

import streamlit as st

_ROOT = str(Path(__file__).parent.parent)
if _ROOT not in sys.path:
    sys.path.insert(0, _ROOT)

from auth.async_admin_auth import authenticate, bootstrap_admin_if_needed, DEFAULT_ADMIN_USERNAME
from dashboard import perf, theme
from dashboard.async_bridge import run as bridge_run
from database.db_async import db

logger = logging.getLogger("honeypot.dashboard.login")


def _run(coro):
    """
    Bridge async db/auth calls into Streamlit's sync script model.

    Delegates to dashboard/async_bridge.py, which runs everything on one
    process-wide loop. This must never go back to asyncio.run(): the pool
    created here at login would then be unusable from every later page.
    """
    return bridge_run(coro)


# ── Process warm-up ───────────────────────────────────────────────────────
# Everything expensive about a cold dashboard process, measured:
#
#   connection pool (5 x TLS + SCRAM to a ~250 ms-RTT pooler) ... ~3.6 s  network-bound
#   pandas + pyarrow + the data layer ........................... ~2 s    CPU-bound
#   plotly.express (Analytics) .................................. ~1 s    CPU-bound
#
# This used to run on the request path: the sign-in form waited on the pool —
# 11 s to first paint on a fresh process — and the admin bootstrap query ran
# again for EVERY new browser session (~0.5 s each) although it only ever needs
# to happen once per process. Now each half runs once, in the background, while
# the operator is typing a password instead of after they click.
#
# The two halves are started separately because they cost differently. The
# pool is network-bound and can start whenever — run_dashboard.py starts it the
# moment the process does. The imports are CPU-bound and contend for the GIL
# with whatever the server is doing: started at process start, they were still
# running when the first browser arrived and made its sign-in form 3.5 s
# SLOWER (measured). So they begin only once a sign-in form has been sent.
#
# It performs no data queries on behalf of an unauthenticated visitor — only
# the pool, the one-time admin bootstrap, and imports.
_WARMED = threading.Event()
_warm_lock = threading.Lock()
_db_warm_started = False
_imports_warm_started = False

# Long enough for the sign-in form to reach the browser before the imports
# start competing for the GIL; invisible to anyone, who is still typing.
IMPORT_WARM_UP_DELAY_SECONDS = 1.0


def _warm_up_process() -> None:
    started = time.perf_counter()
    try:
        _run(db.connect())
        _run(db.init_schema())
        generated_password = _run(bootstrap_admin_if_needed())
        if generated_password:
            banner = "=" * 60
            print(banner)
            print("First-run setup: created default dashboard admin account")
            print(f"  Username: {DEFAULT_ADMIN_USERNAME}")
            print(f"  Password: {generated_password}")
            print("This password is shown ONCE and is not stored anywhere in")
            print("plaintext. Save it now.")
            print(banner)
    except Exception:  # noqa: BLE001 — surfaced at sign-in, where it can be shown
        logger.exception("Dashboard warm-up could not reach the database")
    finally:
        _WARMED.set()
        perf.event(f"warm-up: database ready for sign-in "
                   f"{(time.perf_counter() - started) * 1000:.0f} ms after it started")


# What pages import AFTER their auth gate, in the order a signed-in operator
# needs them. Deliberately NOT google.genai: honeypot/ai/async_analyst.py now
# imports it only when a report is actually generated, and preloading it here
# (4.5 s of GIL-heavy work) is what slowed the first sign-in by 3.5 s.
_PAGE_MODULES = ("pandas", "pyarrow", "dashboard.data", "plotly.express",
                 "honeypot.ai.async_analyst")


def _import_page_modules() -> None:
    """
    Load the pages' heavy modules in the background, while the form is shown.

    Every page imports these below require_auth rather than at the top, and
    that placement is measured, not stylistic. Above the gate, a freshly
    started server had to import pandas, the data layer and — on AI Analysis —
    google.genai before it could send even the SIGN-IN form: ~3-4 s on most
    pages and 8 s on AI Analysis, for a screen that uses none of them. The auth
    gate itself needs 81 ms of imports. Below the gate, the form goes out at
    once and this thread loads the rest while the operator types; a page that
    reaches its imports first simply waits on Python's import lock rather than
    importing twice.

    Its own thread, not the database one: imports are CPU-bound and pool
    creation is network-bound, so running them side by side overlaps the two.
    """
    time.sleep(IMPORT_WARM_UP_DELAY_SECONDS)
    for name in _PAGE_MODULES:
        try:
            importlib.import_module(name)
        except Exception:  # noqa: BLE001 — the page will import it again and report properly
            logger.exception(f"Dashboard warm-up could not preload {name}")


def start_warm_up(*, imports: bool = True) -> None:
    """
    Start the once-per-process warm-up in the background; repeat calls no-op.

    The database half always starts. The import half starts only when
    `imports` is true — the sign-in screen passes that, having just sent its
    form; run_dashboard.py does not, because at process start nothing has been
    sent yet and the imports would compete with the first browser's request.
    """
    global _db_warm_started, _imports_warm_started
    with _warm_lock:
        start_db = not _db_warm_started
        start_imports = imports and not _imports_warm_started
        _db_warm_started = True
        _imports_warm_started = _imports_warm_started or imports
    if start_db:
        threading.Thread(target=_warm_up_process, name="hs-warmup-db", daemon=True).start()
    if start_imports:
        threading.Thread(target=_import_page_modules, name="hs-warmup-imports",
                         daemon=True).start()


def show_login_page() -> bool:
    """
    Render the sign-in screen. Returns True if credentials were accepted in
    THIS run, in which case the caller carries straight on and draws the page.
    """
    start_warm_up()

    # The whole sign-in UI lives inside one placeholder so it can be removed
    # from the current frame the moment credentials are accepted.
    shell = st.empty()
    success = False

    with shell.container():
        # Narrow centre column: a full-width form on a 1500px canvas looks like
        # an unfinished layout rather than a deliberate sign-in screen.
        _, mid, _ = st.columns([1, 1.05, 1])
        with mid:
            theme.auth_brand("HoneyShield", "Sign in to the intelligence console")

            # clear_on_submit: the page is now drawn in the same run as the
            # submission, so these widgets — the password included — would
            # otherwise keep their values in server-side session state until
            # the next interaction. Clearing on submit drops them immediately.
            with st.form("login_form", border=False, clear_on_submit=True):
                username = st.text_input("Username", placeholder="admin")
                password = st.text_input("Password", type="password",
                                         placeholder="Enter your password")
                submit = st.form_submit_button("Sign in", width="stretch", type="primary")

            if submit and (not username or not password):
                st.error("Enter both username and password.")
                return False

            # Deliberately says nothing about the hashing algorithm, the lockout
            # threshold, or how many accounts exist. The previous version listed
            # all three, which handed an unauthenticated visitor a free
            # description of the auth implementation.
            st.markdown(
                '<div class="hs-auth-foot">AUTHORIZED ACCESS ONLY</div>',
                unsafe_allow_html=True,
            )

            if submit:
                with st.spinner("Signing in…"):
                    _WARMED.wait(timeout=60)
                    try:
                        success = _run(authenticate(username, password))
                    except Exception:  # noqa: BLE001 — never leak DB detail pre-auth
                        logger.exception("Sign-in could not reach the database")
                        st.error("The console cannot reach its database right now. "
                                 "Try again shortly.")
                        return False
                if not success:
                    # Deliberately generic — never echoes the submitted password,
                    # never distinguishes "wrong password" from "locked out" from
                    # "unknown user".
                    st.error("Invalid username or password.")

    if submit and success:
        st.session_state["authenticated"] = True
        st.session_state["username"] = username
        shell.empty()
        return True
    return False


def check_authentication() -> bool:
    return bool(st.session_state.get("authenticated"))


def logout():
    st.session_state["authenticated"] = False
    st.session_state["username"] = None
    st.rerun()


def show_user_info():
    """Sidebar: brand, navigation, identity, refresh, sign-out."""
    theme.sidebar_identity(st.session_state.get("username") or "unknown")
    theme.sidebar_nav()

    # Page data is cached for a short TTL so re-renders don't re-query a remote
    # database (see dashboard/data.py). This is the escape hatch when you want
    # the current state right now rather than within the TTL.
    if st.sidebar.button("Refresh data", width="stretch", icon=":material/refresh:"):
        from dashboard import data
        data.refresh()
        st.rerun()

    st.sidebar.markdown("<div style='height:.4rem'></div>", unsafe_allow_html=True)
    if st.sidebar.button("Sign out", width="stretch"):
        logout()


def require_auth(page_icon: str, page_title: str) -> None:
    """
    Standard page preamble: gate, theme, sidebar.

    Every page called the same four functions in the same order and drifted
    over time; centralising it means a new page cannot forget the auth gate.
    Call immediately after st.set_page_config().

    Order matters: the theme goes in FIRST, because it is pure CSS and needs no
    database.

    A successful sign-in does NOT st.rerun(). It used to, after emptying the
    sign-in placeholder — and the card still stayed painted over the dashboard
    for as long as the dashboard took to load. The cause is in Streamlit
    itself: when a run starts, AppSession._clear_queue() discards every queued
    delta the browser has not received yet. The "remove the card" delta was
    queued microseconds before the rerun began, so it was almost always thrown
    away, and the browser kept showing the card (dimmed as stale) until the new
    run overwrote its position. Measured in a real browser: 675 ms of card over
    Overview on a cache miss, longer against the remote database.

    Carrying on in the same run means there is no new run to discard anything:
    the card is removed and the page drawn in one continuous stream of deltas.
    """
    authenticated = check_authentication()   # session_state only — instant
    gate = theme.inject(authenticated=authenticated)

    if not authenticated:
        if not show_login_page():
            st.stop()
        if gate is not None:
            gate.empty()                     # lift the sign-in screen's sidebar hide

    show_user_info()
