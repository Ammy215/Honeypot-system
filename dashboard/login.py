"""
Admin login and the shared page shell for the HoneyShield v2 dashboard.

Single admin account, argon2-hashed, lockout after repeated failures
(auth/async_admin_auth.py). Session state is Streamlit's own per-browser-
session store — nothing is written to disk or exposed to the client.
"""

import sys
from pathlib import Path

import streamlit as st

sys.path.insert(0, str(Path(__file__).parent.parent))

from auth.async_admin_auth import authenticate, bootstrap_admin_if_needed, DEFAULT_ADMIN_USERNAME
from dashboard import theme
from dashboard.async_bridge import run as bridge_run
from database.db_async import db


def _run(coro):
    """
    Bridge async db/auth calls into Streamlit's sync script model.

    Delegates to dashboard/async_bridge.py, which runs everything on one
    process-wide loop. This must never go back to asyncio.run(): the pool
    created here at login would then be unusable from every later page.
    """
    return bridge_run(coro)


def _ensure_bootstrapped():
    if st.session_state.get("_bootstrap_checked"):
        return
    st.session_state["_bootstrap_checked"] = True

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


def show_login_page():
    # Styling is applied by require_auth() BEFORE this runs, and deliberately
    # before any database work: _ensure_bootstrapped() opens the connection
    # pool, which costs ~3s on a cold process, and any CSS injected after it
    # leaves Streamlit's raw page nav visible and unstyled for that whole
    # window. theme.inject() needs no database, so it must never sit behind one.
    with st.spinner("Connecting…"):
        _ensure_bootstrapped()

    # The whole sign-in UI lives inside one placeholder so it can be cleared
    # from the CURRENT frame the instant credentials are accepted.
    #
    # Why that matters: st.rerun() aborts the script and re-runs it, but the
    # browser keeps displaying the last completed frame until the new one
    # arrives. Without this, the login card stayed painted on top of the
    # dashboard while it loaded. CSS on Streamlit's data-stale attribute does
    # not fix it either — that attribute lands on element containers, and a
    # form is a block, so the card was never matched. Emptying the placeholder
    # sends a delta that removes the card before the rerun begins, so the frame
    # the user stares at during loading no longer contains it.
    shell = st.empty()

    with shell.container():
        # Narrow centre column: a full-width form on a 1500px canvas looks like
        # an unfinished layout rather than a deliberate sign-in screen.
        _, mid, _ = st.columns([1, 1.05, 1])
        with mid:
            theme.auth_brand("HoneyShield", "Sign in to the intelligence console")

            with st.form("login_form", border=False):
                username = st.text_input("Username", placeholder="admin")
                password = st.text_input("Password", type="password",
                                         placeholder="Enter your password")
                submit = st.form_submit_button("Sign in", width="stretch", type="primary")

            if submit and (not username or not password):
                st.error("Enter both username and password.")
                return

            # Deliberately says nothing about the hashing algorithm, the lockout
            # threshold, or how many accounts exist. The previous version listed
            # all three, which handed an unauthenticated visitor a free
            # description of the auth implementation.
            st.markdown(
                '<div class="hs-auth-foot">AUTHORIZED ACCESS ONLY</div>',
                unsafe_allow_html=True,
            )

            if submit:
                success = _run(authenticate(username, password))
                if not success:
                    # Deliberately generic — never echoes the submitted password,
                    # never distinguishes "wrong password" from "locked out" from
                    # "unknown user".
                    st.error("Invalid username or password.")

    if submit and success:
        st.session_state["authenticated"] = True
        st.session_state["username"] = username
        shell.empty()          # clear the card from the frame being displayed
        st.rerun()


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
    database, whereas the login path opens the connection pool. Injecting after
    that showed Streamlit's unstyled page nav on a black canvas for the whole
    cold-start window.
    """
    authenticated = check_authentication()   # session_state only — instant
    theme.inject(authenticated=authenticated)

    if not authenticated:
        show_login_page()
        st.stop()

    show_user_info()
