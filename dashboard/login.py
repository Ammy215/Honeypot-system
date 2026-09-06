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
    _ensure_bootstrapped()
    theme.inject(authenticated=False)

    # Narrow centre column: a full-width form on a 1500px canvas looks like an
    # unfinished layout rather than a deliberate sign-in screen.
    _, mid, _ = st.columns([1, 1.05, 1])
    with mid:
        theme.auth_brand("HoneyShield", "Sign in to the intelligence console")

        with st.form("login_form", border=False):
            username = st.text_input("Username", placeholder="admin")
            password = st.text_input("Password", type="password", placeholder="Enter your password")
            submit = st.form_submit_button("Sign in", width="stretch", type="primary")

        if submit:
            if not username or not password:
                st.error("Enter both username and password.")
                return

            success = _run(authenticate(username, password))

            if success:
                st.session_state["authenticated"] = True
                st.session_state["username"] = username
                st.rerun()
            else:
                # Deliberately generic — never echoes the submitted password, never
                # distinguishes "wrong password" from "locked out" from "unknown user".
                st.error("Invalid username or password.")

        # Deliberately says nothing about the hashing algorithm, the lockout
        # threshold, or how many accounts exist. The previous version listed all
        # three, which handed an unauthenticated visitor a free description of
        # the auth implementation — and read as debug output besides.
        st.markdown(
            '<div class="hs-auth-foot">AUTHORIZED ACCESS ONLY</div>',
            unsafe_allow_html=True,
        )


def check_authentication() -> bool:
    return bool(st.session_state.get("authenticated"))


def logout():
    st.session_state["authenticated"] = False
    st.session_state["username"] = None
    st.rerun()


def show_user_info():
    """Sidebar: brand, identity, navigation, sign-out."""
    theme.sidebar_identity(st.session_state.get("username") or "unknown")
    st.sidebar.markdown("<div style='height:.6rem'></div>", unsafe_allow_html=True)
    if st.sidebar.button("Sign out", width="stretch"):
        logout()


def require_auth(page_icon: str, page_title: str) -> None:
    """
    Standard page preamble: gate, theme, sidebar.

    Every page called the same four functions in the same order and drifted
    over time; centralising it means a new page cannot forget the auth gate.
    Call immediately after st.set_page_config().
    """
    if not check_authentication():
        show_login_page()
        st.stop()
    theme.inject()
    show_user_info()
