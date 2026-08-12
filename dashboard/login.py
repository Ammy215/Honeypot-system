"""
Admin login for the HoneyShield v2 dashboard.

Single admin account, argon2-hashed, lockout after repeated failures
(auth/async_admin_auth.py). Session state is Streamlit's own per-browser-
session store — nothing is written to disk or exposed to the client.
"""

import asyncio
import sys
from pathlib import Path

import streamlit as st

sys.path.insert(0, str(Path(__file__).parent.parent))

from auth.async_admin_auth import authenticate, bootstrap_admin_if_needed, DEFAULT_ADMIN_USERNAME
from database.db_async import db


def _run(coro):
    """Bridge async db/auth calls into Streamlit's sync script model."""
    return asyncio.run(coro)


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

    st.set_page_config(page_title="HoneyShield Login", page_icon="🔐", layout="centered")
    st.title("🔐 HoneyShield Login")
    st.caption("Single admin account. Default credentials are printed once to the server console on first run.")

    with st.form("login_form"):
        username = st.text_input("Username")
        password = st.text_input("Password", type="password")
        submit = st.form_submit_button("Log In", width='stretch')

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


def check_authentication() -> bool:
    return bool(st.session_state.get("authenticated"))


def logout():
    st.session_state["authenticated"] = False
    st.session_state["username"] = None
    st.rerun()


def show_user_info():
    if st.session_state.get("username"):
        st.sidebar.markdown("---")
        st.sidebar.markdown(f"**Logged in as:** {st.session_state['username']}")
        if st.sidebar.button("Log Out", width='stretch'):
            logout()
