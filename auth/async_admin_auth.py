"""
Admin authentication for the v2 dashboard — HoneyShield v2 (asyncio).

Single admin account, argon2 password hashing, lockout after repeated
failures — per HONEYSHIELD_PROJECT.md section 6 point 6 and section 10
phase 4. Separate from the v1 auth system (auth/auth_manager.py, bcrypt,
users.json) which stays untouched for the old dashboard.

The admin password is never persisted in plaintext, never logged, and
never displayed anywhere in the app — the only place it's ever shown is
once, on the console, the moment the first-run account is created.
"""

import logging
import secrets
from typing import Optional

from argon2 import PasswordHasher
from argon2.exceptions import VerifyMismatchError, InvalidHash

from database.db_async import db

logger = logging.getLogger("honeypot.dashboard.auth")

MAX_FAILED_ATTEMPTS = 10
LOCKOUT_MINUTES = 15
DEFAULT_ADMIN_USERNAME = "admin"

_hasher = PasswordHasher()


def hash_password(password: str) -> str:
    return _hasher.hash(password)


async def bootstrap_admin_if_needed() -> Optional[str]:
    """
    Create the default admin account on first run. Returns the generated
    password if one was created (so main/login code can print it once),
    or None if an admin already exists.
    """
    if await db.count_admin_users() > 0:
        return None

    password = secrets.token_urlsafe(16)
    await db.create_admin_user(DEFAULT_ADMIN_USERNAME, hash_password(password))
    logger.warning("Created default admin account (credentials printed to console once, not persisted).")
    return password


async def authenticate(username: str, password: str) -> bool:
    """Verify credentials, enforcing lockout. Never raises, never logs the password."""
    user = await db.get_admin_user(username)
    if not user:
        return False

    if user.get("locked_until") and await db.is_admin_locked_out(username):
        logger.warning(f"Login blocked: {username} is locked out")
        return False

    try:
        _hasher.verify(user["password_hash"], password)
    except (VerifyMismatchError, InvalidHash):
        await db.record_admin_login_failure(username, MAX_FAILED_ATTEMPTS, LOCKOUT_MINUTES)
        logger.warning(f"Login failed for {username}: invalid password")
        return False

    await db.record_admin_login_success(username)
    logger.info(f"Login succeeded for {username}")
    return True
