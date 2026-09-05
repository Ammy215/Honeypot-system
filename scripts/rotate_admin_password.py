"""
Rotate the dashboard admin password.

Run this yourself, in your own terminal. The plaintext password exists only in
this process and on your screen: it is never written to disk, never logged,
never sent anywhere except as an argon2 hash to the database. Typed input is
read with getpass, so it is not echoed and does not enter your shell history.

    python scripts/rotate_admin_password.py            # generate a random one
    python scripts/rotate_admin_password.py --type     # type your own

Also clears failed_attempts and any lockout, so the account is left in a clean
state rather than carrying over counters from earlier testing.

Uses DATABASE_URL (the honeyshield_dashboard role), which holds UPDATE on
admin_users — the DB owner credential is deliberately not required here.
"""

import argparse
import asyncio
import getpass
import secrets
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from argon2 import PasswordHasher

import config
from auth.async_admin_auth import DEFAULT_ADMIN_USERNAME
from database.db_async import db

MIN_LENGTH = 12
_hasher = PasswordHasher()


def collect_password(generate: bool) -> tuple[str, bool]:
    """Return (password, was_generated). Never returns via stdout."""
    if generate:
        return secrets.token_urlsafe(24), True

    while True:
        first = getpass.getpass("New admin password (not echoed): ")
        if len(first) < MIN_LENGTH:
            print(f"  Too short — minimum {MIN_LENGTH} characters. Try again.")
            continue
        second = getpass.getpass("Confirm password: ")
        if first != second:
            print("  Passwords did not match. Try again.")
            continue
        return first, False


async def main() -> int:
    parser = argparse.ArgumentParser(description="Rotate the dashboard admin password.")
    parser.add_argument(
        "--type", dest="type_it", action="store_true",
        help="type your own password instead of generating one",
    )
    parser.add_argument(
        "--username", default=DEFAULT_ADMIN_USERNAME,
        help=f"admin username to rotate (default: {DEFAULT_ADMIN_USERNAME})",
    )
    args = parser.parse_args()

    if not config.DATABASE_URL:
        print("DATABASE_URL is not set — nothing to connect to. Check your .env.")
        return 1

    if db.backend != "postgres":
        # admin_users lives in the Postgres schema; the SQLite dev database
        # doesn't carry it. Fail loudly rather than half-succeeding.
        print(f"Backend is {db.backend!r}, expected 'postgres'. Set DATABASE_URL "
              f"to the dashboard role and retry.")
        return 1

    await db.connect()
    try:
        existing = await db.get_admin_user(args.username)
        if not existing:
            print(f"No admin_users row for {args.username!r}. Nothing rotated.")
            return 1

        password, generated = collect_password(generate=not args.type_it)
        new_hash = _hasher.hash(password)

        async with db._pg_pool.acquire() as conn:
            await conn.execute(
                "UPDATE admin_users "
                "SET password_hash = $1, failed_attempts = 0, locked_until = NULL "
                "WHERE username = $2",
                new_hash, args.username,
            )

        # Prove the new hash verifies before telling you it worked.
        check = await db.get_admin_user(args.username)
        _hasher.verify(check["password_hash"], password)

        print()
        print("=" * 60)
        print(f"Password rotated for {args.username!r} — verified against the stored hash.")
        print("failed_attempts reset to 0, lockout cleared.")
        if generated:
            print()
            print(f"  New password: {password}")
            print()
            print("Shown once, here, on your screen only. Save it now.")
        else:
            print("Your typed password is in effect. It was never displayed.")
        print("=" * 60)
        return 0
    finally:
        # Drop the plaintext reference as early as possible.
        password = None
        await db.close()


if __name__ == "__main__":
    raise SystemExit(asyncio.run(main()))
