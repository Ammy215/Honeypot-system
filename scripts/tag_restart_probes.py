#!/usr/bin/env python3
"""
Label the hosting platform's restart probes in `connections` / `attackers`.

    python scripts/tag_restart_probes.py             # dry run: shows every decision
    python scripts/tag_restart_probes.py --apply     # write the labels

Render probes the service once, about a second after every deploy or restart,
and the honeypot captures that request like any other visitor. Those rows are
true records, but they are not attacker traffic, and unlabelled they inflate
every count on the dashboard. This labels them; it never deletes anything.

The rule, the evidence behind it and the per-row reasoning live in
database/traffic_classification.py. Re-run this after a deploy to label the
probe that deploy produced; it is idempotent, so re-running changes nothing
else. Needs the owner role (SUPABASE_OWNER_DATABASE_URL) because the dashboard
role is read-only by design.
"""

import argparse
import asyncio
import os
import sys
from pathlib import Path
from urllib.parse import quote, urlsplit, urlunsplit

REPO_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO_ROOT))

import asyncpg  # noqa: E402
from dotenv import load_dotenv  # noqa: E402

from database.traffic_classification import (  # noqa: E402
    CLASS_LIKELY, CLASS_PROBE, RESTART_WINDOW_SECONDS, attacker_class, classify,
)

COLUMNS = (
    ("connections", "traffic_class", "TEXT"),
    ("connections", "traffic_class_note", "TEXT"),
    ("attackers", "traffic_class", "TEXT"),
)

ROWS_SQL = """
    SELECT c.id, c.connected_at, host(c.ip_address) AS ip, c.method, c.path,
           c.user_agent, c.traffic_class AS current_class,
           a.isp, a.city, a.asn
    FROM connections c
    LEFT JOIN attackers a ON a.ip_address = c.ip_address
    ORDER BY c.connected_at
"""


def owner_url() -> str:
    load_dotenv(REPO_ROOT / ".env")
    raw = os.environ["SUPABASE_OWNER_DATABASE_URL"]
    parts = urlsplit(raw)                       # the owner password contains &%!*_
    user, _, pwd = parts.netloc.rpartition("@")[0].partition(":")
    host = parts.netloc.rpartition("@")[2]
    netloc = f"{quote(user, safe='')}:{quote(pwd, safe='')}@{host}"
    return urlunsplit((parts.scheme, netloc, parts.path, parts.query, parts.fragment))


async def ensure_columns(conn, apply: bool) -> bool:
    """Add the label columns if they are missing. Additive and nullable."""
    missing = []
    for table, column, coltype in COLUMNS:
        exists = await conn.fetchval(
            "SELECT 1 FROM information_schema.columns "
            "WHERE table_schema = 'public' AND table_name = $1 AND column_name = $2",
            table, column)
        if not exists:
            missing.append((table, column, coltype))
    if not missing:
        return True
    print(f"  schema: {len(missing)} column(s) missing: "
          + ", ".join(f"{t}.{c}" for t, c, _ in missing))
    if not apply:
        print("  schema: --apply would add them (nullable, no default: existing rows"
              " stay valid and the honeypot's INSERTs are unaffected)")
        return False
    for table, column, coltype in missing:
        await conn.execute(f"ALTER TABLE {table} ADD COLUMN IF NOT EXISTS {column} {coltype}")
        print(f"  schema: added {table}.{column}")
    return True


async def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--apply", action="store_true", help="write labels (default: dry run)")
    ap.add_argument("--window", type=int, default=RESTART_WINDOW_SECONDS,
                    help=f"seconds after an instance start (default {RESTART_WINDOW_SECONDS})")
    args = ap.parse_args()

    conn = await asyncpg.connect(owner_url(), ssl="require")
    try:
        have_columns = await ensure_columns(conn, args.apply)

        markers = [r["filtered_at"] for r in await conn.fetch(
            "SELECT filtered_at FROM filtered_connections "
            "WHERE host(peer_ip) = '127.0.0.1' ORDER BY filtered_at")]
        rows = await conn.fetch(ROWS_SQL) if have_columns else await conn.fetch(
            ROWS_SQL.replace("c.traffic_class AS current_class,", "NULL AS current_class,"))
        print(f"\n  {len(markers)} instance-start marker(s); {len(rows)} connection(s); "
              f"window {args.window}s\n")

        decisions, counts = [], {CLASS_PROBE: 0, CLASS_LIKELY: 0, None: 0}
        for row in rows:
            klass, note = classify(dict(row), markers, args.window)
            counts[klass] += 1
            decisions.append((row, klass, note))
            mark = {CLASS_PROBE: "PROBE ", CLASS_LIKELY: "LIKELY", None: "keep  "}[klass]
            req = f"{row['method'] or '-'} {row['path'] or '-'}"
            print(f"  {mark} id={row['id']:<4} {row['connected_at']:%Y-%m-%d %H:%M:%S} "
                  f"{row['ip']:<16} {req:<10} {note}")

        print(f"\n  restart probes: {counts[CLASS_PROBE]}   "
              f"likely (request never recorded): {counts[CLASS_LIKELY]}   "
              f"unlabelled: {counts[None]}")

        if not args.apply:
            print("\n  DRY RUN — nothing written. Re-run with --apply.\n")
            return 0

        async with conn.transaction():
            for row, klass, note in decisions:
                await conn.execute(
                    "UPDATE connections SET traffic_class = $1, traffic_class_note = $2 "
                    "WHERE id = $3", klass, note if klass else None, row["id"])

            by_ip = {}
            for row, klass, _ in decisions:
                by_ip.setdefault(row["ip"], []).append(klass)
            labelled = 0
            for ip, classes in by_ip.items():
                klass = attacker_class(classes)
                labelled += klass is not None
                await conn.execute(
                    "UPDATE attackers SET traffic_class = $1 WHERE ip_address = $2::inet",
                    klass, ip)

        print(f"\n  COMMITTED: {counts[CLASS_PROBE] + counts[CLASS_LIKELY]} connection(s) "
              f"labelled, {labelled}/{len(by_ip)} source(s) labelled\n")
        return 0
    finally:
        await conn.close()


if __name__ == "__main__":
    sys.exit(asyncio.run(main()))
