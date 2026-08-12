"""
Brute-force and credential-stuffing detection — HoneyShield v2 (asyncio).

HONEYSHIELD_PROJECT.md section 10, phase 2 scope only: brute_force and
credential_stuffing. rapid_fire and multi_service are later phases (multi_service
is explicitly phase 5 — the correlation engine) and aren't implemented here.

Thresholds carried over from the v1 detector (honeypot/detectors/brute_force.py),
which already tuned them per service (Telnet bots are typically faster/noisier
than SSH/FTP, so its threshold is lower; HTTP gets a longer window since web
form-fill bots tend to be slower).
"""

import logging
from typing import Dict, List, Optional

from database.db_async import db

logger = logging.getLogger("honeypot.detector")

# service -> (attempt threshold, window in seconds)
BRUTE_FORCE_RULES = {
    "ssh": (10, 300),
    "ftp": (10, 300),
    "telnet": (5, 300),
    "http": (10, 600),
}

CREDENTIAL_STUFFING_THRESHOLD = 5
CREDENTIAL_STUFFING_WINDOW_SECONDS = 600


async def check_brute_force(ip_address: str, service: str) -> Optional[Dict]:
    """Too many login attempts against one service from one IP."""
    rule = BRUTE_FORCE_RULES.get(service)
    if not rule:
        return None
    threshold, window = rule

    count = await db.count_login_attempts_since(ip_address, service, window)
    if count < threshold:
        return None

    if await db.recent_alert_exists(ip_address, "brute_force", window):
        return None  # already alerted for this ongoing campaign

    evidence = {"service": service, "attempt_count": count, "window_seconds": window}
    alert_id = await db.record_alert(ip_address, "brute_force", "HIGH", evidence)
    logger.warning(
        f"BRUTE FORCE DETECTED: {ip_address} — {count} attempts on {service} in {window}s (alert {alert_id})"
    )
    return {"id": alert_id, "alert_type": "brute_force", "severity": "HIGH", "evidence": evidence}


async def check_credential_stuffing(ip_address: str) -> Optional[Dict]:
    """Many different usernames tried by one IP, across any service."""
    count = await db.count_distinct_usernames_since(ip_address, CREDENTIAL_STUFFING_WINDOW_SECONDS)
    if count < CREDENTIAL_STUFFING_THRESHOLD:
        return None

    if await db.recent_alert_exists(ip_address, "credential_stuffing", CREDENTIAL_STUFFING_WINDOW_SECONDS):
        return None

    evidence = {"unique_usernames": count, "window_seconds": CREDENTIAL_STUFFING_WINDOW_SECONDS}
    alert_id = await db.record_alert(ip_address, "credential_stuffing", "HIGH", evidence)
    logger.warning(f"CREDENTIAL STUFFING DETECTED: {ip_address} — {count} unique usernames (alert {alert_id})")
    return {"id": alert_id, "alert_type": "credential_stuffing", "severity": "HIGH", "evidence": evidence}


async def check_and_alert(ip_address: str, service: str) -> List[Dict]:
    """Run both checks after a login attempt. Returns any newly created alerts."""
    alerts = []
    brute_force = await check_brute_force(ip_address, service)
    if brute_force:
        alerts.append(brute_force)
    credential_stuffing = await check_credential_stuffing(ip_address)
    if credential_stuffing:
        alerts.append(credential_stuffing)
    return alerts
