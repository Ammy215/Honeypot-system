"""
Brute-force, credential-stuffing, and multi-service detection — HoneyShield v2 (asyncio).

HONEYSHIELD_PROJECT.md section 10: brute_force/credential_stuffing landed in
phase 2; multi_service is phase 5 (the correlation engine), added here.
rapid_fire and IOC-list matching are still out of scope — not named in any
phase 5 instruction and not part of the alert_type set actually exercised.

Thresholds carried over from the v1 detector (honeypot/detectors/brute_force.py),
which already tuned them per service (Telnet bots are typically faster/noisier
than SSH/FTP, so its threshold is lower; HTTP gets a longer window since web
form-fill bots tend to be slower).
"""

import config
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
    """Run both login-attempt-driven checks. Returns any newly created alerts."""
    alerts = []
    brute_force = await check_brute_force(ip_address, service)
    if brute_force:
        alerts.append(brute_force)
    credential_stuffing = await check_credential_stuffing(ip_address)
    if credential_stuffing:
        alerts.append(credential_stuffing)
    return alerts


async def check_multi_service(ip_address: str) -> Optional[Dict]:
    """
    Same IP hitting 2+ different honeypot services within a short window —
    classic recon/scanning behavior. Driven by connections, not login
    attempts, so it fires even for services like SSH that never submit
    credentials — see check_connection_patterns().
    """
    window = config.MULTI_SERVICE_WINDOW_SECONDS
    threshold = config.MULTI_SERVICE_THRESHOLD

    count = await db.count_distinct_services_since(ip_address, window)
    if count < threshold:
        return None

    if await db.recent_alert_exists(ip_address, "multi_service", window):
        return None

    sequence = await db.get_service_sequence_since(ip_address, window)
    evidence = {
        "service_count": count,
        "window_seconds": window,
        "sequence": [{"service": row["service"], "connected_at": str(row["connected_at"])} for row in sequence],
    }
    alert_id = await db.record_alert(ip_address, "multi_service", "HIGH", evidence)
    logger.warning(
        f"MULTI-SERVICE ATTACK DETECTED: {ip_address} — {count} services in {window}s (alert {alert_id})"
    )
    return {"id": alert_id, "alert_type": "multi_service", "severity": "HIGH", "evidence": evidence}


async def check_connection_patterns(ip_address: str) -> List[Dict]:
    """Run connection-driven checks (currently just multi-service). Called
    after every accepted connection, from all four honeypot services —
    including SSH, which never reaches check_and_alert() since it has no
    login attempts to trigger on."""
    alerts = []
    multi_service = await check_multi_service(ip_address)
    if multi_service:
        alerts.append(multi_service)
    return alerts
