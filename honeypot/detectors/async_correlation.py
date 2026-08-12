"""
Campaign correlation — HoneyShield v2 (asyncio), phase 5.

Groups attackers by ASN within a rolling time window, per
HONEYSHIELD_PROJECT.md section 10 ("campaign detection by ASN/time
window"). Computed on demand (used by the Campaigns dashboard page and
directly testable) rather than persisted — the v2 schema (spec section 4)
has no dedicated campaigns table, and the alerts table's alert_type set
(brute_force / credential_stuffing / rapid_fire / multi_service) doesn't
include a campaign type, so this stays a query-time view rather than
writing alert rows.

Threshold/window carried over from v1's honeypot/detectors/campaign_detector.py
(_detect_asn_campaigns: >= 3 distinct IPs, 24h window).
"""

import logging
from typing import Dict, List

import config
from database.db_async import db

logger = logging.getLogger("honeypot.detector.campaign")


async def detect_asn_campaigns(
    window_seconds: int = None, min_attackers: int = None
) -> List[Dict]:
    """Return ASN groupings with >= min_attackers distinct IPs active within window_seconds."""
    window_seconds = window_seconds or config.CAMPAIGN_WINDOW_SECONDS
    min_attackers = min_attackers or config.CAMPAIGN_MIN_ATTACKERS

    rows = await db.detect_asn_campaigns(window_seconds, min_attackers)

    campaigns = []
    for row in rows:
        ip_list = (row["ip_list"] or "").split(",")
        campaign = {
            "asn": row["asn"],
            "attacker_count": row["attacker_count"],
            "ip_addresses": ip_list,
            "campaign_start": row["campaign_start"],
            "campaign_end": row["campaign_end"],
            "total_connections": row["total_connections"] or 0,
            "severity": "HIGH" if row["attacker_count"] >= 5 else "MEDIUM",
        }
        campaigns.append(campaign)
        logger.info(
            f"ASN campaign: {row['asn']} — {row['attacker_count']} attackers "
            f"({row['campaign_start']} to {row['campaign_end']})"
        )

    return campaigns


async def get_campaign_members(ip_addresses: List[str]) -> List[Dict]:
    """Full attacker profiles for a campaign's member IPs (for the dashboard detail view)."""
    return await db.get_attackers_by_ips(ip_addresses)
