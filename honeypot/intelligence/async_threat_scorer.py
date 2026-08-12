"""
Weighted threat scoring engine — HoneyShield v2 (asyncio).

Scoped to signals available through phase 5: connection/login volume
(phases 1-2), credential-stuffing breadth (phase 2), the three enrichment
sources from phase 3 (AbuseIPDB score, OTX pulse count, datacenter/hosting
ISP from geolocation), and multi-service targeting from phase 5's
correlation engine. rapid_fire, IOC list matching, and Tor exit detection
are still out of scope — not backed by any detector yet.

Weights and verdict bands are carried over from the v1 scorer
(honeypot/intelligence/threat_scorer.py), which already tuned them.
"""

import logging
from typing import Dict

from database.db_async import db

logger = logging.getLogger("honeypot.intelligence.threat_scorer")

THREAT_WEIGHTS = {
    "connections_1_to_5": 5,
    "connections_6_to_20": 10,
    "connections_over_20": 20,
    "login_attempts_1_to_10": 5,
    "login_attempts_11_to_50": 15,
    "login_attempts_over_50": 30,
    "multiple_usernames_over_5": 10,
    "abuseipdb_score_over_90": 25,
    "abuseipdb_score_over_75": 20,
    "abuseipdb_score_over_50": 15,
    "abuseipdb_score_over_25": 10,
    "otx_pulse_match": 15,
    "datacenter_hosting_ip": 5,
    "multi_service_targeting": 15,
}

VERDICT_THRESHOLDS = [
    (0, 15, "LOW"),
    (15, 35, "MEDIUM"),
    (35, 60, "HIGH"),
    (60, 101, "CRITICAL"),
]

DATACENTER_KEYWORDS = [
    "hosting", "datacenter", "data center", "cloud", "server",
    "digital ocean", "aws", "amazon", "linode", "vultr", "ovh", "hetzner",
]


def _is_datacenter_isp(isp: str) -> bool:
    if not isp:
        return False
    isp_lower = isp.lower()
    return any(keyword in isp_lower for keyword in DATACENTER_KEYWORDS)


def _get_verdict(score: int) -> str:
    for lo, hi, verdict in VERDICT_THRESHOLDS:
        if lo <= score < hi:
            return verdict
    return "CRITICAL"


async def calculate_threat_score(ip_address: str) -> Dict:
    """Calculate (without persisting) the weighted threat score for an IP."""
    attacker = await db.get_attacker(ip_address)
    if not attacker:
        logger.warning(f"No attacker record for {ip_address}")
        return {"score": 0, "verdict": "UNKNOWN", "breakdown": {}}

    score = 0
    breakdown = {}

    def add(key: str, weight_key: str):
        nonlocal score
        weight = THREAT_WEIGHTS[weight_key]
        score += weight
        breakdown[key] = weight

    connections = attacker.get("total_connections") or 0
    if connections > 20:
        add("connections", "connections_over_20")
    elif connections >= 6:
        add("connections", "connections_6_to_20")
    elif connections >= 1:
        add("connections", "connections_1_to_5")

    login_attempts = await db.count_login_attempts_total(ip_address)
    if login_attempts > 50:
        add("login_attempts", "login_attempts_over_50")
    elif login_attempts >= 11:
        add("login_attempts", "login_attempts_11_to_50")
    elif login_attempts >= 1:
        add("login_attempts", "login_attempts_1_to_10")

    unique_usernames = await db.count_distinct_usernames_total(ip_address)
    if unique_usernames > 5:
        add("credential_stuffing", "multiple_usernames_over_5")

    abuse_score = attacker.get("abuseipdb_score")
    if abuse_score is not None:
        if abuse_score >= 90:
            add("abuseipdb", "abuseipdb_score_over_90")
        elif abuse_score >= 75:
            add("abuseipdb", "abuseipdb_score_over_75")
        elif abuse_score >= 50:
            add("abuseipdb", "abuseipdb_score_over_50")
        elif abuse_score >= 25:
            add("abuseipdb", "abuseipdb_score_over_25")

    if (attacker.get("otx_pulse_count") or 0) > 0:
        add("otx_pulses", "otx_pulse_match")

    if _is_datacenter_isp(attacker.get("isp")):
        add("datacenter", "datacenter_hosting_ip")

    services_targeted = await db.count_distinct_services_total(ip_address)
    if services_targeted >= 2:
        add("multi_service", "multi_service_targeting")

    score = min(score, 100)
    verdict = _get_verdict(score)

    logger.info(f"Threat score for {ip_address}: {score}/100 ({verdict})")
    return {"score": score, "verdict": verdict, "breakdown": breakdown}


async def update_threat_score(ip_address: str) -> Dict:
    """Calculate and persist the threat score/verdict for an IP."""
    result = await calculate_threat_score(ip_address)
    await db.update_threat_score(ip_address, result["score"], result["verdict"])
    return result
