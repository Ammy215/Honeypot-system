"""
Enrichment orchestrator — HoneyShield v2 (asyncio).

Runs geolocation, AbuseIPDB, and OTX concurrently (independent external
services, independent rate limiters/caches), then recalculates the threat
score from the results. enrich_and_score() is meant to be scheduled as a
background task from the honeypot's connection handlers
(see AsyncHoneypotService.spawn_background in async_base_service.py) so a
slow, rate-limited, or down enrichment API can never block or crash the
capture pipeline.
"""

import asyncio
import logging
from typing import Dict, List

from database.db_async import db
from honeypot.intelligence.async_geolocation import get_geolocation
from honeypot.intelligence.async_abuseipdb import check_reputation
from honeypot.intelligence.async_otx import check_pulses
from honeypot.intelligence.async_threat_scorer import update_threat_score

logger = logging.getLogger("honeypot.intelligence.enrichment")


async def enrich_attacker(ip_address: str, force: bool = False) -> Dict:
    """Run all three enrichment sources concurrently, then rescore. Never raises."""
    geo, abuse_score, otx_pulses = await asyncio.gather(
        get_geolocation(ip_address, force=force),
        check_reputation(ip_address, force=force),
        check_pulses(ip_address, force=force),
        return_exceptions=True,
    )

    for label, result in (("geolocation", geo), ("abuseipdb", abuse_score), ("otx", otx_pulses)):
        if isinstance(result, Exception):
            logger.error(f"{label} enrichment raised for {ip_address}: {result}")

    score_result = await update_threat_score(ip_address)
    return {
        "ip_address": ip_address,
        "geo": geo if not isinstance(geo, Exception) else None,
        "abuseipdb_score": abuse_score if not isinstance(abuse_score, Exception) else None,
        "otx_pulse_count": otx_pulses if not isinstance(otx_pulses, Exception) else None,
        **score_result,
    }


async def enrich_and_score(ip_address: str):
    """
    Fire-and-forget entry point for honeypot connection handlers. Swallows
    everything — a broken/rate-limited threat-intel API must never surface
    as an error in the capture pipeline.
    """
    try:
        await enrich_attacker(ip_address)
    except Exception as e:
        logger.error(f"Background enrichment failed for {ip_address}: {e}")


async def enrich_captured_attackers(limit: int = 50, force: bool = False) -> List[Dict]:
    """Batch-enrich attackers already sitting in the attackers table (e.g. from a script)."""
    ips = await db.list_attacker_ips(limit=limit)
    logger.info(f"Enriching {len(ips)} captured attacker(s)")
    return [await enrich_attacker(ip, force=force) for ip in ips]
