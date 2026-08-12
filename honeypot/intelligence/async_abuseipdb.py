"""
AbuseIPDB reputation lookup — HoneyShield v2 (asyncio).
Requires ABUSEIPDB_API_KEY (free tier at https://www.abuseipdb.com/).

One retry with a short backoff on transient failures (timeouts, connection
errors, 429, 5xx); gives up and returns None otherwise. Never raises —
enrichment failures must not affect the honeypot's connection-handling
pipeline.
"""

import asyncio
import ipaddress
import logging
from typing import Optional

import requests

import config
from database.db_async import db

logger = logging.getLogger("honeypot.intelligence.abuseipdb")

ABUSEIPDB_URL = "https://api.abuseipdb.com/api/v2/check"
REQUEST_TIMEOUT_SECONDS = 10
RETRY_BACKOFF_SECONDS = 3
TRANSIENT_STATUS_CODES = {429, 500, 502, 503, 504}


def _is_private_ip(ip_address: str) -> bool:
    try:
        addr = ipaddress.ip_address(ip_address)
        return addr.is_private or addr.is_loopback
    except ValueError:
        return False


def _has_api_key() -> bool:
    return bool(config.ABUSEIPDB_API_KEY) and config.ABUSEIPDB_API_KEY != "your_key_here"


def _fetch(ip_address: str) -> int:
    """Blocking HTTP call — raises on transient failure, run via run_in_executor."""
    response = requests.get(
        ABUSEIPDB_URL,
        headers={"Key": config.ABUSEIPDB_API_KEY, "Accept": "application/json"},
        params={"ipAddress": ip_address, "maxAgeInDays": 90},
        timeout=REQUEST_TIMEOUT_SECONDS,
    )
    response.raise_for_status()
    data = response.json()
    return data.get("data", {}).get("abuseConfidenceScore", 0)


async def check_reputation(ip_address: str, force: bool = False) -> Optional[int]:
    """Get (and cache) the AbuseIPDB confidence score (0-100) for an IP, or None if unavailable."""
    if _is_private_ip(ip_address):
        return None

    if not _has_api_key():
        logger.debug("AbuseIPDB API key not configured — skipping reputation check")
        return None

    if not force:
        stale = await db.is_stale(ip_address, "abuseipdb_checked_at", config.ABUSEIPDB_CACHE_TTL_SECONDS)
        if not stale:
            logger.debug(f"AbuseIPDB cache hit for {ip_address}")
            attacker = await db.get_attacker(ip_address)
            if attacker and attacker.get("abuseipdb_score") is not None:
                return attacker["abuseipdb_score"]

    loop = asyncio.get_running_loop()
    score = None
    for attempt in (1, 2):
        try:
            score = await loop.run_in_executor(None, _fetch, ip_address)
            break
        except requests.exceptions.HTTPError as e:
            status = e.response.status_code if e.response is not None else None
            if status in TRANSIENT_STATUS_CODES and attempt == 1:
                logger.warning(f"AbuseIPDB transient error ({status}) for {ip_address}, retrying...")
                await asyncio.sleep(RETRY_BACKOFF_SECONDS)
                continue
            logger.warning(f"AbuseIPDB request failed for {ip_address}: HTTP {status}")
            return None
        except requests.exceptions.RequestException as e:
            if attempt == 1:
                logger.warning(f"AbuseIPDB connection error for {ip_address}, retrying: {e}")
                await asyncio.sleep(RETRY_BACKOFF_SECONDS)
                continue
            logger.warning(f"AbuseIPDB request failed for {ip_address} after retry: {e}")
            return None
        except Exception as e:
            logger.error(f"AbuseIPDB error for {ip_address}: {e}")
            return None

    if score is None:
        return None

    await db.update_abuseipdb(ip_address, score)
    logger.info(f"AbuseIPDB score for {ip_address}: {score}/100")
    return score
