"""
IP geolocation via ip-api.com (free, no API key) — HoneyShield v2 (asyncio).

Uses the sync `requests` library through run_in_executor rather than adding
an async HTTP dependency, matching the pattern already used for SQLite in
database/db_async.py. Never raises — enrichment failures must not affect
the honeypot's connection-handling pipeline.
"""

import asyncio
import ipaddress
import logging
from typing import Optional, Dict

import requests

import config
from database.db_async import db

logger = logging.getLogger("honeypot.intelligence.geolocation")

GEOIP_URL_TEMPLATE = "http://ip-api.com/json/{ip}?fields=status,message,country,city,isp,as"
REQUEST_TIMEOUT_SECONDS = 10


def _is_private_ip(ip_address: str) -> bool:
    try:
        addr = ipaddress.ip_address(ip_address)
        return addr.is_private or addr.is_loopback
    except ValueError:
        return False


def _fetch(ip_address: str) -> Optional[Dict]:
    """Blocking HTTP call — always run via run_in_executor, never awaited directly."""
    response = requests.get(GEOIP_URL_TEMPLATE.format(ip=ip_address), timeout=REQUEST_TIMEOUT_SECONDS)
    response.raise_for_status()
    data = response.json()

    if data.get("status") != "success":
        logger.info(f"Geolocation lookup failed for {ip_address}: {data.get('message')}")
        return None

    return {
        "country": data.get("country"),
        "city": data.get("city"),
        "isp": data.get("isp"),
        "asn": data.get("as"),
    }


async def get_geolocation(ip_address: str, force: bool = False) -> Optional[Dict]:
    """
    Get (and cache) geolocation for an IP. Returns None on private IPs,
    missing/failed lookups, or when the cached value is still fresh and
    force=False (cache hit — no network call made).
    """
    if _is_private_ip(ip_address):
        logger.debug(f"Skipping geolocation for private/loopback IP: {ip_address}")
        return None

    if not force:
        stale = await db.is_stale(ip_address, "geo_checked_at", config.GEO_CACHE_TTL_SECONDS)
        if not stale:
            logger.debug(f"Geolocation cache hit for {ip_address}")
            attacker = await db.get_attacker(ip_address)
            if attacker:
                return {
                    "country": attacker.get("country"),
                    "city": attacker.get("city"),
                    "isp": attacker.get("isp"),
                    "asn": attacker.get("asn"),
                }

    loop = asyncio.get_running_loop()
    try:
        geo_data = await loop.run_in_executor(None, _fetch, ip_address)
    except requests.exceptions.RequestException as e:
        logger.warning(f"Geolocation request failed for {ip_address}: {e}")
        return None
    except Exception as e:
        logger.error(f"Geolocation error for {ip_address}: {e}")
        return None

    if not geo_data:
        return None

    await db.update_geolocation(
        ip_address, geo_data.get("country"), geo_data.get("city"), geo_data.get("isp"), geo_data.get("asn")
    )
    logger.info(f"Geolocation for {ip_address}: {geo_data.get('city')}, {geo_data.get('country')}")
    return geo_data
