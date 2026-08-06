"""
IP Geolocation using ip-api.com (free, no API key required)
"""

import logging
import requests
import time
from typing import Dict, Optional
from database.db import db

logger = logging.getLogger("honeypot.intelligence.geolocation")

# API Configuration
GEOIP_API_URL = "http://ip-api.com/json/{ip}"
BATCH_API_URL = "http://ip-api.com/batch"
RATE_LIMIT_PER_MINUTE = 45  # Free tier limit
RATE_LIMIT_DELAY = 1.5  # Seconds between requests

# Last request timestamp for rate limiting
_last_request_time = 0


def _rate_limit():
    """Enforce rate limiting"""
    global _last_request_time
    
    current_time = time.time()
    time_since_last = current_time - _last_request_time
    
    if time_since_last < RATE_LIMIT_DELAY:
        sleep_time = RATE_LIMIT_DELAY - time_since_last
        logger.debug(f"Rate limiting: sleeping {sleep_time:.2f}s")
        time.sleep(sleep_time)
    
    _last_request_time = time.time()


def get_geolocation(ip_address: str, use_cache: bool = True) -> Optional[Dict]:
    """
    Get geolocation data for an IP address
    
    Args:
        ip_address: IP address to lookup
        use_cache: Check database cache first
    
    Returns:
        Dictionary with geolocation data or None if failed
    """
    
    # Skip private/local IPs
    if _is_private_ip(ip_address):
        logger.debug(f"Skipping geolocation for private IP: {ip_address}")
        return None
    
    # Check cache first
    if use_cache:
        cached = _get_cached_geolocation(ip_address)
        if cached:
            logger.debug(f"Using cached geolocation for {ip_address}")
            return cached
    
    # Rate limiting
    _rate_limit()
    
    # Make API request
    try:
        url = GEOIP_API_URL.format(ip=ip_address)
        logger.info(f"Fetching geolocation for {ip_address}")
        
        response = requests.get(url, timeout=10)
        response.raise_for_status()
        
        data = response.json()
        
        if data.get('status') == 'success':
            geo_data = {
                'country': data.get('country'),
                'country_code': data.get('countryCode'),
                'region': data.get('regionName'),
                'city': data.get('city'),
                'latitude': data.get('lat'),
                'longitude': data.get('lon'),
                'isp': data.get('isp'),
                'asn': data.get('as'),
                'timezone': data.get('timezone'),
                'zip_code': data.get('zip')
            }
            
            logger.info(
                f"Geolocation for {ip_address}: "
                f"{geo_data.get('city')}, {geo_data.get('country')}"
            )
            
            # Update database cache
            _update_attacker_geolocation(ip_address, geo_data)
            
            return geo_data
        else:
            logger.error(f"Geolocation failed for {ip_address}: {data.get('message')}")
            return None
            
    except requests.exceptions.RequestException as e:
        logger.error(f"Geolocation request failed for {ip_address}: {e}")
        return None
    except Exception as e:
        logger.error(f"Geolocation error for {ip_address}: {e}")
        return None


def get_geolocation_batch(ip_addresses: list) -> Dict[str, Dict]:
    """
    Get geolocation for multiple IPs in batch (more efficient)
    
    Args:
        ip_addresses: List of IP addresses (max 100)
    
    Returns:
        Dictionary mapping IP -> geolocation data
    """
    
    if not ip_addresses:
        return {}
    
    # Filter out private IPs
    public_ips = [ip for ip in ip_addresses if not _is_private_ip(ip)]
    
    if not public_ips:
        return {}
    
    # Limit to 100 IPs per batch
    public_ips = public_ips[:100]
    
    # Rate limiting for batch
    _rate_limit()
    
    try:
        logger.info(f"Batch geolocation lookup for {len(public_ips)} IPs")
        
        # Prepare batch request
        batch_data = [{"query": ip} for ip in public_ips]
        
        response = requests.post(
            BATCH_API_URL,
            json=batch_data,
            timeout=30
        )
        response.raise_for_status()
        
        results = response.json()
        
        geo_map = {}
        for result in results:
            if result.get('status') == 'success':
                ip = result.get('query')
                geo_data = {
                    'country': result.get('country'),
                    'country_code': result.get('countryCode'),
                    'region': result.get('regionName'),
                    'city': result.get('city'),
                    'latitude': result.get('lat'),
                    'longitude': result.get('lon'),
                    'isp': result.get('isp'),
                    'asn': result.get('as'),
                    'timezone': result.get('timezone'),
                    'zip_code': result.get('zip')
                }
                
                geo_map[ip] = geo_data
                _update_attacker_geolocation(ip, geo_data)
        
        logger.info(f"Batch geolocation completed: {len(geo_map)} successful")
        return geo_map
        
    except Exception as e:
        logger.error(f"Batch geolocation failed: {e}")
        return {}


def _is_private_ip(ip_address: str) -> bool:
    """Check if IP is private/local"""
    
    if ip_address in ['127.0.0.1', 'localhost', '::1']:
        return True
    
    parts = ip_address.split('.')
    if len(parts) != 4:
        return False
    
    try:
        first = int(parts[0])
        second = int(parts[1])
        
        # Private ranges
        if first == 10:
            return True
        if first == 172 and 16 <= second <= 31:
            return True
        if first == 192 and second == 168:
            return True
        
        return False
    except ValueError:
        return False


def _get_cached_geolocation(ip_address: str) -> Optional[Dict]:
    """Get cached geolocation from database"""
    
    query = """
        SELECT country, country_code, region, city, latitude, longitude, isp, asn
        FROM attackers
        WHERE ip_address = ? AND geo_enriched = 1
    """
    
    results = db.execute_query(query, (ip_address,))
    
    if results and results[0]['country']:
        row = results[0]
        return {
            'country': row['country'],
            'country_code': row['country_code'],
            'region': row['region'],
            'city': row['city'],
            'latitude': row['latitude'],
            'longitude': row['longitude'],
            'isp': row['isp'],
            'asn': row['asn']
        }
    
    return None


def _update_attacker_geolocation(ip_address: str, geo_data: Dict):
    """Update attacker record with geolocation data"""
    
    query = """
        UPDATE attackers
        SET country = ?,
            country_code = ?,
            region = ?,
            city = ?,
            latitude = ?,
            longitude = ?,
            isp = ?,
            asn = ?,
            geo_enriched = 1
        WHERE ip_address = ?
    """
    
    db.execute_update(
        query,
        (
            geo_data.get('country'),
            geo_data.get('country_code'),
            geo_data.get('region'),
            geo_data.get('city'),
            geo_data.get('latitude'),
            geo_data.get('longitude'),
            geo_data.get('isp'),
            geo_data.get('asn'),
            ip_address
        )
    )
    
    logger.debug(f"Updated geolocation for {ip_address} in database")


def enrich_unenriched_attackers(limit: int = 10):
    """
    Enrich attackers that don't have geolocation data yet
    
    Args:
        limit: Maximum number of IPs to enrich in this batch
    """
    
    # Get IPs without geolocation
    query = """
        SELECT ip_address
        FROM attackers
        WHERE geo_enriched = 0
        ORDER BY last_seen DESC
        LIMIT ?
    """
    
    results = db.execute_query(query, (limit,))
    
    if not results:
        logger.info("No unenriched attackers found")
        return
    
    ips = [row['ip_address'] for row in results]
    logger.info(f"Enriching {len(ips)} attackers with geolocation data")
    
    # Use batch API if multiple IPs
    if len(ips) > 1:
        get_geolocation_batch(ips)
    else:
        for ip in ips:
            get_geolocation(ip, use_cache=False)


def get_country_flag(country_code: str) -> str:
    """
    Get emoji flag for country code
    
    Args:
        country_code: Two-letter country code (ISO 3166-1 alpha-2)
    
    Returns:
        Emoji flag string
    """
    
    if not country_code or len(country_code) != 2:
        return "🏴"
    
    # Convert country code to regional indicator symbols
    code = country_code.upper()
    flag = chr(ord(code[0]) + 127397) + chr(ord(code[1]) + 127397)
    
    return flag
