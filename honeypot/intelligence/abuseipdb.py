"""
AbuseIPDB reputation checking
Requires API key from https://www.abuseipdb.com/
"""

import logging
import requests
import time
from typing import Dict, Optional
import config
from database.db import db

logger = logging.getLogger("honeypot.intelligence.abuseipdb")

# API Configuration
ABUSEIPDB_API_URL = "https://api.abuseipdb.com/api/v2/check"
RATE_LIMIT_DELAY = 1.0  # Seconds between requests

# Last request timestamp
_last_request_time = 0


def _rate_limit():
    """Enforce rate limiting"""
    global _last_request_time
    
    current_time = time.time()
    time_since_last = current_time - _last_request_time
    
    if time_since_last < RATE_LIMIT_DELAY:
        sleep_time = RATE_LIMIT_DELAY - time_since_last
        time.sleep(sleep_time)
    
    _last_request_time = time.time()


def check_ip_reputation(ip_address: str, max_age_days: int = 90, use_cache: bool = True) -> Optional[Dict]:
    """
    Check IP reputation with AbuseIPDB
    
    Args:
        ip_address: IP address to check
        max_age_days: Consider reports within this many days
        use_cache: Check database cache first
    
    Returns:
        Dictionary with reputation data or None if failed
    """
    
    # Check if API key is configured
    if not config.ABUSEIPDB_API_KEY or config.ABUSEIPDB_API_KEY == "your_key_here":
        logger.warning("AbuseIPDB API key not configured - skipping reputation check")
        return None
    
    # Skip private IPs
    if _is_private_ip(ip_address):
        return None
    
    # Check cache first
    if use_cache:
        cached = _get_cached_reputation(ip_address)
        if cached is not None:
            logger.debug(f"Using cached AbuseIPDB score for {ip_address}")
            return cached
    
    # Rate limiting
    _rate_limit()
    
    try:
        logger.info(f"Checking AbuseIPDB reputation for {ip_address}")
        
        headers = {
            'Key': config.ABUSEIPDB_API_KEY,
            'Accept': 'application/json'
        }
        
        params = {
            'ipAddress': ip_address,
            'maxAgeInDays': max_age_days,
            'verbose': True
        }
        
        response = requests.get(
            ABUSEIPDB_API_URL,
            headers=headers,
            params=params,
            timeout=10
        )
        
        response.raise_for_status()
        data = response.json()
        
        if 'data' in data:
            result = data['data']
            
            reputation_data = {
                'abuse_confidence_score': result.get('abuseConfidenceScore', 0),
                'total_reports': result.get('totalReports', 0),
                'num_distinct_users': result.get('numDistinctUsers', 0),
                'last_reported_at': result.get('lastReportedAt'),
                'is_whitelisted': result.get('isWhitelisted', False),
                'usage_type': result.get('usageType'),
                'isp': result.get('isp'),
                'domain': result.get('domain'),
                'country_code': result.get('countryCode'),
                'is_tor': result.get('isTor', False)
            }
            
            logger.info(
                f"AbuseIPDB for {ip_address}: "
                f"Score={reputation_data['abuse_confidence_score']}, "
                f"Reports={reputation_data['total_reports']}"
            )
            
            # Update database
            _update_attacker_reputation(ip_address, reputation_data)
            
            return reputation_data
        else:
            logger.error(f"Invalid AbuseIPDB response for {ip_address}")
            return None
            
    except requests.exceptions.HTTPError as e:
        if e.response.status_code == 429:
            logger.warning("AbuseIPDB rate limit exceeded")
        else:
            logger.error(f"AbuseIPDB HTTP error for {ip_address}: {e}")
        return None
    except requests.exceptions.RequestException as e:
        logger.error(f"AbuseIPDB request failed for {ip_address}: {e}")
        return None
    except Exception as e:
        logger.error(f"AbuseIPDB error for {ip_address}: {e}")
        return None


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
        
        if first == 10:
            return True
        if first == 172 and 16 <= second <= 31:
            return True
        if first == 192 and second == 168:
            return True
        
        return False
    except ValueError:
        return False


def _get_cached_reputation(ip_address: str) -> Optional[Dict]:
    """Get cached reputation from database"""
    
    query = """
        SELECT abuseipdb_score, is_tor_exit, intel_enriched
        FROM attackers
        WHERE ip_address = ? AND intel_enriched = 1
    """
    
    results = db.execute_query(query, (ip_address,))
    
    if results and results[0]['intel_enriched']:
        return {
            'abuse_confidence_score': results[0]['abuseipdb_score'],
            'is_tor': results[0]['is_tor_exit']
        }
    
    return None


def _update_attacker_reputation(ip_address: str, reputation_data: Dict):
    """Update attacker record with reputation data"""
    
    query = """
        UPDATE attackers
        SET abuseipdb_score = ?,
            is_tor_exit = ?,
            intel_enriched = 1
        WHERE ip_address = ?
    """
    
    db.execute_update(
        query,
        (
            reputation_data.get('abuse_confidence_score', 0),
            1 if reputation_data.get('is_tor') else 0,
            ip_address
        )
    )
    
    logger.debug(f"Updated AbuseIPDB reputation for {ip_address} in database")


def get_reputation_verdict(score: int) -> tuple:
    """
    Get human-readable verdict based on abuse score
    
    Args:
        score: AbuseIPDB confidence score (0-100)
    
    Returns:
        Tuple of (verdict, color)
    """
    
    if score >= 90:
        return ("MALICIOUS", "red")
    elif score >= 75:
        return ("HIGHLY SUSPICIOUS", "orange1")
    elif score >= 50:
        return ("SUSPICIOUS", "yellow")
    elif score >= 25:
        return ("QUESTIONABLE", "cyan")
    else:
        return ("CLEAN", "green")


def enrich_unenriched_attackers(limit: int = 10):
    """
    Enrich attackers that don't have reputation data yet
    
    Args:
        limit: Maximum number of IPs to check
    """
    
    if not config.ABUSEIPDB_API_KEY or config.ABUSEIPDB_API_KEY == "your_key_here":
        logger.debug("AbuseIPDB API key not configured - skipping enrichment")
        return
    
    # Get IPs without reputation data
    query = """
        SELECT ip_address
        FROM attackers
        WHERE intel_enriched = 0
        ORDER BY last_seen DESC
        LIMIT ?
    """
    
    results = db.execute_query(query, (limit,))
    
    if not results:
        logger.info("No unenriched attackers found for reputation check")
        return
    
    ips = [row['ip_address'] for row in results]
    logger.info(f"Checking AbuseIPDB reputation for {len(ips)} attackers")
    
    for ip in ips:
        check_ip_reputation(ip, use_cache=False)
        # Rate limiting handled in check_ip_reputation
