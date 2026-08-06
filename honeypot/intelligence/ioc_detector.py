"""
IOC (Indicator of Compromise) detection
Checks IPs against local IOC list
"""

import logging
from pathlib import Path
from typing import Set, Optional
import config
from database.db import db

logger = logging.getLogger("honeypot.intelligence.ioc")

# Cached IOC list
_ioc_cache: Optional[Set[str]] = None
_ioc_cache_timestamp = 0


def load_ioc_list(force_reload: bool = False) -> Set[str]:
    """
    Load IOC list from file
    
    Args:
        force_reload: Force reload even if cached
    
    Returns:
        Set of malicious IP addresses
    """
    
    global _ioc_cache, _ioc_cache_timestamp
    
    import time
    current_time = time.time()
    
    # Use cache if fresh (less than 5 minutes old)
    if not force_reload and _ioc_cache is not None:
        if current_time - _ioc_cache_timestamp < 300:
            return _ioc_cache
    
    ioc_path = Path(config.IOC_FILE_PATH)
    
    if not ioc_path.exists():
        logger.warning(f"IOC file not found: {ioc_path}")
        _ioc_cache = set()
        _ioc_cache_timestamp = current_time
        return _ioc_cache
    
    try:
        with open(ioc_path, 'r', encoding='utf-8') as f:
            lines = f.readlines()
        
        ioc_set = set()
        
        for line in lines:
            line = line.strip()
            
            # Skip empty lines and comments
            if not line or line.startswith('#'):
                continue
            
            # Basic IP validation
            if _is_valid_ip(line):
                ioc_set.add(line)
            else:
                logger.warning(f"Invalid IP in IOC file: {line}")
        
        logger.info(f"Loaded {len(ioc_set)} IOCs from {ioc_path}")
        
        _ioc_cache = ioc_set
        _ioc_cache_timestamp = current_time
        
        return ioc_set
        
    except Exception as e:
        logger.error(f"Failed to load IOC file: {e}")
        _ioc_cache = set()
        _ioc_cache_timestamp = current_time
        return _ioc_cache


def check_ioc(ip_address: str) -> bool:
    """
    Check if IP is in IOC list
    
    Args:
        ip_address: IP to check
    
    Returns:
        True if IP is a known bad actor
    """
    
    if not config.IOC_CHECK_ENABLED:
        return False
    
    ioc_list = load_ioc_list()
    
    is_bad = ip_address in ioc_list
    
    if is_bad:
        logger.warning(f"IOC MATCH: {ip_address} is in known bad IP list")
        
        # Log to database
        _log_ioc_match(ip_address, 'local_file', 'exact_match')
        
        # Update attacker record
        _mark_as_known_bad(ip_address)
    
    return is_bad


def add_ioc(ip_address: str, source: str = "manual") -> bool:
    """
    Add IP to IOC list
    
    Args:
        ip_address: IP to add
        source: Source of IOC (manual, external_feed, etc.)
    
    Returns:
        True if successfully added
    """
    
    if not _is_valid_ip(ip_address):
        logger.error(f"Invalid IP address: {ip_address}")
        return False
    
    ioc_path = Path(config.IOC_FILE_PATH)
    
    try:
        # Ensure directory exists
        ioc_path.parent.mkdir(parents=True, exist_ok=True)
        
        # Check if already exists
        existing = load_ioc_list()
        if ip_address in existing:
            logger.info(f"IP already in IOC list: {ip_address}")
            return True
        
        # Append to file
        with open(ioc_path, 'a', encoding='utf-8') as f:
            f.write(f"{ip_address}\n")
        
        logger.info(f"Added {ip_address} to IOC list (source: {source})")
        
        # Force reload cache
        load_ioc_list(force_reload=True)
        
        # Mark in database
        _mark_as_known_bad(ip_address)
        
        # Log the IOC match
        _log_ioc_match(ip_address, source, 'added')
        
        return True
        
    except Exception as e:
        logger.error(f"Failed to add IOC: {e}")
        return False


def bulk_check_iocs(ip_addresses: list) -> dict:
    """
    Check multiple IPs against IOC list
    
    Args:
        ip_addresses: List of IPs to check
    
    Returns:
        Dictionary mapping IP -> is_bad (bool)
    """
    
    if not config.IOC_CHECK_ENABLED:
        return {ip: False for ip in ip_addresses}
    
    ioc_list = load_ioc_list()
    
    results = {}
    
    for ip in ip_addresses:
        is_bad = ip in ioc_list
        results[ip] = is_bad
        
        if is_bad:
            logger.warning(f"IOC MATCH: {ip}")
            _log_ioc_match(ip, 'local_file', 'exact_match')
            _mark_as_known_bad(ip)
    
    return results


def scan_existing_attackers():
    """
    Scan all existing attackers against IOC list
    Useful after adding new IOCs
    """
    
    query = "SELECT ip_address FROM attackers"
    results = db.execute_query(query)
    
    if not results:
        logger.info("No attackers to scan")
        return
    
    ips = [row['ip_address'] for row in results]
    
    logger.info(f"Scanning {len(ips)} existing attackers against IOC list")
    
    matches = bulk_check_iocs(ips)
    match_count = sum(1 for is_bad in matches.values() if is_bad)
    
    logger.info(f"Found {match_count} IOC matches in existing attackers")


def _is_valid_ip(ip_address: str) -> bool:
    """Basic IP validation"""
    
    parts = ip_address.split('.')
    
    if len(parts) != 4:
        return False
    
    try:
        return all(0 <= int(part) <= 255 for part in parts)
    except ValueError:
        return False


def _log_ioc_match(ip_address: str, source: str, match_type: str):
    """Log IOC match to database"""
    
    query = """
        INSERT INTO ioc_matches
        (ip_address, ioc_source, match_type, severity, matched_at)
        VALUES (?, ?, ?, 'HIGH', CURRENT_TIMESTAMP)
    """
    
    db.execute_update(query, (ip_address, source, match_type))


def _mark_as_known_bad(ip_address: str):
    """Mark attacker as known bad in database"""
    
    query = """
        UPDATE attackers
        SET is_known_bad = 1
        WHERE ip_address = ?
    """
    
    db.execute_update(query, (ip_address,))


def get_ioc_stats() -> dict:
    """Get IOC statistics"""
    
    ioc_list = load_ioc_list()
    
    # Get match count from database
    query = "SELECT COUNT(DISTINCT ip_address) as cnt FROM ioc_matches"
    result = db.execute_query(query)
    match_count = result[0]['cnt'] if result else 0
    
    return {
        'total_iocs': len(ioc_list),
        'total_matches': match_count
    }


def export_current_attackers_to_ioc(min_threat_score: int = 75):
    """
    Export high-threat attackers to IOC list
    
    Args:
        min_threat_score: Minimum threat score to include
    """
    
    query = """
        SELECT ip_address, threat_score, verdict
        FROM attackers
        WHERE threat_score >= ?
        AND is_known_bad = 0
        ORDER BY threat_score DESC
    """
    
    results = db.execute_query(query, (min_threat_score,))
    
    if not results:
        logger.info("No attackers meet the threat score threshold")
        return
    
    logger.info(f"Exporting {len(results)} high-threat attackers to IOC list")
    
    for row in results:
        ip = row['ip_address']
        score = row['threat_score']
        verdict = row['verdict']
        
        add_ioc(ip, source=f"auto_export_score_{score}_{verdict}")
    
    logger.info("IOC export complete")
