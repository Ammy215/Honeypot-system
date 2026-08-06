"""
Automatic threat intelligence enrichment pipeline
"""

import logging
import time
from typing import Dict
from database.db import db
from honeypot.intelligence.geolocation import get_geolocation
from honeypot.intelligence.abuseipdb import check_ip_reputation
from honeypot.intelligence.ioc_detector import check_ioc
from honeypot.intelligence.threat_scorer import update_attacker_threat_score

logger = logging.getLogger("honeypot.intelligence.enrichment")


def enrich_attacker(ip_address: str, async_mode: bool = False) -> Dict:
    """
    Fully enrich an attacker with all available intelligence
    
    Args:
        ip_address: IP address to enrich
        async_mode: If True, run in background without blocking
    
    Returns:
        Dictionary with enrichment results
    """
    
    logger.info(f"Starting enrichment for {ip_address}")
    
    start_time = time.time()
    results = {
        'ip_address': ip_address,
        'geo': None,
        'reputation': None,
        'ioc_match': False,
        'threat_score': 0,
        'verdict': 'UNKNOWN',
        'enrichment_time': 0
    }
    
    try:
        # 1. Check IOC list (fast, local)
        logger.debug(f"Checking IOC for {ip_address}")
        results['ioc_match'] = check_ioc(ip_address)
        
        # 2. Get geolocation (moderate speed, free API)
        logger.debug(f"Getting geolocation for {ip_address}")
        geo_data = get_geolocation(ip_address, use_cache=True)
        results['geo'] = geo_data
        
        if geo_data:
            logger.info(
                f"Geolocation: {ip_address} -> "
                f"{geo_data.get('city')}, {geo_data.get('country')}"
            )
        
        # 3. Check reputation (slower, requires API key)
        logger.debug(f"Checking reputation for {ip_address}")
        reputation_data = check_ip_reputation(ip_address, use_cache=True)
        results['reputation'] = reputation_data
        
        if reputation_data:
            score = reputation_data.get('abuse_confidence_score', 0)
            logger.info(f"Reputation: {ip_address} -> AbuseIPDB score: {score}/100")
        
        # 4. Calculate threat score (local, based on all data)
        logger.debug(f"Calculating threat score for {ip_address}")
        update_attacker_threat_score(ip_address)
        
        # Get updated threat score
        query = "SELECT threat_score, verdict FROM attackers WHERE ip_address = ?"
        attacker_results = db.execute_query(query, (ip_address,))
        
        if attacker_results:
            results['threat_score'] = attacker_results[0]['threat_score']
            results['verdict'] = attacker_results[0]['verdict']
        
        # Calculate enrichment time
        results['enrichment_time'] = time.time() - start_time
        
        logger.info(
            f"Enrichment complete for {ip_address}: "
            f"Score={results['threat_score']}/100 ({results['verdict']}) "
            f"in {results['enrichment_time']:.2f}s"
        )
        
        return results
        
    except Exception as e:
        logger.error(f"Enrichment failed for {ip_address}: {e}")
        results['error'] = str(e)
        return results


def enrich_recent_attackers(limit: int = 10, skip_enriched: bool = True):
    """
    Enrich recently seen attackers
    
    Args:
        limit: Maximum number to enrich
        skip_enriched: Skip attackers already enriched
    """
    
    if skip_enriched:
        query = """
            SELECT ip_address
            FROM attackers
            WHERE geo_enriched = 0 OR intel_enriched = 0
            ORDER BY last_seen DESC
            LIMIT ?
        """
    else:
        query = """
            SELECT ip_address
            FROM attackers
            ORDER BY last_seen DESC
            LIMIT ?
        """
    
    results = db.execute_query(query, (limit,))
    
    if not results:
        logger.info("No attackers to enrich")
        return
    
    ips = [row['ip_address'] for row in results]
    
    logger.info(f"Enriching {len(ips)} recent attackers")
    
    for ip in ips:
        enrich_attacker(ip)
        # Small delay to respect rate limits
        time.sleep(1)


def auto_enrich_new_attacker(ip_address: str):
    """
    Automatically enrich a new attacker (called on first connection)
    
    Args:
        ip_address: IP address that just connected
    """
    
    # Quick checks only (IOC and geolocation)
    logger.info(f"Auto-enriching new attacker: {ip_address}")
    
    try:
        # IOC check (instant)
        check_ioc(ip_address)
        
        # Geolocation (fast)
        get_geolocation(ip_address, use_cache=False)
        
        # Reputation check (slower - skip for now, will be done in background)
        # check_ip_reputation(ip_address, use_cache=False)
        
        logger.debug(f"Auto-enrichment complete for {ip_address}")
        
    except Exception as e:
        logger.error(f"Auto-enrichment failed for {ip_address}: {e}")


def get_enrichment_status() -> Dict:
    """Get enrichment statistics"""
    
    query = """
        SELECT 
            COUNT(*) as total,
            SUM(CASE WHEN geo_enriched = 1 THEN 1 ELSE 0 END) as geo_enriched,
            SUM(CASE WHEN intel_enriched = 1 THEN 1 ELSE 0 END) as intel_enriched,
            SUM(CASE WHEN is_known_bad = 1 THEN 1 ELSE 0 END) as known_bad,
            SUM(CASE WHEN threat_score > 0 THEN 1 ELSE 0 END) as scored
        FROM attackers
    """
    
    results = db.execute_query(query)
    
    if results:
        row = results[0]
        total = row['total']
        
        return {
            'total_attackers': total,
            'geo_enriched': row['geo_enriched'],
            'geo_enriched_pct': (row['geo_enriched'] / total * 100) if total > 0 else 0,
            'intel_enriched': row['intel_enriched'],
            'intel_enriched_pct': (row['intel_enriched'] / total * 100) if total > 0 else 0,
            'known_bad': row['known_bad'],
            'scored': row['scored'],
            'pending_geo': total - row['geo_enriched'],
            'pending_intel': total - row['intel_enriched']
        }
    
    return {
        'total_attackers': 0,
        'geo_enriched': 0,
        'intel_enriched': 0,
        'known_bad': 0,
        'scored': 0
    }


def display_enrichment_status():
    """Display enrichment status with Rich formatting"""
    
    from rich.console import Console
    from rich.table import Table
    
    console = Console()
    status = get_enrichment_status()
    
    table = Table(title="Threat Intelligence Enrichment Status")
    
    table.add_column("Metric", style="cyan")
    table.add_column("Value", justify="right", style="green")
    table.add_column("Percentage", justify="right", style="yellow")
    
    table.add_row(
        "Total Attackers",
        str(status['total_attackers']),
        "100%"
    )
    
    table.add_row(
        "Geo Enriched",
        str(status['geo_enriched']),
        f"{status['geo_enriched_pct']:.1f}%"
    )
    
    table.add_row(
        "Intel Enriched",
        str(status['intel_enriched']),
        f"{status['intel_enriched_pct']:.1f}%"
    )
    
    table.add_row(
        "Known Bad IPs",
        str(status['known_bad']),
        f"{(status['known_bad'] / status['total_attackers'] * 100):.1f}%" if status['total_attackers'] > 0 else "0%"
    )
    
    table.add_row(
        "Threat Scored",
        str(status['scored']),
        f"{(status['scored'] / status['total_attackers'] * 100):.1f}%" if status['total_attackers'] > 0 else "0%"
    )
    
    console.print()
    console.print(table)
    console.print()
    
    if status['pending_geo'] > 0 or status['pending_intel'] > 0:
        console.print(
            f"[yellow]Pending:[/yellow] "
            f"{status['pending_geo']} need geo, "
            f"{status['pending_intel']} need intel"
        )
        console.print()
