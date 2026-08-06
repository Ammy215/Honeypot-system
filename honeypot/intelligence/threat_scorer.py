"""
Threat scoring engine - calculates weighted threat score (0-100) for attackers
"""

import logging
from typing import Dict, Optional
from datetime import datetime, timedelta
from database.db import db

logger = logging.getLogger("honeypot.intelligence.threat_scorer")


# Threat scoring weights
THREAT_WEIGHTS = {
    # Volume-based scoring
    "connections_1_to_5": 5,
    "connections_6_to_20": 10,
    "connections_over_20": 20,
    "login_attempts_1_to_10": 5,
    "login_attempts_11_to_50": 15,
    "login_attempts_over_50": 30,  # Confirmed brute force
    
    # Credential attack patterns
    "multiple_usernames_over_5": 10,   # Credential stuffing
    "multiple_passwords_over_10": 10,  # Password spraying
    "targeted_root_login": 10,         # Targeting privileged account
    "targeted_admin_login": 8,
    "common_default_creds": 12,        # admin/admin, root/root etc
    
    # Behavioral signals
    "rapid_fire_under_1_second": 15,   # Automated attack tool
    "multi_service_targeting": 15,      # Same IP hitting SSH + FTP + HTTP
    "port_scan_behavior": 10,           # Connecting to many ports
    
    # Intelligence signals
    "known_bad_ip": 30,                 # In local IOC list
    "abuseipdb_score_over_90": 25,
    "abuseipdb_score_over_75": 20,
    "abuseipdb_score_over_50": 15,
    "abuseipdb_score_over_25": 10,
    "otx_pulse_match": 15,              # Found in AlienVault OTX
    "tor_exit_node": 15,
    "datacenter_hosting_ip": 5,
}


# Verdict thresholds
VERDICT_THRESHOLDS = [
    (0, 15, "LOW"),
    (15, 35, "MEDIUM"),
    (35, 60, "HIGH"),
    (60, 101, "CRITICAL"),
]


def calculate_threat_score(ip_address: str) -> Dict:
    """
    Calculate comprehensive threat score for an IP
    
    Args:
        ip_address: IP address to score
    
    Returns:
        Dictionary with score, verdict, and breakdown
    """
    
    # Get attacker data
    attacker = _get_attacker_data(ip_address)
    
    if not attacker:
        logger.warning(f"No attacker data found for {ip_address}")
        return {
            'score': 0,
            'verdict': 'UNKNOWN',
            'breakdown': {}
        }
    
    score = 0
    breakdown = {}
    
    # === Volume-based scoring ===
    
    connections = attacker.get('total_connections', 0)
    if 1 <= connections <= 5:
        score += THREAT_WEIGHTS['connections_1_to_5']
        breakdown['connections'] = THREAT_WEIGHTS['connections_1_to_5']
    elif 6 <= connections <= 20:
        score += THREAT_WEIGHTS['connections_6_to_20']
        breakdown['connections'] = THREAT_WEIGHTS['connections_6_to_20']
    elif connections > 20:
        score += THREAT_WEIGHTS['connections_over_20']
        breakdown['connections'] = THREAT_WEIGHTS['connections_over_20']
    
    login_attempts = attacker.get('total_login_attempts', 0)
    if 1 <= login_attempts <= 10:
        score += THREAT_WEIGHTS['login_attempts_1_to_10']
        breakdown['login_attempts'] = THREAT_WEIGHTS['login_attempts_1_to_10']
    elif 11 <= login_attempts <= 50:
        score += THREAT_WEIGHTS['login_attempts_11_to_50']
        breakdown['login_attempts'] = THREAT_WEIGHTS['login_attempts_11_to_50']
    elif login_attempts > 50:
        score += THREAT_WEIGHTS['login_attempts_over_50']
        breakdown['login_attempts'] = THREAT_WEIGHTS['login_attempts_over_50']
    
    # === Credential attack patterns ===
    
    unique_usernames = attacker.get('unique_usernames', 0)
    if unique_usernames > 5:
        score += THREAT_WEIGHTS['multiple_usernames_over_5']
        breakdown['credential_stuffing'] = THREAT_WEIGHTS['multiple_usernames_over_5']
    
    unique_passwords = attacker.get('unique_passwords', 0)
    if unique_passwords > 10:
        score += THREAT_WEIGHTS['multiple_passwords_over_10']
        breakdown['password_spray'] = THREAT_WEIGHTS['multiple_passwords_over_10']
    
    # Check for targeted privileged accounts
    targeted_accounts = _check_targeted_accounts(ip_address)
    if 'root' in targeted_accounts:
        score += THREAT_WEIGHTS['targeted_root_login']
        breakdown['targeted_root'] = THREAT_WEIGHTS['targeted_root_login']
    elif 'admin' in targeted_accounts or 'administrator' in targeted_accounts:
        score += THREAT_WEIGHTS['targeted_admin_login']
        breakdown['targeted_admin'] = THREAT_WEIGHTS['targeted_admin_login']
    
    # Check for default credentials
    if _used_default_credentials(ip_address):
        score += THREAT_WEIGHTS['common_default_creds']
        breakdown['default_creds'] = THREAT_WEIGHTS['common_default_creds']
    
    # === Behavioral signals ===
    
    if _has_rapid_fire_behavior(ip_address):
        score += THREAT_WEIGHTS['rapid_fire_under_1_second']
        breakdown['rapid_fire'] = THREAT_WEIGHTS['rapid_fire_under_1_second']
    
    services_targeted = _get_services_targeted(ip_address)
    if len(services_targeted) >= 2:
        score += THREAT_WEIGHTS['multi_service_targeting']
        breakdown['multi_service'] = THREAT_WEIGHTS['multi_service_targeting']
    
    # === Intelligence signals ===
    
    if attacker.get('is_known_bad'):
        score += THREAT_WEIGHTS['known_bad_ip']
        breakdown['known_bad'] = THREAT_WEIGHTS['known_bad_ip']
    
    abuse_score = attacker.get('abuseipdb_score', 0)
    if abuse_score >= 90:
        score += THREAT_WEIGHTS['abuseipdb_score_over_90']
        breakdown['abuseipdb'] = THREAT_WEIGHTS['abuseipdb_score_over_90']
    elif abuse_score >= 75:
        score += THREAT_WEIGHTS['abuseipdb_score_over_75']
        breakdown['abuseipdb'] = THREAT_WEIGHTS['abuseipdb_score_over_75']
    elif abuse_score >= 50:
        score += THREAT_WEIGHTS['abuseipdb_score_over_50']
        breakdown['abuseipdb'] = THREAT_WEIGHTS['abuseipdb_score_over_50']
    elif abuse_score >= 25:
        score += THREAT_WEIGHTS['abuseipdb_score_over_25']
        breakdown['abuseipdb'] = THREAT_WEIGHTS['abuseipdb_score_over_25']
    
    if attacker.get('otx_pulses', 0) > 0:
        score += THREAT_WEIGHTS['otx_pulse_match']
        breakdown['otx_pulses'] = THREAT_WEIGHTS['otx_pulse_match']
    
    if attacker.get('is_tor_exit'):
        score += THREAT_WEIGHTS['tor_exit_node']
        breakdown['tor_exit'] = THREAT_WEIGHTS['tor_exit_node']
    
    # Check if datacenter/hosting IP
    if _is_datacenter_ip(attacker.get('isp', '')):
        score += THREAT_WEIGHTS['datacenter_hosting_ip']
        breakdown['datacenter'] = THREAT_WEIGHTS['datacenter_hosting_ip']
    
    # Cap score at 100
    score = min(score, 100)
    
    # Determine verdict
    verdict = _get_verdict(score)
    
    logger.info(f"Threat score for {ip_address}: {score}/100 ({verdict})")
    
    return {
        'score': score,
        'verdict': verdict,
        'breakdown': breakdown
    }


def _get_attacker_data(ip_address: str) -> Optional[Dict]:
    """Get attacker record from database"""
    
    query = """
        SELECT *,
               (SELECT COUNT(DISTINCT username) FROM login_attempts WHERE ip_address = ?) as unique_usernames,
               (SELECT COUNT(DISTINCT password_attempt) FROM login_attempts WHERE ip_address = ?) as unique_passwords
        FROM attackers
        WHERE ip_address = ?
    """
    
    results = db.execute_query(query, (ip_address, ip_address, ip_address))
    
    if results:
        return dict(results[0])
    
    return None


def _check_targeted_accounts(ip_address: str) -> set:
    """Get set of usernames targeted by this IP"""
    
    query = """
        SELECT DISTINCT LOWER(username) as username
        FROM login_attempts
        WHERE ip_address = ?
        AND username IS NOT NULL
    """
    
    results = db.execute_query(query, (ip_address,))
    
    return {row['username'] for row in results if row['username']}


def _used_default_credentials(ip_address: str) -> bool:
    """Check if IP tried common default credentials"""
    
    default_pairs = [
        ('admin', 'admin'),
        ('root', 'root'),
        ('admin', 'password'),
        ('root', 'toor'),
        ('admin', '123456'),
        ('root', 'password'),
        ('test', 'test'),
        ('guest', 'guest'),
    ]
    
    for username, password in default_pairs:
        query = """
            SELECT COUNT(*) as cnt
            FROM login_attempts
            WHERE ip_address = ?
            AND LOWER(username) = LOWER(?)
            AND password_attempt = ?
        """
        
        results = db.execute_query(query, (ip_address, username, password))
        
        if results and results[0]['cnt'] > 0:
            return True
    
    return False


def _has_rapid_fire_behavior(ip_address: str) -> bool:
    """Check for rapid-fire attack behavior"""
    
    query = """
        SELECT time_since_last_attempt
        FROM login_attempts
        WHERE ip_address = ?
        AND time_since_last_attempt IS NOT NULL
        AND time_since_last_attempt < 1.0
        LIMIT 3
    """
    
    results = db.execute_query(query, (ip_address,))
    
    # If we have 3+ attempts under 1 second apart
    return len(results) >= 3


def _get_services_targeted(ip_address: str) -> set:
    """Get set of services targeted by this IP"""
    
    query = """
        SELECT DISTINCT service_name
        FROM connections
        WHERE ip_address = ?
    """
    
    results = db.execute_query(query, (ip_address,))
    
    return {row['service_name'] for row in results}


def _is_datacenter_ip(isp: str) -> bool:
    """Check if ISP indicates datacenter/hosting provider"""
    
    if not isp:
        return False
    
    isp_lower = isp.lower()
    
    datacenter_keywords = [
        'hosting', 'datacenter', 'data center', 'cloud',
        'server', 'digital ocean', 'aws', 'amazon',
        'linode', 'vultr', 'ovh', 'hetzner'
    ]
    
    return any(keyword in isp_lower for keyword in datacenter_keywords)


def _get_verdict(score: int) -> str:
    """Get verdict based on score"""
    
    for min_score, max_score, verdict in VERDICT_THRESHOLDS:
        if min_score <= score < max_score:
            return verdict
    
    return "UNKNOWN"


def update_attacker_threat_score(ip_address: str):
    """
    Calculate and update threat score for an attacker
    
    Args:
        ip_address: IP address to update
    """
    
    result = calculate_threat_score(ip_address)
    
    query = """
        UPDATE attackers
        SET threat_score = ?,
            verdict = ?
        WHERE ip_address = ?
    """
    
    db.execute_update(
        query,
        (result['score'], result['verdict'], ip_address)
    )
    
    logger.info(
        f"Updated threat score for {ip_address}: "
        f"{result['score']}/100 ({result['verdict']})"
    )


def recalculate_all_scores(limit: int = None):
    """
    Recalculate threat scores for all attackers
    
    Args:
        limit: Optional limit on number of attackers to process
    """
    
    query = "SELECT ip_address FROM attackers ORDER BY last_seen DESC"
    
    if limit:
        query += f" LIMIT {limit}"
    
    results = db.execute_query(query)
    
    logger.info(f"Recalculating threat scores for {len(results)} attackers")
    
    for row in results:
        update_attacker_threat_score(row['ip_address'])
