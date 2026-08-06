"""
Query functions for login attempts and detection
"""

from database.db import db
from honeypot.detectors.brute_force import detector
from honeypot.alerting.alert_engine import alert_engine


def check_and_alert_after_login(ip_address: str, service_name: str, 
                                 username: str = None, password: str = None):
    """
    Run detection checks after a login attempt and generate alerts if needed
    
    This should be called after logging a login attempt to the database
    """
    
    # Run all detection checks
    alerts = detector.run_all_checks(ip_address, service_name, username, password)
    
    # Generate alerts for each detection
    for alert_data in alerts:
        alert_engine.generate_alert(alert_data)
    
    # Update threat score after login activity
    try:
        from honeypot.intelligence.threat_scorer import update_attacker_threat_score
        update_attacker_threat_score(ip_address)
    except Exception as e:
        # Don't fail if threat scoring fails
        pass
    
    return len(alerts)


def get_login_attempts_by_ip(ip_address: str, limit: int = 100):
    """Get all login attempts for a specific IP"""
    
    query = """
        SELECT * FROM login_attempts
        WHERE ip_address = ?
        ORDER BY timestamp DESC
        LIMIT ?
    """
    
    results = db.execute_query(query, (ip_address, limit))
    return [dict(row) for row in results]


def get_login_attempts_by_service(service_name: str, limit: int = 100):
    """Get all login attempts for a specific service"""
    
    query = """
        SELECT * FROM login_attempts
        WHERE service_name = ?
        ORDER BY timestamp DESC
        LIMIT ?
    """
    
    results = db.execute_query(query, (service_name, limit))
    return [dict(row) for row in results]


def get_recent_login_attempts(limit: int = 50):
    """Get most recent login attempts across all services"""
    
    query = """
        SELECT 
            la.*,
            a.country,
            a.country_code
        FROM login_attempts la
        LEFT JOIN attackers a ON la.attacker_id = a.id
        ORDER BY la.timestamp DESC
        LIMIT ?
    """
    
    results = db.execute_query(query, (limit,))
    return [dict(row) for row in results]


def get_top_usernames_tried(limit: int = 20):
    """Get most commonly attempted usernames"""
    
    query = """
        SELECT 
            username,
            COUNT(*) as attempt_count,
            COUNT(DISTINCT ip_address) as unique_ips
        FROM login_attempts
        WHERE username IS NOT NULL
        GROUP BY username
        ORDER BY attempt_count DESC
        LIMIT ?
    """
    
    results = db.execute_query(query, (limit,))
    return [dict(row) for row in results]


def get_top_passwords_tried(limit: int = 20):
    """Get most commonly attempted passwords"""
    
    query = """
        SELECT 
            password_attempt,
            COUNT(*) as attempt_count,
            COUNT(DISTINCT ip_address) as unique_ips
        FROM login_attempts
        WHERE password_attempt IS NOT NULL
        GROUP BY password_attempt
        ORDER BY attempt_count DESC
        LIMIT ?
    """
    
    results = db.execute_query(query, (limit,))
    return [dict(row) for row in results]


def get_credential_pairs(limit: int = 50):
    """Get most commonly attempted username/password pairs"""
    
    query = """
        SELECT 
            username,
            password_attempt,
            COUNT(*) as attempt_count,
            COUNT(DISTINCT ip_address) as unique_ips
        FROM login_attempts
        WHERE username IS NOT NULL AND password_attempt IS NOT NULL
        GROUP BY username, password_attempt
        ORDER BY attempt_count DESC
        LIMIT ?
    """
    
    results = db.execute_query(query, (limit,))
    return [dict(row) for row in results]
