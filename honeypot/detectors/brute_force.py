import logging
from datetime import datetime, timedelta
from typing import List, Dict, Optional
import config
from database.db import db

logger = logging.getLogger("honeypot.detector.brute_force")


# Detection rule definitions
DETECTION_RULES = {
    "brute_force_ssh": {
        "description": "More than 10 login attempts from same IP in 5 minutes",
        "threshold_count": 10,
        "threshold_window_seconds": 300,
        "service": "SSH",
        "severity": "HIGH",
        "alert_type": "BRUTE_FORCE"
    },
    "brute_force_ftp": {
        "description": "More than 10 FTP login attempts from same IP in 5 minutes",
        "threshold_count": 10,
        "threshold_window_seconds": 300,
        "service": "FTP",
        "severity": "HIGH",
        "alert_type": "BRUTE_FORCE"
    },
    "brute_force_telnet": {
        "description": "More than 5 Telnet login attempts from same IP in 5 minutes",
        "threshold_count": 5,
        "threshold_window_seconds": 300,
        "service": "Telnet",
        "severity": "HIGH",
        "alert_type": "BRUTE_FORCE"
    },
    "brute_force_http": {
        "description": "More than 10 HTTP login attempts from same IP in 10 minutes",
        "threshold_count": 10,
        "threshold_window_seconds": 600,
        "service": "HTTP",
        "severity": "HIGH",
        "alert_type": "BRUTE_FORCE"
    },
    "credential_stuffing": {
        "description": "More than 5 different usernames from same IP in 10 minutes",
        "threshold_unique_usernames": 5,
        "threshold_window_seconds": 600,
        "severity": "HIGH",
        "alert_type": "CREDENTIAL_STUFFING"
    },
    "password_spray": {
        "description": "Same username attempted with more than 20 different passwords",
        "threshold_unique_passwords": 20,
        "severity": "HIGH",
        "alert_type": "PASSWORD_SPRAY"
    },
    "rapid_fire": {
        "description": "More than 3 attempts per second - automated tool",
        "threshold_per_second": 3,
        "severity": "CRITICAL",
        "alert_type": "AUTOMATED_ATTACK"
    },
    "multi_service": {
        "description": "Same IP attacking more than 2 different services",
        "threshold_services": 2,
        "severity": "HIGH",
        "alert_type": "MULTI_SERVICE_ATTACK"
    },
    "default_credentials": {
        "description": "Attempting default/common credentials",
        "credential_pairs": [
            ("admin", "admin"), ("root", "root"), ("admin", "password"),
            ("root", "toor"), ("admin", "123456"), ("user", "user"),
            ("admin", "admin123"), ("root", "password"), ("test", "test"),
            ("guest", "guest"), ("pi", "raspberry"), ("ubnt", "ubnt"),
            ("administrator", "administrator"), ("admin", "1234"),
            ("root", "12345"), ("admin", ""), ("root", "")
        ],
        "severity": "MEDIUM",
        "alert_type": "DEFAULT_CREDENTIALS"
    }
}


class BruteForceDetector:
    """Detects brute force and credential attacks"""
    
    def __init__(self):
        self.logger = logger
    
    def check_brute_force(self, ip_address: str, service_name: str) -> Optional[Dict]:
        """Check for brute force attack pattern"""
        
        # Get rule for this service
        rule_key = f"brute_force_{service_name.lower()}"
        if rule_key not in DETECTION_RULES:
            return None
        
        rule = DETECTION_RULES[rule_key]
        threshold = rule["threshold_count"]
        window_seconds = rule["threshold_window_seconds"]
        
        # Query login attempts in time window
        query = """
            SELECT COUNT(*) as attempt_count
            FROM login_attempts
            WHERE ip_address = ?
            AND service_name = ?
            AND timestamp >= datetime('now', '-' || ? || ' seconds')
        """
        
        results = db.execute_query(query, (ip_address, service_name, window_seconds))
        
        if results and results[0]['attempt_count'] >= threshold:
            self.logger.warning(
                f"BRUTE FORCE DETECTED: {ip_address} - "
                f"{results[0]['attempt_count']} attempts on {service_name} "
                f"in {window_seconds}s"
            )
            
            return {
                "alert_type": rule["alert_type"],
                "severity": rule["severity"],
                "description": f"{rule['description']} - Detected {results[0]['attempt_count']} attempts",
                "ip_address": ip_address,
                "service": service_name,
                "attempt_count": results[0]['attempt_count'],
                "time_window": f"{window_seconds} seconds"
            }
        
        return None
    
    def check_credential_stuffing(self, ip_address: str) -> Optional[Dict]:
        """Check for credential stuffing pattern - many different usernames"""
        
        rule = DETECTION_RULES["credential_stuffing"]
        threshold = rule["threshold_unique_usernames"]
        window_seconds = rule["threshold_window_seconds"]
        
        # Query unique usernames in time window
        query = """
            SELECT COUNT(DISTINCT username) as unique_usernames,
                   GROUP_CONCAT(DISTINCT username) as usernames_tried
            FROM login_attempts
            WHERE ip_address = ?
            AND timestamp >= datetime('now', '-' || ? || ' seconds')
        """
        
        results = db.execute_query(query, (ip_address, window_seconds))
        
        if results and results[0]['unique_usernames'] >= threshold:
            self.logger.warning(
                f"CREDENTIAL STUFFING DETECTED: {ip_address} - "
                f"{results[0]['unique_usernames']} unique usernames tried"
            )
            
            return {
                "alert_type": rule["alert_type"],
                "severity": rule["severity"],
                "description": f"{rule['description']} - Tried {results[0]['unique_usernames']} usernames",
                "ip_address": ip_address,
                "unique_usernames": results[0]['unique_usernames'],
                "usernames_tried": results[0]['usernames_tried'],
                "time_window": f"{window_seconds} seconds"
            }
        
        return None
    
    def check_password_spray(self, ip_address: str, username: str) -> Optional[Dict]:
        """Check for password spray attack - many passwords for same username"""
        
        rule = DETECTION_RULES["password_spray"]
        threshold = rule["threshold_unique_passwords"]
        
        # Query unique passwords for this username
        query = """
            SELECT COUNT(DISTINCT password_attempt) as unique_passwords
            FROM login_attempts
            WHERE ip_address = ?
            AND username = ?
        """
        
        results = db.execute_query(query, (ip_address, username))
        
        if results and results[0]['unique_passwords'] >= threshold:
            self.logger.warning(
                f"PASSWORD SPRAY DETECTED: {ip_address} - "
                f"{results[0]['unique_passwords']} passwords for user '{username}'"
            )
            
            return {
                "alert_type": rule["alert_type"],
                "severity": rule["severity"],
                "description": f"{rule['description']} - {results[0]['unique_passwords']} passwords for '{username}'",
                "ip_address": ip_address,
                "username": username,
                "unique_passwords": results[0]['unique_passwords']
            }
        
        return None
    
    def check_rapid_fire(self, ip_address: str, service_name: str) -> Optional[Dict]:
        """Check for rapid-fire automated attacks"""
        
        rule = DETECTION_RULES["rapid_fire"]
        threshold = rule["threshold_per_second"]
        
        # Get last 10 attempts
        query = """
            SELECT timestamp, time_since_last_attempt
            FROM login_attempts
            WHERE ip_address = ?
            AND service_name = ?
            AND time_since_last_attempt IS NOT NULL
            ORDER BY timestamp DESC
            LIMIT 10
        """
        
        results = db.execute_query(query, (ip_address, service_name))
        
        if results and len(results) >= 3:
            # Check if multiple attempts are under 1 second apart
            rapid_count = sum(1 for r in results if r['time_since_last_attempt'] and r['time_since_last_attempt'] < 1.0)
            
            if rapid_count >= threshold:
                self.logger.critical(
                    f"RAPID FIRE ATTACK DETECTED: {ip_address} - "
                    f"{rapid_count} attempts under 1 second apart"
                )
                
                return {
                    "alert_type": rule["alert_type"],
                    "severity": rule["severity"],
                    "description": f"{rule['description']} - Automated tool detected",
                    "ip_address": ip_address,
                    "service": service_name,
                    "rapid_attempts": rapid_count
                }
        
        return None
    
    def check_multi_service(self, ip_address: str) -> Optional[Dict]:
        """Check if IP is attacking multiple services"""
        
        rule = DETECTION_RULES["multi_service"]
        threshold = rule["threshold_services"]
        
        # Query distinct services attacked
        query = """
            SELECT COUNT(DISTINCT service_name) as service_count,
                   GROUP_CONCAT(DISTINCT service_name) as services
            FROM login_attempts
            WHERE ip_address = ?
        """
        
        results = db.execute_query(query, (ip_address,))
        
        if results and results[0]['service_count'] >= threshold:
            self.logger.warning(
                f"MULTI-SERVICE ATTACK DETECTED: {ip_address} - "
                f"Attacking {results[0]['service_count']} services"
            )
            
            return {
                "alert_type": rule["alert_type"],
                "severity": rule["severity"],
                "description": f"{rule['description']} - Targeting {results[0]['services']}",
                "ip_address": ip_address,
                "service_count": results[0]['service_count'],
                "services": results[0]['services']
            }
        
        return None
    
    def check_default_credentials(self, ip_address: str, username: str, password: str) -> Optional[Dict]:
        """Check if default/common credentials are being tried"""
        
        rule = DETECTION_RULES["default_credentials"]
        credential_pairs = rule["credential_pairs"]
        
        # Check if this credential pair is in the list
        if (username, password) in credential_pairs:
            self.logger.warning(
                f"DEFAULT CREDENTIALS DETECTED: {ip_address} - "
                f"Trying {username}/{password}"
            )
            
            return {
                "alert_type": rule["alert_type"],
                "severity": rule["severity"],
                "description": f"{rule['description']} - Tried {username}/{password}",
                "ip_address": ip_address,
                "username": username,
                "password": password
            }
        
        return None
    
    def run_all_checks(self, ip_address: str, service_name: str, 
                       username: str = None, password: str = None) -> List[Dict]:
        """Run all detection checks and return any alerts"""
        
        alerts = []
        
        # Brute force check
        brute_force = self.check_brute_force(ip_address, service_name)
        if brute_force:
            alerts.append(brute_force)
        
        # Credential stuffing check
        credential_stuffing = self.check_credential_stuffing(ip_address)
        if credential_stuffing:
            alerts.append(credential_stuffing)
        
        # Password spray check (only if username provided)
        if username:
            password_spray = self.check_password_spray(ip_address, username)
            if password_spray:
                alerts.append(password_spray)
        
        # Rapid fire check
        rapid_fire = self.check_rapid_fire(ip_address, service_name)
        if rapid_fire:
            alerts.append(rapid_fire)
        
        # Multi-service check
        multi_service = self.check_multi_service(ip_address)
        if multi_service:
            alerts.append(multi_service)
        
        # Default credentials check (only if both username and password provided)
        if username and password:
            default_creds = self.check_default_credentials(ip_address, username, password)
            if default_creds:
                alerts.append(default_creds)
        
        return alerts


# Global detector instance
detector = BruteForceDetector()
