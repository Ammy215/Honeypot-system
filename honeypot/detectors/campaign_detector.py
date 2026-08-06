"""
Campaign Detection - Identifies coordinated attack campaigns
"""

import logging
from datetime import datetime, timedelta
from typing import List, Dict, Optional
from database.db import db

logger = logging.getLogger("honeypot.detector.campaign")


class CampaignDetector:
    """Detects coordinated attack campaigns"""
    
    def __init__(self):
        self.logger = logger
    
    def detect_campaigns(self, time_window_hours: int = 24) -> List[Dict]:
        """
        Detect attack campaigns based on multiple correlation factors
        
        Args:
            time_window_hours: Time window to analyze
        
        Returns:
            List of detected campaigns
        """
        
        campaigns = []
        
        # 1. ASN-based campaigns (same network)
        asn_campaigns = self._detect_asn_campaigns(time_window_hours)
        campaigns.extend(asn_campaigns)
        
        # 2. Credential pattern campaigns (same username/password pattern)
        cred_campaigns = self._detect_credential_campaigns(time_window_hours)
        campaigns.extend(cred_campaigns)
        
        # 3. Timing-based campaigns (coordinated timing)
        timing_campaigns = self._detect_timing_campaigns(time_window_hours)
        campaigns.extend(timing_campaigns)
        
        # 4. Target pattern campaigns (same services/ports)
        target_campaigns = self._detect_target_campaigns(time_window_hours)
        campaigns.extend(target_campaigns)
        
        self.logger.info(f"Detected {len(campaigns)} attack campaigns")
        
        return campaigns
    
    def _detect_asn_campaigns(self, hours: int) -> List[Dict]:
        """Detect campaigns from same ASN/network"""
        
        query = f"""
            SELECT 
                asn,
                COUNT(DISTINCT ip_address) as attacker_count,
                COUNT(*) as total_attempts,
                MIN(first_seen) as campaign_start,
                MAX(last_seen) as campaign_end,
                GROUP_CONCAT(DISTINCT ip_address) as ip_list
            FROM attackers
            WHERE asn IS NOT NULL
            AND last_seen >= datetime('now', '-{hours} hours')
            GROUP BY asn
            HAVING attacker_count >= 3
            ORDER BY attacker_count DESC
        """
        
        results = db.execute_query(query)
        
        campaigns = []
        for row in results:
            # Get targeted services
            services = self._get_services_for_ips(row['ip_list'].split(','))
            
            campaign = {
                'type': 'ASN_COORDINATED',
                'asn': row['asn'],
                'attacker_count': row['attacker_count'],
                'total_attempts': row['total_attempts'],
                'start_time': row['campaign_start'],
                'end_time': row['campaign_end'],
                'ip_addresses': row['ip_list'].split(','),
                'services_targeted': services,
                'severity': 'HIGH' if row['attacker_count'] >= 5 else 'MEDIUM',
                'description': f"Coordinated attack from {row['attacker_count']} IPs in {row['asn']}"
            }
            
            campaigns.append(campaign)
            
            self.logger.warning(
                f"ASN Campaign detected: {row['asn']} - "
                f"{row['attacker_count']} attackers"
            )
        
        return campaigns
    
    def _detect_credential_campaigns(self, hours: int) -> List[Dict]:
        """Detect campaigns using same credentials"""
        
        query = f"""
            SELECT 
                username,
                password_attempt,
                COUNT(DISTINCT ip_address) as attacker_count,
                COUNT(*) as attempt_count,
                MIN(timestamp) as first_seen,
                MAX(timestamp) as last_seen,
                GROUP_CONCAT(DISTINCT ip_address) as ip_list,
                GROUP_CONCAT(DISTINCT service_name) as services
            FROM login_attempts
            WHERE timestamp >= datetime('now', '-{hours} hours')
            AND username IS NOT NULL
            AND password_attempt IS NOT NULL
            GROUP BY username, password_attempt
            HAVING attacker_count >= 3
            ORDER BY attacker_count DESC
            LIMIT 20
        """
        
        results = db.execute_query(query)
        
        campaigns = []
        for row in results:
            campaign = {
                'type': 'CREDENTIAL_PATTERN',
                'username': row['username'],
                'password': row['password_attempt'],
                'attacker_count': row['attacker_count'],
                'attempt_count': row['attempt_count'],
                'start_time': row['first_seen'],
                'end_time': row['last_seen'],
                'ip_addresses': row['ip_list'].split(','),
                'services_targeted': row['services'].split(','),
                'severity': 'HIGH' if row['attacker_count'] >= 5 else 'MEDIUM',
                'description': f"Credential pattern campaign: {row['attacker_count']} IPs using {row['username']}/{row['password_attempt']}"
            }
            
            campaigns.append(campaign)
            
            self.logger.warning(
                f"Credential Campaign detected: {row['username']}/{row['password_attempt']} - "
                f"{row['attacker_count']} attackers"
            )
        
        return campaigns
    
    def _detect_timing_campaigns(self, hours: int) -> List[Dict]:
        """Detect campaigns with coordinated timing (burst attacks)"""
        
        # Find time periods with unusual activity
        query = f"""
            SELECT 
                strftime('%Y-%m-%d %H:00:00', timestamp) as time_bucket,
                COUNT(DISTINCT ip_address) as unique_ips,
                COUNT(*) as connection_count,
                GROUP_CONCAT(DISTINCT ip_address) as ip_list
            FROM connections
            WHERE timestamp >= datetime('now', '-{hours} hours')
            GROUP BY time_bucket
            HAVING unique_ips >= 5 AND connection_count >= 20
            ORDER BY connection_count DESC
        """
        
        results = db.execute_query(query)
        
        campaigns = []
        for row in results:
            # Get common services
            ips = row['ip_list'].split(',')
            services = self._get_services_for_ips(ips)
            
            campaign = {
                'type': 'TIMING_COORDINATED',
                'time_bucket': row['time_bucket'],
                'attacker_count': row['unique_ips'],
                'connection_count': row['connection_count'],
                'ip_addresses': ips,
                'services_targeted': services,
                'severity': 'HIGH' if row['unique_ips'] >= 10 else 'MEDIUM',
                'description': f"Coordinated timing attack: {row['unique_ips']} IPs in 1-hour window"
            }
            
            campaigns.append(campaign)
            
            self.logger.warning(
                f"Timing Campaign detected: {row['time_bucket']} - "
                f"{row['unique_ips']} attackers, {row['connection_count']} connections"
            )
        
        return campaigns
    
    def _detect_target_campaigns(self, hours: int) -> List[Dict]:
        """Detect campaigns targeting same services"""
        
        query = f"""
            SELECT 
                service_name,
                destination_port,
                COUNT(DISTINCT ip_address) as attacker_count,
                COUNT(*) as connection_count,
                MIN(timestamp) as first_seen,
                MAX(timestamp) as last_seen,
                GROUP_CONCAT(DISTINCT ip_address) as ip_list
            FROM connections
            WHERE timestamp >= datetime('now', '-{hours} hours')
            GROUP BY service_name, destination_port
            HAVING attacker_count >= 5
            ORDER BY attacker_count DESC
        """
        
        results = db.execute_query(query)
        
        campaigns = []
        for row in results:
            # Check if IPs share common characteristics
            ips = row['ip_list'].split(',')
            common_asns = self._get_common_asns(ips)
            
            campaign = {
                'type': 'TARGET_FOCUSED',
                'service': row['service_name'],
                'port': row['destination_port'],
                'attacker_count': row['attacker_count'],
                'connection_count': row['connection_count'],
                'start_time': row['first_seen'],
                'end_time': row['last_seen'],
                'ip_addresses': ips,
                'common_asns': common_asns,
                'severity': 'HIGH' if row['attacker_count'] >= 10 else 'MEDIUM',
                'description': f"Focused attack on {row['service_name']}: {row['attacker_count']} attackers"
            }
            
            campaigns.append(campaign)
            
            self.logger.warning(
                f"Target Campaign detected: {row['service_name']}:{row['destination_port']} - "
                f"{row['attacker_count']} attackers"
            )
        
        return campaigns
    
    def _get_services_for_ips(self, ip_list: List[str]) -> List[str]:
        """Get services targeted by a list of IPs"""
        
        if not ip_list:
            return []
        
        ip_str = "','".join(ip_list[:50])  # Limit to prevent SQL issues
        
        query = f"""
            SELECT DISTINCT service_name
            FROM connections
            WHERE ip_address IN ('{ip_str}')
        """
        
        results = db.execute_query(query)
        return [row['service_name'] for row in results]
    
    def _get_common_asns(self, ip_list: List[str]) -> List[str]:
        """Get common ASNs for a list of IPs"""
        
        if not ip_list:
            return []
        
        ip_str = "','".join(ip_list[:50])
        
        query = f"""
            SELECT DISTINCT asn
            FROM attackers
            WHERE ip_address IN ('{ip_str}')
            AND asn IS NOT NULL
        """
        
        results = db.execute_query(query)
        return [row['asn'] for row in results]
    
    def get_campaign_summary(self) -> Dict:
        """Get summary of all detected campaigns"""
        
        campaigns = self.detect_campaigns(24)
        
        summary = {
            'total_campaigns': len(campaigns),
            'by_type': {},
            'by_severity': {},
            'top_asns': [],
            'top_credentials': []
        }
        
        # Count by type
        for campaign in campaigns:
            campaign_type = campaign['type']
            summary['by_type'][campaign_type] = summary['by_type'].get(campaign_type, 0) + 1
            
            severity = campaign['severity']
            summary['by_severity'][severity] = summary['by_severity'].get(severity, 0) + 1
        
        # Get top ASNs
        asn_campaigns = [c for c in campaigns if c['type'] == 'ASN_COORDINATED']
        summary['top_asns'] = sorted(
            asn_campaigns,
            key=lambda x: x['attacker_count'],
            reverse=True
        )[:5]
        
        # Get top credential patterns
        cred_campaigns = [c for c in campaigns if c['type'] == 'CREDENTIAL_PATTERN']
        summary['top_credentials'] = sorted(
            cred_campaigns,
            key=lambda x: x['attacker_count'],
            reverse=True
        )[:5]
        
        return summary


# Global detector instance
campaign_detector = CampaignDetector()
