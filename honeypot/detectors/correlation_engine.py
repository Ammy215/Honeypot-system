"""
Correlation Engine - Advanced pattern correlation across all data
"""

import logging
from datetime import datetime, timedelta
from typing import List, Dict, Optional, Tuple
from database.db import db

logger = logging.getLogger("honeypot.detector.correlation")


class CorrelationEngine:
    """Advanced correlation of attack patterns"""
    
    def __init__(self):
        self.logger = logger
    
    def correlate_attacker_behavior(self, ip_address: str) -> Dict:
        """
        Comprehensive behavior correlation for a single attacker
        
        Args:
            ip_address: IP to analyze
        
        Returns:
            Dictionary with correlation analysis
        """
        
        analysis = {
            'ip_address': ip_address,
            'attack_sequence': [],
            'temporal_patterns': {},
            'service_correlation': {},
            'credential_patterns': {},
            'behavioral_score': 0
        }
        
        # 1. Attack sequence timeline
        analysis['attack_sequence'] = self._get_attack_sequence(ip_address)
        
        # 2. Temporal patterns (when they attack)
        analysis['temporal_patterns'] = self._analyze_temporal_patterns(ip_address)
        
        # 3. Service correlation (which services, in what order)
        analysis['service_correlation'] = self._analyze_service_patterns(ip_address)
        
        # 4. Credential patterns
        analysis['credential_patterns'] = self._analyze_credential_patterns(ip_address)
        
        # 5. Calculate behavioral score
        analysis['behavioral_score'] = self._calculate_behavioral_score(analysis)
        
        return analysis
    
    def find_similar_attackers(self, ip_address: str, threshold: float = 0.7) -> List[Tuple[str, float]]:
        """
        Find attackers with similar behavior patterns
        
        Args:
            ip_address: Reference IP
            threshold: Similarity threshold (0-1)
        
        Returns:
            List of (ip, similarity_score) tuples
        """
        
        # Get reference behavior
        ref_behavior = self.correlate_attacker_behavior(ip_address)
        
        # Get all other attackers
        query = """
            SELECT DISTINCT ip_address
            FROM attackers
            WHERE ip_address != ?
            AND total_login_attempts > 0
        """
        
        results = db.execute_query(query, (ip_address,))
        
        similar = []
        
        for row in results:
            other_ip = row['ip_address']
            other_behavior = self.correlate_attacker_behavior(other_ip)
            
            # Calculate similarity
            similarity = self._calculate_behavior_similarity(ref_behavior, other_behavior)
            
            if similarity >= threshold:
                similar.append((other_ip, similarity))
        
        # Sort by similarity
        similar.sort(key=lambda x: x[1], reverse=True)
        
        return similar
    
    def detect_attack_chains(self, time_window_minutes: int = 60) -> List[Dict]:
        """
        Detect attack chains (sequences of related attacks)
        
        Args:
            time_window_minutes: Time window to consider attacks as chained
        
        Returns:
            List of detected attack chains
        """
        
        # Find attackers with multiple service attempts in short time
        query = f"""
            SELECT 
                c.ip_address,
                c.service_name,
                c.timestamp,
                c.destination_port
            FROM connections c
            WHERE c.timestamp >= datetime('now', '-24 hours')
            ORDER BY c.ip_address, c.timestamp
        """
        
        results = db.execute_query(query)
        
        if not results:
            return []
        
        chains = []
        current_chain = None
        last_ip = None
        last_time = None
        
        for row in results:
            ip = row['ip_address']
            service = row['service_name']
            timestamp = datetime.fromisoformat(row['timestamp'])
            
            if ip != last_ip:
                # New IP - start new potential chain
                if current_chain and len(current_chain['sequence']) >= 2:
                    chains.append(current_chain)
                
                current_chain = {
                    'ip_address': ip,
                    'sequence': [(service, timestamp)],
                    'start_time': timestamp,
                    'services': [service]
                }
                last_ip = ip
                last_time = timestamp
            else:
                # Same IP - check if within time window
                time_diff = (timestamp - last_time).total_seconds() / 60
                
                if time_diff <= time_window_minutes:
                    # Part of chain
                    current_chain['sequence'].append((service, timestamp))
                    if service not in current_chain['services']:
                        current_chain['services'].append(service)
                    last_time = timestamp
                else:
                    # Gap too large - save old chain, start new
                    if len(current_chain['sequence']) >= 2:
                        chains.append(current_chain)
                    
                    current_chain = {
                        'ip_address': ip,
                        'sequence': [(service, timestamp)],
                        'start_time': timestamp,
                        'services': [service]
                    }
                    last_time = timestamp
        
        # Add last chain
        if current_chain and len(current_chain['sequence']) >= 2:
            chains.append(current_chain)
        
        # Enrich chains
        for chain in chains:
            chain['length'] = len(chain['sequence'])
            chain['duration_minutes'] = (chain['sequence'][-1][1] - chain['start_time']).total_seconds() / 60
            chain['unique_services'] = len(chain['services'])
            chain['severity'] = 'HIGH' if chain['unique_services'] >= 3 else 'MEDIUM'
        
        self.logger.info(f"Detected {len(chains)} attack chains")
        
        return chains
    
    def _get_attack_sequence(self, ip_address: str) -> List[Dict]:
        """Get chronological sequence of attacks"""
        
        query = """
            SELECT 
                timestamp,
                'connection' as event_type,
                service_name as target,
                NULL as username
            FROM connections
            WHERE ip_address = ?
            
            UNION ALL
            
            SELECT 
                timestamp,
                'login_attempt' as event_type,
                service_name as target,
                username
            FROM login_attempts
            WHERE ip_address = ?
            
            ORDER BY timestamp
        """
        
        results = db.execute_query(query, (ip_address, ip_address))
        
        return [dict(row) for row in results]
    
    def _analyze_temporal_patterns(self, ip_address: str) -> Dict:
        """Analyze when attacks occur (time patterns)"""
        
        query = """
            SELECT 
                strftime('%H', timestamp) as hour,
                strftime('%w', timestamp) as day_of_week,
                COUNT(*) as count
            FROM connections
            WHERE ip_address = ?
            GROUP BY hour, day_of_week
        """
        
        results = db.execute_query(query, (ip_address,))
        
        if not results:
            return {}
        
        # Find peak hours
        peak_hours = {}
        for row in results:
            hour = int(row['hour'])
            count = row['count']
            peak_hours[hour] = peak_hours.get(hour, 0) + count
        
        # Find most active hour
        most_active_hour = max(peak_hours, key=peak_hours.get) if peak_hours else None
        
        return {
            'peak_hour': most_active_hour,
            'hourly_distribution': peak_hours,
            'is_after_hours': most_active_hour and (most_active_hour < 6 or most_active_hour > 22)
        }
    
    def _analyze_service_patterns(self, ip_address: str) -> Dict:
        """Analyze which services are targeted and in what pattern"""
        
        query = """
            SELECT 
                service_name,
                COUNT(*) as hit_count,
                MIN(timestamp) as first_hit,
                MAX(timestamp) as last_hit
            FROM connections
            WHERE ip_address = ?
            GROUP BY service_name
            ORDER BY first_hit
        """
        
        results = db.execute_query(query, (ip_address,))
        
        if not results:
            return {}
        
        services = [row['service_name'] for row in results]
        
        return {
            'services_targeted': services,
            'service_count': len(services),
            'service_order': services,  # Order of first contact
            'is_scanning': len(services) >= 3,  # Hitting 3+ services suggests scanning
            'service_details': [dict(row) for row in results]
        }
    
    def _analyze_credential_patterns(self, ip_address: str) -> Dict:
        """Analyze credential attack patterns"""
        
        query = """
            SELECT 
                COUNT(DISTINCT username) as unique_users,
                COUNT(DISTINCT password_attempt) as unique_passwords,
                COUNT(*) as total_attempts,
                GROUP_CONCAT(DISTINCT username) as usernames
            FROM login_attempts
            WHERE ip_address = ?
        """
        
        results = db.execute_query(query, (ip_address,))
        
        if not results or not results[0]['total_attempts']:
            return {}
        
        row = results[0]
        
        # Determine attack type
        attack_type = None
        if row['unique_users'] > row['unique_passwords'] * 2:
            attack_type = 'credential_stuffing'
        elif row['unique_passwords'] > row['unique_users'] * 2:
            attack_type = 'password_spray'
        elif row['total_attempts'] >= 20:
            attack_type = 'brute_force'
        else:
            attack_type = 'targeted'
        
        return {
            'unique_usernames': row['unique_users'],
            'unique_passwords': row['unique_passwords'],
            'total_attempts': row['total_attempts'],
            'attack_type': attack_type,
            'usernames_tried': row['usernames'].split(',') if row['usernames'] else []
        }
    
    def _calculate_behavioral_score(self, analysis: Dict) -> int:
        """Calculate behavioral threat score based on patterns"""
        
        score = 0
        
        # Service correlation
        service_count = analysis['service_correlation'].get('service_count', 0)
        if service_count >= 4:
            score += 30  # Extensive scanning
        elif service_count >= 2:
            score += 20  # Multi-service
        else:
            score += 10  # Single service
        
        # Temporal patterns
        if analysis['temporal_patterns'].get('is_after_hours'):
            score += 15  # After-hours activity
        
        # Credential patterns
        cred = analysis['credential_patterns']
        if cred:
            if cred.get('attack_type') == 'credential_stuffing':
                score += 25
            elif cred.get('attack_type') == 'brute_force':
                score += 20
            
            if cred.get('total_attempts', 0) > 50:
                score += 10
        
        # Attack sequence length
        if len(analysis['attack_sequence']) > 20:
            score += 15  # Persistent attacker
        
        return min(score, 100)  # Cap at 100
    
    def _calculate_behavior_similarity(self, behavior1: Dict, behavior2: Dict) -> float:
        """Calculate similarity between two behavior profiles"""
        
        similarity = 0.0
        factors = 0
        
        # Service similarity
        services1 = set(behavior1['service_correlation'].get('services_targeted', []))
        services2 = set(behavior2['service_correlation'].get('services_targeted', []))
        
        if services1 and services2:
            service_sim = len(services1 & services2) / len(services1 | services2)
            similarity += service_sim
            factors += 1
        
        # Temporal similarity
        peak1 = behavior1['temporal_patterns'].get('peak_hour')
        peak2 = behavior2['temporal_patterns'].get('peak_hour')
        
        if peak1 is not None and peak2 is not None:
            hour_diff = abs(peak1 - peak2)
            hour_sim = 1.0 - (min(hour_diff, 24 - hour_diff) / 12)
            similarity += hour_sim
            factors += 1
        
        # Credential pattern similarity
        cred1 = behavior1['credential_patterns'].get('attack_type')
        cred2 = behavior2['credential_patterns'].get('attack_type')
        
        if cred1 and cred2:
            if cred1 == cred2:
                similarity += 1.0
            factors += 1
        
        return similarity / factors if factors > 0 else 0.0


# Global engine instance
correlation_engine = CorrelationEngine()
