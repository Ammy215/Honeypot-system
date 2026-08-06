"""
Report Generator - Create formatted threat reports
"""

import logging
from datetime import datetime
from typing import Dict, Optional
from pathlib import Path

from database.db import db

logger = logging.getLogger("honeypot.ai.reports")


class ReportGenerator:
    """Generate formatted threat intelligence reports"""
    
    def __init__(self, output_dir: str = "reports"):
        self.logger = logger
        self.output_dir = Path(output_dir)
        self.output_dir.mkdir(exist_ok=True)
    
    def generate_text_report(self, report_data: Dict, filename: Optional[str] = None) -> str:
        """
        Generate formatted text report
        
        Args:
            report_data: Report data from AI analyst
            filename: Optional custom filename
        
        Returns:
            Path to generated report file
        """
        
        if not filename:
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            filename = f"threat_report_{timestamp}.txt"
        
        filepath = self.output_dir / filename
        
        try:
            with open(filepath, 'w', encoding='utf-8') as f:
                # Header
                f.write("=" * 70 + "\n")
                f.write("HONEYPOT THREAT INTELLIGENCE REPORT\n")
                f.write("=" * 70 + "\n\n")
                
                f.write(f"Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
                
                if 'time_window' in report_data:
                    f.write(f"Time Window: Last {report_data['time_window']} hours\n")
                
                if 'model' in report_data:
                    f.write(f"AI Model: {report_data['model']}\n")
                
                f.write("\n" + "-" * 70 + "\n\n")
                
                # Main report content
                if 'report_text' in report_data:
                    f.write(report_data['report_text'])
                    f.write("\n\n")
                
                # Statistics
                if 'statistics' in report_data:
                    f.write("-" * 70 + "\n")
                    f.write("STATISTICS\n")
                    f.write("-" * 70 + "\n\n")
                    
                    stats = report_data['statistics']
                    for key, value in stats.items():
                        label = key.replace('_', ' ').title()
                        f.write(f"{label}: {value}\n")
                    
                    f.write("\n")
                
                # Footer
                f.write("\n" + "=" * 70 + "\n")
                f.write("END OF REPORT\n")
                f.write("=" * 70 + "\n")
            
            self.logger.info(f"Generated text report: {filepath}")
            return str(filepath)
        
        except Exception as e:
            self.logger.error(f"Error generating text report: {e}")
            raise
    
    def generate_attacker_report(self, ip_address: str, analysis: Dict, filename: Optional[str] = None) -> str:
        """
        Generate attacker-specific report
        
        Args:
            ip_address: IP address
            analysis: Analysis data from AI analyst
            filename: Optional custom filename
        
        Returns:
            Path to generated report file
        """
        
        if not filename:
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            filename = f"attacker_report_{ip_address.replace('.', '_')}_{timestamp}.txt"
        
        filepath = self.output_dir / filename
        
        try:
            # Get attacker data
            query = "SELECT * FROM attackers WHERE ip_address = ?"
            results = db.execute_query(query, (ip_address,))
            
            if not results:
                raise ValueError(f"No data found for IP: {ip_address}")
            
            attacker = dict(results[0])
            
            with open(filepath, 'w', encoding='utf-8') as f:
                # Header
                f.write("=" * 70 + "\n")
                f.write(f"ATTACKER PROFILE REPORT: {ip_address}\n")
                f.write("=" * 70 + "\n\n")
                
                f.write(f"Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n\n")
                
                # Basic Info
                f.write("-" * 70 + "\n")
                f.write("ATTACKER INFORMATION\n")
                f.write("-" * 70 + "\n\n")
                
                f.write(f"IP Address: {attacker['ip_address']}\n")
                f.write(f"Country: {attacker.get('country', 'Unknown')}\n")
                f.write(f"City: {attacker.get('city', 'Unknown')}\n")
                f.write(f"ISP: {attacker.get('isp', 'Unknown')}\n")
                f.write(f"ASN: {attacker.get('asn', 'Unknown')}\n\n")
                
                # Threat Assessment
                f.write("-" * 70 + "\n")
                f.write("THREAT ASSESSMENT\n")
                f.write("-" * 70 + "\n\n")
                
                f.write(f"Threat Score: {attacker['threat_score']}/100\n")
                f.write(f"Verdict: {attacker['verdict']}\n")
                f.write(f"AbuseIPDB Score: {attacker.get('abuseipdb_score', 'N/A')}\n")
                f.write(f"TOR Exit Node: {'Yes' if attacker.get('is_tor_exit') else 'No'}\n")
                f.write(f"Known Bad IP: {'Yes' if attacker.get('is_known_bad') else 'No'}\n\n")
                
                # Activity Stats
                f.write("-" * 70 + "\n")
                f.write("ACTIVITY STATISTICS\n")
                f.write("-" * 70 + "\n\n")
                
                f.write(f"Total Connections: {attacker['total_connections']}\n")
                f.write(f"Total Login Attempts: {attacker['total_login_attempts']}\n")
                f.write(f"First Seen: {attacker['first_seen']}\n")
                f.write(f"Last Seen: {attacker['last_seen']}\n\n")
                
                # AI Analysis
                if 'analysis_text' in analysis:
                    f.write("-" * 70 + "\n")
                    f.write("AI THREAT ANALYSIS\n")
                    f.write("-" * 70 + "\n\n")
                    
                    f.write(analysis['analysis_text'])
                    f.write("\n\n")
                
                # Recent Alerts
                alert_query = """
                    SELECT alert_type, severity, description, timestamp
                    FROM alerts
                    WHERE ip_address = ?
                    ORDER BY timestamp DESC
                    LIMIT 10
                """
                alerts = db.execute_query(alert_query, (ip_address,))
                
                if alerts:
                    f.write("-" * 70 + "\n")
                    f.write("RECENT ALERTS\n")
                    f.write("-" * 70 + "\n\n")
                    
                    for alert in alerts:
                        f.write(f"[{alert['severity']}] {alert['alert_type']}\n")
                        f.write(f"  {alert['description']}\n")
                        f.write(f"  Time: {alert['timestamp']}\n\n")
                
                # Footer
                f.write("=" * 70 + "\n")
                f.write("END OF REPORT\n")
                f.write("=" * 70 + "\n")
            
            self.logger.info(f"Generated attacker report: {filepath}")
            return str(filepath)
        
        except Exception as e:
            self.logger.error(f"Error generating attacker report: {e}")
            raise
    
    def generate_executive_summary(self, time_hours: int = 24) -> str:
        """
        Generate executive summary report
        
        Args:
            time_hours: Time window in hours
        
        Returns:
            Path to generated report file
        """
        
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        filename = f"executive_summary_{timestamp}.txt"
        filepath = self.output_dir / filename
        
        try:
            # Gather statistics
            stats = self._gather_executive_stats(time_hours)
            
            with open(filepath, 'w', encoding='utf-8') as f:
                # Header
                f.write("=" * 70 + "\n")
                f.write("EXECUTIVE SECURITY SUMMARY\n")
                f.write("=" * 70 + "\n\n")
                
                f.write(f"Report Date: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
                f.write(f"Period: Last {time_hours} hours\n\n")
                
                # Key Metrics
                f.write("-" * 70 + "\n")
                f.write("KEY METRICS\n")
                f.write("-" * 70 + "\n\n")
                
                f.write(f"Total Attack Attempts: {stats['total_connections']}\n")
                f.write(f"Unique Attackers: {stats['unique_attackers']}\n")
                f.write(f"Login Attempts: {stats['total_logins']}\n")
                f.write(f"Alerts Generated: {stats['total_alerts']}\n")
                f.write(f"Critical Alerts: {stats['critical_alerts']}\n\n")
                
                # Top Threats
                if stats['top_attackers']:
                    f.write("-" * 70 + "\n")
                    f.write("TOP THREATS\n")
                    f.write("-" * 70 + "\n\n")
                    
                    for i, attacker in enumerate(stats['top_attackers'][:5], 1):
                        f.write(f"{i}. {attacker['ip_address']} ({attacker.get('country', 'Unknown')})\n")
                        f.write(f"   Score: {attacker['threat_score']}/100 | ")
                        f.write(f"Verdict: {attacker['verdict']}\n")
                        f.write(f"   Activity: {attacker['total_connections']} connections, ")
                        f.write(f"{attacker['total_login_attempts']} login attempts\n\n")
                
                # Service Activity
                if stats['service_stats']:
                    f.write("-" * 70 + "\n")
                    f.write("SERVICE ACTIVITY\n")
                    f.write("-" * 70 + "\n\n")
                    
                    for service in stats['service_stats']:
                        f.write(f"• {service['service_name']}: ")
                        f.write(f"{service['connection_count']} connections\n")
                    
                    f.write("\n")
                
                # Geographic Distribution
                if stats['top_countries']:
                    f.write("-" * 70 + "\n")
                    f.write("GEOGRAPHIC DISTRIBUTION\n")
                    f.write("-" * 70 + "\n\n")
                    
                    for country in stats['top_countries']:
                        f.write(f"• {country['country']}: ")
                        f.write(f"{country['attacker_count']} attackers\n")
                    
                    f.write("\n")
                
                # Recommendations
                f.write("-" * 70 + "\n")
                f.write("RECOMMENDATIONS\n")
                f.write("-" * 70 + "\n\n")
                
                if stats['critical_alerts'] > 0:
                    f.write("• IMMEDIATE ACTION: Review and respond to critical alerts\n")
                
                if stats['unique_attackers'] > 10:
                    f.write("• HIGH ACTIVITY: Consider geo-blocking or rate limiting\n")
                
                if stats['total_logins'] > 100:
                    f.write("• CREDENTIAL ATTACKS: Review and strengthen authentication\n")
                
                f.write("• Continue monitoring threat intelligence feeds\n")
                f.write("• Review and update detection rules regularly\n\n")
                
                # Footer
                f.write("=" * 70 + "\n")
                f.write("END OF SUMMARY\n")
                f.write("=" * 70 + "\n")
            
            self.logger.info(f"Generated executive summary: {filepath}")
            return str(filepath)
        
        except Exception as e:
            self.logger.error(f"Error generating executive summary: {e}")
            raise
    
    def _gather_executive_stats(self, time_hours: int) -> Dict:
        """Gather statistics for executive summary"""
        
        stats = {}
        
        # Total connections
        query = f"""
            SELECT COUNT(*) as count
            FROM connections
            WHERE timestamp >= datetime('now', '-{time_hours} hours')
        """
        result = db.execute_query(query)
        stats['total_connections'] = result[0]['count'] if result else 0
        
        # Unique attackers
        query = f"""
            SELECT COUNT(DISTINCT ip_address) as count
            FROM connections
            WHERE timestamp >= datetime('now', '-{time_hours} hours')
        """
        result = db.execute_query(query)
        stats['unique_attackers'] = result[0]['count'] if result else 0
        
        # Total logins
        query = f"""
            SELECT COUNT(*) as count
            FROM login_attempts
            WHERE timestamp >= datetime('now', '-{time_hours} hours')
        """
        result = db.execute_query(query)
        stats['total_logins'] = result[0]['count'] if result else 0
        
        # Total alerts
        query = f"""
            SELECT COUNT(*) as count
            FROM alerts
            WHERE timestamp >= datetime('now', '-{time_hours} hours')
        """
        result = db.execute_query(query)
        stats['total_alerts'] = result[0]['count'] if result else 0
        
        # Critical alerts
        query = f"""
            SELECT COUNT(*) as count
            FROM alerts
            WHERE timestamp >= datetime('now', '-{time_hours} hours')
            AND severity = 'CRITICAL'
        """
        result = db.execute_query(query)
        stats['critical_alerts'] = result[0]['count'] if result else 0
        
        # Top attackers
        query = f"""
            SELECT ip_address, country, threat_score, verdict,
                   total_connections, total_login_attempts
            FROM attackers
            WHERE last_seen >= datetime('now', '-{time_hours} hours')
            ORDER BY threat_score DESC
            LIMIT 5
        """
        stats['top_attackers'] = [dict(row) for row in db.execute_query(query)]
        
        # Service stats
        query = f"""
            SELECT service_name, COUNT(*) as connection_count
            FROM connections
            WHERE timestamp >= datetime('now', '-{time_hours} hours')
            GROUP BY service_name
            ORDER BY connection_count DESC
        """
        stats['service_stats'] = [dict(row) for row in db.execute_query(query)]
        
        # Top countries
        query = f"""
            SELECT country, COUNT(*) as attacker_count
            FROM attackers
            WHERE last_seen >= datetime('now', '-{time_hours} hours')
            AND country IS NOT NULL
            GROUP BY country
            ORDER BY attacker_count DESC
            LIMIT 5
        """
        stats['top_countries'] = [dict(row) for row in db.execute_query(query)]
        
        return stats


# Global report generator instance
report_generator = ReportGenerator()
