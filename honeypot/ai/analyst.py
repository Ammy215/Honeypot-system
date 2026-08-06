"""
AI Analyst - OpenAI-powered threat analysis and reporting
"""

import logging
import json
from datetime import datetime
from typing import Dict, List, Optional
import os

try:
    from openai import OpenAI
    OPENAI_AVAILABLE = True
except ImportError:
    OPENAI_AVAILABLE = False

from database.db import db
from config import OPENAI_API_KEY, OPENAI_MODEL

logger = logging.getLogger("honeypot.ai.analyst")


class AIAnalyst:
    """AI-powered threat analyst using OpenAI GPT"""
    
    def __init__(self):
        self.logger = logger
        self.client = None
        self.model = OPENAI_MODEL
        
        if OPENAI_AVAILABLE and OPENAI_API_KEY and OPENAI_API_KEY != "your_key_here":
            try:
                self.client = OpenAI(api_key=OPENAI_API_KEY)
                self.logger.info(f"AI Analyst initialized with model: {self.model}")
            except Exception as e:
                self.logger.warning(f"Failed to initialize OpenAI client: {e}")
                self.client = None
        else:
            self.logger.warning("OpenAI not available. Set OPENAI_API_KEY in .env file.")
    
    def is_available(self) -> bool:
        """Check if AI analyst is available"""
        return self.client is not None
    
    def analyze_attacker(self, ip_address: str) -> Optional[Dict]:
        """
        Generate AI-powered analysis of an attacker
        
        Args:
            ip_address: IP to analyze
        
        Returns:
            Dictionary with analysis results or None if unavailable
        """
        
        if not self.is_available():
            return None
        
        try:
            # Gather attacker data
            attacker_data = self._gather_attacker_data(ip_address)
            
            if not attacker_data:
                return None
            
            # Generate analysis
            analysis = self._generate_attacker_analysis(attacker_data)
            
            # Store in database
            self._store_analysis(ip_address, analysis, "attacker_profile")
            
            return analysis
        
        except Exception as e:
            self.logger.error(f"Error analyzing attacker {ip_address}: {e}")
            return None
    
    def generate_threat_report(self, time_hours: int = 24) -> Optional[Dict]:
        """
        Generate comprehensive threat report
        
        Args:
            time_hours: Time window in hours
        
        Returns:
            Dictionary with report data or None if unavailable
        """
        
        if not self.is_available():
            return None
        
        try:
            # Gather threat data
            threat_data = self._gather_threat_data(time_hours)
            
            # Generate report
            report = self._generate_threat_report(threat_data, time_hours)
            
            # Store in database
            self._store_analysis(None, report, "threat_report")
            
            return report
        
        except Exception as e:
            self.logger.error(f"Error generating threat report: {e}")
            return None
    
    def analyze_campaign(self, campaign: Dict) -> Optional[Dict]:
        """
        Analyze a detected campaign
        
        Args:
            campaign: Campaign data dictionary
        
        Returns:
            Analysis dictionary or None
        """
        
        if not self.is_available():
            return None
        
        try:
            # Generate campaign analysis
            analysis = self._generate_campaign_analysis(campaign)
            
            # Store in database
            self._store_analysis(None, analysis, "campaign_analysis")
            
            return analysis
        
        except Exception as e:
            self.logger.error(f"Error analyzing campaign: {e}")
            return None
    
    def summarize_alerts(self, alert_count: int = 10) -> Optional[str]:
        """
        Generate natural language summary of recent alerts
        
        Args:
            alert_count: Number of alerts to summarize
        
        Returns:
            Summary text or None
        """
        
        if not self.is_available():
            return None
        
        try:
            # Get recent alerts
            query = """
                SELECT 
                    a.alert_type,
                    a.severity,
                    a.description,
                    a.ip_address,
                    att.country,
                    a.timestamp
                FROM alerts a
                LEFT JOIN attackers att ON a.ip_address = att.ip_address
                ORDER BY a.timestamp DESC
                LIMIT ?
            """
            
            alerts = db.execute_query(query, (alert_count,))
            
            if not alerts:
                return "No recent alerts to summarize."
            
            # Format for AI
            alert_text = "\n".join([
                f"- {alert['severity']} [{alert['alert_type']}] from {alert['ip_address']} "
                f"({alert['country'] or 'Unknown'}): {alert['description']}"
                for alert in alerts
            ])
            
            # Generate summary
            prompt = f"""Summarize these security alerts in 2-3 sentences:

{alert_text}

Focus on the most critical threats and patterns."""
            
            response = self.client.chat.completions.create(
                model=self.model,
                messages=[
                    {"role": "system", "content": "You are a cybersecurity analyst. Provide concise, professional summaries."},
                    {"role": "user", "content": prompt}
                ],
                max_tokens=200,
                temperature=0.3
            )
            
            summary = response.choices[0].message.content.strip()
            
            self.logger.info(f"Generated alert summary: {len(summary)} chars")
            
            return summary
        
        except Exception as e:
            self.logger.error(f"Error summarizing alerts: {e}")
            return None
    
    def _gather_attacker_data(self, ip_address: str) -> Optional[Dict]:
        """Gather all data for an attacker"""
        
        # Get attacker profile
        query = "SELECT * FROM attackers WHERE ip_address = ?"
        results = db.execute_query(query, (ip_address,))
        
        if not results:
            return None
        
        attacker = dict(results[0])
        
        # Get login attempts
        query = """
            SELECT service_name, username, password_attempt, timestamp
            FROM login_attempts
            WHERE ip_address = ?
            ORDER BY timestamp DESC
            LIMIT 20
        """
        login_attempts = db.execute_query(query, (ip_address,))
        
        # Get alerts
        query = """
            SELECT alert_type, severity, description, timestamp
            FROM alerts
            WHERE ip_address = ?
            ORDER BY timestamp DESC
            LIMIT 10
        """
        alerts = db.execute_query(query, (ip_address,))
        
        # Get connections
        query = """
            SELECT service_name, destination_port, timestamp
            FROM connections
            WHERE ip_address = ?
            ORDER BY timestamp DESC
            LIMIT 20
        """
        connections = db.execute_query(query, (ip_address,))
        
        return {
            'attacker': attacker,
            'login_attempts': [dict(row) for row in login_attempts] if login_attempts else [],
            'alerts': [dict(row) for row in alerts] if alerts else [],
            'connections': [dict(row) for row in connections] if connections else []
        }
    
    def _gather_threat_data(self, time_hours: int) -> Dict:
        """Gather threat landscape data"""
        
        # Top attackers
        query = f"""
            SELECT ip_address, country, threat_score, verdict, 
                   total_connections, total_login_attempts
            FROM attackers
            WHERE last_seen >= datetime('now', '-{time_hours} hours')
            ORDER BY threat_score DESC
            LIMIT 10
        """
        top_attackers = db.execute_query(query)
        
        # Alert summary
        query = f"""
            SELECT severity, COUNT(*) as count
            FROM alerts
            WHERE timestamp >= datetime('now', '-{time_hours} hours')
            GROUP BY severity
        """
        alert_summary = db.execute_query(query)
        
        # Service statistics
        query = f"""
            SELECT service_name, COUNT(*) as connection_count
            FROM connections
            WHERE timestamp >= datetime('now', '-{time_hours} hours')
            GROUP BY service_name
        """
        service_stats = db.execute_query(query)
        
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
        top_countries = db.execute_query(query)
        
        # Common credentials
        query = f"""
            SELECT username, COUNT(DISTINCT ip_address) as ip_count
            FROM login_attempts
            WHERE timestamp >= datetime('now', '-{time_hours} hours')
            GROUP BY username
            ORDER BY ip_count DESC
            LIMIT 5
        """
        common_usernames = db.execute_query(query)
        
        return {
            'top_attackers': [dict(row) for row in top_attackers] if top_attackers else [],
            'alert_summary': [dict(row) for row in alert_summary] if alert_summary else [],
            'service_stats': [dict(row) for row in service_stats] if service_stats else [],
            'top_countries': [dict(row) for row in top_countries] if top_countries else [],
            'common_usernames': [dict(row) for row in common_usernames] if common_usernames else [],
            'time_window': time_hours
        }
    
    def _generate_attacker_analysis(self, data: Dict) -> Dict:
        """Generate AI analysis of attacker"""
        
        attacker = data['attacker']
        
        # Build context
        context = f"""Analyze this attacker profile:

IP: {attacker['ip_address']}
Country: {attacker.get('country', 'Unknown')}
ISP: {attacker.get('isp', 'Unknown')}
Threat Score: {attacker['threat_score']}/100
Verdict: {attacker['verdict']}
Total Connections: {attacker['total_connections']}
Total Login Attempts: {attacker['total_login_attempts']}
TOR Exit Node: {attacker.get('is_tor_exit', False)}
Known Bad IP: {attacker.get('is_known_bad', False)}

Recent Login Attempts ({len(data['login_attempts'])}):
"""
        
        for attempt in data['login_attempts'][:5]:
            context += f"- {attempt['service_name']}: {attempt['username']}/{attempt['password_attempt']}\n"
        
        context += f"\nRecent Alerts ({len(data['alerts'])}):\n"
        for alert in data['alerts'][:3]:
            context += f"- [{alert['severity']}] {alert['alert_type']}: {alert['description']}\n"
        
        # Generate analysis
        prompt = f"""{context}

Provide a concise threat assessment including:
1. Threat Level (1 sentence)
2. Attack Pattern (1-2 sentences)
3. Likely Motivation (1 sentence)
4. Recommended Action (1 sentence)

Be specific and professional."""
        
        try:
            response = self.client.chat.completions.create(
                model=self.model,
                messages=[
                    {"role": "system", "content": "You are an expert cybersecurity threat analyst. Provide clear, actionable analysis."},
                    {"role": "user", "content": prompt}
                ],
                max_tokens=500,
                temperature=0.3
            )
            
            analysis_text = response.choices[0].message.content.strip()
            
            return {
                'ip_address': attacker['ip_address'],
                'analysis_text': analysis_text,
                'timestamp': datetime.now().isoformat(),
                'model': self.model,
                'threat_score': attacker['threat_score'],
                'verdict': attacker['verdict']
            }
        
        except Exception as e:
            self.logger.error(f"Error calling OpenAI API: {e}")
            return {
                'ip_address': attacker['ip_address'],
                'analysis_text': f"Error generating AI analysis: {str(e)}",
                'timestamp': datetime.now().isoformat(),
                'error': True
            }
    
    def _generate_threat_report(self, data: Dict, time_hours: int) -> Dict:
        """Generate comprehensive threat report"""
        
        # Build context
        context = f"""Generate a threat intelligence report for the last {time_hours} hours:

TOP ATTACKERS:
"""
        
        for attacker in data['top_attackers'][:5]:
            context += f"- {attacker['ip_address']} ({attacker.get('country', 'Unknown')}): "
            context += f"Score {attacker['threat_score']}, {attacker['total_login_attempts']} attempts\n"
        
        context += "\nALERT SUMMARY:\n"
        for alert in data['alert_summary']:
            context += f"- {alert['severity']}: {alert['count']} alerts\n"
        
        context += "\nSERVICE ACTIVITY:\n"
        for service in data['service_stats']:
            context += f"- {service['service_name']}: {service['connection_count']} connections\n"
        
        context += "\nTOP COUNTRIES:\n"
        for country in data['top_countries']:
            context += f"- {country['country']}: {country['attacker_count']} attackers\n"
        
        prompt = f"""{context}

Generate a professional threat intelligence report with:
1. Executive Summary (2-3 sentences)
2. Key Findings (3-4 bullet points)
3. Threat Landscape Assessment (2-3 sentences)
4. Recommendations (2-3 bullet points)

Be concise and actionable."""
        
        try:
            response = self.client.chat.completions.create(
                model=self.model,
                messages=[
                    {"role": "system", "content": "You are a senior cybersecurity analyst creating professional threat reports."},
                    {"role": "user", "content": prompt}
                ],
                max_tokens=800,
                temperature=0.4
            )
            
            report_text = response.choices[0].message.content.strip()
            
            return {
                'report_text': report_text,
                'timestamp': datetime.now().isoformat(),
                'time_window': time_hours,
                'model': self.model,
                'statistics': {
                    'total_attackers': len(data['top_attackers']),
                    'total_alerts': sum(a['count'] for a in data['alert_summary']),
                    'services_hit': len(data['service_stats']),
                    'countries': len(data['top_countries'])
                }
            }
        
        except Exception as e:
            self.logger.error(f"Error generating threat report: {e}")
            return {
                'report_text': f"Error generating threat report: {str(e)}",
                'timestamp': datetime.now().isoformat(),
                'error': True
            }
    
    def _generate_campaign_analysis(self, campaign: Dict) -> Dict:
        """Generate AI analysis of attack campaign"""
        
        context = f"""Analyze this attack campaign:

Type: {campaign['type']}
Severity: {campaign.get('severity', 'MEDIUM')}
Attacker Count: {campaign.get('attacker_count', 'Unknown')}
Description: {campaign.get('description', 'No description')}

Provide a brief analysis (2-3 sentences) covering:
- What this campaign indicates
- Potential threat level
- Recommended response"""
        
        try:
            response = self.client.chat.completions.create(
                model=self.model,
                messages=[
                    {"role": "system", "content": "You are a cybersecurity analyst specializing in attack campaigns."},
                    {"role": "user", "content": context}
                ],
                max_tokens=300,
                temperature=0.3
            )
            
            analysis_text = response.choices[0].message.content.strip()
            
            return {
                'campaign_type': campaign['type'],
                'analysis_text': analysis_text,
                'timestamp': datetime.now().isoformat(),
                'severity': campaign.get('severity', 'MEDIUM')
            }
        
        except Exception as e:
            self.logger.error(f"Error analyzing campaign: {e}")
            return {
                'campaign_type': campaign['type'],
                'analysis_text': f"Error generating analysis: {str(e)}",
                'timestamp': datetime.now().isoformat(),
                'error': True
            }
    
    def _store_analysis(self, ip_address: Optional[str], analysis: Dict, report_type: str):
        """Store AI analysis in database"""
        
        try:
            query = """
                INSERT INTO ai_reports (
                    ip_address, report_type, report_data, 
                    timestamp, model_used
                ) VALUES (?, ?, ?, ?, ?)
            """
            
            db.execute_update(
                query,
                (
                    ip_address,
                    report_type,
                    json.dumps(analysis),
                    datetime.now().isoformat(),
                    self.model
                )
            )
            
            self.logger.info(f"Stored AI analysis: {report_type} for {ip_address or 'system'}")
        
        except Exception as e:
            self.logger.error(f"Error storing AI analysis: {e}")


# Global analyst instance
ai_analyst = AIAnalyst()
