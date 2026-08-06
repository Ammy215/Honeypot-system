import logging
from datetime import datetime
from typing import Dict, List, Optional
from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from database.db import db, get_or_create_attacker

logger = logging.getLogger("honeypot.alerting")
console = Console()


class AlertEngine:
    """Generates and manages security alerts"""
    
    def __init__(self):
        self.logger = logger
        self.console = console
    
    def generate_alert(self, alert_data: Dict) -> int:
        """
        Generate a new alert and store in database
        
        Args:
            alert_data: Dictionary containing:
                - alert_type: Type of alert
                - severity: LOW, MEDIUM, HIGH, CRITICAL
                - description: Human-readable description
                - ip_address: Source IP
                - Additional metadata fields
        
        Returns:
            Alert ID
        """
        
        # Get attacker ID
        attacker_id = get_or_create_attacker(alert_data['ip_address'])
        
        # Insert alert
        query = """
            INSERT INTO alerts
            (attacker_id, ip_address, alert_type, severity, description)
            VALUES (?, ?, ?, ?, ?)
        """
        
        alert_id = db.execute_update(
            query,
            (
                attacker_id,
                alert_data['ip_address'],
                alert_data['alert_type'],
                alert_data['severity'],
                alert_data['description']
            )
        )
        
        self.logger.info(
            f"Alert generated: {alert_data['alert_type']} - "
            f"{alert_data['severity']} - {alert_data['ip_address']}"
        )
        
        # Display alert to console
        self._display_alert(alert_data)
        
        # Log to alerts file
        self._log_to_file(alert_data)
        
        return alert_id
    
    def _display_alert(self, alert_data: Dict):
        """Display alert to console with Rich formatting"""
        
        severity = alert_data['severity']
        
        # Color based on severity
        severity_colors = {
            'LOW': 'cyan',
            'MEDIUM': 'yellow',
            'HIGH': 'orange1',
            'CRITICAL': 'red'
        }
        
        color = severity_colors.get(severity, 'white')
        
        # Create alert panel
        alert_text = f"""[bold]{alert_data['alert_type']}[/bold]
        
IP: {alert_data['ip_address']}
Severity: [{color}]{severity}[/{color}]
        
{alert_data['description']}"""
        
        # Add metadata if available
        metadata_lines = []
        for key, value in alert_data.items():
            if key not in ['alert_type', 'severity', 'description', 'ip_address']:
                metadata_lines.append(f"{key}: {value}")
        
        if metadata_lines:
            alert_text += "\n\n" + "\n".join(metadata_lines)
        
        panel = Panel(
            alert_text,
            title=f"🚨 SECURITY ALERT - {severity}",
            border_style=color,
            expand=False
        )
        
        self.console.print()
        self.console.print(panel)
        self.console.print()
    
    def _log_to_file(self, alert_data: Dict):
        """Log alert to dedicated alerts log file"""
        import config
        from pathlib import Path
        
        log_file = Path(config.LOG_DIR) / "alerts.log"
        
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        log_line = (
            f"{timestamp} | {alert_data['severity']} | {alert_data['alert_type']} | "
            f"{alert_data['ip_address']} | {alert_data['description']}\n"
        )
        
        try:
            with open(log_file, 'a', encoding='utf-8') as f:
                f.write(log_line)
        except Exception as e:
            self.logger.error(f"Failed to write to alerts.log: {e}")
    
    def get_alerts(self, ip_address: Optional[str] = None, 
                   severity: Optional[str] = None,
                   alert_type: Optional[str] = None,
                   limit: int = 100) -> List[Dict]:
        """Retrieve alerts with optional filters"""
        
        query = "SELECT * FROM alerts WHERE 1=1"
        params = []
        
        if ip_address:
            query += " AND ip_address = ?"
            params.append(ip_address)
        
        if severity:
            query += " AND severity = ?"
            params.append(severity)
        
        if alert_type:
            query += " AND alert_type = ?"
            params.append(alert_type)
        
        query += " ORDER BY timestamp DESC LIMIT ?"
        params.append(limit)
        
        results = db.execute_query(query, tuple(params))
        
        return [dict(row) for row in results]
    
    def get_unacknowledged_alerts(self, limit: int = 50) -> List[Dict]:
        """Get all unacknowledged alerts"""
        
        query = """
            SELECT * FROM alerts
            WHERE acknowledged = 0
            ORDER BY 
                CASE severity
                    WHEN 'CRITICAL' THEN 1
                    WHEN 'HIGH' THEN 2
                    WHEN 'MEDIUM' THEN 3
                    WHEN 'LOW' THEN 4
                END,
                timestamp DESC
            LIMIT ?
        """
        
        results = db.execute_query(query, (limit,))
        return [dict(row) for row in results]
    
    def acknowledge_alert(self, alert_id: int) -> bool:
        """Mark an alert as acknowledged"""
        
        query = """
            UPDATE alerts
            SET acknowledged = 1,
                acknowledged_at = CURRENT_TIMESTAMP
            WHERE id = ?
        """
        
        rows_affected = db.execute_update(query, (alert_id,))
        
        if rows_affected > 0:
            self.logger.info(f"Alert {alert_id} acknowledged")
            return True
        
        return False
    
    def get_alert_summary(self) -> Dict:
        """Get summary statistics of alerts"""
        
        query = """
            SELECT 
                severity,
                COUNT(*) as count,
                SUM(CASE WHEN acknowledged = 0 THEN 1 ELSE 0 END) as unacknowledged
            FROM alerts
            GROUP BY severity
        """
        
        results = db.execute_query(query)
        
        summary = {
            'total': 0,
            'total_unacknowledged': 0,
            'by_severity': {}
        }
        
        for row in results:
            severity = row['severity']
            count = row['count']
            unack = row['unacknowledged']
            
            summary['total'] += count
            summary['total_unacknowledged'] += unack
            summary['by_severity'][severity] = {
                'count': count,
                'unacknowledged': unack
            }
        
        return summary
    
    def display_alert_summary(self):
        """Display alert summary table to console"""
        
        summary = self.get_alert_summary()
        
        table = Table(title="Alert Summary")
        table.add_column("Severity", style="cyan", justify="left")
        table.add_column("Total", justify="right")
        table.add_column("Unacknowledged", style="red", justify="right")
        
        severity_order = ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW']
        
        for severity in severity_order:
            if severity in summary['by_severity']:
                data = summary['by_severity'][severity]
                table.add_row(
                    severity,
                    str(data['count']),
                    str(data['unacknowledged'])
                )
        
        table.add_row(
            "[bold]TOTAL[/bold]",
            f"[bold]{summary['total']}[/bold]",
            f"[bold red]{summary['total_unacknowledged']}[/bold red]"
        )
        
        self.console.print()
        self.console.print(table)
        self.console.print()


# Global alert engine instance
alert_engine = AlertEngine()
