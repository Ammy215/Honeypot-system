"""
Audit Logger - Track all security-relevant actions
"""

import logging
import json
from datetime import datetime
from pathlib import Path
from typing import Optional, Dict, Any

logger = logging.getLogger("honeypot.security.audit")


class AuditLogger:
    """Audit logging for security events"""
    
    EVENT_TYPES = [
        'login_success', 'login_failure', 'logout',
        'user_created', 'user_deleted', 'user_modified',
        'password_changed', 'permission_denied',
        'data_exported', 'data_deleted',
        'config_changed', 'api_key_used', 'api_key_added', 'api_key_removed',
        'database_backup', 'database_restored',
        'session_expired', 'suspicious_activity'
    ]
    
    def __init__(self, log_file: str = "logs/audit.log",
                 json_file: str = "logs/audit.json"):
        self.log_file = Path(log_file)
        self.json_file = Path(json_file)
        self.logger = logger
        
        # Create logs directory
        self.log_file.parent.mkdir(exist_ok=True)
        
        # Setup file handler
        self._setup_file_handler()
    
    def _setup_file_handler(self):
        """Setup dedicated audit log file handler"""
        file_handler = logging.FileHandler(self.log_file)
        file_handler.setLevel(logging.INFO)
        
        formatter = logging.Formatter(
            '%(asctime)s | %(levelname)s | %(message)s',
            datefmt='%Y-%m-%d %H:%M:%S'
        )
        file_handler.setFormatter(formatter)
        
        self.logger.addHandler(file_handler)
        self.logger.setLevel(logging.INFO)
    
    def log_event(self, event_type: str, username: str = None,
                  ip_address: str = None, details: Dict[str, Any] = None,
                  severity: str = 'INFO'):
        """
        Log audit event
        
        Args:
            event_type: Type of event
            username: User who performed action
            ip_address: Source IP address
            details: Additional event details
            severity: INFO, WARNING, ERROR, CRITICAL
        """
        if event_type not in self.EVENT_TYPES:
            self.logger.warning(f"Unknown audit event type: {event_type}")
        
        # Create audit entry
        audit_entry = {
            'timestamp': datetime.now().isoformat(),
            'event_type': event_type,
            'username': username or 'system',
            'ip_address': ip_address or 'localhost',
            'details': details or {},
            'severity': severity
        }
        
        # Log to text file
        log_message = self._format_log_message(audit_entry)
        
        if severity == 'CRITICAL':
            self.logger.critical(log_message)
        elif severity == 'ERROR':
            self.logger.error(log_message)
        elif severity == 'WARNING':
            self.logger.warning(log_message)
        else:
            self.logger.info(log_message)
        
        # Save to JSON file for structured queries
        self._save_to_json(audit_entry)
    
    def _format_log_message(self, entry: dict) -> str:
        """Format audit entry for text log"""
        msg = f"[{entry['event_type']}] "
        msg += f"User: {entry['username']} | "
        msg += f"IP: {entry['ip_address']}"
        
        if entry['details']:
            details_str = ' | '.join(
                f"{k}: {v}" for k, v in entry['details'].items()
            )
            msg += f" | {details_str}"
        
        return msg
    
    def _save_to_json(self, entry: dict):
        """Save audit entry to JSON file for querying"""
        try:
            # Load existing entries
            if self.json_file.exists():
                with open(self.json_file, 'r') as f:
                    entries = json.load(f)
            else:
                entries = []
            
            # Append new entry
            entries.append(entry)
            
            # Keep only last 10,000 entries
            if len(entries) > 10000:
                entries = entries[-10000:]
            
            # Save
            with open(self.json_file, 'w') as f:
                json.dump(entries, f, indent=2)
                
        except Exception as e:
            self.logger.error(f"Error saving audit JSON: {e}")
    
    def query_events(self, event_type: str = None, username: str = None,
                    start_time: str = None, end_time: str = None,
                    limit: int = 100) -> list:
        """
        Query audit log
        
        Args:
            event_type: Filter by event type
            username: Filter by username
            start_time: Start timestamp (ISO format)
            end_time: End timestamp (ISO format)
            limit: Max results
        
        Returns:
            List of matching audit entries
        """
        if not self.json_file.exists():
            return []
        
        try:
            with open(self.json_file, 'r') as f:
                entries = json.load(f)
            
            # Filter
            filtered = entries
            
            if event_type:
                filtered = [e for e in filtered if e['event_type'] == event_type]
            
            if username:
                filtered = [e for e in filtered if e['username'] == username]
            
            if start_time:
                filtered = [e for e in filtered if e['timestamp'] >= start_time]
            
            if end_time:
                filtered = [e for e in filtered if e['timestamp'] <= end_time]
            
            # Sort by timestamp (newest first)
            filtered.sort(key=lambda x: x['timestamp'], reverse=True)
            
            # Limit
            return filtered[:limit]
            
        except Exception as e:
            self.logger.error(f"Error querying audit log: {e}")
            return []
    
    def get_user_activity(self, username: str, limit: int = 50) -> list:
        """Get activity log for specific user"""
        return self.query_events(username=username, limit=limit)
    
    def get_failed_logins(self, limit: int = 100) -> list:
        """Get failed login attempts"""
        return self.query_events(event_type='login_failure', limit=limit)
    
    def get_suspicious_activity(self, limit: int = 100) -> list:
        """Get suspicious activity events"""
        return self.query_events(event_type='suspicious_activity', limit=limit)
    
    # Convenience methods for common events
    
    def log_login_success(self, username: str, ip_address: str):
        self.log_event('login_success', username, ip_address)
    
    def log_login_failure(self, username: str, ip_address: str, reason: str = None):
        details = {'reason': reason} if reason else {}
        self.log_event('login_failure', username, ip_address, details, 'WARNING')
    
    def log_logout(self, username: str):
        self.log_event('logout', username)
    
    def log_permission_denied(self, username: str, resource: str, action: str):
        self.log_event('permission_denied', username, details={
            'resource': resource,
            'action': action
        }, severity='WARNING')
    
    def log_data_export(self, username: str, data_type: str, record_count: int):
        self.log_event('data_exported', username, details={
            'data_type': data_type,
            'record_count': record_count
        })
    
    def log_config_change(self, username: str, setting: str, old_value: Any, new_value: Any):
        self.log_event('config_changed', username, details={
            'setting': setting,
            'old_value': str(old_value),
            'new_value': str(new_value)
        })
    
    def log_api_key_usage(self, service: str, success: bool):
        self.log_event('api_key_used', details={
            'service': service,
            'success': success
        })
    
    def log_suspicious_activity(self, username: str, ip_address: str, description: str):
        self.log_event('suspicious_activity', username, ip_address, 
                      details={'description': description}, severity='CRITICAL')


# Global audit logger instance
audit_logger = AuditLogger()
