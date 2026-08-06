"""
Secure API Key Manager - Production-grade key management with encryption
"""

import os
import json
import logging
from pathlib import Path
from typing import Optional, Dict
from cryptography.fernet import Fernet
from datetime import datetime, timedelta

logger = logging.getLogger("honeypot.security.api_keys")


class APIKeyManager:
    """Secure API key management with encryption"""
    
    def __init__(self, key_file: str = "security/api_keys.enc",
                 master_key_file: str = "security/.master_key"):
        self.key_file = Path(key_file)
        self.master_key_file = Path(master_key_file)
        self.logger = logger
        
        # Create security directory
        self.key_file.parent.mkdir(exist_ok=True)
        
        # Load or create master key
        self.master_key = self._load_or_create_master_key()
        self.cipher = Fernet(self.master_key)
        
        # Load API keys
        self.api_keys: Dict[str, dict] = self._load_keys()
        
        # Usage tracking
        self.usage_stats = {}
    
    def _load_or_create_master_key(self) -> bytes:
        """Load master encryption key.

        Prefers API_KEY_ENCRYPTION_SECRET from the environment so the key
        never has to live on disk next to the ciphertext it protects. Falls
        back to a local file only for development convenience (the file is
        gitignored and should never be relied on outside a single machine).
        """
        env_key = os.getenv('API_KEY_ENCRYPTION_SECRET')
        if env_key:
            return env_key.encode('utf-8')

        if self.master_key_file.exists():
            with open(self.master_key_file, 'rb') as f:
                return f.read()

        # Generate new local-dev master key
        key = Fernet.generate_key()

        with open(self.master_key_file, 'wb') as f:
            f.write(key)

        # Set file permissions (Unix-like systems)
        try:
            os.chmod(self.master_key_file, 0o600)
        except OSError:
            pass

        self.logger.warning(f"No API_KEY_ENCRYPTION_SECRET set — generated a local dev key: {self.master_key_file}")
        self.logger.warning("Set API_KEY_ENCRYPTION_SECRET in your .env for anything beyond local development.")

        return key
    
    def _load_keys(self) -> Dict[str, dict]:
        """Load encrypted API keys"""
        if not self.key_file.exists():
            return {}
        
        try:
            with open(self.key_file, 'rb') as f:
                encrypted_data = f.read()
            
            # Decrypt
            decrypted_data = self.cipher.decrypt(encrypted_data)
            keys = json.loads(decrypted_data.decode('utf-8'))
            
            self.logger.info(f"Loaded {len(keys)} API keys")
            return keys
            
        except Exception as e:
            self.logger.error(f"Error loading API keys: {e}")
            return {}
    
    def _save_keys(self):
        """Save encrypted API keys"""
        try:
            # Convert to JSON
            json_data = json.dumps(self.api_keys, indent=2)
            
            # Encrypt
            encrypted_data = self.cipher.encrypt(json_data.encode('utf-8'))
            
            # Save
            with open(self.key_file, 'wb') as f:
                f.write(encrypted_data)
            
            # Set file permissions
            try:
                os.chmod(self.key_file, 0o600)
            except:
                pass
            
        except Exception as e:
            self.logger.error(f"Error saving API keys: {e}")
    
    def add_key(self, service: str, api_key: str, description: str = "",
                rate_limit: int = 1000, rate_period: str = "day") -> bool:
        """
        Add or update API key
        
        Args:
            service: Service name (e.g., 'abuseipdb', 'openai')
            api_key: The API key
            description: Optional description
            rate_limit: Number of requests allowed
            rate_period: Period (minute, hour, day, month)
        
        Returns:
            True if successful
        """
        try:
            self.api_keys[service] = {
                'key': api_key,
                'description': description,
                'added_at': datetime.now().isoformat(),
                'rate_limit': rate_limit,
                'rate_period': rate_period,
                'active': True,
                'usage_count': 0,
                'last_used': None
            }
            
            self._save_keys()
            self.logger.info(f"API key added for service: {service}")
            return True
            
        except Exception as e:
            self.logger.error(f"Error adding API key: {e}")
            return False
    
    def get_key(self, service: str) -> Optional[str]:
        """
        Get API key for service (with rate limit check)
        
        Args:
            service: Service name
        
        Returns:
            API key if available and within rate limits, None otherwise
        """
        key_data = self.api_keys.get(service)
        
        if not key_data:
            self.logger.warning(f"API key not found for: {service}")
            return None
        
        if not key_data.get('active', True):
            self.logger.warning(f"API key for {service} is inactive")
            return None
        
        # Check rate limit
        if not self._check_rate_limit(service):
            self.logger.warning(f"Rate limit exceeded for: {service}")
            return None
        
        # Update usage
        key_data['usage_count'] = key_data.get('usage_count', 0) + 1
        key_data['last_used'] = datetime.now().isoformat()
        self._save_keys()
        
        return key_data['key']
    
    def _check_rate_limit(self, service: str) -> bool:
        """Check if service is within rate limits"""
        key_data = self.api_keys.get(service)
        
        if not key_data:
            return False
        
        rate_limit = key_data.get('rate_limit', 1000)
        rate_period = key_data.get('rate_period', 'day')
        
        # Initialize usage stats
        if service not in self.usage_stats:
            self.usage_stats[service] = {
                'count': 0,
                'period_start': datetime.now()
            }
        
        stats = self.usage_stats[service]
        
        # Check if period has expired
        period_duration = {
            'minute': timedelta(minutes=1),
            'hour': timedelta(hours=1),
            'day': timedelta(days=1),
            'month': timedelta(days=30)
        }
        
        duration = period_duration.get(rate_period, timedelta(days=1))
        
        if datetime.now() - stats['period_start'] > duration:
            # Reset counter
            stats['count'] = 0
            stats['period_start'] = datetime.now()
        
        # Check limit
        if stats['count'] >= rate_limit:
            return False
        
        stats['count'] += 1
        return True
    
    def remove_key(self, service: str) -> bool:
        """Remove API key"""
        if service in self.api_keys:
            del self.api_keys[service]
            self._save_keys()
            self.logger.info(f"API key removed for: {service}")
            return True
        return False
    
    def deactivate_key(self, service: str) -> bool:
        """Deactivate API key without removing it"""
        if service in self.api_keys:
            self.api_keys[service]['active'] = False
            self._save_keys()
            self.logger.info(f"API key deactivated for: {service}")
            return True
        return False
    
    def activate_key(self, service: str) -> bool:
        """Activate API key"""
        if service in self.api_keys:
            self.api_keys[service]['active'] = True
            self._save_keys()
            self.logger.info(f"API key activated for: {service}")
            return True
        return False
    
    def list_keys(self) -> list:
        """List all services (without exposing keys)"""
        return [
            {
                'service': service,
                'description': data.get('description', ''),
                'active': data.get('active', True),
                'added_at': data.get('added_at'),
                'usage_count': data.get('usage_count', 0),
                'last_used': data.get('last_used'),
                'rate_limit': data.get('rate_limit'),
                'rate_period': data.get('rate_period')
            }
            for service, data in self.api_keys.items()
        ]
    
    def get_usage_stats(self, service: str = None) -> dict:
        """Get usage statistics"""
        if service:
            return self.usage_stats.get(service, {})
        return self.usage_stats
    
    def rotate_key(self, service: str, new_key: str) -> bool:
        """Rotate API key"""
        if service not in self.api_keys:
            return False
        
        old_key_data = self.api_keys[service].copy()
        old_key_data['key'] = new_key
        old_key_data['added_at'] = datetime.now().isoformat()
        old_key_data['usage_count'] = 0
        
        self.api_keys[service] = old_key_data
        self._save_keys()
        
        self.logger.info(f"API key rotated for: {service}")
        return True
    
    def import_from_env(self):
        """Import API keys from environment variables"""
        env_mappings = {
            'ABUSEIPDB_API_KEY': ('abuseipdb', 'AbuseIPDB API', 1000, 'day'),
            'OPENAI_API_KEY': ('openai', 'OpenAI API', 10000, 'day'),
        }
        
        imported = 0
        for env_var, (service, desc, limit, period) in env_mappings.items():
            key = os.getenv(env_var)
            if key and key != 'your_key_here':
                self.add_key(service, key, desc, limit, period)
                imported += 1
        
        if imported:
            self.logger.info(f"Imported {imported} API keys from environment")
        
        return imported


# Global API key manager instance
api_key_manager = APIKeyManager()
