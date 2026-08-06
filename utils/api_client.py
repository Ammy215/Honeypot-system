"""
API Client - Unified interface for external API calls with key management
"""

import logging
from typing import Optional, Dict, Any
import requests
from security.api_key_manager import api_key_manager
from security.audit_logger import audit_logger

logger = logging.getLogger("honeypot.utils.api_client")


class APIClient:
    """Centralized API client with key management and rate limiting"""
    
    def __init__(self):
        self.logger = logger
        self.session = requests.Session()
    
    def get_api_key(self, service: str) -> Optional[str]:
        """
        Get API key for service (with rate limiting)
        
        Args:
            service: Service name (abuseipdb, openai, otx, etc.)
        
        Returns:
            API key or None
        """
        key = api_key_manager.get_key(service)
        
        if key:
            audit_logger.log_api_key_usage(service, True)
        else:
            audit_logger.log_api_key_usage(service, False)
            self.logger.warning(f"Failed to get API key for: {service}")
        
        return key
    
    def make_request(self, service: str, url: str, method: str = "GET",
                    headers: Dict[str, str] = None, data: Dict[str, Any] = None,
                    params: Dict[str, Any] = None, timeout: int = 30) -> Optional[Dict]:
        """
        Make API request with automatic key injection
        
        Args:
            service: Service name
            url: API endpoint URL
            method: HTTP method (GET, POST, etc.)
            headers: Additional headers
            data: Request body
            params: URL parameters
            timeout: Request timeout in seconds
        
        Returns:
            Response JSON or None
        """
        # Get API key
        api_key = self.get_api_key(service)
        
        if not api_key:
            self.logger.error(f"No API key available for {service}")
            return None
        
        # Prepare headers
        request_headers = headers or {}
        
        # Add API key to headers based on service
        if service == "abuseipdb":
            request_headers["Key"] = api_key
            request_headers["Accept"] = "application/json"
        elif service == "openai":
            request_headers["Authorization"] = f"Bearer {api_key}"
            request_headers["Content-Type"] = "application/json"
        elif service == "otx":
            request_headers["X-OTX-API-KEY"] = api_key
        
        # Make request
        try:
            if method.upper() == "GET":
                response = self.session.get(
                    url,
                    headers=request_headers,
                    params=params,
                    timeout=timeout
                )
            elif method.upper() == "POST":
                response = self.session.post(
                    url,
                    headers=request_headers,
                    json=data,
                    params=params,
                    timeout=timeout
                )
            else:
                self.logger.error(f"Unsupported HTTP method: {method}")
                return None
            
            response.raise_for_status()
            
            return response.json()
            
        except requests.exceptions.Timeout:
            self.logger.error(f"Request timeout for {service}: {url}")
            return None
        except requests.exceptions.HTTPError as e:
            self.logger.error(f"HTTP error for {service}: {e}")
            return None
        except Exception as e:
            self.logger.error(f"Request error for {service}: {e}")
            return None
    
    def abuseipdb_check(self, ip_address: str) -> Optional[Dict]:
        """
        Check IP reputation on AbuseIPDB
        
        Args:
            ip_address: IP to check
        
        Returns:
            AbuseIPDB response data
        """
        url = "https://api.abuseipdb.com/api/v2/check"
        params = {
            "ipAddress": ip_address,
            "maxAgeInDays": 90,
            "verbose": ""
        }
        
        return self.make_request("abuseipdb", url, params=params)
    
    def openai_completion(self, model: str, messages: list,
                         temperature: float = 0.7, max_tokens: int = 1000) -> Optional[Dict]:
        """
        Make OpenAI API request
        
        Args:
            model: Model name (gpt-4o-mini, etc.)
            messages: List of message dicts
            temperature: Sampling temperature
            max_tokens: Max response tokens
        
        Returns:
            OpenAI response
        """
        url = "https://api.openai.com/v1/chat/completions"
        data = {
            "model": model,
            "messages": messages,
            "temperature": temperature,
            "max_tokens": max_tokens
        }
        
        return self.make_request("openai", url, method="POST", data=data)


# Global API client instance
api_client = APIClient()
