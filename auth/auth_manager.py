"""
Authentication Manager - Production-grade authentication system
"""

import hashlib
import secrets
import json
import logging
from datetime import datetime, timedelta
from typing import Optional, Dict, List
from pathlib import Path

logger = logging.getLogger("honeypot.auth")


class User:
    """User model"""
    
    def __init__(self, username: str, password_hash: str, role: str, 
                 email: str = "", created_at: str = None, last_login: str = None,
                 active: bool = True, two_factor_enabled: bool = False):
        self.username = username
        self.password_hash = password_hash
        self.role = role  # admin, analyst, viewer
        self.email = email
        self.created_at = created_at or datetime.now().isoformat()
        self.last_login = last_login
        self.active = active
        self.two_factor_enabled = two_factor_enabled
    
    def to_dict(self) -> dict:
        return {
            'username': self.username,
            'password_hash': self.password_hash,
            'role': self.role,
            'email': self.email,
            'created_at': self.created_at,
            'last_login': self.last_login,
            'active': self.active,
            'two_factor_enabled': self.two_factor_enabled
        }
    
    @classmethod
    def from_dict(cls, data: dict):
        return cls(**data)


class Session:
    """Session model"""
    
    def __init__(self, token: str, username: str, created_at: str = None,
                 expires_at: str = None, ip_address: str = None):
        self.token = token
        self.username = username
        self.created_at = created_at or datetime.now().isoformat()
        self.expires_at = expires_at or (datetime.now() + timedelta(hours=8)).isoformat()
        self.ip_address = ip_address
    
    def is_expired(self) -> bool:
        return datetime.fromisoformat(self.expires_at) < datetime.now()
    
    def to_dict(self) -> dict:
        return {
            'token': self.token,
            'username': self.username,
            'created_at': self.created_at,
            'expires_at': self.expires_at,
            'ip_address': self.ip_address
        }
    
    @classmethod
    def from_dict(cls, data: dict):
        return cls(**data)


class AuthManager:
    """Production-grade authentication manager"""
    
    ROLES = ['admin', 'analyst', 'viewer']
    
    PERMISSIONS = {
        'admin': [
            'view_dashboard', 'view_data', 'export_data', 'modify_settings',
            'manage_users', 'delete_data', 'view_api_keys', 'run_reports'
        ],
        'analyst': [
            'view_dashboard', 'view_data', 'export_data', 'run_reports'
        ],
        'viewer': [
            'view_dashboard', 'view_data'
        ]
    }
    
    def __init__(self, auth_file: str = "auth/users.json", 
                 session_file: str = "auth/sessions.json"):
        self.auth_file = Path(auth_file)
        self.session_file = Path(session_file)
        self.logger = logger
        
        # Create auth directory
        self.auth_file.parent.mkdir(exist_ok=True)
        
        # Load or create users
        self.users: Dict[str, User] = self._load_users()
        self.sessions: Dict[str, Session] = self._load_sessions()
        
        # Create default admin if no users exist
        if not self.users:
            self._create_default_admin()
    
    def _load_users(self) -> Dict[str, User]:
        """Load users from file"""
        if not self.auth_file.exists():
            return {}
        
        try:
            with open(self.auth_file, 'r') as f:
                data = json.load(f)
                return {
                    username: User.from_dict(user_data)
                    for username, user_data in data.items()
                }
        except Exception as e:
            self.logger.error(f"Error loading users: {e}")
            return {}
    
    def _save_users(self):
        """Save users to file"""
        try:
            with open(self.auth_file, 'w') as f:
                json.dump(
                    {username: user.to_dict() for username, user in self.users.items()},
                    f,
                    indent=2
                )
        except Exception as e:
            self.logger.error(f"Error saving users: {e}")
    
    def _load_sessions(self) -> Dict[str, Session]:
        """Load sessions from file"""
        if not self.session_file.exists():
            return {}
        
        try:
            with open(self.session_file, 'r') as f:
                data = json.load(f)
                sessions = {
                    token: Session.from_dict(session_data)
                    for token, session_data in data.items()
                }
                
                # Remove expired sessions
                active_sessions = {
                    token: session for token, session in sessions.items()
                    if not session.is_expired()
                }
                
                return active_sessions
        except Exception as e:
            self.logger.error(f"Error loading sessions: {e}")
            return {}
    
    def _save_sessions(self):
        """Save sessions to file"""
        try:
            with open(self.session_file, 'w') as f:
                json.dump(
                    {token: session.to_dict() for token, session in self.sessions.items()},
                    f,
                    indent=2
                )
        except Exception as e:
            self.logger.error(f"Error saving sessions: {e}")
    
    def _create_default_admin(self):
        """Create default admin user"""
        default_password = secrets.token_urlsafe(16)
        
        self.create_user(
            username='admin',
            password=default_password,
            role='admin',
            email='admin@honeypot.local'
        )
        
        # Save default password to file for first login
        default_creds_file = self.auth_file.parent / 'default_credentials.txt'
        with open(default_creds_file, 'w', encoding='utf-8') as f:
            f.write(f"Default Admin Credentials\n")
            f.write(f"=" * 50 + "\n")
            f.write(f"Username: admin\n")
            f.write(f"Password: {default_password}\n")
            f.write(f"\n")
            f.write(f"WARNING: CHANGE THIS PASSWORD IMMEDIATELY AFTER FIRST LOGIN!\n")
            f.write(f"=" * 50 + "\n")
        
        self.logger.warning(f"Created default admin user. Credentials saved to {default_creds_file}")
    
    @staticmethod
    def hash_password(password: str, salt: str = None) -> tuple:
        """Hash password with salt"""
        if salt is None:
            salt = secrets.token_hex(32)
        
        # Use SHA-256 with salt (in production, use bcrypt or argon2)
        password_hash = hashlib.pbkdf2_hmac(
            'sha256',
            password.encode('utf-8'),
            salt.encode('utf-8'),
            100000  # iterations
        ).hex()
        
        return f"{salt}${password_hash}", salt
    
    @staticmethod
    def verify_password(password: str, stored_hash: str) -> bool:
        """Verify password against stored hash"""
        try:
            salt, password_hash = stored_hash.split('$')
            new_hash, _ = AuthManager.hash_password(password, salt)
            return new_hash == stored_hash
        except:
            return False
    
    def create_user(self, username: str, password: str, role: str,
                   email: str = "") -> bool:
        """Create new user"""
        if username in self.users:
            self.logger.warning(f"User {username} already exists")
            return False
        
        if role not in self.ROLES:
            self.logger.error(f"Invalid role: {role}")
            return False
        
        password_hash, _ = self.hash_password(password)
        
        user = User(
            username=username,
            password_hash=password_hash,
            role=role,
            email=email
        )
        
        self.users[username] = user
        self._save_users()
        
        self.logger.info(f"Created user: {username} with role: {role}")
        return True
    
    def authenticate(self, username: str, password: str, ip_address: str = None) -> Optional[str]:
        """Authenticate user and create session"""
        user = self.users.get(username)
        
        if not user:
            self.logger.warning(f"Authentication failed: user {username} not found")
            return None
        
        if not user.active:
            self.logger.warning(f"Authentication failed: user {username} is inactive")
            return None
        
        if not self.verify_password(password, user.password_hash):
            self.logger.warning(f"Authentication failed: invalid password for {username}")
            return None
        
        # Create session
        token = secrets.token_urlsafe(32)
        session = Session(
            token=token,
            username=username,
            ip_address=ip_address
        )
        
        self.sessions[token] = session
        self._save_sessions()
        
        # Update last login
        user.last_login = datetime.now().isoformat()
        self._save_users()
        
        self.logger.info(f"User {username} authenticated successfully from {ip_address}")
        return token
    
    def validate_session(self, token: str) -> Optional[User]:
        """Validate session token"""
        session = self.sessions.get(token)
        
        if not session:
            return None
        
        if session.is_expired():
            self.logout(token)
            return None
        
        user = self.users.get(session.username)
        if not user or not user.active:
            self.logout(token)
            return None
        
        return user
    
    def logout(self, token: str):
        """Logout user and destroy session"""
        if token in self.sessions:
            username = self.sessions[token].username
            del self.sessions[token]
            self._save_sessions()
            self.logger.info(f"User {username} logged out")
    
    def has_permission(self, token: str, permission: str) -> bool:
        """Check if user has specific permission"""
        user = self.validate_session(token)
        if not user:
            return False
        
        return permission in self.PERMISSIONS.get(user.role, [])
    
    def change_password(self, username: str, old_password: str, new_password: str) -> bool:
        """Change user password"""
        user = self.users.get(username)
        
        if not user:
            return False
        
        if not self.verify_password(old_password, user.password_hash):
            self.logger.warning(f"Password change failed: invalid old password for {username}")
            return False
        
        password_hash, _ = self.hash_password(new_password)
        user.password_hash = password_hash
        self._save_users()
        
        self.logger.info(f"Password changed for user: {username}")
        return True
    
    def update_user(self, username: str, **kwargs) -> bool:
        """Update user attributes"""
        user = self.users.get(username)
        
        if not user:
            return False
        
        for key, value in kwargs.items():
            if hasattr(user, key):
                setattr(user, key, value)
        
        self._save_users()
        self.logger.info(f"Updated user: {username}")
        return True
    
    def delete_user(self, username: str) -> bool:
        """Delete user"""
        if username not in self.users:
            return False
        
        # Don't allow deleting the last admin
        if self.users[username].role == 'admin':
            admin_count = sum(1 for u in self.users.values() if u.role == 'admin' and u.active)
            if admin_count <= 1:
                self.logger.error("Cannot delete last admin user")
                return False
        
        del self.users[username]
        self._save_users()
        
        self.logger.info(f"Deleted user: {username}")
        return True
    
    def list_users(self) -> List[Dict]:
        """List all users (without password hashes)"""
        return [
            {
                'username': user.username,
                'role': user.role,
                'email': user.email,
                'created_at': user.created_at,
                'last_login': user.last_login,
                'active': user.active
            }
            for user in self.users.values()
        ]
    
    def get_active_sessions(self) -> List[Dict]:
        """Get all active sessions"""
        return [
            {
                'username': session.username,
                'created_at': session.created_at,
                'expires_at': session.expires_at,
                'ip_address': session.ip_address
            }
            for session in self.sessions.values()
            if not session.is_expired()
        ]
    
    def cleanup_expired_sessions(self):
        """Remove expired sessions"""
        expired = [
            token for token, session in self.sessions.items()
            if session.is_expired()
        ]
        
        for token in expired:
            del self.sessions[token]
        
        if expired:
            self._save_sessions()
            self.logger.info(f"Cleaned up {len(expired)} expired sessions")


# Global auth manager instance
auth_manager = AuthManager()
