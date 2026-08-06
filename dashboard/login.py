"""
Login page for HoneyShield Dashboard
"""

import streamlit as st
import sys
from pathlib import Path

# Add parent directory to path
sys.path.insert(0, str(Path(__file__).parent.parent))

from auth.auth_manager import auth_manager
from security.audit_logger import audit_logger
import config


def show_login_page():
    """Display login page"""
    st.set_page_config(
        page_title="HoneyShield Login",
        page_icon="🔐",
        layout="centered"
    )
    
    # Custom CSS for login page
    st.markdown("""
    <style>
        .login-header {
            font-size: 3rem;
            font-weight: bold;
            text-align: center;
            padding: 2rem;
            background: linear-gradient(90deg, #667eea 0%, #764ba2 100%);
            -webkit-background-clip: text;
            -webkit-text-fill-color: transparent;
        }
        .login-container {
            background-color: #ffffff;
            padding: 2rem;
            border-radius: 1rem;
            box-shadow: 0 4px 6px rgba(0,0,0,0.1);
        }
        .stTextInput > div > div > input {
            border-radius: 0.5rem;
        }
        .stButton > button {
            width: 100%;
            border-radius: 0.5rem;
            background: linear-gradient(90deg, #667eea 0%, #764ba2 100%);
            color: white;
            font-weight: bold;
        }
    </style>
    """, unsafe_allow_html=True)
    
    # Header
    st.markdown('<h1 class="login-header">🔐 HoneyShield Login</h1>', unsafe_allow_html=True)
    
    # Check if default credentials file exists
    default_creds_file = Path("auth/default_credentials.txt")
    if default_creds_file.exists():
        st.warning("⚠️ Default credentials detected! Please login and change your password immediately.")
        with st.expander("View Default Credentials"):
            with open(default_creds_file, 'r') as f:
                st.code(f.read())
    
    # Login form
    st.markdown("### Please Login")
    
    with st.form("login_form"):
        username = st.text_input("Username", placeholder="Enter your username")
        password = st.text_input("Password", type="password", placeholder="Enter your password")
        
        col1, col2 = st.columns(2)
        with col1:
            submit = st.form_submit_button("🔓 Login", use_container_width=True)
        with col2:
            if st.form_submit_button("❓ Help", use_container_width=True):
                st.info("""
                **Need Help?**
                
                - Default admin credentials are created on first run
                - Check `auth/default_credentials.txt` for default password
                - Contact your administrator if you forgot your password
                """)
    
    if submit:
        if not username or not password:
            st.error("❌ Please enter both username and password")
            return
        
        # Get client IP (Streamlit doesn't expose this easily, use placeholder)
        ip_address = "dashboard_user"
        
        # Attempt authentication
        token = auth_manager.authenticate(username, password, ip_address)
        
        if token:
            # Success!
            st.session_state.auth_token = token
            st.session_state.username = username
            st.session_state.authenticated = True
            
            # Get user info
            user = auth_manager.validate_session(token)
            if user:
                st.session_state.user_role = user.role
            
            # Log successful login
            audit_logger.log_login_success(username, ip_address)
            
            st.success(f"✅ Welcome back, {username}!")
            st.balloons()
            
            # Rerun to show dashboard
            st.rerun()
        else:
            # Failed login
            audit_logger.log_login_failure(username, ip_address, "Invalid credentials")
            st.error("❌ Invalid username or password")
    
    # Footer
    st.markdown("---")
    st.caption("🍯 HoneyShield Intelligence Platform | Secure Access Portal")


def check_authentication():
    """
    Check if user is authenticated
    
    Returns:
        bool: True if authenticated, False otherwise
    """
    # Check if authentication is disabled in config
    if not config.ENABLE_AUTHENTICATION:
        st.session_state.authenticated = True
        st.session_state.username = "admin"
        st.session_state.user_role = "admin"
        st.session_state.auth_token = "bypass"
        return True
    
    # Check if session variables exist
    if 'authenticated' not in st.session_state:
        st.session_state.authenticated = False
    
    if 'auth_token' not in st.session_state:
        st.session_state.auth_token = None
    
    # If not authenticated, return False
    if not st.session_state.authenticated or not st.session_state.auth_token:
        return False
    
    # Validate token
    user = auth_manager.validate_session(st.session_state.auth_token)
    
    if not user:
        # Token expired or invalid
        st.session_state.authenticated = False
        st.session_state.auth_token = None
        return False
    
    # Update user info
    st.session_state.username = user.username
    st.session_state.user_role = user.role
    
    return True


def logout():
    """Logout current user"""
    if 'auth_token' in st.session_state and st.session_state.auth_token:
        # Log logout
        audit_logger.log_logout(st.session_state.username)
        
        # Destroy session
        auth_manager.logout(st.session_state.auth_token)
    
    # Clear session state
    st.session_state.authenticated = False
    st.session_state.auth_token = None
    st.session_state.username = None
    st.session_state.user_role = None
    
    st.rerun()


def require_permission(permission: str):
    """
    Check if current user has permission
    
    Args:
        permission: Permission to check
    
    Returns:
        bool: True if user has permission
    """
    if not config.ENABLE_AUTHENTICATION:
        return True
    
    if 'auth_token' not in st.session_state:
        return False
    
    return auth_manager.has_permission(st.session_state.auth_token, permission)


def show_user_info():
    """Display current user info in sidebar"""
    if not config.ENABLE_AUTHENTICATION:
        st.sidebar.info("🔓 Authentication Disabled")
        return
    
    if 'username' in st.session_state and st.session_state.username:
        st.sidebar.markdown("---")
        st.sidebar.markdown(f"**👤 User:** {st.session_state.username}")
        st.sidebar.markdown(f"**🎭 Role:** {st.session_state.user_role}")
        
        if st.sidebar.button("🚪 Logout", use_container_width=True):
            logout()


# Main execution for standalone testing
if __name__ == "__main__":
    if not check_authentication():
        show_login_page()
    else:
        st.success(f"✅ Authenticated as: {st.session_state.username}")
        st.info(f"Role: {st.session_state.user_role}")
        
        if st.button("Logout"):
            logout()
