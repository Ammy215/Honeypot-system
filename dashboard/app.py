"""
HoneyShield Intelligence Platform - Main Dashboard
Multi-page Streamlit application with authentication
"""

import streamlit as st
from pathlib import Path
import sys

# Add parent directory to path
sys.path.insert(0, str(Path(__file__).parent.parent))

# Import authentication
from dashboard.login import check_authentication, show_login_page, show_user_info
import config

# Page configuration
st.set_page_config(
    page_title="HoneyShield Intelligence Platform",
    page_icon="🍯",
    layout="wide",
    initial_sidebar_state="expanded"
)

# Check authentication
if not check_authentication():
    show_login_page()
    st.stop()

# Custom CSS
st.markdown("""
<style>
    .main-header {
        font-size: 2.5rem;
        font-weight: bold;
        color: #1f77b4;
        text-align: center;
        padding: 1rem;
        background: linear-gradient(90deg, #667eea 0%, #764ba2 100%);
        -webkit-background-clip: text;
        -webkit-text-fill-color: transparent;
    }
    .metric-card {
        background-color: #f0f2f6;
        padding: 1rem;
        border-radius: 0.5rem;
        border-left: 4px solid #1f77b4;
    }
    .stMetric {
        background-color: #ffffff;
        padding: 1rem;
        border-radius: 0.5rem;
        box-shadow: 0 2px 4px rgba(0,0,0,0.1);
    }
</style>
""", unsafe_allow_html=True)

# Main header
st.markdown('<h1 class="main-header">🍯 HoneyShield Intelligence Platform 🛡️</h1>', unsafe_allow_html=True)

# Sidebar
with st.sidebar:
    st.image("https://img.icons8.com/emoji/96/000000/honeypot-emoji.png", width=80)
    st.title("Navigation")
    
    # Show user info
    show_user_info()
    
    st.markdown("---")
    
    st.markdown("""
    ### 📊 Dashboard Pages
    
    Use the navigation above to explore:
    
    - **🔴 Live Feed** - Real-time attacks
    - **🌍 Attacker Intel** - Profiles & geo data
    - **📈 Analytics** - Charts & trends
    - **🚨 Alerts** - Security alerts
    - **🔍 Threat Hunting** - IOC search
    - **🤖 AI Analyst** - AI-powered analysis
    """)
    
    st.markdown("---")
    
    # System status
    st.markdown("### 🟢 System Status")
    
    try:
        # Use production database if enabled
        if config.USE_PRODUCTION_DB:
            from database.db_production import db_production as db
        else:
            from database.db import db
        
        # Get counts
        query = "SELECT COUNT(*) as cnt FROM attackers"
        result = db.execute_query(query)
        attacker_count = result[0]['cnt'] if result else 0
        
        query = "SELECT COUNT(*) as cnt FROM connections"
        result = db.execute_query(query)
        connection_count = result[0]['cnt'] if result else 0
        
        query = "SELECT COUNT(*) as cnt FROM alerts WHERE acknowledged = 0"
        result = db.execute_query(query)
        alert_count = result[0]['cnt'] if result else 0
        
        st.metric("Attackers", attacker_count)
        st.metric("Connections", connection_count)
        st.metric("Active Alerts", alert_count, delta=None)
        
    except Exception as e:
        st.error(f"Database error: {e}")
    
    st.markdown("---")
    st.caption("HoneyShield v2.0 | Phase 4")

# Main content
st.info("👈 **Select a page from the sidebar to get started!**")

# Overview cards
col1, col2, col3, col4 = st.columns(4)

try:
    # Use production database if enabled
    if config.USE_PRODUCTION_DB:
        from database.db_production import db_production as db
    else:
        from database.db import db
    
    # Total attackers
    query = "SELECT COUNT(*) as cnt FROM attackers"
    result = db.execute_query(query)
    total_attackers = result[0]['cnt'] if result else 0
    
    # Total connections
    query = "SELECT COUNT(*) as cnt FROM connections"
    result = db.execute_query(query)
    total_connections = result[0]['cnt'] if result else 0
    
    # Total login attempts
    query = "SELECT COUNT(*) as cnt FROM login_attempts"
    result = db.execute_query(query)
    total_logins = result[0]['cnt'] if result else 0
    
    # Critical attackers
    query = "SELECT COUNT(*) as cnt FROM attackers WHERE verdict = 'CRITICAL'"
    result = db.execute_query(query)
    critical_count = result[0]['cnt'] if result else 0
    
    with col1:
        st.metric(
            label="👤 Total Attackers",
            value=total_attackers,
            delta=None
        )
    
    with col2:
        st.metric(
            label="🔌 Total Connections",
            value=total_connections,
            delta=None
        )
    
    with col3:
        st.metric(
            label="🔐 Login Attempts",
            value=total_logins,
            delta=None
        )
    
    with col4:
        st.metric(
            label="⚠️ Critical Threats",
            value=critical_count,
            delta=None,
            delta_color="inverse"
        )

except Exception as e:
    st.error(f"Error loading overview: {e}")

st.markdown("---")

# Quick stats
st.subheader("📊 Quick Statistics")

col1, col2 = st.columns(2)

with col1:
    st.markdown("### 🌍 Top Countries")
    try:
        query = """
            SELECT country, COUNT(*) as count
            FROM attackers
            WHERE country IS NOT NULL
            GROUP BY country
            ORDER BY count DESC
            LIMIT 5
        """
        results = db.execute_query(query)
        
        if results:
            for i, row in enumerate(results, 1):
                st.write(f"{i}. {row['country']}: **{row['count']}** attackers")
        else:
            st.info("No geolocation data yet")
    except Exception as e:
        st.error(f"Error: {e}")

with col2:
    st.markdown("### 🎯 Top Services Targeted")
    try:
        query = """
            SELECT service_name, COUNT(*) as count
            FROM connections
            GROUP BY service_name
            ORDER BY count DESC
            LIMIT 5
        """
        results = db.execute_query(query)
        
        if results:
            for i, row in enumerate(results, 1):
                st.write(f"{i}. {row['service_name']}: **{row['count']}** connections")
        else:
            st.info("No connection data yet")
    except Exception as e:
        st.error(f"Error: {e}")

st.markdown("---")

# Instructions
with st.expander("ℹ️ Getting Started"):
    st.markdown("""
    ### Welcome to HoneyShield! 🍯
    
    This dashboard provides real-time visibility into honeypot activity and threat intelligence.
    
    #### Dashboard Pages:
    
    1. **🔴 Live Feed** - Watch attacks as they happen in real-time
    2. **🌍 Attacker Intel** - Detailed profiles with geolocation and reputation data
    3. **📈 Analytics** - Visual analysis of attack patterns and trends
    4. **🚨 Alerts** - Manage security alerts and investigate threats
    5. **🔍 Threat Hunting** - Search IOCs and correlate attacks
    6. **🤖 AI Analyst** - AI-powered threat analysis and reports
    
    #### Quick Actions:
    
    - 🔄 Pages auto-refresh to show latest data
    - 📊 Interactive charts are clickable and zoomable
    - 🗺️ World map shows attack origins
    - 🔍 Click on any IP to see detailed profile
    - 📥 Export data as CSV from most pages
    
    #### Tips:
    
    - Use filters to narrow down data
    - Sort tables by clicking column headers
    - Hover over charts for detailed information
    - Check the sidebar for system status
    
    **Ready to explore? Select a page from the sidebar!** 👈
    """)

st.markdown("---")
st.caption("Built with ❤️ using Python, Streamlit, and Plotly | HoneyShield Intelligence Platform")
