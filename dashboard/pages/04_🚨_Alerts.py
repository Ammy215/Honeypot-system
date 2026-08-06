"""
Alerts - Security alert management
"""

import streamlit as st
import pandas as pd
from datetime import datetime
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent.parent))

from database.db import db
from dashboard.login import check_authentication, show_login_page, show_user_info

st.set_page_config(page_title="Alerts", page_icon="🚨", layout="wide")

# Check authentication
if not check_authentication():
    show_login_page()
    st.stop()

# Show user info in sidebar
show_user_info()

st.title("🚨 Security Alerts")
st.markdown("Manage and investigate security alerts")

# Filters
st.sidebar.markdown("### 🎛️ Filters")

severity_filter = st.sidebar.multiselect(
    "Severity",
    ["CRITICAL", "HIGH", "MEDIUM", "LOW"],
    default=["CRITICAL", "HIGH"]
)

ack_filter = st.sidebar.radio(
    "Status",
    ["All", "Unacknowledged", "Acknowledged"]
)

# Summary cards
col1, col2, col3, col4 = st.columns(4)

try:
    # Total alerts
    query = "SELECT COUNT(*) as cnt FROM alerts"
    result = db.execute_query(query)
    total = result[0]['cnt'] if result else 0
    
    # Unacknowledged
    query = "SELECT COUNT(*) as cnt FROM alerts WHERE acknowledged = 0"
    result = db.execute_query(query)
    unack = result[0]['cnt'] if result else 0
    
    # Critical
    query = "SELECT COUNT(*) as cnt FROM alerts WHERE severity = 'CRITICAL' AND acknowledged = 0"
    result = db.execute_query(query)
    critical = result[0]['cnt'] if result else 0
    
    # High
    query = "SELECT COUNT(*) as cnt FROM alerts WHERE severity = 'HIGH' AND acknowledged = 0"
    result = db.execute_query(query)
    high = result[0]['cnt'] if result else 0
    
    with col1:
        st.metric("Total Alerts", total)
    
    with col2:
        st.metric("Unacknowledged", unack, delta=None)
    
    with col3:
        st.metric("🔴 Critical", critical, delta_color="inverse")
    
    with col4:
        st.metric("🟠 High", high, delta_color="inverse")

except Exception as e:
    st.error(f"Error: {e}")

st.markdown("---")

# Alert list
st.subheader("📋 Alert List")

try:
    # Build query
    severity_clause = ""
    if severity_filter:
        sev_str = "','".join(severity_filter)
        severity_clause = f"AND severity IN ('{sev_str}')"
    
    ack_clause = ""
    if ack_filter == "Unacknowledged":
        ack_clause = "AND acknowledged = 0"
    elif ack_filter == "Acknowledged":
        ack_clause = "AND acknowledged = 1"
    
    query = f"""
        SELECT 
            id,
            timestamp,
            ip_address,
            alert_type,
            severity,
            description,
            acknowledged
        FROM alerts
        WHERE 1=1 {severity_clause} {ack_clause}
        ORDER BY timestamp DESC
        LIMIT 100
    """
    
    results = db.execute_query(query)
    
    if results:
        for alert in results:
            severity = alert['severity']
            
            # Color based on severity
            if severity == 'CRITICAL':
                st.error(f"""
                **[{severity}] {alert['alert_type']}**
                
                IP: `{alert['ip_address']}` | {alert['timestamp']}
                
                {alert['description']}
                
                {'✓ Acknowledged' if alert['acknowledged'] else '⚠️ Unacknowledged'}
                """)
            elif severity == 'HIGH':
                st.warning(f"""
                **[{severity}] {alert['alert_type']}**
                
                IP: `{alert['ip_address']}` | {alert['timestamp']}
                
                {alert['description']}
                
                {'✓ Acknowledged' if alert['acknowledged'] else '⚠️ Unacknowledged'}
                """)
            elif severity == 'MEDIUM':
                st.info(f"""
                **[{severity}] {alert['alert_type']}**
                
                IP: `{alert['ip_address']}` | {alert['timestamp']}
                
                {alert['description']}
                
                {'✓ Acknowledged' if alert['acknowledged'] else '⚠️ Unacknowledged'}
                """)
            else:
                st.success(f"""
                **[{severity}] {alert['alert_type']}**
                
                IP: `{alert['ip_address']}` | {alert['timestamp']}
                
                {alert['description']}
                
                {'✓ Acknowledged' if alert['acknowledged'] else '⚠️ Unacknowledged'}
                """)
            
            st.markdown("---")
    else:
        st.info("No alerts match the selected filters")

except Exception as e:
    st.error(f"Error: {e}")
