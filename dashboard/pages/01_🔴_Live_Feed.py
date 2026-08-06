"""
Live Feed - Real-time attack monitoring
"""

import streamlit as st
import pandas as pd
from datetime import datetime, timedelta
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent.parent))

from database.db import db
from honeypot.intelligence.geolocation import get_country_flag
from dashboard.login import check_authentication, show_login_page, show_user_info

st.set_page_config(page_title="Live Feed", page_icon="🔴", layout="wide")

# Check authentication
if not check_authentication():
    show_login_page()
    st.stop()

# Show user info in sidebar
show_user_info()

# Header
st.title("🔴 Live Attack Feed")
st.markdown("Real-time monitoring of honeypot activity")

# Auto-refresh
auto_refresh = st.sidebar.checkbox("Auto-refresh (15s)", value=True)
if auto_refresh:
    import time
    time.sleep(15)
    st.rerun()

# Filters
st.sidebar.markdown("### 🎛️ Filters")
time_filter = st.sidebar.selectbox(
    "Time Range",
    ["Last 1 hour", "Last 6 hours", "Last 24 hours", "Last 7 days", "All time"]
)

service_filter = st.sidebar.multiselect(
    "Services",
    ["SSH", "FTP", "HTTP", "Telnet"],
    default=["SSH", "FTP", "HTTP", "Telnet"]
)

# Calculate time range
time_ranges = {
    "Last 1 hour": 1,
    "Last 6 hours": 6,
    "Last 24 hours": 24,
    "Last 7 days": 24 * 7,
    "All time": None
}
hours_back = time_ranges[time_filter]

# Metric cards
col1, col2, col3, col4 = st.columns(4)

try:
    # Get metrics
    if hours_back:
        time_clause = f"AND timestamp >= datetime('now', '-{hours_back} hours')"
    else:
        time_clause = ""
    
    # Recent connections
    query = f"SELECT COUNT(*) as cnt FROM connections WHERE 1=1 {time_clause}"
    result = db.execute_query(query)
    recent_connections = result[0]['cnt'] if result else 0
    
    # Unique attackers
    query = f"SELECT COUNT(DISTINCT ip_address) as cnt FROM connections WHERE 1=1 {time_clause}"
    result = db.execute_query(query)
    unique_attackers = result[0]['cnt'] if result else 0
    
    # Recent alerts
    query = f"SELECT COUNT(*) as cnt FROM alerts WHERE acknowledged = 0 {time_clause.replace('timestamp', 'alerts.timestamp')}"
    result = db.execute_query(query)
    active_alerts = result[0]['cnt'] if result else 0
    
    # Critical threats
    query = f"SELECT COUNT(*) as cnt FROM attackers WHERE verdict = 'CRITICAL'"
    result = db.execute_query(query)
    critical_threats = result[0]['cnt'] if result else 0
    
    with col1:
        st.metric("🔌 Connections", recent_connections)
    
    with col2:
        st.metric("👤 Unique IPs", unique_attackers)
    
    with col3:
        st.metric("🚨 Active Alerts", active_alerts, delta=None)
    
    with col4:
        st.metric("⚠️ Critical", critical_threats, delta_color="inverse")

except Exception as e:
    st.error(f"Error loading metrics: {e}")

st.markdown("---")

# Live connection stream
st.subheader("📡 Recent Connections")

try:
    # Build query with filters
    service_filter_clause = ""
    if service_filter:
        services_str = "','".join(service_filter)
        service_filter_clause = f"AND c.service_name IN ('{services_str}')"
    
    if hours_back:
        time_clause = f"AND c.timestamp >= datetime('now', '-{hours_back} hours')"
    else:
        time_clause = ""
    
    query = f"""
        SELECT 
            c.timestamp,
            c.ip_address,
            a.country,
            a.country_code,
            c.service_name,
            c.destination_port,
            a.threat_score,
            a.verdict,
            CASE 
                WHEN EXISTS (
                    SELECT 1 FROM login_attempts la 
                    WHERE la.ip_address = c.ip_address 
                    AND la.timestamp BETWEEN c.timestamp AND datetime(c.timestamp, '+30 seconds')
                ) THEN 'Login Attempt'
                ELSE 'Connection'
            END as action
        FROM connections c
        LEFT JOIN attackers a ON c.ip_address = a.ip_address
        WHERE 1=1 {service_filter_clause} {time_clause}
        ORDER BY c.timestamp DESC
        LIMIT 100
    """
    
    results = db.execute_query(query)
    
    if results:
        # Convert to DataFrame
        df = pd.DataFrame([dict(row) for row in results])
        
        # Format timestamp
        df['Time'] = pd.to_datetime(df['timestamp']).dt.strftime('%H:%M:%S')
        
        # Add country flag
        df['Country'] = df.apply(
            lambda row: f"{get_country_flag(row['country_code'])} {row['country']}" if row['country'] else "Unknown",
            axis=1
        )
        
        # Add severity color
        def get_severity_emoji(verdict):
            if verdict == 'CRITICAL':
                return '🔴'
            elif verdict == 'HIGH':
                return '🟠'
            elif verdict == 'MEDIUM':
                return '🟡'
            elif verdict == 'LOW':
                return '🔵'
            else:
                return '⚪'
        
        df['Severity'] = df['verdict'].apply(get_severity_emoji) + ' ' + df['verdict'].fillna('UNKNOWN')
        
        # Display table
        display_df = df[[
            'Time', 'ip_address', 'Country', 'service_name', 
            'action', 'Severity', 'threat_score'
        ]].copy()
        
        display_df.columns = [
            'Time', 'IP Address', 'Country', 'Service', 
            'Action', 'Threat Level', 'Score'
        ]
        
        # Color code by severity
        def color_severity(row):
            if 'CRITICAL' in str(row['Threat Level']):
                return ['background-color: #ffcccc'] * len(row)
            elif 'HIGH' in str(row['Threat Level']):
                return ['background-color: #ffe6cc'] * len(row)
            elif 'MEDIUM' in str(row['Threat Level']):
                return ['background-color: #ffffcc'] * len(row)
            else:
                return [''] * len(row)
        
        # Display with styling
        st.dataframe(
            display_df.style.apply(color_severity, axis=1),
            use_container_width=True,
            height=500
        )
        
        # Summary
        st.caption(f"Showing {len(df)} most recent connections")
        
        # Download button
        csv = display_df.to_csv(index=False)
        st.download_button(
            label="📥 Download CSV",
            data=csv,
            file_name=f"live_feed_{datetime.now().strftime('%Y%m%d_%H%M%S')}.csv",
            mime="text/csv"
        )
        
    else:
        st.info("No connections in the selected time range")

except Exception as e:
    st.error(f"Error loading connections: {e}")
    import traceback
    st.code(traceback.format_exc())

st.markdown("---")

# Active services status
st.subheader("🛡️ Service Status")

try:
    query = """
        SELECT 
            service_name,
            port,
            total_connections,
            total_login_attempts,
            last_activity
        FROM service_stats
        ORDER BY service_name
    """
    
    results = db.execute_query(query)
    
    if results:
        cols = st.columns(len(results))
        
        for i, (col, row) in enumerate(zip(cols, results)):
            with col:
                # Calculate time since last activity
                if row['last_activity']:
                    last_seen = datetime.fromisoformat(row['last_activity'])
                    time_diff = datetime.now() - last_seen
                    
                    if time_diff.total_seconds() < 300:  # Less than 5 minutes
                        status = "🟢 Active"
                    elif time_diff.total_seconds() < 3600:  # Less than 1 hour
                        status = "🟡 Idle"
                    else:
                        status = "🔴 Inactive"
                else:
                    status = "⚪ No Activity"
                
                st.markdown(f"""
                **{row['service_name']}** (port {row['port']})
                
                {status}
                
                - 🔌 {row['total_connections']} connections
                - 🔐 {row['total_login_attempts']} login attempts
                """)
    else:
        st.info("No service statistics available")

except Exception as e:
    st.error(f"Error loading service status: {e}")

st.markdown("---")

# Recent alerts
st.subheader("🚨 Recent Alerts")

try:
    query = """
        SELECT 
            timestamp,
            ip_address,
            alert_type,
            severity,
            description
        FROM alerts
        ORDER BY timestamp DESC
        LIMIT 10
    """
    
    results = db.execute_query(query)
    
    if results:
        for row in results:
            severity_colors = {
                'CRITICAL': 'red',
                'HIGH': 'orange',
                'MEDIUM': 'yellow',
                'LOW': 'blue'
            }
            
            color = severity_colors.get(row['severity'], 'gray')
            
            time_str = datetime.fromisoformat(row['timestamp']).strftime('%H:%M:%S')
            
            st.markdown(f"""
            :{color}[**[{row['severity']}]** {row['alert_type']}] - {time_str}
            
            IP: `{row['ip_address']}` - {row['description'][:100]}...
            """)
            st.markdown("---")
    else:
        st.info("No recent alerts")

except Exception as e:
    st.error(f"Error loading alerts: {e}")

# Footer
st.caption(f"Last updated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
