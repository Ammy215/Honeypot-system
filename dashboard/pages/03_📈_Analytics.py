"""
Analytics - Charts and trend analysis
"""

import streamlit as st
import pandas as pd
import plotly.express as px
import plotly.graph_objects as go
from datetime import datetime, timedelta
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent.parent))

from database.db import db
from dashboard.login import check_authentication, show_login_page, show_user_info

st.set_page_config(page_title="Analytics", page_icon="📈", layout="wide")

# Check authentication
if not check_authentication():
    show_login_page()
    st.stop()

# Show user info in sidebar
show_user_info()

st.title("📈 Analytics & Trends")
st.markdown("Visual analysis of attack patterns and statistics")

# Time range filter
st.sidebar.markdown("### 🎛️ Filters")
days_back = st.sidebar.selectbox("Time Range", [1, 7, 30, 90, 365], index=1)

# Attack Timeline
st.subheader("📊 Attack Timeline")

try:
    query = f"""
        SELECT 
            DATE(timestamp) as date,
            service_name,
            COUNT(*) as count
        FROM connections
        WHERE timestamp >= datetime('now', '-{days_back} days')
        GROUP BY DATE(timestamp), service_name
        ORDER BY date
    """
    
    results = db.execute_query(query)
    
    if results:
        df = pd.DataFrame([dict(row) for row in results])
        df['date'] = pd.to_datetime(df['date'])
        
        fig = px.area(
            df,
            x='date',
            y='count',
            color='service_name',
            title=f"Connections Over Last {days_back} Days",
            labels={'count': 'Connections', 'date': 'Date', 'service_name': 'Service'}
        )
        
        fig.update_layout(height=400)
        st.plotly_chart(fig, use_container_width=True)
    else:
        st.info("No data for timeline")

except Exception as e:
    st.error(f"Error: {e}")

st.markdown("---")

# Service Distribution
col1, col2 = st.columns(2)

with col1:
    st.subheader("🎯 Service Distribution")
    
    try:
        query = """
            SELECT 
                service_name,
                COUNT(*) as count
            FROM connections
            GROUP BY service_name
        """
        
        results = db.execute_query(query)
        
        if results:
            df = pd.DataFrame([dict(row) for row in results])
            
            fig = px.pie(
                df,
                values='count',
                names='service_name',
                title="Attacks by Service",
                hole=0.4
            )
            
            st.plotly_chart(fig, use_container_width=True)
        else:
            st.info("No data")
    
    except Exception as e:
        st.error(f"Error: {e}")

with col2:
    st.subheader("⚠️ Threat Level Distribution")
    
    try:
        query = """
            SELECT 
                verdict,
                COUNT(*) as count
            FROM attackers
            WHERE verdict IS NOT NULL
            GROUP BY verdict
        """
        
        results = db.execute_query(query)
        
        if results:
            df = pd.DataFrame([dict(row) for row in results])
            
            colors = {
                'CRITICAL': '#ff4444',
                'HIGH': '#ff8800',
                'MEDIUM': '#ffbb00',
                'LOW': '#00aaff'
            }
            
            fig = px.bar(
                df,
                x='verdict',
                y='count',
                color='verdict',
                color_discrete_map=colors,
                title="Attackers by Threat Level"
            )
            
            fig.update_layout(showlegend=False)
            st.plotly_chart(fig, use_container_width=True)
        else:
            st.info("No data")
    
    except Exception as e:
        st.error(f"Error: {e}")

st.markdown("---")

# Top Credentials
col1, col2 = st.columns(2)

with col1:
    st.subheader("👤 Top Usernames Tried")
    
    try:
        query = """
            SELECT 
                username,
                COUNT(*) as count
            FROM login_attempts
            WHERE username IS NOT NULL
            GROUP BY username
            ORDER BY count DESC
            LIMIT 15
        """
        
        results = db.execute_query(query)
        
        if results:
            df = pd.DataFrame([dict(row) for row in results])
            
            fig = px.bar(
                df,
                y='username',
                x='count',
                orientation='h',
                color='count',
                color_continuous_scale='Blues',
                title="Most Attempted Usernames"
            )
            
            fig.update_layout(height=500, showlegend=False)
            st.plotly_chart(fig, use_container_width=True)
        else:
            st.info("No login data")
    
    except Exception as e:
        st.error(f"Error: {e}")

with col2:
    st.subheader("🔑 Top Passwords Tried")
    
    try:
        query = """
            SELECT 
                password_attempt,
                COUNT(*) as count
            FROM login_attempts
            WHERE password_attempt IS NOT NULL
            GROUP BY password_attempt
            ORDER BY count DESC
            LIMIT 15
        """
        
        results = db.execute_query(query)
        
        if results:
            df = pd.DataFrame([dict(row) for row in results])
            
            # Mask passwords for display
            df['password_display'] = df['password_attempt'].apply(
                lambda x: x if len(x) <= 3 else x[:2] + '*' * (len(x)-2)
            )
            
            fig = px.bar(
                df,
                y='password_display',
                x='count',
                orientation='h',
                color='count',
                color_continuous_scale='Reds',
                title="Most Attempted Passwords"
            )
            
            fig.update_layout(height=500, showlegend=False)
            st.plotly_chart(fig, use_container_width=True)
        else:
            st.info("No login data")
    
    except Exception as e:
        st.error(f"Error: {e}")

st.markdown("---")

# Attack Heatmap
st.subheader("🔥 Attack Heatmap - Hour of Day vs Day of Week")

try:
    query = f"""
        SELECT 
            CAST(strftime('%w', timestamp) AS INTEGER) as day_of_week,
            CAST(strftime('%H', timestamp) AS INTEGER) as hour_of_day,
            COUNT(*) as count
        FROM connections
        WHERE timestamp >= datetime('now', '-{days_back} days')
        GROUP BY day_of_week, hour_of_day
    """
    
    results = db.execute_query(query)
    
    if results:
        df = pd.DataFrame([dict(row) for row in results])
        
        # Create pivot table
        pivot = df.pivot(index='hour_of_day', columns='day_of_week', values='count').fillna(0)
        
        # Day names
        day_names = ['Sunday', 'Monday', 'Tuesday', 'Wednesday', 'Thursday', 'Friday', 'Saturday']
        pivot.columns = [day_names[int(col)] for col in pivot.columns]
        
        fig = px.imshow(
            pivot,
            labels=dict(x="Day of Week", y="Hour of Day", color="Attacks"),
            aspect="auto",
            color_continuous_scale='Reds',
            title="Attack Frequency by Time"
        )
        
        fig.update_layout(height=500)
        st.plotly_chart(fig, use_container_width=True)
    else:
        st.info("No data for heatmap")

except Exception as e:
    st.error(f"Error: {e}")

st.markdown("---")

# Summary Statistics
st.subheader("📊 Summary Statistics")

col1, col2, col3, col4 = st.columns(4)

try:
    # Total unique IPs
    query = "SELECT COUNT(DISTINCT ip_address) as cnt FROM connections"
    result = db.execute_query(query)
    unique_ips = result[0]['cnt'] if result else 0
    
    # Total login attempts
    query = "SELECT COUNT(*) as cnt FROM login_attempts"
    result = db.execute_query(query)
    total_logins = result[0]['cnt'] if result else 0
    
    # Average threat score
    query = "SELECT AVG(threat_score) as avg FROM attackers WHERE threat_score > 0"
    result = db.execute_query(query)
    avg_score = result[0]['avg'] if result and result[0]['avg'] else 0
    
    # Total alerts
    query = "SELECT COUNT(*) as cnt FROM alerts"
    result = db.execute_query(query)
    total_alerts = result[0]['cnt'] if result else 0
    
    with col1:
        st.metric("Unique Attackers", unique_ips)
    
    with col2:
        st.metric("Login Attempts", total_logins)
    
    with col3:
        st.metric("Avg Threat Score", f"{avg_score:.1f}/100")
    
    with col4:
        st.metric("Total Alerts", total_alerts)

except Exception as e:
    st.error(f"Error loading stats: {e}")
