"""
Attacker Intelligence - Detailed attacker profiles with geolocation
"""

import streamlit as st
import pandas as pd
import plotly.express as px
import plotly.graph_objects as go
from datetime import datetime
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent.parent))

from database.db import db
from honeypot.intelligence.geolocation import get_country_flag
from dashboard.login import check_authentication, show_login_page, show_user_info

st.set_page_config(page_title="Attacker Intel", page_icon="🌍", layout="wide")

# Check authentication
if not check_authentication():
    show_login_page()
    st.stop()

# Show user info in sidebar
show_user_info()

# Header
st.title("🌍 Attacker Intelligence")
st.markdown("Detailed profiles with geolocation and threat intelligence")

# IP Search
st.sidebar.markdown("### 🔍 Search IP")
search_ip = st.sidebar.text_input("Enter IP address")

if search_ip:
    # Display detailed profile
    st.subheader(f"🎯 Profile: {search_ip}")
    
    try:
        query = """
            SELECT * FROM attackers WHERE ip_address = ?
        """
        results = db.execute_query(query, (search_ip,))
        
        if results:
            attacker = dict(results[0])
            
            # Profile card
            col1, col2 = st.columns([1, 2])
            
            with col1:
                # Location
                if attacker['country']:
                    flag = get_country_flag(attacker['country_code'])
                    st.markdown(f"### {flag} {attacker['country']}")
                    st.write(f"**City:** {attacker['city']}")
                    st.write(f"**Region:** {attacker['region']}")
                else:
                    st.info("No geolocation data")
                
                # ISP
                if attacker['isp']:
                    st.write(f"**ISP:** {attacker['isp']}")
                if attacker['asn']:
                    st.write(f"**ASN:** {attacker['asn']}")
                
                # Threat indicators
                st.markdown("---")
                if attacker['is_tor_exit']:
                    st.error("🧅 TOR Exit Node")
                if attacker['is_known_bad']:
                    st.error("⚠️ Known Bad IP")
            
            with col2:
                # Threat metrics
                col_a, col_b, col_c = st.columns(3)
                
                with col_a:
                    st.metric(
                        "Threat Score",
                        f"{attacker['threat_score']}/100",
                        delta=None
                    )
                    
                    # Verdict with color
                    verdict = attacker['verdict']
                    if verdict == 'CRITICAL':
                        st.error(f"🔴 {verdict}")
                    elif verdict == 'HIGH':
                        st.warning(f"🟠 {verdict}")
                    elif verdict == 'MEDIUM':
                        st.info(f"🟡 {verdict}")
                    else:
                        st.success(f"🔵 {verdict}")
                
                with col_b:
                    st.metric("Connections", attacker['total_connections'])
                    st.metric("Login Attempts", attacker['total_login_attempts'])
                
                with col_c:
                    if attacker['abuseipdb_score']:
                        st.metric("AbuseIPDB", f"{attacker['abuseipdb_score']}/100")
                    
                    first_seen = datetime.fromisoformat(attacker['first_seen'])
                    last_seen = datetime.fromisoformat(attacker['last_seen'])
                    st.write(f"**First seen:** {first_seen.strftime('%Y-%m-%d %H:%M')}")
                    st.write(f"**Last seen:** {last_seen.strftime('%Y-%m-%d %H:%M')}")
            
            # Activity details
            st.markdown("---")
            
            tab1, tab2, tab3 = st.tabs(["🔐 Login Attempts", "🔌 Connections", "🚨 Alerts"])
            
            with tab1:
                # Login attempts
                query = """
                    SELECT 
                        timestamp,
                        service_name,
                        username,
                        password_attempt
                    FROM login_attempts
                    WHERE ip_address = ?
                    ORDER BY timestamp DESC
                    LIMIT 50
                """
                login_results = db.execute_query(query, (search_ip,))
                
                if login_results:
                    df = pd.DataFrame([dict(row) for row in login_results])
                    df['timestamp'] = pd.to_datetime(df['timestamp'])
                    st.dataframe(df, use_container_width=True)
                else:
                    st.info("No login attempts")
            
            with tab2:
                # Connections
                query = """
                    SELECT 
                        timestamp,
                        service_name,
                        destination_port
                    FROM connections
                    WHERE ip_address = ?
                    ORDER BY timestamp DESC
                    LIMIT 50
                """
                conn_results = db.execute_query(query, (search_ip,))
                
                if conn_results:
                    df = pd.DataFrame([dict(row) for row in conn_results])
                    df['timestamp'] = pd.to_datetime(df['timestamp'])
                    st.dataframe(df, use_container_width=True)
                else:
                    st.info("No connections")
            
            with tab3:
                # Alerts
                query = """
                    SELECT 
                        timestamp,
                        alert_type,
                        severity,
                        description
                    FROM alerts
                    WHERE ip_address = ?
                    ORDER BY timestamp DESC
                """
                alert_results = db.execute_query(query, (search_ip,))
                
                if alert_results:
                    for alert in alert_results:
                        severity_colors = {
                            'CRITICAL': 'red',
                            'HIGH': 'orange',
                            'MEDIUM': 'yellow',
                            'LOW': 'blue'
                        }
                        color = severity_colors.get(alert['severity'], 'gray')
                        
                        st.markdown(f"""
                        :{color}[**[{alert['severity']}]** {alert['alert_type']}]
                        
                        {alert['description']}
                        
                        *{alert['timestamp']}*
                        """)
                        st.markdown("---")
                else:
                    st.info("No alerts")
        
        else:
            st.warning(f"No data found for IP: {search_ip}")
    
    except Exception as e:
        st.error(f"Error: {e}")

else:
    # Show attacker leaderboard and map
    
    # Filters
    st.sidebar.markdown("### 🎛️ Filters")
    
    min_score = st.sidebar.slider("Min Threat Score", 0, 100, 0)
    verdict_filter = st.sidebar.multiselect(
        "Threat Level",
        ["CRITICAL", "HIGH", "MEDIUM", "LOW"],
        default=["CRITICAL", "HIGH", "MEDIUM", "LOW"]
    )
    
    limit = st.sidebar.number_input("Max Results", 10, 1000, 50)
    
    # World Map
    st.subheader("🗺️ Attack Origins - World Map")
    
    try:
        query = """
            SELECT 
                country,
                country_code,
                latitude,
                longitude,
                COUNT(*) as attacker_count,
                AVG(threat_score) as avg_threat_score
            FROM attackers
            WHERE latitude IS NOT NULL 
            AND longitude IS NOT NULL
            GROUP BY country, country_code, latitude, longitude
        """
        
        results = db.execute_query(query)
        
        if results:
            df = pd.DataFrame([dict(row) for row in results])
            
            # Create map
            fig = px.scatter_geo(
                df,
                lat='latitude',
                lon='longitude',
                size='attacker_count',
                color='avg_threat_score',
                hover_name='country',
                hover_data={
                    'attacker_count': True,
                    'avg_threat_score': ':.1f',
                    'latitude': False,
                    'longitude': False
                },
                color_continuous_scale='Reds',
                size_max=50,
                title="Attacker Origins by Country"
            )
            
            fig.update_layout(
                height=500,
                geo=dict(
                    showland=True,
                    landcolor='rgb(243, 243, 243)',
                    coastlinecolor='rgb(204, 204, 204)',
                    projection_type='natural earth'
                )
            )
            
            st.plotly_chart(fig, use_container_width=True)
        else:
            st.info("No geolocation data available yet. Enrichment in progress...")
    
    except Exception as e:
        st.error(f"Error creating map: {e}")
    
    st.markdown("---")
    
    # Attacker Leaderboard
    st.subheader("👥 Attacker Leaderboard")
    
    try:
        # Build query with filters
        verdict_filter_clause = ""
        if verdict_filter:
            verdicts_str = "','".join(verdict_filter)
            verdict_filter_clause = f"AND verdict IN ('{verdicts_str}')"
        
        query = f"""
            SELECT 
                ip_address,
                country,
                country_code,
                threat_score,
                verdict,
                total_connections,
                total_login_attempts,
                abuseipdb_score,
                first_seen,
                last_seen
            FROM attackers
            WHERE threat_score >= ? {verdict_filter_clause}
            ORDER BY threat_score DESC, total_login_attempts DESC
            LIMIT ?
        """
        
        results = db.execute_query(query, (min_score, limit))
        
        if results:
            df = pd.DataFrame([dict(row) for row in results])
            
            # Add rank
            df.insert(0, 'Rank', range(1, len(df) + 1))
            
            # Add flag
            df['Country'] = df.apply(
                lambda row: f"{get_country_flag(row['country_code'])} {row['country']}" if row['country'] else "Unknown",
                axis=1
            )
            
            # Format dates
            df['first_seen'] = pd.to_datetime(df['first_seen']).dt.strftime('%Y-%m-%d')
            df['last_seen'] = pd.to_datetime(df['last_seen']).dt.strftime('%Y-%m-%d')
            
            # Display table
            display_df = df[[
                'Rank', 'ip_address', 'Country', 'threat_score', 'verdict',
                'total_connections', 'total_login_attempts', 'abuseipdb_score',
                'first_seen', 'last_seen'
            ]].copy()
            
            display_df.columns = [
                'Rank', 'IP Address', 'Country', 'Score', 'Verdict',
                'Connections', 'Logins', 'AbuseIPDB', 'First Seen', 'Last Seen'
            ]
            
            # Color code by verdict
            def color_verdict(row):
                verdict = str(row['Verdict'])
                if verdict == 'CRITICAL':
                    return ['background-color: #ffcccc'] * len(row)
                elif verdict == 'HIGH':
                    return ['background-color: #ffe6cc'] * len(row)
                elif verdict == 'MEDIUM':
                    return ['background-color: #ffffcc'] * len(row)
                else:
                    return [''] * len(row)
            
            st.dataframe(
                display_df.style.apply(color_verdict, axis=1),
                use_container_width=True,
                height=600
            )
            
            st.caption(f"Showing top {len(df)} attackers")
            
            # Download
            csv = display_df.to_csv(index=False)
            st.download_button(
                label="📥 Download CSV",
                data=csv,
                file_name=f"attackers_{datetime.now().strftime('%Y%m%d_%H%M%S')}.csv",
                mime="text/csv"
            )
        
        else:
            st.info("No attackers match the selected filters")
    
    except Exception as e:
        st.error(f"Error loading leaderboard: {e}")
    
    st.markdown("---")
    
    # Country Statistics
    col1, col2 = st.columns(2)
    
    with col1:
        st.subheader("🌍 Top Countries")
        
        try:
            query = """
                SELECT 
                    country,
                    country_code,
                    COUNT(*) as count,
                    AVG(threat_score) as avg_score
                FROM attackers
                WHERE country IS NOT NULL
                GROUP BY country, country_code
                ORDER BY count DESC
                LIMIT 10
            """
            
            results = db.execute_query(query)
            
            if results:
                df = pd.DataFrame([dict(row) for row in results])
                df['Country'] = df.apply(
                    lambda row: f"{get_country_flag(row['country_code'])} {row['country']}",
                    axis=1
                )
                
                fig = px.bar(
                    df,
                    x='count',
                    y='Country',
                    orientation='h',
                    color='avg_score',
                    color_continuous_scale='Reds',
                    labels={'count': 'Attackers', 'avg_score': 'Avg Score'}
                )
                
                fig.update_layout(height=400)
                st.plotly_chart(fig, use_container_width=True)
            else:
                st.info("No country data")
        
        except Exception as e:
            st.error(f"Error: {e}")
    
    with col2:
        st.subheader("🏢 Top ISPs")
        
        try:
            query = """
                SELECT 
                    isp,
                    COUNT(*) as count
                FROM attackers
                WHERE isp IS NOT NULL
                GROUP BY isp
                ORDER BY count DESC
                LIMIT 10
            """
            
            results = db.execute_query(query)
            
            if results:
                df = pd.DataFrame([dict(row) for row in results])
                
                fig = px.bar(
                    df,
                    x='count',
                    y='isp',
                    orientation='h',
                    color='count',
                    color_continuous_scale='Blues'
                )
                
                fig.update_layout(height=400, showlegend=False)
                st.plotly_chart(fig, use_container_width=True)
            else:
                st.info("No ISP data")
        
        except Exception as e:
            st.error(f"Error: {e}")
