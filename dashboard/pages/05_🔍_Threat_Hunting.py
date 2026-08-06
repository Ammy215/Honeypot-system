"""
Threat Hunting - Advanced pattern correlation and campaign detection
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
from honeypot.detectors.campaign_detector import campaign_detector
from honeypot.detectors.correlation_engine import correlation_engine
from honeypot.intelligence.geolocation import get_country_flag
from dashboard.login import check_authentication, show_login_page, show_user_info

st.set_page_config(page_title="Threat Hunting", page_icon="🔍", layout="wide")

# Check authentication
if not check_authentication():
    show_login_page()
    st.stop()

# Show user info in sidebar
show_user_info()

# Header
st.title("🔍 Threat Hunting")
st.markdown("Advanced pattern correlation and attack campaign detection")

# Sidebar - Hunt Mode
st.sidebar.markdown("### 🎯 Hunt Mode")
hunt_mode = st.sidebar.radio(
    "Select Analysis Type",
    ["Campaign Detection", "Behavior Correlation", "Attack Chains", "IOC Search"]
)

# ────────────────────────────────────────────────────────────────────
# MODE 1: Campaign Detection
# ────────────────────────────────────────────────────────────────────
if hunt_mode == "Campaign Detection":
    st.subheader("🎪 Attack Campaign Detection")
    st.markdown("Identify coordinated attack campaigns across multiple IPs")
    
    # Time window filter
    time_window = st.sidebar.slider("Time Window (hours)", 1, 168, 24)
    
    try:
        campaigns = campaign_detector.detect_campaigns(time_window)
        
        if campaigns:
            # Summary metrics
            col1, col2, col3, col4 = st.columns(4)
            
            with col1:
                st.metric("Total Campaigns", len(campaigns))
            
            with col2:
                critical_count = sum(1 for c in campaigns if c.get('severity') == 'HIGH')
                st.metric("High Severity", critical_count)
            
            with col3:
                total_attackers = sum(c.get('attacker_count', 0) for c in campaigns)
                st.metric("Total IPs Involved", total_attackers)
            
            with col4:
                campaign_types = len(set(c['type'] for c in campaigns))
                st.metric("Campaign Types", campaign_types)
            
            st.markdown("---")
            
            # Campaign type distribution
            col1, col2 = st.columns([1, 2])
            
            with col1:
                st.markdown("### 📊 Campaign Types")
                type_counts = {}
                for c in campaigns:
                    type_counts[c['type']] = type_counts.get(c['type'], 0) + 1
                
                df_types = pd.DataFrame(list(type_counts.items()), columns=['Type', 'Count'])
                
                fig = px.pie(
                    df_types,
                    values='Count',
                    names='Type',
                    hole=0.4,
                    color_discrete_sequence=px.colors.sequential.Reds
                )
                fig.update_layout(height=300)
                st.plotly_chart(fig, use_container_width=True)
            
            with col2:
                st.markdown("### 📈 Campaign Timeline")
                
                # Create timeline data
                timeline_data = []
                for c in campaigns:
                    if 'start_time' in c:
                        timeline_data.append({
                            'time': c['start_time'],
                            'type': c['type'],
                            'severity': c.get('severity', 'MEDIUM'),
                            'count': c.get('attacker_count', 1)
                        })
                
                if timeline_data:
                    df_timeline = pd.DataFrame(timeline_data)
                    df_timeline['time'] = pd.to_datetime(df_timeline['time'])
                    df_timeline = df_timeline.sort_values('time')
                    
                    fig = px.scatter(
                        df_timeline,
                        x='time',
                        y='type',
                        size='count',
                        color='severity',
                        color_discrete_map={
                            'HIGH': '#ff4444',
                            'MEDIUM': '#ffbb00',
                            'LOW': '#00aaff'
                        }
                    )
                    fig.update_layout(height=300)
                    st.plotly_chart(fig, use_container_width=True)
                else:
                    st.info("No timeline data available")
            
            st.markdown("---")
            
            # Detailed campaign list
            st.markdown("### 🎯 Detected Campaigns")
            
            # Filter by type
            campaign_types_list = list(set(c['type'] for c in campaigns))
            selected_types = st.multiselect(
                "Filter by Type",
                campaign_types_list,
                default=campaign_types_list
            )
            
            filtered_campaigns = [c for c in campaigns if c['type'] in selected_types]
            
            for i, campaign in enumerate(filtered_campaigns, 1):
                severity = campaign.get('severity', 'MEDIUM')
                
                # Color based on severity
                if severity == 'HIGH':
                    color = 'red'
                elif severity == 'MEDIUM':
                    color = 'orange'
                else:
                    color = 'blue'
                
                with st.expander(
                    f":{color}[**Campaign #{i}:** {campaign['type']} - {campaign.get('description', 'No description')}]",
                    expanded=(i <= 3)
                ):
                    col_a, col_b = st.columns([1, 2])
                    
                    with col_a:
                        st.markdown("**Campaign Details**")
                        st.write(f"**Type:** {campaign['type']}")
                        st.write(f"**Severity:** {severity}")
                        st.write(f"**Attackers:** {campaign.get('attacker_count', 'N/A')}")
                        
                        if 'start_time' in campaign:
                            st.write(f"**Start:** {campaign['start_time']}")
                        if 'end_time' in campaign:
                            st.write(f"**End:** {campaign['end_time']}")
                        
                        if 'asn' in campaign:
                            st.write(f"**ASN:** {campaign['asn']}")
                        if 'username' in campaign:
                            st.write(f"**Username:** {campaign['username']}")
                    
                    with col_b:
                        st.markdown("**Involved IP Addresses**")
                        
                        if 'ip_addresses' in campaign and campaign['ip_addresses']:
                            ip_list = campaign['ip_addresses'][:20]  # Limit display
                            
                            # Show as table
                            ip_df = pd.DataFrame({'IP Address': ip_list})
                            st.dataframe(ip_df, use_container_width=True, height=200)
                            
                            if len(campaign['ip_addresses']) > 20:
                                st.caption(f"Showing 20 of {len(campaign['ip_addresses'])} IPs")
                        else:
                            st.info("No IP data")
                        
                        if 'services_targeted' in campaign and campaign['services_targeted']:
                            st.markdown("**Targeted Services**")
                            services = ', '.join(campaign['services_targeted'])
                            st.write(services)
        
        else:
            st.info(f"No campaigns detected in the last {time_window} hours")
    
    except Exception as e:
        st.error(f"Error detecting campaigns: {e}")
        import traceback
        st.code(traceback.format_exc())

# ────────────────────────────────────────────────────────────────────
# MODE 2: Behavior Correlation
# ────────────────────────────────────────────────────────────────────
elif hunt_mode == "Behavior Correlation":
    st.subheader("🧠 Behavioral Analysis")
    st.markdown("Deep dive into attacker behavior patterns")
    
    # IP selection
    st.sidebar.markdown("### 🔍 Select Attacker")
    
    # Get top attackers
    query = """
        SELECT ip_address, threat_score, total_login_attempts
        FROM attackers
        WHERE total_login_attempts > 0
        ORDER BY threat_score DESC
        LIMIT 50
    """
    results = db.execute_query(query)
    
    if results:
        attacker_ips = [row['ip_address'] for row in results]
        selected_ip = st.sidebar.selectbox("IP Address", attacker_ips)
        
        if selected_ip:
            try:
                # Get behavior analysis
                analysis = correlation_engine.correlate_attacker_behavior(selected_ip)
                
                # Summary metrics
                col1, col2, col3, col4 = st.columns(4)
                
                with col1:
                    st.metric("Behavioral Score", analysis['behavioral_score'])
                
                with col2:
                    service_count = analysis['service_correlation'].get('service_count', 0)
                    st.metric("Services Targeted", service_count)
                
                with col3:
                    attack_count = len(analysis['attack_sequence'])
                    st.metric("Total Events", attack_count)
                
                with col4:
                    cred_count = analysis['credential_patterns'].get('total_attempts', 0)
                    st.metric("Login Attempts", cred_count)
                
                st.markdown("---")
                
                # Tabs for different analysis
                tab1, tab2, tab3, tab4 = st.tabs([
                    "📅 Attack Timeline",
                    "🎯 Service Patterns",
                    "🔐 Credential Analysis",
                    "👥 Similar Attackers"
                ])
                
                with tab1:
                    st.markdown("### Attack Sequence Timeline")
                    
                    if analysis['attack_sequence']:
                        df = pd.DataFrame(analysis['attack_sequence'])
                        df['timestamp'] = pd.to_datetime(df['timestamp'])
                        
                        # Timeline visualization
                        fig = px.scatter(
                            df,
                            x='timestamp',
                            y='event_type',
                            color='target',
                            hover_data=['username'],
                            title="Attack Event Timeline"
                        )
                        fig.update_layout(height=400)
                        st.plotly_chart(fig, use_container_width=True)
                        
                        # Data table
                        st.dataframe(df, use_container_width=True)
                    else:
                        st.info("No attack sequence data")
                
                with tab2:
                    st.markdown("### Service Targeting Patterns")
                    
                    service_corr = analysis['service_correlation']
                    
                    if service_corr:
                        col_a, col_b = st.columns(2)
                        
                        with col_a:
                            st.markdown("**Services Targeted (in order)**")
                            for i, service in enumerate(service_corr.get('service_order', []), 1):
                                st.write(f"{i}. {service}")
                            
                            if service_corr.get('is_scanning'):
                                st.warning("⚠️ Scanning behavior detected")
                        
                        with col_b:
                            st.markdown("**Service Hit Details**")
                            
                            if 'service_details' in service_corr:
                                df = pd.DataFrame(service_corr['service_details'])
                                df['first_hit'] = pd.to_datetime(df['first_hit'])
                                df['last_hit'] = pd.to_datetime(df['last_hit'])
                                st.dataframe(df, use_container_width=True)
                    else:
                        st.info("No service correlation data")
                
                with tab3:
                    st.markdown("### Credential Attack Patterns")
                    
                    cred = analysis['credential_patterns']
                    
                    if cred:
                        col_a, col_b = st.columns(2)
                        
                        with col_a:
                            st.metric("Unique Usernames", cred.get('unique_usernames', 0))
                            st.metric("Unique Passwords", cred.get('unique_passwords', 0))
                            st.metric("Total Attempts", cred.get('total_attempts', 0))
                        
                        with col_b:
                            attack_type = cred.get('attack_type', 'unknown')
                            
                            st.markdown("**Attack Type**")
                            if attack_type == 'credential_stuffing':
                                st.error("🎯 Credential Stuffing")
                            elif attack_type == 'password_spray':
                                st.warning("💧 Password Spray")
                            elif attack_type == 'brute_force':
                                st.warning("🔨 Brute Force")
                            else:
                                st.info(f"📝 {attack_type.title()}")
                        
                        # Usernames tried
                        if cred.get('usernames_tried'):
                            st.markdown("**Usernames Attempted**")
                            usernames = cred['usernames_tried'][:20]  # Limit display
                            st.write(', '.join(usernames))
                    else:
                        st.info("No credential attack data")
                
                with tab4:
                    st.markdown("### Find Similar Attackers")
                    
                    threshold = st.slider("Similarity Threshold", 0.0, 1.0, 0.7, 0.05)
                    
                    if st.button("🔍 Find Similar"):
                        with st.spinner("Analyzing behavior patterns..."):
                            similar = correlation_engine.find_similar_attackers(selected_ip, threshold)
                            
                            if similar:
                                st.success(f"Found {len(similar)} similar attackers")
                                
                                df = pd.DataFrame(similar, columns=['IP Address', 'Similarity Score'])
                                df['Similarity Score'] = df['Similarity Score'].round(3)
                                
                                st.dataframe(df, use_container_width=True)
                            else:
                                st.info("No similar attackers found at this threshold")
                
            except Exception as e:
                st.error(f"Error analyzing behavior: {e}")
                import traceback
                st.code(traceback.format_exc())
    else:
        st.info("No attackers with login attempts in database yet")

# ────────────────────────────────────────────────────────────────────
# MODE 3: Attack Chains
# ────────────────────────────────────────────────────────────────────
elif hunt_mode == "Attack Chains":
    st.subheader("⛓️ Attack Chain Detection")
    st.markdown("Identify sequences of related attacks from same source")
    
    # Time window
    time_window = st.sidebar.slider("Time Window (minutes)", 10, 180, 60)
    
    try:
        chains = correlation_engine.detect_attack_chains(time_window)
        
        if chains:
            # Summary
            col1, col2, col3, col4 = st.columns(4)
            
            with col1:
                st.metric("Attack Chains", len(chains))
            
            with col2:
                high_severity = sum(1 for c in chains if c.get('severity') == 'HIGH')
                st.metric("High Severity", high_severity)
            
            with col3:
                avg_length = sum(c['length'] for c in chains) / len(chains)
                st.metric("Avg Chain Length", f"{avg_length:.1f}")
            
            with col4:
                unique_ips = len(set(c['ip_address'] for c in chains))
                st.metric("Unique Attackers", unique_ips)
            
            st.markdown("---")
            
            # Chain length distribution
            col_a, col_b = st.columns(2)
            
            with col_a:
                st.markdown("### Chain Length Distribution")
                
                lengths = [c['length'] for c in chains]
                df_lengths = pd.DataFrame({'Chain Length': lengths})
                
                fig = px.histogram(
                    df_lengths,
                    x='Chain Length',
                    nbins=20,
                    color_discrete_sequence=['#667eea']
                )
                fig.update_layout(height=300)
                st.plotly_chart(fig, use_container_width=True)
            
            with col_b:
                st.markdown("### Service Diversity")
                
                service_counts = [c['unique_services'] for c in chains]
                df_services = pd.DataFrame({'Unique Services': service_counts})
                
                fig = px.histogram(
                    df_services,
                    x='Unique Services',
                    nbins=10,
                    color_discrete_sequence=['#f093fb']
                )
                fig.update_layout(height=300)
                st.plotly_chart(fig, use_container_width=True)
            
            st.markdown("---")
            
            # Chain details
            st.markdown("### 🔗 Detected Attack Chains")
            
            # Sort by severity and length
            sorted_chains = sorted(
                chains,
                key=lambda x: (x.get('severity') == 'HIGH', x['length']),
                reverse=True
            )
            
            for i, chain in enumerate(sorted_chains[:20], 1):
                severity = chain.get('severity', 'MEDIUM')
                color = 'red' if severity == 'HIGH' else 'orange'
                
                with st.expander(
                    f":{color}[**Chain #{i}:** {chain['ip_address']} - "
                    f"{chain['length']} events, {chain['unique_services']} services]"
                ):
                    col_a, col_b = st.columns([1, 2])
                    
                    with col_a:
                        st.markdown("**Chain Info**")
                        st.write(f"**IP:** {chain['ip_address']}")
                        st.write(f"**Length:** {chain['length']} events")
                        st.write(f"**Duration:** {chain['duration_minutes']:.1f} min")
                        st.write(f"**Services:** {chain['unique_services']}")
                        st.write(f"**Severity:** {severity}")
                    
                    with col_b:
                        st.markdown("**Attack Sequence**")
                        
                        seq_data = []
                        for service, timestamp in chain['sequence']:
                            seq_data.append({
                                'Time': timestamp.strftime('%H:%M:%S'),
                                'Service': service
                            })
                        
                        df_seq = pd.DataFrame(seq_data)
                        st.dataframe(df_seq, use_container_width=True, height=200)
            
            if len(chains) > 20:
                st.caption(f"Showing top 20 of {len(chains)} chains")
        
        else:
            st.info(f"No attack chains detected with {time_window} minute window")
    
    except Exception as e:
        st.error(f"Error detecting attack chains: {e}")
        import traceback
        st.code(traceback.format_exc())

# ────────────────────────────────────────────────────────────────────
# MODE 4: IOC Search
# ────────────────────────────────────────────────────────────────────
elif hunt_mode == "IOC Search":
    st.subheader("🔎 IOC Hunt")
    st.markdown("Search for Indicators of Compromise (IOCs) in your data")
    
    # Search type
    search_type = st.sidebar.radio(
        "Search Type",
        ["IP Address", "Username", "Password Pattern", "ASN", "Country"]
    )
    
    if search_type == "IP Address":
        st.markdown("### 🌐 IP Address Search")
        
        ip_search = st.text_input("Enter IP or IP range (e.g., 192.168.1.* or 10.0.0.)")
        
        if ip_search:
            try:
                # Build query based on pattern
                if '*' in ip_search or ip_search.endswith('.'):
                    # Wildcard search
                    pattern = ip_search.replace('*', '%').rstrip('.') + '%'
                    query = "SELECT * FROM attackers WHERE ip_address LIKE ?"
                    results = db.execute_query(query, (pattern,))
                else:
                    # Exact search
                    query = "SELECT * FROM attackers WHERE ip_address = ?"
                    results = db.execute_query(query, (ip_search,))
                
                if results:
                    st.success(f"Found {len(results)} matching IPs")
                    
                    df = pd.DataFrame([dict(row) for row in results])
                    
                    # Add country flags
                    df['Country'] = df.apply(
                        lambda row: f"{get_country_flag(row['country_code'])} {row['country']}"
                        if row['country'] else "Unknown",
                        axis=1
                    )
                    
                    # Display
                    display_cols = [
                        'ip_address', 'Country', 'threat_score', 'verdict',
                        'total_connections', 'total_login_attempts'
                    ]
                    
                    st.dataframe(
                        df[display_cols],
                        use_container_width=True
                    )
                else:
                    st.warning("No matches found")
            
            except Exception as e:
                st.error(f"Search error: {e}")
    
    elif search_type == "Username":
        st.markdown("### 👤 Username Search")
        
        username = st.text_input("Enter username")
        
        if username:
            try:
                query = """
                    SELECT 
                        ip_address,
                        service_name,
                        username,
                        COUNT(*) as attempt_count,
                        MIN(timestamp) as first_attempt,
                        MAX(timestamp) as last_attempt
                    FROM login_attempts
                    WHERE username LIKE ?
                    GROUP BY ip_address, service_name, username
                    ORDER BY attempt_count DESC
                """
                
                results = db.execute_query(query, (f'%{username}%',))
                
                if results:
                    st.success(f"Found {len(results)} IP/service combinations")
                    
                    df = pd.DataFrame([dict(row) for row in results])
                    df['first_attempt'] = pd.to_datetime(df['first_attempt'])
                    df['last_attempt'] = pd.to_datetime(df['last_attempt'])
                    
                    st.dataframe(df, use_container_width=True)
                    
                    # Visualization
                    fig = px.bar(
                        df.head(20),
                        x='attempt_count',
                        y='ip_address',
                        color='service_name',
                        orientation='h',
                        title=f"Top IPs attempting username: {username}"
                    )
                    st.plotly_chart(fig, use_container_width=True)
                else:
                    st.warning("No matches found")
            
            except Exception as e:
                st.error(f"Search error: {e}")
    
    elif search_type == "Password Pattern":
        st.markdown("### 🔐 Password Pattern Search")
        
        password = st.text_input("Enter password or pattern", type="password")
        show_password = st.checkbox("Show password in results")
        
        if password:
            try:
                query = """
                    SELECT 
                        ip_address,
                        service_name,
                        password_attempt,
                        COUNT(*) as attempt_count,
                        GROUP_CONCAT(DISTINCT username) as usernames
                    FROM login_attempts
                    WHERE password_attempt LIKE ?
                    GROUP BY ip_address, service_name, password_attempt
                    ORDER BY attempt_count DESC
                """
                
                results = db.execute_query(query, (f'%{password}%',))
                
                if results:
                    st.success(f"Found {len(results)} matches")
                    
                    df = pd.DataFrame([dict(row) for row in results])
                    
                    if not show_password:
                        df['password_attempt'] = '***'
                    
                    st.dataframe(df, use_container_width=True)
                else:
                    st.warning("No matches found")
            
            except Exception as e:
                st.error(f"Search error: {e}")
    
    elif search_type == "ASN":
        st.markdown("### 🏢 ASN Search")
        
        asn = st.text_input("Enter ASN (e.g., AS15169)")
        
        if asn:
            try:
                query = """
                    SELECT * FROM attackers 
                    WHERE asn LIKE ?
                    ORDER BY threat_score DESC
                """
                
                results = db.execute_query(query, (f'%{asn}%',))
                
                if results:
                    st.success(f"Found {len(results)} attackers from {asn}")
                    
                    df = pd.DataFrame([dict(row) for row in results])
                    
                    # Stats
                    col1, col2, col3 = st.columns(3)
                    
                    with col1:
                        st.metric("Total IPs", len(df))
                    with col2:
                        st.metric("Avg Threat Score", f"{df['threat_score'].mean():.1f}")
                    with col3:
                        st.metric("Total Connections", df['total_connections'].sum())
                    
                    st.dataframe(
                        df[['ip_address', 'country', 'isp', 'threat_score', 'verdict']],
                        use_container_width=True
                    )
                else:
                    st.warning("No matches found")
            
            except Exception as e:
                st.error(f"Search error: {e}")
    
    elif search_type == "Country":
        st.markdown("### 🌍 Country Search")
        
        # Get all countries
        query = "SELECT DISTINCT country FROM attackers WHERE country IS NOT NULL ORDER BY country"
        results = db.execute_query(query)
        
        if results:
            countries = [row['country'] for row in results]
            selected_country = st.selectbox("Select Country", countries)
            
            if selected_country:
                try:
                    query = """
                        SELECT * FROM attackers
                        WHERE country = ?
                        ORDER BY threat_score DESC
                    """
                    
                    results = db.execute_query(query, (selected_country,))
                    
                    if results:
                        df = pd.DataFrame([dict(row) for row in results])
                        
                        # Stats
                        col1, col2, col3 = st.columns(3)
                        
                        with col1:
                            st.metric("Total IPs", len(df))
                        with col2:
                            st.metric("Avg Threat Score", f"{df['threat_score'].mean():.1f}")
                        with col3:
                            critical = len(df[df['verdict'] == 'CRITICAL'])
                            st.metric("Critical Threats", critical)
                        
                        st.dataframe(
                            df[['ip_address', 'isp', 'threat_score', 'verdict', 'total_login_attempts']],
                            use_container_width=True
                        )
                        
                        # Download
                        csv = df.to_csv(index=False)
                        st.download_button(
                            label="📥 Download CSV",
                            data=csv,
                            file_name=f"attackers_{selected_country}_{datetime.now().strftime('%Y%m%d')}.csv",
                            mime="text/csv"
                        )
                
                except Exception as e:
                    st.error(f"Search error: {e}")
        else:
            st.info("No country data in database yet")
