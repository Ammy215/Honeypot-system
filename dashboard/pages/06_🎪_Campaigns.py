"""
Campaign View - Coordinated attack campaign overview
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
from honeypot.detectors.campaign_detector import campaign_detector
from honeypot.intelligence.geolocation import get_country_flag
from dashboard.login import check_authentication, show_login_page, show_user_info

st.set_page_config(page_title="Campaigns", page_icon="🎪", layout="wide")

# Check authentication
if not check_authentication():
    show_login_page()
    st.stop()

# Show user info in sidebar
show_user_info()

# Header
st.title("🎪 Attack Campaigns")
st.markdown("Coordinated attack campaign detection and analysis")

# Sidebar controls
st.sidebar.markdown("### ⚙️ Settings")
time_window = st.sidebar.slider("Analysis Window (hours)", 1, 168, 24)
auto_refresh = st.sidebar.checkbox("Auto-refresh", value=False)

if auto_refresh:
    st.sidebar.info("Refreshing every 30 seconds")
    import time
    time.sleep(30)
    st.rerun()

# Get campaign summary
try:
    summary = campaign_detector.get_campaign_summary()
    campaigns = campaign_detector.detect_campaigns(time_window)
    
    # ────────────────────────────────────────────────────────────────────
    # Summary Metrics
    # ────────────────────────────────────────────────────────────────────
    col1, col2, col3, col4 = st.columns(4)
    
    with col1:
        st.metric(
            "Active Campaigns",
            summary['total_campaigns'],
            delta=None
        )
    
    with col2:
        critical = summary['by_severity'].get('HIGH', 0)
        st.metric(
            "High Severity",
            critical,
            delta=None,
            delta_color="inverse"
        )
    
    with col3:
        asn_campaigns = summary['by_type'].get('ASN_COORDINATED', 0)
        st.metric(
            "ASN Campaigns",
            asn_campaigns
        )
    
    with col4:
        cred_campaigns = summary['by_type'].get('CREDENTIAL_PATTERN', 0)
        st.metric(
            "Credential Campaigns",
            cred_campaigns
        )
    
    st.markdown("---")
    
    # ────────────────────────────────────────────────────────────────────
    # Campaign Type Distribution
    # ────────────────────────────────────────────────────────────────────
    if campaigns:
        col_a, col_b = st.columns(2)
        
        with col_a:
            st.markdown("### 📊 Campaign Types")
            
            type_data = []
            for ctype, count in summary['by_type'].items():
                # Readable names
                readable_names = {
                    'ASN_COORDINATED': 'ASN Coordinated',
                    'CREDENTIAL_PATTERN': 'Credential Pattern',
                    'TIMING_COORDINATED': 'Timing Coordinated',
                    'TARGET_FOCUSED': 'Target Focused'
                }
                
                type_data.append({
                    'Type': readable_names.get(ctype, ctype),
                    'Count': count
                })
            
            df_types = pd.DataFrame(type_data)
            
            fig = px.pie(
                df_types,
                values='Count',
                names='Type',
                hole=0.4,
                color_discrete_sequence=px.colors.sequential.Reds
            )
            fig.update_layout(height=350)
            st.plotly_chart(fig, use_container_width=True)
        
        with col_b:
            st.markdown("### 🎯 Severity Distribution")
            
            severity_data = []
            for severity, count in summary['by_severity'].items():
                severity_data.append({
                    'Severity': severity,
                    'Count': count
                })
            
            df_severity = pd.DataFrame(severity_data)
            
            # Sort by severity
            severity_order = ['HIGH', 'MEDIUM', 'LOW']
            df_severity['Severity'] = pd.Categorical(
                df_severity['Severity'],
                categories=severity_order,
                ordered=True
            )
            df_severity = df_severity.sort_values('Severity')
            
            colors = {
                'HIGH': '#ff4444',
                'MEDIUM': '#ffbb00',
                'LOW': '#00aaff'
            }
            
            fig = px.bar(
                df_severity,
                x='Severity',
                y='Count',
                color='Severity',
                color_discrete_map=colors
            )
            fig.update_layout(height=350, showlegend=False)
            st.plotly_chart(fig, use_container_width=True)
        
        st.markdown("---")
        
        # ────────────────────────────────────────────────────────────────────
        # Top ASN Campaigns
        # ────────────────────────────────────────────────────────────────────
        if summary['top_asns']:
            st.markdown("### 🏢 Top ASN Campaigns")
            st.markdown("Coordinated attacks from same autonomous systems")
            
            for i, campaign in enumerate(summary['top_asns'][:5], 1):
                severity = campaign.get('severity', 'MEDIUM')
                color = 'red' if severity == 'HIGH' else 'orange'
                
                with st.expander(
                    f":{color}[**#{i}:** {campaign['asn']} - "
                    f"{campaign['attacker_count']} IPs]",
                    expanded=(i == 1)
                ):
                    col_x, col_y = st.columns([1, 2])
                    
                    with col_x:
                        st.markdown("**Campaign Details**")
                        st.write(f"**ASN:** {campaign['asn']}")
                        st.write(f"**Attackers:** {campaign['attacker_count']}")
                        st.write(f"**Total Attempts:** {campaign['total_attempts']}")
                        st.write(f"**Severity:** {severity}")
                        
                        if 'start_time' in campaign:
                            st.write(f"**Started:** {campaign['start_time']}")
                    
                    with col_y:
                        st.markdown("**Involved IPs**")
                        
                        if 'ip_addresses' in campaign:
                            ips = campaign['ip_addresses'][:15]
                            
                            # Get country info for these IPs
                            ip_str = "','".join(ips)
                            query = f"""
                                SELECT ip_address, country, country_code, threat_score
                                FROM attackers
                                WHERE ip_address IN ('{ip_str}')
                            """
                            ip_results = db.execute_query(query)
                            
                            if ip_results:
                                df_ips = pd.DataFrame([dict(row) for row in ip_results])
                                df_ips['Country'] = df_ips.apply(
                                    lambda row: f"{get_country_flag(row['country_code'])} {row['country']}"
                                    if row['country'] else "Unknown",
                                    axis=1
                                )
                                
                                st.dataframe(
                                    df_ips[['ip_address', 'Country', 'threat_score']],
                                    use_container_width=True,
                                    height=250
                                )
                            else:
                                st.write(', '.join(ips))
                        
                        if campaign.get('services_targeted'):
                            st.markdown("**Services Targeted**")
                            st.write(', '.join(campaign['services_targeted']))
            
            st.markdown("---")
        
        # ────────────────────────────────────────────────────────────────────
        # Top Credential Campaigns
        # ────────────────────────────────────────────────────────────────────
        if summary['top_credentials']:
            st.markdown("### 🔐 Top Credential Campaigns")
            st.markdown("Same username/password patterns across multiple IPs")
            
            for i, campaign in enumerate(summary['top_credentials'][:5], 1):
                severity = campaign.get('severity', 'MEDIUM')
                color = 'red' if severity == 'HIGH' else 'orange'
                
                with st.expander(
                    f":{color}[**#{i}:** {campaign['username']} - "
                    f"{campaign['attacker_count']} IPs]",
                    expanded=(i == 1)
                ):
                    col_x, col_y = st.columns([1, 2])
                    
                    with col_x:
                        st.markdown("**Campaign Details**")
                        st.write(f"**Username:** `{campaign['username']}`")
                        st.write(f"**Password:** `{campaign['password']}`")
                        st.write(f"**Attackers:** {campaign['attacker_count']}")
                        st.write(f"**Attempts:** {campaign['attempt_count']}")
                        st.write(f"**Severity:** {severity}")
                    
                    with col_y:
                        st.markdown("**Involved IPs**")
                        
                        if 'ip_addresses' in campaign:
                            ips = campaign['ip_addresses'][:15]
                            
                            # Get details
                            ip_str = "','".join(ips)
                            query = f"""
                                SELECT ip_address, country, country_code, isp
                                FROM attackers
                                WHERE ip_address IN ('{ip_str}')
                            """
                            ip_results = db.execute_query(query)
                            
                            if ip_results:
                                df_ips = pd.DataFrame([dict(row) for row in ip_results])
                                df_ips['Country'] = df_ips.apply(
                                    lambda row: f"{get_country_flag(row['country_code'])} {row['country']}"
                                    if row['country'] else "Unknown",
                                    axis=1
                                )
                                
                                st.dataframe(
                                    df_ips[['ip_address', 'Country', 'isp']],
                                    use_container_width=True,
                                    height=250
                                )
                            else:
                                st.write(', '.join(ips))
                        
                        if campaign.get('services_targeted'):
                            st.markdown("**Services Targeted**")
                            st.write(', '.join(campaign['services_targeted']))
            
            st.markdown("---")
        
        # ────────────────────────────────────────────────────────────────────
        # All Campaigns Table
        # ────────────────────────────────────────────────────────────────────
        st.markdown("### 📋 All Detected Campaigns")
        
        # Filter options
        col_filter1, col_filter2 = st.columns(2)
        
        with col_filter1:
            type_filter = st.multiselect(
                "Filter by Type",
                ['ASN_COORDINATED', 'CREDENTIAL_PATTERN', 'TIMING_COORDINATED', 'TARGET_FOCUSED'],
                default=['ASN_COORDINATED', 'CREDENTIAL_PATTERN', 'TIMING_COORDINATED', 'TARGET_FOCUSED']
            )
        
        with col_filter2:
            severity_filter = st.multiselect(
                "Filter by Severity",
                ['HIGH', 'MEDIUM', 'LOW'],
                default=['HIGH', 'MEDIUM', 'LOW']
            )
        
        # Filter campaigns
        filtered = [
            c for c in campaigns
            if c['type'] in type_filter and c.get('severity', 'MEDIUM') in severity_filter
        ]
        
        if filtered:
            # Create table data
            table_data = []
            for campaign in filtered:
                row = {
                    'Type': campaign['type'],
                    'Severity': campaign.get('severity', 'MEDIUM'),
                    'IPs': campaign.get('attacker_count', 0),
                    'Description': campaign.get('description', '')
                }
                
                # Add type-specific fields
                if 'asn' in campaign:
                    row['Identifier'] = campaign['asn']
                elif 'username' in campaign:
                    row['Identifier'] = f"{campaign['username']}/{campaign['password']}"
                elif 'service' in campaign:
                    row['Identifier'] = f"{campaign['service']}:{campaign['port']}"
                elif 'time_bucket' in campaign:
                    row['Identifier'] = campaign['time_bucket']
                else:
                    row['Identifier'] = 'N/A'
                
                table_data.append(row)
            
            df_table = pd.DataFrame(table_data)
            
            # Add color coding
            def color_severity(row):
                if row['Severity'] == 'HIGH':
                    return ['background-color: #ffcccc'] * len(row)
                elif row['Severity'] == 'MEDIUM':
                    return ['background-color: #ffffcc'] * len(row)
                else:
                    return [''] * len(row)
            
            st.dataframe(
                df_table.style.apply(color_severity, axis=1),
                use_container_width=True,
                height=400
            )
            
            st.caption(f"Showing {len(filtered)} campaigns")
            
            # Download
            csv = df_table.to_csv(index=False)
            st.download_button(
                label="📥 Download Campaign Report",
                data=csv,
                file_name=f"campaigns_{datetime.now().strftime('%Y%m%d_%H%M%S')}.csv",
                mime="text/csv"
            )
        else:
            st.info("No campaigns match the selected filters")
    
    else:
        st.info(f"No campaigns detected in the last {time_window} hours")
        st.markdown("""
        **Campaign detection looks for:**
        - Multiple IPs from same ASN attacking together
        - Same credentials being used by multiple IPs
        - Coordinated timing of attacks
        - Multiple IPs targeting same services
        
        Campaigns will appear as attack activity increases.
        """)

except Exception as e:
    st.error(f"Error loading campaigns: {e}")
    import traceback
    st.code(traceback.format_exc())

# ────────────────────────────────────────────────────────────────────
# Footer
# ────────────────────────────────────────────────────────────────────
st.markdown("---")
st.markdown(f"""
<div style='text-align: center; color: #666; font-size: 0.9em;'>
Campaign analysis window: {time_window} hours | 
Last updated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}
</div>
""", unsafe_allow_html=True)
