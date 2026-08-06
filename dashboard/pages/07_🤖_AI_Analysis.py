"""
AI Analysis - AI-powered threat analysis and reporting
"""

import streamlit as st
import pandas as pd
from datetime import datetime
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent.parent))

from database.db import db
from honeypot.ai.analyst import ai_analyst
from honeypot.ai.report_generator import report_generator
from dashboard.login import check_authentication, show_login_page, show_user_info

st.set_page_config(page_title="AI Analysis", page_icon="🤖", layout="wide")

# Check authentication
if not check_authentication():
    show_login_page()
    st.stop()

# Show user info in sidebar
show_user_info()

# Header
st.title("🤖 AI-Powered Threat Analysis")
st.markdown("Automated threat intelligence using GPT-4")

# Check if AI is available
if not ai_analyst.is_available():
    st.error("⚠️ AI Analyst Not Available")
    st.info("""
    **OpenAI API Key Required**
    
    To use AI-powered analysis:
    1. Get an API key from https://platform.openai.com/api-keys
    2. Add to `.env` file: `OPENAI_API_KEY=your_key_here`
    3. Restart the dashboard
    4. Install OpenAI: `pip install openai`
    """)
    st.stop()

# Sidebar - Analysis Mode
st.sidebar.markdown("### 🎯 Analysis Mode")
analysis_mode = st.sidebar.radio(
    "Select Mode",
    ["Threat Report", "Attacker Analysis", "Alert Summary", "Saved Reports"]
)

# ────────────────────────────────────────────────────────────────────
# MODE 1: Threat Report
# ────────────────────────────────────────────────────────────────────
if analysis_mode == "Threat Report":
    st.subheader("📊 AI Threat Intelligence Report")
    st.markdown("Generate comprehensive threat report for your time window")
    
    # Time window selection
    col1, col2 = st.columns([2, 1])
    
    with col1:
        time_window = st.slider("Time Window (hours)", 1, 168, 24)
    
    with col2:
        generate_btn = st.button("🚀 Generate Report", type="primary", use_container_width=True)
    
    if generate_btn:
        with st.spinner("🤖 AI Analyst is analyzing threat data..."):
            # Generate report
            report = ai_analyst.generate_threat_report(time_window)
            
            if report and not report.get('error'):
                st.success("✅ Report Generated Successfully!")
                
                # Display report
                st.markdown("---")
                
                # Statistics
                if 'statistics' in report:
                    col_a, col_b, col_c, col_d = st.columns(4)
                    
                    stats = report['statistics']
                    
                    with col_a:
                        st.metric("Total Attackers", stats.get('total_attackers', 0))
                    
                    with col_b:
                        st.metric("Total Alerts", stats.get('total_alerts', 0))
                    
                    with col_c:
                        st.metric("Services Hit", stats.get('services_hit', 0))
                    
                    with col_d:
                        st.metric("Countries", stats.get('countries', 0))
                    
                    st.markdown("---")
                
                # Report Content
                st.markdown("### 📝 AI Analysis Report")
                st.markdown(report['report_text'])
                
                # Metadata
                st.markdown("---")
                st.caption(f"Generated: {report['timestamp']} | Model: {report['model']} | Window: {time_window}h")
                
                # Export options
                col_x, col_y = st.columns(2)
                
                with col_x:
                    if st.button("💾 Save as Text Report"):
                        try:
                            filepath = report_generator.generate_text_report(report)
                            st.success(f"✅ Report saved: {filepath}")
                        except Exception as e:
                            st.error(f"Error saving report: {e}")
                
                with col_y:
                    # Download button
                    report_text = f"""HONEYPOT THREAT INTELLIGENCE REPORT
{'=' * 70}

Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}
Time Window: Last {time_window} hours
Model: {report['model']}

{'-' * 70}

{report['report_text']}

{'=' * 70}
"""
                    st.download_button(
                        label="📥 Download Report",
                        data=report_text,
                        file_name=f"threat_report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.txt",
                        mime="text/plain"
                    )
            
            else:
                st.error("❌ Failed to generate report")
                if report and report.get('error'):
                    st.code(report.get('report_text', 'Unknown error'))
    
    # Show recent AI reports
    st.markdown("---")
    st.markdown("### 📚 Recent Threat Reports")
    
    try:
        query = """
            SELECT timestamp, model_used, report_data
            FROM ai_reports
            WHERE report_type = 'threat_report'
            ORDER BY timestamp DESC
            LIMIT 5
        """
        
        results = db.execute_query(query)
        
        if results:
            for report in results:
                import json
                data = json.loads(report['report_data'])
                
                with st.expander(f"📄 Report from {report['timestamp']}"):
                    st.markdown(data.get('report_text', 'No content'))
                    st.caption(f"Model: {report['model_used']}")
        else:
            st.info("No saved reports yet. Generate one above!")
    
    except Exception as e:
        st.error(f"Error loading reports: {e}")

# ────────────────────────────────────────────────────────────────────
# MODE 2: Attacker Analysis
# ────────────────────────────────────────────────────────────────────
elif analysis_mode == "Attacker Analysis":
    st.subheader("🎯 AI Attacker Profile Analysis")
    st.markdown("Deep dive AI analysis of individual attackers")
    
    # Get top attackers
    query = """
        SELECT ip_address, country, threat_score, verdict
        FROM attackers
        WHERE total_login_attempts > 0
        ORDER BY threat_score DESC
        LIMIT 50
    """
    
    results = db.execute_query(query)
    
    if results:
        attacker_options = [
            f"{row['ip_address']} - {row.get('country', 'Unknown')} (Score: {row['threat_score']})"
            for row in results
        ]
        
        selected = st.selectbox("Select Attacker", attacker_options)
        
        if selected:
            # Extract IP
            selected_ip = selected.split(" - ")[0]
            
            col1, col2 = st.columns([3, 1])
            
            with col2:
                analyze_btn = st.button("🤖 Analyze with AI", type="primary", use_container_width=True)
            
            if analyze_btn:
                with st.spinner(f"🤖 AI Analyst is analyzing {selected_ip}..."):
                    # Generate analysis
                    analysis = ai_analyst.analyze_attacker(selected_ip)
                    
                    if analysis and not analysis.get('error'):
                        st.success("✅ Analysis Complete!")
                        
                        st.markdown("---")
                        
                        # Metrics
                        col_a, col_b = st.columns(2)
                        
                        with col_a:
                            st.metric("Threat Score", f"{analysis['threat_score']}/100")
                        
                        with col_b:
                            verdict = analysis['verdict']
                            if verdict == 'CRITICAL':
                                st.error(f"🔴 {verdict}")
                            elif verdict == 'HIGH':
                                st.warning(f"🟠 {verdict}")
                            elif verdict == 'MEDIUM':
                                st.info(f"🟡 {verdict}")
                            else:
                                st.success(f"🔵 {verdict}")
                        
                        st.markdown("---")
                        
                        # Analysis
                        st.markdown("### 🤖 AI Analysis")
                        st.markdown(analysis['analysis_text'])
                        
                        st.markdown("---")
                        st.caption(f"Generated: {analysis['timestamp']} | Model: {analysis['model']}")
                        
                        # Export options
                        col_x, col_y = st.columns(2)
                        
                        with col_x:
                            if st.button("💾 Save Full Report"):
                                try:
                                    filepath = report_generator.generate_attacker_report(selected_ip, analysis)
                                    st.success(f"✅ Report saved: {filepath}")
                                except Exception as e:
                                    st.error(f"Error saving report: {e}")
                        
                        with col_y:
                            # Download
                            report_text = f"""ATTACKER ANALYSIS REPORT
{'=' * 70}

IP: {selected_ip}
Threat Score: {analysis['threat_score']}/100
Verdict: {analysis['verdict']}
Generated: {analysis['timestamp']}
Model: {analysis['model']}

{'-' * 70}

{analysis['analysis_text']}

{'=' * 70}
"""
                            st.download_button(
                                label="📥 Download Analysis",
                                data=report_text,
                                file_name=f"attacker_{selected_ip.replace('.', '_')}_{datetime.now().strftime('%Y%m%d')}.txt",
                                mime="text/plain"
                            )
                    
                    else:
                        st.error("❌ Failed to generate analysis")
                        if analysis:
                            st.code(analysis.get('analysis_text', 'Unknown error'))
        
        # Show recent analyses
        st.markdown("---")
        st.markdown("### 📚 Recent Attacker Analyses")
        
        try:
            query = """
                SELECT ip_address, timestamp, model_used, report_data
                FROM ai_reports
                WHERE report_type = 'attacker_profile'
                ORDER BY timestamp DESC
                LIMIT 5
            """
            
            results = db.execute_query(query)
            
            if results:
                for report in results:
                    import json
                    data = json.loads(report['report_data'])
                    
                    with st.expander(f"🎯 {report['ip_address']} - {report['timestamp']}"):
                        st.markdown(data.get('analysis_text', 'No content'))
                        st.caption(f"Model: {report['model_used']}")
            else:
                st.info("No saved analyses yet. Generate one above!")
        
        except Exception as e:
            st.error(f"Error loading analyses: {e}")
    
    else:
        st.info("No attackers with login attempts in database yet.")

# ────────────────────────────────────────────────────────────────────
# MODE 3: Alert Summary
# ────────────────────────────────────────────────────────────────────
elif analysis_mode == "Alert Summary":
    st.subheader("🚨 AI Alert Summary")
    st.markdown("Natural language summary of recent security alerts")
    
    # Alert count selection
    col1, col2 = st.columns([2, 1])
    
    with col1:
        alert_count = st.slider("Number of Alerts to Summarize", 5, 50, 10)
    
    with col2:
        summarize_btn = st.button("🤖 Generate Summary", type="primary", use_container_width=True)
    
    if summarize_btn:
        with st.spinner("🤖 AI Analyst is summarizing alerts..."):
            # Generate summary
            summary = ai_analyst.summarize_alerts(alert_count)
            
            if summary:
                st.success("✅ Summary Generated!")
                
                st.markdown("---")
                st.markdown("### 📝 AI Summary")
                st.info(summary)
                
                st.markdown("---")
                
                # Download
                st.download_button(
                    label="📥 Download Summary",
                    data=summary,
                    file_name=f"alert_summary_{datetime.now().strftime('%Y%m%d_%H%M%S')}.txt",
                    mime="text/plain"
                )
            else:
                st.error("❌ Failed to generate summary")
    
    # Show recent alerts
    st.markdown("---")
    st.markdown(f"### 📋 Recent Alerts (Last {alert_count})")
    
    try:
        query = """
            SELECT 
                a.alert_type,
                a.severity,
                a.description,
                a.ip_address,
                att.country,
                a.timestamp
            FROM alerts a
            LEFT JOIN attackers att ON a.ip_address = att.ip_address
            ORDER BY a.timestamp DESC
            LIMIT ?
        """
        
        alerts = db.execute_query(query, (alert_count,))
        
        if alerts:
            for alert in alerts:
                severity = alert['severity']
                
                if severity == 'CRITICAL':
                    color = 'red'
                elif severity == 'HIGH':
                    color = 'orange'
                elif severity == 'MEDIUM':
                    color = 'blue'
                else:
                    color = 'gray'
                
                with st.container():
                    st.markdown(f"""
                    :{color}[**[{severity}]** {alert['alert_type']}] - {alert['ip_address']} ({alert.get('country', 'Unknown')})
                    
                    {alert['description']}
                    
                    *{alert['timestamp']}*
                    """)
                    st.markdown("---")
        else:
            st.info("No alerts in database yet.")
    
    except Exception as e:
        st.error(f"Error loading alerts: {e}")

# ────────────────────────────────────────────────────────────────────
# MODE 4: Saved Reports
# ────────────────────────────────────────────────────────────────────
elif analysis_mode == "Saved Reports":
    st.subheader("📚 Saved AI Reports")
    st.markdown("View and manage saved AI analyses and reports")
    
    # Report type filter
    report_type = st.selectbox(
        "Report Type",
        ["All", "Threat Reports", "Attacker Profiles", "Campaign Analyses"]
    )
    
    # Map selection to DB types
    type_map = {
        "All": None,
        "Threat Reports": "threat_report",
        "Attacker Profiles": "attacker_profile",
        "Campaign Analyses": "campaign_analysis"
    }
    
    selected_type = type_map[report_type]
    
    try:
        if selected_type:
            query = """
                SELECT id, ip_address, report_type, timestamp, model_used, report_data
                FROM ai_reports
                WHERE report_type = ?
                ORDER BY timestamp DESC
                LIMIT 20
            """
            results = db.execute_query(query, (selected_type,))
        else:
            query = """
                SELECT id, ip_address, report_type, timestamp, model_used, report_data
                FROM ai_reports
                ORDER BY timestamp DESC
                LIMIT 20
            """
            results = db.execute_query(query)
        
        if results:
            st.markdown(f"### 📄 {len(results)} Reports Found")
            
            for report in results:
                import json
                data = json.loads(report['report_data'])
                
                # Title
                if report['ip_address']:
                    title = f"{report['report_type'].replace('_', ' ').title()} - {report['ip_address']}"
                else:
                    title = f"{report['report_type'].replace('_', ' ').title()}"
                
                with st.expander(f"📝 {title} ({report['timestamp']})"):
                    # Display content
                    if 'report_text' in data:
                        st.markdown(data['report_text'])
                    elif 'analysis_text' in data:
                        st.markdown(data['analysis_text'])
                    else:
                        st.json(data)
                    
                    # Metadata
                    st.caption(f"Model: {report['model_used']} | ID: {report['id']}")
                    
                    # Download
                    content = data.get('report_text') or data.get('analysis_text') or json.dumps(data, indent=2)
                    
                    st.download_button(
                        label="📥 Download",
                        data=content,
                        file_name=f"report_{report['id']}_{datetime.now().strftime('%Y%m%d')}.txt",
                        mime="text/plain",
                        key=f"download_{report['id']}"
                    )
        
        else:
            st.info("No saved reports yet. Generate some analyses!")
    
    except Exception as e:
        st.error(f"Error loading reports: {e}")
        import traceback
        st.code(traceback.format_exc())

# ────────────────────────────────────────────────────────────────────
# Sidebar Info
# ────────────────────────────────────────────────────────────────────
st.sidebar.markdown("---")
st.sidebar.markdown("### ℹ️ About AI Analysis")
st.sidebar.info("""
**AI Analyst Features:**
- Threat intelligence reports
- Attacker behavior analysis
- Alert summarization
- Natural language insights
- Report generation

**Model**: GPT-4o-mini  
**Provider**: OpenAI
""")

# Footer
st.markdown("---")
st.markdown(f"""
<div style='text-align: center; color: #666; font-size: 0.9em;'>
AI Analysis powered by OpenAI GPT | 
Last updated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}
</div>
""", unsafe_allow_html=True)
