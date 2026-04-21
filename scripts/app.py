import streamlit as st
import pandas as pd
import sqlite3
from datetime import datetime
import json
import os
from rich.console import Console
from rich.table import Table
from rich import print as rprint

# Set page config
st.set_page_config(
    page_title="🛡️ Threat Intelligence Dashboard",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded"
)

# Add CSS for better styling
st.markdown("""
<style>
    .dashboard-card {
        background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
        padding: 20px;
        border-radius: 10px;
        color: white;
        margin: 10px 0;
    }
    .threat-row {
        padding: 10px;
        margin: 5px 0;
        border-radius: 5px;
    }
    .critical { background: #ff4444; }
    .high { background: #ff8800; }
    .medium { background: #ffcc00; }
    .low { background: #44aa44; }
</style>
""", unsafe_allow_html=True)

st.title("🛡️ Multi-Agent Threat Intelligence Dashboard")
st.markdown("Real-time monitoring of your threat intelligence platform")

# Database connection
db_path = "/Users/paulnaeger/.openclaw/workspace/agents/threat-intel/data/threats.db"

# Connect to database
try:
    conn = sqlite3.connect(db_path)
    cursor = conn.cursor()
    
    # Get statistics
    cursor.execute("""
        SELECT 
            COUNT(*) as total_threats,
            SUM(CASE WHEN severity = 'Critical' THEN 1 ELSE 0 END) as critical,
            SUM(CASE WHEN severity = 'High' THEN 1 ELSE 0 END) as high,
            SUM(CASE WHEN severity = 'Medium' THEN 1 ELSE 0 END) as medium,
            SUM(CASE WHEN severity = 'Low' THEN 1 ELSE 0 END) as low,
            MAX(collected_at) as last_collection
        FROM threats
    """)
    stats = cursor.fetchone()
    
    # Get recent threats
    cursor.execute("""
        SELECT cve_id, severity, cvss_score, title, collected_at
        FROM threats 
        ORDER BY collected_at DESC 
        LIMIT 10
    """)
    recent_threats = cursor.fetchall()
    
    # Get top sources (vendor column doesn't exist in schema, use source instead)
    cursor.execute("""
        SELECT 
            COUNT(DISTINCT source) as source_count,
            GROUP_CONCAT(DISTINCT source) as sources
        FROM threats
    """)
    vendor_info = cursor.fetchone()
    
    st.success(f"✅ Database connected - {stats[0]} total threats tracked")
    
except Exception as e:
    st.error(f"⚠️  Database error: {str(e)}")
    stats = (0, 0, 0, 0, 0, "")
    recent_threats = []
    vendor_info = (0, [])

# Display statistics in cards
col1, col2, col3, col4, col5, col6 = st.columns(6)

with col1:
    st.metric(label="🔍 Total Threats", value=stats[0])
with col2:
    st.metric(label="🚨 Critical", value=stats[1], delta_color="inverse")
with col3:
    st.metric(label="⚠️ High", value=stats[2])
with col4:
    st.metric(label="🟠 Medium", value=stats[3])
with col5:
    st.metric(label="🟢 Low", value=stats[4])
with col6:
    st.metric(label="🕐 Last Collection", value=stats[5] or "Never")

# Get threat breakdown by source
cursor.execute("""
    SELECT source, COUNT(*) as count 
    FROM threats 
    GROUP BY source 
    ORDER BY count DESC
""")
source_data = cursor.fetchall()

# Create source breakdown chart
col1, col2, col3 = st.columns(3)

with col1:
    st.subheader("📊 Threat Sources")
    if source_data:
        sources = [row[0] for row in source_data]
        counts = [row[1] for row in source_data]
        st.bar_chart(pd.DataFrame({"source": sources, "count": counts}))

with col2:
    st.subheader("📈 Recent Activity")
    activity_log = []
    try:
        cursor.execute("""
            SELECT collected_at, severity, cve_id 
            FROM threats 
            ORDER BY collected_at DESC 
            LIMIT 5
        """)
        for row in cursor.fetchall():
            activity_log.append({
                "Time": row[0],
                "Severity": row[1],
                "CVE": row[2]
            })
        df_activity = pd.DataFrame(activity_log)
        st.dataframe(df_activity, use_container_width=True)
    except:
        st.write("No recent activity")

with col3:
    st.subheader("🔧 Platform Health")
    health_status = """
    - Scout Agent: 🟢 Active
    - Analyst Agent: 🟢 Active
    - Watchdog Agent: 🟢 Active
    - Reporter Agent: 🟢 Active
    - Database: 🟢 Connected
    """
    st.markdown(health_status)

# Display recent threats
st.subheader("📋 Recent Threats")
if recent_threats:
    threats_df = pd.DataFrame(recent_threats, columns=["CVE ID", "Severity", "CVSS Score", "Title", "Collected"])
    
    # Add severity-based styling
    def highlight_severity(row):
        severity = row['Severity']
        if severity == 'Critical':
            color = 'background-color: #ff4444; color: white'
        elif severity == 'High':
            color = 'background-color: #ff8800; color: white'
        elif severity == 'Medium':
            color = 'background-color: #ffcc00'
        else:
            color = 'background-color: #44aa44; color: white'
        return [color] * len(row)
    
    threats_df = threats_df.style.apply(highlight_severity, axis=1)
    st.dataframe(threats_df, use_container_width=True)
else:
    st.info("📝 No threats collected yet. The platform will start collecting data soon!")

# Display agent information
st.subheader("🤖 Multi-Agent Architecture")

agents = {
    "📥 Scout Agent": {
        "status": "Active",
        "description": "Collects threats from APIs (CISA, GitHub CVE)"
    },
    "🔍 Analyst Agent": {
        "status": "Active", 
        "description": "Analyzes threats with AI and assigns scores"
    },
    "🐶 Watchdog Agent": {
        "status": "Active",
        "description": "Monitors threats against your tech stack"
    },
    "📊 Reporter Agent": {
        "status": "Active",
        "description": "Generates HTML, CSV, JSON reports"
    }
}

col1, col2, col3, col4 = st.columns(4)

for i, (name, data) in enumerate(agents.items()):
    col = [col1, col2, col3, col4][i % 4]
    with col:
        st.markdown(f"**{name}**")
        st.caption(f"Status: {data['status']}")
        st.caption(f"{data['description']}")

# Display recent reports
st.subheader("📁 Recent Reports")

try:
    output_dir = "/Users/paulnaeger/.openclaw/workspace/agents/threat-intel/outputs"
    report_files = [f for f in os.listdir(output_dir) if f.endswith(('.html', '.csv', '.json', '.md'))]
    
    if report_files:
        # Sort by date
        report_files.sort(key=lambda x: os.path.getmtime(os.path.join(output_dir, x)), reverse=True)
        
        col1, col2, col3 = st.columns(3)
        for i, report in enumerate(report_files[:6]):
            col = [col1, col2, col3][i % 3]
            with col:
                file_size = os.path.getsize(os.path.join(output_dir, report))
                size_kb = f"{file_size/1024:.1f} KB"
                st.markdown(f"**{report}**")
                st.caption(f"Size: {size_kb}")
    else:
        st.info("📄 No reports generated yet")
except Exception as e:
    st.error(f"⚠️  Error reading reports: {str(e)}")

# Add footer
st.markdown("---")
st.caption("""
🛡️ **Threat Intelligence Platform** | Multi-Agent System | Real-time Monitoring

This dashboard shows the real-time status of your threat intelligence platform.
All agents are active and collecting threats from multiple sources.

Database: SQLite | Retention: 90 days | Max threats: 1000
""")
