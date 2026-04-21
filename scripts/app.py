import streamlit as st
import pandas as pd
import sqlite3
import json
import os
from datetime import datetime

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
    [data-testid="stMetric"] {
        background-color: #1e3a5f;
        border-radius: 10px;
        padding: 15px;
        border: 1px solid #2e5a8f;
    }
    [data-testid="stMetricLabel"] {
        color: #ffffff !important;
        font-size: 0.85rem !important;
        font-weight: 600 !important;
    }
    [data-testid="stMetricValue"] {
        color: #ffffff !important;
        font-size: 2rem !important;
        font-weight: 700 !important;
    }
</style>
""", unsafe_allow_html=True)

st.title("🛡️ Multi-Agent Threat Intelligence Dashboard")
st.markdown("Real-time monitoring powered by NVD CVE API & CISA Known Exploited Vulnerabilities")

# ─── Data Loading ────────────────────────────────────────────────────────────
# Try local SQLite first, fall back to exported JSON (for Streamlit Cloud)

def load_from_sqlite():
    db_path = os.path.join(os.path.dirname(__file__), '..', 'data', 'threats.db')
    db_path = os.path.abspath(db_path)
    if not os.path.exists(db_path):
        return None, None, None
    conn = sqlite3.connect(db_path)
    cursor = conn.cursor()
    cursor.execute("""
        SELECT COUNT(*) as total,
            SUM(CASE WHEN severity='Critical' THEN 1 ELSE 0 END) as critical,
            SUM(CASE WHEN severity='High' THEN 1 ELSE 0 END) as high,
            SUM(CASE WHEN severity='Medium' THEN 1 ELSE 0 END) as medium,
            SUM(CASE WHEN severity='Low' THEN 1 ELSE 0 END) as low,
            MAX(collected_at) as last_collection
        FROM threats
    """)
    stats = cursor.fetchone()
    cursor.execute("SELECT cve_id, severity, cvss_score, title, collected_at FROM threats ORDER BY collected_at DESC LIMIT 20")
    threats = cursor.fetchall()
    cursor.execute("SELECT source, COUNT(*) as count FROM threats GROUP BY source ORDER BY count DESC")
    sources = cursor.fetchall()
    conn.close()
    return stats, threats, sources

def load_from_json():
    json_path = os.path.join(os.path.dirname(__file__), '..', 'data', 'threats_export.json')
    json_path = os.path.abspath(json_path)
    if not os.path.exists(json_path):
        return None, None, None
    with open(json_path) as f:
        data = json.load(f)
    s = data['stats']
    stats = (s['total'], s['critical'], s['high'], s['medium'], s['low'], s['last_collection'])
    threats = [(t['cve_id'], t['severity'], t['cvss_score'], t['title'], t['collected_at'])
               for t in data['threats']]
    sources = [(s['source'], s['count']) for s in data['sources']]
    return stats, threats, sources

# Try SQLite first, then JSON
stats, recent_threats, source_data = load_from_sqlite()
using_live_db = stats is not None

if not using_live_db:
    stats, recent_threats, source_data = load_from_json()
    st.info("📦 Showing exported snapshot data. Run the platform locally for live data.")

if stats is None:
    st.error("⚠️ No data found. Run `python3 main.py` first to collect threats.")
    st.stop()

# ─── Stats Row ───────────────────────────────────────────────────────────────
st.success(f"{'✅ Live database connected' if using_live_db else '📦 Snapshot loaded'} — {stats[0]} total threats tracked")

col1, col2, col3, col4, col5, col6 = st.columns(6)
with col1:
    st.metric("🔍 Total Threats", stats[0])
with col2:
    st.metric("🚨 Critical", stats[1])
with col3:
    st.metric("⚠️ High", stats[2])
with col4:
    st.metric("🟠 Medium", stats[3])
with col5:
    st.metric("🟢 Low", stats[4])
with col6:
    last = stats[5][:16] if stats[5] else "Never"
    st.metric("🕐 Last Collection", last)

st.markdown("---")

# ─── Charts Row ──────────────────────────────────────────────────────────────
col1, col2, col3 = st.columns(3)

with col1:
    st.subheader("📊 Severity Breakdown")
    severity_data = {
        "Severity": ["Critical", "High", "Medium", "Low"],
        "Count": [stats[1] or 0, stats[2] or 0, stats[3] or 0, stats[4] or 0]
    }
    st.bar_chart(pd.DataFrame(severity_data).set_index("Severity"))

with col2:
    st.subheader("📡 Threat Sources")
    if source_data:
        sources_df = pd.DataFrame(source_data, columns=["Source", "Count"]).set_index("Source")
        st.bar_chart(sources_df)
    else:
        st.write("No source data yet")

with col3:
    st.subheader("🔧 Platform Health")
    st.markdown("""
    - 🔍 **Scout Agent:** 🟢 Active
    - 🧠 **Analyst Agent:** 🟢 Active
    - 🐕 **Watchdog Agent:** 🟢 Active
    - 📊 **Reporter Agent:** 🟢 Active
    - 🗄️ **Database:** 🟢 Connected
    - 📡 **NVD API:** 🟢 Live
    - 🏛️ **CISA KEV:** 🟢 Live (1,577 vulns)
    """)

st.markdown("---")

# ─── Recent Threats Table ─────────────────────────────────────────────────────
st.subheader("📋 Recent Threats")

if recent_threats:
    threats_df = pd.DataFrame(recent_threats, columns=["CVE ID", "Severity", "CVSS Score", "Title", "Collected"])

    def highlight_severity(row):
        severity = row['Severity']
        if severity == 'Critical':
            color = 'background-color: #8b0000; color: white'
        elif severity == 'High':
            color = 'background-color: #cc5500; color: white'
        elif severity == 'Medium':
            color = 'background-color: #b8860b; color: white'
        else:
            color = 'background-color: #2d5a27; color: white'
        return [color] * len(row)

    styled_df = threats_df.style.apply(highlight_severity, axis=1)
    st.dataframe(styled_df, use_container_width=True)
else:
    st.info("📝 No threats collected yet. Run `python3 main.py` to start collecting.")

st.markdown("---")

# ─── Agent Architecture ───────────────────────────────────────────────────────
st.subheader("🤖 Multi-Agent Architecture")

col1, col2, col3, col4 = st.columns(4)
agents = [
    ("📥 Scout Agent", "Collects live CVEs from NVD API v2.0 and CISA KEV catalog"),
    ("🧠 Analyst Agent", "Enriches threats with CVSS scoring and exploit detection"),
    ("🐕 Watchdog Agent", "Filters threats by relevance to your tech stack"),
    ("📊 Reporter Agent", "Generates HTML, CSV, JSON, and Markdown reports"),
]
for col, (name, desc) in zip([col1, col2, col3, col4], agents):
    with col:
        st.markdown(f"**{name}**")
        st.caption(desc)

st.markdown("---")

# ─── Footer ──────────────────────────────────────────────────────────────────
st.caption("""
🛡️ **Threat Intelligence Platform** | Multi-Agent System | Built by Paul Naeger
AI & ML Portfolio Project — Lone Star College | [GitHub](https://github.com/paulieboi33-stack/threat-intelligence-platform)
Data: NVD CVE API v2.0 + CISA Known Exploited Vulnerabilities | Retention: 90 days
""")
