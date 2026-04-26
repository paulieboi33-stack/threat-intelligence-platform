#!/usr/bin/env python3
"""
Threat Intelligence Platform - Streamlit Web Dashboard
"""
import streamlit as st
import sqlite3
import json
import os
import pandas as pd
from datetime import datetime

DB_PATH = os.path.join(os.path.dirname(__file__), 'data', 'threats.db')
IPHONE_PATH = os.path.join(os.path.dirname(__file__), 'data', 'iphone', 'full_analysis.json')
NETWORK_PATH = os.path.join(os.path.dirname(__file__), 'data', 'network', 'network_analysis.json')

st.set_page_config(
    page_title="Threat Intelligence Platform",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded"
)

st.markdown("""
<style>
[data-testid="stMetricValue"] { font-size: 2.2rem; }
.block-container { padding-top: 1.5rem; }
</style>
""", unsafe_allow_html=True)

# ── Sidebar ──────────────────────────────────────────────────────────────────
st.sidebar.title("🛡️ Threat Intel Platform")
st.sidebar.markdown("Multi-Agent Cybersecurity System")
page = st.sidebar.radio("Navigate", ["📊 Dashboard", "📱 iPhone Analysis", "📡 Network Traffic", "🔍 Threat Explorer"])
st.sidebar.markdown("---")
st.sidebar.caption(f"Last loaded: {datetime.now().strftime('%H:%M:%S')}")

# ── Load data ────────────────────────────────────────────────────────────────
@st.cache_data(ttl=30)
def load_threats():
    try:
        conn = sqlite3.connect(DB_PATH)
        df = pd.read_sql_query("SELECT * FROM threats ORDER BY collected_at DESC", conn)
        conn.close()
        return df
    except Exception as e:
        return pd.DataFrame()

@st.cache_data(ttl=30)
def load_network():
    try:
        with open(NETWORK_PATH) as f:
            return json.load(f)
    except:
        return None

@st.cache_data
def load_iphone():
    try:
        with open(IPHONE_PATH) as f:
            return json.load(f)
    except:
        return None

df = load_threats()
iphone = load_iphone()
network = load_network()

# ── DASHBOARD PAGE ────────────────────────────────────────────────────────────
if page == "📊 Dashboard":
    st.title("🛡️ Threat Intelligence Dashboard")
    st.caption(f"Live data from multi-agent pipeline · {len(df)} threats tracked")

    if not df.empty:
        col1, col2, col3, col4, col5 = st.columns(5)
        col1.metric("Total Threats", len(df))
        col2.metric("🔴 Critical", len(df[df['severity'] == 'Critical']))
        col3.metric("🟠 High", len(df[df['severity'] == 'High']))
        col4.metric("🟡 Medium", len(df[df['severity'] == 'Medium']))
        col5.metric("🟢 Low", len(df[df['severity'] == 'Low']))

        st.markdown("---")
        col_a, col_b = st.columns(2)

        with col_a:
            st.subheader("Severity Breakdown")
            sev_counts = df['severity'].value_counts().reset_index()
            sev_counts.columns = ['Severity', 'Count']
            st.bar_chart(sev_counts.set_index('Severity'))

        with col_b:
            st.subheader("Top CVSS Scores")
            top = df.nlargest(10, 'cvss_score')[['cve_id', 'title', 'cvss_score', 'severity']].copy()
            top['title'] = top['title'].str[:60] + '...'
            st.dataframe(top, use_container_width=True, hide_index=True)

        st.markdown("---")
        st.subheader("📅 Threats Over Time")
        df['date'] = pd.to_datetime(df['collected_at']).dt.date
        timeline = df.groupby('date').size().reset_index(name='count')
        st.line_chart(timeline.set_index('date'))

    else:
        st.warning("No threat data found. Run main.py to collect threats.")

# ── IPHONE PAGE ───────────────────────────────────────────────────────────────
elif page == "📱 iPhone Analysis":
    st.title("📱 iPhone Threat Analysis")
    st.caption("Paul's iPhone 16 Pro — collected via USB (libimobiledevice)")

    if iphone:
        device = iphone.get('device', {})
        flags = iphone.get('flags', [])
        apps = iphone.get('apps', [])

        col1, col2, col3, col4 = st.columns(4)
        col1.metric("📱 Device", device.get('product_type', 'Unknown'))
        col2.metric("🍎 iOS", device.get('ios_version', 'Unknown'))
        col3.metric("📦 Apps Scanned", len(apps))
        col4.metric("⚠️ Risks Found", len(flags))

        st.markdown("---")

        if flags:
            st.subheader("🚨 Risk Findings")
            for f in sorted(flags, key=lambda x: {"HIGH":0,"MEDIUM":1,"LOW":2}.get(x['risk'], 3)):
                risk = f['risk']
                color = "🔴" if risk == "HIGH" else "🟡" if risk == "MEDIUM" else "🟢"
                with st.expander(f"{color} [{risk}] {f['app']}"):
                    st.write(f"**Bundle ID:** `{f['bundle_id']}`")
                    st.write(f"**Reason:** {f['reason']}")

        st.markdown("---")
        st.subheader("📋 Full App Inventory")
        if apps:
            apps_df = pd.DataFrame(apps)
            st.dataframe(apps_df, use_container_width=True, hide_index=True)
        else:
            st.info("No app data available.")
    else:
        st.warning("No iPhone data found. Connect your iPhone and run iphone_collector.py first.")

# ── NETWORK TRAFFIC PAGE ─────────────────────────────────────────────────────
elif page == "📡 Network Traffic":
    st.title("📡 Network Traffic Analysis")
    st.caption("Live capture from iPhone via mitmproxy — what your phone is really talking to")

    if network:
        col1, col2, col3, col4 = st.columns(4)
        col1.metric("📶 Total Requests", network.get("total_flows", 0))
        col2.metric("🌐 Unique Domains", network.get("unique_domains", 0))
        findings = network.get("findings", [])
        suspicious = [f for f in findings if f["type"] == "SUSPICIOUS"]
        trackers = [f for f in findings if f["type"] == "TRACKER"]
        col3.metric("⚠️ Suspicious", len(suspicious))
        col4.metric("📡 Trackers", len(trackers))

        st.markdown("---")

        col_a, col_b = st.columns(2)

        with col_a:
            st.subheader("🔝 Most Active Domains")
            top = network.get("top_domains", [])
            if top:
                top_df = pd.DataFrame(top)
                st.bar_chart(top_df.set_index("domain")["count"])

        with col_b:
            st.subheader("⚠️ Suspicious Connections")
            if suspicious:
                for f in suspicious:
                    risk = f["risk"]
                    icon = "🔴" if risk == "HIGH" else "🟡"
                    with st.expander(f"{icon} {f['host']}"):
                        st.write(f"**Risk:** {risk}")
                        st.write(f"**Reason:** {f['reason']}")
                        st.write(f"**Requests:** {f['count']}")
            else:
                st.success("No suspicious connections detected")

        st.markdown("---")
        st.subheader("📡 Trackers & Data Collectors")
        if trackers:
            tracker_df = pd.DataFrame([{
                "Host": f["host"],
                "Tracker": f["reason"],
                "Requests": f["count"]
            } for f in trackers])
            st.dataframe(tracker_df, use_container_width=True, hide_index=True)
        else:
            st.info("No trackers detected yet — open more apps on your iPhone")

        st.caption(f"Last analyzed: {network.get('collected_at', 'unknown')}")
    else:
        st.warning("No network data yet. Keep mitmproxy running and open apps on your iPhone, then run: `python3 agents/network_analyzer.py`")
        st.code("python3 agents/network_analyzer.py", language="bash")

# ── THREAT EXPLORER PAGE ──────────────────────────────────────────────────────
elif page == "🔍 Threat Explorer":
    st.title("🔍 Threat Explorer")
    st.caption("Browse and filter all collected CVEs")

    if not df.empty:
        col1, col2, col3 = st.columns(3)
        sev_filter = col1.multiselect("Severity", df['severity'].unique().tolist(), default=df['severity'].unique().tolist())
        min_cvss = col2.slider("Min CVSS Score", 0.0, 10.0, 0.0, 0.1)
        search = col3.text_input("Search CVE ID or title", "")

        filtered = df[df['severity'].isin(sev_filter) & (df['cvss_score'] >= min_cvss)]
        if search:
            filtered = filtered[
                filtered['cve_id'].str.contains(search, case=False, na=False) |
                filtered['title'].str.contains(search, case=False, na=False)
            ]

        st.markdown(f"**{len(filtered)} threats** match your filters")

        display = filtered[['cve_id', 'severity', 'cvss_score', 'title', 'collected_at']].copy()
        display['title'] = display['title'].str[:80] + '...'
        display = display.rename(columns={
            'cve_id': 'CVE ID', 'severity': 'Severity',
            'cvss_score': 'CVSS', 'title': 'Title', 'collected_at': 'Collected'
        })
        st.dataframe(display, use_container_width=True, hide_index=True)

        if st.checkbox("Show full details for a CVE"):
            cve_pick = st.selectbox("Select CVE", filtered['cve_id'].tolist())
            row = filtered[filtered['cve_id'] == cve_pick].iloc[0]
            st.json({
                "CVE ID": row['cve_id'],
                "Severity": row['severity'],
                "CVSS Score": row['cvss_score'],
                "Title": row['title'],
                "Description": row['description'],
                "MITRE Tactics": row.get('mitre_tactics', ''),
                "MITRE Techniques": row.get('mitre_techniques', ''),
                "AI Summary": row.get('ai_summary', ''),
                "Collected At": row['collected_at'],
            })
    else:
        st.warning("No threat data found.")
