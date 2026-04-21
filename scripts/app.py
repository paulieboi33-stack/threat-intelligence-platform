import streamlit as st
import pandas as pd
import sqlite3
import json
import os
from datetime import datetime

st.set_page_config(
    page_title="🛡️ Threat Intelligence Dashboard",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded"
)

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
    .threat-critical { border-left: 4px solid #cc0000; padding: 8px 12px; margin: 4px 0; border-radius: 4px; background: #1a0000; }
    .threat-high     { border-left: 4px solid #cc5500; padding: 8px 12px; margin: 4px 0; border-radius: 4px; background: #1a0800; }
    .threat-medium   { border-left: 4px solid #b8860b; padding: 8px 12px; margin: 4px 0; border-radius: 4px; background: #1a1400; }
    .threat-low      { border-left: 4px solid #2d7a2d; padding: 8px 12px; margin: 4px 0; border-radius: 4px; background: #001a00; }
</style>
""", unsafe_allow_html=True)

st.title("🛡️ Multi-Agent Threat Intelligence Dashboard")
st.markdown("Real-time monitoring powered by **NVD CVE API** & **CISA Known Exploited Vulnerabilities** · AI analysis via llama3.1")

# ─── Data Loading ─────────────────────────────────────────────────────────────
def load_from_sqlite():
    db_path = os.path.abspath(os.path.join(os.path.dirname(__file__), '..', 'data', 'threats.db'))
    if not os.path.exists(db_path):
        return None, None, None
    conn = sqlite3.connect(db_path)
    cursor = conn.cursor()
    cursor.execute("""
        SELECT COUNT(*) as total,
            SUM(CASE WHEN severity='Critical' THEN 1 ELSE 0 END),
            SUM(CASE WHEN severity='High' THEN 1 ELSE 0 END),
            SUM(CASE WHEN severity='Medium' THEN 1 ELSE 0 END),
            SUM(CASE WHEN severity='Low' THEN 1 ELSE 0 END),
            MAX(collected_at) as last_collection
        FROM threats
    """)
    stats = cursor.fetchone()
    cursor.execute("""
        SELECT cve_id, severity, cvss_score, title, description,
               ai_summary, priority, threat_actor_interest, collected_at
        FROM threats ORDER BY
            CASE severity WHEN 'Critical' THEN 1 WHEN 'High' THEN 2 WHEN 'Medium' THEN 3 ELSE 4 END,
            cvss_score DESC
        LIMIT 50
    """)
    threats = cursor.fetchall()
    cursor.execute("SELECT source, COUNT(*) FROM threats GROUP BY source ORDER BY COUNT(*) DESC")
    sources = cursor.fetchall()
    conn.close()
    return stats, threats, sources

def load_from_json():
    json_path = os.path.abspath(os.path.join(os.path.dirname(__file__), '..', 'data', 'threats_export.json'))
    if not os.path.exists(json_path):
        return None, None, None
    with open(json_path) as f:
        data = json.load(f)
    s = data['stats']
    stats = (s['total'], s['critical'], s['high'], s['medium'], s['low'], s['last_collection'])
    threats = [
        (t.get('cve_id'), t.get('severity'), t.get('cvss_score'), t.get('title'),
         t.get('description'), t.get('ai_summary'), t.get('priority'),
         t.get('threat_actor_interest'), t.get('collected_at'))
        for t in data['threats']
    ]
    sources = [(s['source'], s['count']) for s in data['sources']]
    return stats, threats, sources

stats, threats, source_data = load_from_sqlite()
using_live_db = stats is not None
if not using_live_db:
    stats, threats, source_data = load_from_json()
    st.info("📦 Showing snapshot data. Run `python3 main.py` locally for live AI analysis.")
if stats is None:
    st.error("⚠️ No data found. Run `python3 main.py` first.")
    st.stop()

# ─── Stats Row ────────────────────────────────────────────────────────────────
status_msg = f"{'✅ Live database' if using_live_db else '📦 Snapshot'} · {stats[0]} threats tracked"
st.success(status_msg)

col1, col2, col3, col4, col5, col6 = st.columns(6)
with col1: st.metric("🔍 Total", stats[0])
with col2: st.metric("🚨 Critical", stats[1])
with col3: st.metric("⚠️ High", stats[2])
with col4: st.metric("🟠 Medium", stats[3])
with col5: st.metric("🟢 Low", stats[4])
with col6: st.metric("🕐 Last Run", (stats[5] or "")[:16])

st.markdown("---")

# ─── Charts + Health ──────────────────────────────────────────────────────────
col1, col2, col3 = st.columns(3)

with col1:
    st.subheader("📊 Severity Breakdown")
    sev_df = pd.DataFrame({
        "Severity": ["Critical", "High", "Medium", "Low"],
        "Count": [stats[1] or 0, stats[2] or 0, stats[3] or 0, stats[4] or 0]
    }).set_index("Severity")
    st.bar_chart(sev_df)

with col2:
    st.subheader("📡 Threat Sources")
    if source_data:
        src_df = pd.DataFrame(source_data, columns=["Source", "Count"]).set_index("Source")
        st.bar_chart(src_df)

with col3:
    st.subheader("🔧 Platform Health")
    st.markdown("""
    - 🔍 **Scout Agent:** 🟢 Active
    - 🧠 **Analyst Agent:** 🟢 Active (llama3.1:8b)
    - 🐕 **Watchdog Agent:** 🟢 Active
    - 📊 **Reporter Agent:** 🟢 Active
    - 🗄️ **Database:** 🟢 Connected
    - 📡 **NVD API:** 🟢 Live
    - 🏛️ **CISA KEV:** 🟢 Live (1,577 vulns)
    """)

st.markdown("---")

# ─── Threat Feed with AI Detail ───────────────────────────────────────────────
st.subheader("📋 Threat Intelligence Feed")

# Sidebar filters
with st.sidebar:
    st.header("🔎 Filters")
    severity_filter = st.multiselect(
        "Severity",
        ["Critical", "High", "Medium", "Low"],
        default=["Critical", "High", "Medium", "Low"]
    )
    search_term = st.text_input("Search CVE or keyword", "")
    show_ai_only = st.checkbox("Only show AI-analyzed threats", False)
    st.markdown("---")
    st.markdown("**[📂 GitHub Repo](https://github.com/paulieboi33-stack/threat-intelligence-platform)**")
    st.markdown("Built by Paul Naeger · Lone Star College")

# Apply filters
filtered = []
for t in threats:
    cve_id, severity, cvss, title, desc, ai_summary, priority, actor_interest, collected = t
    if severity not in severity_filter:
        continue
    if search_term and search_term.lower() not in (cve_id or "").lower() and search_term.lower() not in (title or "").lower():
        continue
    if show_ai_only and not ai_summary:
        continue
    filtered.append(t)

st.caption(f"Showing {len(filtered)} of {len(threats)} threats")

if not filtered:
    st.info("No threats match your filters.")
else:
    for t in filtered:
        cve_id, severity, cvss, title, desc, ai_summary, priority, actor_interest, collected = t

        # Color by severity
        sev_color = {"Critical": "🔴", "High": "🟠", "Medium": "🟡", "Low": "🟢"}.get(severity, "⚪")
        priority_badge = f" · ⚡ {priority}" if priority else ""
        actor_badge = f" · 🎯 Actor Interest: {actor_interest}" if actor_interest else ""

        display_title = title if title and title != "Unknown" else (desc[:70] + "..." if desc else cve_id)

        with st.expander(f"{sev_color} **{cve_id}** — {display_title[:70]}  |  CVSS {cvss}  |  {severity}{priority_badge}"):
            col1, col2 = st.columns([2, 1])

            with col1:
                if ai_summary:
                    st.markdown("**🧠 AI Analysis:**")
                    st.info(ai_summary)
                elif desc:
                    st.markdown("**📄 Description:**")
                    st.write(desc)

            with col2:
                st.markdown("**Details**")
                st.write(f"**CVE ID:** {cve_id}")
                st.write(f"**Severity:** {severity}")
                st.write(f"**CVSS Score:** {cvss}")
                if priority:
                    st.write(f"**Priority:** {priority}")
                if actor_interest:
                    st.write(f"**Threat Actor Interest:** {actor_interest}")
                if collected:
                    st.write(f"**Collected:** {collected[:10]}")

            if title and title != "Unknown" and desc and desc != title:
                st.markdown(f"**Full Description:** {desc}")

st.markdown("---")

# ─── Agent Architecture ───────────────────────────────────────────────────────
st.subheader("🤖 Multi-Agent Architecture")
col1, col2, col3, col4 = st.columns(4)
agents = [
    ("📥 Scout Agent", "Collects live CVEs from NVD API v2.0 and CISA KEV (1,577 actively exploited vulns)"),
    ("🧠 Analyst Agent", "Uses llama3.1:8b to write plain-English summaries, attack scenarios & remediation steps"),
    ("🐕 Watchdog Agent", "Filters threats relevant to your org's tech stack and fires priority alerts"),
    ("📊 Reporter Agent", "Generates HTML, CSV, JSON, and Markdown reports on every pipeline run"),
]
for col, (name, desc) in zip([col1, col2, col3, col4], agents):
    with col:
        st.markdown(f"**{name}**")
        st.caption(desc)

st.markdown("---")
st.caption("🛡️ **Threat Intelligence Platform** · Multi-Agent AI System · Built by Paul Naeger · [GitHub](https://github.com/paulieboi33-stack/threat-intelligence-platform)")
