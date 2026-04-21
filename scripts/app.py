import streamlit as st
import pandas as pd
import sqlite3
import json
import os
from datetime import datetime, timedelta
from collections import defaultdict

st.set_page_config(
    page_title="🛡️ Threat Intelligence Platform",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded"
)

st.markdown("""
<style>
    /* Overall background */
    .stApp { background-color: #0d1117; }

    /* Metric cards */
    [data-testid="stMetric"] {
        background: linear-gradient(135deg, #161b22, #1c2333);
        border-radius: 12px;
        padding: 16px;
        border: 1px solid #30363d;
        box-shadow: 0 4px 12px rgba(0,0,0,0.3);
    }
    [data-testid="stMetricLabel"] { color: #8b949e !important; font-size: 0.8rem !important; font-weight: 600 !important; text-transform: uppercase; letter-spacing: 0.05em; }
    [data-testid="stMetricValue"] { color: #ffffff !important; font-size: 2.2rem !important; font-weight: 700 !important; }

    /* Severity badges */
    .badge-critical { background:#8b0000; color:#fff; padding:3px 10px; border-radius:20px; font-size:0.75rem; font-weight:700; }
    .badge-high     { background:#7d3c00; color:#fff; padding:3px 10px; border-radius:20px; font-size:0.75rem; font-weight:700; }
    .badge-medium   { background:#7d6608; color:#fff; padding:3px 10px; border-radius:20px; font-size:0.75rem; font-weight:700; }
    .badge-low      { background:#1a4731; color:#fff; padding:3px 10px; border-radius:20px; font-size:0.75rem; font-weight:700; }

    /* Section headers */
    h2, h3 { color: #58a6ff !important; }

    /* Expander styling */
    .streamlit-expanderHeader { background: #161b22 !important; border-radius: 8px !important; }

    /* Sidebar */
    [data-testid="stSidebar"] { background: #161b22 !important; border-right: 1px solid #30363d; }

    /* Info/success boxes */
    .stAlert { border-radius: 8px !important; }

    /* Divider */
    hr { border-color: #30363d !important; }

    /* Progress bar */
    .stProgress > div > div { background: linear-gradient(90deg, #1f6feb, #58a6ff); border-radius: 4px; }

    /* Hide streamlit branding */
    #MainMenu {visibility: hidden;}
    footer {visibility: hidden;}
</style>
""", unsafe_allow_html=True)

# ─── Header Banner ────────────────────────────────────────────────────────────
st.markdown("""
<div style="background:linear-gradient(135deg,#0d1117,#1c2333); border:1px solid #30363d; border-radius:12px; padding:24px 32px; margin-bottom:24px;">
    <div style="display:flex; align-items:center; gap:16px;">
        <span style="font-size:3rem;">🛡️</span>
        <div>
            <h1 style="color:#ffffff; margin:0; font-size:1.8rem; font-weight:700;">Threat Intelligence Platform</h1>
            <p style="color:#8b949e; margin:4px 0 0 0; font-size:0.95rem;">
                Multi-Agent Cybersecurity System &nbsp;·&nbsp; 
                Powered by <strong style="color:#58a6ff;">NVD CVE API</strong> + 
                <strong style="color:#58a6ff;">CISA KEV</strong> + 
                <strong style="color:#58a6ff;">llama3.1 AI</strong>
            </p>
        </div>
    </div>
</div>
""", unsafe_allow_html=True)

# ─── Data Loading ─────────────────────────────────────────────────────────────
def load_from_sqlite():
    db_path = os.path.abspath(os.path.join(os.path.dirname(__file__), '..', 'data', 'threats.db'))
    if not os.path.exists(db_path):
        return None, None, None, None
    conn = sqlite3.connect(db_path)
    cursor = conn.cursor()
    cursor.execute("""
        SELECT COUNT(*),
            SUM(CASE WHEN severity='Critical' THEN 1 ELSE 0 END),
            SUM(CASE WHEN severity='High' THEN 1 ELSE 0 END),
            SUM(CASE WHEN severity='Medium' THEN 1 ELSE 0 END),
            SUM(CASE WHEN severity='Low' THEN 1 ELSE 0 END),
            MAX(collected_at)
        FROM threats
    """)
    stats = cursor.fetchone()
    cursor.execute("""
        SELECT cve_id, severity, cvss_score, title, description,
               ai_summary, priority, threat_actor_interest, collected_at
        FROM threats ORDER BY
            CASE severity WHEN 'Critical' THEN 1 WHEN 'High' THEN 2 WHEN 'Medium' THEN 3 ELSE 4 END,
            cvss_score DESC
        LIMIT 100
    """)
    threats = cursor.fetchall()
    cursor.execute("SELECT source, COUNT(*) FROM threats GROUP BY source ORDER BY COUNT(*) DESC")
    sources = cursor.fetchall()
    cursor.execute("""
        SELECT DATE(collected_at) as day,
            SUM(CASE WHEN severity='Critical' THEN 1 ELSE 0 END),
            SUM(CASE WHEN severity='High' THEN 1 ELSE 0 END),
            SUM(CASE WHEN severity='Medium' THEN 1 ELSE 0 END),
            SUM(CASE WHEN severity='Low' THEN 1 ELSE 0 END),
            COUNT(*) FROM threats GROUP BY day ORDER BY day
    """)
    trend = cursor.fetchall()
    conn.close()
    return stats, threats, sources, trend

def load_from_json():
    json_path = os.path.abspath(os.path.join(os.path.dirname(__file__), '..', 'data', 'threats_export.json'))
    if not os.path.exists(json_path):
        return None, None, None, None
    with open(json_path) as f:
        data = json.load(f)
    s = data['stats']
    stats = (s['total'], s['critical'], s['high'], s['medium'], s['low'], s['last_collection'])
    threats = [(t.get('cve_id'), t.get('severity'), t.get('cvss_score'), t.get('title'),
                t.get('description'), t.get('ai_summary'), t.get('priority'),
                t.get('threat_actor_interest'), t.get('collected_at')) for t in data['threats']]
    sources = [(s['source'], s['count']) for s in data.get('sources', [])]
    day_map = defaultdict(lambda: [0,0,0,0,0])
    for t in data['threats']:
        day = (t.get('collected_at') or '')[:10]
        sev = (t.get('severity') or '').lower()
        if day:
            day_map[day][4] += 1
            if sev == 'critical': day_map[day][0] += 1
            elif sev == 'high': day_map[day][1] += 1
            elif sev == 'medium': day_map[day][2] += 1
            elif sev == 'low': day_map[day][3] += 1
    trend = [(d,v[0],v[1],v[2],v[3],v[4]) for d,v in sorted(day_map.items())]
    return stats, threats, sources, trend

stats, threats, source_data, trend_data = load_from_sqlite()
using_live_db = stats is not None
if not using_live_db:
    stats, threats, source_data, trend_data = load_from_json()
    st.info("📦 Showing snapshot data. Run `python3 main.py` locally for live AI analysis.")
if stats is None:
    st.error("⚠️ No data found. Run `python3 main.py` first to collect threats.")
    st.stop()

# ─── Sidebar ──────────────────────────────────────────────────────────────────
with st.sidebar:
    st.markdown("### 🔎 Filters")
    severity_filter = st.multiselect(
        "Severity",
        ["Critical", "High", "Medium", "Low"],
        default=["Critical", "High", "Medium", "Low"]
    )
    search_term = st.text_input("🔍 Search CVE or keyword", "")
    sort_by = st.radio("Sort by", ["Severity (worst first)", "Date (newest first)", "CVSS Score"])
    show_ai_only = st.checkbox("Only AI-analyzed threats", False)

    st.markdown("---")
    st.markdown("### 📊 Quick Stats")
    total = stats[0] or 0
    critical = stats[1] or 0
    st.markdown(f"**{total}** threats tracked")
    st.markdown(f"**{critical}** critical severity")
    pct = int((critical / total * 100)) if total > 0 else 0
    st.progress(pct / 100)
    st.caption(f"{pct}% are Critical")

    st.markdown("---")
    st.markdown("### 🔗 Links")
    st.markdown("**[📂 GitHub Repo](https://github.com/paulieboi33-stack/threat-intelligence-platform)**")
    st.markdown("**[🏛️ CISA KEV](https://www.cisa.gov/known-exploited-vulnerabilities-catalog)**")
    st.markdown("**[🔬 NVD CVE](https://nvd.nist.gov/vuln)**")
    st.markdown("---")
    st.caption("Built by **Paul Naeger**\nAI & ML · Lone Star College")

# ─── Stats Row ────────────────────────────────────────────────────────────────
last_run = (stats[5] or "")[:16]
col1, col2, col3, col4, col5, col6 = st.columns(6)
with col1: st.metric("🔍 Total Threats", stats[0] or 0)
with col2: st.metric("🚨 Critical", stats[1] or 0)
with col3: st.metric("⚠️ High", stats[2] or 0)
with col4: st.metric("🟠 Medium", stats[3] or 0)
with col5: st.metric("🟢 Low", stats[4] or 0)
with col6: st.metric("🕐 Last Run", last_run)

st.markdown("---")

# ─── Trend Chart ──────────────────────────────────────────────────────────────
st.markdown("### 📈 Threat Trend")
if trend_data and len(trend_data) >= 1:
    trend_df = pd.DataFrame(trend_data, columns=["Date","Critical","High","Medium","Low","Total"])
    trend_df = trend_df.sort_values("Date").set_index("Date")
    col_chart, col_peak = st.columns([3,1])
    with col_chart:
        st.line_chart(trend_df[["Critical","High","Medium","Low"]], height=220)
    with col_peak:
        st.markdown("**📊 Trend Summary**")
        peak_day = trend_df["Total"].idxmax()
        st.metric("Peak Day", peak_day)
        st.metric("Peak Threats", int(trend_df.loc[peak_day,"Total"]))
        st.metric("Days Tracked", len(trend_df))
        st.metric("Total Critical", int(trend_df["Critical"].sum()))
else:
    st.info("Trend data will appear after multiple pipeline runs.")

st.markdown("---")

# ─── Charts Row ───────────────────────────────────────────────────────────────
col1, col2, col3 = st.columns(3)

with col1:
    st.markdown("### 📊 Severity Breakdown")
    sev_df = pd.DataFrame({
        "Severity": ["Critical","High","Medium","Low"],
        "Count": [stats[1] or 0, stats[2] or 0, stats[3] or 0, stats[4] or 0]
    }).set_index("Severity")
    st.bar_chart(sev_df, height=200)

with col2:
    st.markdown("### 📡 Data Sources")
    if source_data:
        src_df = pd.DataFrame(source_data, columns=["Source","Count"]).set_index("Source")
        st.bar_chart(src_df, height=200)
    else:
        st.markdown("""
        - 🔬 **NVD CVE API** — Last 30 days
        - 🏛️ **CISA KEV** — 1,577 exploited vulns
        """)

with col3:
    st.markdown("### 🔧 Platform Status")
    st.markdown("""
    | Agent | Status |
    |-------|--------|
    | 🔍 Scout | 🟢 Active |
    | 🧠 Analyst (AI) | 🟢 Active |
    | 🐕 Watchdog | 🟢 Active |
    | 📊 Reporter | 🟢 Active |
    | ⏰ Auto-Run | 🟢 Every 6h |
    | 📧 Email Alerts | 🟢 Active |
    """)

st.markdown("---")

# ─── Threat Feed ──────────────────────────────────────────────────────────────
st.markdown("### 📋 Threat Intelligence Feed")

# Filter & sort
filtered = []
for t in threats:
    cve_id, severity, cvss, title, desc, ai_summary, priority, actor_interest, collected = t
    if severity not in severity_filter:
        continue
    if search_term:
        haystack = f"{cve_id} {title} {desc} {ai_summary}".lower()
        if search_term.lower() not in haystack:
            continue
    if show_ai_only and not ai_summary:
        continue
    filtered.append(t)

# Sort
if sort_by == "Date (newest first)":
    filtered.sort(key=lambda t: t[8] or "", reverse=True)
elif sort_by == "CVSS Score":
    filtered.sort(key=lambda t: t[2] or 0, reverse=True)

st.caption(f"Showing **{len(filtered)}** of **{len(threats)}** threats · {sort_by}")

if not filtered:
    st.info("No threats match your current filters.")
else:
    for t in filtered:
        cve_id, severity, cvss, title, desc, ai_summary, priority, actor_interest, collected = t

        sev_icon = {"Critical":"🔴","High":"🟠","Medium":"🟡","Low":"🟢"}.get(severity,"⚪")
        priority_text = f" · ⚡ {priority}" if priority else ""
        display_title = title if (title and title != "Unknown") else (desc[:70]+"..." if desc else cve_id)
        cvss_display = f"{cvss:.1f}" if cvss else "N/A"

        label = f"{sev_icon} **{cve_id}** — {display_title[:65]}  |  CVSS {cvss_display}{priority_text}"

        with st.expander(label):
            col_left, col_right = st.columns([3,1])

            with col_left:
                if ai_summary:
                    st.markdown("**🧠 AI Analysis:**")
                    st.info(ai_summary)
                elif desc:
                    st.markdown("**📄 Description:**")
                    st.write(desc[:300])

            with col_right:
                # Severity badge
                badge_class = f"badge-{severity.lower()}"
                st.markdown(f'<span class="{badge_class}">{severity}</span>', unsafe_allow_html=True)
                st.markdown(f"**CVE:** `{cve_id}`")

                # CVSS bar
                if cvss:
                    st.markdown(f"**CVSS:** {cvss_display} / 10")
                    st.progress(float(cvss) / 10)

                if priority:
                    st.markdown(f"**Priority:** {priority}")
                if actor_interest:
                    st.markdown(f"**Actor Interest:** {actor_interest}")
                if collected:
                    st.markdown(f"**Detected:** {collected[:10]}")

                # NVD link
                st.markdown(f"[🔗 View on NVD](https://nvd.nist.gov/vuln/detail/{cve_id})")

st.markdown("---")

# ─── How It Works ─────────────────────────────────────────────────────────────
st.markdown("### 🤖 How It Works — Multi-Agent Architecture")

col1, col2, col3, col4 = st.columns(4)
agents = [
    ("📥", "Scout Agent", "Collects live CVEs from NVD API v2.0 and CISA KEV — 1,577 actively exploited vulnerabilities tracked by the U.S. government."),
    ("🧠", "Analyst Agent", "Local AI (llama3.1:8b) reads each CVE and writes plain-English summaries, attack scenarios, and remediation steps."),
    ("🐕", "Watchdog Agent", "Compares threats against your organization's tech stack and fires priority alerts for relevant CVEs."),
    ("📊", "Reporter Agent", "Generates HTML, CSV, JSON, and Markdown reports. Sends email alerts for Critical threats automatically."),
]
for col, (icon, name, desc) in zip([col1,col2,col3,col4], agents):
    with col:
        st.markdown(f"""
        <div style="background:#161b22; border:1px solid #30363d; border-radius:10px; padding:16px; height:180px;">
            <div style="font-size:2rem; margin-bottom:8px;">{icon}</div>
            <strong style="color:#58a6ff;">{name}</strong>
            <p style="color:#8b949e; font-size:0.85rem; margin-top:8px;">{desc}</p>
        </div>
        """, unsafe_allow_html=True)

st.markdown("---")
st.markdown("""
<div style="text-align:center; color:#555; font-size:0.85rem; padding:12px;">
    🛡️ <strong>Threat Intelligence Platform</strong> · Built by <strong>Paul Naeger</strong> · 
    AI & ML Program, Lone Star College · 
    <a href="https://github.com/paulieboi33-stack/threat-intelligence-platform" style="color:#58a6ff;">GitHub</a>
</div>
""", unsafe_allow_html=True)
