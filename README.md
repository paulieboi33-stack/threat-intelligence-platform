# 🛡️ Multi-Agent Threat Intelligence Platform

[![Python](https://img.shields.io/badge/Python-3.9+-blue?style=flat-square&logo=python)](https://python.org)
[![Streamlit](https://img.shields.io/badge/Streamlit-Dashboard-red?style=flat-square&logo=streamlit)](https://streamlit.io)
[![License](https://img.shields.io/badge/License-MIT-green?style=flat-square)](LICENSE)
[![CVEs Tracked](https://img.shields.io/badge/Live%20Data-NVD%20%2B%20CISA%20KEV-orange?style=flat-square)](https://nvd.nist.gov)
[![Tests](https://img.shields.io/badge/Tests-12%20Passing-brightgreen?style=flat-square)]()

> **AI & Machine Learning Portfolio Project — Lone Star College**
> A production-grade cybersecurity threat intelligence platform powered by multiple specialized AI agents.

---

## 🎯 What This Does

This platform automatically monitors, collects, analyzes, and reports on real-world cybersecurity threats — 24/7 — using a team of coordinated AI agents. It pulls live data from government threat feeds and the National Vulnerability Database, then generates actionable reports.

**Real data. Real threats. Right now.**

---

## 🤖 The Agent Team

| Agent | Role | Data Sources |
|-------|------|-------------|
| **🔍 Scout** | Collects threats from live APIs | NVD CVE API v2.0, CISA KEV |
| **🧠 Analyst** | Enriches threats with AI scoring | CVSS metrics, exploit analysis |
| **🐕 Watchdog** | Filters threats by relevance | Org tech stack profile |
| **📊 Reporter** | Generates multi-format reports | HTML, JSON, CSV, Markdown |

---

## 📡 Live Data Sources

- **[NVD (National Vulnerability Database)](https://nvd.nist.gov/developers/vulnerabilities)** — NIST's official CVE feed, updated daily. Pulls the last 30 days of new vulnerabilities with CVSS scores.
- **[CISA Known Exploited Vulnerabilities](https://www.cisa.gov/known-exploited-vulnerabilities-catalog)** — 1,500+ CVEs the U.S. government has confirmed are actively being exploited in the wild right now.

---

## 🖥️ Dashboard

Real-time Streamlit dashboard showing:
- Live threat counts by severity (Critical / High / Medium / Low)
- Recent threat feed with CVE IDs and scores
- Threat source breakdown
- Multi-agent health status
- Generated report library

![Dashboard](outputs/report.md)

---

## 🚀 Quick Start

### Requirements
- Python 3.9+
- pip

### Install

```bash
git clone https://github.com/paulieboi33-stack/threat-intelligence-platform.git
cd threat-intelligence-platform
pip install -r requirements.txt
```

### Run the Platform

```bash
# Full pipeline: collect → analyze → alert → report
python3 main.py
```

### Launch Dashboard

```bash
python3 -m streamlit run scripts/app.py
# Open http://localhost:8501
```

### Run Tests

```bash
python3 tests/test_suite.py
```

---

## 📁 Project Structure

```
threat-intelligence-platform/
├── agents/
│   ├── api_integration.py   # Live API clients (NVD, CISA KEV)
│   ├── scout.py             # Threat collection agent
│   ├── analyst.py           # AI threat enrichment agent
│   ├── watchdog.py          # Relevance filtering agent
│   └── reporter.py          # Report generation agent
├── scripts/
│   └── app.py               # Streamlit dashboard
├── templates/
│   └── report.html          # HTML report template
├── data/
│   ├── threats.db           # SQLite threat database
│   └── org_profile.json     # Target environment config
├── tests/
│   └── test_suite.py        # Test suite (12 tests, all passing)
├── outputs/                 # Generated reports
└── main.py                  # Main orchestrator
```

---

## 📊 Sample Output

```
🔍 Phase 1: Threat Collection
  ✓ NVD API: Retrieved 20 CVEs (last 30 days)
  ✓ CISA KEV: Retrieved 20 actively-exploited vulnerabilities

🧠 Phase 2: AI Analysis
  ✓ Analyzed 40 threats
  ✓ Critical: 22 | High: 5 | Medium: 13 | Low: 2

🐕 Phase 3: Watchdog Alerts
  ⚠️  8 threats match your tech stack

📊 Phase 4: Reports Generated
  ✓ HTML Report
  ✓ JSON Export
  ✓ CSV Export
  ✓ Markdown Summary
```

---

## 🧪 Tests

```bash
$ python3 tests/test_suite.py

Ran 12 tests in 0.798s
✅ ALL TESTS PASSED!
```

Test coverage includes:
- API integration (NVD, CISA KEV)
- CVSS severity calculation
- Threat data loading and validation
- Watchdog relevance filtering
- Organization profile loading

---

## 🗺️ Architecture

```
┌─────────────────────────────────────────────────────┐
│                   main.py (Orchestrator)            │
└──────────┬──────────┬──────────┬────────────────────┘
           │          │          │
    ┌──────▼──┐  ┌────▼────┐ ┌──▼──────┐  ┌──────────┐
    │  Scout  │  │Analyst  │ │Watchdog │  │ Reporter │
    │  Agent  │  │  Agent  │ │  Agent  │  │  Agent   │
    └──────┬──┘  └────┬────┘ └──┬──────┘  └──────────┘
           │          │          │
    ┌──────▼──────────▼──────────▼────────┐
    │         SQLite Database             │
    │    (threats, scores, alerts)        │
    └─────────────────────────────────────┘
           │
    ┌──────▼──────────┐
    │  Streamlit UI   │
    │  localhost:8501 │
    └─────────────────┘
```

---

## 🔧 Configuration

Edit `data/org_profile.json` to customize the watchdog for your organization's tech stack:

```json
{
  "tech_stack": ["Windows", "Linux", "Apache", "Python", "MySQL"],
  "critical_assets": ["web-server", "database", "auth-service"],
  "alert_threshold": "High"
}
```

---

## 📈 Roadmap

- [ ] Shodan integration for exposed asset scanning
- [ ] Email/Slack alerting for critical CVEs
- [ ] AI-generated executive summaries (LLM)
- [ ] Exploit PoC detection from GitHub
- [ ] MITRE ATT&CK framework mapping
- [ ] Docker containerization

---

## 👤 About

Built by **Paul Naeger** as a portfolio project for the **AI & Machine Learning AAS program** at Lone Star College, Texas.

Demonstrates: multi-agent system design, REST API integration, SQLite data persistence, real-time dashboards, automated reporting, and test-driven development.

---

## 📄 License

MIT License — see [LICENSE](LICENSE) for details.
