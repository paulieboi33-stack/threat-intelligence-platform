# Multi-Agent Cybersecurity Threat Intelligence Platform
### Final Project — AI & Machine Learning AAS Program
### Lone Star College | Spring 2026
### Student: Paul Naeger

---

## Abstract

This project presents the design, development, and deployment of a **Multi-Agent Cybersecurity Threat Intelligence Platform** — an autonomous system that continuously monitors, collects, analyzes, and reports on real-world cybersecurity threats from multiple data sources, including live government vulnerability feeds and a physical iPhone 16 Pro. The platform integrates multiple specialized AI agents, live government threat feeds, a local large language model (LLM), mobile device forensics via USB, live network traffic interception via proxy, and the MITRE ATT&CK Enterprise Framework to deliver production-grade threat intelligence. The system runs autonomously every six hours, generating AI-powered threat summaries, mapping vulnerabilities to attack techniques, and presenting all findings through an interactive multi-page web dashboard deployed to the cloud.

---

## 1. Use Case and Problem Statement

Cybersecurity threats are growing at an unprecedented rate. In 2026, the National Vulnerability Database (NVD) tracks over 345,000 known vulnerabilities, with hundreds of new CVEs (Common Vulnerabilities and Exposures) published every week. The U.S. Cybersecurity and Infrastructure Security Agency (CISA) maintains a catalog of over 1,577 vulnerabilities actively being exploited by threat actors right now.

Beyond server-side threats, mobile devices represent a significant and often overlooked attack surface. The average person carries a smartphone containing financial apps, health data, communications, and location history — and most users have no visibility into what those apps are actually doing on the network.

**The use case:** Build an autonomous, AI-powered threat intelligence platform that:
1. Continuously collects real-world vulnerability data from authoritative government sources
2. Uses AI to translate technical CVE descriptions into plain-English summaries
3. Maps threats to the industry-standard MITRE ATT&CK framework used by the NSA, CISA, and major security vendors
4. Performs mobile device forensics on a real iPhone to identify risky apps and permissions
5. Captures and analyzes live network traffic from a mobile device to detect trackers, data collectors, and suspicious connections
6. Presents all findings through a live, multi-page web dashboard

---

## 2. Objectives

1. **Automate threat collection** — integrate with live APIs (NVD, CISA KEV) to pull real vulnerability data
2. **Apply AI analysis** — use a local LLM to generate plain-English threat summaries and remediation guidance
3. **Implement MITRE ATT&CK mapping** — classify each threat using the globally recognized ATT&CK Enterprise framework
4. **Mobile device forensics** — enumerate installed applications, device metadata, and crash logs from a real iPhone via USB (no jailbreak required)
5. **Network traffic analysis** — intercept and analyze real network traffic from a mobile device to detect trackers, ad networks, and suspicious data collectors
6. **Build a production-ready dashboard** — deploy a live multi-page Streamlit web application with charts, filters, and drill-down views
7. **Enable autonomous operation** — schedule the pipeline to run every six hours automatically

---

## 3. Technologies and Tools

| Category | Technology | Purpose |
|----------|------------|---------|
| **Language** | Python 3.9 | Core development language |
| **AI / LLM** | llama3.1:8b via Ollama | Local AI for threat analysis |
| **Web Framework** | Flask 3.1 | REST API server |
| **Dashboard** | Streamlit 1.50 | Interactive multi-page web dashboard |
| **Database** | SQLite | Threat data persistence |
| **Data Source** | NVD CVE API v2.0 | Live CVE vulnerability feed (NIST) |
| **Data Source** | CISA KEV JSON Feed | U.S. gov't actively exploited vulnerabilities |
| **Framework** | MITRE ATT&CK Enterprise | Attack tactic/technique classification |
| **Mobile Forensics** | libimobiledevice | iPhone USB data collection (no jailbreak) |
| **Mobile Forensics** | ideviceinstaller | iPhone app inventory enumeration |
| **Network Capture** | mitmproxy 12.2.2 | HTTPS traffic interception and analysis |
| **Version Control** | GitHub | Source code hosting |
| **Scheduling** | cron | Automated 6-hour pipeline runs |
| **Rich** | Python Rich library | Terminal output formatting |

---

## 4. System Design and Architecture

### 4.1 Multi-Agent Architecture

The platform is built on a **multi-agent architecture** where each agent is a specialized module responsible for one stage of the pipeline. Two new data collection agents were added: the **iPhone Collector Agent** (USB forensics) and the **Network Analyzer Agent** (traffic interception).

```
┌─────────────────────────────────────────────────────────────────┐
│                         Data Sources                            │
│  NVD CVE API v2.0  │  CISA KEV Feed  │  iPhone USB  │  mitmproxy│
└──────────┬──────────────────┬────────────────┬──────────────────┘
           │                  │                │
    ┌──────▼──────┐    ┌──────▼──────┐  ┌──────▼──────┐
    │ Scout Agent │    │  iPhone     │  │  Network    │
    │ (CVE/KEV)   │    │  Collector  │  │  Analyzer   │
    └──────┬──────┘    └──────┬──────┘  └──────┬──────┘
           │                  │                │
           └──────────────────┼────────────────┘
                              │
                     ┌────────▼────────┐
                     │ Analyst Agent   │  ← AI summaries via llama3.1:8b
                     └────────┬────────┘
                              │
                     ┌────────▼────────┐
                     │  MITRE Mapper   │  ← ATT&CK tactic/technique mapping
                     └────────┬────────┘
                              │
                     ┌────────▼────────┐
                     │ Watchdog Agent  │  ← Filters by org tech stack
                     └────────┬────────┘
                              │
                     ┌────────▼────────┐
                     │ Reporter Agent  │  ← HTML/CSV/JSON/MD reports
                     └────────┬────────┘
                              │
                   ┌──────────▼──────────┐
                   │    SQLite Database   │
                   └──────────┬──────────┘
                              │
              ┌───────────────▼────────────────┐
              │     Streamlit Dashboard        │
              │  📊 Dashboard | 📱 iPhone |    │
              │  📡 Network   | 🔍 Explorer    │
              └────────────────────────────────┘
```

### 4.2 Agent Descriptions

**Scout Agent** (`agents/api_integration.py`)
Connects to the NVD CVE API v2.0 and CISA KEV JSON feed. Collects up to 20 CVEs published in the last 30 days and the 20 most recent CISA Known Exploited Vulnerabilities. Normalizes data into a consistent schema and stores to SQLite.

**iPhone Collector Agent** (`agents/iphone_collector.py`)
Connects to a physical iPhone 16 Pro via USB using the libimobiledevice toolkit. No jailbreak is required. Collects: device metadata (model, iOS version, serial number, MAC addresses), full installed app inventory (430 apps enumerated), battery/power statistics, and crash logs. Analyzes apps against known risk patterns including suspicious bundle ID keywords, known risky publishers, and permission risk profiles. Classifies findings as HIGH / MEDIUM / LOW risk.

**Network Analyzer Agent** (`agents/network_analyzer.py`)
Reads traffic flows captured by mitmproxy from an iPhone connected through a HTTPS proxy. Extracts every domain the phone contacted, counts request frequency per domain, and matches against a database of 40+ known ad networks, tracker SDKs, and analytics platforms. Flags suspicious or undisclosed data collectors. Saves findings to the threat database for dashboard display.

**Analyst Agent** (`agents/analyst.py`)
Uses a locally-running large language model (llama3.1:8b via Ollama) to analyze each CVE. Generates plain-English summaries, attack scenarios, remediation recommendations, priority ratings, and threat actor interest levels. Runs entirely locally — no data leaves the machine.

**MITRE Mapper Agent** (`agents/mitre_mapper.py`)
Maps each CVE to the MITRE ATT&CK Enterprise Framework using keyword-based pattern matching. Identifies relevant tactics and specific techniques for every threat.

**Watchdog Agent** (`agents/watchdog.py`)
Compares threat data against a configurable organizational technology profile and generates priority alerts for threats affecting the known tech stack.

**Reporter Agent** (`agents/reporter.py`)
Generates comprehensive reports in HTML, JSON, CSV, and Markdown formats.

---

## 5. Data Collection

### 5.1 CVE and KEV Feeds

The National Vulnerability Database (NVD) provides a public REST API for CVE data. The platform queries the `/rest/json/cves/2.0` endpoint with a 30-day date filter. The CISA KEV catalog lists vulnerabilities confirmed as actively exploited by real threat actors — the highest-priority subset of all known vulnerabilities. The platform currently tracks **162 threats** collected across multiple pipeline runs.

### 5.2 iPhone Mobile Device Forensics

**Collection method:** USB connection using libimobiledevice (open-source, no jailbreak required). The iPhone must be unlocked and have "Trust" the connected computer.

**Data collected from Paul's iPhone 16 Pro (iOS 26.3.1):**

| Data Type | Result |
|-----------|--------|
| Total apps enumerated | 430 |
| HIGH risk findings | 2 |
| MEDIUM risk findings | 7 |
| LOW risk findings | 1 |
| Crash logs collected | 200+ |
| Battery level at scan | 81% |

**Key findings:**

| App | Risk | Reason |
|-----|------|--------|
| Voice Recorder (TapMedia) | HIGH | Microphone-access app from small publisher — potential for silent recording upload |
| Check In | HIGH | Name matches monitoring keyword pattern |
| Zoom | MEDIUM | Known aggressive data collection; camera/mic access |
| Zedge | MEDIUM | Wallpaper apps routinely request excessive permissions and track users |
| Cash App | MEDIUM | High-value financial target; ensure 2FA enabled |
| Wonder AI | MEDIUM | AI image app; unknown data upload practices |
| Crypto Pie | MEDIUM | Small/unknown publisher; verify legitimacy |

### 5.3 Live Network Traffic Analysis

**Collection method:** mitmproxy 12.2.2 configured as an HTTPS proxy. iPhone proxy settings pointed to Mac mini at 10.0.0.60:8080. mitmproxy CA certificate installed and trusted on iPhone. Traffic captured over a 15-minute active session while opening multiple apps.

**Results (249 HTTP/HTTPS flows captured):**

| Domain | Requests | Type | Finding |
|--------|----------|------|---------|
| zobj.net / zedge.net | 136 | Suspicious | Zedge app making constant background requests — highest volume by far |
| googleads.g.doubleclick.net | 14 | Tracker | Google ad/tracking network |
| pagead2.googlesyndication.com | 8 | Tracker | Google ad syndication |
| unity3d.com | 10 | Tracker | Unity game ad SDK phoning home |
| ep2.facebook.com | 5 | Tracker | Facebook tracking pixel firing without app open |
| singular.net | 3 | Tracker | Mobile attribution/analytics platform |

**Notable security finding — Certificate Pinning:**
When mitmproxy attempted to intercept traffic to `gateway.icloud.com`, the connection was refused with a TLS handshake failure. This is because Apple implements **certificate pinning** on iCloud connections — the app will only accept Apple's own certificate, not a proxy certificate. This is a deliberate security design that protects iCloud data from interception, including by proxies like mitmproxy. This behavior was observed and documented as a positive security control.

---

## 6. MITRE ATT&CK Framework Implementation

MITRE ATT&CK (Adversarial Tactics, Techniques, and Common Knowledge) is a globally-recognized knowledge base of cyber adversary behavior used by the NSA, CISA, FBI, and virtually every major cybersecurity vendor.

The MITRE Mapper agent uses keyword-based pattern matching on CVE titles, descriptions, and AI summaries. From the current threat database of 162 threats:

| Tactic | ID | Threats |
|--------|-----|---------|
| Execution | TA0002 | 24 |
| Initial Access | TA0001 | 19 |
| Persistence | TA0003 | 13 |
| Lateral Movement | TA0008 | 12 |
| Impact | TA0040 | 11 |
| Privilege Escalation | TA0004 | 7 |
| Exfiltration | TA0010 | 5 |
| Credential Access | TA0006 | 4 |

This distribution shows current threat actors are primarily focused on **Execution** and **Initial Access** — consistent with 2026 attack trends.

---

## 7. AI Implementation

The platform uses **llama3.1:8b**, an 8-billion parameter open-source LLM by Meta, running locally via Ollama. Key reasons: free, private (data never leaves the machine), fast (10-30 seconds per analysis on Apple M4), and capable enough for structured summarization.

Each threat is analyzed using a structured prompt instructing the model to output JSON containing: plain-English summary, attack scenario, remediation steps, priority rating, and threat actor interest level. Temperature is set to 0.2 for consistent, factual output.

---

## 8. Project Outcomes

### 8.1 Deployed System

| Component | Status |
|-----------|--------|
| Live Streamlit dashboard | ✅ https://threat-intelligence-platform-hwlwosewldz68jyv8f8wbn.streamlit.app |
| GitHub repository | ✅ https://github.com/paulieboi33-stack/threat-intelligence-platform |
| Threats collected | ✅ 162 CVEs (auto-updates every 6 hours) |
| iPhone app scan | ✅ 430 apps, 10 risks flagged |
| Network traffic capture | ✅ 249 flows, 4 trackers, 1 suspicious connection |
| Automated pipeline | ✅ Runs every 6 hours via cron |
| Cloud deployment | ✅ Auto-deploys on GitHub push |

### 8.2 Dashboard Pages

The Streamlit dashboard has four pages:

1. **📊 Dashboard** — Platform metrics, severity breakdown chart, top CVSS scores, threats over time, latest CVEs
2. **📱 iPhone Analysis** — Device info, app risk findings with expandable detail, full 430-app inventory table
3. **📡 Network Traffic** — Request volume by domain (bar chart), suspicious connections, tracker list with request counts
4. **🔍 Threat Explorer** — Full CVE database with severity/CVSS/keyword filters and per-CVE detail view

### 8.3 Test Results

```
Ran 12 tests in 0.798s
✅ ALL TESTS PASSED
```

---

## 9. Challenges

### 9.1 NVD API Migration
The NVD migrated their API from v1.0 to v2.0, changing endpoint URLs and response schemas. Required updating the endpoint, fixing CVSS field parsing, and adding date filters to retrieve recent CVEs.

### 9.2 mitmproxy Version Conflict
Two versions of mitmproxy were present: the Homebrew binary (v12.2.2) and the pip3 Python library (v9.0.1). The binary wrote flows in format version 21, which the old Python library could not read. Solved by using the mitmdump binary to export flows to JSON, which the analyzer then reads — bypassing the library version mismatch entirely.

### 9.3 iPhone Certificate Pinning
Several Apple services (iCloud, App Store) refused proxy connections due to certificate pinning. Rather than being a blocker, this became a documented security finding — demonstrating that Apple actively protects certain communications from interception.

### 9.4 Streamlit Cloud vs. Local Database
Streamlit Cloud cannot access the local SQLite database. Solved by including the database file in the GitHub repository and pushing updates after each collection run, triggering automatic cloud redeployment with fresh data.

### 9.5 Dependency Conflicts
The typing_extensions package version conflict between mitmproxy (required <4.5) and Streamlit (required >=4.10) caused the dashboard to crash. Resolved by upgrading to the latest version — Streamlit's requirement took precedence as the active web service.

---

## 10. Next Steps

1. **Docker containerization** — Package the platform for one-command deployment
2. **Additional threat feeds** — Shodan, Exploit-DB, MalwareBazaar
3. **Automated network capture** — Schedule mitmproxy sessions and auto-analyze traffic
4. **DNS monitoring** — Passive network analysis on home router without proxy setup
5. **iOS Shortcuts integration** — Automatic device data reporting via webhook on schedule
6. **PDF report generation** — Executive summary reports for non-technical audiences

---

## 11. References

1. MITRE ATT&CK Enterprise Framework. (2026). *MITRE Corporation*. https://attack.mitre.org
2. National Vulnerability Database CVE API v2.0. (2026). *NIST*. https://nvd.nist.gov/developers/vulnerabilities
3. CISA Known Exploited Vulnerabilities Catalog. (2026). *CISA*. https://www.cisa.gov/known-exploited-vulnerabilities-catalog
4. Meta AI. (2024). *Llama 3.1 Model Card*. https://github.com/meta-llama/llama-models
5. Ollama. (2024). *Run Large Language Models Locally*. https://ollama.com
6. libimobiledevice. (2024). *A cross-platform FOSS library for iOS devices*. https://libimobiledevice.org
7. mitmproxy. (2024). *An interactive HTTPS proxy*. https://mitmproxy.org
8. Streamlit Inc. (2024). *Streamlit Documentation*. https://docs.streamlit.io
9. First.org. (2023). *Common Vulnerability Scoring System v3.1 Specification*. https://www.first.org/cvss/specification-document

---

## Appendix A — File Structure

```
threat-intelligence-platform/
├── main.py                      # Main pipeline orchestrator
├── api.py                       # Flask REST API
├── webapp.py                    # Streamlit multi-page dashboard
├── agents/
│   ├── api_integration.py       # Scout Agent (NVD + CISA KEV)
│   ├── analyst.py               # Analyst Agent (AI/LLM)
│   ├── mitre_mapper.py          # MITRE ATT&CK Mapper
│   ├── watchdog.py              # Watchdog Agent
│   ├── reporter.py              # Reporter Agent
│   ├── alerter.py               # Email Alert Agent
│   ├── iphone_collector.py      # iPhone USB Forensics Agent
│   └── network_analyzer.py      # Network Traffic Analyzer Agent
├── scripts/
│   ├── iphone_setup.sh          # mitmproxy setup guide
│   └── push_to_github.sh        # Auto-push to trigger cloud redeploy
├── data/
│   ├── threats.db               # SQLite database (162 threats)
│   ├── iphone/
│   │   ├── full_analysis.json   # iPhone app scan results
│   │   └── crashes/             # iPhone crash logs (200+ files)
│   └── network/
│       ├── flows.mitm           # Raw mitmproxy capture
│       ├── flows_export.json    # Parsed flow data
│       └── network_analysis.json# Tracker/threat analysis
├── outputs/
│   ├── report.html              # Generated threat report
│   └── iphone_threat_report.html# iPhone threat assessment report
├── tests/
│   └── test_suite.py            # 12-test test suite
└── requirements.txt             # Python dependencies
```

## Appendix B — API Endpoints

| Method | Endpoint | Description |
|--------|----------|-------------|
| GET | `/api/status` | Platform status and statistics |
| GET | `/api/threats` | All threats (filterable) |
| GET | `/api/threats/<cve_id>` | Single threat detail |
| GET | `/api/critical` | Critical threats only |
| GET | `/api/mitre` | MITRE ATT&CK tactic distribution |
| POST | `/api/run` | Trigger a collection pipeline run |

---

*Submitted in partial fulfillment of the requirements for the AI & Machine Learning AAS Program*
*Lone Star College | Spring 2026 | Paul Naeger*
