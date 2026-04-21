# Multi-Agent Cybersecurity Threat Intelligence Platform
### Final Project — AI & Machine Learning AAS Program
### Lone Star College | Spring 2026
### Student: Paul Naeger

---

## Abstract

This project presents the design, development, and deployment of a **Multi-Agent Cybersecurity Threat Intelligence Platform** — an autonomous system that continuously monitors, collects, analyzes, and reports on real-world cybersecurity threats. The platform integrates multiple specialized AI agents, live government threat feeds, a local large language model (LLM), and the MITRE ATT&CK Enterprise Framework to deliver production-grade threat intelligence. The system runs autonomously every six hours, generating AI-powered threat summaries, mapping vulnerabilities to attack techniques, and delivering email alerts to security personnel. This paper describes the use case, objectives, system design, tools and technologies, implementation, outcomes, challenges encountered, and future directions.

---

## 1. Use Case and Problem Statement

Cybersecurity threats are growing at an unprecedented rate. In 2026, the National Vulnerability Database (NVD) tracks over 345,000 known vulnerabilities, with hundreds of new CVEs (Common Vulnerabilities and Exposures) published every week. The U.S. Cybersecurity and Infrastructure Security Agency (CISA) maintains a catalog of over 1,577 vulnerabilities that are actively being exploited by threat actors right now.

The challenge for most organizations — especially small and mid-sized businesses — is that monitoring this volume of threat data manually is impossible. Security teams are overwhelmed, and critical vulnerabilities often go unpatched because organizations simply do not know they exist.

**The use case:** Build an autonomous, AI-powered threat intelligence platform that:
1. Continuously collects real-world vulnerability data from authoritative government sources
2. Uses artificial intelligence to translate technical CVE descriptions into plain-English summaries that non-technical stakeholders can understand
3. Maps threats to the industry-standard MITRE ATT&CK framework used by the NSA, CISA, and major security vendors
4. Automatically alerts security personnel when critical threats are detected
5. Presents all data through an interactive web dashboard accessible from any device

---

## 2. Objectives

The primary objectives of this project were:

1. **Automate threat collection** — integrate with live APIs (NVD, CISA KEV) to pull real vulnerability data without human intervention
2. **Apply AI analysis** — use a local large language model to generate plain-English threat summaries, attack scenarios, and remediation recommendations
3. **Implement MITRE ATT&CK mapping** — automatically classify each threat using the globally recognized ATT&CK Enterprise framework (14 tactics, 200+ techniques)
4. **Build a production-ready dashboard** — deploy a live Streamlit web application showing trend charts, severity breakdowns, and AI-analyzed threat cards
5. **Enable autonomous operation** — schedule the platform to run every six hours automatically, with email alerts for critical findings
6. **Demonstrate portfolio-quality engineering** — write tests, document the code, deploy to GitHub, and expose a REST API

---

## 3. Technologies and Tools

| Category | Technology | Purpose |
|----------|------------|---------|
| **Language** | Python 3.9 | Core development language |
| **AI / LLM** | llama3.1:8b via Ollama | Local AI for threat analysis |
| **Web Framework** | Flask 3.1 | REST API server |
| **Dashboard** | Streamlit 1.50 | Interactive web dashboard |
| **Database** | SQLite | Threat data persistence |
| **Data Sources** | NVD CVE API v2.0 | Live CVE vulnerability feed |
| **Data Sources** | CISA KEV JSON Feed | U.S. gov't actively exploited vulns |
| **Framework** | MITRE ATT&CK Enterprise | Attack tactic/technique classification |
| **Alerting** | Gmail API (gog CLI) | Email alerts for critical threats |
| **Tunneling** | ngrok | Public access to local API |
| **Version Control** | GitHub | Source code hosting and portfolio |
| **Rich** | Python Rich library | Terminal output formatting |
| **Scheduling** | OpenClaw Cron | Automated 6-hour pipeline runs |

---

## 4. System Design and Architecture

### 4.1 Multi-Agent Architecture

The platform is built on a **multi-agent architecture**, where each agent is a specialized module responsible for one stage of the threat intelligence pipeline. Agents run sequentially, passing data to the next agent in the chain.

```
┌─────────────────────────────────────────────────────────┐
│                    Data Sources                         │
│  NVD CVE API v2.0  │  CISA KEV Feed  │  MalwareBazaar  │
└────────────┬────────────────┬──────────────────────────-┘
             └────────────────┘
                      │
             ┌────────▼────────┐
             │  Scout Agent    │  ← Collects & normalizes threats
             └────────┬────────┘
                      │
             ┌────────▼────────┐
             │ Analyst Agent   │  ← AI summaries via llama3.1:8b
             └────────┬────────┘
                      │
             ┌────────▼────────┐
             │ MITRE Mapper    │  ← Maps to ATT&CK tactics/techniques
             └────────┬────────┘
                      │
             ┌────────▼────────┐
             │Watchdog Agent   │  ← Filters by org tech stack
             └────────┬────────┘
                      │
             ┌────────▼────────┐
             │ Reporter Agent  │  ← HTML/CSV/JSON/MD reports
             └────────┬────────┘
                      │
             ┌────────▼────────┐
             │ Alerter Agent   │  ← Email alerts for Critical CVEs
             └─────────────────┘
                      │
          ┌───────────▼──────────┐
          │    SQLite Database   │
          │  (90-day retention)  │
          └───────────┬──────────┘
                      │
          ┌───────────▼──────────┐
          │  Streamlit Dashboard │  ← Live web UI
          │  Flask REST API      │  ← Programmatic access
          └──────────────────────┘
```

### 4.2 Agent Descriptions

**Scout Agent** (`agents/api_integration.py`)
Connects to the NVD CVE API v2.0 and CISA KEV JSON feed. Collects up to 20 CVEs published in the last 30 days from NVD and the 20 most recent entries from the CISA Known Exploited Vulnerabilities catalog. Normalizes data into a consistent schema and passes to the next agent.

**Analyst Agent** (`agents/analyst.py`)
Uses a locally-running large language model (llama3.1:8b via Ollama) to analyze each CVE. For every threat, the AI generates:
- A plain-English summary (2-3 sentences for non-technical readers)
- An attack scenario describing how a threat actor would exploit the vulnerability
- Specific remediation recommendations
- A priority rating (Patch Immediately / Patch This Week / Monitor / Low Priority)
- A threat actor interest level (High / Medium / Low)

This agent processes threats entirely locally — no cloud API calls, no cost, no data leaving the machine.

**MITRE Mapper Agent** (`agents/mitre_mapper.py`)
Maps each CVE to the MITRE ATT&CK Enterprise Framework using keyword-based pattern matching against CVE titles, descriptions, and AI summaries. Identifies the relevant tactic (e.g., Initial Access, Privilege Escalation, Exfiltration) and specific technique (e.g., T1190 Exploit Public-Facing Application, T1068 Exploitation for Privilege Escalation). Results are stored in the database and visualized in the dashboard.

**Watchdog Agent** (`agents/watchdog.py`)
Compares threat data against a configurable organizational technology profile (Apache, Linux, WordPress, MySQL, Python). Generates priority alerts for threats that directly affect the organization's known technology stack.

**Reporter Agent** (`agents/reporter.py`)
Generates comprehensive reports in four formats: HTML (with charts and styling), JSON (for API consumption), CSV (for spreadsheet analysis), and Markdown (for documentation). Reports include executive summaries, top threats, severity distributions, and trend analysis.

**Alerter Agent** (`agents/alerter.py`)
After each pipeline run, checks for new Critical severity threats that have not been alerted on previously. If found, sends a formatted HTML email via Gmail to the designated recipient. Maintains a state file to prevent duplicate alerts.

### 4.3 Data Flow

1. Pipeline triggered (automatic every 6 hours, or manually via API/dashboard)
2. Scout Agent pulls 40 threats from NVD + CISA KEV
3. Analyst Agent processes up to 20 threats through llama3.1:8b AI
4. MITRE Mapper assigns ATT&CK tactics and techniques to all threats
5. Watchdog Agent generates relevance alerts
6. Reporter Agent generates HTML/CSV/JSON/MD reports
7. Alerter Agent sends email for any new Critical threats
8. All data saved to SQLite with 90-day retention policy
9. Dashboard and API serve updated data in real time

---

## 5. Data Collection

### 5.1 NVD CVE API v2.0

The National Vulnerability Database, maintained by NIST (National Institute of Standards and Technology), provides a public REST API for accessing CVE data. The platform queries the `/rest/json/cves/2.0` endpoint with a 30-day date filter to retrieve recently published vulnerabilities. Each CVE record includes:
- CVE identifier (e.g., CVE-2026-24060)
- CVSS (Common Vulnerability Scoring System) score (0.0–10.0)
- Severity classification (Critical/High/Medium/Low)
- Full technical description
- Publication and modification dates
- References and advisories

### 5.2 CISA Known Exploited Vulnerabilities (KEV)

The CISA KEV catalog is a JSON feed published by the U.S. government listing vulnerabilities that have been confirmed as actively exploited by threat actors. Unlike the NVD which lists all known vulnerabilities, the KEV catalog represents the highest-priority threats — ones that real attackers are using right now. The catalog currently contains 1,577 entries. The platform collects the 20 most recent additions on each run.

### 5.3 Database Schema

All collected threats are stored in a SQLite database (`data/threats.db`) with the following key fields:

| Field | Type | Description |
|-------|------|-------------|
| cve_id | TEXT | CVE identifier |
| severity | TEXT | Critical/High/Medium/Low |
| cvss_score | REAL | CVSS base score (0-10) |
| title | TEXT | Vulnerability name |
| description | TEXT | Technical description |
| ai_summary | TEXT | AI-generated plain English summary |
| priority | TEXT | AI-assigned priority rating |
| mitre_tactics | TEXT | JSON array of ATT&CK tactics |
| mitre_techniques | TEXT | JSON array of ATT&CK techniques |
| collected_at | TEXT | Timestamp of collection |

---

## 6. MITRE ATT&CK Framework Implementation

### 6.1 What is MITRE ATT&CK?

MITRE ATT&CK (Adversarial Tactics, Techniques, and Common Knowledge) is a globally-recognized knowledge base of cyber adversary behavior. It is maintained by the MITRE Corporation and used by the NSA, CISA, FBI, and virtually every major cybersecurity vendor including CrowdStrike, Splunk, Microsoft Defender, and Palo Alto Networks.

The Enterprise framework organizes attacks into 14 **tactics** (the "why" — what the attacker is trying to achieve) and over 200 **techniques** (the "how" — specific methods used).

### 6.2 Mapping Methodology

The platform's MITRE Mapper agent uses keyword-based pattern matching to map each CVE to the appropriate tactic(s) and technique(s). The matching logic analyzes the CVE title, technical description, and AI-generated summary for keywords associated with each technique. For example:

- Keywords like "privilege escalation," "elevated privileges," "unauthorized actor," "improper authorization" → **TA0004 Privilege Escalation** / **T1068 Exploitation for Privilege Escalation**
- Keywords like "path traversal," "directory traversal," "remote code execution," "unauthenticated" → **TA0001 Initial Access** / **T1190 Exploit Public-Facing Application**
- Keywords like "information disclosure," "data exposure," "sensitive information" → **TA0007 Discovery** / **T1046 Network Service Discovery**

### 6.3 Results

From the current threat database of 62 threats, the MITRE mapper identified the following tactic distribution:

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
| Discovery | TA0007 | 4 |

This distribution reveals that current threat actors are primarily focused on **Execution** (running malicious code) and **Initial Access** (breaking into systems), consistent with observed attack trends in 2026.

---

## 7. AI Implementation

### 7.1 Model Selection

The platform uses **llama3.1:8b**, an 8-billion parameter open-source large language model developed by Meta and run locally via Ollama. Key reasons for this choice:

- **Free** — no API costs, runs on local hardware
- **Private** — threat data never leaves the machine
- **Fast** — processes one CVE analysis in 10-30 seconds on Apple M4
- **Capable** — 8B parameters sufficient for structured summarization tasks

### 7.2 Prompt Engineering

Each threat is analyzed using a structured prompt that instructs the model to output valid JSON containing five specific fields. The temperature is set to 0.2 (low randomness) to ensure consistent, factual output. Example output for CVE-2026-20122 (Cisco SD-WAN):

> **Plain English:** "A vulnerability in Cisco's SD-WAN Manager allows an attacker to gain elevated access on a network if they have already been authenticated."
>
> **Attack Scenario:** "An attacker could exploit this by authenticating to the system and then using the vulnerable API to escalate their privileges, potentially leading to unauthorized access or data modification."
>
> **Remediation:** "Apply the latest patches from Cisco as soon as possible. In the meantime, consider restricting access to the system and monitoring for suspicious activity."
>
> **Priority:** Patch Immediately
>
> **Threat Actor Interest:** High

### 7.3 AI Analysis Results

In the current dataset of 62 threats, the AI analyst successfully generated summaries for 42 threats. All summaries were validated for accuracy against the original CVE descriptions.

---

## 8. Project Outcomes

### 8.1 Functional System

The platform is fully operational and deployed:

- **Live dashboard:** https://threat-intelligence-platform-hwlwosewldz68jyv8f8wbn.streamlit.app
- **GitHub repository:** https://github.com/paulieboi33-stack/threat-intelligence-platform
- **62 threats** collected, analyzed, and stored
- **100% MITRE mapped** — all 62 threats assigned to ATT&CK tactics/techniques
- **Automated** — runs every 6 hours via scheduled cron job
- **Email alerts** live — Critical CVEs trigger automatic Gmail notifications
- **REST API** — 6 endpoints for programmatic access
- **Mobile control panel** — accessible from phone via ngrok tunnel

### 8.2 Technical Achievements

- Integrated two live government APIs (NVD, CISA KEV) with proper error handling and rate limiting
- Implemented local AI inference pipeline with structured JSON output
- Built MITRE ATT&CK mapping covering 13 tactics and 16 techniques
- Deployed production Streamlit dashboard with dark/light themes, filters, search
- Created Flask REST API with 6 endpoints
- Established automated scheduling (every 6 hours) with zero manual intervention
- Wrote comprehensive test suite (12 tests, all passing)

### 8.3 Test Results

```
Ran 12 tests in 0.798s
✅ ALL TESTS PASSED
```

Tests cover: API integration, CVSS severity calculation, threat data validation, watchdog relevance filtering, and organization profile loading.

---

## 9. Challenges

### 9.1 NVD API Migration
The NVD migrated their API from version 1.0 to 2.0, which changed the endpoint URL and response schema. The original platform was returning 404 errors. This required updating the endpoint from `/cves` to `/cves/2.0`, fixing the CVSS data parsing (field names changed), and adding date filters to retrieve recent CVEs instead of historical data going back to 1988.

### 9.2 AI Model Timeout Issues
The initial implementation used qwen2.5:32b (32 billion parameters) for AI analysis. While more capable, this model required too much time to load into memory and caused HTTP timeout errors. The solution was to fall back to llama3.1:8b, which is already loaded in memory and responds within the timeout window while still producing high-quality analysis.

### 9.3 Streamlit Cloud Deployment
The Streamlit Cloud deployment could not connect to the local SQLite database (which only exists on the development machine). This was solved by exporting a JSON snapshot of the threat data to the repository, which the dashboard loads as a fallback when the database is not available. The live local version uses real-time database queries.

### 9.4 Database Schema Evolution
As new features were added (AI analysis columns, MITRE mapping columns, priority fields), the SQLite database schema needed to evolve. Since SQLite does not support automatic migrations, `ALTER TABLE` statements were added to the code to safely add new columns if they did not already exist, preserving existing data.

---

## 10. Next Steps

1. **Docker containerization** — Package the entire platform into a Docker container for one-command deployment on any machine
2. **REST API public deployment** — Host the Flask API on a cloud server (AWS/GCP) for permanent public access
3. **Additional data sources** — Integrate Shodan (exposed asset scanning), Exploit-DB (public exploits), and MalwareBazaar (active malware samples)
4. **Enhanced MITRE mapping** — Download the full MITRE CTI dataset for more precise technique matching
5. **Executive reporting** — Generate weekly PDF reports with trend analysis and executive summaries
6. **Custom org profiles** — Allow users to configure their own technology stack for personalized watchdog alerts
7. **ClearWater Automation integration** — Use this threat intelligence platform to power security features in the ClearWater AI front desk product

---

## 11. References

1. MITRE ATT&CK Enterprise Framework. (2026). *MITRE Corporation*. https://attack.mitre.org
2. National Vulnerability Database CVE API v2.0. (2026). *NIST*. https://nvd.nist.gov/developers/vulnerabilities
3. CISA Known Exploited Vulnerabilities Catalog. (2026). *Cybersecurity and Infrastructure Security Agency*. https://www.cisa.gov/known-exploited-vulnerabilities-catalog
4. Meta AI. (2024). *Llama 3.1 Model Card*. https://github.com/meta-llama/llama-models
5. Ollama. (2024). *Run Large Language Models Locally*. https://ollama.com
6. Streamlit Inc. (2024). *Streamlit Documentation*. https://docs.streamlit.io
7. Stoneburner, G., Goguen, A., & Feringa, A. (2002). *Risk Management Guide for Information Technology Systems*. NIST Special Publication 800-30.
8. First.org. (2023). *Common Vulnerability Scoring System v3.1 Specification*. https://www.first.org/cvss/specification-document

---

## Appendix A — File Structure

```
threat-intelligence-platform/
├── main.py                    # Main pipeline orchestrator
├── api.py                     # Flask REST API
├── agents/
│   ├── api_integration.py     # Scout Agent (NVD + CISA KEV)
│   ├── analyst.py             # Analyst Agent (AI/LLM)
│   ├── mitre_mapper.py        # MITRE ATT&CK Mapper Agent
│   ├── watchdog.py            # Watchdog Agent
│   ├── reporter.py            # Reporter Agent
│   └── alerter.py             # Email Alert Agent
├── scripts/
│   └── app.py                 # Streamlit Dashboard
├── templates/
│   ├── report.html            # HTML report template
│   └── control.html           # Mobile control panel
├── data/
│   ├── threats.db             # SQLite database
│   ├── threats_export.json    # JSON snapshot for cloud deployment
│   └── org_profile.json       # Organization tech stack config
├── tests/
│   └── test_suite.py          # 12-test test suite
├── outputs/                   # Generated reports
└── requirements.txt           # Python dependencies
```

## Appendix B — API Endpoints

| Method | Endpoint | Description |
|--------|----------|-------------|
| GET | `/api/status` | Platform status and statistics |
| GET | `/api/threats` | All threats (filterable by severity, search) |
| GET | `/api/threats/<cve_id>` | Single threat detail |
| GET | `/api/critical` | Critical threats only |
| GET | `/api/mitre` | MITRE ATT&CK tactic distribution |
| POST | `/api/run` | Trigger a collection pipeline run |
| GET | `/api/run/status` | Check pipeline run status |
| GET | `/control` | Mobile control panel (HTML) |

---

*Submitted in partial fulfillment of the requirements for the AI & Machine Learning AAS Program*
*Lone Star College | Spring 2026*
*Paul Naeger*
