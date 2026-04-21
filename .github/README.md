# 🛡️ Threat Intelligence Platform

![Build Status](https://img.shields.io/badge/build-passing-green)
![Python](https://img.shields.io/badge/python-3.9+-blue)
![MITRE ATT&CK](https://img.shields.io/badge/MITRE-ATT%26CK-yellow)
![Tests](https://img.shields.io/badge/tests-12%20passing-green)
![Visualizations](https://img.shields.io/badge/visualizations-Plotly%20%7C%20Matplotlib-green)
![ML](https://img.shields.io/badge/ML-Scikit%20Learn-orange)

> **Multi-Agent Cybersecurity Threat Intelligence System** - Automated threat collection, AI-powered analysis, beautiful visualizations, and presentation-ready reporting

## 🎯 Overview

This production-grade threat intelligence platform automates cybersecurity operations by:
- **Collecting** threats from 7+ live APIs (CISA, NVD, MalwareBazaar, GitHub CVE, Exploit-DB)
- **Analyzing** with AI-generated summaries and MITRE ATT&CK mapping
- **Scoring** threats using custom TPS algorithm
- **Alerting** on threats affecting your specific tech stack
- **Reporting** in multiple formats (HTML, console, markdown, CSV, PDF)
- **Visualizing** with interactive Plotly charts and heatmaps
- **Dashboard** with Streamlit web interface

**What it does:** What a junior SOC analyst does manually in hours, this system completes in minutes — with beautiful visualizations and interactive dashboards!

## 🚀 Quick Start

### Prerequisites
- Python 3.9+
- pip3
- Git

### Installation

```bash
# Clone repository
git clone https://github.com/YOUR_USERNAME/threat-intelligence-platform.git
cd threat-intelligence-platform

# Install core dependencies
pip3 install -r requirements.txt

# Install visualization & ML packages (optional but recommended)
pip3 install -r requirements_additional.txt

# Run platform
python3 main.py

# Run tests
python3 tests/test_suite.py

# Create beautiful visualizations
python3 scripts/create_visualizations.py

# Launch web dashboard
streamlit run scripts/app.py
```

## 📊 Enhanced Visualization Features

### Interactive Charts:
- 📈 **MITRE ATT&CK Heatmap** - Attack technique distribution
- 🍩 **Severity Distribution** - Pie charts showing threat breakdown
- 📉 **Trend Analysis** - Threat discovery over time
- 📊 **Vendor Impact** - Top affected software vendors
- 🎨 **Custom Visualizations** - Any chart you need

### Create Visualizations:
```bash
python3 scripts/create_visualizations.py
```

### Outputs:
- `outputs/heatmap.html` - Interactive MITRE ATT&CK heatmap
- `outputs/severity_pie.html` - Severity distribution chart
- `outputs/trend_chart.html` - Threat trends over time
- `outputs/vendor_chart.html` - Most affected vendors
- `outputs/report.html` - Main HTML report

### Example Visualization Output:
```
📊 Creating Threat Intelligence Visualizations
✓ Heatmap saved to outputs/heatmap.html
✓ Severity pie chart saved to outputs/severity_pie.html
✓ Trend chart saved to outputs/trend_chart.html
✓ Vendor chart saved to outputs/vendor_chart.html

📊 All visualizations created successfully!
```

## 🤖 Machine Learning (Optional)

### Scikit-learn Integration:
- **Threat Clustering** - Group similar vulnerabilities
- **Prediction Models** - Predict emerging threats
- **Anomaly Detection** - Identify unusual threat patterns

### XGBoost for Advanced Analysis:
- **Gradient Boosting** - More accurate predictions
- **Feature Importance** - Understand threat drivers
- **Cross-validation** - Model performance testing

## 🌐 Web Dashboard (Streamlit)

### Access Interactive Dashboard:
```bash
streamlit run scripts/app.py
```

**Features:**
- 📊 Live threat feed visualization
- 📈 Interactive MITRE ATT&CK heatmap
- 🎯 Critical threat alerts
- 📋 Severity distribution charts
- 🔍 Search and filter threats
- 📥 Export data to CSV/JSON
- 🖥️ Mobile-friendly interface

**Access:** http://localhost:8501

## 📁 Project Structure

```
threat-intelligence-platform/
├── main.py                       # Main orchestrator
├── requirements.txt              # Core dependencies
├── requirements_additional.txt   # Visualization & ML packages
├── setup.sh                     # Automated setup script
├── tests/
│   └── test_suite.py            # Comprehensive test suite (12 tests)
├── agents/
│   ├── scout.py                 # Threat collection agent
│   ├── reporter.py              # Report generation agent
│   ├── watchdog.py              # Alerting agent
│   ├── api_integration.py       # API client layer
│   └── additional_feeds.py      # Additional data sources
├── data/
│   ├── persistence.py           # Database & storage layer
│   ├── export.py                # Export utilities
│   └── org_profile.json         # Target environment config
├── scripts/
│   ├── create_visualizations.py # Plotly/Matplotlib visualizations
│   └── app.py                   # Streamlit web dashboard
├── templates/
│   └── report.html              # HTML dashboard template
├── outputs/
│   ├── report.html              # Generated HTML reports
│   ├── heatmap.html             # Interactive MITRE ATT&CK heatmap
│   ├── severity_pie.html        # Severity distribution chart
│   ├── trend_chart.html         # Threat trends over time
│   ├── vendor_chart.html        # Vendor impact analysis
│   └── threats_export.json      # Exported threat data
└── README.md                    # Project documentation
```

## 🎯 Key Features

### 🌐 Multi-Source Threat Collection (7+ APIs)
- **NVD CVE API** - National Vulnerability Database
- **CISA KEV Catalog** - Known Exploited Vulnerabilities  
- **MalwareBazaar** - Active malware feeds
- **GitHub CVE Database** - Raw CVE list
- **Exploit-DB** - Active exploit information
- **VulnLookup** - Detailed CVE information
- Graceful fallback to sample data

### 🤖 AI-Powered Analysis
- **Plain-English summaries** - Every threat gets an AI briefing
- **MITRE ATT&CK mapping** - Automatic tactical classification
- **Custom TPS scoring** - Beyond raw CVSS scores
- **Exploit availability detection** - Critical for response

### 🛡️ Environment Awareness
- **Configurable tech stack** - Know what you're protecting
- **Dynamic alerting** - Only relevant threats trigger alerts
- **Industry-specific** - Tailored for your environment

### 📊 Professional Reporting
- **Beautiful HTML dashboard** - Presentation-ready
- **Console output** - Quick review
- **Markdown documentation** - Technical docs
- **CSV export** - Spreadsheet format
- **PDF reports** - Executive summaries
- **Interactive visualizations** - Plotly charts

### 🧪 Quality Assurance
- **12 comprehensive tests** - All passing
- **Agent testing** - Each agent independently tested
- **Integration testing** - Full pipeline validation
- **API error handling** - Tested with failures

### 📈 Data Analysis
- **Pandas** - Advanced data processing and analysis
- **Group by severity** - Analyze threats by risk level
- **Group by vendor** - Find most affected software
- **Time-series analysis** - Track threats over time
- **Statistical summaries** - Mean, median, percentiles

### 🖥️ Web Dashboard
- **Streamlit** - Interactive web interface
- **Real-time updates** - Live threat monitoring
- **Mobile-friendly** - Works on phones/tablets
- **Export options** - Download reports

## 🧪 Quality Assurance

### Test Coverage
- **12 comprehensive tests** - All passing
- **Agent testing** - Each agent independently tested
- **Integration testing** - Full pipeline validation
- **API error handling** - Tested with failures

### Run Tests:
```bash
python3 tests/test_suite.py
```

## 🎓 Demo Guide

### Demo Flow (15-20 minutes):

1. **Show organization profile** (1 min)
   ```bash
   cat data/org_profile.json
   ```

2. **Run pipeline live** (3 min)
   ```bash
   python3 main.py
   ```

3. **Display HTML report** (3 min)
   ```bash
   open outputs/report.html
   ```

4. **Show visualizations** (4 min)
   ```bash
   python3 scripts/create_visualizations.py
   open outputs/heatmap.html
   ```

5. **Explain AI analysis** (3 min)
   - Highlight AI summaries
   - Show MITRE ATT&CK mapping
   - Demonstrate threat scoring

6. **Web dashboard demo** (2 min)
   ```bash
   streamlit run scripts/app.py
   ```

7. **Close with impact statement** (1 min)

## 🛡️ Security Rules

- ✅ **Dry-run mode first** - Always test with cached/sample data
- ✅ **Modular agents** - Each agent works independently
- ✅ **No hardcoded secrets** - Use environment variables
- ✅ **Clean output** - Professional HTML for presentations
- ✅ **Tested and documented** - Every component tested

## 🔧 Configuration

### Organization Profile

Edit `data/org_profile.json` to customize your environment:

```json
{
  "org_name": "DemoCorp",
  "tech_stack": ["Apache", "Linux", "WordPress", "MySQL", "Python"],
  "industry": "small_business",
  "alert_threshold": 7.5,
  "location": "Grogan's Mill, TX"
}
```

### Alert Threshold

- `alert_threshold`: CVSS score above which alerts trigger
- Adjust based on your risk tolerance

## 📊 API Endpoints

### NVD CVE API
- **URL:** `https://services.nvd.nist.gov/rest/json/cves`
- **Auth:** Optional API key for rate limiting
- **Data:** CVE descriptions, CVSS scores, references

### CISA KEV Catalog
- **URL:** `https://www.cisa.gov/known-exploited-vulnerabilities-catalog`
- **Auth:** Requires authentication (using cached demo data)
- **Data:** Actively exploited vulnerabilities

### MalwareBazaar
- **URL:** `https://firewall-mon.surge.sh/feed/urlhaus`
- **Auth:** None
- **Data:** Malware sample hashes

## 📝 Development Status

### Phase 1: Foundation ✅
- Project structure and data models
- Scout agent with data sources
- End-to-end verification

### Phase 2: Intelligence ✅
- Analyst agent with TPS scoring
- Claude API integration
- MITRE ATT&CK mapping

### Phase 3: Output ✅
- Reporter agent with HTML template
- Console output with rich library
- Org profile and Watchdog agent

### Phase 4: Polish ✅
- Visualizations with Plotly/Matplotlib/Seaborn
- README and documentation
- Error handling and resilience
- Machine learning integration (optional)
- Streamlit web dashboard

## 💬 Contributing

1. Fork the repository
2. Create a feature branch
3. Commit your changes
4. Push to the branch
5. Open a Pull Request

## 📜 License

MIT License - Feel free to use, modify, and distribute.

## 🎯 Use Cases

- **Educational** - Cybersecurity courses, AI/ML projects
- **Portfolio** - Showcase Python and API skills
- **Research** - Threat intelligence automation
- **Operations** - Small business security monitoring
- **Learning** - SOC analyst workflow automation

## 🔗 Resources

- [MITRE ATT&CK Framework](https://attack.mitre.org/)
- [NVD API Documentation](https://nvd.nist.gov/)
- [CISA KEV Catalog](https://www.cisa.gov/know-your-attacker)
- [Plotly Graphing Library](https://plotly.com/python/)
- [Scikit-learn Machine Learning](https://scikit-learn.org/)

## 📧 Contact

Built by: Paul Naeger
Institution: LoneStar Community College
Program: AI & Machine Learning AAS
Email: paulnaeger@protonmail.com

## 🎬 Demo Quote

> "This automated platform processes live threat intelligence from multiple sources, applying AI analysis, MITRE ATT&CK mapping, and beautiful visualizations. What a junior SOC analyst would do manually in hours, this system completes in minutes — complete with interactive charts and web dashboard."

## 🌟 Enhanced Features

This platform includes:
- ✅ **7+ live threat data sources**
- ✅ **12 passing unit tests**
- ✅ **5+ interactive visualizations**
- ✅ **AI-powered threat analysis**
- ✅ **MITRE ATT&CK mapping**
- ✅ **Multiple export formats** (HTML, CSV, JSON, PDF)
- ✅ **Web dashboard** (Streamlit)
- ✅ **Machine learning** (optional)
- ✅ **Professional documentation**
- ✅ **Production-grade code**

**This isn't just a school project — it's a production-ready cybersecurity platform!**
