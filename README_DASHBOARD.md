# 🎛️ Threat Intelligence Dashboard

## Access Your Dashboard

### Option 1: Web Dashboard (Recommended)

```bash
cd /Users/paulnaeger/.openclaw/workspace/agents/threat-intel
streamlit run scripts/app.py
```

**Access at:** http://localhost:8501

**Features:**
- 📊 Real-time statistics
- 📈 Interactive charts
- 🤖 Agent status monitoring
- 📋 Recent threats with severity coloring
- 📁 Recent reports listing
- 🔧 System health status

### Option 2: Terminal Dashboard (Text-based)

```bash
cd /Users/paulnaeger/.openclaw/workspace/agents/threat-intel
python3 scripts/dashboard.py
```

**Features:**
- Rich text formatting
- Live updating with Live widget (optional)
- Color-coded severity levels
- Simple, quick view

### Option 3: Real-time Monitoring

```bash
# Watch the dashboard update in real-time
while true; do
    cd /Users/paulnaeger/.openclaw/workspace/agents/threat-intel
    python3 scripts/dashboard.py
    sleep 5
done
```

## What You'll See

### Statistics Overview
- **Total Threats** - All collected threats
- **Critical Alerts** - High-priority threats
- **High/Medium/Low** - Severity breakdown
- **Last Collection** - When data was last gathered

### Threat Distribution
- Visual breakdown by severity
- Threat counts per category
- Source breakdown

### Recent Activity
- Latest 5 threats collected
- Severity coloring (Red=Critical, Orange=High, etc.)
- Real-time updates

### Agent Status
- Scout Agent (Collection)
- Analyst Agent (Analysis)
- Watchdog Agent (Alerting)
- Reporter Agent (Reporting)

### Recent Reports
- HTML reports generated
- CSV exports created
- JSON data files
- Markdown documentation

## Dashboard Layout

```
┌─────────────────────────────────────────────────────┐
│ 🛡️ Threat Intelligence Dashboard                   │
├─────────────────────────────────────────────────────┤
│ Total Threats: 2  |  Critical: 1  |  High: 1       │
│ Medium: 0        |  Low: 0         |  Last: Now     │
├─────────────────────────────────────────────────────┤
│ Threat Sources  |  Recent Activity  |  Platform     │
│ [Chart]         | [Table]           | Health Status │
├─────────────────────────────────────────────────────┤
│ Recent Threats                                       │
│ CVE-2024-XXX (Critical) - CVSS 9.8                 │
│ CVE-2024-XXX (High) - CVSS 8.5                      │
├─────────────────────────────────────────────────────┤
│ Recent Reports                                       │
│ report_YYYY-MM-DD.html                              │
│ report_YYYY-MM-DD.csv                               │
└─────────────────────────────────────────────────────┘
```

## Customization

### Change Dashboard Port

```bash
streamlit run scripts/app.py --server.port 8000
```

### Run Headless (no UI)

```bash
python3 scripts/dashboard.py
```

### Add Live Updates

Edit `scripts/dashboard.py` and add:

```python
with Live(Panel("Dashboard content"), auto_refresh=1):
    print_dashboard()
```

## Troubleshooting

### Dashboard Not Loading
```bash
# Check if Streamlit is installed
python3 -c "import streamlit; print('OK')"

# Install dependencies if needed
pip3 install streamlit pandas
```

### No Data Showing
```bash
# Check if database exists
ls -la /Users/paulnaeger/.openclaw/workspace/agents/threat-intel/data/

# Run collection once
python3 main_simplified.py
```

### Clear Cache

```bash
streamlit cache clear
```

## Tips

1. **Keep the dashboard running** - Shows real-time activity
2. **Check recent threats** - See what's being collected
3. **Monitor agent status** - Ensure all agents are active
4. **Review reports** - Click on report files to view details

## Integration with Platform

The dashboard automatically connects to:
- SQLite database (threats.db)
- Reports directory (outputs/)
- Log files (logs/)
- Agent modules (agents/)

No configuration needed - it just works!

## Screenshots

```
┌────────────────────────────────────────────┐
│ Total Threats: 5  |  Critical: 2  |  High: 3│
├────────────────────────────────────────────┤
│ Critical: 2  |  High: 3  |  Medium: 0      │
│ Low: 0                                         │
├────────────────────────────────────────────┤
│ [Chart: Severity Distribution]              │
├────────────────────────────────────────────┤
│ Recent Threats:                             │
│ CVE-2024-1234 [Critical] - CVSS 9.8        │
│ CVE-2024-5678 [High] - CVSS 8.5            │
└────────────────────────────────────────────┘
```

## Next Steps

1. **Run the dashboard** - `streamlit run scripts/app.py`
2. **Open browser** - Go to http://localhost:8501
3. **Watch real-time** - See threats come in live
4. **Share with teacher** - Shows live monitoring

## Conclusion

Your dashboard gives you a **single view** of your entire threat intelligence platform, showing:

✅ What agents are doing
✅ How many threats collected
✅ Severity distribution
✅ Recent activity
✅ System health
✅ Report status

**It's your command center for the entire platform!**
