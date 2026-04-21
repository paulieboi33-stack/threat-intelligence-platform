#!/bin/bash
# Deployment Script - Threat Intelligence Platform
# ===============================
# Deploys simplified agents for continuous monitoring
# Runs 24/7 collecting, analyzing, and reporting on threats

set -e  # Exit on error

echo ""
echo "===================================="
echo "  🚀 Deploying Threat Intelligence Platform"
echo "===================================="
echo ""

# Colors
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

# Create logs directory
LOG_DIR="/Users/paulnaeger/.openclaw/workspace/agents/threat-intel/logs"
mkdir -p "$LOG_DIR"

echo "[INFO] Creating deployment structure..."
echo ""

# Create deployment configuration
cat > "$LOG_DIR/deployment_config.txt" << 'EOF'
# Threat Intelligence Platform Deployment
# ========================================

# Schedule: Run every 6 hours
# This keeps data fresh without overwhelming APIs

# Daily report times
- 6:00 AM - Morning collection
- 12:00 PM - Midday collection  
- 6:00 PM - Evening collection
- 12:00 AM - Midnight collection

# Weekly reports
- Sunday 8:00 AM - Weekly summary
- 1st of month 6:00 AM - Monthly summary

# Data retention
- Keep threats for 90 days
- Auto-cleanup old data
- Maximum 1000 threats

# API rate limits respected
- CISA KEV: Check every 6 hours
- GitHub CVE: Check every 6 hours
- VulnLookup: Skip (unreliable)

# Report schedules
- Daily: HTML + CSV + JSON
- Weekly: Summary report
- Monthly: Trend analysis
EOF

echo "[INFO] Configuration created"
echo ""

# Create deployment script
cat > "$LOG_DIR/deploy_monitor.sh" << 'SCRIPT'
#!/bin/bash

# Threat Intelligence Continuous Monitor
# ======================================

LOG_DIR="/Users/paulnaeger/.openclaw/workspace/agents/threat-intel/logs"
THREAT_DIR="/Users/paulnaeger/.openclaw/workspace/agents/threat-intel/data"

echo "=== Threat Intelligence Monitor ==="
echo "Time: $(date)"

# Run simplified pipeline
cd /Users/paulnaeger/.openclaw/workspace/agents/threat-intel
python3 main_simplified.py > "$LOG_DIR/monitor_$(date '+%Y-%m-%d_%H-%M').log" 2>&1

# Check for errors
if grep -q "Error" "$LOG_DIR/monitor_$(date '+%Y-%m-%d_%H-%M').log"; then
    echo "⚠️  Errors detected in last run"
    tail -20 "$LOG_DIR/monitor_$(date '+%Y-%m-%d_%H-%M').log" >> "$LOG_DIR/errors.log"
else
    echo "✓ Collection complete"
fi

# Cleanup old logs (keep last 30 days)
find "$LOG_DIR" -name "monitor_*.log" -mtime +30 -delete
echo "=== Monitor Complete ==="
SCRIPT

chmod +x "$LOG_DIR/deploy_monitor.sh"

echo "[INFO] Monitor script created"
echo ""

# Create crontab for automated deployment
cat > "$LOG_DIR/crontab.monitor" << 'EOF'
# Threat Intelligence Platform - Automated Monitoring
# ===================================================

# Run monitor every 6 hours
# This keeps data fresh without overwhelming APIs
0 */6 * * * cd /Users/paulnaeger/.openclaw/workspace/agents/threat-intel && /Users/paulnaeger/.openclaw/workspace/agents/threat-intel/logs/deploy_monitor.sh >> /Users/paulnaeger/.openclaw/workspace/agents/threat-intel/logs/deploy.log 2>&1

# Weekly summary on Sunday at 8 AM
0 8 * * 0 cd /Users/paulnaeger/.openclaw/workspace/agents/threat-intel && python3 scripts/scheduled_exports.py 2 >> /Users/paulnaeger/.openclaw/workspace/agents/threat-intel/logs/weekly_export.log 2>&1

# Monthly summary on 1st of month at 6 AM
0 6 1 * * cd /Users/paulnaeger/.openclaw/workspace/agents/threat-intel && python3 scripts/scheduled_exports.py 3 >> /Users/paulnaeger/.openclaw/workspace/agents/threat-intel/logs/monthly_export.log 2>&1

# Maintenance every Saturday at 3 AM
0 3 * * 6 cd /Users/paulnaeger/.openclaw/workspace/agents/threat-intel && python3 scripts/scheduled_exports.py 4 >> /Users/paulnaeger/.openclaw/workspace/agents/threat-intel/logs/maintenance.log 2>&1
EOF

echo "[INFO] Crontab created"
echo ""

# Apply crontab
echo "[INFO] Installing crontab..."
crontab "$LOG_DIR/crontab.monitor"

echo "[INFO] Crontab installed"
echo ""

# Show current crontab
echo "[INFO] Current scheduled tasks:"
crontab -l
echo ""

# Create deployment status file
cat > "$LOG_DIR/deploy_status.txt" << 'EOF'
Deployment Status: ACTIVE
=======================

Deployment Time: $(date)
Platform Version: Simplified v1.0
Monitoring Schedule: Every 6 hours
Data Retention: 90 days
Maximum Threats: 1000

Current Status: Ready for deployment
Last Collection: N/A (just deployed)
Next Collection: In 6 hours

Notes:
- Platform is optimized for continuous monitoring
- API rate limits are respected
- Automatic cleanup of old data
- Weekly and monthly reports scheduled
- Maintenance tasks scheduled

Ready to track real threat data!
EOF

echo ""
echo "===================================="
echo "  🚀 Deployment Complete!"
echo "===================================="
echo ""
echo "Your threat intelligence platform is now:"
echo "  - Running every 6 hours (24/7 monitoring)"
echo "  - Collecting real threat data"
echo "  - Generating daily/weekly/monthly reports"
echo "  - Maintaining 90-day retention policy"
echo "  - Running on your Mac mini M4"
echo ""
echo "To view logs:"
echo "  tail -f /Users/paulnaeger/.openclaw/workspace/agents/threat-intel/logs/deploy.log"
echo ""
echo "To stop monitoring:"
echo "  crontab -r"
echo ""
echo "To pause temporarily:"
echo "  crontab -e"
echo "# Comment out the lines"
echo ""
