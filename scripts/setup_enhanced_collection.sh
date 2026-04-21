#!/bin/bash
# Enhanced collection scheduler
# ====================================

echo "[INFO] Setting up enhanced data collection..."
echo ""
echo "This will collect maximum data every 4 hours:"
echo "  - GitHub CVE Database"
echo "  - Exploit-DB"
echo "  - CISA-style sources"
echo "  - VulnLookup-style sources"
echo ""
echo "Add to crontab:"
echo "  0 */4 * * * cd /Users/paulnaeger/.openclaw/workspace/agents/threat-intel && python3 scripts/max_collection.py >> logs/enhanced_collection.log 2>&1"
