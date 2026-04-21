#!/bin/bash
# Quick fix for streamlit PATH issue
# ======================================

echo "[INFO] Fixing Streamlit PATH issue..."
echo ""

# Add Streamlit to PATH
echo "export PATH=\$HOME/Library/Python/3.9/bin:\$PATH" >> ~/.zshrc

# Source the fix
source ~/.zshrc

# Test
streamlit --version

echo ""
echo "✅ Streamlit should now be accessible!"
echo ""
echo "To run dashboard:"
echo "  cd /Users/paulnaeger/.openclaw/workspace/agents/threat-intel"
echo "  streamlit run scripts/app.py"
