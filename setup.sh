#!/bin/bash
# Threat Intelligence Platform - Setup Script
# ======================================
# Installs dependencies, validates installation, and runs initial test

set -e  # Exit on error

echo ""
echo "=========================================="
echo "  🛡️  Threat Intelligence Platform Setup"
echo "=========================================="
echo ""

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

echo "[INFO] Installing Python dependencies..."
echo ""

# Install dependencies
pip3 install -r requirements.txt

echo ""
echo "[INFO] ✅ Dependencies installed successfully"
echo ""

# Validate installation
echo "[INFO] Validating installation..."
echo ""

# Check if main.py exists
if [ -f "main.py" ]; then
    echo "[INFO] ✅ main.py found"
else
    echo "[FAIL] ✗ main.py not found"
    exit 1
fi

# Check if agents exist
if [ -d "agents" ]; then
    echo "[INFO] ✅ agents/ directory found"
    
    for agent in scout reporter watchdog api_integration; do
        if [ -f "agents/${agent}.py" ]; then
            echo "[INFO] ✅ agents/${agent}.py found"
        else
            echo "[FAIL] ✗ agents/${agent}.py missing"
            exit 1
        fi
    done
else
    echo "[FAIL] ✗ agents/ directory missing"
    exit 1
fi

# Check if templates exist
if [ -d "templates" ]; then
    echo "[INFO] ✅ templates/ directory found"
    
    if [ -f "templates/report.html" ]; then
        echo "[INFO] ✅ templates/report.html found"
    else
        echo "[FAIL] ✗ templates/report.html missing"
        exit 1
    fi
else
    echo "[FAIL] ✗ templates/ directory missing"
    exit 1
fi

# Check if data exists
if [ -d "data" ]; then
    echo "[INFO] ✅ data/ directory found"
    
    if [ -f "data/org_profile.json" ]; then
        echo "[INFO] ✅ data/org_profile.json found"
    else
        echo "[FAIL] ✗ data/org_profile.json missing"
        exit 1
    fi
else
    echo "[FAIL] ✗ data/ directory missing"
    exit 1
fi

# Check if tests exist
if [ -d "tests" ]; then
    echo "[INFO] ✅ tests/ directory found"
    
    if [ -f "tests/test_suite.py" ]; then
        echo "[INFO] ✅ tests/test_suite.py found"
    else
        echo "[FAIL] ✗ tests/test_suite.py missing"
        exit 1
    fi
else
    echo "[FAIL] ✗ tests/ directory missing"
    exit 1
fi

# Run initial test
echo ""
echo "[INFO] Running initial test suite..."
echo ""

python3 tests/test_suite.py

echo ""
echo "[INFO] ✅ All checks passed!"
echo ""
echo "=========================================="
echo "  🎉 Setup Complete!"
echo "=========================================="
echo ""
echo "Next steps:"
echo "1. Edit data/org_profile.json with your environment"
echo "2. Run: python3 main.py"
echo "3. View reports in outputs/ directory"
echo ""
echo "Happy hunting! 🛡️"
echo ""
