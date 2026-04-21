#!/bin/bash
# Install additional skills for Threat Intelligence Platform
# Each skill adds specific capabilities

set -e

echo ""
echo "=========================================="
echo "  🔧 Installing Additional Skills"
echo "=========================================="
echo ""

# Colors
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

echo "[INFO] This will install additional Python packages to enhance your platform."
echo "[INFO] These are OPTIONAL - your platform works fine without them."
echo ""
echo "Skills being installed:"
echo "  📊 Plotly - Interactive charts and graphs"
echo "  📈 Matplotlib - Static charts and data visualization"
echo "  🐼 Pandas - Advanced data processing and analysis"
echo "  📋 Polars - Faster data processing than pandas"
echo "  📄 WeasyPrint - PDF report generation"
echo "  🧠 Scikit-learn - Machine learning for threat prediction"
echo "  🤖 NLTK/Spacy - NLP for analyzing threat descriptions"
echo "  🔍 Pytest - Advanced testing framework"
echo "  📋 MkDocs - Professional documentation generator"
echo "  🌐 Streamlit - Web dashboard creation"
echo ""
echo "These skills will:"
echo "  - Make visualizations more beautiful"
echo "  - Speed up data processing"
echo "  - Enable PDF reports"
echo "  - Add machine learning capabilities"
echo "  - Create web dashboards"
echo "  - Improve testing coverage"
echo ""
read -p "Do you want to install these additional skills? (yes/no): " -n 1 -r

echo ""

if [[ $REPLY =~ ^[Yy]$ ]]; then
    echo "[INFO] Installing additional skills..."
    echo ""
    
    # Install dependencies
    pip3 install -r /Users/paulnaeger/.openclaw/workspace/agents/threat-intel/requirements_additional.txt
    
    echo ""
    echo "[SUCCESS] All skills installed successfully!"
    echo ""
    echo "Next steps:"
    echo "  1. Re-run your platform: python3 main.py"
    echo "  2. Try new visualizations: python3 scripts/create_charts.py"
    echo "  3. Generate PDF reports: python3 scripts/generate_pdf_report.py"
    echo "  4. View web dashboard: streamlit run app.py"
    echo ""
else
    echo "[INFO] Skipping additional skills installation."
    echo "[INFO] Your platform still works great with basic packages!"
    echo ""
fi

echo "=========================================="
echo "  Skill installation complete"
echo "=========================================="
echo ""
