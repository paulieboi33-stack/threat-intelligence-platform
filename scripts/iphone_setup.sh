#!/bin/bash
# iPhone Traffic Monitoring Setup
# Generates mitmproxy cert and starts proxy for iPhone traffic capture

echo "================================================"
echo "  iPhone Network Traffic Monitor Setup"
echo "================================================"

# 1. Get Mac's local IP
MAC_IP=$(ipconfig getifaddr en0 2>/dev/null || ipconfig getifaddr en1 2>/dev/null)
echo ""
echo "📍 Your Mac's IP address: $MAC_IP"
echo "📡 Proxy will run on port: 8080"
echo ""

# 2. Generate mitmproxy cert if not already done
mkdir -p ~/.mitmproxy
if [ ! -f ~/.mitmproxy/mitmproxy-ca-cert.pem ]; then
    echo "🔐 Generating mitmproxy certificate..."
    mitmdump --quiet &
    sleep 3
    kill %1 2>/dev/null
    echo "✅ Certificate generated at ~/.mitmproxy/"
else
    echo "✅ Certificate already exists"
fi

echo ""
echo "================================================"
echo "  SETUP YOUR IPHONE (do these steps manually):"
echo "================================================"
echo ""
echo "STEP 1: Set Proxy on iPhone"
echo "  Settings → WiFi → tap your network (ⓘ)"
echo "  → Configure Proxy → Manual"
echo "  Server: $MAC_IP"
echo "  Port: 8080"
echo ""
echo "STEP 2: Install mitmproxy cert on iPhone"
echo "  Open Safari on iPhone → go to:"
echo "  http://mitm.it"
echo "  → Tap 'iOS' → install the certificate"
echo ""
echo "STEP 3: Trust the cert in Settings"
echo "  Settings → General → VPN & Device Management"
echo "  → mitmproxy → Trust"
echo "  Settings → General → About → Certificate Trust Settings"
echo "  → Enable mitmproxy cert"
echo ""
echo "STEP 4: Start capturing traffic (run this):"
echo "  mitmweb --listen-port 8080 --web-port 8081"
echo "  Then open: http://localhost:8081"
echo ""
echo "================================================"
echo "  Starting mitmweb now..."
echo "================================================"
echo ""
mitmweb --listen-port 8080 --web-port 8081 --set flow_detail=2
