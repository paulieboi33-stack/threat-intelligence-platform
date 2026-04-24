#!/usr/bin/env python3
"""
iPhone Data Collector Agent
============================
Collects data from iPhone via USB (libimobiledevice) and formats
it for analysis by the Threat Intelligence Platform.

Collects:
- Device info
- Installed apps list
- Battery/power stats
- Crash logs (if any)
"""

import subprocess
import json
import os
import re
from datetime import datetime
from rich.console import Console
from rich.table import Table
from rich.panel import Panel

console = Console()

OUTPUT_DIR = os.path.join(os.path.dirname(__file__), '..', 'data', 'iphone')
os.makedirs(OUTPUT_DIR, exist_ok=True)


def run_cmd(cmd):
    """Run a shell command and return stdout."""
    try:
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=15)
        return result.stdout.strip(), result.returncode
    except subprocess.TimeoutExpired:
        return "", 1
    except Exception as e:
        return str(e), 1


def check_device_connected():
    """Check if an iPhone is connected via USB."""
    out, code = run_cmd(["idevice_id", "-l"])
    if code != 0 or not out.strip():
        return None
    udids = [line.strip() for line in out.splitlines() if line.strip()]
    return udids[0] if udids else None


def get_device_info(udid):
    """Get basic device info."""
    console.print("[cyan]📱 Collecting device info...[/cyan]")
    out, _ = run_cmd(["ideviceinfo", "-u", udid])
    
    info = {}
    for line in out.splitlines():
        if ": " in line:
            key, _, val = line.partition(": ")
            info[key.strip()] = val.strip()
    
    # Extract key fields
    summary = {
        "udid": udid,
        "device_name": info.get("DeviceName", "Unknown"),
        "product_type": info.get("ProductType", "Unknown"),
        "ios_version": info.get("ProductVersion", "Unknown"),
        "serial_number": info.get("SerialNumber", "Unknown"),
        "wifi_mac": info.get("WiFiAddress", "Unknown"),
        "bluetooth_mac": info.get("BluetoothAddress", "Unknown"),
        "timezone": info.get("TimeZone", "Unknown"),
        "collected_at": datetime.now().isoformat(),
    }
    return summary


def get_installed_apps(udid):
    """Get list of installed apps."""
    console.print("[cyan]📦 Collecting installed apps...[/cyan]")
    out, code = run_cmd(["ideviceinstaller", "-u", udid, "-l", "-o", "xml"])
    
    apps = []
    if code != 0 or not out:
        # fallback: try without xml flag
        out, code = run_cmd(["ideviceinstaller", "-u", udid, "--list-apps"])
        if code != 0:
            console.print("[yellow]⚠️  ideviceinstaller not available or no app access. Try: brew install ideviceinstaller[/yellow]")
            return apps
        
        for line in out.splitlines():
            line = line.strip()
            if line and not line.startswith("Total"):
                parts = line.split(",", 2)
                if len(parts) >= 2:
                    apps.append({
                        "bundle_id": parts[0].strip(),
                        "version": parts[1].strip() if len(parts) > 1 else "unknown",
                        "name": parts[2].strip() if len(parts) > 2 else parts[0].strip(),
                    })
        return apps

    # Parse plist XML if available
    try:
        import plistlib
        plist = plistlib.loads(out.encode())
        if isinstance(plist, list):
            for app in plist:
                apps.append({
                    "bundle_id": app.get("CFBundleIdentifier", "unknown"),
                    "name": app.get("CFBundleDisplayName", app.get("CFBundleName", "unknown")),
                    "version": app.get("CFBundleShortVersionString", "unknown"),
                    "type": app.get("ApplicationType", "unknown"),
                })
    except Exception:
        pass
    
    return apps


def get_battery_info(udid):
    """Get battery and power stats."""
    console.print("[cyan]🔋 Collecting battery stats...[/cyan]")
    out, _ = run_cmd(["ideviceinfo", "-u", udid, "-q", "com.apple.mobile.battery"])
    
    info = {}
    for line in out.splitlines():
        if ": " in line:
            key, _, val = line.partition(": ")
            info[key.strip()] = val.strip()
    
    return {
        "battery_level": info.get("BatteryCurrentCapacity", "Unknown"),
        "is_charging": info.get("ExternalChargeCapable", "Unknown"),
        "battery_health": info.get("BatteryIsFullyCharged", "Unknown"),
    }


def get_crash_logs(udid):
    """Pull crash logs from device."""
    console.print("[cyan]💥 Checking crash logs...[/cyan]")
    crash_dir = os.path.join(OUTPUT_DIR, "crashes")
    os.makedirs(crash_dir, exist_ok=True)
    
    out, code = run_cmd(["idevicecrashreport", "-u", udid, "-e", crash_dir])
    
    if code != 0:
        return {"status": "unavailable", "count": 0}
    
    crash_files = [f for f in os.listdir(crash_dir) if f.endswith(".ips") or f.endswith(".crash")]
    return {
        "status": "collected",
        "count": len(crash_files),
        "path": crash_dir,
        "files": crash_files[:10],  # cap at 10
    }


# Known suspicious bundle IDs / patterns
SUSPICIOUS_PATTERNS = [
    r"spyware", r"stalker", r"monitor", r"track", r"keylog",
    r"spy", r"snoop", r"intercept", r"shadow", r"stealth",
]

KNOWN_RISKY_APPS = {
    "com.termius.ssh": "SSH client — could be used for unauthorized remote access",
    "com.cisco.anyconnect": "VPN app — verify it's configured correctly",
    "com.lookout.enterprise": "MDM agent — monitor for corporate surveillance",
    "com.fing.app": "Network scanner — legitimate but powerful",
}


def analyze_apps(apps):
    """Flag potentially risky or suspicious apps."""
    flags = []
    
    for app in apps:
        bundle_id = app.get("bundle_id", "").lower()
        name = app.get("name", "").lower()
        
        # Check suspicious patterns
        for pattern in SUSPICIOUS_PATTERNS:
            if re.search(pattern, bundle_id) or re.search(pattern, name):
                flags.append({
                    "app": app.get("name", bundle_id),
                    "bundle_id": bundle_id,
                    "risk": "HIGH",
                    "reason": f"Name matches suspicious pattern: '{pattern}'",
                })
                break
        
        # Check known risky apps
        if bundle_id in KNOWN_RISKY_APPS:
            flags.append({
                "app": app.get("name", bundle_id),
                "bundle_id": bundle_id,
                "risk": "MEDIUM",
                "reason": KNOWN_RISKY_APPS[bundle_id],
            })
    
    return flags


def collect_all(udid=None):
    """Main collection function — gather all iPhone data."""
    console.print(Panel("[bold cyan]📱 iPhone Threat Data Collector[/bold cyan]", expand=False))
    
    # Auto-detect device
    if not udid:
        udid = check_device_connected()
    
    if not udid:
        console.print("[red]❌ No iPhone detected. Please connect via USB and trust this computer.[/red]")
        console.print("[yellow]Steps: Connect iPhone → tap 'Trust' on phone → run again[/yellow]")
        return None
    
    console.print(f"[green]✅ iPhone detected: {udid[:8]}...[/green]\n")
    
    # Collect data
    result = {
        "source": "iphone_usb",
        "collected_at": datetime.now().isoformat(),
        "device": get_device_info(udid),
        "battery": get_battery_info(udid),
        "apps": get_installed_apps(udid),
        "crashes": get_crash_logs(udid),
    }
    
    # Analyze for threats
    result["threat_flags"] = analyze_apps(result["apps"])
    result["app_count"] = len(result["apps"])
    result["threat_count"] = len(result["threat_flags"])
    
    # Save to file
    out_file = os.path.join(OUTPUT_DIR, f"iphone_data_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json")
    with open(out_file, "w") as f:
        json.dump(result, f, indent=2)
    
    # Display summary
    console.print(f"\n[bold]📊 Collection Summary[/bold]")
    console.print(f"  Device: {result['device']['device_name']} ({result['device']['product_type']})")
    console.print(f"  iOS: {result['device']['ios_version']}")
    console.print(f"  Battery: {result['battery']['battery_level']}%")
    console.print(f"  Apps collected: {result['app_count']}")
    console.print(f"  Threat flags: [{'red' if result['threat_count'] > 0 else 'green'}]{result['threat_count']}[/{'red' if result['threat_count'] > 0 else 'green'}]")
    
    if result["threat_flags"]:
        console.print("\n[bold red]⚠️  Flagged Apps:[/bold red]")
        for flag in result["threat_flags"]:
            console.print(f"  [{flag['risk']}] {flag['app']}: {flag['reason']}")
    
    console.print(f"\n[green]✅ Data saved to: {out_file}[/green]")
    return result


if __name__ == "__main__":
    collect_all()
