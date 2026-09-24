#!/usr/bin/env python3
"""
   ____                  _ _____     _                 
  / __ \____ ___  ____  (_)__   \_ __(_) __ _  __ _  ___ 
 / / / / __ `__ \/ __ \/ /  / /\/ '__/ / _` |/ _` |/ _ \\
/ /_/ / / / / / / / / / /  / /  | | / / (_| | (_| |  __/
\____/_/ /_/ /_/_/ /_/_/   \/   |_|/_/ \__,_|\__, |\___|
                                             |___/      
OmniTriage v1.0.0 - Zero-Dependency Digital Forensics & Incident Response (DFIR) Engine
Author: Çınar (prox0959)
Target OS: Windows 10 / Windows 11 / Windows Server
"""

import os
import sys
import time
import argparse
from datetime import datetime

# Ensure stdout handles UTF-8 on Windows terminals
if sys.platform == "win32":
    try:
        sys.stdout.reconfigure(encoding="utf-8")
        sys.stderr.reconfigure(encoding="utf-8")
    except Exception:
        pass

from collectors import (
    collect_system_info,
    collect_execution_artifacts,
    collect_browser_history,
    collect_network_artifacts,
    collect_filesystem_artifacts,
    collect_persistence_artifacts
)
from reporters import generate_json_report, generate_html_report

BANNER = r"""
   ____                  _ _____     _                 
  / __ \____ ___  ____  (_)__   \_ __(_) __ _  __ _  ___ 
 / / / / __ `__ \/ __ \/ /  / /\/ '__/ / _` |/ _` |/ _ \
/ /_/ / / / / / / / / / /  / /  | | / / (_| | (_| |  __/
\____/_/ /_/ /_/_/ /_/_/   \/   |_|/_/ \__,_|\__, |\___|
                                             |___/      
 [::] OmniTriage v1.0.0 | Pure Python DFIR Live Triage Engine
 [::] Author: Çınar (prox0959) | Zero External Dependencies
"""

def log(msg: str, status: str = "INFO"):
    colors = {
        "INFO": "\033[94m[*]\033[0m",
        "SUCCESS": "\033[92m[+]\033[0m",
        "WARN": "\033[93m[!]\033[0m",
        "ALERT": "\033[91m[-]\033[0m"
    }
    prefix = colors.get(status, "[*]")
    print(f"{prefix} {msg}")

def main():
    parser = argparse.ArgumentParser(
        description="OmniTriage - Windows Live Forensics & Incident Response Triage Engine",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="Examples:\n"
               "  python omnitriage.py\n"
               "  python omnitriage.py --out C:\\Forensics\\Case_001\n"
               "  python omnitriage.py --quick --json-only\n"
    )
    parser.add_argument("--out", "-o", default="triage_output", help="Output directory for reports (default: triage_output)")
    parser.add_argument("--quick", "-q", action="store_true", help="Quick mode (skips deep staging file hash calculations)")
    parser.add_argument("--json-only", action="store_true", help="Only produce JSON report")
    parser.add_argument("--html-only", action="store_true", help="Only produce interactive HTML dashboard")
    parser.add_argument("--no-browser", action="store_true", help="Skip browser history acquisition")
    parser.add_argument("--no-fs", action="store_true", help="Skip staging directory filesystem scans")
    parser.add_argument("--lang", default="en", choices=["en", "tr"], help="Console output language (en/tr)")

    args = parser.parse_args()

    print(BANNER)
    start_time = time.time()
    scan_dt = datetime.now()
    timestamp_str = scan_dt.strftime("%Y-%m-%d %H:%M:%S")
    file_timestamp = scan_dt.strftime("%Y%m%d_%H%M%S")

    output_dir = os.path.abspath(args.out)
    os.makedirs(output_dir, exist_ok=True)

    log(f"Starting live forensic acquisition on target system...", "INFO")
    log(f"Destination: {output_dir}", "INFO")

    data = {
        "metadata": {
            "tool_name": "OmniTriage",
            "version": "1.0.0",
            "author": "Çınar (prox0959)",
            "scan_timestamp": timestamp_str,
            "scan_mode": "Quick" if args.quick else "Full Standard"
        }
    }

    # Step 1: System Telemetry & Format Date
    log("Acquiring OS telemetry, InstallDate, and Uptime...", "INFO")
    data["system_info"] = collect_system_info()
    sys_info = data["system_info"]
    log(f"Host: {sys_info.get('hostname')} | User: {sys_info.get('current_user')}", "SUCCESS")
    log(f"OS: {sys_info.get('product_name')} (Build: {sys_info.get('full_build_str', 'N/A')})", "SUCCESS")
    log(f"Windows Format/Install Date: {sys_info.get('install_date_local', 'N/A')}", "SUCCESS")
    log(f"System Uptime: {sys_info.get('uptime_formatted', 'N/A')} (Boot: {sys_info.get('boot_time', 'N/A')})", "SUCCESS")

    # Step 2: Execution Artifacts
    log("Collecting program execution evidence (PowerShell, RunMRU, UserAssist)...", "INFO")
    data["execution_artifacts"] = collect_execution_artifacts()
    exec_art = data["execution_artifacts"]
    ps_data = exec_art.get("powershell_history", {})
    log(f"PowerShell history: {ps_data.get('total_commands', 0)} commands ({len(ps_data.get('flagged_commands', []))} flagged)", "SUCCESS")
    log(f"RunMRU (Win+R history): {len(exec_art.get('run_mru', []))} items", "SUCCESS")
    log(f"UserAssist GUI applications: {len(exec_art.get('userassist', []))} items decoded", "SUCCESS")

    # Step 3: Browser History
    if not args.no_browser:
        log("Bypassing SQLite locks & harvesting browser history...", "INFO")
        data["browser_artifacts"] = collect_browser_history(max_visits_per_browser=100)
        total_visits = sum(b.get("total_visits_extracted", 0) for b in data["browser_artifacts"].values())
        total_downloads = sum(b.get("total_downloads_extracted", 0) for b in data["browser_artifacts"].values())
        log(f"Browser activity: {total_visits} URLs, {total_downloads} downloads acquired", "SUCCESS")
    else:
        log("Skipping browser history acquisition (--no-browser)", "WARN")
        data["browser_artifacts"] = {}

    # Step 4: Network & USB
    log("Harvesting Wi-Fi profiles, USB connection history, and active sockets...", "INFO")
    data["network_artifacts"] = collect_network_artifacts()
    net_art = data["network_artifacts"]
    usb_data = net_art.get("usb_storage_history", {})
    usb_count = len(usb_data.get("usbstor_devices", [])) if isinstance(usb_data, dict) else len(usb_data)
    log(f"Wi-Fi & Network Profiles: {len(net_art.get('wifi_profiles', []))} profiles discovered", "SUCCESS")
    log(f"Historical USB storage devices: {usb_count} drives logged", "SUCCESS")
    log(f"Active TCP sockets: {len(net_art.get('active_tcp_connections', []))} connections", "SUCCESS")

    # Step 5: Filesystem & Staging
    if not args.no_fs:
        log("Scanning staging directories (%TEMP%, %APPDATA%) for suspicious executables...", "INFO")
        data["filesystem_artifacts"] = collect_filesystem_artifacts()
        fs_art = data["filesystem_artifacts"]
        log(f"Executables in %TEMP%: {fs_art.get('temp_executables_found', 0)} found", "SUCCESS")
        log(f"Recent shortcut items: {fs_art.get('recent_shortcuts_found', 0)} items", "SUCCESS")
    else:
        log("Skipping filesystem staging scan (--no-fs)", "WARN")
        data["filesystem_artifacts"] = {}

    # Step 6: Persistence
    log("Auditing autostart persistence mechanisms (Run/RunOnce, Startup)...", "INFO")
    data["persistence_artifacts"] = collect_persistence_artifacts()
    pers_art = data["persistence_artifacts"]
    log(f"Registry Run/RunOnce keys: {pers_art.get('registry_run_keys_count', 0)} entries", "SUCCESS")
    log(f"Startup folder items: {pers_art.get('startup_folder_items_count', 0)} files", "SUCCESS")

    # Generate Reports
    log("Compiling forensic reports...", "INFO")
    hostname = sys_info.get("hostname", "TARGET")
    base_filename = f"Triage_{hostname}_{file_timestamp}"

    # JSON Report
    if not args.html_only:
        json_path = os.path.join(output_dir, f"{base_filename}.json")
        json_res = generate_json_report(data, json_path)
        if json_res["success"]:
            log(f"JSON Report written: {json_res['path']} ({json_res['size_kb']} KB)", "SUCCESS")
        else:
            log(f"Failed to generate JSON report: {json_res.get('error')}", "ALERT")

    # HTML Report
    if not args.json_only:
        html_path = os.path.join(output_dir, f"{base_filename}.html")
        html_res = generate_html_report(data, html_path)
        if html_res["success"]:
            log(f"HTML Dashboard written: {html_res['path']} ({html_res['size_kb']} KB)", "SUCCESS")
        else:
            log(f"Failed to generate HTML report: {html_res.get('error')}", "ALERT")

    elapsed = round(time.time() - start_time, 2)
    print("\n" + "=" * 65)
    log(f"Forensic acquisition completed in {elapsed} seconds.", "SUCCESS")
    log(f"Review your triage reports in: {output_dir}", "SUCCESS")
    print("=" * 65 + "\n")

if __name__ == "__main__":
    main()
