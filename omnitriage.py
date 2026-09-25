#!/usr/bin/env python3
"""
   ____                  _ _____     _                 
  / __ \____ ___  ____  (_)__   \_ __(_) __ _  __ _  ___ 
 / / / / __ `__ \/ __ \/ /  / /\/ '__/ / _` |/ _` |/ _ \\
/ /_/ / / / / / / / / / /  / /  | | / / (_| | (_| |  __/
\____/_/ /_/ /_/_/ /_/_/   \/   |_|/_/ \__,_|\__, |\___|
                                             |___/      
OmniTriage v1.1.0 - Zero-Dependency Digital Forensics & Incident Response (DFIR) Engine
Author: Çınar (prox0959)
Target OS: Windows 10 / Windows 11 / Windows Server
RFC 3227 Compliant (Order of Volatility) | Chain of Custody SHA-256 Hashing
"""

import os
import sys
import time
import hashlib
import logging
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
    collect_running_processes,
    collect_execution_artifacts,
    collect_browser_history,
    collect_network_artifacts,
    collect_filesystem_artifacts,
    collect_persistence_artifacts,
    collect_dns_cache,
    collect_event_logs,
    collect_remote_execution_artifacts,
    parse_shimcache,
    collect_scheduled_tasks
)
from reporters import generate_json_report, generate_html_report

BANNER = r"""
   ____                  _ _____     _                 
  / __ \____ ___  ____  (_)__   \_ __(_) __ _  __ _  ___ 
 / / / / __ `__ \/ __ \/ /  / /\/ '__/ / _` |/ _` |/ _ \
/ /_/ / / / / / / / / / /  / /  | | / / (_| | (_| |  __/
\____/_/ /_/ /_/_/ /_/_/   \/   |_|/_/ \__,_|\__, |\___|
                                             |___/      
 [::] OmniTriage v1.1.0 | Pure Python DFIR Live Triage Engine (RFC 3227 Compliant)
 [::] Author: Çınar (prox0959) | Zero External Dependencies
"""


def setup_audit_logger(log_file_path: str) -> logging.Logger:
    """
    Configures file-based audit logging for forensic chain of custody (RFC 3227).
    """
    logger = logging.getLogger("OmniTriageAudit")
    logger.setLevel(logging.INFO)
    if not logger.handlers:
        fh = logging.FileHandler(log_file_path, encoding="utf-8")
        formatter = logging.Formatter("%(asctime)s [%(levelname)s] %(message)s", datefmt="%Y-%m-%d %H:%M:%S")
        fh.setFormatter(formatter)
        logger.addHandler(fh)
    return logger


def compute_sha256(file_path: str) -> str:
    """
    Computes SHA-256 cryptographic digest of a file to guarantee forensic integrity.
    """
    h = hashlib.sha256()
    with open(file_path, "rb") as f:
        while chunk := f.read(65536):
            h.update(chunk)
    return h.hexdigest()


def log(msg: str, status: str = "INFO", audit_logger: logging.Logger = None):
    colors = {
        "INFO": "\033[94m[*]\033[0m",
        "SUCCESS": "\033[92m[+]\033[0m",
        "WARN": "\033[93m[!]\033[0m",
        "ALERT": "\033[91m[-]\033[0m"
    }
    prefix = colors.get(status, "[*]")
    print(f"{prefix} {msg}")
    if audit_logger:
        audit_logger.info(f"[{status}] {msg}")


def main():
    parser = argparse.ArgumentParser(
        description="OmniTriage - Windows Live Forensics & Incident Response Triage Engine (RFC 3227)",
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

    # Initialize dedicated forensic audit log file
    audit_log_path = os.path.join(output_dir, f"omnitriage_audit_{file_timestamp}.log")
    audit_logger = setup_audit_logger(audit_log_path)

    log("Starting live forensic acquisition following RFC 3227 Order of Volatility...", "INFO", audit_logger)
    log(f"Destination: {output_dir}", "INFO", audit_logger)
    log(f"Audit Log initialized: {audit_log_path}", "INFO", audit_logger)

    data = {
        "metadata": {
            "tool_name": "OmniTriage",
            "version": "1.1.0",
            "author": "Çınar (prox0959)",
            "methodology": "RFC 3227 Order of Volatility",
            "scan_timestamp": timestamp_str,
            "scan_mode": "Quick" if args.quick else "Full Standard"
        }
    }

    # =========================================================================
    # TIER 1: HIGHLY VOLATILE EVIDENCE (Live Network Sockets, DNS Cache, Processes)
    # Must be acquired first before process termination or socket closure!
    # =========================================================================

    # Step 1 (RFC 3227 Tier 1A): Active Network Sockets & Connections
    log("[RFC 3227 - Tier 1] Acquiring ephemeral network sockets, Wi-Fi, and USB state...", "INFO", audit_logger)
    data["network_artifacts"] = collect_network_artifacts()
    net_art = data["network_artifacts"]
    usb_data = net_art.get("usb_storage_history", {})
    usb_count = len(usb_data.get("usbstor_devices", [])) if isinstance(usb_data, dict) else len(usb_data)
    log(f"Active TCP sockets: {len(net_art.get('active_tcp_connections', []))} connections", "SUCCESS", audit_logger)
    log(f"Wi-Fi & Network Profiles: {len(net_art.get('wifi_profiles', []))} profiles discovered", "SUCCESS", audit_logger)
    log(f"Historical USB storage devices: {usb_count} drives logged", "SUCCESS", audit_logger)

    # Step 2 (RFC 3227 Tier 1B): Live DNS Resolver Cache
    log("[RFC 3227 - Tier 1] Harvesting volatile DNS resolver cache & C2 indicators...", "INFO", audit_logger)
    data["dns_cache_artifacts"] = collect_dns_cache()
    dns_art = data["dns_cache_artifacts"]
    log(f"DNS Cache: {dns_art.get('total_records', 0)} domains resolved ({dns_art.get('flagged_count', 0)} suspicious C2 domains)", "SUCCESS", audit_logger)

    # Step 3 (RFC 3227 Tier 1C): Live Running Processes
    log("[RFC 3227 - Tier 1] Enumerating live running processes and LOLBin activity...", "INFO", audit_logger)
    data["running_processes"] = collect_running_processes()
    proc_art = data["running_processes"]
    log(f"Running Processes: {proc_art.get('total_processes', 0)} active ({proc_art.get('suspicious_processes_count', 0)} LOLBins/flagged)", "SUCCESS", audit_logger)

    # Step 4 (RFC 3227 Tier 1D): System Telemetry & Uptime
    log("[RFC 3227 - Tier 1] Acquiring OS telemetry, InstallDate, and Uptime...", "INFO", audit_logger)
    data["system_info"] = collect_system_info()
    sys_info = data["system_info"]
    log(f"Host: {sys_info.get('hostname')} | User: {sys_info.get('current_user')}", "SUCCESS", audit_logger)
    log(f"OS: {sys_info.get('product_name')} (Build: {sys_info.get('full_build_str', 'N/A')})", "SUCCESS", audit_logger)
    log(f"System Uptime: {sys_info.get('uptime_formatted', 'N/A')} (Boot: {sys_info.get('boot_time', 'N/A')})", "SUCCESS", audit_logger)

    # =========================================================================
    # TIER 2: SEMI-VOLATILE & REGISTRY/MEMORY LOGS (ShimCache, Registry, Events)
    # =========================================================================

    # Step 5 (RFC 3227 Tier 2A): ShimCache (AppCompatCache)
    log("[RFC 3227 - Tier 2] Mining Windows ShimCache (AppCompatCache) for binary executions...", "INFO", audit_logger)
    data["shimcache_artifacts"] = parse_shimcache()
    shim_art = data["shimcache_artifacts"]
    log(f"ShimCache: {shim_art.get('total_entries', 0)} binary execution records ({shim_art.get('suspicious_count', 0)} staging/temp binaries)", "SUCCESS", audit_logger)

    # Step 6 (RFC 3227 Tier 2B): Execution Artifacts (UserAssist, RunMRU, PowerShell)
    log("[RFC 3227 - Tier 2] Collecting execution evidence (PowerShell, RunMRU, UserAssist)...", "INFO", audit_logger)
    data["execution_artifacts"] = collect_execution_artifacts()
    exec_art = data["execution_artifacts"]
    ps_data = exec_art.get("powershell_history", {})
    log(f"PowerShell history: {ps_data.get('total_commands', 0)} commands ({len(ps_data.get('flagged_commands', []))} flagged)", "SUCCESS", audit_logger)
    log(f"RunMRU (Win+R history): {len(exec_art.get('run_mru', []))} items", "SUCCESS", audit_logger)
    log(f"UserAssist GUI applications: {len(exec_art.get('userassist', []))} items decoded", "SUCCESS", audit_logger)

    # Step 7 (RFC 3227 Tier 2C): Persistence & Scheduled Tasks
    log("[RFC 3227 - Tier 2] Auditing autostart persistence (Run/RunOnce, Startup, Tasks)...", "INFO", audit_logger)
    data["persistence_artifacts"] = collect_persistence_artifacts()
    pers_art = data["persistence_artifacts"]
    data["scheduled_tasks"] = collect_scheduled_tasks()
    task_art = data["scheduled_tasks"]
    log(f"Registry Run/RunOnce keys: {pers_art.get('registry_run_keys_count', 0)} entries", "SUCCESS", audit_logger)
    log(f"Scheduled Tasks: {task_art.get('total_tasks_discovered', 0)} total ({task_art.get('suspicious_tasks_count', 0)} suspicious flagged)", "SUCCESS", audit_logger)

    # Step 8 (RFC 3227 Tier 2D): Remote Execution & Event Logs
    log("[RFC 3227 - Tier 2] Auditing Event Logs, RDP sessions, and ScriptBlock RCE (4104)...", "INFO", audit_logger)
    data["event_log_artifacts"] = collect_event_logs()
    evt_art = data["event_log_artifacts"]
    data["remote_execution_artifacts"] = collect_remote_execution_artifacts()
    rce_art = data["remote_execution_artifacts"]
    log(f"Recent Installed Services (Event 7045): {evt_art.get('recent_installed_services_count', 0)}", "SUCCESS", audit_logger)
    log(f"PowerShell ScriptBlock RCE Detections: {rce_art.get('scriptblock_rce_detections_count', 0)} flagged blocks", "SUCCESS", audit_logger)
    if evt_art.get("anti_forensics_cleared_logs", {}).get("audit_logs_cleared"):
        log("CRITICAL ALERT: Windows Security/System event logs were purged (Event 104/1102)!", "ALERT", audit_logger)

    # =========================================================================
    # TIER 3: NON-VOLATILE PERSISTENT DISK ARTIFACTS (Staging Files, Browser DBs)
    # Collected last as they persist on non-volatile storage.
    # =========================================================================

    # Step 9 (RFC 3227 Tier 3A): Filesystem Staging Scan
    if not args.no_fs:
        log("[RFC 3227 - Tier 3] Scanning disk staging directories (%TEMP%, %APPDATA%)...", "INFO", audit_logger)
        data["filesystem_artifacts"] = collect_filesystem_artifacts()
        fs_art = data["filesystem_artifacts"]
        log(f"Executables in %TEMP%: {fs_art.get('temp_executables_found', 0)} found", "SUCCESS", audit_logger)
        log(f"Recent shortcut items: {fs_art.get('recent_shortcuts_found', 0)} items", "SUCCESS", audit_logger)
    else:
        log("Skipping filesystem staging scan (--no-fs)", "WARN", audit_logger)
        data["filesystem_artifacts"] = {}

    # Step 10 (RFC 3227 Tier 3B): Browser SQLite History
    if not args.no_browser:
        log("[RFC 3227 - Tier 3] Bypassing SQLite locks & harvesting disk browser history...", "INFO", audit_logger)
        data["browser_artifacts"] = collect_browser_history(max_visits_per_browser=100)
        total_visits = sum(b.get("total_visits_extracted", 0) for b in data["browser_artifacts"].values())
        total_downloads = sum(b.get("total_downloads_extracted", 0) for b in data["browser_artifacts"].values())
        log(f"Browser activity: {total_visits} URLs, {total_downloads} downloads acquired", "SUCCESS", audit_logger)
    else:
        log("Skipping browser history acquisition (--no-browser)", "WARN", audit_logger)
        data["browser_artifacts"] = {}

    # =========================================================================
    # REPORT GENERATION & CRYPTOGRAPHIC HASHING (CHAIN OF CUSTODY)
    # =========================================================================
    log("Compiling forensic reports and computing SHA-256 Chain of Custody hashes...", "INFO", audit_logger)
    hostname = sys_info.get("hostname", "TARGET")
    base_filename = f"Triage_{hostname}_{file_timestamp}"
    generated_files = []

    # JSON Report
    if not args.html_only:
        json_path = os.path.join(output_dir, f"{base_filename}.json")
        json_res = generate_json_report(data, json_path)
        if json_res["success"]:
            generated_files.append(json_res["path"])
            log(f"JSON Report written: {json_res['path']} ({json_res['size_kb']} KB)", "SUCCESS", audit_logger)
        else:
            log(f"Failed to generate JSON report: {json_res.get('error')}", "ALERT", audit_logger)

    # HTML Report
    if not args.json_only:
        html_path = os.path.join(output_dir, f"{base_filename}.html")
        html_res = generate_html_report(data, html_path)
        if html_res["success"]:
            generated_files.append(html_res["path"])
            log(f"HTML Dashboard written: {html_res['path']} ({html_res['size_kb']} KB)", "SUCCESS", audit_logger)
        else:
            log(f"Failed to generate HTML report: {html_res.get('error')}", "ALERT", audit_logger)

    # Compute SHA-256 Manifest for Chain of Custody
    manifest_path = os.path.join(output_dir, f"{base_filename}_hashes.sha256")
    try:
        with open(manifest_path, "w", encoding="utf-8") as mf:
            mf.write(f"# OmniTriage v1.1.0 - Chain of Custody SHA-256 Manifest\n")
            mf.write(f"# Generated: {timestamp_str} | Host: {hostname}\n\n")
            for fpath in generated_files:
                digest = compute_sha256(fpath)
                fname = os.path.basename(fpath)
                mf.write(f"{digest}  {fname}\n")
                log(f"SHA-256 [{fname}]: {digest}", "SUCCESS", audit_logger)
            # Also hash the audit log snapshot
            for h in audit_logger.handlers:
                h.flush()
            log_digest = compute_sha256(audit_log_path)
            mf.write(f"{log_digest}  {os.path.basename(audit_log_path)}\n")
        log(f"Chain of Custody Hash Manifest saved: {manifest_path}", "SUCCESS", audit_logger)
    except Exception as e:
        log(f"Failed to write SHA-256 manifest: {e}", "WARN", audit_logger)

    elapsed = round(time.time() - start_time, 2)
    print("\n" + "=" * 65)
    log(f"Forensic acquisition completed in {elapsed} seconds.", "SUCCESS", audit_logger)
    log(f"Review your triage reports & SHA-256 hashes in: {output_dir}", "SUCCESS", audit_logger)
    print("=" * 65 + "\n")


if __name__ == "__main__":
    main()
