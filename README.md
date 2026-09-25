# OmniTriage ⚡

[![Python 3.8+](https://img.shields.io/badge/Python-3.8%2B-3776AB?style=flat&logo=python&logoColor=white)](https://www.python.org/)
[![Platform Windows](https://img.shields.io/badge/Platform-Windows%2010%20%7C%2011%20%7C%20Server-0078D6?style=flat&logo=windows&logoColor=white)](https://microsoft.com/windows)
[![License MIT](https://img.shields.io/badge/License-MIT-green.svg?style=flat)](LICENSE)
[![Zero External Dependencies](https://img.shields.io/badge/Dependencies-Zero%20(Pure%20Stdlib)-brightgreen.svg?style=flat)](#zero-dependency-architecture)
[![DFIR Standard](https://img.shields.io/badge/Domain-Digital%20Forensics%20%26%20IR-critical.svg?style=flat)](#mitre-attck-mapping)

> **Zero-dependency, sub-second Windows live digital forensics and incident response (DFIR) triage engine designed for rapid USB responders.**

---

## 📌 The Problem in Modern Digital Forensics

During live incident response, time and stealth are everything. Traditional triage scripts suffer from critical vulnerabilities:
1. **Tool Bloat & EDR Flags:** Tools like DFIRtriage bundle 50+ external utilities (Sysinternals, NirSoft, external batch scripts) that immediately trigger modern Endpoint Detection and Response (EDR) agents or Windows Defender alerts.
2. **Database Locks:** Live Chromium browsers (Chrome, Edge, Brave) lock their SQLite `History` databases via Windows file sharing handles (`dwShareMode`), causing standard collectors to crash or fail unless the browser is forcefully terminated (destroying volatile memory evidence).
3. **Infrastructure Burden:** Server-based agents like Velociraptor require certificates, complex network infrastructure, and background daemon installation—impossible during an ad-hoc field triage.

**OmniTriage** solves this cleanly: built from the ground up in **100% pure Python standard library** (`winreg`, `sqlite3`, `ctypes`, `subprocess`, `hashlib`, `struct`). No `pip install`, no external binaries, zero disk noise, executing in **under 1 second** and generating an interactive, standalone dark-mode HTML report alongside structured JSON.

---

## 🚀 Key Features (v1.1.0 — RFC 3227 Compliant)

* **⚖️ RFC 3227 Order of Volatility Pipeline:** Strictly sequences acquisition from most volatile to least volatile:
  1. **Tier 1 (Ephemeral/Volatile):** Active TCP sockets, live DNS resolver cache, and running process memory snapshots.
  2. **Tier 2 (Semi-Volatile/Registry):** ShimCache, UserAssist, RunMRU, Persistence keys, Scheduled Tasks, and Event Logs.
  3. **Tier 3 (Persistent Disk):** Staging directory files (`%TEMP%`, `%APPDATA%`) and locked Chromium SQLite databases.
* **🔬 Native Win32 Live Process Snapshot (`processes.py`):** Enumerates all running processes (PID, PPID, parent name, thread count, full image path) in <5ms via `CreateToolhelp32Snapshot` & `QueryFullProcessImageNameW` without spawning child processes (`tasklist.exe`), preserving volatile memory state and flagging active LOLBins or anomalous parent-child spawns (e.g., Office spawning PowerShell).
* **🔐 Chain of Custody & SHA-256 Hashing:** Automatically generates a cryptographic `_hashes.sha256` manifest and a dedicated timestamped `omnitriage_audit.log` file alongside every report for forensic integrity verification.
* **⚡ Sub-Second Live Execution:** Completes a comprehensive forensic triage in ~0.8 seconds.
* **🛡️ Zero 3rd-Party Dependencies:** Runs out-of-the-box on any Windows machine with Python installed. Does not write temp utilities or drop executables to disk.
* **🔓 SQLite Lock Bypass (Shadow Buffer Querying):** Extracts live browsing history and download logs from Chrome, Edge, and Brave even while the suspect or user has the browser actively open.
* **🧠 Program Execution Evidence:**
  * PSReadLine PowerShell command history (`ConsoleHost_history.txt`) with heuristic keyword flagging (`IEX`, `DownloadString`, `mimikatz`, `bypass`, `vssadmin`).
  * Windows Explorer RunMRU (`Win+R` dialog history).
  * UserAssist ROT13-decoded GUI execution records and timestamps.
  * Background Activity Moderator (BAM) forensic records.
* **💾 Staging & Dropper Hunting:**
  * Scans `%TEMP%`, `%APPDATA%`, and `%LOCALAPPDATA%` for suspicious binaries (`.exe`, `.dll`, `.bat`, `.ps1`, `.vbs`, `.js`, `.scr`).
  * Computes cryptographic SHA-256 hashes of staged executables for instant hash lookups.
  * Windows Recent `.lnk` shortcut activity tracking.
* **📡 Network & USB Footprint:**
  * Extracts known Wi-Fi profiles and SSIDs (with dual registry and Netsh fallback).
  * Historical USB drive connections (Vendor, Product ID, Serial number via `USBSTOR`).
  * Live listening TCP ports and active remote connections with PID association.
* **🔒 Persistence Audit (MITRE T1547.001):**
  * Audits `HKCU` and `HKLM` `Run` and `RunOnce` autostart keys.
  * Inspects User and System `Startup` directories.
* **🌐 DNS Cache & C2 IoC Hunting:**
  * Pulls live resolved DNS entries (`ipconfig /displaydns`) to detect active Command & Control infrastructure (e.g. `ngrok`, `duckdns`, `pastebin`, `discord webhooks`).
* **📡 Remote Code Execution & Lateral Movement (MITRE T1021 / T1059):**
  * Audits RDP listener status (Port, `fDenyTSConnections`) and Terminal Services logon sessions (Event ID 21/24/25).
  * PowerShell ScriptBlock Logging (Event 4104) analysis for offensive payloads (`IEX`, `DownloadString`, `mimikatz`, `encodedcommand`).
* **🏛️ ShimCache (AppCompatCache) Mining:**
  * Parses binary Application Compatibility Cache (`10ts` structure) directly from Windows Registry. Uncovers historical paths of deleted malware executables!
* **📅 Scheduled Tasks Persistence (MITRE T1053.005):**
  * Audits Windows Scheduled Tasks (`schtasks`) to detect suspicious automated triggers running out of `%TEMP%`, `%APPDATA%`, or `Users\Public`.
* **🚨 Windows Event Logs & Anti-Forensics (Event 7045 / 1102 / 104):**
  * Uncovers recently installed Windows services and kernel drivers.
  * Detects security audit log purges and anti-forensic tampering.
* **📊 Standalone Interactive Reports:**
  * Interactive dark-themed HTML report (`Triage_<HOST>_<TIMESTAMP>.html`) with zero CDN dependencies (completely offline capable).
  * Normalized structured JSON (`Triage_<HOST>_<TIMESTAMP>.json`) ready for SIEM ingestion (Splunk, Elastic, Sentinel).

---

## 🗺️ MITRE ATT&CK Mapping

| MITRE ATT&CK ID | Tactic | Technique | OmniTriage Collector |
|---|---|---|---|
| **T1059.001** | Execution | PowerShell Command History & ScriptBlocks | `execution.py`, `remote_exec.py` |
| **T1021** | Lateral Movement | Remote Services (RDP, WinRM) | `collectors/remote_exec.py` |
| **T1071.004** | Command & Control | DNS Domain Resolutions | `collectors/dns_cache.py` |
| **T1204** | Execution | User Execution (RunMRU / UserAssist / ShimCache) | `execution.py`, `shimcache.py` |
| **T1053.005** | Persistence | Scheduled Task Persistence | `collectors/tasks.py` |
| **T1070** | Anti-Forensics | Indicator Removal on Host (Log Clearing) | `collectors/event_logs.py` |
| **T1543.003** | Persistence | Windows Service Creation (Event 7045) | `collectors/event_logs.py` |
| **T1036** | Defense Evasion | Masquerading in `%TEMP%` / `%APPDATA%` | `collectors/filesystem.py` |
| **T1547.001** | Persistence | Registry Run Keys / Startup Folder | `collectors/persistence.py` |
| **T1082** | Discovery | System Information & InstallDate | `collectors/sysinfo.py` |
| **T1049** | Discovery | System Network Connections & Wi-Fi | `collectors/network.py` |
| **T1005** | Collection | Browser Data & Download Logs | `collectors/browser.py` |
| **T1005** | Collection | Browser Data & Download Logs | `collectors/browser.py` |

---

## 📂 Project Architecture

```
OmniTriage/
├── collectors/
│   ├── __init__.py
│   ├── sysinfo.py         # OS build, InstallDate/Format date, Uptime (GetTickCount64), RAM
│   ├── execution.py       # PowerShell history, RunMRU, UserAssist (ROT13), BAM
│   ├── browser.py         # Chrome, Edge, Brave SQLite lock bypass & download records
│   ├── network.py         # Wi-Fi SSIDs, USBSTOR device history, active TCP sockets
│   ├── filesystem.py      # Executables/scripts in %TEMP%, SHA-256 hashing, Recent .lnk
│   └── persistence.py     # Registry Run/RunOnce keys & Startup folder audit
├── reporters/
│   ├── __init__.py
│   ├── json_reporter.py   # Normalized JSON serialization
│   └── html_reporter.py   # Standalone dark-mode HTML dashboard
├── omnitriage.py          # Main CLI orchestrator & banner
├── run_usb_triage.bat     # One-click USB rapid response launcher
├── LICENSE                # MIT License
└── README.md
```

---

## ⚡ Quick Start

### 1. Direct Execution
```bash
git clone https://github.com/prox0959/OmniTriage.git
cd OmniTriage
python omnitriage.py
```

### 2. USB Incident Responder Deployment
Copy the `OmniTriage` folder onto an incident response USB drive. When plugged into a target machine, execute:
```cmd
run_usb_triage.bat
```
Or directly via command-line:
```cmd
python omnitriage.py --out D:\Evidence\Case_101
```

### 3. Command Line Arguments
```text
options:
  -h, --help            show this help message and exit
  --out OUT, -o OUT     Output directory for reports (default: triage_output)
  --quick, -q           Quick mode (skips deep file hashing)
  --json-only           Only produce JSON report
  --html-only           Only produce interactive HTML dashboard
  --no-browser          Skip browser history acquisition
  --no-fs               Skip staging directory filesystem scans
  --lang {en,tr}        Console output language (default: en)
```

---

## 🔬 Sample Live Output

```text
   ____                  _ _____     _                 
  / __ \____ ___  ____  (_)__   \_ __(_) __ _  __ _  ___ 
 / / / / __ `__ \/ __ \/ /  / /\/ '__/ / _` |/ _` |/ _ \
/ /_/ / / / / / / / / / /  / /  | | / / (_| | (_| |  __/
\____/_/ /_/ /_/_/ /_/_/   \/   |_|/_/ \__,_|\__, |\___|
                                             |___/      
 [::] OmniTriage v1.0.0 | Pure Python DFIR Live Triage Engine
 [::] Author: Çınar (prox0959) | Zero External Dependencies

[*] Starting live forensic acquisition on target system...
[*] Destination: C:\Forensics\Case_01
[*] Acquiring OS telemetry, InstallDate, and Uptime...
[+] Host: DESKTOP-IR01 | User: analyst
[+] OS: Windows 10 Home (Build: 26200.9457)
[+] Windows Format/Install Date: 2026-07-03 16:31:44
[+] System Uptime: 0d 6h 52m (Boot: 2026-09-24 17:29:51)
[*] Collecting program execution evidence (PowerShell, RunMRU, UserAssist)...
[+] PowerShell history: 89 commands (0 flagged)
[+] RunMRU (Win+R history): 2 items
[+] UserAssist GUI applications: 100 items decoded
[*] Bypassing SQLite locks & harvesting browser history...
[+] Browser activity: 300 URLs, 19 downloads acquired
[*] Harvesting Wi-Fi profiles, USB connection history, and active sockets...
[+] Wi-Fi & Network Profiles: 2 profiles discovered
[+] Historical USB storage devices: 3 drives logged
[+] Active TCP sockets: 139 connections
[*] Scanning staging directories (%TEMP%, %APPDATA%) for suspicious executables...
[+] Executables in %TEMP%: 40 found
[+] Recent shortcut items: 40 items
[*] Auditing autostart persistence mechanisms (Run/RunOnce, Startup)...
[+] Registry Run/RunOnce keys: 20 entries
[+] Startup folder items: 4 files
[*] Compiling forensic reports...
[+] JSON Report written: C:\Forensics\Case_01\Triage_DESKTOP-IR01_20260925_002236.json (193.21 KB)
[+] HTML Dashboard written: C:\Forensics\Case_01\Triage_DESKTOP-IR01_20260925_002236.html (88.56 KB)

=================================================================
[+] Forensic acquisition completed in 0.24 seconds.
=================================================================
```

---

## ⚖️ Legal & Ethical Notice

This software is developed strictly for authorized digital forensics, incident response, system auditing, and educational research. Always obtain proper authorization and consent prior to acquiring artifacts on any computer system.

## 📄 License

This project is licensed under the [MIT License](LICENSE) - authored by **Çınar ([@prox0959](https://github.com/prox0959))**.
