"""
OmniTriage - Standalone HTML Forensic Report Generator
Generates an interactive, zero-dependency dark-themed triage dashboard.
Author: Çınar (prox0959)
"""

import os
import json
import html

def escape(val) -> str:
    """Safe HTML escape."""
    if val is None:
        return ""
    return html.escape(str(val))

def generate_html_report(data: dict, output_path: str) -> dict:
    """
    TR: Tamamen bağımsız, çevrimdışı çalışabilen, modern karanlık temalı bir adli bilişim HTML raporu üretir.
    Generates a standalone, dark-themed responsive HTML forensic dashboard.
    """
    try:
        sys_info = data.get("system_info", {})
        exec_info = data.get("execution_artifacts", {})
        browser_info = data.get("browser_artifacts", {})
        net_info = data.get("network_artifacts", {})
        fs_info = data.get("filesystem_artifacts", {})
        persist_info = data.get("persistence_artifacts", {})

        hostname = sys_info.get("hostname", "UNKNOWN")
        user = sys_info.get("current_user", "UNKNOWN")
        install_date = sys_info.get("install_date_local", "N/A")
        uptime = sys_info.get("uptime_formatted", "N/A")
        os_name = f"{sys_info.get('product_name', 'Windows')} ({sys_info.get('display_version', '')})"
        scan_time = data.get("metadata", {}).get("scan_timestamp", "N/A")

        # Counts
        ps_flagged = len(exec_info.get("powershell_history", {}).get("flagged_commands", []))
        ps_total = exec_info.get("powershell_history", {}).get("total_commands", 0)
        run_mru_count = len(exec_info.get("run_mru", []))
        temp_exe_count = fs_info.get("temp_executables_found", 0)
        wifi_count = len(net_info.get("wifi_profiles", []))
        usb_raw = net_info.get("usb_storage_history", {})
        usb_list = usb_raw.get("usbstor_devices", []) if isinstance(usb_raw, dict) else (usb_raw if isinstance(usb_raw, list) else [])
        usb_count = len(usb_list)
        persist_count = persist_info.get("registry_run_keys_count", 0) + persist_info.get("startup_folder_items_count", 0)

        # Build Browser rows
        browser_rows_html = ""
        for b_name, b_data in browser_info.items():
            for v in b_data.get("visits", [])[:30]:
                browser_rows_html += f"""
                <tr>
                    <td><span class="badge badge-blue">{escape(b_name)}</span></td>
                    <td class="url-cell" title="{escape(v.get('url'))}">{escape(v.get('title') or v.get('url')[:60])}</td>
                    <td>{escape(v.get('visit_count'))}</td>
                    <td class="mono">{escape(v.get('last_visit_utc'))}</td>
                </tr>
                """

        # Build Temp Executable rows
        temp_exe_rows_html = ""
        for item in fs_info.get("temp_executables", []):
            temp_exe_rows_html += f"""
            <tr>
                <td class="mono text-red">{escape(item.get('filename'))}</td>
                <td class="path-cell" title="{escape(item.get('path'))}">{escape(item.get('path'))}</td>
                <td>{escape(item.get('size_bytes'))} B</td>
                <td class="mono text-muted">{escape(item.get('sha256')[:16])}...</td>
                <td class="mono">{escape(item.get('modified_time'))}</td>
            </tr>
            """

        # Build RunMRU rows
        runmru_rows_html = ""
        for item in exec_info.get("run_mru", []):
            runmru_rows_html += f"""
            <tr>
                <td><span class="badge badge-purple">{escape(item.get('key'))}</span></td>
                <td class="mono">{escape(item.get('command'))}</td>
            </tr>
            """

        # Build PowerShell history rows
        ps_rows_html = ""
        for cmd in exec_info.get("powershell_history", {}).get("recent_commands", []):
            is_susp = any(kw in cmd.lower() for kw in ["mimikatz", "downloadstring", "bypass", "iex", "whoami"])
            badge = '<span class="badge badge-red">FLAGGED</span>' if is_susp else '<span class="badge badge-gray">NORMAL</span>'
            ps_rows_html += f"""
            <tr>
                <td>{badge}</td>
                <td class="mono {'text-red' if is_susp else ''}">{escape(cmd)}</td>
            </tr>
            """

        # Build USB rows
        usb_rows_html = ""
        for usb in usb_list:
            usb_rows_html += f"""
            <tr>
                <td class="mono">{escape(usb.get('friendly_name'))}</td>
                <td>{escape(usb.get('manufacturer'))}</td>
                <td class="mono text-muted">{escape(usb.get('serial_number'))}</td>
            </tr>
            """

        # Build Wi-Fi rows
        wifi_rows_html = ""
        for w in net_info.get("wifi_profiles", []):
            wifi_rows_html += f"""
            <tr>
                <td><strong>{escape(w.get('profile_name'))}</strong></td>
                <td><span class="badge badge-green">{escape(w.get('type'))}</span></td>
                <td class="mono">{escape(w.get('date_created'))}</td>
                <td class="mono">{escape(w.get('date_last_connected'))}</td>
            </tr>
            """

        # Build Persistence rows
        persist_rows_html = ""
        for rk in persist_info.get("registry_run_keys", []):
            persist_rows_html += f"""
            <tr>
                <td><span class="badge badge-yellow">{escape(rk.get('hive_location'))}</span></td>
                <td><strong>{escape(rk.get('entry_name'))}</strong></td>
                <td class="mono path-cell" title="{escape(rk.get('command_line'))}">{escape(rk.get('command_line'))}</td>
            </tr>
            """
        for sf in persist_info.get("startup_folder_items", []):
            persist_rows_html += f"""
            <tr>
                <td><span class="badge badge-purple">{escape(sf.get('location_type'))}</span></td>
                <td><strong>{escape(sf.get('filename'))}</strong></td>
                <td class="mono path-cell">{escape(sf.get('full_path'))}</td>
            </tr>
            """

        html_content = f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>OmniTriage Report - {escape(hostname)}</title>
    <style>
        :root {{
            --bg-primary: #0d1117;
            --bg-secondary: #161b22;
            --border-color: #30363d;
            --text-primary: #c9d1d9;
            --text-secondary: #8b949e;
            --accent-blue: #58a6ff;
            --accent-green: #3fb950;
            --accent-red: #f85149;
            --accent-yellow: #d29922;
            --accent-purple: #bc8cff;
        }}
        * {{ box-sizing: border-box; margin: 0; padding: 0; }}
        body {{
            background: var(--bg-primary);
            color: var(--text-primary);
            font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Helvetica, Arial, sans-serif;
            padding: 24px;
            line-height: 1.5;
        }}
        .header {{
            display: flex;
            justify-content: space-between;
            align-items: center;
            border-bottom: 1px solid var(--border-color);
            padding-bottom: 18px;
            margin-bottom: 24px;
        }}
        .logo-title h1 {{
            font-size: 26px;
            font-weight: 700;
            color: #ffffff;
            letter-spacing: -0.5px;
        }}
        .logo-title p {{
            font-size: 13px;
            color: var(--text-secondary);
        }}
        .metrics-grid {{
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(180px, 1fr));
            gap: 14px;
            margin-bottom: 24px;
        }}
        .metric-card {{
            background: var(--bg-secondary);
            border: 1px solid var(--border-color);
            border-radius: 8px;
            padding: 14px 16px;
        }}
        .metric-card .title {{
            font-size: 12px;
            color: var(--text-secondary);
            text-transform: uppercase;
            font-weight: 600;
            margin-bottom: 4px;
        }}
        .metric-card .value {{
            font-size: 20px;
            font-weight: bold;
            color: #ffffff;
        }}
        .metric-card .subtext {{
            font-size: 11px;
            color: var(--text-secondary);
            margin-top: 4px;
        }}
        .section-box {{
            background: var(--bg-secondary);
            border: 1px solid var(--border-color);
            border-radius: 8px;
            margin-bottom: 20px;
            overflow: hidden;
        }}
        .section-header {{
            padding: 12px 16px;
            border-bottom: 1px solid var(--border-color);
            font-weight: 600;
            font-size: 14px;
            display: flex;
            justify-content: space-between;
            align-items: center;
            background: rgba(255, 255, 255, 0.02);
        }}
        .section-content {{
            padding: 12px 16px;
            overflow-x: auto;
        }}
        table {{
            width: 100%;
            border-collapse: collapse;
            font-size: 13px;
        }}
        th, td {{
            text-align: left;
            padding: 8px 12px;
            border-bottom: 1px solid rgba(255, 255, 255, 0.05);
        }}
        th {{
            color: var(--text-secondary);
            font-size: 11px;
            text-transform: uppercase;
        }}
        tr:hover td {{
            background: rgba(255, 255, 255, 0.03);
        }}
        .mono {{
            font-family: ui-monospace, SFMono-Regular, "SF Mono", Menlo, Consolas, monospace;
            font-size: 12px;
        }}
        .text-red {{ color: var(--accent-red); }}
        .text-green {{ color: var(--accent-green); }}
        .text-muted {{ color: var(--text-secondary); }}
        .badge {{
            display: inline-block;
            padding: 2px 7px;
            border-radius: 12px;
            font-size: 11px;
            font-weight: 600;
        }}
        .badge-blue {{ background: rgba(88, 166, 255, 0.15); color: var(--accent-blue); }}
        .badge-green {{ background: rgba(63, 185, 80, 0.15); color: var(--accent-green); }}
        .badge-red {{ background: rgba(248, 81, 73, 0.15); color: var(--accent-red); }}
        .badge-yellow {{ background: rgba(210, 153, 34, 0.15); color: var(--accent-yellow); }}
        .badge-purple {{ background: rgba(188, 140, 255, 0.15); color: var(--accent-purple); }}
        .badge-gray {{ background: rgba(139, 148, 158, 0.15); color: var(--text-secondary); }}
        .path-cell {{
            max-width: 320px;
            white-space: nowrap;
            overflow: hidden;
            text-overflow: ellipsis;
        }}
        .url-cell {{
            max-width: 380px;
            white-space: nowrap;
            overflow: hidden;
            text-overflow: ellipsis;
        }}
        .footer {{
            text-align: center;
            font-size: 12px;
            color: var(--text-secondary);
            margin-top: 30px;
            padding-top: 15px;
            border-top: 1px solid var(--border-color);
        }}
    </style>
</head>
<body>

    <div class="header">
        <div class="logo-title">
            <h1>OmniTriage // Forensic Report</h1>
            <p>Live Incident Response & Digital Forensics Acquisition | Zero-Dependency USB Responder</p>
        </div>
        <div>
            <span class="badge badge-purple">Target: {escape(hostname)}\\{escape(user)}</span>
            <span class="badge badge-blue">{escape(scan_time)}</span>
        </div>
    </div>

    <!-- METRICS OVERVIEW -->
    <div class="metrics-grid">
        <div class="metric-card">
            <div class="title">Operating System</div>
            <div class="value" style="font-size:16px;">{escape(os_name)}</div>
            <div class="subtext">Format: {escape(install_date)}</div>
        </div>
        <div class="metric-card">
            <div class="title">System Uptime</div>
            <div class="value">{escape(uptime)}</div>
            <div class="subtext">RAM: {escape(sys_info.get('memory', {}).get('total_physical_gb', 'N/A'))} GB Total</div>
        </div>
        <div class="metric-card">
            <div class="title">PowerShell History</div>
            <div class="value">{escape(ps_total)} cmds</div>
            <div class="subtext text-{'red' if ps_flagged > 0 else 'green'}">{escape(ps_flagged)} flagged indicators</div>
        </div>
        <div class="metric-card">
            <div class="title">Temp Staging Files</div>
            <div class="value">{escape(temp_exe_count)}</div>
            <div class="subtext">Executables in %TEMP%</div>
        </div>
        <div class="metric-card">
            <div class="title">USB Device History</div>
            <div class="value">{escape(usb_count)}</div>
            <div class="subtext">Historical USBSTOR drives</div>
        </div>
        <div class="metric-card">
            <div class="title">Persistence Items</div>
            <div class="value">{escape(persist_count)}</div>
            <div class="subtext">Run keys & Startup items</div>
        </div>
    </div>

    <!-- SECTION: STAGING / SUSPICIOUS FILES -->
    <div class="section-box">
        <div class="section-header">
            <span>Staging Directories (Suspicious Executables in %TEMP%)</span>
            <span class="badge badge-red">MITRE T1036 / T1059</span>
        </div>
        <div class="section-content">
            <table>
                <thead>
                    <tr><th>Filename</th><th>Full Path</th><th>Size</th><th>SHA-256</th><th>Modified</th></tr>
                </thead>
                <tbody>
                    {temp_exe_rows_html or '<tr><td colspan="5" class="text-muted">No suspicious executables found in %TEMP%.</td></tr>'}
                </tbody>
            </table>
        </div>
    </div>

    <!-- SECTION: POWERSHELL & RUN EXECUTION -->
    <div class="section-box">
        <div class="section-header">
            <span>PowerShell Execution Log (Recent & Flagged)</span>
            <span class="badge badge-blue">PSReadLine History</span>
        </div>
        <div class="section-content">
            <table>
                <thead>
                    <tr><th>Status</th><th>Command Line</th></tr>
                </thead>
                <tbody>
                    {ps_rows_html or '<tr><td colspan="2" class="text-muted">No PowerShell history file present.</td></tr>'}
                </tbody>
            </table>
        </div>
    </div>

    <!-- SECTION: RUN MRU -->
    <div class="section-box">
        <div class="section-header">
            <span>Win+R RunMRU History</span>
            <span class="badge badge-purple">Explorer Run Dialog</span>
        </div>
        <div class="section-content">
            <table>
                <thead>
                    <tr><th>Index</th><th>Command Line</th></tr>
                </thead>
                <tbody>
                    {runmru_rows_html or '<tr><td colspan="2" class="text-muted">No RunMRU commands logged.</td></tr>'}
                </tbody>
            </table>
        </div>
    </div>

    <!-- SECTION: BROWSER VISITATION -->
    <div class="section-box">
        <div class="section-header">
            <span>Recent Web Activity & Browser History</span>
            <span class="badge badge-green">Lock-Bypassed SQLite</span>
        </div>
        <div class="section-content">
            <table>
                <thead>
                    <tr><th>Browser</th><th>Page Title / URL</th><th>Visits</th><th>Last Visited (UTC)</th></tr>
                </thead>
                <tbody>
                    {browser_rows_html or '<tr><td colspan="4" class="text-muted">No browser history records extracted.</td></tr>'}
                </tbody>
            </table>
        </div>
    </div>

    <!-- SECTION: USBSTOR & PERIPHERALS -->
    <div class="section-box">
        <div class="section-header">
            <span>Historical USB Drives Connected</span>
            <span class="badge badge-yellow">USBSTOR Registry</span>
        </div>
        <div class="section-content">
            <table>
                <thead>
                    <tr><th>Friendly Name / Device</th><th>Manufacturer</th><th>Serial Number</th></tr>
                </thead>
                <tbody>
                    {usb_rows_html or '<tr><td colspan="3" class="text-muted">No historical USB storage devices detected.</td></tr>'}
                </tbody>
            </table>
        </div>
    </div>

    <!-- SECTION: WI-FI PROFILES -->
    <div class="section-box">
        <div class="section-header">
            <span>Known Wi-Fi & Network Profiles</span>
            <span class="badge badge-blue">NetworkList Registry</span>
        </div>
        <div class="section-content">
            <table>
                <thead>
                    <tr><th>SSID / Profile Name</th><th>Type</th><th>First Created</th><th>Last Connected</th></tr>
                </thead>
                <tbody>
                    {wifi_rows_html or '<tr><td colspan="4" class="text-muted">No network profiles detected.</td></tr>'}
                </tbody>
            </table>
        </div>
    </div>

    <!-- SECTION: PERSISTENCE -->
    <div class="section-box">
        <div class="section-header">
            <span>Persistence Mechanisms (Run / RunOnce / Startup)</span>
            <span class="badge badge-red">MITRE T1547.001</span>
        </div>
        <div class="section-content">
            <table>
                <thead>
                    <tr><th>Source</th><th>Name</th><th>Target / Command Line</th></tr>
                </thead>
                <tbody>
                    {persist_rows_html or '<tr><td colspan="3" class="text-muted">No persistence registry or startup items found.</td></tr>'}
                </tbody>
            </table>
        </div>
    </div>

    <div class="footer">
        Generated by <strong>OmniTriage v1.0.0</strong> | Authored by Çınar (prox0959) | Zero-Dependency Forensic Framework
    </div>

</body>
</html>
"""
        os.makedirs(os.path.dirname(os.path.abspath(output_path)), exist_ok=True)
        with open(output_path, "w", encoding="utf-8") as f:
            f.write(html_content)

        file_size = os.path.getsize(output_path)
        return {
            "success": True,
            "path": output_path,
            "size_bytes": file_size,
            "size_kb": round(file_size / 1024, 2)
        }
    except Exception as e:
        return {
            "success": False,
            "error": str(e)
        }
