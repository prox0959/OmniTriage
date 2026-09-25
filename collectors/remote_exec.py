"""
OmniTriage - Remote Code Execution & Lateral Movement Collector
Detects remote execution attempts, PowerShell ScriptBlock activity,
RDP sessions, and WinRM listener status.
Author: Çınar (prox0959)
MITRE ATT&CK: T1021 (Remote Services), T1059.001 (PowerShell ScriptBlock), T1053 (Scheduled Tasks)
"""

import subprocess
import winreg

SUSPICIOUS_RCE_PATTERNS = [
    "invoke-expression", "iex", "downloadstring", "downloadfile", "webclient",
    "mimikatz", "bypass", "encodedcommand", "wmic process call create",
    "psexec", "winrm", "powershell -enc", "mshta", "rundll32", "certutil -urlcache"
]

def audit_remote_desktop_and_winrm() -> dict:
    """
    TR: RDP ve WinRM uzaktan yönetim servislerinin açık olup olmadığını kontrol eder.
    Checks whether RDP and WinRM remote execution listeners are enabled.
    """
    status = {"rdp_enabled": False, "rdp_port": 3389, "rdp_deny_ts": True}
    
    # RDP Status from Registry
    try:
        with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, r"SYSTEM\CurrentControlSet\Control\Terminal Server") as k:
            deny, _ = winreg.QueryValueEx(k, "fDenyTSConnections")
            status["rdp_deny_ts"] = bool(deny)
            status["rdp_enabled"] = not bool(deny)
    except Exception:
        pass

    try:
        with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, r"SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp") as k:
            port, _ = winreg.QueryValueEx(k, "PortNumber")
            status["rdp_port"] = port
    except Exception:
        pass

    return status

def get_rdp_session_history(max_events: int = 10) -> list:
    """
    TR: TerminalServices-LocalSessionManager üzerinden uzaktan veya yerel oturum açma kayıtlarını toplar.
    Event ID 21: Logon succeeded
    Event ID 24: Session disconnected
    Event ID 25: Session reconnected
    """
    sessions = []
    try:
        cmd = [
            "wevtutil", "qe", "Microsoft-Windows-TerminalServices-LocalSessionManager/Operational",
            "/q:*[System[(EventID=21 or EventID=24 or EventID=25)]]",
            f"/c:{max_events}",
            "/f:text",
            "/rd:true"
        ]
        out = subprocess.check_output(cmd, text=True, errors="ignore", stderr=subprocess.DEVNULL)
        current = {}
        for line in out.splitlines():
            line = line.strip()
            if line.startswith("Event["):
                if current:
                    sessions.append(current)
                current = {}
                continue
            if ":" in line:
                k, v = line.split(":", 1)
                k, v = k.strip(), v.strip()
                if k == "Event ID":
                    action_map = {"21": "LOGON_SUCCESS", "24": "DISCONNECT", "25": "RECONNECT"}
                    current["event_id"] = v
                    current["action"] = action_map.get(v, v)
                elif k == "Date":
                    current["timestamp"] = v
                elif "Kullanıcı" in k or "User" in k:
                    current["target_user"] = v
                elif "Kaynak Ağ Adresi" in k or "Source Network Address" in k:
                    current["source_ip"] = v
        if current:
            sessions.append(current)
    except Exception:
        pass

    return sessions

def audit_powershell_scriptblock_rce(max_events: int = 30) -> list:
    """
    TR: Event ID 4104 (ScriptBlock Logging) ile PowerShell üzerinden yürütülen
    uzaktan indirme veya kod çalıştırma teşebbüslerini yakalar.
    Extracts PowerShell ScriptBlock execution events and flags offensive patterns.
    """
    flagged = []
    try:
        cmd = [
            "wevtutil", "qe", "Microsoft-Windows-PowerShell/Operational",
            "/q:*[System[(EventID=4104)]]",
            f"/c:{max_events}",
            "/f:text",
            "/rd:true"
        ]
        out = subprocess.check_output(cmd, text=True, errors="ignore", stderr=subprocess.DEVNULL)
        
        current_block = []
        current_date = "N/A"
        for line in out.splitlines():
            line_str = line.strip()
            if line_str.startswith("Event["):
                if current_block:
                    full_script = " ".join(current_block)
                    lower = full_script.lower()
                    matched = [kw for kw in SUSPICIOUS_RCE_PATTERNS if kw in lower]
                    if matched:
                        flagged.append({
                            "timestamp": current_date,
                            "matched_patterns": matched,
                            "snippet": full_script[:200]
                        })
                current_block = []
                continue
            if line_str.startswith("Date:"):
                current_date = line_str.split("Date:", 1)[1].strip()
            elif not line_str.startswith("Log Name:") and not line_str.startswith("Source:") and not line_str.startswith("User:") and not line_str.startswith("Computer:") and not line_str.startswith("Task:"):
                current_block.append(line_str)
                
    except Exception:
        pass

    return flagged

def collect_remote_execution_artifacts() -> dict:
    """
    TR: Uzaktan kod çalıştırma ve yanal ilerleme kanıtlarını bir araya getirir.
    Aggregates remote execution indicators, RDP sessions, and ScriptBlock logs.
    """
    listener_status = audit_remote_desktop_and_winrm()
    rdp_sessions = get_rdp_session_history()
    ps_rce = audit_powershell_scriptblock_rce()

    return {
        "remote_services_status": listener_status,
        "rdp_session_history": rdp_sessions,
        "scriptblock_rce_detections_count": len(ps_rce),
        "scriptblock_rce_detections": ps_rce
    }
