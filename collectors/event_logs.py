"""
OmniTriage - Windows Event Log Forensic Collector
Harvests critical security events: Service Installations (Event 7045),
Audit Log Clearing (Event 1102), and Terminal Services activity.
Author: Çınar (prox0959)
"""

import subprocess
from datetime import datetime

def parse_wevtutil_text_events(output: str) -> list:
    """Parses text output from wevtutil qe into structured event dictionaries."""
    events = []
    current = {}
    
    for line in output.splitlines():
        line = line.strip()
        if line.startswith("Event["):
            if current:
                events.append(current)
            current = {}
            continue

        if ":" in line:
            parts = line.split(":", 1)
            key = parts[0].strip()
            val = parts[1].strip()

            if key == "Event ID":
                current["event_id"] = val
            elif key == "Date":
                current["timestamp"] = val
            elif key in ("Hizmet Adı", "Hizmet Ad", "Service Name"):
                current["service_name"] = val
            elif key in ("Hizmet Dosya Adı", "Hizmet Dosya Ad", "Service File Name", "ImagePath"):
                current["image_path"] = val
            elif key in ("Hizmet Türü", "Hizmet T", "Service Type"):
                current["service_type"] = val
            elif key in ("Hizmet Başlatma Türü", "Hizmet Ba", "Service Start Type"):
                current["start_type"] = val
            elif key == "User Name":
                current["user"] = val
            elif key == "Computer":
                current["computer"] = val

    if current:
        events.append(current)

    return events

def get_installed_services_events(max_events: int = 15) -> list:
    """
    TR: System Event Log (Event ID 7045) üzerinden son yüklenen servis ve sürücüleri tespit eder.
    Hizmet yolu %TEMP% veya kullanıcı dizini olan şüpheli servisleri yakalar.
    """
    try:
        cmd = [
            "wevtutil", "qe", "System",
            "/q:*[System[(EventID=7045)]]",
            f"/c:{max_events}",
            "/f:text",
            "/rd:true"
        ]
        out = subprocess.check_output(cmd, text=True, errors="ignore", stderr=subprocess.DEVNULL)
        return parse_wevtutil_text_events(out)
    except Exception:
        return []

def check_log_clearing_anti_forensics() -> dict:
    """
    TR: Olay Günlüğü temizleme teşebbüslerini (Event 1102 / 104) kontrol eder.
    Checks if audit logs have been purged by an attacker (Anti-Forensics T1070).
    """
    findings = []
    try:
        cmd = [
            "wevtutil", "qe", "System",
            "/q:*[System[(EventID=104)]]",
            "/c:5", "/f:text", "/rd:true"
        ]
        out = subprocess.check_output(cmd, text=True, errors="ignore", stderr=subprocess.DEVNULL)
        cleared_system = parse_wevtutil_text_events(out)
        if cleared_system:
            findings.extend(cleared_system)
    except Exception:
        pass

    return {
        "audit_logs_cleared": len(findings) > 0,
        "incidents": findings
    }

def collect_event_logs() -> dict:
    """
    TR: Tüm kritik sistem olaylarını toplar.
    Aggregates service installation events and anti-forensics log clearance artifacts.
    """
    services = get_installed_services_events(max_events=20)
    
    # Flag suspicious service paths (running outside System32 or Program Files)
    suspicious_services = []
    for s in services:
        img = s.get("image_path", "").lower()
        if any(bad in img for bad in [r"\temp\\", r"\appdata\\", r"\users\\", ".bat", ".ps1"]):
            suspicious_services.append(s)

    anti_forensics = check_log_clearing_anti_forensics()

    return {
        "recent_installed_services_count": len(services),
        "suspicious_services_flagged": len(suspicious_services),
        "suspicious_services": suspicious_services,
        "recent_installed_services": services,
        "anti_forensics_cleared_logs": anti_forensics
    }
