"""
OmniTriage - Program Execution Artifacts Collector
Extracts evidence of executed programs: PowerShell history, RunMRU (Win+R),
UserAssist (ROT13 decoded), and BAM (Background Activity Moderator).
Author: Çınar (prox0959)
"""

import os
import re
import codecs
import winreg
import struct
from datetime import datetime

SUSPICIOUS_CMD_KEYWORDS = [
    "invoke-expression", "iex", "downloadstring", "downloadfile", "webclient",
    "mimikatz", "bypass", "encodedcommand", "vssadmin", "certutil",
    "bitsadmin", "rundll32", "regsvr32", "powershell -enc", "whoami",
    "net user", "net localgroup", "nltest", "taskkill", "sc stop"
]

def parse_filetime(filetime_int: int) -> str:
    """
    TR: Windows 64-bit FILETIME değerini okunabilir ISO tarih saatine çevirir.
    Converts 64-bit Windows FILETIME (intervals of 100ns since 1601-01-01) to ISO string.
    """
    try:
        if filetime_int <= 0:
            return "N/A"
        # 11644473600 is seconds between 1601-01-01 and 1970-01-01
        epoch_seconds = (filetime_int / 10_000_000) - 11644473600
        if 0 < epoch_seconds < 4102444800: # between 1970 and 2100
            return datetime.utcfromtimestamp(epoch_seconds).strftime('%Y-%m-%d %H:%M:%S UTC')
    except Exception:
        pass
    return "N/A"

def get_powershell_history() -> dict:
    """
    TR: PSReadLine ConsoleHost_history.txt dosyasını okur ve şüpheli komutları analiz eder.
    Reads PSReadLine history and flags offensive or evasion commands.
    """
    history_file = os.path.expandvars(r"%APPDATA%\Microsoft\Windows\PowerShell\PSReadLine\ConsoleHost_history.txt")
    if not os.path.exists(history_file):
        return {"exists": False, "total_commands": 0, "commands": [], "flagged": []}

    try:
        with open(history_file, "r", encoding="utf-8", errors="replace") as f:
            lines = [line.strip() for line in f if line.strip()]

        flagged = []
        for idx, line in enumerate(lines, 1):
            lower_line = line.lower()
            matched = [kw for kw in SUSPICIOUS_CMD_KEYWORDS if kw in lower_line]
            if matched:
                flagged.append({
                    "line_number": idx,
                    "command": line,
                    "matched_keywords": matched
                })

        return {
            "exists": True,
            "path": history_file,
            "total_commands": len(lines),
            "recent_commands": lines[-50:] if len(lines) > 50 else lines,
            "flagged_commands": flagged
        }
    except Exception as e:
        return {"exists": True, "error": str(e), "total_commands": 0}

def get_run_mru() -> list:
    """
    TR: Win+R (Çalıştır) penceresinden çalıştırılan komut geçmişini Registry'den çeker.
    Reads RunMRU history (Run dialog box executed commands).
    """
    entries = []
    try:
        with winreg.OpenKey(winreg.HKEY_CURRENT_USER, r"Software\Microsoft\Windows\CurrentVersion\Explorer\RunMRU") as key:
            try:
                mru_order, _ = winreg.QueryValueEx(key, "MRUList")
            except FileNotFoundError:
                mru_order = ""

            for i in range(winreg.QueryInfoKey(key)[1]):
                name, val, _ = winreg.EnumValue(key, i)
                if name != "MRUList" and isinstance(val, str):
                    # Clean trailing \1 or \0
                    clean_val = val.rstrip("\x01\x00")
                    entries.append({
                        "key": name,
                        "command": clean_val,
                        "order_index": mru_order.find(name) if mru_order else -1
                    })
    except Exception:
        pass
    
    entries.sort(key=lambda x: x["order_index"] if x["order_index"] != -1 else 999)
    return entries

def get_userassist() -> list:
    """
    TR: Explorer UserAssist anahtarını tarar ve ROT13 ile şifrelenmiş GUI program yürütme kayıtlarını çözer.
    Scans UserAssist registry keys and decodes ROT13 execution artifacts.
    """
    artifacts = []
    base_path = r"Software\Microsoft\Windows\CurrentVersion\Explorer\UserAssist"
    try:
        with winreg.OpenKey(winreg.HKEY_CURRENT_USER, base_path) as root_key:
            num_subkeys = winreg.QueryInfoKey(root_key)[0]
            for i in range(num_subkeys):
                guid = winreg.EnumKey(root_key, i)
                count_path = f"{base_path}\\{guid}\\Count"
                try:
                    with winreg.OpenKey(winreg.HKEY_CURRENT_USER, count_path) as count_key:
                        num_vals = winreg.QueryInfoKey(count_key)[1]
                        for j in range(num_vals):
                            name, val, val_type = winreg.EnumValue(count_key, j)
                            # UserAssist values are ROT13 encoded
                            decoded_name = codecs.decode(name, 'rot_13')
                            if not decoded_name.endswith(".exe") and not decoded_name.endswith(".lnk"):
                                continue

                            run_count = 0
                            last_exec = "N/A"
                            if isinstance(val, bytes) and len(val) >= 72:
                                # Standard Win7/10/11 UserAssist format
                                run_count = struct.unpack_from("<I", val, 4)[0]
                                ft_raw = struct.unpack_from("<Q", val, 60)[0]
                                last_exec = parse_filetime(ft_raw)

                            artifacts.append({
                                "decoded_name": decoded_name,
                                "run_count": run_count,
                                "last_execution": last_exec
                            })
                except Exception:
                    continue
    except Exception:
        pass

    # Sort by run count descending
    artifacts.sort(key=lambda x: x["run_count"], reverse=True)
    return artifacts[:100]

def get_bam_artifacts() -> list:
    """
    TR: Background Activity Moderator (BAM) kayıtlarını çeker. Windows 10 Fall Creators ve üzeri.
    Reads BAM registry entries (recent executable paths and execution timestamps).
    """
    entries = []
    base_bam = r"SYSTEM\CurrentControlSet\Services\bam\State\UserSettings"
    try:
        with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, base_bam) as bam_key:
            num_subkeys = winreg.QueryInfoKey(bam_key)[0]
            for i in range(num_subkeys):
                sid = winreg.EnumKey(bam_key, i)
                sid_path = f"{base_bam}\\{sid}"
                try:
                    with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, sid_path) as user_key:
                        num_vals = winreg.QueryInfoKey(user_key)[1]
                        for j in range(num_vals):
                            name, val, _ = winreg.EnumValue(user_key, j)
                            if isinstance(val, bytes) and len(val) >= 8:
                                ft_raw = struct.unpack_from("<Q", val, 0)[0]
                                ts = parse_filetime(ft_raw)
                                entries.append({
                                    "binary_path": name,
                                    "user_sid": sid,
                                    "last_execution": ts
                                })
                except Exception:
                    continue
    except Exception:
        pass

    return entries

def collect_execution_artifacts() -> dict:
    """
    TR: Tüm program çalıştırma kanıtlarını bir araya getirir.
    Collects PowerShell, RunMRU, UserAssist, and BAM execution evidence.
    """
    return {
        "powershell_history": get_powershell_history(),
        "run_mru": get_run_mru(),
        "userassist": get_userassist(),
        "bam_activity": get_bam_artifacts()
    }
