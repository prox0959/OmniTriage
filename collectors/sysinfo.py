"""
OmniTriage - System Information Collector
Extracts OS version, installation date, system uptime, boot time, and hardware telemetry.
Author: Çınar (prox0959)
"""

import os
import sys
import time
import winreg
import ctypes
from datetime import datetime

class MEMORYSTATUSEX(ctypes.Structure):
    _fields_ = [
        ("dwLength", ctypes.c_ulong),
        ("dwMemoryLoad", ctypes.c_ulong),
        ("ullTotalPhys", ctypes.c_ulonglong),
        ("ullAvailPhys", ctypes.c_ulonglong),
        ("ullTotalPageFile", ctypes.c_ulonglong),
        ("ullAvailPageFile", ctypes.c_ulonglong),
        ("ullTotalVirtual", ctypes.c_ulonglong),
        ("ullAvailVirtual", ctypes.c_ulonglong),
        ("sullAvailExtendedVirtual", ctypes.c_ulonglong),
    ]

def get_memory_info() -> dict:
    """
    TR: Windows API (GlobalMemoryStatusEx) ile fiziksel ve sanal RAM miktarını çeker.
    Returns physical and virtual RAM metrics.
    """
    stat = MEMORYSTATUSEX()
    stat.dwLength = ctypes.sizeof(MEMORYSTATUSEX)
    if ctypes.windll.kernel32.GlobalMemoryStatusEx(ctypes.byref(stat)):
        total_gb = round(stat.ullTotalPhys / (1024 ** 3), 2)
        avail_gb = round(stat.ullAvailPhys / (1024 ** 3), 2)
        return {
            "total_physical_gb": total_gb,
            "available_physical_gb": avail_gb,
            "memory_load_percent": stat.dwMemoryLoad
        }
    return {}

def get_uptime_info() -> dict:
    """
    TR: GetTickCount64() ile sistemin kaç milisaniyedir açık olduğunu alır ve önyükleme zamanını hesaplar.
    Calculates uptime and estimated boot time via kernel32.GetTickCount64.
    """
    try:
        millis = ctypes.windll.kernel32.GetTickCount64()
        seconds = millis / 1000.0
        boot_timestamp = time.time() - seconds
        boot_time_str = datetime.fromtimestamp(boot_timestamp).strftime('%Y-%m-%d %H:%M:%S')
        
        days = int(seconds // (24 * 3600))
        hours = int((seconds % (24 * 3600)) // 3600)
        minutes = int((seconds % 3600) // 60)
        
        return {
            "uptime_seconds": int(seconds),
            "uptime_formatted": f"{days}d {hours}h {minutes}m",
            "boot_time": boot_time_str
        }
    except Exception as e:
        return {"uptime_error": str(e)}

def collect_system_info() -> dict:
    """
    TR: Registry ve Windows API üzerinden OS sürümü, format tarihi ve donanım özetini toplar.
    Collects Windows OS product, build, InstallDate, uptime, and identity.
    """
    info = {
        "hostname": os.environ.get("COMPUTERNAME", "UNKNOWN"),
        "current_user": os.environ.get("USERNAME", "UNKNOWN"),
        "user_domain": os.environ.get("USERDOMAIN", "UNKNOWN"),
        "system_root": os.environ.get("SystemRoot", "C:\\Windows"),
        "architecture": os.environ.get("PROCESSOR_ARCHITECTURE", "x64"),
    }

    # Registry: Windows NT CurrentVersion
    try:
        with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\Microsoft\Windows NT\CurrentVersion") as key:
            def qv(name):
                try:
                    val, _ = winreg.QueryValueEx(key, name)
                    return val
                except FileNotFoundError:
                    return None

            info["product_name"] = qv("ProductName")
            info["display_version"] = qv("DisplayVersion") or qv("ReleaseId")
            info["current_build"] = qv("CurrentBuild") or qv("CurrentBuildNumber")
            info["ubr"] = qv("UBR") # Update Build Revision
            if info["current_build"] and info["ubr"]:
                info["full_build_str"] = f"{info['current_build']}.{info['ubr']}"

            # InstallDate (Unix Epoch timestamp)
            install_raw = qv("InstallDate")
            if install_raw and isinstance(install_raw, int):
                info["install_timestamp"] = install_raw
                info["install_date_utc"] = datetime.utcfromtimestamp(install_raw).strftime('%Y-%m-%d %H:%M:%S UTC')
                info["install_date_local"] = datetime.fromtimestamp(install_raw).strftime('%Y-%m-%d %H:%M:%S')
    except Exception as e:
        info["reg_error"] = str(e)

    # CPU Information from Registry
    try:
        with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, r"HARDWARE\DESCRIPTION\System\CentralProcessor\0") as key:
            cpu_name, _ = winreg.QueryValueEx(key, "ProcessorNameString")
            info["cpu_model"] = cpu_name.strip()
    except Exception:
        info["cpu_model"] = os.environ.get("PROCESSOR_IDENTIFIER", "Unknown")

    # Admin privileges check
    try:
        info["is_admin"] = bool(ctypes.windll.shell32.IsUserAnAdmin())
    except Exception:
        info["is_admin"] = False

    # Uptime & Memory
    info.update(get_uptime_info())
    info["memory"] = get_memory_info()

    return info
