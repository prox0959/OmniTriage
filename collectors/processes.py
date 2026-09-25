"""
OmniTriage - Live Running Processes & Volatile Memory Artifact Collector
Author: Çınar (prox0959)
License: MIT

Collects live volatile process state (PID, PPID, Threads, Executable Name, Full Image Path)
directly via Win32 API (CreateToolhelp32Snapshot & QueryFullProcessImageNameW) in <5ms
without spawning external child processes, preserving RFC 3227 volatile integrity.
"""

import sys
import ctypes
from ctypes import wintypes
from typing import Dict, Any, List

# Win32 Constants
TH32CS_SNAPPROCESS = 0x00000002
PROCESS_QUERY_LIMITED_INFORMATION = 0x1000
MAX_PATH = 260

# Suspicious process names (LOLBins) and anomalous parent-child relationships
SUSPICIOUS_LOLBINS = {
    "powershell.exe", "pwsh.exe", "cmd.exe", "mshta.exe", "wscript.exe",
    "cscript.exe", "rundll32.exe", "regsvr32.exe", "certutil.exe",
    "bitsadmin.exe", "wmic.exe", "vssadmin.exe", "ntdsutil.exe", "procdump.exe"
}

SUSPICIOUS_STAGING_DIRS = (
    "\\appdata\\local\\temp\\",
    "\\appdata\\roaming\\",
    "\\users\\public\\",
    "\\windows\\temp\\",
    "\\programdata\\"
)


class PROCESSENTRY32W(ctypes.Structure):
    _fields_ = [
        ("dwSize", wintypes.DWORD),
        ("cntUsage", wintypes.DWORD),
        ("th32ProcessID", wintypes.DWORD),
        ("th32DefaultHeapID", ctypes.c_size_t),
        ("th32ModuleID", wintypes.DWORD),
        ("cntThreads", wintypes.DWORD),
        ("th32ParentProcessID", wintypes.DWORD),
        ("pcPriClassBase", wintypes.LONG),
        ("dwFlags", wintypes.DWORD),
        ("szExeFile", wintypes.WCHAR * MAX_PATH),
    ]


def _get_process_path(pid: int, kernel32) -> str:
    """Queries the full disk path of a running process via QueryFullProcessImageNameW."""
    if pid in (0, 4):
        return "System Kernel"
    h_proc = kernel32.OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, False, pid)
    if not h_proc:
        return "Protected / Access Denied"
    try:
        buf = ctypes.create_unicode_buffer(1024)
        size = wintypes.DWORD(1024)
        if kernel32.QueryFullProcessImageNameW(h_proc, 0, buf, ctypes.byref(size)):
            return buf.value
        return "Unknown"
    finally:
        kernel32.CloseHandle(h_proc)


def collect_running_processes() -> Dict[str, Any]:
    """
    Enumerates all currently active processes using native Win32 kernel snapshots.
    Avoids spawning tasklist.exe/wmic.exe to minimize volatile memory footprint (RFC 3227).
    """
    if sys.platform != "win32":
        return {
            "total_processes": 0,
            "suspicious_processes_count": 0,
            "processes": [],
            "error": "Non-Windows platform"
        }

    kernel32 = ctypes.windll.kernel32
    snap = kernel32.CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0)
    if snap == -1 or snap is None:
        return {
            "total_processes": 0,
            "suspicious_processes_count": 0,
            "processes": [],
            "error": "CreateToolhelp32Snapshot failed"
        }

    processes: List[Dict[str, Any]] = []
    pid_to_name: Dict[int, str] = {}

    try:
        pe = PROCESSENTRY32W()
        pe.dwSize = ctypes.sizeof(PROCESSENTRY32W)

        if kernel32.Process32FirstW(snap, ctypes.byref(pe)):
            while True:
                pid = pe.th32ProcessID
                ppid = pe.th32ParentProcessID
                threads = pe.cntThreads
                exe_name = pe.szExeFile
                pid_to_name[pid] = exe_name

                full_path = _get_process_path(pid, kernel32)

                processes.append({
                    "pid": pid,
                    "ppid": ppid,
                    "image_name": exe_name,
                    "full_path": full_path,
                    "threads": threads,
                })

                if not kernel32.Process32NextW(snap, ctypes.byref(pe)):
                    break
    finally:
        kernel32.CloseHandle(snap)

    # Enrich with parent process name and heuristic flags
    suspicious_count = 0
    for proc in processes:
        parent_name = pid_to_name.get(proc["ppid"], "Terminated/Unknown")
        proc["parent_name"] = parent_name
        indicators = []

        img_lower = proc["image_name"].lower()
        path_lower = proc["full_path"].lower()
        parent_lower = parent_name.lower()

        if img_lower in SUSPICIOUS_LOLBINS:
            indicators.append(f"Active LOLBin / Administrative Shell: {proc['image_name']}")

        if any(stage in path_lower for stage in SUSPICIOUS_STAGING_DIRS):
            if "microsoft\\windows defender" not in path_lower and "microsoft\\windows\\start menu" not in path_lower:
                indicators.append(f"Process executing from user-writable staging directory: {proc['full_path']}")

        # Office or Browser spawning shell
        if parent_lower in ("winword.exe", "excel.exe", "powerpnt.exe", "outlook.exe") and img_lower in SUSPICIOUS_LOLBINS:
            indicators.append(f"CRITICAL: Office application ({parent_name}) spawned shell ({proc['image_name']})")

        proc["is_suspicious"] = len(indicators) > 0
        proc["indicators"] = indicators
        if proc["is_suspicious"]:
            suspicious_count += 1

    # Sort suspicious first, then by PID
    processes.sort(key=lambda x: (not x["is_suspicious"], x["pid"]))

    return {
        "total_processes": len(processes),
        "suspicious_processes_count": suspicious_count,
        "processes": processes
    }
