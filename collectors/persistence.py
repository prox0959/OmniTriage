"""
OmniTriage - Persistence Mechanisms Collector
Inspects Windows Registry Run/RunOnce keys and Startup folders for autostart entries.
Author: Çınar (prox0959)
MITRE ATT&CK: T1547.001 (Boot or Logon Autostart Execution)
"""

import os
import winreg

RUN_KEYS = [
    (winreg.HKEY_CURRENT_USER, r"Software\Microsoft\Windows\CurrentVersion\Run", "HKCU_Run"),
    (winreg.HKEY_CURRENT_USER, r"Software\Microsoft\Windows\CurrentVersion\RunOnce", "HKCU_RunOnce"),
    (winreg.HKEY_LOCAL_MACHINE, r"Software\Microsoft\Windows\CurrentVersion\Run", "HKLM_Run"),
    (winreg.HKEY_LOCAL_MACHINE, r"Software\Microsoft\Windows\CurrentVersion\RunOnce", "HKLM_RunOnce"),
    (winreg.HKEY_LOCAL_MACHINE, r"Software\WOW6432Node\Microsoft\Windows\CurrentVersion\Run", "HKLM_WOW64_Run"),
]

def scan_registry_run_keys() -> list:
    """
    TR: HKCU ve HKLM altındaki Run ve RunOnce kayıt defteri anahtarlarını tarar.
    Scans autostart registry keys across Current User and Local Machine hives.
    """
    entries = []
    for root_hive, subkey_path, hive_tag in RUN_KEYS:
        try:
            with winreg.OpenKey(root_hive, subkey_path) as key:
                num_vals = winreg.QueryInfoKey(key)[1]
                for i in range(num_vals):
                    name, val, _ = winreg.EnumValue(key, i)
                    entries.append({
                        "hive_location": hive_tag,
                        "registry_path": subkey_path,
                        "entry_name": name,
                        "command_line": str(val)
                    })
        except Exception:
            continue
    return entries

def scan_startup_folders() -> list:
    """
    TR: Kullanıcı ve Sistem Başlangıç (Startup) klasörlerindeki kısayol ve dosyaları tespit eder.
    Scans Startup directories in User Profile and ProgramData.
    """
    startup_paths = [
        ("User_Startup", os.path.expandvars(r"%APPDATA%\Microsoft\Windows\Start Menu\Programs\Startup")),
        ("Common_Startup", os.path.expandvars(r"%PROGRAMDATA%\Microsoft\Windows\Start Menu\Programs\Startup"))
    ]

    items = []
    for label, folder in startup_paths:
        if not os.path.exists(folder):
            continue
        try:
            for fname in os.listdir(folder):
                full_path = os.path.join(folder, fname)
                if os.path.isfile(full_path):
                    items.append({
                        "location_type": label,
                        "folder_path": folder,
                        "filename": fname,
                        "full_path": full_path,
                        "size_bytes": os.path.getsize(full_path)
                    })
        except Exception:
            continue
    return items

def collect_persistence_artifacts() -> dict:
    """
    TR: Kayıt defteri ve klasör tabanlı başlangıç mekanizmalarını toplar.
    Aggregates registry autostarts and startup folder artifacts.
    """
    reg_runs = scan_registry_run_keys()
    startup_files = scan_startup_folders()

    return {
        "registry_run_keys_count": len(reg_runs),
        "registry_run_keys": reg_runs,
        "startup_folder_items_count": len(startup_files),
        "startup_folder_items": startup_files
    }
