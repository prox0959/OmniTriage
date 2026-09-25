"""
OmniTriage - ShimCache (AppCompatCache) Parser
Extracts execution history from the Windows Application Compatibility Cache.
Provides historical proof of executed binaries even if they were deleted.
Author: Çınar (prox0959)
"""

import winreg
import struct

def parse_shimcache() -> dict:
    """
    TR: HKLM\\...\\AppCompatCache altındaki binary veriyi ayrıştırır.
    Windows 10 ve 11 '10ts' başlıklarını bularak sistemde çalıştırılmış
    tüm programların tam dosya yollarını çıkarır.
    """
    entries = []
    suspicious_entries = []
    
    try:
        with winreg.OpenKey(
            winreg.HKEY_LOCAL_MACHINE,
            r"SYSTEM\CurrentControlSet\Control\Session Manager\AppCompatCache"
        ) as key:
            data, _ = winreg.QueryValueEx(key, "AppCompatCache")

        offset = 0
        data_len = len(data)

        while offset < data_len - 14:
            if data[offset:offset+4] == b"10ts":
                # Entry length is at offset+8 (4 bytes), path len is at offset+12 (2 bytes)
                try:
                    path_len = struct.unpack_from("<H", data, offset + 12)[0]
                    if 0 < path_len < 1200 and (offset + 14 + path_len) <= data_len:
                        raw_path = data[offset + 14 : offset + 14 + path_len]
                        path_str = raw_path.decode("utf-16le", errors="ignore").rstrip("\x00")
                        
                        if "\\" in path_str and (path_str.endswith(".exe") or path_str.endswith(".dll")):
                            entries.append(path_str)
                            
                            # Flag staging or temp execution
                            p_lower = path_str.lower()
                            if any(bad in p_lower for bad in [r"\temp\\", r"\appdata\\local\\temp", r"\users\\public", r"powershell.exe", r"cmd.exe"]):
                                suspicious_entries.append(path_str)

                        offset += 14 + path_len
                        continue
                except Exception:
                    pass
            offset += 1

    except Exception as e:
        return {
            "total_entries": 0,
            "suspicious_count": 0,
            "entries": [],
            "suspicious_staging_entries": [],
            "error": str(e)
        }

    return {
        "total_entries": len(entries),
        "suspicious_count": len(suspicious_entries),
        "suspicious_staging_entries": suspicious_entries[:40],
        "recent_entries": entries[:60]
    }
