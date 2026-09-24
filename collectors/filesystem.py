"""
OmniTriage - File System & Staging Artifacts Collector
Hunts for executables/scripts in staging directories (%TEMP%, %APPDATA%, %LOCALAPPDATA%)
and extracts recent user file activity (.lnk shortcuts).
Author: Çınar (prox0959)
"""

import os
import hashlib
from datetime import datetime

SUSPICIOUS_EXTENSIONS = {".exe", ".dll", ".bat", ".cmd", ".ps1", ".vbs", ".js", ".scr", ".hta"}

def calculate_sha256(filepath: str, max_size_bytes: int = 15 * 1024 * 1024) -> str:
    """
    TR: Dosyanın SHA-256 hash değerini hesaplar. 15MB'tan büyükse vakit kaybetmemek için 'SKIPPED_LARGE' döner.
    Computes SHA-256 hash of a file up to max_size_bytes.
    """
    try:
        if os.path.getsize(filepath) > max_size_bytes:
            return "SKIPPED_LARGE_FILE"
        hasher = hashlib.sha256()
        with open(filepath, "rb") as f:
            while chunk := f.read(65536):
                hasher.update(chunk)
        return hasher.hexdigest()
    except Exception as e:
        return f"ERROR_{str(e)[:20]}"

def scan_staging_directory(directory_path: str, max_depth: int = 2, max_files: int = 50) -> list:
    """
    TR: Verilen klasörü belirtilen derinlikte tarayarak çalıştırılabilir dosyaları (.exe, .bat vb.) tespit eder.
    Scans a directory up to max_depth for binary and script extensions.
    """
    findings = []
    if not os.path.exists(directory_path):
        return findings

    base_depth = directory_path.rstrip(os.path.sep).count(os.path.sep)

    try:
        for root, dirs, files in os.walk(directory_path):
            current_depth = root.count(os.path.sep) - base_depth
            if current_depth > max_depth:
                dirs.clear() # Stop descending deeper
                continue

            for file in files:
                ext = os.path.splitext(file)[1].lower()
                if ext in SUSPICIOUS_EXTENSIONS:
                    full_path = os.path.join(root, file)
                    try:
                        st = os.stat(full_path)
                        findings.append({
                            "filename": file,
                            "extension": ext,
                            "path": full_path,
                            "size_bytes": st.st_size,
                            "created_time": datetime.fromtimestamp(st.st_ctime).strftime('%Y-%m-%d %H:%M:%S'),
                            "modified_time": datetime.fromtimestamp(st.st_mtime).strftime('%Y-%m-%d %H:%M:%S'),
                            "sha256": calculate_sha256(full_path)
                        })
                    except Exception:
                        continue

                    if len(findings) >= max_files:
                        return findings
    except Exception:
        pass

    return findings

def get_recent_shortcuts(max_items: int = 40) -> list:
    """
    TR: %APPDATA%\\Microsoft\\Windows\\Recent altındaki son kullanılan dosya kısayollarını (.lnk) çeker.
    Extracts recent user opened files from Windows Recent shortcuts.
    """
    recent_dir = os.path.expandvars(r"%APPDATA%\Microsoft\Windows\Recent")
    if not os.path.exists(recent_dir):
        return []

    shortcuts = []
    try:
        entries = os.scandir(recent_dir)
        for entry in entries:
            if entry.name.endswith(".lnk") and entry.is_file():
                try:
                    st = entry.stat()
                    shortcuts.append({
                        "filename": entry.name[:-4], # strip .lnk
                        "path": entry.path,
                        "last_accessed": datetime.fromtimestamp(st.st_atime).strftime('%Y-%m-%d %H:%M:%S'),
                        "last_modified": datetime.fromtimestamp(st.st_mtime).strftime('%Y-%m-%d %H:%M:%S'),
                        "size_bytes": st.st_size
                    })
                except Exception:
                    continue
        
        shortcuts.sort(key=lambda x: x["last_modified"], reverse=True)
    except Exception:
        pass

    return shortcuts[:max_items]

def collect_filesystem_artifacts() -> dict:
    """
    TR: Temp dizinlerindeki şüpheli çalıştırılabilir dosyaları ve son erişilen dosyaları toplar.
    Aggregates staging directory binaries and recent file activity.
    """
    temp_dir = os.environ.get("TEMP", r"C:\Windows\Temp")
    appdata_dir = os.environ.get("APPDATA", "")
    local_appdata_dir = os.environ.get("LOCALAPPDATA", "")

    temp_executables = scan_staging_directory(temp_dir, max_depth=2, max_files=40)
    
    # Check Roaming AppData top level and programs
    appdata_executables = []
    if appdata_dir:
        appdata_executables = scan_staging_directory(appdata_dir, max_depth=2, max_files=40)

    # Check Local AppData Programs/Temp
    local_executables = []
    if local_appdata_dir:
        programs_dir = os.path.join(local_appdata_dir, "Programs")
        if os.path.exists(programs_dir):
            local_executables.extend(scan_staging_directory(programs_dir, max_depth=2, max_files=20))

    return {
        "temp_executables_found": len(temp_executables),
        "temp_executables": temp_executables,
        "appdata_executables_found": len(appdata_executables),
        "appdata_executables": appdata_executables,
        "recent_shortcuts_found": len(get_recent_shortcuts()),
        "recent_shortcuts": get_recent_shortcuts()
    }
