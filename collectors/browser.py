"""
OmniTriage - Browser Forensics Collector (Chrome, Edge, Brave)
Safely extracts browsing history and download logs while bypassing active SQLite file locks.
Author: Çınar (prox0959)
"""

import os
import shutil
import sqlite3
import tempfile
from datetime import datetime

def webkit_to_datetime(webkit_timestamp: int) -> str:
    """
    TR: Chromium WebKit zaman damgasını (1601'den bu yana geçen mikrosaniye) ISO tarihine çevirir.
    Converts WebKit timestamp (microseconds since Jan 1, 1601) to ISO datetime string.
    """
    try:
        if not webkit_timestamp or webkit_timestamp <= 0:
            return "N/A"
        epoch_seconds = (webkit_timestamp / 1_000_000) - 11644473600
        if 0 < epoch_seconds < 4102444800:
            return datetime.utcfromtimestamp(epoch_seconds).strftime('%Y-%m-%d %H:%M:%S UTC')
    except Exception:
        pass
    return "N/A"

def extract_from_history_db(db_path: str, max_visits: int = 100, max_downloads: int = 50) -> dict:
    """
    TR: Kilitli History veritabanını geçici bir dosyaya kopyalayarak güvenli bir şekilde sorgular.
    Copies locked SQLite database to a temporary location to bypass live browser file locks.
    """
    results = {"visits": [], "downloads": [], "error": None}
    temp_copy = None

    try:
        # Create unique temp file name
        fd, temp_copy = tempfile.mkstemp(prefix="omnitriage_hist_", suffix=".sqlite")
        os.close(fd)

        # Copy original db while open
        shutil.copy2(db_path, temp_copy)

        conn = sqlite3.connect(temp_copy)
        cursor = conn.cursor()

        # 1. Recent Visited URLs
        try:
            cursor.execute("""
                SELECT url, title, visit_count, last_visit_time 
                FROM urls 
                ORDER BY last_visit_time DESC 
                LIMIT ?
            """, (max_visits,))
            for row in cursor.fetchall():
                url, title, visit_count, last_visit_time = row
                results["visits"].append({
                    "url": url,
                    "title": title or "",
                    "visit_count": visit_count,
                    "last_visit_utc": webkit_to_datetime(last_visit_time)
                })
        except Exception as e:
            results["visits_error"] = str(e)

        # 2. File Downloads
        try:
            cursor.execute("""
                SELECT target_path, total_bytes, start_time 
                FROM downloads 
                ORDER BY start_time DESC 
                LIMIT ?
            """, (max_downloads,))
            for row in cursor.fetchall():
                target_path, total_bytes, start_time = row
                results["downloads"].append({
                    "target_path": target_path,
                    "file_size_bytes": total_bytes,
                    "start_time_utc": webkit_to_datetime(start_time)
                })
        except Exception as e:
            results["downloads_error"] = str(e)

        conn.close()
    except Exception as e:
        results["error"] = str(e)
    finally:
        if temp_copy and os.path.exists(temp_copy):
            try:
                os.remove(temp_copy)
            except Exception:
                pass

    return results

def get_chromium_history_paths() -> dict:
    """
    TR: Chrome, Edge ve Brave profil yollarını tespit eder.
    Discovers history database paths for Chrome, Edge, and Brave across Default and common profiles.
    """
    local_app_data = os.environ.get("LOCALAPPDATA", "")
    if not local_app_data:
        return {}

    targets = {
        "Google Chrome": os.path.join(local_app_data, r"Google\Chrome\User Data"),
        "Microsoft Edge": os.path.join(local_app_data, r"Microsoft\Edge\User Data"),
        "Brave": os.path.join(local_app_data, r"BraveSoftware\Brave-Browser\User Data")
    }

    discovered = {}
    for browser_name, user_data_path in targets.items():
        if not os.path.exists(user_data_path):
            continue

        profiles_to_check = ["Default", "Profile 1", "Profile 2", "Profile 3"]
        for profile in profiles_to_check:
            hist_file = os.path.join(user_data_path, profile, "History")
            if os.path.exists(hist_file):
                key = f"{browser_name} ({profile})"
                discovered[key] = hist_file

    return discovered

def collect_browser_history(max_visits_per_browser: int = 100) -> dict:
    """
    TR: Tüm tespit edilen tarayıcılardan geçmiş ve indirme kayıtlarını toplar.
    Collects forensic browser artifacts from all detected Chromium profiles.
    """
    paths = get_chromium_history_paths()
    browsers_data = {}

    for label, db_path in paths.items():
        extracted = extract_from_history_db(db_path, max_visits=max_visits_per_browser)
        browsers_data[label] = {
            "path": db_path,
            "total_visits_extracted": len(extracted["visits"]),
            "total_downloads_extracted": len(extracted["downloads"]),
            "visits": extracted["visits"],
            "downloads": extracted["downloads"],
            "error": extracted.get("error")
        }

    return browsers_data
