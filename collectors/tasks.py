"""
OmniTriage - Scheduled Tasks Persistence & Execution Collector
Enumerates Windows Scheduled Tasks looking for persistence or malicious triggers.
Author: Çınar (prox0959)
MITRE ATT&CK: T1053.005 (Scheduled Task)
"""

import subprocess
import csv
import io

SUSPICIOUS_TASK_KEYWORDS = [
    "powershell", "cmd.exe", "wscript", "cscript", "mshta",
    "bitsadmin", "certutil", "curl", "wget", "rundll32",
    "regsvr32", "temp\\", "appdata\\", "users\\public"
]

def collect_scheduled_tasks(max_tasks: int = 60) -> dict:
    """
    TR: schtasks /query ile sistemdeki zamanlanmış görevleri listeler
    ve şüpheli komut çalıştıran veya Temp/AppData altından tetiklenen görevleri işaretler.
    """
    tasks = []
    suspicious = []

    try:
        output = subprocess.check_output(
            ["schtasks", "/query", "/fo", "CSV", "/nh"],
            text=True,
            errors="ignore",
            stderr=subprocess.DEVNULL
        )

        reader = csv.reader(io.StringIO(output))
        for row in reader:
            if len(row) >= 3:
                name, next_run, status = row[0], row[1], row[2]
                
                # Check suspicious
                name_lower = name.lower()
                matched = [kw for kw in SUSPICIOUS_TASK_KEYWORDS if kw in name_lower]
                
                task_item = {
                    "task_name": name,
                    "next_run_time": next_run,
                    "status": status
                }
                
                if matched:
                    task_item["matched_keywords"] = matched
                    suspicious.append(task_item)
                else:
                    tasks.append(task_item)

    except Exception as e:
        return {"total_tasks": 0, "suspicious_tasks": [], "tasks": [], "error": str(e)}

    return {
        "total_tasks_discovered": len(tasks) + len(suspicious),
        "suspicious_tasks_count": len(suspicious),
        "suspicious_tasks": suspicious,
        "sample_tasks": tasks[:max_tasks]
    }
