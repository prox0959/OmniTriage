"""
OmniTriage - JSON Report Generator
Serializes complete forensic triage findings into structured, machine-readable JSON.
Author: Çınar (prox0959)
"""

import json
import os

def generate_json_report(data: dict, output_path: str) -> dict:
    """
    TR: Tüm adli bilişim verilerini UTF-8 formatında yapılandırılmış JSON dosyası olarak kaydeder.
    Serializes forensic data to JSON with UTF-8 encoding and indentation.
    """
    try:
        os.makedirs(os.path.dirname(os.path.abspath(output_path)), exist_ok=True)
        with open(output_path, "w", encoding="utf-8") as f:
            json.dump(data, f, indent=2, ensure_ascii=False)

        file_size = os.path.getsize(output_path)
        return {
            "success": True,
            "path": output_path,
            "size_bytes": file_size,
            "size_kb": round(file_size / 1024, 2)
        }
    except Exception as e:
        return {
            "success": False,
            "error": str(e)
        }
