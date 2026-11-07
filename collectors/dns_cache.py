"""
OmniTriage - DNS Cache & IoC Hunter Collector
Extracts cached DNS query records to detect recent Command and Control (C2) domains.
Author: Çınar (prox0959)
"""

import subprocess
import re

SUSPICIOUS_DOMAIN_KEYWORDS = [
    "ngrok", "duckdns", "pastebin", "discordapp.com/api/webhooks",
    "telegram.org", "transfer.sh", "raw.githubusercontent.com",
    "anonfiles", "temp-mail", "temp.sh", "burpcollaborator",
    "interact.sh", "oastify", "oast.fun"
]

def collect_dns_cache() -> dict:
    """
    TR: ipconfig /displaydns çıktısını ayrıştırarak son çözümlenen alan adlarını toplar
    ve bilinen C2 veya veri sızdırma (exfiltration) alan adlarını işaretler.
    Extracts live DNS cache entries and flags suspicious C2 infrastructure.
    """
    records = []
    flagged = []
    
    try:
        output = subprocess.check_output(
            ["ipconfig", "/displaydns"],
            text=True,
            errors="ignore",
            stderr=subprocess.DEVNULL
        )
        
        current_record = {}
        for line in output.splitlines():
            line = line.strip()
            if not line:
                if current_record.get("domain"):
                    records.append(current_record)
                    # Check for suspicious keywords
                    domain_lower = current_record["domain"].lower()
                    matched = [kw for kw in SUSPICIOUS_DOMAIN_KEYWORDS if kw in domain_lower]
                    if matched:
                        flagged.append({
                            "domain": current_record["domain"],
                            "matched_keywords": matched,
                            "type": current_record.get("type", "A")
                        })
                current_record = {}
                continue

            if ":" in line:
                parts = line.split(":", 1)
                key = parts[0].strip()
                val = parts[1].strip()

                if "Record Name" in key or "Kay" in key and "Ad" in key:
                    current_record["domain"] = val
                elif "Record Type" in key or "Kay" in key and "T" in key:
                    current_record["type"] = val
                elif "Time To Live" in key or "TTL" in key:
                    current_record["ttl"] = val

        if current_record.get("domain"):
            records.append(current_record)

    except Exception:
        pass

    # Fallback / Supplement: Inspect Windows hosts file for custom or hijacked DNS mappings
    try:
        import os
        hosts_path = os.path.join(os.environ.get("SystemRoot", r"C:\Windows"), "System32", "drivers", "etc", "hosts")
        if os.path.exists(hosts_path):
            with open(hosts_path, "r", encoding="utf-8", errors="ignore") as hf:
                for line in hf:
                    line = line.strip()
                    if not line or line.startswith("#"):
                        continue
                    parts = line.split()
                    if len(parts) >= 2:
                        dom = parts[1].strip()
                        records.append({"domain": dom, "type": f"HOSTS ({parts[0]})", "ttl": "STATIC"})
                        matched = [kw for kw in SUSPICIOUS_DOMAIN_KEYWORDS if kw in dom.lower()]
                        if matched:
                            flagged.append({"domain": dom, "matched_keywords": matched, "type": "HOSTS"})
    except Exception:
        pass

    # Deduplicate domains preserving order
    seen = set()
    unique_records = []
    for r in records:
        dom = r.get("domain")
        if dom and dom not in seen:
            seen.add(dom)
            unique_records.append(r)

    return {
        "total_records": len(unique_records),
        "flagged_count": len(flagged),
        "flagged_c2_domains": flagged,
        "recent_domains": unique_records[:60]
    }
