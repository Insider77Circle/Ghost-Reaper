"""
VirusTotal Feed — checks IPs, domains, and file hashes against VirusTotal.
Requires: VIRUSTOTAL_API_KEY in .env
"""

import os
import json
import urllib.request
import re

FEED_NAME = "virustotal"


def _is_ip(s: str) -> bool:
    return bool(re.match(r"^\d{1,3}(\.\d{1,3}){3}$", s))

def _is_hash(s: str) -> bool:
    return bool(re.match(r"^[a-fA-F0-9]{32,64}$", s))


def query(indicator: str) -> dict:
    api_key = os.getenv("VIRUSTOTAL_API_KEY", "")
    if not api_key:
        return {"status": "disabled", "reason": "VIRUSTOTAL_API_KEY not set"}

    if _is_hash(indicator):
        url = f"https://www.virustotal.com/api/v3/files/{indicator}"
    elif _is_ip(indicator):
        url = f"https://www.virustotal.com/api/v3/ip_addresses/{indicator}"
    else:
        url = f"https://www.virustotal.com/api/v3/domains/{indicator}"

    req = urllib.request.Request(url, headers={"x-apikey": api_key})
    try:
        with urllib.request.urlopen(req, timeout=5) as resp:
            data = json.loads(resp.read()).get("data", {}).get("attributes", {})
            stats = data.get("last_analysis_stats", {})
            return {
                "malicious":  stats.get("malicious", 0),
                "suspicious": stats.get("suspicious", 0),
                "harmless":   stats.get("harmless", 0),
                "undetected": stats.get("undetected", 0),
                "reputation": data.get("reputation"),
                "tags":       data.get("tags", []),
            }
    except Exception as e:
        return {"error": str(e)}
