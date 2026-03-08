"""
AbuseIPDB Feed — checks IPs against AbuseIPDB threat intelligence.
Requires: ABUSEIPDB_API_KEY in .env
"""

import os
import json
import urllib.request

FEED_NAME = "abuseipdb"


def query(indicator: str) -> dict:
    api_key = os.getenv("ABUSEIPDB_API_KEY", "")
    if not api_key:
        return {"status": "disabled", "reason": "ABUSEIPDB_API_KEY not set"}

    url = f"https://api.abuseipdb.com/api/v2/check?ipAddress={indicator}&maxAgeInDays=90"
    req = urllib.request.Request(url, headers={
        "Key": api_key,
        "Accept": "application/json",
    })
    try:
        with urllib.request.urlopen(req, timeout=5) as resp:
            data = json.loads(resp.read())["data"]
            return {
                "abuse_score":    data.get("abuseConfidenceScore"),
                "total_reports":  data.get("totalReports"),
                "country":        data.get("countryCode"),
                "domain":         data.get("domain"),
                "isp":            data.get("isp"),
                "is_tor":         data.get("isTor"),
                "last_reported":  data.get("lastReportedAt"),
            }
    except Exception as e:
        return {"error": str(e)}
