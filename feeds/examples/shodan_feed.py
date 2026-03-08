"""
Shodan Feed — IP intelligence from Shodan.
Requires: SHODAN_API_KEY in .env
"""

import os
import json
import urllib.request

FEED_NAME = "shodan"


def query(indicator: str) -> dict:
    api_key = os.getenv("SHODAN_API_KEY", "")
    if not api_key:
        return {"status": "disabled", "reason": "SHODAN_API_KEY not set"}

    url = f"https://api.shodan.io/shodan/host/{indicator}?key={api_key}"
    try:
        with urllib.request.urlopen(url, timeout=5) as resp:
            data = json.loads(resp.read())
            return {
                "org":        data.get("org"),
                "country":    data.get("country_name"),
                "city":       data.get("city"),
                "isp":        data.get("isp"),
                "open_ports": data.get("ports", []),
                "hostnames":  data.get("hostnames", []),
                "vulns":      list(data.get("vulns", {}).keys()),
                "tags":       data.get("tags", []),
            }
    except Exception as e:
        return {"error": str(e)}
