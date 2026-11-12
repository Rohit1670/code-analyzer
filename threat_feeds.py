import urllib.request
import json


def check_threatfox_ioc(ioc_value):
    """Queries abuse.ch ThreatFox live botnet/malware IOC database (no API key required)."""
    if not ioc_value or ioc_value == "N/A":
        return None
    try:
        payload = json.dumps({"query": "search_ioc", "search_term": ioc_value}).encode("utf-8")
        req = urllib.request.Request(
            "https://abuse.ch",
            data=payload,
            headers={"Content-Type": "application/json", "User-Agent": "CodeAnalyzer-SOC/1.0"},
        )
        with urllib.request.urlopen(req, timeout=4) as resp:
            data = json.loads(resp.read().decode("utf-8"))
            if data.get("query_status") == "ok" and data.get("data"):
                hit = data["data"][0]
                return {
                    "matched": True,
                    "malware": hit.get("malware_printable", "Known Malware"),
                    "threat_type": hit.get("threat_type", "C2 / Payload"),
                    "confidence": hit.get("confidence_level", 100),
                }
    except Exception:
        pass
    return {"matched": False}
