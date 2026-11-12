import ipaddress
import urllib.request
import json


def lookup_ip_geo(ip_str):
    try:
        ip_obj = ipaddress.ip_address(ip_str)
        if ip_obj.is_private or ip_obj.is_loopback or ip_obj.is_reserved:
            return {"label": "Private / Reserved IP", "lat": None, "lon": None}
    except ValueError:
        return {"label": "Domain / Non-IP Endpoint", "lat": None, "lon": None}

    try:
        url = f"https://ipwho.is{ip_str}"
        req = urllib.request.Request(url, headers={"User-Agent": "CodeAnalyzer-SOC/1.0"})
        with urllib.request.urlopen(req, timeout=3) as resp:
            data = json.loads(resp.read().decode("utf-8"))
            if data.get("success"):
                isp = data.get("connection", {}).get("isp", "Unknown ISP")
                label = f"{data.get('country', 'Unknown')}, {data.get('city', 'Unknown')} ({isp})"
                return {"label": label, "lat": data.get("latitude"), "lon": data.get("longitude")}
    except Exception:
        pass
    return {"label": "Lookup Unavailable (Offline / Timeout)", "lat": None, "lon": None}
