import urllib.request
import urllib.error
import json


def query_virustotal_hash(sha256_hash, api_key):
    """Queries VirusTotal v3 API for file hash detection ratio without uploading the file."""
    if not api_key or not api_key.strip():
        return None
    url = f"https://virustotal.com{sha256_hash}"
    req = urllib.request.Request(url, headers={"x-apikey": api_key.strip(), "Accept": "application/json"})
    try:
        with urllib.request.urlopen(req, timeout=5) as resp:
            data = json.loads(resp.read().decode("utf-8"))
            stats = data.get("data", {}).get("attributes", {}).get("last_analysis_stats", {})
            mal = stats.get("malicious", 0)
            susp = stats.get("suspicious", 0)
            total = sum(stats.values())
            label = data.get("data", {}).get("attributes", {}).get("popular_threat_classification", {}).get("suggested_threat_label", "Unclassified")
            return {"status": "found", "malicious": mal, "suspicious": susp, "total": total, "label": label}
    except urllib.error.HTTPError as e:
        if e.code == 404:
            return {"status": "not_found"}
        return {"status": "error", "message": f"VT API HTTP {e.code}"}
    except Exception as e:
        return {"status": "error", "message": str(e)}
