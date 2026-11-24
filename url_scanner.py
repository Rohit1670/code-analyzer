import re
import socket
import ssl
from urllib.parse import urlparse
from geo_enrichment import lookup_ip_geo
from security_guard import is_safe_public_target

SUSPICIOUS_TLDS = (".xyz", ".top", ".tk", ".ml", ".ga", ".cf", ".gq", ".pw", ".cc", ".su", ".bid")
PHISH_KEYWORDS = ("login", "verify", "update", "bank", "secure", "wallet", "otp", "kyc", "gate", "panel", "steal", "drop")
TRUSTED_DOMAINS = ("microsoft.com", "google.com", "apple.com", "github.com", "amazon.com", "cloudflare.com", "wikipedia.org")


def _check_ssl_valid_pinned(resolved_ip, server_hostname):
    """Connects directly to the validated IP while verifying SNI hostname to prevent DNS rebinding."""
    try:
        ctx = ssl.create_default_context()
        with socket.create_connection((resolved_ip, 443), timeout=3) as sock:
            with ctx.wrap_socket(sock, server_hostname=server_hostname):
                return True
    except Exception:
        return False


def scan_url_or_ip(target_input):
    raw = target_input.strip()
    if not raw:
        return [], []

    has_scheme = raw.startswith(("http://", "https://"))
    normalized = raw if has_scheme else f"https://{raw}"
    parsed = urlparse(normalized)
    host = (parsed.hostname or raw).lower()
    issues, exfil = [], []

    safe, resolved_or_msg = is_safe_public_target(host)
    if not safe:
        issues.append({"file": host, "type": "SSRF / Private Target Blocked", "line": 0, "mitre": "T1090 - Proxy / Internal Pivot", "message": f"Security Guard blocked target: {resolved_or_msg}", "severity": "Critical"})
        return issues, exfil

    resolved_ip = resolved_or_msg
    is_ip = bool(re.match(r'^(?:[0-9]{1,3}\.){3}[0-9]{1,3}$', host))
    geo = lookup_ip_geo(resolved_ip)
    is_trusted = any(host == d or host.endswith(f".{d}") for d in TRUSTED_DOMAINS)

    if is_trusted:
        exfil.append({"Destination Type": "Verified Trusted Domain", "Where Data Is Sent (Endpoint)": host, "Server Location / ISP": f"{resolved_ip} — {geo['label']}", "Likely Stolen Data": "None (Legitimate Infrastructure)", "Transmission Method": "HTTPS / TLS Verified", "lat": geo["lat"], "lon": geo["lon"]})
        return issues, exfil

    if is_ip:
        issues.append({"file": host, "type": "Raw IP Endpoint", "line": 0, "mitre": "T1071 - Application Layer Protocol", "message": f"Direct IPv4 endpoint without domain [{geo['label']}]", "severity": "High"})
    if raw.startswith("http://"):
        issues.append({"file": host, "type": "Unencrypted HTTP", "line": 0, "mitre": "T1071.001 - Web Protocols", "message": "Cleartext HTTP traffic lacks TLS encryption", "severity": "Medium"})
    elif not is_ip and not _check_ssl_valid_pinned(resolved_ip, host):
        issues.append({"file": host, "type": "Invalid / Missing SSL", "line": 0, "mitre": "T1587.003 - Digital Certificates", "message": "HTTPS TLS handshake failed or certificate is untrusted", "severity": "Medium"})
    if any(host.endswith(tld) for tld in SUSPICIOUS_TLDS):
        issues.append({"file": host, "type": "High-Risk TLD", "line": 0, "mitre": "T1583.001 - Domains", "message": f"Domain uses high-abuse TLD: '{host}'", "severity": "High"})
    if "api.telegram.org/bot" in raw.lower() or "://discord.com" in raw.lower():
        issues.append({"file": host, "type": "Bot/Webhook C2", "line": 0, "mitre": "T1437 - Application Layer Protocol", "message": "Chat-platform C2 exfiltration endpoint detected", "severity": "Critical"})
    for kw in PHISH_KEYWORDS:
        if kw in raw.lower():
            issues.append({"file": host, "type": "Suspicious Keyword", "line": 0, "mitre": "T1566 - Phishing", "message": f"URL contains high-risk lure/C2 keyword: '{kw}'", "severity": "Medium"})
    if raw.lower().endswith((".apk", ".exe", ".sh", ".jar", ".dex")):
        issues.append({"file": host, "type": "Payload Dropper Link", "line": 0, "mitre": "T1105 - Ingress Tool Transfer", "message": "Direct link to executable/package payload", "severity": "Critical"})

    if issues:
        exfil.append({"Destination Type": "Direct IPv4 Host" if is_ip else "Suspicious URL / Domain", "Where Data Is Sent (Endpoint)": raw, "Server Location / ISP": f"{resolved_ip} — {geo['label']}", "Likely Stolen Data": "Phishing / C2 Telemetry", "Transmission Method": "HTTP/HTTPS", "lat": geo["lat"], "lon": geo["lon"]})
    return issues, exfil


# --- NEW: Multi-Artifact IOC Extractor & Batch Directory Scanner ---
import ipaddress
import os
import re

URL_REGEX = re.compile(r"https?://[^\s'\"<>\]\)]{4,200}", re.IGNORECASE)
IPV4_REGEX = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")


def extract_network_iocs(text: str) -> dict[str, list[str]]:
    """Extracts public IPv4 addresses and HTTP/HTTPS URLs while filtering private/loopback ranges."""
    urls = sorted(set(URL_REGEX.findall(text)))
    public_ips: set[str] = set()

    for candidate in IPV4_REGEX.findall(text):
        try:
            ip_obj = ipaddress.ip_address(candidate)
            if ip_obj.is_global:
                public_ips.add(candidate)
        except ValueError:
            continue

    return {
        "urls": urls[:100],
        "ips": sorted(public_ips)[:100],
    }


def batch_scan_directory(root_dir: str) -> dict:
    """Scans all supported scripts in an extracted repository or ZIP folder."""
    from script_scanner import scan_script_deobfuscated

    aggregated_findings: list[dict] = []
    combined_text: list[str] = []
    scanned_count = 0

    for current_root, _, files in os.walk(root_dir):
        if ".git" in current_root or "__pycache__" in current_root:
            continue
        for fname in files:
            ext = os.path.splitext(fname).lower()
            if ext in {".ps1", ".psm1", ".js", ".vbs", ".hta", ".py"}:
                fpath = os.path.join(current_root, fname)
                rel_path = os.path.relpath(fpath, root_dir)
                try:
                    with open(fpath, "r", encoding="utf-8", errors="ignore") as f:
                        content = f.read()
                except OSError:
                    continue

                scanned_count += 1
                combined_text.append(content[:20000])
                res = scan_script_deobfuscated(content, ext)
                for item in res["findings"]:
                    aggregated_findings.append({
                        "rule_id": item["rule"].upper(),
                        "severity": item["severity"],
                        "description": f"{item['rule']} ({item['match_count']} match(es))",
                        "file": rel_path,
                    })

    iocs = extract_network_iocs("\n".join(combined_text))
    return {
        "files_scanned": scanned_count,
        "findings": aggregated_findings,
        "iocs": iocs,
    }
