import re
import os
import base64
from geo_enrichment import lookup_ip_geo

JS_PATTERNS = {
    "Arbitrary JS Execution": (re.compile(r'\b(?:eval|Function)\s*\('), "Critical", "T1059.007 - JavaScript", "Dynamic code execution via eval() or new Function()", "Avoid eval(); use JSON.parse() for data."),
    "Child Process Command Exec": (re.compile(r'child_process|execSync|spawnSync|WScript\.Shell'), "Critical", "T1059 - Command Interpreter", "OS command execution detected in JavaScript/JScript", "Remove shell execution or strictly allowlist arguments."),
    "DOM XSS Sink": (re.compile(r'\.(?:innerHTML|outerHTML)\s*=|document\.write\s*\('), "High", "T1189 - Drive-by Compromise", "Unsafe DOM HTML injection sink detected", "Use textContent or sanitize HTML with DOMPurify."),
    "Hex / CharCode Obfuscation": (re.compile(r'String\.fromCharCode\s*\(|\\x[0-9a-fA-F]{2}(?:\\x[0-9a-fA-F]{2}){4,}'), "Medium", "T1027 - Obfuscated Files", "Character-code or hex string obfuscation detected", "De-obfuscate string literals before deployment."),
}

PS_PATTERNS = {
    "Encoded PowerShell Payload": (re.compile(r'(?i)-(?:enc|encodedcommand)\s+[A-Za-z0-9+/=]{16,}'), "Critical", "T1059.001 - PowerShell", "Base64-encoded PowerShell command execution flag detected", "Inspect decoded payload and avoid -EncodedCommand."),
    "In-Memory Download Cradle": (re.compile(r'(?i)(?:Invoke-Expression|\biex\b).*(?:DownloadString|DownloadData|Invoke-WebRequest|\biwr\b)'), "Critical", "T1105 - Ingress Tool Transfer", "Fileless download-and-execute cradle detected", "Download scripts to disk, verify hashes, and sign scripts."),
    "AMSI / Defense Evasion": (re.compile(r'(?i)AmsiUtils|amsiInitFailed|-ExecutionPolicy\s+Bypass'), "High", "T1562.001 - Impair Defenses", "Attempts to bypass PowerShell execution policy or AMSI", "Enforce signed PowerShell execution policies."),
    "Dynamic Invoke-Expression": (re.compile(r'(?i)\b(?:Invoke-Expression|iex)\b'), "High", "T1059.001 - PowerShell", "Dynamic string execution via Invoke-Expression (IEX)", "Replace IEX with direct cmdlet invocations."),
}


def scan_js_or_ps1(file_path):
    """Scans JavaScript (.js) and PowerShell (.ps1) files for malware & vulnerability patterns."""
    issues, exfil = [], []
    fname = os.path.basename(file_path)
    with open(file_path, "r", encoding="utf-8", errors="ignore") as f:
        lines = f.readlines()

    rules = JS_PATTERNS if file_path.endswith(".js") else PS_PATTERNS
    ip_re = re.compile(r'\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b')
    url_re = re.compile(r'https?://[^\s\'"<>`]+', re.IGNORECASE)

    for idx, line in enumerate(lines, 1):
        for label, (pat, sev, mitre, desc, fix) in rules.items():
            if pat.search(line):
                issues.append({"file": fname, "type": label, "line": idx, "mitre": mitre, "message": f"Line {idx}: {desc}", "severity": sev, "remediation": fix})

        for b64_tok in re.findall(r'[A-Za-z0-9+/]{24,}={0,2}', line):
            try:
                dec = base64.b64decode(b64_tok).decode("utf-16le" if file_path.endswith(".ps1") else "utf-8", errors="ignore").strip()
                if len(dec) > 6 and any(k in dec.lower() for k in ("http", "iex", "powershell", "cmd.exe", "eval")):
                    issues.append({"file": fname, "type": "Decoded Script Payload", "line": idx, "mitre": "T1027 - Obfuscated Files", "message": f"Line {idx}: Hidden Base64 decoded -> [{dec[:80]}]", "severity": "High", "remediation": "Remove obfuscated Base64 payloads."})
            except Exception:
                pass

        for ip in ip_re.findall(line):
            if ip not in ("127.0.0.1", "0.0.0.0"):
                geo = lookup_ip_geo(ip)
                exfil.append({"Destination Type": "Script C2 IP", "Where Data Is Sent (Endpoint)": ip, "Server Location / ISP": geo["label"], "Likely Stolen Data": "Script Telemetry", "Transmission Method": "Network Socket", "lat": geo["lat"], "lon": geo["lon"]})
                issues.append({"file": fname, "type": "Network Indicator", "line": idx, "mitre": "T1071 - Application Layer", "message": f"Line {idx}: Hardcoded IP '{ip}' [{geo['label']}]", "severity": "Medium", "remediation": "Use verified HTTPS domains."})

        for url in url_re.findall(line):
            exfil.append({"Destination Type": "Script Callback URL", "Where Data Is Sent (Endpoint)": url, "Server Location / ISP": "External Web Gate", "Likely Stolen Data": "Exfiltrated Data", "Transmission Method": "HTTP/HTTPS", "lat": None, "lon": None})
            issues.append({"file": fname, "type": "Network Indicator", "line": idx, "mitre": "T1071 - Application Layer", "message": f"Line {idx}: External URL '{url}'", "severity": "Medium", "remediation": "Verify endpoint allowlist."})

    return issues, exfil
