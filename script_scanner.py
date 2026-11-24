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


# --- NEW: De-obfuscation Pre-pass & Heuristic Scanner ---
import base64
import re
from typing import Any


def deobfuscate_powershell(code: str) -> str:
    cleaned = code.replace("`", "")
    cleaned = re.sub(r"(['\"])\s*\+\s*\1", "", cleaned)
    enc_matches = re.findall(r"(?:-[eE](?:ncodedCommand|nc|c)?)\s+([A-Za-z0-9+/=]{20,})", cleaned)
    decoded_blocks = []
    for b64_str in enc_matches:
        try:
            raw = base64.b64decode(b64_str + "=" * (-len(b64_str) % 4))
            decoded_blocks.append(raw.decode("utf-16le", errors="ignore"))
        except Exception:
            continue
    if decoded_blocks:
        cleaned += "\n# [DECODED_ENC_CMD]\n" + "\n".join(decoded_blocks)
    return cleaned


def deobfuscate_javascript(code: str) -> str:
    def _decode_char_codes(match: re.Match) -> str:
        nums = [int(n.strip()) for n in match.group(1).split(",") if n.strip().isdigit()]
        return '"' + "".join(chr(n) for n in nums if 0 <= n <= 0x10FFFF) + '"'

    cleaned = re.sub(r"String\.fromCharCode\(([\d,\s]+)\)", _decode_char_codes, code)
    cleaned = re.sub(r"\\x([0-9a-fA-F]{2})", lambda m: chr(int(m.group(1), 16)), cleaned)
    cleaned = re.sub(r"(['\"])\s*\+\s*\1", "", cleaned)
    return cleaned


SUSPICIOUS_SCRIPT_PATTERNS = {
    "remote_download_exec": (r"(?:Invoke-Expression|IEX|DownloadString|DownloadFile|eval\(|Function\(|WScript\.Shell)", "HIGH"),
    "amsi_bypass": (r"(?:AmsiUtils|amsiInitFailed|SetValue\(\$null,\$true\))", "CRITICAL"),
    "hidden_window_execution": (r"(?:-WindowStyle\s+Hidden|-w\s+hidden|CreateObject\(['\"]WScript\.Shell['\"]\)\.Run.*0)", "HIGH"),
    "credential_or_token_harvest": (r"(?:mimikatz|lsass|document\.cookie|localStorage\.getItem|Authorization:\s*Bearer)", "HIGH"),
}


def scan_script_deobfuscated(content: str, extension: str) -> dict[str, Any]:
    ext = extension.lower().lstrip(".")
    normalized = content
    if ext in {"ps1", "psm1", "psd1"}:
        normalized = deobfuscate_powershell(content)
    elif ext in {"js", "vbs", "hta"}:
        normalized = deobfuscate_javascript(content)

    findings = []
    for rule_name, (pattern, severity) in SUSPICIOUS_SCRIPT_PATTERNS.items():
        matches = re.findall(pattern, normalized, flags=re.IGNORECASE)
        if matches:
            findings.append({
                "rule": rule_name,
                "severity": severity,
                "match_count": len(matches),
                "sample": str(matches)[:120],
            })

    return {
        "obfuscation_stripped": normalized != content,
        "findings": findings,
        "normalized_preview": normalized[:1500],
    }
