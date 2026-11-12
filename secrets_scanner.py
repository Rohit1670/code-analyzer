import re

SECRET_PATTERNS = {
    "Exposed Firebase Realtime DB": (
        re.compile(rb'https://[a-zA-Z0-9-]+\.firebaseio\.com'),
        "High",
        "T1530 - Data from Cloud Storage",
        "Firebase database URL exposed (check /.json for public read/write misconfiguration)",
    ),
    "Google Cloud / Maps API Key": (
        re.compile(rb'AIza[0-9A-Za-z\-_]{35}'),
        "Medium",
        "T1552.001 - Credentials in Files",
        "Hardcoded Google API key found in binary/resources",
    ),
    "AWS Access Key ID": (
        re.compile(rb'AKIA[0-9A-Z]{16}'),
        "Critical",
        "T1552.001 - Credentials in Files",
        "Hardcoded AWS IAM Access Key ID exposed",
    ),
    "Private RSA / EC Key Block": (
        re.compile(rb'-----BEGIN (?:RSA |EC )?PRIVATE KEY-----'),
        "Critical",
        "T1552.004 - Private Keys",
        "Embedded cryptographic private key found inside package",
    ),
    "Hardcoded JWT Bearer Token": (
        re.compile(rb'eyJ[a-zA-Z0-9_-]{10,}\.[a-zA-Z0-9_-]{10,}\.[a-zA-Z0-9_-]{10,}'),
        "High",
        "T1528 - Steal Application Access Token",
        "Hardcoded JSON Web Token (JWT) found in bytecode/assets",
    ),
}


def scan_for_cloud_secrets(raw_bytes, source_name):
    """Hunts for leaked cloud database URLs, API keys, and private keys in raw bytes."""
    findings = []
    seen = set()
    for label, (pattern, sev, mitre, desc) in SECRET_PATTERNS.items():
        for match in pattern.findall(raw_bytes):
            val = match.decode("utf-8", errors="ignore")
            masked = f"{val[:12]}...{val[-6:]}" if len(val) > 22 else val
            key = (label, masked)
            if key not in seen:
                seen.add(key)
                findings.append({
                    "type": f"Leaked Secret ({label})",
                    "severity": sev,
                    "mitre": mitre,
                    "message": f"[{source_name}] {desc} -> `{masked}`",
                })
    return findings
