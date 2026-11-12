import re

MALWARE_FAMILY_RULES = [
    {
        "family": "SpyNote / CypherRat (Android RAT)",
        "severity": "Critical",
        "mitre": "T1453 - Abuse Accessibility Features",
        "min_matches": 2,
        "patterns": [
            rb"AccessibilityService",
            rb"MediaProjection",
            rb"AudioRecord",
            rb"WakeLock",
            rb"SmsManager",
        ],
    },
    {
        "family": "Joker / Fleckpe (Toll Fraud & SMS Stealer)",
        "severity": "Critical",
        "mitre": "T1412 - Capture SMS Messages",
        "min_matches": 2,
        "patterns": [
            rb"NotificationListenerService",
            rb"DexClassLoader",
            rb"getSimOperator",
            rb"sendTextMessage",
        ],
    },
    {
        "family": "Anubis / Hydra (Banking Overlay Trojan)",
        "severity": "Critical",
        "mitre": "T1411 - Input Prompt / Overlay",
        "min_matches": 2,
        "patterns": [
            rb"SYSTEM_ALERT_WINDOW",
            rb"TYPE_APPLICATION_OVERLAY",
            rb"getRunningTasks",
            rb"KeyguardManager",
        ],
    },
    {
        "family": "Telegram / Discord Exfiltration Dropper",
        "severity": "High",
        "mitre": "T1437 - Application Layer Protocol",
        "min_matches": 1,
        "patterns": [
            rb"api\.telegram\.org/bot",
            rb"discord(?:app)?\.com/api/webhooks",
        ],
    },
]


def scan_malware_families(raw_bytes):
    """Matches binary DEX/APK contents against behavioral malware family rules."""
    matches = []
    for rule in MALWARE_FAMILY_RULES:
        hit_count = sum(1 for pat in rule["patterns"] if re.search(pat, raw_bytes))
        if hit_count >= rule["min_matches"]:
            matches.append({
                "family": rule["family"],
                "severity": rule["severity"],
                "mitre": rule["mitre"],
                "matched_indicators": f"{hit_count}/{len(rule['patterns'])} behavioral signatures",
            })
    return matches
