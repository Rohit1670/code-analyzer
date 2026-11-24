DANGEROUS_PERMISSIONS = {
    "android.permission.BIND_ACCESSIBILITY_SERVICE": ("Critical", "T1453 - Abuse Accessibility Features", "Keylogging & auto-clicking"),
    "android.permission.SYSTEM_ALERT_WINDOW": ("High", "T1411 - Input Prompt / Overlay", "Screen overlay banking phishing"),
    "android.permission.READ_SMS": ("High", "T1412 - Capture SMS Messages", "Reads incoming SMS & 2FA OTPs"),
    "android.permission.RECEIVE_SMS": ("High", "T1412 - Capture SMS Messages", "Intercepts incoming SMS silently"),
    "android.permission.SEND_SMS": ("High", "T1582 - SMS Control", "Sends SMS or forwards stolen OTPs"),
    "android.permission.REQUEST_INSTALL_PACKAGES": ("High", "T1407 - Dynamic Code Loading", "Dropper: installs secondary APKs"),
    "android.permission.RECEIVE_BOOT_COMPLETED": ("Medium", "T1402 - Broadcast Receivers", "Auto-starts malware on reboot"),
    "android.permission.READ_CONTACTS": ("Medium", "T1636.003 - Contact Exfiltration", "Harvests user contacts"),
    "android.permission.RECORD_AUDIO": ("High", "T1429 - Audio Capture", "Spyware microphone recording"),
    "android.permission.CAMERA": ("Medium", "T1512 - Video Capture", "Spyware camera access"),
    "android.permission.ACCESS_FINE_LOCATION": ("Medium", "T1430 - Location Tracking", "Real-time GPS tracking"),
}

MALICIOUS_DEX_APIS = {
    b"Ldalvik/system/DexClassLoader;": ("Critical", "T1407 - Dynamic Code Loading", "Loads hidden DEX payloads"),
    b"Ldalvik/system/PathClassLoader;": ("High", "T1407 - Dynamic Code Loading", "Dynamic class loading detected"),
    b"Ljava/lang/reflect/Method;->invoke": ("Medium", "T1406 - Obfuscated Files", "Java reflection hides API calls"),
    b"Landroid/telephony/SmsManager;->sendTextMessage": ("Critical", "T1582 - SMS Control", "Outbound SMS exfiltration"),
    b"Ljava/lang/Runtime;->exec": ("Critical", "T1623 - Command Interpreter", "Executes shell commands on OS"),
    b"Ljavax/crypto/Cipher;": ("Low", "T1406 - Obfuscated Files", "Cryptographic cipher routine"),
    b"/system/bin/su": ("Medium", "T1404 - Privilege Escalation", "Checks for root 'su' binary"),
}

EXFIL_CHANNELS = {
    b"Ljava/net/HttpURLConnection;": "HTTP/HTTPS Exfiltration",
    b"Lokhttp3/OkHttpClient;": "OkHttp Network Client",
    b"Lretrofit2/Retrofit;": "REST API (Retrofit)",
    b"Ljava/net/Socket;": "Raw TCP Socket Stream",
    b"Landroid/telephony/SmsManager;": "SMS Gateway Forwarding",
}


# --- NEW: MITRE ATT&CK & Mobile ATT&CK Technique Mapping ---
MITRE_ATTACK_MAP: dict[str, dict[str, str]] = {
    "REMOTE_DOWNLOAD_EXEC": {"id": "T1059.001", "tactic": "Execution", "name": "PowerShell / Script Execution"},
    "AMSI_BYPASS": {"id": "T1562.001", "tactic": "Defense Evasion", "name": "Disable or Modify Tools (AMSI)"},
    "HIDDEN_WINDOW_EXECUTION": {"id": "T1564.003", "tactic": "Defense Evasion", "name": "Hidden Window"},
    "CREDENTIAL_OR_TOKEN_HARVEST": {"id": "T1552", "tactic": "Credential Access", "name": "Unsecured Credentials"},
    "DYNAMIC_CODE_LOADING": {"id": "T1407", "tactic": "Defense Evasion", "name": "Download New Code at Runtime (Mobile)"},
    "android.permission.BIND_ACCESSIBILITY_SERVICE": {"id": "T1417.001", "tactic": "Collection", "name": "Keylogging / Accessibility Abuse (Mobile)"},
    "android.permission.READ_SMS": {"id": "T1412", "tactic": "Collection", "name": "Capture SMS Messages (Mobile)"},
    "android.permission.SEND_SMS": {"id": "T1582", "tactic": "Impact", "name": "SMS Control / Toll Fraud (Mobile)"},
    "android.permission.SYSTEM_ALERT_WINDOW": {"id": "T1411", "tactic": "Collection", "name": "Input Prompt / Overlay Attack (Mobile)"},
    "APK-HIGH-ENTROPY-ASSET": {"id": "T1027", "tactic": "Defense Evasion", "name": "Obfuscated Files or Information"},
    "ELF-PACKER-ENTROPY": {"id": "T1027.002", "tactic": "Defense Evasion", "name": "Software Packing"},
}


def enrich_findings_with_mitre(findings: list[dict]) -> list[dict]:
    """Attaches MITRE ATT&CK technique IDs, tactics, and names to normalized findings."""
    enriched = []
    for item in findings:
        copy_item = dict(item)
        key = str(copy_item.get("rule_id") or copy_item.get("rule") or copy_item.get("permission") or "")
        mitre = MITRE_ATTACK_MAP.get(key) or MITRE_ATTACK_MAP.get(key.upper())
        if mitre:
            copy_item["mitre_id"] = mitre["id"]
            copy_item["mitre_tactic"] = mitre["tactic"]
            copy_item["mitre_name"] = mitre["name"]
        enriched.append(copy_item)
    return enriched
