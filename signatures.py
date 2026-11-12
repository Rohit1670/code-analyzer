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
