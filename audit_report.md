# Static Code & APK Threat Report

- **Target Scanned:** `mock_bank_trojan.apk`
- **SHA-256 Hash:** `8bf94cc25292f31c7d54c2a896cc5da212bdc3131d67d1c5b46b3d7e3d125ccb`
- **Threat Verdict:** **MALICIOUS / HIGH RISK** (Risk Score: **100/100**)
- **Severity Breakdown:** `Critical: 4` | `High: 2` | `Medium: 3` | `Low: 3`

| # | Severity | File Name | Line | Threat Type | Alert Message |
|---|---|---|---|---|---|
| 1 | `Critical` | `mock_bank_trojan.apk` | 0 | **Dropper Indicator** | Embedded archive payload found inside APK: 'assets/hidden_update.apk' |
| 2 | `Critical` | `mock_bank_trojan.apk` | 0 | **Malicious API Signature** | [classes.dex] Dynamic DEX loading (loads hidden payloads at runtime) (Ldalvik/system/DexClassLoader;) |
| 3 | `Critical` | `mock_bank_trojan.apk` | 0 | **Malicious API Signature** | [classes.dex] Programmatic SMS sending API detected in bytecode (Landroid/telephony/SmsManager;->sendTextMessage) |
| 4 | `Critical` | `mock_bank_trojan.apk` | 0 | **Malicious API Signature** | [classes.dex] Shell command execution inside Android app (Ljava/lang/Runtime;->exec) |
| 5 | `High` | `mock_bank_trojan.apk` | 0 | **DEX Obfuscation (Base64)** | [classes.dex] Hidden Base64 string decoded -> 'https://hidden-b64-c2-panel.top' |
| 6 | `High` | `mock_bank_trojan.apk` | 0 | **DEX Obfuscation (Hex)** | [classes.dex] Hidden Hex payload decoded -> 'http://185.220.101' |
| 7 | `Medium` | `mock_bank_trojan.apk` | 0 | **Malicious API Signature** | [classes.dex] Java reflection used (often hides sensitive API calls) (Ljava/lang/reflect/Method;->invoke) |
| 8 | `Medium` | `mock_bank_trojan.apk` | 0 | **Malicious API Signature** | [classes.dex] Reference to 'su' binary (root detection or privilege escalation) (/system/bin/su) |
| 9 | `Medium` | `mock_bank_trojan.apk` | 0 | **Network Indicator** | [classes.dex] Embedded URL endpoint: 'http://198.51.100https://c2-exfil-dropzone.xyz' |
| 10 | `Low` | `mock_bank_trojan.apk` | 0 | **APK Metadata** | Package: '' | Main Activity: 'None' |
| 11 | `Low` | `mock_bank_trojan.apk` | 0 | **Native Code** | Compiled native C/C++ library present (inspect in Ghidra): 'lib/arm64-v8a/libnative_crypto.so' |
| 12 | `Low` | `mock_bank_trojan.apk` | 0 | **Engine Notice** | JADX CLI not found in PATH. Install JADX to enable full decompiled Java source scanning. |
