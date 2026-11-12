# 🛡️ CyberSentinel — Static Code & APK Malware Analyzer

**CyberSentinel** is a sandboxed static malware analysis and threat intelligence workbench built in Python and Streamlit. It dissects Android `.apk` packages and Python `.py` scripts without executing code to uncover hidden C2 exfiltration endpoints, dangerous permissions, software packers, and MITRE ATT&CK techniques.

---

## 🏗️ System Architecture

```text
+-------------------------------------------------------------------+

|                   Streamlit Threat-Intel Web UI                   |
|                         (dashboard.py)                            |
+---------------------------------+---------------------------------+
                                  |
                                  v
+-------------------------------------------------------------------+

|                   Core Orchestrator & AST Engine                  |
|                          (analyzer.py)                            |
+----------------+---------------------------------+----------------+

                 |                                 |
                 v                                 v
+---------------------------------+ +-------------------------------+

|       Android APK Engine        | |      Threat Enrichment        |
|        (apk_engine.py)          | |  (yara_rules / geo_enrich)    |
|  - Manifest & Permissions       | |  - Malware Family Matching    |
|  - DEX Bytecode & Deobfuscation | |  - Live C2 IP Geolocation     |
|  - Shannon Entropy Packer Check | |  - MITRE ATT&CK Mapping       |
|  - Signing Certificate Audit    | |  - MD5 / SHA-1 / SHA-256      |
+---------------------------------+ +-------------------------------+
```

---

## ✨ Key Capabilities

* **📡 Data Exfiltration & C2 Mapper:** Identifies outbound C2 domains, raw IPv4 servers, Telegram Bot API tokens, Discord webhooks, and network channels (`OkHttp`, `Retrofit`, `SmsManager`).
* **🌍 Live C2 IP Geolocation:** Automatically resolves detected C2 IP addresses to show hosting country, city, and ISP/ASN provider.
* **🧬 Malware Family Signature Scanner:** Flags indicators associated with known Android banking trojans and spyware families (SpyNote, Joker, Anubis, Hydra).
* **📊 Shannon Entropy Packer Detection:** Detects encrypted or packed payloads hidden inside `assets/` or `res/raw/` (`Entropy >= 7.2 / 8.0`).
* **🔐 Signing Certificate Forensics:** Extracts certificate fingerprints from `META-INF/` and flags `Android Debug` or self-signed keys.
* **🎯 MITRE ATT&CK Mobile Mapping:** Maps every finding to standardized adversary technique IDs (`T1453`, `T1412`, `T1407`, `T1437`).

---

## 🚀 Quick Start (Local)

```bash
pip install -r requirements.txt
python -m streamlit run dashboard.py
```
