# Code Analyzer — Static Code & APK Malware Analyzer

**Code Analyzer** is a multi-engine static malware analysis, reverse-engineering, and threat-intelligence platform built with Python, Streamlit, and FastAPI. It inspects Python scripts, PowerShell/JavaScript payloads, Android APKs (DEX, Manifest, signing blocks, native `.so` ELF binaries), and hardcoded secrets—enriching extracted IOCs against VirusTotal, `abuse.ch` ThreatFox, and `ipwho.is` while exporting industry-standard **SARIF v2.1.0** and **STIX 2.1** reports.

---

## Key Capabilities

### Multi-Engine Static Scanning
* **Python AST Analyzer (`analyzer.py`):** Detects dangerous imports, dynamic execution (`eval`/`exec`), subprocess spawning, and computes a weighted **0–100 Threat Score** with an explainable verdict.
* **Android APK Deep Audit (`apk_engine.py`, `apk_diff.py`):** Parses `AndroidManifest.xml` and DEX bytecode, correlates dangerous permissions (`SEND_SMS`, `BIND_ACCESSIBILITY_SERVICE`, `SYSTEM_ALERT_WINDOW`) with actual API invocations, flags dynamic code loading (`DexClassLoader`), checks v1 vs. v2/v3 signing blocks, detects Janus vulnerability anomalies, and compares APK versions.
* **Native Binary & Entropy Inspector (`native_inspector.py`):** Calculates Shannon entropy across `.so` ELF libraries and APK assets (`assets/`, `res/raw/`) to detect encryption and packers (`UPX`, `SecNeo`, `Bangcle`, `Jiagu`).
* **De-obfuscating Script Scanner (`script_scanner.py`):** Strips PowerShell backticks and decodes `-EncodedCommand` UTF-16LE blobs, resolves JavaScript `String.fromCharCode` and hex escapes, and detects AMSI bypasses and download-exec cradles.
* **Secrets & YARA Detection (`secrets_scanner.py`, `yara_rules.py`, `signatures.py`):** Identifies exposed AWS, Firebase, Google, and JWT credentials, runs custom YARA rules, and maps detections to **MITRE ATT&CK** and **Mobile ATT&CK** technique IDs.

### Threat Intelligence & Hardened Security
* **Live IOC Enrichment (`vt_lookup.py`, `threat_feeds.py`, `geo_enrichment.py`, `url_scanner.py`):** Extracts public IPs and URLs, queries VirusTotal (`st.secrets["VT_API_KEY"]`) and `abuse.ch` ThreatFox, enriches ASN/geolocation via `ipwho.is`, and validates SSL/DNS with SSRF pinning.
* **Defense-in-Depth Guard (`security_guard.py`):** Blocks Zip Bombs (size & compression ratio ceilings), Zip Slip path traversals, archive symlinks, SSRF targets, XSS, and DOT graph injection.

### Enterprise Reporting & CI/CD
* **Export Formats (`report_builder.py`):** Generates **SARIF v2.1.0** (for GitHub Code Scanning), **STIX 2.1** JSON IOC bundles (for MISP/OpenCTI), HTML, Markdown, and JSON audit reports.
* **Dual Interface (`dashboard.py`, `api.py`):** Interactive Streamlit web UI alongside a FastAPI REST service (`/scan/upload`).

---

## MITRE ATT&CK & Mobile ATT&CK Coverage

| Rule / Behavior | Technique ID | Tactic | Technique Name |
| :--- | :--- | :--- | :--- |
| `REMOTE_DOWNLOAD_EXEC` | `T1059.001` | Execution | PowerShell / Script Execution |
| `AMSI_BYPASS` | `T1562.001` | Defense Evasion | Disable or Modify Tools (AMSI) |
| `HIDDEN_WINDOW_EXECUTION` | `T1564.003` | Defense Evasion | Hidden Window |
| `CREDENTIAL_OR_TOKEN_HARVEST` | `T1552` | Credential Access | Unsecured Credentials |
| `DYNAMIC_CODE_LOADING` | `T1407` | Defense Evasion | Download New Code at Runtime (Mobile) |
| `BIND_ACCESSIBILITY_SERVICE` | `T1417.001` | Collection | Keylogging / Accessibility Abuse (Mobile) |
| `READ_SMS` | `T1412` | Collection | Capture SMS Messages (Mobile) |
| `SEND_SMS` | `T1582` | Impact | SMS Control / Toll Fraud (Mobile) |
| `SYSTEM_ALERT_WINDOW` | `T1411` | Collection | Input Prompt / Overlay Attack (Mobile) |
| `APK-HIGH-ENTROPY-ASSET` | `T1027` | Defense Evasion | Obfuscated Files or Information |
| `ELF-PACKER-ENTROPY` | `T1027.002` | Defense Evasion | Software Packing |

---

## Project Architecture

```text
code_analyzer/
├── dashboard.py                 # Streamlit web application entry point
├── ui_tabs.py                   # Modular UI tabs & SARIF/STIX export controls
├── api.py                       # FastAPI REST API (/scan/upload)
├── analyzer.py                  # Python AST scanner & weighted 0-100 risk scorer
├── apk_engine.py                # Android DEX/Manifest analyzer, Janus & signature checks
├── apk_diff.py                  # APK v1 vs v2 version diff engine
├── native_inspector.py          # ELF .so binary & Shannon entropy/packer inspector
├── script_scanner.py            # PowerShell & JavaScript de-obfuscator + scanner
├── secrets_scanner.py           # AWS, Firebase, Google & JWT secret detector
├── signatures.py                # Heuristic signatures & MITRE ATT&CK technique mapper
├── yara_rules.py                # Custom YARA rule definitions & matcher
├── security_guard.py            # Zip Bomb, Zip Slip, Symlink, SSRF & XSS protections
├── url_scanner.py               # SSRF-pinned URL/SSL inspector & batch repo scanner
├── geo_enrichment.py            # ASN & geolocation enrichment (ipwho.is)
├── vt_lookup.py                 # VirusTotal API v3 integration
├── threat_feeds.py              # abuse.ch ThreatFox IOC feed lookup
├── report_builder.py            # SARIF v2.1.0, STIX 2.1, HTML & JSON report generators
├── demo_samples.py              # Built-in sample payloads for testing
├── tests/
│   └── test_analyzer.py         # Automated pytest security & scanner test suite
├── .github/workflows/
│   └── security-scan.yml        # GitHub Actions CI/CD test & SARIF upload workflow
├── Dockerfile                   # Container image definition
├── docker-compose.yml           # Multi-service deployment (Streamlit + FastAPI)
└── requirements.txt             # Python dependencies
```

---

## Quick Start (Local Setup)

### 1. Clone & Install Dependencies
```bash
git clone https://github.com
cd code-analyzer
pip install -r requirements.txt
```

### 2. Configure Secrets (Optional for VirusTotal)
Create `.streamlit/secrets.toml` locally (excluded via `.gitignore`):
```toml
VT_API_KEY = "your_virustotal_api_key_here"
```

### 3. Run the Streamlit Dashboard
```bash
python -m streamlit run dashboard.py
```
Open `http://localhost:8501` in your browser.

### 4. Run the FastAPI REST Service
```bash
uvicorn api:app --host 0.0.0.0 --port 8000
```
Example API scan with SARIF output:
```bash
curl -X POST "http://localhost:8000/scan/upload?export_format=sarif" \
  -F "file=@mock_bank_trojan.apk"
```

---

## Docker Deployment

Launch both the **Streamlit UI (`:8501`)** and **FastAPI REST API (`:8000`)** with Docker Compose:

```bash
docker compose up --build -d
```

---

## Testing & CI/CD Integration

Run the automated unit test suite locally:
```bash
python -m pytest -v
```

Every push and pull request to `main` triggers **`.github/workflows/security-scan.yml`**, which:
1. Executes all `pytest` security and scanner verification tests.
2. Scans repository scripts and generates `results.sarif`.
3. Uploads findings directly into GitHub's **Security -> Code scanning** dashboard via `github/codeql-action/upload-sarif@v3`.
