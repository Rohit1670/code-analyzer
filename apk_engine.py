import re
import os
import base64
import zipfile
import shutil
import subprocess
import tempfile
from signatures import DANGEROUS_PERMISSIONS, MALICIOUS_DEX_APIS, EXFIL_CHANNELS
from yara_rules import scan_malware_families
from geo_enrichment import lookup_ip_geo
from secrets_scanner import scan_for_cloud_secrets
from native_inspector import calc_shannon_entropy, inspect_signing_cert, inspect_native_so
from security_guard import validate_zip_bomb

try:
    from androguard.core.apk import APK
    ANDROGUARD_AVAILABLE = True
except ImportError:
    ANDROGUARD_AVAILABLE = False


class APKStaticAnalyzer:
    def __init__(self, apk_path):
        self.apk_path = apk_path
        self.filename = os.path.basename(apk_path)
        self.issues, self.exfil_targets, self.cert_info, self.file_tree, self.components = [], [], [], [], []
        self.ip_pattern = re.compile(rb'\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b')
        self.url_pattern = re.compile(rb'https?://[a-zA-Z0-9./?=_%:-]+')
        self.tg_pattern = re.compile(rb'api\.telegram\.org/bot[0-9A-Za-z:_-]+')
        self.benign = (b"://android.com", b"www.w3.org", b"://adobe.com", b"apache.org", b"google.com", b"googleapis.com")

    def _is_c2_string(self, text):
        low = text.lower()
        return any(k in low for k in ("http://", "https://", "telegram", "discord")) or bool(self.ip_pattern.search(text.encode("utf-8", errors="ignore")))

    def analyze(self):
        if not zipfile.is_zipfile(self.apk_path):
            self._log_issue("Invalid Archive", 0, "Not a valid APK/ZIP archive.", "Low", "N/A")
            return
        if ANDROGUARD_AVAILABLE:
            self._analyze_with_androguard()
        with zipfile.ZipFile(self.apk_path, 'r') as zf:
            ok, msg = validate_zip_bomb(zf)
            if not ok:
                self._log_issue("Security Guard Blocked", 0, msg, "Critical", "T1499 - Endpoint Denial of Service")
                return
            for entry in zf.namelist():
                self._inspect_zip_entry(entry, zf.read(entry))
        self._scan_decompiled_java_with_jadx()

    def _inspect_zip_entry(self, entry, raw):
        ent = calc_shannon_entropy(raw)
        tag = "Standard Asset"
        for sec in scan_for_cloud_secrets(raw, entry):
            self._log_issue(sec["type"], 0, sec["message"], sec["severity"], sec["mitre"])
        if entry.startswith("META-INF/") and entry.upper().endswith((".RSA", ".DSA", ".EC")):
            tag = "Signing Certificate"
            cert_row, is_dbg = inspect_signing_cert(entry, raw)
            self.cert_info.append(cert_row)
            if is_dbg:
                self._log_issue("Debug Certificate", 0, f"Signed with 'Android Debug' key ({entry})", "High", "T1588.003 - Signing Certificates")
        elif entry.endswith((".apk", ".jar")):
            tag = "🚨 Nested Dropper"
            self._log_issue("Dropper Indicator", 0, f"Nested archive payload: '{entry}'", "Critical", "T1407 - Dynamic Code Loading")
        elif entry.startswith("lib/") and entry.endswith(".so"):
            tag = "Native C/C++ Library"
            native_hits, native_urls = inspect_native_so(entry, raw)
            for nh in native_hits:
                self._log_issue(nh["type"], 0, nh["message"], nh["severity"], nh["mitre"])
            for nu in native_urls:
                self._log_exfil("Native ELF C2 URL", nu, {"label": "Compiled Native Binary"}, "Native Payload C2", "C/C++ JNI Socket")
        elif entry.startswith("classes") and entry.endswith(".dex"):
            tag = "Dalvik Bytecode"
            if ent >= 7.3:
                self._log_issue("Packed DEX Bytecode", 0, f"[{entry}] High entropy ({ent}/8.0)", "Medium", "T1406.002 - Software Packing")
            for fam in scan_malware_families(raw):
                self._log_issue("Malware Family Match", 0, f"[{entry}] Matches {fam['family']} ({fam['matched_indicators']})", fam["severity"], fam["mitre"])
            self._scan_dex_bytes(entry, raw)
            self._deobfuscate_dex_strings(entry, raw)
        elif entry.startswith(("assets/", "res/raw/")) and len(raw) > 256 and ent >= 7.2:
            tag = "⚠️ Packed / Encrypted"
            self._log_issue("High-Entropy Packer", 0, f"Packed/encrypted file '{entry}' (Entropy: {ent}/8.0)", "High", "T1406.002 - Software Packing")
        self.file_tree.append({"Internal Path": entry, "Size (Bytes)": len(raw), "Entropy (0-8)": ent, "Classification": tag})

    def _analyze_with_androguard(self):
        try:
            apk = APK(self.apk_path)
            self._log_issue("APK Metadata", 0, f"Package: '{apk.get_package()}'", "Low", "N/A")
            for perm in apk.get_permissions():
                if perm in DANGEROUS_PERMISSIONS:
                    sev, mitre, desc = DANGEROUS_PERMISSIONS[perm]
                    self._log_issue("Dangerous Permission", 0, f"{perm} -> {desc}", sev, mitre)
            for act in apk.get_activities():
                self.components.append({"Component Type": "Activity", "Class Name": act})
            for srv in apk.get_services():
                self.components.append({"Component Type": "Service", "Class Name": srv})
            for rcv in apk.get_receivers():
                self.components.append({"Component Type": "Broadcast Receiver", "Class Name": rcv})
        except Exception:
            pass

    def _scan_dex_bytes(self, dex_name, data):
        for sig, (sev, mitre, desc) in MALICIOUS_DEX_APIS.items():
            if sig in data:
                self._log_issue("Malicious DEX API", 0, f"[{dex_name}] {desc}", sev, mitre)
        channels = [lbl for sig, lbl in EXFIL_CHANNELS.items() if sig in data]
        ch_str = ", ".join(channels) if channels else "HTTP / Socket Stream"
        for tg in self.tg_pattern.findall(data):
            ep = tg.decode('utf-8', errors='ignore')
            self._log_exfil("Telegram Bot C2", ep, {"label": "Telegram Cloud API"}, "SMS / Keystrokes", "Telegram Bot API")
            self._log_issue("Data Exfiltration", 0, f"[{dex_name}] Telegram C2 bot: '{ep}'", "Critical", "T1437 - Application Layer Protocol")
        seen_ips = set()
        for ip_b in self.ip_pattern.findall(data):
            ip_s = ip_b.decode('utf-8', errors='ignore')
            if ip_s not in ("127.0.0.1", "0.0.0.0", "255.255.255.255") and ip_s not in seen_ips:
                seen_ips.add(ip_s)
                geo = lookup_ip_geo(ip_s)
                self._log_exfil("Direct C2 IP Server", ip_s, geo, "Stolen Device Telemetry", ch_str)
                self._log_issue("Network Indicator", 0, f"[{dex_name}] Hardcoded C2 IP: '{ip_s}' [{geo['label']}]", "High", "T1437 - Application Layer Protocol")
        seen_urls = set()
        for url_b in self.url_pattern.findall(data):
            if any(d in url_b for d in self.benign):
                continue
            url_s = url_b.decode('utf-8', errors='ignore')
            if len(url_s) > 10 and url_s not in seen_urls:
                seen_urls.add(url_s)
                self._log_exfil("Remote C2 Domain", url_s, {"label": "External Web Gate"}, "User Credentials / OTPs", ch_str)
                self._log_issue("Network Indicator", 0, f"[{dex_name}] Outbound C2 URL: '{url_s}'", "Medium", "T1437 - Application Layer Protocol")

    def _deobfuscate_dex_strings(self, dex_name, data):
        seen = set()
        for tok in re.findall(rb'[A-Za-z0-9+/]{16,}={0,2}', data):
            try:
                dec = base64.b64decode(tok, validate=True).decode('utf-8', errors='strict').strip()
                if len(dec) >= 6 and dec.isprintable() and dec not in seen and self._is_c2_string(dec):
                    seen.add(dec)
                    self._log_exfil("Hidden Base64 C2", dec, {"label": "Obfuscated Endpoint"}, "Exfiltrated Data", "Base64 Stream")
                    self._log_issue("DEX Obfuscation (Base64)", 0, f"[{dex_name}] Decoded C2 -> '{dec}'", "High", "T1406 - Obfuscated Files")
            except Exception:
                pass
        for hx in re.findall(rb'\b(?:[0-9a-fA-F]{2}){8,}\b', data):
            try:
                dec = bytes.fromhex(hx.decode('ascii')).decode('utf-8', errors='strict').strip()
                if len(dec) >= 6 and dec.isprintable() and dec not in seen and self._is_c2_string(dec):
                    seen.add(dec)
                    self._log_exfil("Hidden Hex C2", dec, {"label": "Obfuscated Endpoint"}, "Dropper / Payload", "Hex Stream")
                    self._log_issue("DEX Obfuscation (Hex)", 0, f"[{dex_name}] Decoded Hex C2 -> '{dec}'", "High", "T1406 - Obfuscated Files")
            except Exception:
                pass

    def _scan_decompiled_java_with_jadx(self):
        jadx_bin = shutil.which("jadx")
        if not jadx_bin:
            return
        with tempfile.TemporaryDirectory() as tmp_dir:
            subprocess.run([jadx_bin, "-d", tmp_dir, "--no-res", self.apk_path], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=60)
            for root, _, files in os.walk(tmp_dir):
                for file in files:
                    if file.endswith(".java"):
                        with open(os.path.join(root, file), "r", encoding="utf-8", errors="ignore") as jf:
                            if "AccessibilityService" in jf.read():
                                self._log_issue("Decompiled Java Risk", 0, f"[{file}] AccessibilityService hook", "Critical", "T1453 - Accessibility Abuse")

    def _log_exfil(self, target_type, destination, geo_dict, data_type, method):
        self.exfil_targets.append({"Destination Type": target_type, "Where Data Is Sent (Endpoint)": destination, "Server Location / ISP": geo_dict.get("label", "Unknown"), "Likely Stolen Data": data_type, "Transmission Method": method, "lat": geo_dict.get("lat"), "lon": geo_dict.get("lon")})

    def _log_issue(self, type_str, line, message, severity, mitre="N/A"):
        self.issues.append({"file": self.filename, "type": type_str, "line": line, "mitre": mitre, "message": message, "severity": severity})
