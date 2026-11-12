import re
import math
import hashlib

NATIVE_RISK_SYMBOLS = {
    b"ptrace": ("High", "T1622 - Debugger Evasion", "Anti-debugging ptrace() call inside native C/C++ library"),
    b"frida": ("High", "T1622 - Debugger Evasion", "Anti-Frida instrumentation detection string in native library"),
    b"xposed": ("Medium", "T1622 - Debugger Evasion", "Xposed framework detection check in native library"),
    b"system": ("High", "T1623 - Command Interpreter", "Native C system() shell execution symbol present"),
    b"execve": ("High", "T1623 - Command Interpreter", "Native C execve() process spawn symbol present"),
    b"/system/bin/su": ("High", "T1404 - Privilege Escalation", "Hardcoded root 'su' binary path inside native library"),
}


def calc_shannon_entropy(data):
    if not data:
        return 0.0
    freq = {}
    for b in data:
        freq[b] = freq.get(b, 0) + 1
    n = len(data)
    return round(-sum((c / n) * math.log2(c / n) for c in freq.values()), 2)


def inspect_signing_cert(entry, raw_bytes):
    fp = hashlib.sha256(raw_bytes).hexdigest()
    is_debug = b"Android Debug" in raw_bytes
    status = "Debug / Test Certificate" if is_debug else "Self-Signed / Release Key"
    return {"Certificate File": entry, "Signer Status": status, "SHA-256 Fingerprint": fp}, is_debug


def inspect_native_so(entry_name, raw_bytes):
    findings, hidden_urls = [], []
    if not raw_bytes.startswith(b"\x7fELF"):
        findings.append({"type": "Disguised Native File", "severity": "High", "mitre": "T1036 - Masquerading", "message": f"[{entry_name}] Lacks valid ELF binary header"})

    for sym, (sev, mitre, desc) in NATIVE_RISK_SYMBOLS.items():
        if sym in raw_bytes:
            findings.append({"type": "Native ELF Risk", "severity": sev, "mitre": mitre, "message": f"[{entry_name}] {desc}"})

    jni_exports = re.findall(rb'Java_[a-zA-Z0-9_]+', raw_bytes)
    if jni_exports:
        sample = ", ".join(x.decode("utf-8", errors="ignore") for x in jni_exports[:3])
        findings.append({"type": "JNI Native Bridge", "severity": "Low", "mitre": "T1575 - Native Code", "message": f"[{entry_name}] Exports {len(jni_exports)} JNI functions ({sample})"})

    for url_b in re.findall(rb'https?://[a-zA-Z0-9./?=_%:-]+', raw_bytes):
        url_s = url_b.decode("utf-8", errors="ignore")
        if len(url_s) > 10 and "android.com" not in url_s and url_s not in hidden_urls:
            hidden_urls.append(url_s)
            findings.append({"type": "Hidden Native C2 URL", "severity": "Critical", "mitre": "T1437 - Application Layer Protocol", "message": f"[{entry_name}] C2 URL inside native library: '{url_s}'"})

    return findings, hidden_urls
