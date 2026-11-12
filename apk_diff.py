import os
import tempfile
from apk_engine import APKStaticAnalyzer


def _analyze_uploaded_apk(uploaded_obj):
    with tempfile.TemporaryDirectory() as tmp_dir:
        path = os.path.join(tmp_dir, uploaded_obj.name)
        uploaded_obj.seek(0)
        with open(path, "wb") as f:
            while True:
                chunk = uploaded_obj.read(1024 * 1024)
                if not chunk:
                    break
                f.write(chunk)
        eng = APKStaticAnalyzer(path)
        eng.analyze()
        return eng


def compare_two_apks(base_file, target_file):
    """Compares a clean/base APK against a suspect update APK to detect trojanized injections."""
    base_eng = _analyze_uploaded_apk(base_file)
    targ_eng = _analyze_uploaded_apk(target_file)

    base_issues = {i["message"] for i in base_eng.issues}
    new_issues = [i for i in targ_eng.issues if i["message"] not in base_issues]

    base_c2 = {e["Where Data Is Sent (Endpoint)"] for e in base_eng.exfil_targets}
    new_c2 = [e for e in targ_eng.exfil_targets if e["Where Data Is Sent (Endpoint)"] not in base_c2]

    base_files = {f["Internal Path"] for f in base_eng.file_tree}
    added_files = [f for f in targ_eng.file_tree if f["Internal Path"] not in base_files]

    base_fps = {c["SHA-256 Fingerprint"] for c in base_eng.cert_info}
    targ_fps = {c["SHA-256 Fingerprint"] for c in targ_eng.cert_info}
    cert_changed = bool(targ_fps and base_fps != targ_fps)

    if cert_changed:
        new_issues.insert(0, {
            "file": target_file.name,
            "type": "Signing Certificate Hijack",
            "line": 0,
            "mitre": "T1588.003 - Signing Certificates",
            "severity": "Critical",
            "message": "Update APK is signed with a DIFFERENT developer certificate than the original APK!",
            "remediation": "Reject update: legitimate updates must keep the exact same signing key."
        })

    return {
        "base_name": base_file.name,
        "target_name": target_file.name,
        "cert_changed": cert_changed,
        "new_issues": new_issues,
        "new_c2": new_c2,
        "added_files": added_files,
    }
