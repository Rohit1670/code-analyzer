import hashlib
import streamlit as st
import pandas as pd
from demo_samples import execute_file_scan_job
from url_scanner import scan_url_or_ip
from vt_lookup import query_virustotal_hash
from threat_feeds import check_threatfox_ioc
from apk_diff import compare_two_apks
from ui_tabs import render_analysis_tabs

st.set_page_config(page_title="Code Analyzer | Static Code & APK Malware Analyzer", page_icon="🛡️", layout="wide", initial_sidebar_state="collapsed")

st.markdown("""
<style>
    [data-testid="stSidebar"], [data-testid="collapsedControl"] { display: none; }
    [data-testid="stMetric"] { background-color: var(--secondary-background-color); border: 1px solid rgba(128, 128, 128, 0.25); padding: 14px 16px; border-radius: 10px; }
    [data-testid="stMetricLabel"] { color: var(--text-color) !important; opacity: 0.85; font-weight: 600; }
    [data-testid="stMetricValue"] { color: var(--text-color) !important; }
    .soc-banner { background: linear-gradient(90deg, #0f172a 0%, #1e3a8a 100%); padding: 22px; border-radius: 12px; border-left: 5px solid #38bdf8; margin-bottom: 18px; }
</style>
<div class="soc-banner">
    <h2 style="margin:0; color:#ffffff;">🛡️ Code Analyzer — Static Code & APK Malware Analyzer</h2>
    <p style="margin:6px 0 0 0; color:#e2e8f0;">Sandboxed static forensics with Automated Secure Code Fixes, APK Update Diffing, MITRE ATT&CK mapping, and C2 Geolocation.</p>
</div>
""", unsafe_allow_html=True)

try:
    default_vt = st.secrets.get("VT_API_KEY", "")
except Exception:
    default_vt = ""

mode_col, vt_col, clr_col = st.columns([2.1, 1.1, 0.5])
with mode_col:
    scan_mode = st.radio("Mode:", ["📁 File / APK Scan", "⚖️ Compare Two APKs (Diff)", "🌐 URL / IP Scanner"], horizontal=True)
with vt_col:
    vt_api_key = st.text_input("Optional VirusTotal API Key:", value=default_vt, type="password", placeholder="Paste free VT API key...")
with clr_col:
    st.markdown("<div style='height:28px'></div>", unsafe_allow_html=True)
    if st.button("🔄 Reset", use_container_width=True):
        st.session_state.clear()
        st.rerun()

if scan_mode == "📁 File / APK Scan":
    up_col, d1_col, d2_col = st.columns([2.2, 1, 1])
    with up_col:
        uploaded_file = st.file_uploader("Upload (.apk or .py)", type=["apk", "py"], label_visibility="collapsed")
    with d1_col:
        demo_apk_btn = st.button("📱 Test Demo Trojan (.apk)", use_container_width=True)
    with d2_col:
        demo_py_btn = st.button("🐍 Test Demo Backdoor (.py)", use_container_width=True)

    if demo_apk_btn:
        st.session_state["scan_data"] = execute_file_scan_job("demo_bank_trojan.apk")
    elif demo_py_btn:
        st.session_state["scan_data"] = execute_file_scan_job("demo_backdoor.py")
    elif uploaded_file is not None and st.session_state.get("last_upload") != uploaded_file.file_id:
        st.session_state["last_upload"] = uploaded_file.file_id
        st.session_state["scan_data"] = execute_file_scan_job(uploaded_file.name, uploaded_file)

elif scan_mode == "⚖️ Compare Two APKs (Diff)":
    b_col, t_col = st.columns(2)
    with b_col:
        base_apk = st.file_uploader("1. Upload Original / Clean APK (v1)", type=["apk"], key="base_apk")
    with t_col:
        suspect_apk = st.file_uploader("2. Upload Suspect Update APK (v2)", type=["apk"], key="suspect_apk")
    if base_apk and suspect_apk and st.button("⚖️ Run Trojan Update Diff", use_container_width=True):
        diff = compare_two_apks(base_apk, suspect_apk)
        st.session_state["scan_data"] = {
            "name": f"DIFF: {diff['base_name']} ➔ {diff['target_name']}", "size_kb": 0, "md5": "N/A", "sha1": "N/A", "sha256": "N/A",
            "results": diff["new_issues"], "exfil": diff["new_c2"], "certs": [], "ftree": diff["added_files"], "comps": []
        }
else:
    u_col, btn_col = st.columns([3.2, 1])
    with u_col:
        target_url = st.text_input("URL / Domain / IPv4:", placeholder="e.g., https://microsoft.com or http://185.220.101", label_visibility="collapsed")
    with btn_col:
        if st.button("🔍 Analyze URL / IP", use_container_width=True) and target_url:
            res, exf = scan_url_or_ip(target_url)
            st.session_state["scan_data"] = {"name": target_url, "size_kb": 0, "md5": "N/A", "sha1": "N/A", "sha256": hashlib.sha256(target_url.encode()).hexdigest(), "results": res, "exfil": exf, "certs": [], "ftree": [], "comps": []}

data = st.session_state.get("scan_data")
if data:
    results, exfil_targets, cert_info, file_tree, comps = data["results"], data["exfil"], data["certs"], data["ftree"], data.get("comps", [])
    df = pd.DataFrame(results)
    crit = len(df[df["severity"] == "Critical"]) if not df.empty else 0
    high = len(df[df["severity"] == "High"]) if not df.empty else 0
    med = len(df[df["severity"] == "Medium"]) if not df.empty else 0
    low = len(df[df["severity"] == "Low"]) if not df.empty else 0
    risk_score = min((crit * 25) + (high * 15) + (med * 5) + (low * 1), 100)
    verdict = "MALICIOUS" if (risk_score >= 60 or crit > 0) else ("SUSPICIOUS" if risk_score >= 25 else "CLEAN")

    vt_res = query_virustotal_hash(data["sha256"], vt_api_key) if data["sha256"] != "N/A" else None
    vt_badge = f" | 🛡️ VT: **{vt_res['malicious']}/{vt_res['total']} Engines** ({vt_res['label']})" if (vt_res and vt_res.get("status") == "found") else ""
    tf_res = check_threatfox_ioc(data["sha256"] if data["size_kb"] > 0 else data["name"])
    tf_badge = f" | 🚨 ThreatFox: **{tf_res['malware']}**" if (tf_res and tf_res.get("matched")) else ""

    if verdict == "MALICIOUS":
        st.error(f"🚨 **VERDICT: MALICIOUS / HIGH RISK** — Target: `{data['name']}`{vt_badge}{tf_badge}")
    elif verdict == "SUSPICIOUS":
        st.warning(f"⚠️ **VERDICT: SUSPICIOUS** — Target: `{data['name']}`{vt_badge}{tf_badge}")
    else:
        st.success(f"✅ **VERDICT: CLEAN / LOW RISK** — Target: `{data['name']}`{vt_badge}{tf_badge}")

    c1, c2, c3, c4, c5 = st.columns(5)
    c1.metric("Threat Score", f"{risk_score} / 100"); c2.metric("Critical Alerts", crit); c3.metric("High Alerts", high); c4.metric("Exfil Targets", len(exfil_targets)); c5.metric("Total Findings", len(results))

    render_analysis_tabs(data, results, exfil_targets, cert_info, file_tree, comps, df, crit, high, med, low, verdict, risk_score)
