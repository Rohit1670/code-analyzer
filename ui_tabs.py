import json
import streamlit as st
import pandas as pd
import altair as alt
from analyzer import build_markdown_string, build_html_report, build_killchain_dot


def render_analysis_tabs(data, results, exfil_targets, cert_info, file_tree, comps, df, crit, high, med, low, verdict, risk_score):
    t1, t2, t3, t4, t5, t6 = st.tabs([
        "📡 C2 & Exfiltration Map",
        "🕸️ Attack Kill-Chain",
        "🚨 Findings & Code Fixes",
        "📂 APK Structure & Diff",
        "🔐 Certs & Hashes",
        "📄 Export Reports",
    ])

    with t1:
        if exfil_targets:
            ex_df = pd.DataFrame(exfil_targets)
            st.dataframe(ex_df[["Destination Type", "Where Data Is Sent (Endpoint)", "Server Location / ISP", "Likely Stolen Data", "Transmission Method"]].drop_duplicates(), use_container_width=True, hide_index=True)
            map_df = ex_df.dropna(subset=["lat", "lon"])[["lat", "lon"]]
            if not map_df.empty:
                st.map(map_df, zoom=2)
        else:
            st.info("No external C2 servers or outbound data endpoints were detected.")

    with t2:
        st.graphviz_chart(build_killchain_dot(data["name"], results, exfil_targets))

    with t3:
        if not df.empty:
            if "remediation" not in df.columns:
                df["remediation"] = "Review indicator manually."
            badge_map = {"Critical": "🔴 Critical", "High": "🟠 High", "Medium": "🟡 Medium", "Low": "🔵 Low"}
            df["Severity"] = df["severity"].map(lambda s: badge_map.get(s, s))
            col_c, col_t = st.columns([1, 2.6])
            with col_c:
                chart = alt.Chart(pd.DataFrame({"Severity": ["Critical", "High", "Medium", "Low"], "Count": [crit, high, med, low]})).mark_bar(cornerRadiusTopLeft=6, cornerRadiusTopRight=6).encode(
                    x=alt.X("Severity:N", sort=["Critical", "High", "Medium", "Low"], axis=alt.Axis(labelAngle=0, title=None)),
                    y=alt.Y("Count:Q", axis=alt.Axis(tickMinStep=1)),
                    color=alt.Color("Severity:N", scale=alt.Scale(domain=["Critical", "High", "Medium", "Low"], range=["#ef4444", "#f97316", "#eab308", "#3b82f6"]), legend=None),
                ).properties(height=280)
                st.altair_chart(chart, use_container_width=True)
            with col_t:
                q = st.text_input("Search alerts, MITRE IDs, or fixes:", placeholder="e.g., T1059, literal_eval, Firebase...")
                sel = st.multiselect("Filter Severity:", ["Critical", "High", "Medium", "Low"], default=["Critical", "High", "Medium", "Low"])
                flt = df[df["severity"].isin(sel)]
                if q:
                    flt = flt[flt["message"].str.contains(q, case=False, na=False) | flt["mitre"].str.contains(q, case=False, na=False)]
                st.dataframe(flt[["Severity", "mitre", "type", "message", "remediation"]], use_container_width=True, hide_index=True)
        else:
            st.success("✅ No threat findings detected.")

    with t4:
        if file_tree:
            st.subheader("Internal Archive Files & Shannon Entropy")
            st.dataframe(pd.DataFrame(file_tree), use_container_width=True, hide_index=True)
        if comps:
            st.subheader("Manifest Components (Activities, Services, Receivers)")
            st.dataframe(pd.DataFrame(comps), use_container_width=True, hide_index=True)
        if not file_tree and not comps:
            st.info("ℹ️ Internal archive structure and manifest components are shown when scanning Android (.apk) files or comparing two APKs.")

    with t5:
        if cert_info:
            st.subheader("APK Signing Certificate Forensics")
            st.dataframe(pd.DataFrame(cert_info), use_container_width=True, hide_index=True)
        st.subheader("Cryptographic File Hashes")
        st.markdown(f"- **MD5:** `{data['md5']}`\n- **SHA-1:** `{data['sha1']}`\n- **SHA-256:** `{data['sha256']}`")
        if data["sha256"] != "N/A":
            st.link_button("🔍 Cross-Check SHA-256 on VirusTotal", f"https://virustotal.com{data['sha256']}")

    with t6:
        st.subheader("Download Forensic Audit Reports")
        d1, d2, d3 = st.columns(3)
        d1.download_button("⬇️ Executive HTML Report (.html)", build_html_report(results, data["name"], data["sha256"], verdict, risk_score), file_name=f"{data['name']}_report.html", mime="text/html", use_container_width=True)
        d2.download_button("⬇️ Markdown Report (.md)", build_markdown_string(results, data["name"], data["sha256"]), file_name=f"{data['name']}_audit.md", use_container_width=True)
        d3.download_button("⬇️ JSON Telemetry (.json)", json.dumps({"target": data["name"], "sha256": data["sha256"], "risk_score": risk_score, "results": results}, indent=4), file_name=f"{data['name']}_audit.json", use_container_width=True)
