from security_guard import sanitize_html, sanitize_dot_label


def build_markdown_string(findings, target_name="Unknown", file_hash="N/A"):
    severity_rank = {"Critical": 1, "High": 2, "Medium": 3, "Low": 4}
    sorted_findings = sorted(findings, key=lambda x: severity_rank.get(x["severity"], 5))
    lines = [
        "# 🛡️ Code Analyzer Threat Report\n",
        f"- **Target:** `{target_name}`",
        f"- **SHA-256:** `{file_hash}`\n",
        "| # | Severity | MITRE ATT&CK | Threat Type | Alert Message | Suggested Fix |",
        "|---|---|---|---|---|---|"
    ]
    for idx, issue in enumerate(sorted_findings, 1):
        lines.append(
            f"| {idx} | `{issue['severity']}` | `{issue.get('mitre', 'N/A')}` | "
            f"**{issue['type']}** | {issue['message']} | {issue.get('remediation', 'N/A')} |"
        )
    return "\n".join(lines)


def build_html_report(findings, target_name="Unknown", file_hash="N/A", verdict="CLEAN", risk_score=0):
    safe_t, safe_h, safe_v = sanitize_html(target_name), sanitize_html(file_hash), sanitize_html(verdict)
    rows = "".join(
        f"<tr><td><b>{sanitize_html(i['severity'])}</b></td><td><code>{sanitize_html(i.get('mitre','N/A'))}</code></td>"
        f"<td>{sanitize_html(i['type'])}</td><td>{sanitize_html(i['message'])}</td>"
        f"<td>{sanitize_html(i.get('remediation','Review manually'))}</td></tr>"
        for i in findings
    )
    return (
        f"<!DOCTYPE html><html><head><meta charset='utf-8'><title>Code Analyzer - {safe_t}</title>"
        f"<style>body{{font-family:Arial,sans-serif;background:#0f172a;color:#f8fafc;padding:30px}}"
        f".card{{background:#1e293b;padding:20px;border-radius:10px;margin-bottom:20px;border-left:5px solid #38bdf8}}"
        f"table{{width:100%;border-collapse:collapse;background:#1e293b}}"
        f"th,td{{padding:12px;border-bottom:1px solid #334155;text-align:left}}th{{background:#0f172a;color:#38bdf8}}</style>"
        f"</head><body><div class='card'><h1>🛡️ Code Analyzer — Executive Threat Report</h1>"
        f"<p><b>Target:</b> {safe_t} | <b>Verdict:</b> {safe_v} ({risk_score}/100)</p>"
        f"<p><b>SHA-256:</b> <code>{safe_h}</code></p></div>"
        f"<table><thead><tr><th>Severity</th><th>MITRE ATT&CK</th><th>Threat Type</th><th>Alert Message</th><th>Remediation</th></tr></thead>"
        f"<tbody>{rows}</tbody></table></body></html>"
    )


def build_killchain_dot(target_name, findings, exfil_targets):
    dot = [
        'digraph G {', 'rankdir=LR;', 'bgcolor="transparent";',
        'node [shape=box, style="rounded,filled", fontname="Arial", fontsize=11, margin="0.2,0.12"];',
        f'target [label="Target Inspected\\n{sanitize_dot_label(target_name)}", fillcolor="#1e3a8a", fontcolor="white", color="#38bdf8"];'
    ]
    if not findings:
        dot.append('clean [label="Verified Clean\\nNo Malicious Flow Detected", fillcolor="#065f46", fontcolor="white", color="#10b981"];')
        dot.append('target -> clean [color="#10b981", penwidth=2];}')
        return "\n".join(dot)
    caps = list({sanitize_dot_label(f["type"]) for f in findings if f["severity"] in ("Critical", "High", "Medium")})[:4] or ["Suspicious Indicator"]
    dests = list({sanitize_dot_label(e["Where Data Is Sent (Endpoint)"]) for e in exfil_targets})[:4] or ["Local Host Execution"]
    for idx, cap in enumerate(caps):
        dot.append(f'cap{idx} [label="{cap}", fillcolor="#7f1d1d", fontcolor="white", color="#ef4444"];')
        dot.append(f'target -> cap{idx} [color="#94a3b8"];')
    for jdx, dst in enumerate(dests):
        dot.append(f'dst{jdx} [label="Destination / Sink\\n{dst}", fillcolor="#78350f", fontcolor="white", color="#f59e0b"];')
        for idx in range(len(caps)):
            dot.append(f'cap{idx} -> dst{jdx} [color="#f59e0b"];')
    dot.append('}')
    return "\n".join(dot)
