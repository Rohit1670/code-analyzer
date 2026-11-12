import ast
import re
import os
import base64
from apk_engine import APKStaticAnalyzer
from geo_enrichment import lookup_ip_geo
from security_guard import MAX_PYTHON_FILE_BYTES
from report_builder import build_markdown_string, build_html_report, build_killchain_dot


class AdvancedStaticAnalyzer(ast.NodeVisitor):
    def __init__(self, filename="Unknown"):
        self.filename = filename
        self.issues, self.exfil_targets = [], []
        self.secret_keywords = re.compile(r'(password|secret|passwd|api_key|apikey|token|private_key|auth_token)', re.IGNORECASE)
        self.b64_pattern = re.compile(r'^(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?$')
        self.ip_pattern = re.compile(r'\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b')
        self.url_pattern = re.compile(r'https?://[^\s\'"<>]+', re.IGNORECASE)
        self.suspicious_subprocesses = {'system', 'popen', 'subprocess', 'spawn', 'fork'}

    def visit_Assign(self, node):
        for target in node.targets:
            if isinstance(target, ast.Name) and self.secret_keywords.search(target.id):
                if isinstance(node.value, ast.Constant) and isinstance(node.value.value, str):
                    self._log_issue(
                        "Security Risk", node.lineno, f"Hardcoded credential: '{target.id}'",
                        "High", "T1552 - Unsecured Credentials", f"Use `os.environ.get('{target.id.upper()}')`"
                    )
        self.generic_visit(node)

    def visit_Constant(self, node):
        if isinstance(node.value, str):
            cleaned = node.value.strip()
            if 8 < len(cleaned) < 2048 and self.b64_pattern.match(cleaned):
                try:
                    dec = base64.b64decode(cleaned, validate=True).decode('utf-8', errors='strict')
                    if dec.isprintable() and len(dec.strip()) > 4:
                        self._log_issue("Obfuscation Detected", node.lineno, f"Hidden Base64 -> [{dec}]", "Medium", "T1027 - Obfuscated Files", "Remove encoded strings.")
                        self._scan_text_for_network_ioc(dec, node.lineno, True)
                except Exception:
                    pass
            self._scan_text_for_network_ioc(cleaned[:2048], node.lineno)
        self.generic_visit(node)

    def _scan_text_for_network_ioc(self, text, lineno, via_obf=False):
        prefix = "De-obfuscated " if via_obf else ""
        for ip in self.ip_pattern.findall(text):
            if ip not in ("127.0.0.1", "0.0.0.0"):
                geo = lookup_ip_geo(ip)
                self.exfil_targets.append({"Destination Type": "Hardcoded IP", "Where Data Is Sent (Endpoint)": ip, "Server Location / ISP": geo["label"], "Likely Stolen Data": "Script Output", "Transmission Method": "Direct IP", "lat": geo["lat"], "lon": geo["lon"]})
                self._log_issue("Network Indicator", lineno, f"{prefix}Hardcoded IP: '{ip}' [{geo['label']}]", "Medium", "T1071 - Application Layer", "Use verified HTTPS domains.")
        for url in self.url_pattern.findall(text):
            self.exfil_targets.append({"Destination Type": "External C2 URL", "Where Data Is Sent (Endpoint)": url, "Server Location / ISP": "External Web Gate", "Likely Stolen Data": "Payload", "Transmission Method": "HTTP", "lat": None, "lon": None})
            self._log_issue("Network Indicator", lineno, f"{prefix}Callback URL: '{url}'", "Medium", "T1071 - Application Layer", "Enforce domain allowlists.")

    def visit_Call(self, node):
        if isinstance(node.func, ast.Name) and node.func.id in ('eval', 'exec'):
            self._log_issue("Critical Risk", node.lineno, f"Execution wrapper: '{node.func.id}()'", "Critical", "T1059.006 - Python", "Use `ast.literal_eval()`.")
        elif isinstance(node.func, ast.Attribute):
            if node.func.attr in self.suspicious_subprocesses:
                self._log_issue("Suspicious Indicator", node.lineno, f"Process call: '{node.func.attr}'", "Medium", "T1059 - Command Interpreter", "Use `subprocess.run(..., shell=False)`.")
            elif node.func.attr == 'execute' and node.args:
                arg = node.args
                if isinstance(arg, ast.JoinedStr) or (isinstance(arg, ast.BinOp) and isinstance(arg.op, ast.Mod)):
                    self._log_issue("Security Risk", node.lineno, "Dynamic SQL string formatting.", "High", "T1190 - Exploit Public App", "Use parameterized SQL `?` queries.")
        self.generic_visit(node)

    def _log_issue(self, type_str, line, message, severity, mitre="N/A", remediation="Review manually."):
        self.issues.append({"file": os.path.basename(self.filename), "type": type_str, "line": line, "mitre": mitre, "message": message, "severity": severity, "remediation": remediation})


def _scan_single_python(file_path):
    if os.path.getsize(file_path) > MAX_PYTHON_FILE_BYTES:
        return [{"file": os.path.basename(file_path), "type": "Size Guard", "line": 0, "mitre": "T1499 - DoS", "message": "Exceeds 2 MB limit.", "severity": "Medium", "remediation": "Split large scripts."}], []
    with open(file_path, "r", encoding="utf-8") as f:
        tree = ast.parse(f.read(), filename=file_path)
    py_analyzer = AdvancedStaticAnalyzer(filename=file_path)
    py_analyzer.visit(tree)
    return py_analyzer.issues, py_analyzer.exfil_targets


def scan_target_full(target_path):
    findings, exfil_list, cert_list, file_tree, comp_list = [], [], [], [], []
    if not os.path.exists(target_path):
        return findings, exfil_list, cert_list, file_tree, comp_list
    files = [target_path] if os.path.isfile(target_path) else [os.path.join(r, fn) for r, _, fs in os.walk(target_path) for fn in fs if fn.endswith(('.py', '.apk'))]
    for fp in files:
        try:
            if fp.endswith('.py'):
                py_res, py_exf = _scan_single_python(fp)
                findings.extend(py_res)
                exfil_list.extend(py_exf)
            elif fp.endswith('.apk'):
                apk = APKStaticAnalyzer(apk_path=fp)
                apk.analyze()
                findings.extend(apk.issues)
                exfil_list.extend(apk.exfil_targets)
                cert_list.extend(apk.cert_info)
                file_tree.extend(apk.file_tree)
                comp_list.extend(apk.components)
        except (SyntaxError, RecursionError) as e:
            findings.append({"file": os.path.basename(fp), "type": "Parser Guard", "line": 0, "mitre": "N/A", "message": f"Syntax blocked: {type(e).__name__}", "severity": "Low", "remediation": "Fix syntax."})
    return findings, exfil_list, cert_list, file_tree, comp_list
