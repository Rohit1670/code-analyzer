import os
import hashlib
import tempfile
from fastapi import FastAPI, UploadFile, File, HTTPException
from analyzer import scan_target_full

app = FastAPI(title="Code Analyzer REST API", version="1.0.0", description="Automated Static Code & APK Malware Scanning API")


@app.get("/health")
def health_check():
    return {"status": "online", "supported_formats": [".apk", ".py", ".js", ".ps1"]}


@app.post("/api/v1/scan")
async def scan_artifact(file: UploadFile = File(...)):
    if not file.filename.endswith((".apk", ".py", ".js", ".ps1")):
        raise HTTPException(status_code=400, detail="Unsupported file type. Allowed: .apk, .py, .js, .ps1")

    with tempfile.TemporaryDirectory() as tmp_dir:
        temp_path = os.path.join(tmp_dir, os.path.basename(file.filename))
        sha256 = hashlib.sha256()
        with open(temp_path, "wb") as f:
            while chunk := await file.read(1024 * 1024):
                sha256.update(chunk)
                f.write(chunk)

        findings, exfil, certs, ftree, comps = scan_target_full(temp_path)
        crit = sum(1 for i in findings if i["severity"] == "Critical")
        high = sum(1 for i in findings if i["severity"] == "High")
        med = sum(1 for i in findings if i["severity"] == "Medium")
        low = sum(1 for i in findings if i["severity"] == "Low")
        risk_score = min((crit * 25) + (high * 15) + (med * 5) + low, 100)
        verdict = "MALICIOUS" if (risk_score >= 60 or crit > 0) else ("SUSPICIOUS" if risk_score >= 25 else "CLEAN")

        return {
            "filename": file.filename,
            "sha256": sha256.hexdigest(),
            "verdict": verdict,
            "risk_score": risk_score,
            "summary": {"critical": crit, "high": high, "medium": med, "low": low},
            "exfiltration_targets": exfil,
            "findings": findings,
        }
