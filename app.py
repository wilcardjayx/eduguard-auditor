from fastapi import FastAPI, Request
from fastapi.responses import HTMLResponse, JSONResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
import yaml
from pathlib import Path

from core.models import AuditPackRequest, AuditReport
from scanners.orchestrator import run_audit
from ai_engine.gemma_remediator import remediate_findings
from core.exporter import generate_client_report

app = FastAPI(title="EduGuard - Local Gemma Security Auditor", version="1.0.0")

# Setup UI templates directory
templates_dir = Path("ui")
templates_dir.mkdir(exist_ok=True)
templates = Jinja2Templates(directory="ui")

@app.get("/", response_class=HTMLResponse)
async def dashboard(request: Request):
    # Load YAML rules for UI template pack selection checkboxes
    yaml_path = Path("templates/edu_asvs_rules.yaml")
    packs = []
    if yaml_path.exists():
        with open(yaml_path, "r") as f:
            packs = yaml.safe_load(f).get("packs", [])
            
    return templates.TemplateResponse("index.html", {"request": request, "packs": packs})

@app.post("/api/scan", response_model=AuditReport)
async def execute_scan(payload: AuditPackRequest):
    # 1. Run multi-scanner deterministic engine
    findings = run_audit(payload)
    
    # 2. Run Local Gemma AI Remediator on findings
    remediations = remediate_findings(findings)
    
    # 3. Calculate Security Grade based on severity
    critical_count = sum(1 for f in findings if f.severity == "CRITICAL")
    high_count = sum(1 for f in findings if f.severity == "HIGH")
    
    grade = "A"
    if critical_count > 0:
        grade = "F"
    elif high_count > 2:
        grade = "D"
    elif high_count > 0:
        grade = "C"
    elif len(findings) > 0:
        grade = "B"

    report = AuditReport(
        target=payload.target,
        security_grade=grade,
        total_findings=len(findings),
        findings=findings,
        remediations=remediations
    )
    return report

if __name__ == "__main__":
    import uvicorn
    uvicorn.run("app:app", host="0.0.0.0", port=8000, reload=True)
