from fastapi import FastAPI, Request
from fastapi.responses import HTMLResponse
from fastapi.templating import Jinja2Templates
from pathlib import Path
import yaml
from collections import Counter

from core.models import AuditPackRequest, AuditReport
from scanners.orchestrator import run_audit
from ai_engine.gemma_remediator import remediate_findings
from ai_engine.tracing import init_sentry
from core.exporter import generate_client_report

init_sentry()

app = FastAPI(title="EduGuard - Local Gemma Security Auditor", version="1.0.0")

templates_dir = Path("ui")
templates_dir.mkdir(exist_ok=True)
templates = Jinja2Templates(directory="ui")
app.mount("/ui", __import__("fastapi.staticfiles").staticfiles.StaticFiles(directory="ui"), name="ui")

def load_packs():
    yaml_path = Path("templates/edu_asvs_rules.yaml")
    if yaml_path.exists():
        with open(yaml_path, "r") as f:
            return yaml.safe_load(f).get("packs", [])
    return []

@app.get("/", response_class=HTMLResponse)
async def dashboard(request: Request):
    packs = load_packs()
    return templates.TemplateResponse("index.html", {"request": request, "packs": packs})

@app.post("/api/scan", response_model=AuditReport)
async def execute_scan(payload: AuditPackRequest):
    findings = run_audit(payload)
    remediations = remediate_findings(findings, model_name=payload.model_name)
    
    counts = Counter(f.severity for f in findings)
    critical_count = counts.get("CRITICAL", 0)
    high_count = counts.get("HIGH", 0)
    
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

@app.post("/api/export", response_class=HTMLResponse)
async def export_report(payload: AuditPackRequest):
    findings = run_audit(payload)
    remediations = remediate_findings(findings, model_name=payload.model_name)
    counts = Counter(f.severity for f in findings)
    
    grade = "A"
    if counts.get("CRITICAL", 0) > 0:
        grade = "F"
    elif counts.get("HIGH", 0) > 2:
        grade = "D"
    elif counts.get("HIGH", 0) > 0:
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
    return HTMLResponse(content=generate_client_report(report))

if __name__ == "__main__":
    import uvicorn
    uvicorn.run("app:app", host="0.0.0.0", port=8000, reload=True)
