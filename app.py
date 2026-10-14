from fastapi import FastAPI, Request
from fastapi.responses import HTMLResponse
from fastapi.templating import Jinja2Templates
import yaml
from pathlib import Path
from collections import Counter

from core.models import AuditPackRequest, AuditReport
from scanners.orchestrator import run_audit
from ai_engine.gemma_remediator import remediate_findings
from core.exporter import generate_client_report
from fastapi.staticfiles import StaticFiles

app = FastAPI(title="EduGuard - Local Gemma Security Auditor", version="1.0.0")
app.mount("/ui", StaticFiles(directory="ui"), name="ui")

# Setup UI templates directory
templates_dir = Path("ui")
templates_dir.mkdir(exist_ok=True)
templates = Jinja2Templates(directory="ui")

# Cache template packs on startup
_cached_packs = None

def get_template_packs():
    global _cached_packs
    if _cached_packs is None:
        yaml_path = Path("templates/edu_asvs_rules.yaml")
        if yaml_path.exists():
            with open(yaml_path, "r") as f:
                _cached_packs = yaml.safe_load(f).get("packs", [])
        else:
            _cached_packs = []
    return _cached_packs

@app.get("/", response_class=HTMLResponse)
async def dashboard(request: Request):
    packs = get_template_packs()
    return templates.TemplateResponse("index.html", {"request": request, "packs": packs})

@app.post("/api/scan", response_model=AuditReport)
async def execute_scan(payload: AuditPackRequest):
    # 1. Run multi-scanner deterministic engine
    findings = run_audit(payload)
    
    # 2. Run Local Gemma AI Remediator on findings
    remediations = remediate_findings(findings)
    
    # 3. Calculate Security Grade based on severity
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
async def export_report(report: AuditReport):
    html_content = generate_client_report(report)
    return html_content

if __name__ == "__main__":
    import uvicorn
    uvicorn.run("app:app", host="0.0.0.0", port=8000, reload=True)
