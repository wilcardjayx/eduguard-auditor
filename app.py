import os
from collections import Counter
from pathlib import Path
from typing import List

import httpx
import yaml
from fastapi import FastAPI, HTTPException, Request
from fastapi.responses import HTMLResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates

from ai_engine.gemma_remediator import remediate_findings
from ai_engine.tracing import init_sentry
from core.exporter import generate_client_report
from core.models import AuditPackRequest, AuditReport, Finding
from scanners.orchestrator import run_audit

init_sentry()

BASE_DIR = Path(__file__).resolve().parent
UI_DIR = BASE_DIR / "ui"
REACT_BUILD_DIR = UI_DIR / "react_build"
TEMPLATES_DIR = UI_DIR / "templates" if (UI_DIR / "templates").is_dir() else UI_DIR
RULES_PATH = BASE_DIR / "templates" / "edu_asvs_rules.yaml"
OLLAMA_BASE = os.getenv("OLLAMA_BASE", "http://127.0.0.1:11434")

# Serve the React build if it's been built yet; otherwise fall back to the
# existing Jinja templates. Lets this file work mid-migration either way.
USE_REACT_BUILD = (REACT_BUILD_DIR / "index.html").is_file()

app = FastAPI(title="EduGuard - Local Gemma Security Auditor", version="1.1.0")

(UI_DIR / "static").mkdir(parents=True, exist_ok=True)
templates = Jinja2Templates(directory=str(TEMPLATES_DIR))
# Only static assets are public; template source is not served.
app.mount("/ui/static", StaticFiles(directory=str(UI_DIR / "static")), name="static")


def load_packs() -> list:
    if RULES_PATH.exists():
        return (yaml.safe_load(RULES_PATH.read_text()) or {}).get("packs", [])
    return []


def grade_for(findings: List[Finding]) -> str:
    counts = Counter(f.severity for f in findings)
    if counts.get("CRITICAL", 0) > 0:
        return "F"
    if counts.get("HIGH", 0) > 2:
        return "D"
    if counts.get("HIGH", 0) > 0:
        return "C"
    if findings:
        return "B"
    return "A"


def build_report(payload: AuditPackRequest) -> AuditReport:
    try:
        findings = run_audit(payload)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc))
    remediations = remediate_findings(findings, model_name=payload.model_name)
    return AuditReport(
        target=payload.target,
        security_grade=grade_for(findings),
        total_findings=len(findings),
        findings=findings,
        remediations=remediations,
    )


# ---- Pages (Jinja fallback, only registered if React build isn't present) ----
if not USE_REACT_BUILD:
    @app.get("/", response_class=HTMLResponse)
    def landing_page(request: Request):
        return templates.TemplateResponse(request, "index.html", {"active_page": "landing"})

    @app.get("/audit", response_class=HTMLResponse)
    def audit_workspace(request: Request):
        return templates.TemplateResponse(request, "audit.html", {"packs": load_packs(), "active_page": "audit"})

    @app.get("/templates", response_class=HTMLResponse)
    def template_catalog(request: Request):
        return templates.TemplateResponse(request, "templates.html", {"packs": load_packs(), "active_page": "templates"})

    @app.get("/owasp", response_class=HTMLResponse)
    def owasp_mapping(request: Request):
        return templates.TemplateResponse(request, "owasp.html", {"packs": load_packs(), "active_page": "owasp"})

    @app.get("/engine", response_class=HTMLResponse)
    def engine_docs(request: Request):
        return templates.TemplateResponse(request, "engine.html", {"active_page": "engine"})


# ---- API ---------------------------------------------------------------
@app.get("/api/gemma/status")
def gemma_status():
    try:
        resp = httpx.get(f"{OLLAMA_BASE}/api/tags", timeout=5.0)
        if resp.status_code == 200:
            return {"connected": True, "status": "online", "runtime": "Ollama"}
    except Exception as exc:
        return {"connected": False, "status": "offline", "runtime": "Ollama", "error": str(exc)}
    return {"connected": False, "status": "offline", "runtime": "Ollama"}


@app.post("/api/scan", response_model=AuditReport)
def execute_scan(payload: AuditPackRequest):
    return build_report(payload)


@app.post("/api/export", response_class=HTMLResponse)
def export_report(payload: AuditPackRequest):
    return HTMLResponse(content=generate_client_report(build_report(payload)))


# ---- React build (only mounted if it exists; must stay LAST so it never
# shadows the /api/* routes or the Jinja pages above) ----------------------
if USE_REACT_BUILD:
    app.mount("/", StaticFiles(directory=str(REACT_BUILD_DIR), html=True), name="react-app")


if __name__ == "__main__":
    import uvicorn
    uvicorn.run("app:app", host=os.getenv("EDUGUARD_HOST", "0.0.0.0"), port=int(os.getenv("PORT", 8000)), reload=False)
