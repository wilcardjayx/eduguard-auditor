import yaml
from pathlib import Path
from typing import List
from core.models import AuditPackRequest, Finding
from scanners.perimeter_scanner import scan_perimeter
from scanners.code_scanner import scan_codebase

def run_audit(request: AuditPackRequest) -> List[Finding]:
    all_findings = []
    active_packs = request.selected_packs
    
    # Run Code Scanner if target path exists and scan mode supports code/hybrid
    if Path(request.target).exists() and request.scan_mode in ["source_code", "hybrid"]:
        code_findings = scan_codebase(request.target)
        all_findings.extend(code_findings)

    # Run Perimeter Scanner ONLY if target is a true external URL/domain
    is_url = request.target.startswith(("http://", "https://")) or (
        "." in request.target and not Path(request.target).exists()
    )
    if is_url and request.scan_mode in ["perimeter", "hybrid"]:
        perimeter_findings = scan_perimeter(request.target)
        all_findings.extend(perimeter_findings)

    # Filter findings based on selected template packs (if not "all")
    if "all" not in active_packs:
        all_findings = [f for f in all_findings if f.pack_id in active_packs]

    return all_findings
