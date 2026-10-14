import yaml
from pathlib import Path
from typing import List
from core.models import AuditPackRequest, Finding
from scanners.perimeter_scanner import scan_perimeter
from scanners.code_scanner import scan_codebase

def run_audit(request: AuditPackRequest) -> List[Finding]:
    all_findings = []
    
    # Load YAML rules to filter packs if specified
    yaml_path = Path("templates/edu_asvs_rules.yaml")
    active_packs = request.selected_packs
    
    # Run Code Scanner if target is a local path and mode is source_code or hybrid
    if Path(request.target).exists() and request.scan_mode in ["source_code", "hybrid"]:
        code_findings = scan_codebase(request.target)
        all_findings.extend(code_findings)

    # Run Perimeter Scanner if target looks like a URL/domain and mode is perimeter or hybrid
    if "." in request.target and request.scan_mode in ["perimeter", "hybrid"]:
        perimeter_findings = scan_perimeter(request.target)
        all_findings.extend(perimeter_findings)

    # Filter findings based on selected packs (if not "all")
    if "all" not in active_packs:
        all_findings = [f for f in all_findings if f.pack_id in active_packs]

    return all_findings
