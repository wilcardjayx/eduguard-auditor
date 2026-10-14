from core.models import AuditPackRequest
from scanners.orchestrator import run_audit
from ai_engine.gemma_remediator import remediate_findings

if __name__ == "__main__":
    print("🚀 Running EduGuard AI Remediation Test...")
    req = AuditPackRequest(target="./demo_target", scan_mode="source_code", selected_packs=["all"])
    findings = run_audit(req)
    
    print(f"🔍 Found {len(findings)} issues. Passing to Gemma Remediator...")
    remediations = remediate_findings(findings)
    
    for i, rem in enumerate(remediations):
        print(f"\n--- Remediation #{i+1} ---")
        print(f"Board Summary: {rem.executive_summary}")
        print(f"Patch Snippet:\n{rem.patched_code_snippet}\n")
