from core.models import AuditPackRequest
from scanners.orchestrator import run_audit

if __name__ == "__main__":
    print("🚀 Running EduGuard Orchestrator Test against './demo_target'...")
    req = AuditPackRequest(target="./demo_target", scan_mode="source_code", selected_packs=["all"])
    findings = run_audit(req)
    
    print(f"\n🔍 Scan Complete! Found {len(findings)} security issues:")
    for f in findings:
        print(f"   - [{f.severity}] {f.title} ({f.id}) in {f.location}")
        print(f"     Impact: {f.compliance_impact}\n")
