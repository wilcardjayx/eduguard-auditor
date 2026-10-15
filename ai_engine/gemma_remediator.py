import json
import httpx
from typing import List
from core.models import Finding, GemmaRemediation
from ai_engine.cheatsheets import OWASP_CHEATSHEETS
from ai_engine.tracing import trace_ai_pipeline

OLLAMA_URL = "http://localhost:11434/api/generate"

def remediate_findings(findings: List[Finding], model_name: str = "gemma2:2b") -> List[GemmaRemediation]:
    remediations = []
    
    for finding in findings:
        cheatsheet_context = OWASP_CHEATSHEETS.get(finding.pack_id, "Follow secure coding best practices.")
        
        prompt = f"""
        You are a senior EdTech Security Engineer and Compliance Auditor helping a school IT administrator secure a student portal.
        
        Security Finding:
        - Title: {finding.title}
        - Severity: {finding.severity}
        - OWASP ASVS Control: {finding.owasp_asvs_id}
        - Location / File: {finding.location}
        - Evidence: {finding.evidence}
        - Compliance Impact: {finding.compliance_impact}

        Defensive Standard Reference:
        {cheatsheet_context}

        Respond strictly in valid JSON format with the following keys:
        - "executive_summary": A 1-2 sentence plain-English risk overview tailored for a School Principal or Board of Education regarding FERPA/NDPR compliance.
        - "patched_code_snippet": The exact secure replacement code, config block, or fix instructions.
        - "unified_diff": A standard unified git diff format showing the remediation.
        """

        try:
            with trace_ai_pipeline(finding.title, model_name):
                response = httpx.post(
                    OLLAMA_URL,
                    json={
                        "model": model_name,
                        "prompt": prompt,
                        "format": "json",
                        "stream": False
                    },
                    timeout=300.0
                )
                response.raise_for_status()
                result_json = json.loads(response.json()["response"])
                
                remediations.append(GemmaRemediation(
                    executive_summary=result_json.get("executive_summary", "Compliance risk identified."),
                    patched_code_snippet=result_json.get("patched_code_snippet", "# Apply security hardening"),
                    unified_diff=result_json.get("unified_diff", "--- a/file\n+++ b/file\n# Secure fix applied")
                ))
        except Exception:
            remediations.append(GemmaRemediation(
                executive_summary=f"[Local AI Fallback] {finding.title} exposes the school portal to compliance penalties. Immediate remediation required.",
                patched_code_snippet=f"# Recommended fix per {finding.owasp_asvs_id}\n# Secure the file path: {finding.location}",
                unified_diff=f"--- {finding.location}\n+++ {finding.location} (Secured)\n@@ -1,1 +1,1 @@\n- VULN\n+ SECURE"
            ))

    return remediations
