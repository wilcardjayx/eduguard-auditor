from typing import List, Optional, Literal
from pydantic import BaseModel, Field

class AuditPackRequest(BaseModel):
    target: str = Field(..., description="Target domain URL or local path to scan")
    scan_mode: Literal["perimeter", "source_code", "hybrid"] = "hybrid"
    selected_packs: List[str] = Field(default=["all"], description="List of template packs to execute")
    model_name: str = Field(default="gemma4:e4b", description="Ollama model tag to use for AI remediation")

class Finding(BaseModel):
    id: str
    pack_id: str
    title: str
    severity: Literal["LOW", "MEDIUM", "HIGH", "CRITICAL"]
    owasp_asvs_id: str
    location: str
    evidence: str
    compliance_impact: str

class GemmaRemediation(BaseModel):
    executive_summary: str = Field(..., description="FERPA/NDPR risk overview")
    patched_code_snippet: str = Field(..., description="Secure replacement code")
    unified_diff: str = Field(..., description="Ready-to-apply diff patch")

class AuditReport(BaseModel):
    target: str
    security_grade: Literal["A", "B", "C", "D", "F"]
    total_findings: int
    findings: List[Finding]
    remediations: List[GemmaRemediation]
