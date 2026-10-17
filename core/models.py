import os
from typing import List, Literal
from pydantic import BaseModel, ConfigDict, Field, field_validator

# Models the API will accept. Override with: EDUGUARD_MODELS="gemma4:e4b,gemma2:2b"
ALLOWED_MODELS = [
    m.strip()
    for m in os.getenv("EDUGUARD_MODELS", "gemma4:e4b,gemma2:2b").split(",")
    if m.strip()
]


class AuditPackRequest(BaseModel):
    model_config = ConfigDict(protected_namespaces=())
    target: str = Field(..., min_length=1, max_length=2048, description="Target domain URL or local path to scan")
    scan_mode: Literal["perimeter", "source_code", "hybrid"] = "hybrid"
    selected_packs: List[str] = Field(default=["all"], description="List of template pack IDs to execute")
    model_name: str = Field(default="gemma2:2b", description="Ollama model tag to use for AI remediation")

    @field_validator("model_name")
    @classmethod
    def model_must_be_allowed(cls, v: str) -> str:
        if v not in ALLOWED_MODELS:
            raise ValueError(f"model_name must be one of {ALLOWED_MODELS}")
        return v


class Finding(BaseModel):
    id: str
    pack_id: str
    title: str
    severity: Literal["LOW", "MEDIUM", "HIGH", "CRITICAL"]
    owasp_asvs_id: str
    location: str
    evidence: str
    compliance_impact: str
    description: str = ""


class GemmaRemediation(BaseModel):
    executive_summary: str = Field(..., description="Non-technical FERPA/NDPR risk overview for school administrators")
    patched_code_snippet: str = Field(..., description="Secure code or config replacement block")
    unified_diff: str = Field(..., description="Ready-to-apply diff patch")
    ai_fallback: bool = Field(default=False, description="True when local Gemma was unavailable and generic guidance was used")


class AuditReport(BaseModel):
    target: str
    security_grade: Literal["A", "B", "C", "D", "F"]
    total_findings: int
    findings: List[Finding]
    remediations: List[GemmaRemediation]
