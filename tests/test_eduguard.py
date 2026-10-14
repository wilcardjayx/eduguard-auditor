import pytest
import httpx
from unittest.mock import patch

from scanners.code_scanner import scan_codebase
from ai_engine.gemma_remediator import remediate_findings
from core.exporter import generate_client_report
from core.models import Finding, AuditReport

def test_scan_codebase_demo_target():
    """
    Verifies scan_codebase("./demo_target") detects all expected finding IDs
    across the deliberately vulnerable files.
    """
    findings = scan_codebase("./demo_target")
    found_ids = [f.id for f in findings]

    expected_ids = [
        "EDU-CFG-001",
        "EDU-CFG-002",
        "EDU-SAST-001",
        "EDU-RBAC-001",
        "EDU-PRIV-001",
        "EDU-HTTP-001"
    ]

    for expected_id in expected_ids:
        assert expected_id in found_ids, f"Expected {expected_id} to be found, but it was not."

    assert len(found_ids) == 6, f"Expected exactly 6 findings, got {len(found_ids)}: {found_ids}"

def test_gemma_remediator_fallback():
    """
    Mocks httpx.post to raise an exception and verifies remediate_findings()
    gracefully returns a GemmaRemediation fallback object.
    """
    dummy_findings = [
        Finding(
            id="TEST-001",
            pack_id="pack_test",
            title="Test Finding",
            severity="LOW",
            owasp_asvs_id="ASVS-1.1",
            location="test.py",
            evidence="evidence",
            compliance_impact="impact"
        )
    ]

    with patch("httpx.post", side_effect=httpx.RequestError("Mocked connection error")):
        remediations = remediate_findings(dummy_findings)

    assert len(remediations) == 1
    remediation = remediations[0]

    # Verify the object structure - exact text might vary based on existing fallback implementation
    # Just verify it returns the fallback gracefully without crashing
    assert remediation.executive_summary
    assert remediation.patched_code_snippet
    assert remediation.unified_diff
    assert "fallback" in remediation.executive_summary.lower() or "offline" in remediation.executive_summary.lower() or "error" in remediation.executive_summary.lower() or "manual" in remediation.executive_summary.lower()

def test_generate_client_report():
    """
    Constructs a dummy AuditReport with grade "F" and verifies generate_client_report()
    outputs valid HTML containing the target name and a red grade badge.
    """
    dummy_report = AuditReport(
        target="tests_target_school",
        security_grade="F",
        total_findings=1,
        findings=[
            Finding(
                id="TEST-F-001",
                pack_id="pack_test",
                title="Critical Failure",
                severity="CRITICAL",
                owasp_asvs_id="ASVS-F",
                location="f.py",
                evidence="failed",
                compliance_impact="high"
            )
        ],
        remediations=[]
    )

    html_output = generate_client_report(dummy_report)

    # Verify it outputs valid HTML
    assert html_output.strip().lower().startswith("<html") or html_output.strip().lower().startswith("<!doctype html>")
    assert html_output.strip().lower().endswith("</html>")

    # Contains target name
    assert "tests_target_school" in html_output

    # Contains red grade badge logic. Grade F with bg-red-600 or similar
    assert ">F<" in html_output
    assert "red" in html_output.lower()
