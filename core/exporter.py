from html import escape

from core.models import AuditReport


def generate_client_report(report: AuditReport) -> str:
    """Generates an HTML compliance report. All dynamic values are HTML-escaped."""
    grade_color = "red" if report.security_grade in ["D", "F"] else "green"
    html = f"""<html>
<head><title>EduGuard Compliance Report - {escape(report.target)}</title></head>
<body style="font-family: Arial, sans-serif; padding: 40px; color: #333;">
<h1>EduGuard FERPA &amp; OWASP ASVS Compliance Report</h1>
<p><strong>Target Audited:</strong> {escape(report.target)}</p>
<p><strong>Overall Security Grade:</strong> <span style="font-size: 24px; font-weight: bold; color: {grade_color};">{escape(report.security_grade)}</span></p>
<p><strong>Total Vulnerabilities Flagged:</strong> {report.total_findings}</p>
<hr/>
<h2>Findings and Executive Summary</h2>
"""
    for i, finding in enumerate(report.findings):
        rem = report.remediations[i] if i < len(report.remediations) else None
        html += (
            f"<h3>[{escape(finding.severity)}] {escape(finding.title)}</h3>"
            f"<p>{escape(finding.owasp_asvs_id)} | {escape(finding.location)}</p>"
            f"<p>{escape(finding.compliance_impact)}</p>"
        )
        if rem:
            note = " (generic guidance: local AI was unavailable)" if rem.ai_fallback else ""
            html += f"<p>&bull; {escape(rem.executive_summary)}{note}</p>"
    if not report.findings:
        for rem in report.remediations:
            html += f"<p>&bull; {escape(rem.executive_summary)}</p>"
    html += "</body></html>"
    return html
