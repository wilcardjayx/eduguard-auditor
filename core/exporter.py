from core.models import AuditReport

def generate_client_report(report: AuditReport) -> str:
    """Generates a professional Markdown/HTML compliance report for freelance devs to sell to schools."""
    html = f"""
    <html>
    <head><title>EduGuard Compliance Report - {report.target}</title></head>
    <body style="font-family: Arial, sans-serif; padding: 40px; color: #333;">
        <h1>🎓 EduGuard FERPA & OWASP ASVS Compliance Report</h1>
        <p><strong>Target Audited:</strong> {report.target}</p>
        <p><strong>Overall Security Grade:</strong> <span style="font-size: 24px; font-weight: bold; color: {'red' if report.security_grade in ['D','F'] else 'green'};">{report.security_grade}</span></p>
        <p><strong>Total Vulnerabilities Flagged:</strong> {report.total_findings}</p>
        <hr/>
        <h2>Executive Board Summary (Powered by Local Gemma)</h2>
    """
    for rem in report.remediations:
        html += f"<p>• {rem.executive_summary}</p>"
        
    html += "</body></html>"
    return html
