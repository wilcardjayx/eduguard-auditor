import ssl
import socket
import httpx
import dns.resolver
from urllib.parse import urlparse
from typing import List
from core.models import Finding

def scan_perimeter(target_url: str) -> List[Finding]:
    findings = []
    parsed = urlparse(target_url if "://" in target_url else f"https://{target_url}")
    domain = parsed.netloc or parsed.path

    # 1. Passive HTTP Header & Cookie Check
    try:
        response = httpx.get(f"https://{domain}", timeout=5.0, follow_redirects=True)
        headers = response.headers
        
        # Check HSTS (EDU-HTTP-001)
        if "strict-transport-security" not in headers:
            findings.append(Finding(
                id="EDU-HTTP-001",
                pack_id="pack_2_transport",
                title="Missing Strict-Transport-Security (HSTS) Header",
                severity="MEDIUM",
                owasp_asvs_id="ASVS v4.0 - 14.4.4",
                location=f"https://{domain}",
                evidence=f"Response headers received: {list(headers.keys())[:5]}...",
                compliance_impact="Fails transport security standards; leaves student session tokens vulnerable to downgrade attacks."
            ))

        # Check Cookie Flags (EDU-HTTP-002)
        set_cookie = headers.get("set-cookie", "")
        if set_cookie and ("HttpOnly" not in set_cookie or "Secure" not in set_cookie):
            findings.append(Finding(
                id="EDU-HTTP-002",
                pack_id="pack_2_transport",
                title="Insecure Session Cookie Attributes",
                severity="HIGH",
                owasp_asvs_id="ASVS v4.0 - 3.4.1",
                location=f"https://{domain}",
                evidence=f"Set-Cookie header: {set_cookie}",
                compliance_impact="Session cookies lack Secure/HttpOnly flags, enabling potential XSS session theft."
            ))
    except Exception as e:
        # If live HTTP check fails or domain is offline/local path
        pass

    # 2. DNS DMARC & SPF Check (Pack 1)
    try:
        # Check DMARC
        dmarc_records = dns.resolver.resolve(f"_dmarc.{domain}", "TXT")
        dmarc_found = any("v=DMARC1" in str(r) for r in dmarc_records)
        if not dmarc_found:
            raise Exception("No DMARC record")
    except Exception:
        findings.append(Finding(
            id="EDU-DNS-001",
            pack_id="pack_1_dns",
            title="Missing DMARC Policy on School Domain",
            severity="HIGH",
            owasp_asvs_id="ASVS v4.0 - 1.14.3",
            location=domain,
            evidence=f"Could not resolve valid _dmarc.{domain} TXT record.",
            compliance_impact="Permits malicious actors to spoof bursar and admissions emails to students and parents."
        ))

    return findings
