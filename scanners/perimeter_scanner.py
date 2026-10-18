import ipaddress
import os
import re
import socket
from typing import List, Optional
from urllib.parse import urlparse

import dns.exception
import dns.resolver
import httpx

from core.models import Finding


def _host_from_target(target: str) -> str:
    parsed = urlparse(target if "://" in target else f"https://{target}")
    if parsed.scheme not in ("http", "https"):
        raise ValueError("Only http(s) targets are supported.")
    if parsed.username or parsed.password:
        raise ValueError("Credentials in the target URL are not allowed.")
    if not parsed.hostname:
        raise ValueError("Target has no hostname.")
    return parsed.hostname.lower()


def _is_ip(host: str) -> bool:
    try:
        ipaddress.ip_address(host)
        return True
    except ValueError:
        return False


def assert_public_host(host: str) -> bool:
    """Block SSRF: refuse private/loopback/link-local targets.
    Returns False when the name does not resolve (HTTP check is skipped)."""
    if os.getenv("EDUGUARD_ALLOW_PRIVATE_TARGETS") == "1":
        return True
    if _is_ip(host):
        ips = [ipaddress.ip_address(host)]
    else:
        try:
            infos = socket.getaddrinfo(host, None, proto=socket.IPPROTO_TCP)
        except socket.gaierror:
            return False
        ips = [ipaddress.ip_address(i[4][0]) for i in infos]
    for ip in ips:
        if ip.version == 6 and ip.ipv4_mapped:
            ip = ip.ipv4_mapped
        if not ip.is_global:
            raise ValueError(f"Target resolves to a non-public address ({ip}); scan blocked.")
    return True


def _dmarc_policy(domain: str) -> Optional[str]:
    """Returns the DMARC policy ('reject'/'quarantine'/'none') if a record exists,
    '' if no record was found, or None if the lookup could not be determined."""
    labels = domain.split(".")
    candidates = [".".join(labels[i:]) for i in range(len(labels) - 1)]  # subdomain inherits parent policy
    unknown = False
    for cand in candidates:
        try:
            answers = dns.resolver.resolve(f"_dmarc.{cand}", "TXT", lifetime=5.0)
            for r in answers:
                txt = str(r).lower()
                if "v=dmarc1" in txt:
                    match = re.search(r"p=(\w+)", txt)
                    return match.group(1) if match else "none"
        except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer):
            continue
        except Exception:
            unknown = True
    return None if unknown else ""


def scan_perimeter(target_url: str) -> List[Finding]:
    findings: List[Finding] = []
    host = _host_from_target(target_url)
    resolvable = assert_public_host(host)

    # 1. Passive HTTP header and cookie checks (no redirects followed)
    if resolvable:
        try:
            response = httpx.get(f"https://{host}", timeout=5.0, follow_redirects=False)
            headers = response.headers

            if "strict-transport-security" not in headers:
                findings.append(Finding(
                    id="EDU-HTTP-001",
                    pack_id="pack_2_transport",
                    title="Missing Strict-Transport-Security (HSTS) Header",
                    severity="MEDIUM",
                    owasp_asvs_id="ASVS v4.0 - 14.4.4",
                    location=f"https://{host}",
                    evidence=f"Response headers received: {list(headers.keys())[:5]}...",
                    compliance_impact="Fails transport security standards; leaves student session tokens vulnerable to downgrade attacks.",
                ))

            weak = []
            for cookie in headers.get_list("set-cookie"):
                low = cookie.lower()
                name = cookie.split("=", 1)[0].strip()
                missing = [flag for flag, token in (("HttpOnly", "httponly"), ("Secure", "secure")) if token not in low]
                if missing:
                    weak.append(f"{name} (missing {', '.join(missing)})")
            if weak:
                findings.append(Finding(
                    id="EDU-HTTP-002",
                    pack_id="pack_2_transport",
                    title="Insecure Session Cookie Attributes",
                    severity="HIGH",
                    owasp_asvs_id="ASVS v4.0 - 3.4.1",
                    location=f"https://{host}",
                    evidence="Cookies with weak flags: " + "; ".join(weak[:5]),
                    compliance_impact="Session cookies lack Secure/HttpOnly flags, enabling potential XSS session theft.",
                ))
        except Exception:
            pass  # host offline or TLS failure: no HTTP findings

    # 2. DMARC check (Pack 1); skipped for raw IP targets
    if not _is_ip(host):
        policy = _dmarc_policy(host)
        if policy == "":
            findings.append(Finding(
                id="EDU-DNS-001",
                pack_id="pack_1_dns",
                title="Missing DMARC Policy on School Domain",
                severity="HIGH",
                owasp_asvs_id="ASVS v4.0 - 1.14.3",
                location=host,
                evidence=f"No valid _dmarc TXT record found for {host} or its parent domains.",
                compliance_impact="Permits malicious actors to spoof bursar and admissions emails to students and parents.",
            ))
        elif policy == "none":
            findings.append(Finding(
                id="EDU-DNS-003",
                pack_id="pack_1_dns",
                title="Weak DMARC Policy (p=none) on School Domain",
                severity="MEDIUM",
                owasp_asvs_id="ASVS v4.0 - 1.14.3",
                location=host,
                evidence=f"_dmarc.{host} record found, but policy is 'p=none' (monitor-only).",
                compliance_impact="A p=none policy only reports spoofed mail after the fact; it does not block or quarantine forged emails impersonating the bursar or admissions office.",
            ))

    return findings
