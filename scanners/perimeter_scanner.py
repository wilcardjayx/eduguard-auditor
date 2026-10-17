import ipaddress
import os
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


def _dmarc_status(domain: str) -> Optional[bool]:
    """True = found, False = definitively missing, None = could not determine."""
    labels = domain.split(".")
    candidates = [".".join(labels[i:]) for i in range(len(labels) - 1)]  # subdomain inherits parent policy
    unknown = False
    for cand in candidates:
        try:
            answers = dns.resolver.resolve(f"_dmarc.{cand}", "TXT", lifetime=5.0)
            if any("v=dmarc1" in str(r).lower() for r in answers):
                return True
        except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer):
            continue
        except Exception:
            unknown = True
    return None if unknown else False


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
    if not _is_ip(host) and _dmarc_status(host) is False:
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

    return findings
