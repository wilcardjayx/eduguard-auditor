import os
import re
from pathlib import Path
from typing import List
from core.models import Finding

# Pre-compiled Regex Patterns
RE_SQL_INJECTION = re.compile(r"(?:f['\"].*?(?:SELECT|INSERT|UPDATE|DELETE).*?\{.*?\})|(?:(?:SELECT|INSERT|UPDATE|DELETE).*?(?:%s|\+))", re.IGNORECASE | re.DOTALL)
RE_COMMENTS = re.compile(r"(#.*$|//.*$)", re.MULTILINE)

def scan_codebase(target_path: str) -> List[Finding]:
    findings = []
    base_dir = Path(target_path)
    if not base_dir.exists():
        return findings

    # Walk through target files
    for root, _, files in os.walk(base_dir):
        for file in files:
            file_path = Path(root) / file
            rel_path = file_path.relative_to(base_dir)
            
            try:
                content = file_path.read_text(errors="ignore")
            except Exception:
                continue

            # 1. Check for exposed .env files (EDU-CFG-001)
            if file == ".env" or file.endswith(".env.example"):
                findings.append(Finding(
                    id="EDU-CFG-001",
                    pack_id="pack_3_configs",
                    title="Exposed Environment File (.env)",
                    severity="CRITICAL",
                    owasp_asvs_id="ASVS v4.0 - 14.2.1",
                    location=str(rel_path),
                    evidence=f"Found sensitive environment file: {file}",
                    compliance_impact="Exposes database credentials and secret keys to unauthorized viewers."
                ))

            # 2. Check for APP_DEBUG=true (EDU-CFG-002)
            if "APP_DEBUG=true" in content or "DEBUG = True" in content:
                findings.append(Finding(
                    id="EDU-CFG-002",
                    pack_id="pack_3_configs",
                    title="Production Debug Mode Enabled (APP_DEBUG=true)",
                    severity="HIGH",
                    owasp_asvs_id="ASVS v4.0 - 7.1.1",
                    location=str(rel_path),
                    evidence=content.split("\n")[0][:80],
                    compliance_impact="Verbose stack traces leak internal file paths and database schemas."
                ))

            # 3. Check for unparameterized SQL queries (EDU-SAST-001)
            if RE_SQL_INJECTION.search(content):
                findings.append(Finding(
                    id="EDU-SAST-001",
                    pack_id="pack_4_sast",
                    title="Unparameterized SQL String Interpolation",
                    severity="CRITICAL",
                    owasp_asvs_id="ASVS v4.0 - 5.3.5",
                    location=str(rel_path),
                    evidence="Detected Python f-string or raw concatenation inside a database query string.",
                    compliance_impact="Allows SQL injection attacks against student records and databases."
                ))

            # 4. Check for missing RBAC on student routes (EDU-RBAC-001)
            clean_content = RE_COMMENTS.sub("", content)
            if "@app.route" in clean_content and "student" in clean_content.lower() and "session" not in clean_content and "token" not in clean_content:
                findings.append(Finding(
                    id="EDU-RBAC-001",
                    pack_id="pack_5_rbac",
                    title="Missing Session Verification on Student Grade Route (IDOR)",
                    severity="CRITICAL",
                    owasp_asvs_id="ASVS v4.0 - 4.2.1",
                    location=str(rel_path),
                    evidence="Route accepts student ID parameter without validating session user ownership.",
                    compliance_impact="Permits unauthorized access to sensitive student grades and transcripts (IDOR)."
                ))

            # 5. Check for unrestricted file upload (EDU-PRIV-001)
            if "move_uploaded_file" in clean_content or "multer" in clean_content:
                if "allowed_extensions" not in content and "mimetype" not in content:
                    findings.append(Finding(
                        id="EDU-PRIV-001",
                        pack_id="pack_6_privacy",
                        title="Unrestricted Student File Upload Handler",
                        severity="HIGH",
                        owasp_asvs_id="ASVS v4.0 - 12.3.1",
                        location=str(rel_path),
                        evidence="File upload routine lacks extension whitelist or MIME-type validation.",
                        compliance_impact="Allows attackers to upload malicious executable scripts onto school servers."
                    ))

            # 6. Check for static Nginx configs lacking security headers (EDU-HTTP-001)
            if file.endswith(".conf") and "listen 80;" in clean_content:
                if "Strict-Transport-Security" not in clean_content and "return 301 https://" not in clean_content:
                    findings.append(Finding(
                        id="EDU-HTTP-001",
                        pack_id="pack_2_transport",
                        title="Missing Strict-Transport-Security (HSTS) Header",
                        severity="MEDIUM",
                        owasp_asvs_id="ASVS v4.0 - 14.4.4",
                        location=str(rel_path),
                        evidence="Nginx config listens on port 80 without enforcing HTTPS redirects or HSTS.",
                        compliance_impact="Enforces HTTPS connections for student login and grade portals."
                    ))

    return findings
