import os
import re
from pathlib import Path
from typing import List
from core.models import Finding

MAX_FILE_BYTES = 512_000
MAX_LINE_CHARS = 2_000
SKIP_DIRS = {".git", "node_modules", "__pycache__", ".venv", "venv", ".pytest_cache"}
TEMPLATE_SUFFIXES = (".example", ".sample", ".template", ".dist")

RE_ENV_FILE = re.compile(r"^\.env(\.[\w.-]+)?$")
RE_DEBUG_LINE = re.compile(
    r"""^\s*(?:export\s+)?(?:APP_)?DEBUG\s*[=:]\s*['"]?(?:true|1)['"]?\s*(?:#.*)?$""",
    re.IGNORECASE,
)

# SQL-shaped text, evaluated one line at a time (no DOTALL) to avoid false positives.
_SQL = r"(?:SELECT\b[^\n]*?\bFROM\b|INSERT\s+INTO\b|UPDATE\s+\w+\s+SET\b|DELETE\s+FROM\b)"
SQL_INJECTION_PATTERNS = [
    re.compile(r"""\bf(["'])[^\n]*?""" + _SQL + r"""[^\n]*?\{[^}\n]+\}""", re.IGNORECASE),        # Python f-string
    re.compile(r"""["'][^\n]*?""" + _SQL + r"""[^\n]*?["']\s*%\s*[\w(\[]""", re.IGNORECASE),       # "..." % value
    re.compile(r"""["'][^\n]*?""" + _SQL + r"""[^\n]*?["']\s*\+\s*\w""", re.IGNORECASE),            # "..." + value
    re.compile(r"""["'][^\n]*?""" + _SQL + r"""[^\n]*?["']\s*\.\s*\$""", re.IGNORECASE),            # PHP: "..." . $var
    re.compile(r"""["'][^\n]*?""" + _SQL + r"""[^\n]*?["']\s*\.format\(""", re.IGNORECASE),          # "...".format(x)
    re.compile(r"`[^`\n]*?" + _SQL + r"[^`\n]*?\$\{", re.IGNORECASE),                               # JS template literal
]
RE_COMMENTS = re.compile(r"(#.*$|//.*$)", re.MULTILINE)


def _is_template_env(name: str) -> bool:
    return name.lower().endswith(TEMPLATE_SUFFIXES)


def scan_codebase(target_path: str) -> List[Finding]:
    findings: List[Finding] = []
    base_dir = Path(target_path)
    if not base_dir.is_dir():
        return findings

    for root, dirs, files in os.walk(base_dir):
        dirs[:] = [d for d in dirs if d not in SKIP_DIRS and not (Path(root) / d).is_symlink()]
        for file in files:
            file_path = Path(root) / file
            if file_path.is_symlink():
                continue
            rel_path = file_path.relative_to(base_dir)

            try:
                if file_path.stat().st_size > MAX_FILE_BYTES:
                    continue
                content = file_path.read_text(errors="ignore")
            except Exception:
                continue

            lines = content.splitlines()
            is_template = _is_template_env(file)

            # 1. Exposed .env files (EDU-CFG-001)
            if RE_ENV_FILE.match(file) or (file.lower().startswith(".env") and is_template):
                findings.append(Finding(
                    id="EDU-CFG-001",
                    pack_id="pack_3_configs",
                    title="Exposed Environment File (.env)",
                    severity="LOW" if is_template else "CRITICAL",
                    owasp_asvs_id="ASVS v4.0 - 14.2.1",
                    location=str(rel_path),
                    evidence=f"Found {'environment template' if is_template else 'sensitive environment file'}: {file}",
                    compliance_impact=(
                        "Template file: confirm it contains no real credentials and is not served publicly."
                        if is_template else
                        "Exposes database credentials and secret keys to unauthorized viewers."
                    ),
                ))

            # 2. Debug mode enabled (EDU-CFG-002)
            for lineno, line in enumerate(lines, start=1):
                if len(line) <= MAX_LINE_CHARS and RE_DEBUG_LINE.match(line):
                    findings.append(Finding(
                        id="EDU-CFG-002",
                        pack_id="pack_3_configs",
                        title="Production Debug Mode Enabled (APP_DEBUG=true)",
                        severity="MEDIUM" if is_template else "HIGH",
                        owasp_asvs_id="ASVS v4.0 - 7.1.1",
                        location=f"{rel_path}:{lineno}",
                        evidence=line.strip()[:120],
                        compliance_impact="Verbose stack traces leak internal file paths and database schemas.",
                    ))
                    break

            # 3. Unparameterized SQL (EDU-SAST-001)
            for lineno, line in enumerate(lines, start=1):
                if len(line) > MAX_LINE_CHARS:
                    continue
                if any(p.search(line) for p in SQL_INJECTION_PATTERNS):
                    findings.append(Finding(
                        id="EDU-SAST-001",
                        pack_id="pack_4_sast",
                        title="Unparameterized SQL String Interpolation",
                        severity="CRITICAL",
                        owasp_asvs_id="ASVS v4.0 - 5.3.5",
                        location=f"{rel_path}:{lineno}",
                        evidence=f"Query built with string interpolation: {line.strip()[:120]}",
                        compliance_impact="Allows SQL injection attacks against student records and databases.",
                    ))
                    break

            clean_content = RE_COMMENTS.sub("", content)

            # 4. Missing RBAC on student routes (EDU-RBAC-001)
            if "@app.route" in clean_content and "student" in clean_content.lower() and "session" not in clean_content and "token" not in clean_content:
                findings.append(Finding(
                    id="EDU-RBAC-001",
                    pack_id="pack_5_rbac",
                    title="Missing Session Verification on Student Grade Route (IDOR)",
                    severity="CRITICAL",
                    owasp_asvs_id="ASVS v4.0 - 4.2.1",
                    location=str(rel_path),
                    evidence="Route accepts student ID parameter without validating session user ownership.",
                    compliance_impact="Permits unauthorized access to sensitive student grades and transcripts (IDOR).",
                ))

            # 5. Unrestricted file upload (EDU-PRIV-001)
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
                        compliance_impact="Allows attackers to upload malicious executable scripts onto school servers.",
                    ))

            # 6. Nginx config without HTTPS enforcement (EDU-HTTP-001)
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
                        compliance_impact="Enforces HTTPS connections for student login and grade portals.",
                    ))

    return findings
