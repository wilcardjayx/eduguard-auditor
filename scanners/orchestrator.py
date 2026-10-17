import os
import re
from pathlib import Path
from typing import Dict, List, Optional, Tuple

import yaml

from core.models import AuditPackRequest, Finding
from scanners.code_scanner import scan_codebase
from scanners.perimeter_scanner import scan_perimeter

PROJECT_ROOT = Path(__file__).resolve().parent.parent
RULES_PATH = PROJECT_ROOT / "templates" / "edu_asvs_rules.yaml"

_HOST_RE = re.compile(
    r"^(?:[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?\.)+[A-Za-z]{2,63}(?::\d{1,5})?(?:/.*)?$"
)


def allowed_roots() -> List[Path]:
    """Folders the scanner may read. Override: EDUGUARD_ALLOWED_ROOTS=/path/a:/path/b"""
    raw = os.getenv("EDUGUARD_ALLOWED_ROOTS")
    if raw:
        return [Path(p).expanduser().resolve() for p in raw.split(os.pathsep) if p.strip()]
    return [(PROJECT_ROOT / "demo_target").resolve()]


def looks_like_url(target: str) -> bool:
    t = target.strip()
    return t.lower().startswith(("http://", "https://")) or bool(_HOST_RE.match(t))


def resolve_local_target(target: str) -> Path:
    candidates = [Path(target).expanduser()]
    if not candidates[0].is_absolute():
        candidates = [Path.cwd() / target, PROJECT_ROOT / target]
    for cand in candidates:
        try:
            resolved = cand.resolve()
        except (OSError, RuntimeError):
            continue
        if resolved.is_dir() and any(resolved == r or r in resolved.parents for r in allowed_roots()):
            return resolved
    raise ValueError(
        "Target must be a domain/URL or a folder inside the allowed scan roots "
        "(set EDUGUARD_ALLOWED_ROOTS to add folders)."
    )


def _load_rules() -> Tuple[set, Dict[str, str]]:
    packs, descriptions = set(), {}
    if RULES_PATH.exists():
        data = yaml.safe_load(RULES_PATH.read_text()) or {}
        for pack in data.get("packs", []):
            packs.add(pack["id"])
            for check in pack.get("checks", []):
                descriptions[check["check_id"]] = check.get("description", "")
    return packs, descriptions


def run_audit(request: AuditPackRequest) -> List[Finding]:
    known_packs, descriptions = _load_rules()
    active_packs = request.selected_packs or ["all"]
    if "all" not in active_packs:
        unknown = [p for p in active_packs if p not in known_packs]
        if unknown:
            raise ValueError(f"Unknown pack id(s): {', '.join(unknown)}")

    target = request.target.strip()
    mode = request.scan_mode
    findings: List[Finding] = []

    if looks_like_url(target):
        if mode == "source_code":
            raise ValueError("source_code mode needs a local folder, not a domain.")
        findings.extend(scan_perimeter(target))
    else:
        if mode == "perimeter":
            raise ValueError("perimeter mode needs a domain or URL, not a local path.")
        findings.extend(scan_codebase(str(resolve_local_target(target))))

    if "all" not in active_packs:
        findings = [f for f in findings if f.pack_id in active_packs]

    for f in findings:
        if not f.description:
            f.description = descriptions.get(f.id, "")
    return findings
