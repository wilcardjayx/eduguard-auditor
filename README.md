# EduGuard

**Pre-launch security audits for school portals, with a Gemma model running on hardware the auditor controls.**

EduGuard runs fixed, deterministic checks against a codebase or a live domain, maps every finding to an OWASP ASVS v4.0 control, and then asks a locally hosted Gemma model to write a fix for each verified finding. The output is a graded A to F report with a plain-English summary for a school board and a git-style diff for the developer.

Built by [@wilcardjayx](https://github.com/wilcardjayx) for the Hacktoberfest Open-Source AI Challenge, Week 2: Side Hustle (October 2026).

**Live demo:** [eduguardauditor.onrender.com](https://eduguardauditor.onrender.com)

> The demo runs on Render's free tier. If nobody has opened it recently, the first load can take 30 to 60 seconds while the instance wakes up.

---

## Contents

- [Why it exists](#why-it-exists)
- [How it works](#how-it-works)
- [Template packs](#template-packs)
- [Quick start](#quick-start)
- [API](#api)
- [Configuration](#configuration)
- [Project structure](#project-structure)
- [Tests](#tests)
- [Security and responsible use](#security-and-responsible-use)
- [Known limitations](#known-limitations)
- [Roadmap](#roadmap)
- [License](#license)

---

## Why it exists

Campus tech clubs and freelance developers ship student portals (elections, hostel management, grade lookups) that rarely get a security review before launch. Selling that review as a small fixed-price service runs into three problems:

1. **Client code can't go to a cloud LLM.** Source, configs and credentials belong to the client, and student records fall under data protection law (FERPA in the US, the NDPA in Nigeria). The working rule here: client code stays on hardware the auditor controls.
2. **Existing scanners are built for security teams.** Their output is a long CVE or XML dump that a campus sysadmin won't read.
3. **Per-token pricing doesn't fit.** A review priced for a student club can't absorb an API bill on every re-scan after the client fixes something.

EduGuard addresses all three: open-weight Gemma on the auditor's own server, a readable graded report, and a fixed server cost no matter how often you re-scan.

---

## How it works

```text
Target (local folder or domain)
   │
   ▼
Deterministic scanners (plain Python)
  - DNS lookups via dnspython
  - HTTP header and cookie checks via httpx
  - Line-by-line regex rules over source files
   │
   ▼
Verified findings (ASVS-mapped, severity-rated, with evidence)
   │
   ▼
Gemma via Ollama, one finding at a time
  - executive summary for a school administrator
  - replacement snippet
  - unified diff
   │
   ▼
Graded report (A–F), Board view + Dev view, CSV / PDF export
```

**Deterministic first, Gemma second.** The model never hunts for bugs. Detection is done by fixed rules, so the same target always gives the same findings. Gemma only receives one verified finding at a time and writes the remediation.

**Prompt-injection aware.** Finding evidence comes from the files being scanned, so the prompt marks it as untrusted data and tells the model not to follow instructions inside it.

**Graceful fallback.** If Ollama is unreachable or a call times out, that finding gets generic OWASP guidance prefixed with `[Local AI Fallback]` instead of hanging the audit.

### Grading

| Grade | Rule |
| :---: | :--- |
| F | any CRITICAL finding |
| D | more than two HIGH findings |
| C | one or two HIGH findings |
| B | only MEDIUM or LOW findings |
| A | no findings |

---

## Template packs

Each pack maps to OWASP ASVS v4.0 controls (`templates/edu_asvs_rules.yaml`).

| Pack | Target | What it checks today | Status |
| :--- | :--- | :--- | :--- |
| 1. Subdomain and email spoofing | live domain | DMARC record missing, or policy is only `p=none` | DMARC done, SPF planned |
| 2. Transport and headers | live domain, nginx configs | HSTS header, `Secure` / `HttpOnly` cookie flags, nginx on port 80 with no HTTPS redirect | SameSite planned |
| 3. Exposed configs | folder | committed `.env` files, `APP_DEBUG=true` | done |
| 4. Injection | folder | SQL built with f-strings, `%`, `+`, `.format()`, PHP `.` concatenation, JS template literals | done |
| 5. Access control | folder | student-record routes with no session or token check | done (heuristic) |
| 6. Uploads and student PII | folder | upload handlers with no extension or MIME validation | done |

Packs 1 and 2 run against a live domain. Packs 3 to 6 need source code, because those bug classes can't be proven from the outside.

---

## Quick start

Requires Python 3.12. Node or Bun is only needed if you change the UI; a built front end ships in `ui/react_build/`.

```bash
git clone https://github.com/wilcardjayx/EduGuard-auditor.git
cd EduGuard-auditor
pip install -r requirements.txt

# local model
curl -fsSL https://ollama.com/install.sh | sh
ollama pull gemma2:2b        # fast triage
# or
ollama pull gemma4:e4b       # slower, better patches

python app.py                # http://localhost:8000
```

Open the audit page, scan the bundled `./demo_target` folder, and pick a model from the navbar.

### The demo target

`demo_target/` is a deliberately vulnerable sample portal: a SQL-injectable grade lookup, a route with no session check, an upload form that accepts any file, an `.env` template with debug on, and an nginx config with no HSTS. Scanning it returns **six findings and a grade of F**.

### Rebuilding the front end (optional)

```bash
cd frontend
bun install            # or: npm install --legacy-peer-deps
bun run build
rm -rf ../ui/react_build && mkdir -p ../ui/react_build
cp -r dist/. ../ui/react_build/
```

---

## API

### `POST /api/scan`

Scan the sample portal with the source code packs:

```bash
curl -X POST http://127.0.0.1:8000/api/scan \
  -H "Content-Type: application/json" \
  -d '{
    "target": "./demo_target",
    "scan_mode": "source_code",
    "selected_packs": ["pack_3_configs", "pack_4_sast", "pack_5_rbac", "pack_6_privacy"],
    "model_name": "gemma2:2b"
  }'
```

Scan a domain you own with the perimeter packs:

```bash
curl -X POST http://127.0.0.1:8000/api/scan \
  -H "Content-Type: application/json" \
  -d '{
    "target": "example.com",
    "scan_mode": "perimeter",
    "selected_packs": ["pack_1_dns", "pack_2_transport"],
    "model_name": "gemma2:2b"
  }'
```

| Field | Values |
| :--- | :--- |
| `target` | a folder inside the allowed scan roots, or a domain / URL |
| `scan_mode` | `source_code`, `perimeter`, or `hybrid` |
| `selected_packs` | pack ids from the table above, or `["all"]` |
| `model_name` | any model listed in `EDUGUARD_MODELS` |

The response is an `AuditReport` with `security_grade`, `total_findings`, `findings` and one `remediations` entry per finding, in the same order.

### Other endpoints

| Endpoint | Purpose |
| :--- | :--- |
| `POST /api/export` | same body as `/api/scan`, returns a printable HTML client report |
| `GET /api/gemma/status` | whether the Ollama server is reachable |

---

## Configuration

All settings are environment variables.

| Variable | Default | Purpose |
| :--- | :--- | :--- |
| `OLLAMA_BASE` | `http://127.0.0.1:11434` | Ollama server, e.g. a Cloudflare tunnel URL |
| `OLLAMA_URL` | `$OLLAMA_BASE/api/generate` | override the generate endpoint directly |
| `EDUGUARD_MODELS` | `gemma4:e4b,gemma2:2b` | models offered in the model picker |
| `EDUGUARD_ALLOWED_ROOTS` | `./demo_target` | folders the scanner may read, separated by `:` |
| `EDUGUARD_ALLOW_PRIVATE_TARGETS` | unset | set to `1` to allow private or loopback hosts (local testing only) |
| `EDUGUARD_HOST` | `0.0.0.0` | bind address |
| `PORT` | `8000` | bind port (Render sets this) |
| `SENTRY_DSN` | unset | enables a Sentry span around each Gemma call to track latency per finding |

### Deployment used for the demo

- **Render** hosts the FastAPI backend and the React build.
- **Gemma** runs through Ollama on a separate CPU-only server controlled by the author, reached through a Cloudflare tunnel set in `OLLAMA_BASE`.

The first call after the model has been idle loads several gigabytes into memory and can outrun the tunnel's request timeout. If the first finding falls back, run the scan again.

---

## Project structure

```text
app.py                      FastAPI app, grading, routes
scanners/
  orchestrator.py           picks scanners by target, enforces allowed roots
  code_scanner.py           packs 2 (nginx), 3, 4, 5, 6
  perimeter_scanner.py      packs 1 and 2 against a live domain, SSRF guard
ai_engine/
  gemma_remediator.py       prompt, Ollama call, fallback
  cheatsheets.py            OWASP guidance used for fallback and context
  tracing.py                optional Sentry spans
core/
  models.py                 Pydantic request, finding and report models
  exporter.py               HTML client report
templates/edu_asvs_rules.yaml   pack and check definitions
demo_target/                deliberately vulnerable sample portal
frontend/                   React 19 + TypeScript + Vite + Tailwind source
ui/react_build/             built front end served by FastAPI
tests/test_eduguard.py      test suite
```

The part worth reading is `ai_engine/gemma_remediator.py`.

---

## Tests

```bash
pip install pytest
python -m pytest -q tests
```

The suite covers:

- all six checks firing on `demo_target` (exactly six findings)
- the AI fallback path when Ollama is unreachable
- the HTML client report export

---

## Security and responsible use

- **Only scan domains you own or have written permission to test.** Perimeter checks are passive (DNS lookups and one HTTPS GET), but permission still matters.
- **SSRF protection:** perimeter scans refuse targets that resolve to private, loopback or link-local addresses.
- **Path restriction:** source scans only read folders inside `EDUGUARD_ALLOWED_ROOTS`, skip symlinks, and skip files over 512 KB.
- **Where data goes:** with Ollama on your own machine, scanned source never reaches a third-party AI provider. Scanning a live domain still sends ordinary DNS and HTTPS requests to that domain, which is the point of the scan.

---

## Known limitations

- **These are pattern rules, not full code analysis.** They miss things a human reviewer would catch and can flag harmless code.
- **The access-control check is a heuristic.** It flags a file that has a student route and never mentions a session or token. A file that mentions either anywhere passes.
- **Header checks don't follow redirects.** A CDN or firewall response (such as a Cloudflare 403) can look like a missing header, so a site behind a WAF may score worse than it is.
- **Gemma's fixes are drafts to review, not patches to paste.** It has produced a malformed DNS record name, for example.
- **CPU-only inference is slow,** especially with `gemma4:e4b`. Long calls time out per finding and fall back rather than blocking the audit.
- **Packs 3 to 6 say nothing about a live site** without its source.

---

## Roadmap

- [ ] SPF check (`EDU-DNS-002`)
- [ ] `SameSite` cookie flag check
- [ ] Follow one redirect hop and detect CDN block pages
- [ ] Tests for the perimeter scanner with mocked DNS and HTTP
- [ ] Route-level access-control check instead of file-level
- [ ] Demo video

---

## License

Apache 2.0. See [LICENSE](LICENSE).
