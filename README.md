# EduGuard | Autonomous Educational Security Auditor

> *An open-weight AI security scanner built for schools and universities, powered entirely by a local Gemma model no cloud API, no per-scan cost, no student data ever leaving the school's own server.*

**Built by wilcardjayx**, for the **Hacktoberfest Open-Source AI Challenge: Week 2 | "Side Hustle"** *(October 2026)*.

---

## 📋 Table of Contents

- [The Problem](#-the-problem)
- [The Solution](#-the-solution)
- [Why Open-Weight AI?](#-why-open-weight-ai-specifically)
- [What's Being Audited (Template Packs)](#-whats-being-audited-template-packs)
- [How the AI Pipeline Works](#-how-the-ai-pipeline-works)
- [Tech Stack](#-tech-stack)
- [Running Locally](#-running-it-locally)
- [How This Was Built](#-how-this-was-actually-built)
- [Known Limitations](#-known-limitations-stated-honestly)
- [First User](#-first-user)
- [Demo Video](#-demo-video)

---

## 🔍 The Problem

Schools and universities run public-facing websites — **student portals, admissions systems, grade APIs** — on tight IT budgets with understaffed security teams. These sites routinely ship with:

- ❌ **Missing or weak email-spoofing protection** (*no DMARC/SPF*), letting attackers forge emails that look like they're from the bursar or admissions office
- ❌ **Missing transport security** (*no HSTS*), leaving student login sessions open to downgrade attacks
- ❌ **Exposed configuration files**, debug flags left on in production
- ❌ **SQL injection and broken access control** in student-facing APIs
- ❌ **Unrestricted file upload handlers** on assignment/transcript portals

Commercial vulnerability scanners exist, but they're *priced for enterprises*, not school IT budgets and they send your data to *someone else's cloud*.

---

## 💡 The Solution

Paste a school's domain *(or point at a codebase)*, and **EduGuard** runs a set of deterministic security checks mapped to **OWASP ASVS v4.0**, then hands each finding to a **locally-running Gemma model** to generate a plain-English risk explanation and a concrete fix — all *without a single byte of scan data leaving the school's own infrastructure*.

---

## 🤖 Why Open-Weight AI, Specifically

*This is the part that makes the project actually viable as a real tool a school could use — not just a demo:*

| Reason | Explanation |
|:---|:---|
| 🔒 **Data never leaves the premises** | A security scan of a live production student portal is *sensitive by nature* it's literally a list of a school's own vulnerabilities. Running Gemma locally via **Ollama** means that data stays on the school's own server, *never touching a third-party API*. |
| 💰 **Zero per-scan cost** | A cloud LLM API charges *per call*. A school running recurring scans across dozens of subdomains, every week, on a tight budget, **cannot sustainably pay per-token pricing**. A local model makes this financially viable as an actual *recurring service*, not just a one-off audit. |
| 📡 **Works offline** | Many school networks are *deliberately locked down*. A tool that depends on reaching an external API is a tool that **can't be deployed inside those networks at all**. |

---

## 🎯 What's Being Audited (Template Packs)

*Six packs, each mapped to an **OWASP ASVS v4.0** control:*

| Pack | What It Checks | Works Against |
|:---:|:---|:---:|
| **1 — DNS/Email Spoofing** | DMARC policy (*missing, or weak `p=none`*) | 🌐 A real domain |
| **2 — Transport & Headers** | HSTS header, secure cookie flags | 🌐 A real domain |
| **3 — Exposed Configs** | `.env` files, debug-mode flags left on | 💻 Local source code |
| **4 — SQL Injection** | Unparameterized query string-building | 💻 Local source code |
| **5 — RBAC / IDOR** | Missing session checks on student-record routes | 💻 Local source code |
| **6 — File Uploads & PII** | Unrestricted upload handlers | 💻 Local source code |

> ⚠️ **Note:** *Packs 1 and 2* run **live checks** against any domain you give it. *Packs 3–6* require **access to the actual source code**, since those vulnerability classes **can't be proven from the outside** without it.

---

## ⚙️ How the AI Pipeline Works

```text
Target (domain or folder)
   │
   ▼
Deterministic scanner (Python — DNS lookups via dnspython,
HTTP header checks via httpx, regex-based source scanning)
   │
   ▼
Findings (OWASP ASVS-mapped, severity-rated)
   │
   ▼
Local Gemma model via Ollama (gemma2:2b / gemma4:e4b)
   │  — generates: plain-English risk summary, concrete fix,
   │    FERPA/NDPR-framed compliance impact
   ▼
Scored report (Security Grade A–F, per-finding remediation)
```

The **detection logic is fully deterministic** *it doesn't depend on the AI at all*, and is the **same every time** for the same target. The AI's job is *purely explanation and remediation text*, generated fresh per scan.

---

## 🛠️ Tech Stack

| Layer | Technologies |
|:---|:---|
| 🐍 **Backend** | **FastAPI** (Python), `dnspython` for DNS checks, `httpx` for HTTP probing, `pytest` test suite |
| ⚛️ **Frontend** | **React** + **TypeScript** + **Vite** + **Tailwind** |
| 🧠 **AI** | **Ollama** running Gemma locally (`gemma2:2b` for speed, `gemma4:e4b` for deeper reasoning) |
| 📊 **Observability** | **Sentry Agent Tracing** on the AI pipeline *(optional, off by default)* |

---

## 🚀 Running It Locally

### **1. Clone and install backend dependencies**

```bash
git clone https://github.com/wilcardjayx/eduguard-auditor
cd eduguard-auditor
pip install -r requirements.txt
```

### **2. Install and start Ollama, pull a model**

```bash
curl -fsSL https://ollama.com/install.sh | sh
ollama pull gemma2:2B or ollama pull gemma4:e4b
```

### **3. Build the frontend**

```bash
cd frontend
bun install        # or npm install --legacy-peer-deps
bun run build
cp -r dist/. ../ui/react_build/
```

### **4. Run the backend**

```bash
cd ..
python app.py
```

Open **`http://localhost:8000`**, enter a target, pick a template pack, and run an audit.

---

## 🧱 How This Was Actually Built

This started as a *broader idea* an **open-source recon pipeline** *(subdomain enumeration, port scanning, fingerprinting via existing OSS security tools)* with an LLM triage layer on top. Partway through, the project **pivoted** to something *narrower and more defensible*: a **purpose-built scanner for schools specifically**, with every finding mapped to a real **OWASP ASVS v4.0** control ID and framed around **FERPA/NDPR compliance language** that actually means something to a school administrator rather than *raw tool output* a non-technical IT staffer can't parse.

The build went through **two frontend iterations** a simpler server-rendered version, then a full **React rebuild** with *scan history, CSV/PDF export, and a live AI-connection status panel* wired to the same **FastAPI backend** throughout.

Along the way, a chain of **real bugs** got found and fixed, each **confirmed against actual evidence** rather than assumption:

- 🐛 **A misleading "Gemma disconnected" message** that fired on *any* backend error, including a perfectly clean scan with zero findings — *fixed so a clean result shows as clean, not broken*.
- 🐛 **Hardcoded fake "status" cards** that displayed "Unreachable"/"Offline" regardless of actual connectivity *caught because one of them claimed the backend was offline while it was being used to serve the very page displaying that claim*.
- 🐛 **An Ollama cold-start timing issue** behind a Cloudflare tunnel, where the first inference call *(loading a multi-GB model into memory)* outran the tunnel's request timeout, *making a working pipeline look broken on the first try*.
- 🐛 **A DMARC check that only looked for a record's existence**, not its strength missing the common real-world case of a `p=none` policy, which *exists but provides no actual protection*. **Added a second, more precise check** for this.
- 🐛 **Stale demo/seed data** that looked like real scan history on a fresh browser load *removed so a new visitor starts from a genuinely empty state*.

> ✅ **Every fix in this list was verified, not assumed** — the DMARC and HSTS findings shown in this project's own testing were *independently cross-checked* against raw `dig` and `curl` output before being trusted.

---

## ⚠️ Known Limitations (Stated Honestly)

- 🧪 **AI-generated remediation text is not guaranteed perfect.** The detection logic is deterministic and has been verified against ground truth; the fix snippets generated by the local model *occasionally contain errors* (e.g., a malformed DNS record name, or advice for a platform that doesn't support the suggested fix). **The findings themselves are trustworthy**; treat generated fix snippets as a *draft to review*, not a copy-paste-ready patch.
- 🚧 **SPF checking is defined but not yet implemented.** The template pack lists it as a check; the current scanner only implements the **DMARC half** of Pack 1.
- 📁 **Packs 3–6 need source code access.** They *cannot meaningfully evaluate* a live website from the outside alone.

---

## 👤 First User

Tested against **FUOYE's own domain** (`fuoye.edu.ng`) and a **live personal site**, both of which returned *real, independently-verified findings* a **weak DMARC policy** and a **missing HSTS header**, respectively **not synthetic demo data**.

---

## 🎥 Demo Video

> *(to be added)*

---

*Built for the **Hacktoberfest Open-Source AI Challenge: Week 2 | "Side Hustle."** Open innovation made this project possible to actually run: a local, open-weight model is the only reason a tool like this can exist without per-scan cost or a school having to send its own vulnerability data to someone else's cloud.*
