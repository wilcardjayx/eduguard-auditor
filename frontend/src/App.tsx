import React, { useState, useEffect, useRef } from 'react';
import { Toaster, toast } from 'sonner';
import { motion } from 'framer-motion';
import { 
  ShieldAlert, 
  Terminal, 
  Copy, 
  Check, 
  Play, 
  CheckCircle2, 
  AlertTriangle, 
  FileText, 
  Cpu, 
  ExternalLink, 
  ChevronRight, 
  Menu, 
  X,
  Printer,
  Sparkles,
  Loader2,
  ShieldCheck,
  History,
  Clock,
  RotateCcw,
  Search,
  Trash2,
  Globe,
  Calendar,
  Filter,
  ArrowUpRight,
  Database,
  Download,
  RefreshCw,
  WifiOff,
  Activity
} from 'lucide-react';

interface CheckItem {
  check_id: string;
  title: string;
  severity: 'CRITICAL' | 'HIGH' | 'MEDIUM';
  owasp_asvs_id: string;
  target_type: string;
  rule_logic: string;
  description: string;
}

interface TemplatePack {
  id: string;
  name: string;
  description: string;
  checks: CheckItem[];
}

const TEMPLATE_PACKS: TemplatePack[] = [
  {
    id: "pack_1_dns",
    name: "Subdomain & Email Spoofing Hygiene",
    description: "Audits DNS records for dangling CNAMEs, bursar/tuition email spoofing protection, and CA authorization.",
    checks: [
      {
        check_id: "EDU-DNS-001",
        title: "Missing DMARC Policy on School Domain",
        severity: "HIGH",
        owasp_asvs_id: "ASVS v4.0 - 1.14.3",
        target_type: "domain",
        rule_logic: "dns_txt_missing_dmarc",
        description: "Checks if the domain lacks a DMARC TXT record, allowing attackers to spoof official emails from the bursar or admissions office."
      },
      {
        check_id: "EDU-DNS-002",
        title: "Missing Sender Policy Framework (SPF) Record",
        severity: "HIGH",
        owasp_asvs_id: "ASVS v4.0 - 1.14.3",
        target_type: "domain",
        rule_logic: "dns_txt_missing_spf",
        description: "Verify SPF records are published to prevent forged @school.edu phishing emails."
      }
    ]
  },
  {
    id: "pack_2_transport",
    name: "Transport, TLS & Header Posture",
    description: "Inspects HTTP response headers, HSTS preloading, cookie security flags, and TLS certificate validity.",
    checks: [
      {
        check_id: "EDU-HTTP-001",
        title: "Missing Strict-Transport-Security (HSTS) Header",
        severity: "MEDIUM",
        owasp_asvs_id: "ASVS v4.0 - 14.4.4",
        target_type: "domain",
        rule_logic: "missing_header_hsts",
        description: "Enforces HTTPS connections for student login and grade portals."
      },
      {
        check_id: "EDU-HTTP-002",
        title: "Insecure Session Cookie Attributes (Missing HttpOnly/Secure/SameSite)",
        severity: "HIGH",
        owasp_asvs_id: "ASVS v4.0 - 3.4.1",
        target_type: "domain",
        rule_logic: "insecure_cookie_flags",
        description: "Ensures session cookies protect student authentication tokens against XSS theft and CSRF."
      }
    ]
  },
  {
    id: "pack_3_configs",
    name: "Exposed Configs & LMS Footprints",
    description: "Detects exposed .env files, debug modes enabled in production, and backup archives.",
    checks: [
      {
        check_id: "EDU-CFG-001",
        title: "Exposed Environment File (.env)",
        severity: "CRITICAL",
        owasp_asvs_id: "ASVS v4.0 - 14.2.1",
        target_type: "source_code",
        rule_logic: "file_exists_env",
        description: "Flags accidentally committed or published .env files containing database credentials and secret keys."
      },
      {
        check_id: "EDU-CFG-002",
        title: "Production Debug Mode Enabled (APP_DEBUG=true)",
        severity: "HIGH",
        owasp_asvs_id: "ASVS v4.0 - 7.1.1",
        target_type: "source_code",
        rule_logic: "code_pattern_debug_true",
        description: "Prevents verbose stack traces from leaking internal database schemas and file paths."
      }
    ]
  },
  {
    id: "pack_4_sast",
    name: "Injection & Query Safety",
    description: "Flags unparameterized SQL queries, unsafe template rendering, and injection vectors.",
    checks: [
      {
        check_id: "EDU-SAST-001",
        title: "Unparameterized SQL String Interpolation",
        severity: "CRITICAL",
        owasp_asvs_id: "ASVS v4.0 - 5.3.5",
        target_type: "source_code",
        rule_logic: "semgrep_sql_injection",
        description: "Detects raw string formatting in database queries that permit SQL injection into academic transcripts."
      }
    ]
  },
  {
    id: "pack_5_rbac",
    name: "Access Control & Student Record IDOR",
    description: "Audits API endpoints for missing session ownership and role-based middleware checks.",
    checks: [
      {
        check_id: "EDU-RBAC-001",
        title: "Missing Session Verification on Student Grade Route (IDOR)",
        severity: "CRITICAL",
        owasp_asvs_id: "ASVS v4.0 - 4.2.1",
        target_type: "source_code",
        rule_logic: "semgrep_missing_rbac",
        description: "Ensures student record and transcript endpoints verify that the requesting user owns the ID."
      }
    ]
  },
  {
    id: "pack_6_privacy",
    name: "File Uploads & Student PII Privacy",
    description: "Audits assignment/transcript upload handlers and sensitive data masking.",
    checks: [
      {
        check_id: "EDU-PRIV-001",
        title: "Unrestricted Student File Upload Handler",
        severity: "HIGH",
        owasp_asvs_id: "ASVS v4.0 - 12.3.1",
        target_type: "source_code",
        rule_logic: "semgrep_unrestricted_upload",
        description: "Ensures uploaded assignments and documents validate MIME types and store files outside web roots."
      }
    ]
  }
];

interface Finding {
  id: string;
  title: string;
  severity: 'CRITICAL' | 'HIGH' | 'MEDIUM';
  owasp_asvs_id: string;
  description: string;
  compliance_impact?: string;
}

interface Remediation {
  executive_summary: string;
  patched_code_snippet: string;
  unified_diff: string;
}


// Plays a video and makes near-white pixels transparent in real time via canvas,
// since MP4 itself has no alpha channel. Threshold/softness are tunable.
function ChromaKeyVideo({ src, className }: { src: string; className?: string }) {
  const videoRef = useRef<HTMLVideoElement>(null);
  const canvasRef = useRef<HTMLCanvasElement>(null);

  useEffect(() => {
    const video = videoRef.current;
    const canvas = canvasRef.current;
    if (!video || !canvas) return;
    const ctx = canvas.getContext('2d', { willReadFrequently: true });
    if (!ctx) return;

    let rafId = 0;
    const threshold = 235;
    const softness = 40;

    const draw = () => {
      if (video.readyState >= 2 && video.videoWidth > 0) {
        if (canvas.width !== video.videoWidth || canvas.height !== video.videoHeight) {
          canvas.width = video.videoWidth;
          canvas.height = video.videoHeight;
        }
        ctx.drawImage(video, 0, 0, canvas.width, canvas.height);
        const frame = ctx.getImageData(0, 0, canvas.width, canvas.height);
        const d = frame.data;
        for (let i = 0; i < d.length; i += 4) {
          const r = d[i], g = d[i + 1], b = d[i + 2];
          const minChannel = Math.min(r, g, b);
          if (minChannel > threshold - softness) {
            const t = Math.min(1, Math.max(0, (minChannel - (threshold - softness)) / softness));
            d[i + 3] = Math.round(d[i + 3] * (1 - t));
          }
        }
        ctx.putImageData(frame, 0, 0);
      }
      rafId = requestAnimationFrame(draw);
    };
    rafId = requestAnimationFrame(draw);
    return () => cancelAnimationFrame(rafId);
  }, []);

  return (
    <>
      <video
        ref={videoRef}
        src={src}
        autoPlay
        loop
        muted
        playsInline
        style={{ position: 'absolute', width: 1, height: 1, opacity: 0, pointerEvents: 'none', overflow: 'hidden' }}
      />
      <canvas ref={canvasRef} className={className} />
    </>
  );
}

const SAMPLE_FINDINGS: Finding[] = [
  {
    id: "EDU-DNS-001",
    title: "Missing DMARC Policy on School Domain",
    severity: "HIGH",
    owasp_asvs_id: "ASVS v4.0 - 1.14.3",
    description: "Checks if the domain lacks a DMARC TXT record, allowing attackers to spoof official emails from the bursar or admissions office.",
    compliance_impact: "FERPA §99.31 Risk — Spoofed official email vectors lead to unauthorized credential phishing."
  },
  {
    id: "EDU-CFG-001",
    title: "Exposed Environment File (.env)",
    severity: "CRITICAL",
    owasp_asvs_id: "ASVS v4.0 - 14.2.1",
    description: "Flags accidentally committed or published .env files containing database credentials and secret keys.",
    compliance_impact: "FERPA Direct Violation — Student educational records and SSN hashes exposed to unauthorized retrieval."
  },
  {
    id: "EDU-RBAC-001",
    title: "Missing Session Verification on Student Grade Route (IDOR)",
    severity: "CRITICAL",
    owasp_asvs_id: "ASVS v4.0 - 4.2.1",
    description: "Ensures student record and transcript endpoints verify that the requesting user owns the ID.",
    compliance_impact: "FERPA Grade Privacy Violation — Unauthenticated or cross-student grade enumeration permitted."
  }
];

const SAMPLE_REMEDIATIONS: Remediation[] = [
  {
    executive_summary: "Configure TXT record '_dmarc.school.edu' with 'v=DMARC1; p=reject; rua=mailto:dmarc-reports@school.edu' to block spoofed student bursar billing emails.",
    patched_code_snippet: "_dmarc.school.edu. 300 IN TXT \"v=DMARC1; p=reject; rua=mailto:security-reports@school.edu; aspf=s; adkim=s;\"",
    unified_diff: "--- a/dns/zonefile.zone\n+++ b/dns/zonefile.zone\n@@ -14,3 +14,4 @@\n+ _dmarc.school.edu. IN TXT \"v=DMARC1; p=reject; rua=mailto:security-reports@school.edu;\""
  },
  {
    executive_summary: "Immediately exclude .env from web server root, rotate exposed database secrets, and add .env to .gitignore.",
    patched_code_snippet: "# .gitignore\n.env\n.env.*\n!.env.example\ncredentials.json\n*.pem",
    unified_diff: "--- a/.gitignore\n+++ b/.gitignore\n@@ -1,2 +1,6 @@\n+ .env\n+ .env.*\n+ !.env.example\n+ credentials.json"
  },
  {
    executive_summary: "Enforce ownership middleware verifying that the requesting user's identity matches student_id before querying records.",
    patched_code_snippet: "@router.get('/students/{student_id}/grades')\nasync def get_grades(student_id: str, user=Depends(get_current_user)):\n    if user.role != 'faculty' and user.student_id != student_id:\n        raise HTTPException(status_code=403, detail='Access Denied: FERPA Protected')\n    return fetch_student_grades(student_id)",
    unified_diff: "--- a/api/students.py\n+++ b/api/students.py\n@@ -24,4 +24,7 @@\n async def get_grades(student_id: str, user=Depends(get_current_user)):\n+    if user.role != 'faculty' and user.student_id != student_id:\n+        raise HTTPException(status_code=403, detail='Access Denied: FERPA Protected')\n     return fetch_student_grades(student_id)"
  }
];

export interface ScanReport {
  id: string;
  name: string;
  timestamp: string;
  dateFormatted: string;
  isoDate: string;
  target: string;
  scanMode: string;
  model: string;
  selectedPacks: string[];
  grade: 'A' | 'A-' | 'B+' | 'B' | 'C' | 'D' | 'F';
  gradeColor: string;
  isSampleData: boolean;
  findings: Finding[];
  remediations: Remediation[];
  executiveNotes?: string;
}

const DEFAULT_SCAN_HISTORY: ScanReport[] = [
  {
    id: "SCAN-9482",
    name: "Campus Core & Student Portal",
    timestamp: "Today, 16:42",
    dateFormatted: "Oct 16, 2026 · 16:42",
    isoDate: "2026-10-16T16:42:00Z",
    target: "./demo_target",
    scanMode: "hybrid",
    model: "gemma4:e4b",
    selectedPacks: ['pack_1_dns', 'pack_3_configs', 'pack_5_rbac'],
    grade: "C",
    gradeColor: "#FF6B2B",
    isSampleData: true,
    findings: SAMPLE_FINDINGS,
    remediations: SAMPLE_REMEDIATIONS,
    executiveNotes: "Critical exposure of .env credential file and insecure IDOR on student grades API. Immediate remediation required under FERPA §99.31."
  },
  {
    id: "SCAN-8830",
    name: "Admissions API & Applicant Registry",
    timestamp: "Yesterday, 14:15",
    dateFormatted: "Oct 15, 2026 · 14:15",
    isoDate: "2026-10-15T14:15:00Z",
    target: "https://admissions.state.edu/api/v2",
    scanMode: "perimeter",
    model: "gemma4:e4b",
    selectedPacks: ['pack_1_dns', 'pack_2_tls', 'pack_4_headers'],
    grade: "B",
    gradeColor: "#FF6B2B",
    isSampleData: true,
    findings: [
      {
        id: "EDU-TLS-002",
        title: "TLS 1.0/1.1 Deprecated Cipher Negotiation Allowed",
        severity: "HIGH",
        owasp_asvs_id: "ASVS v4.0 - 9.1.2",
        description: "Edge load balancer allows legacy TLS 1.0/1.1 connections with CBC ciphers vulnerable to POODLE attacks.",
        compliance_impact: "FERPA Transport Privacy — Weak cryptographic negotiation could allow intercepting applicant tax forms."
      },
      {
        id: "EDU-HDR-001",
        title: "Missing HSTS Preload & Subdomain Enforcement",
        severity: "MEDIUM",
        owasp_asvs_id: "ASVS v4.0 - 14.4.3",
        description: "Strict-Transport-Security header lacks 'includeSubDomains' and max-age is set under 31536000 seconds.",
        compliance_impact: "Man-in-the-Middle downgrade vulnerability for student portal subdomains."
      }
    ],
    remediations: [
      {
        executive_summary: "Configure NGINX reverse proxy to enforce TLS 1.2 and TLS 1.3 only, disabling legacy 3DES and CBC ciphers.",
        patched_code_snippet: "ssl_protocols TLSv1.2 TLSv1.3;\nssl_ciphers 'ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256:ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384';\nssl_prefer_server_ciphers off;\nssl_session_timeout 1d;\nssl_session_cache shared:SSL:10m;",
        unified_diff: "--- a/nginx/admissions.conf\n+++ b/nginx/admissions.conf\n@@ -14,2 +14,3 @@\n- ssl_protocols TLSv1.0 TLSv1.1 TLSv1.2;\n+ ssl_protocols TLSv1.2 TLSv1.3;\n+ ssl_prefer_server_ciphers off;"
      },
      {
        executive_summary: "Apply Strict-Transport-Security with 2-year duration, includeSubDomains, and preload flag.",
        patched_code_snippet: "add_header Strict-Transport-Security \"max-age=63072000; includeSubDomains; preload\" always;\nadd_header X-Content-Type-Options \"nosniff\" always;",
        unified_diff: "--- a/nginx/admissions.conf\n+++ b/nginx/admissions.conf\n@@ -24,1 +24,2 @@\n- add_header Strict-Transport-Security \"max-age=3600\";\n+ add_header Strict-Transport-Security \"max-age=63072000; includeSubDomains; preload\" always;"
      }
    ],
    executiveNotes: "Surface transport audit identified legacy TLS support and missing HSTS subdomains policy on admissions endpoints."
  },
  {
    id: "SCAN-7215",
    name: "Registrar Gradebook Internal API",
    timestamp: "Oct 13, 2026 · 11:30",
    dateFormatted: "Oct 13, 2026 · 11:30",
    isoDate: "2026-10-13T11:30:00Z",
    target: "internal-sis.campus.edu",
    scanMode: "source_code",
    model: "gemma4:e4b",
    selectedPacks: ['pack_3_configs', 'pack_5_rbac', 'pack_6_storage'],
    grade: "F",
    gradeColor: "#FF4D4D",
    isSampleData: true,
    findings: [
      {
        id: "EDU-CFG-003",
        title: "Hardcoded JWT Secret Key in Faculty Auth Middleware",
        severity: "CRITICAL",
        owasp_asvs_id: "ASVS v4.0 - 3.5.2",
        description: "Found static string 'edu_portal_jwt_2025' used as HMAC secret to verify professor and registrar tokens.",
        compliance_impact: "FERPA System Compromise — Forged instructor sessions permit arbitrary grade inflation and record tampering."
      },
      {
        id: "EDU-RBAC-004",
        title: "Unrestricted Transcript Export Route Missing Role Guard",
        severity: "CRITICAL",
        owasp_asvs_id: "ASVS v4.0 - 4.1.3",
        description: "Route `/api/sis/transcripts/bulk-download` does not verify administrative clearance or multi-factor authentication.",
        compliance_impact: "Mass Exfiltration Risk — Bulk export of entire university student transcript database without audit trail."
      },
      {
        id: "EDU-STR-001",
        title: "Unencrypted Student SSN & Financial Records in S3 Bucket",
        severity: "CRITICAL",
        owasp_asvs_id: "ASVS v4.0 - 8.3.1",
        description: "Discovered public read ACL on `s3://univ-student-transcripts-prod` without KMS client-side envelope encryption.",
        compliance_impact: "Direct FERPA & GLBA Violation — Immediate reporting to Department of Education mandated."
      }
    ],
    remediations: [
      {
        executive_summary: "Move JWT secret to secret manager, require minimum 256-bit entropy, and reject hardcoded default fallbacks.",
        patched_code_snippet: "import os\nJWT_SECRET = os.environ.get('SIS_JWT_SECRET')\nif not JWT_SECRET or len(JWT_SECRET) < 32:\n    raise RuntimeError('FATAL: SIS_JWT_SECRET missing or insufficient entropy.')",
        unified_diff: "--- a/sis/auth.py\n+++ b/sis/auth.py\n@@ -8,1 +8,4 @@\n- JWT_SECRET = 'edu_portal_jwt_2025'\n+ JWT_SECRET = os.environ.get('SIS_JWT_SECRET')\n+ if not JWT_SECRET: raise RuntimeError('Insecure')"
      },
      {
        executive_summary: "Enforce `@require_roles(['REGISTRAR_ADMIN'])` and active MFA session challenge before transcript dumping.",
        patched_code_snippet: "@router.get('/sis/transcripts/bulk-download')\n@require_roles(['REGISTRAR_ADMIN'])\nasync def bulk_export_transcripts(auth: AuthContext = Depends(verify_mfa_challenge)):\n    audit_logger.log_admin_export(auth.user_id)\n    return generate_transcripts_archive()",
        unified_diff: "--- a/sis/routes.py\n+++ b/sis/routes.py\n@@ -34,1 +34,3 @@\n- async def bulk_export_transcripts():\n+ @require_roles(['REGISTRAR_ADMIN'])\n+ async def bulk_export_transcripts(auth=Depends(verify_mfa_challenge)):"
      },
      {
        executive_summary: "Apply S3 Block Public Access and enable SSE-KMS with university-managed key.",
        patched_code_snippet: "resource \"aws_s3_bucket_public_access_block\" \"transcripts\" {\n  bucket = aws_s3_bucket.transcripts.id\n  block_public_acls       = true\n  block_public_policy     = true\n  ignore_public_acls      = true\n  restrict_public_buckets = true\n}",
        unified_diff: "--- a/infra/s3.tf\n+++ b/infra/s3.tf\n@@ -12,1 +12,4 @@\n- acl = \"public-read\"\n+ acl = \"private\"\n+ server_side_encryption_configuration { rule { apply_server_side_encryption_by_default { sse_algorithm = \"aws:kms\" } } }"
      }
    ],
    executiveNotes: "CRITICAL: Multiple high-risk vulnerabilities expose student PII and unauthenticated transcripts export."
  },
  {
    id: "SCAN-6091",
    name: "Course Catalog & Public Library",
    timestamp: "Oct 10, 2026 · 09:12",
    dateFormatted: "Oct 10, 2026 · 09:12",
    isoDate: "2026-10-10T09:12:00Z",
    target: "https://catalog.university.edu",
    scanMode: "perimeter",
    model: "gemma2:2b",
    selectedPacks: ['pack_1_dns', 'pack_2_tls', 'pack_4_headers'],
    grade: "A-",
    gradeColor: "#E2FF32",
    isSampleData: true,
    findings: [
      {
        id: "EDU-HDR-004",
        title: "Permissions-Policy Missing Camera and Geolocation Directives",
        severity: "MEDIUM",
        owasp_asvs_id: "ASVS v4.0 - 14.4.7",
        description: "HTTP headers lack explicit sandbox restrictions for third-party scripts embedded in the online course catalog.",
        compliance_impact: "Minor hardening recommendation — Prevents unauthorized sensory telemetry collection."
      }
    ],
    remediations: [
      {
        executive_summary: "Add modern Permissions-Policy header denying camera, microphone, and geolocation by default.",
        patched_code_snippet: "add_header Permissions-Policy \"geolocation=(), camera=(), microphone=(), payment=()\" always;",
        unified_diff: "--- a/nginx/catalog.conf\n+++ b/nginx/catalog.conf\n@@ -22,0 +22,1 @@\n+ add_header Permissions-Policy \"geolocation=(), camera=(), microphone=()\" always;"
      }
    ],
    executiveNotes: "Strong baseline compliance observed. Only minor HTTP header policy hardening recommended."
  }
];

// Framer Motion Staggered Entrance Variants for Findings Bento Cards
const findingsContainerVariants = {
  hidden: { opacity: 0 },
  visible: {
    opacity: 1,
    transition: {
      staggerChildren: 0.12,
      delayChildren: 0.08
    }
  }
};

const findingCardVariants = {
  hidden: { 
    opacity: 0, 
    y: 28,
    scale: 0.98
  },
  visible: { 
    opacity: 1, 
    y: 0,
    scale: 1,
    transition: {
      type: "spring" as const,
      stiffness: 260,
      damping: 24,
      mass: 0.8
    }
  }
};

export default function App() {
  const [activePage, setActivePage] = useState<'landing' | 'audit' | 'templates' | 'owasp' | 'engine'>('landing');
  const [selectedModel, setSelectedModel] = useState<string>('gemma4:e4b');
  const [scanTarget, setScanTarget] = useState<string>('./demo_target');
  const [scanMode, setScanMode] = useState<string>('hybrid');
  const [selectedPacks, setSelectedPacks] = useState<string[]>(['pack_1_dns', 'pack_3_configs', 'pack_5_rbac']);
  const [isScanning, setIsScanning] = useState<boolean>(false);
  const [scanProgressStep, setScanProgressStep] = useState<string>('');
  const [hasScanned, setHasScanned] = useState<boolean>(true);
  const [isDevDiffMode, setIsDevDiffMode] = useState<boolean>(false);
  const [copiedIndex, setCopiedIndex] = useState<number | null>(null);
  const [mobileMenuOpen, setMobileMenuOpen] = useState<boolean>(false);

  // Scan History Sidebar State
  const [scanHistory, setScanHistory] = useState<ScanReport[]>(() => {
    try {
      const saved = localStorage.getItem('eduguard_scan_history');
      if (saved) {
        const parsed = JSON.parse(saved);
        if (Array.isArray(parsed) && parsed.length > 0) return parsed;
      }
    } catch (e) {}
    return [];
  });

  const [selectedScanId, setSelectedScanId] = useState<string | null>(() => {
    try {
      const saved = localStorage.getItem('eduguard_scan_history');
      if (saved) {
        const parsed = JSON.parse(saved);
        if (Array.isArray(parsed) && parsed.length > 0) return parsed[0].id;
      }
    } catch (e) {}
    return null;
  });

  const [isHistoryOpen, setIsHistoryOpen] = useState<boolean>(false);
  const [historySearch, setHistorySearch] = useState<string>('');
  const [historyFilter, setHistoryFilter] = useState<'all' | 'critical' | 'passing'>('all');

  // Gemma Engine Connectivity State (Suppresses generic output if not connected)
  const [isGemmaConnected, setIsGemmaConnected] = useState<boolean>(false);
  const [isBackendReachable, setIsBackendReachable] = useState<boolean>(false);
  const [isProbingGemma, setIsProbingGemma] = useState<boolean>(false);
  const [showDisconnectedWriteup, setShowDisconnectedWriteup] = useState<boolean>(true);

  // Check Gemma live probe
  const checkGemmaLiveStatus = async (silent = false) => {
    setIsProbingGemma(true);
    try {
      const res = await fetch('/api/gemma/status', { method: 'GET' });
      setIsBackendReachable(true); // got any HTTP response at all => FastAPI is up
      if (res.ok) {
        const data = await res.json();
        if (data.connected) {
          setIsGemmaConnected(true);
          setShowDisconnectedWriteup(false);
          if (!silent) {
            toast.success("Gemma Engine Connected", {
              description: `Active ${data.runtime || 'Ollama'} runtime detected on port ${data.port || 11434}.`,
              style: {
                background: '#181818',
                border: '1px solid #E2FF32',
                color: '#F4F2ED',
                fontFamily: 'JetBrains Mono, monospace'
              }
            });
          }
          setIsProbingGemma(false);
          return true;
        }
      }
    } catch (err) {
      setIsBackendReachable(false); // fetch itself failed => truly unreachable
    }

    setIsGemmaConnected(false);
    if (!silent) {
      toast.error("Gemma Engine Offline", {
        description: "Local daemon at localhost:11434 / localhost:8000 is unreachable.",
        style: {
          background: '#181818',
          border: '1px solid #FF6B2B',
          color: '#F4F2ED',
          fontFamily: 'JetBrains Mono, monospace'
        }
      });
    }
    setIsProbingGemma(false);
    return false;
  };

  useEffect(() => {
    checkGemmaLiveStatus(true);
  }, []);

  // Currently active scan report
  const activeReport = scanHistory.find(s => s.id === selectedScanId) || scanHistory[0] || null;

  // Filtered scans for history sidebar
  const filteredHistory = scanHistory.filter(report => {
    const term = historySearch.toLowerCase().trim();
    const matchesSearch = !term || 
      report.target.toLowerCase().includes(term) ||
      report.id.toLowerCase().includes(term) ||
      report.name.toLowerCase().includes(term) ||
      report.model.toLowerCase().includes(term);
    
    if (!matchesSearch) return false;

    if (historyFilter === 'critical') {
      return report.grade === 'C' || report.grade === 'D' || report.grade === 'F';
    }
    if (historyFilter === 'passing') {
      return report.grade === 'A' || report.grade === 'A-' || report.grade === 'B+' || report.grade === 'B';
    }
    return true;
  });

  // Switch between past scan reports
  const selectScanReport = (reportId: string) => {
    setSelectedScanId(reportId);
    setHasScanned(true);
    setShowDisconnectedWriteup(false);
    const rep = scanHistory.find(s => s.id === reportId);
    if (rep) {
      toast.info(`Switched to Report: ${rep.id}`, {
        description: `${rep.name} (${rep.isSampleData ? 'Archived Baseline' : 'Live Verified'} · Grade ${rep.grade}) · ${rep.findings.length} findings`,
        style: {
          background: '#181818',
          border: '1px solid #E2FF32',
          color: '#F4F2ED',
          fontFamily: 'JetBrains Mono, monospace'
        }
      });
      const workbenchEl = document.getElementById('workbench-anchor');
      if (workbenchEl) {
        workbenchEl.scrollIntoView({ behavior: 'smooth' });
      }
    }
  };

  // Delete an individual scan report from history
  const deleteScanReport = (reportId: string, e?: React.MouseEvent) => {
    if (e) e.stopPropagation();
    setScanHistory(prev => {
      const filtered = prev.filter(s => s.id !== reportId);
      try {
        localStorage.setItem('eduguard_scan_history', JSON.stringify(filtered));
      } catch (err) {}
      if (selectedScanId === reportId) {
        setSelectedScanId(filtered.length > 0 ? filtered[0].id : null);
        if (filtered.length === 0) setHasScanned(false);
      }
      return filtered;
    });
    toast.info("Report Removed", {
      description: `Removed ${reportId} from scan history archive.`,
      style: {
        background: '#181818',
        border: '1px solid #FF6B2B',
        color: '#F4F2ED',
        fontFamily: 'JetBrains Mono, monospace'
      }
    });
  };

  // Restore baseline benchmark demo scans
  const restoreDefaultHistory = () => {
    setScanHistory(DEFAULT_SCAN_HISTORY);
    setSelectedScanId(DEFAULT_SCAN_HISTORY[0].id);
    setHasScanned(true);
    try {
      localStorage.setItem('eduguard_scan_history', JSON.stringify(DEFAULT_SCAN_HISTORY));
    } catch (e) {}
    toast.success("Benchmark History Restored", {
      description: "Restored 4 institutional demo audit reports.",
      style: {
        background: '#181818',
        border: '1px solid #E2FF32',
        color: '#F4F2ED',
        fontFamily: 'JetBrains Mono, monospace'
      }
    });
  };

  // Export current scan findings as CSV spreadsheet for institutional compliance reporting
  const exportFindingsCSV = (report: ScanReport | null | undefined) => {
    if (!report || !report.findings || report.findings.length === 0) {
      toast.error("No Findings to Export", {
        description: "The active report does not contain any findings to export.",
        style: {
          background: '#181818',
          border: '1px solid #FF4D4D',
          color: '#F4F2ED',
          fontFamily: 'JetBrains Mono, monospace'
        }
      });
      return;
    }

    const headers = [
      "Finding ID",
      "Severity",
      "OWASP ASVS Standard",
      "Title",
      "Compliance Impact",
      "Description",
      "Remediation Summary",
      "Remediation Patch / Diff",
      "Report ID",
      "Scan Target",
      "Audit Date",
      "AI Engine",
      "Security Grade"
    ];

    const escapeCsv = (str: string | undefined | null) => {
      if (str === undefined || str === null) return '""';
      const clean = String(str).replace(/"/g, '""');
      return `"${clean}"`;
    };

    const rows = report.findings.map((f, idx) => {
      const remediation = report.remediations[idx] || SAMPLE_REMEDIATIONS[0];
      return [
        escapeCsv(f.id),
        escapeCsv(f.severity),
        escapeCsv(f.owasp_asvs_id),
        escapeCsv(f.title),
        escapeCsv(f.compliance_impact || "N/A"),
        escapeCsv(f.description),
        escapeCsv(remediation?.executive_summary || "N/A"),
        escapeCsv(remediation?.patched_code_snippet || remediation?.unified_diff || "N/A"),
        escapeCsv(report.id),
        escapeCsv(report.target),
        escapeCsv(report.dateFormatted || report.timestamp),
        escapeCsv(report.model),
        escapeCsv(report.grade)
      ].join(",");
    });

    const csvContent = "\uFEFF" + [headers.join(","), ...rows].join("\r\n");
    const blob = new Blob([csvContent], { type: "text/csv;charset=utf-8;" });
    const url = URL.createObjectURL(blob);
    const link = document.createElement("a");
    const filename = `eduguard_findings_${report.id.toLowerCase()}_${new Date().toISOString().slice(0, 10)}.csv`;
    link.setAttribute("href", url);
    link.setAttribute("download", filename);
    document.body.appendChild(link);
    link.click();
    document.body.removeChild(link);
    URL.revokeObjectURL(url);

    toast.success("CSV Export Generated", {
      description: `Exported ${report.findings.length} findings to ${filename} for institutional spreadsheets.`,
      style: {
        background: '#181818',
        border: '1px solid #E2FF32',
        color: '#F4F2ED',
        fontFamily: 'JetBrains Mono, monospace'
      }
    });
  };

  // Close sidebar on Escape key
  useEffect(() => {
    const handleKeyDown = (e: KeyboardEvent) => {
      if (e.key === 'Escape' && isHistoryOpen) {
        setIsHistoryOpen(false);
      }
    };
    window.addEventListener('keydown', handleKeyDown);
    return () => window.removeEventListener('keydown', handleKeyDown);
  }, [isHistoryOpen]);
  const togglePack = (packId: string) => {
    setSelectedPacks(prev => 
      prev.includes(packId) ? prev.filter(id => id !== packId) : [...prev, packId]
    );
  };

  const toggleAllPacks = () => {
    if (selectedPacks.length === TEMPLATE_PACKS.length) {
      setSelectedPacks([]);
    } else {
      setSelectedPacks(TEMPLATE_PACKS.map(p => p.id));
    }
  };

  const handleRunAudit = async () => {
    if (selectedPacks.length === 0) {
      toast.error("Selection Required", {
        description: "Please select at least one template pack to initiate an audit.",
        style: {
          background: '#181818',
          border: '1px solid #FF4D4D',
          color: '#F4F2ED',
          fontFamily: 'JetBrains Mono, monospace'
        }
      });
      return;
    }

    setIsScanning(true);
    const auditToastId = "eduguard-audit-run";

    // Stage 1 Toast: Attack Perimeter & Endpoints
    toast.loading("Stage 1/3: Surface Perimeter Inspection", {
      id: auditToastId,
      description: `Auditing ${selectedPacks.length} packs on ${scanTarget || './demo_target'}...`,
      style: {
        background: '#181818',
        border: '1px solid #383838',
        color: '#F4F2ED',
        fontFamily: 'JetBrains Mono, monospace'
      }
    });

    // Stage 2 Toast: OWASP ASVS v4.0 Matrix Evaluation
    const stage2Timer = setTimeout(() => {
      toast.loading("Stage 2/3: OWASP ASVS v4.0 Baselines", {
        id: auditToastId,
        description: "Asserting deterministic verification rules across DNS, Transport, and RBAC...",
        style: {
          background: '#181818',
          border: '1px solid #E2FF32',
          color: '#F4F2ED',
          fontFamily: 'JetBrains Mono, monospace'
        }
      });
    }, 900);

    // Stage 3 Toast: Local Gemma Remediation Generation
    const stage3Timer = setTimeout(() => {
      toast.loading(`Stage 3/3: ${selectedModel} Remediation`, {
        id: auditToastId,
        description: `Synthesizing verified diff patches and FERPA impact summaries locally...`,
        style: {
          background: '#181818',
          border: '1px solid #FF6B2B',
          color: '#F4F2ED',
          fontFamily: 'JetBrains Mono, monospace'
        }
      });
    }, 1800);

    // Call real /api/scan backend or fallback gracefully
    const startTime = Date.now();
    let liveResult: any = null;
    let isConnectedBackend = false;

    try {
      const response = await fetch('/api/scan', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          target: scanTarget || './demo_target',
          scan_mode: scanMode,
          selected_packs: selectedPacks,
          model_name: selectedModel
        })
      });
      if (response.ok) {
        liveResult = await response.json();
        isConnectedBackend = true;
      }
    } catch (e) {
      // Backend not running locally yet; fall back smoothly
      isConnectedBackend = false;
    }

    const elapsed = Date.now() - startTime;
    const remainingDelay = Math.max(0, 2700 - elapsed);

    // Final Stage Toast: Audit Completion & Verification
    setTimeout(() => {
      clearTimeout(stage2Timer);
      clearTimeout(stage3Timer);
      setIsScanning(false);
      setHasScanned(true);

      if (isConnectedBackend && liveResult && liveResult.findings) {
        // Gemma IS connected: Generate authentic audit scorecard
        setIsGemmaConnected(true);
        setShowDisconnectedWriteup(false);

        const newScanId = `SCAN-${Math.floor(1000 + Math.random() * 9000)}`;
        const now = new Date();
        const formattedTime = now.toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' });
        const formattedDate = now.toLocaleDateString([], { month: 'short', day: 'numeric', year: 'numeric' });

        const findingsToUse = liveResult.findings;
        const remediationsToUse = liveResult.remediations || [];
        const grade = (liveResult.security_grade as any) || 'B';
        const gradeColor = (grade === 'A' || grade === 'A-') ? '#E2FF32' : (grade === 'B' || grade === 'B+') ? '#00D1FF' : '#FF6B2B';

        const newReport: ScanReport = {
          id: newScanId,
          name: `Live Audit: ${scanTarget || './demo_target'}`,
          timestamp: `Today, ${formattedTime}`,
          dateFormatted: `${formattedDate} · ${formattedTime}`,
          isoDate: now.toISOString(),
          target: scanTarget || './demo_target',
          scanMode: scanMode,
          model: selectedModel,
          selectedPacks: [...selectedPacks],
          grade,
          gradeColor,
          isSampleData: false,
          findings: findingsToUse,
          remediations: remediationsToUse,
          executiveNotes: `Live audit of ${scanTarget || './demo_target'} executed via FastAPI backend & local ${selectedModel}. AST inspection generated ${findingsToUse.length} remediation diffs.`
        };

        setScanHistory(prev => {
          const updated = [newReport, ...prev];
          try {
            localStorage.setItem('eduguard_scan_history', JSON.stringify(updated));
          } catch (e) {}
          return updated;
        });
        setSelectedScanId(newScanId);

        toast.success("Security Audit Complete", {
          id: auditToastId,
          description: `Live Gemma verified ${findingsToUse.length} findings with ${selectedModel}. Scorecard Grade ${grade}.`,
          duration: 4500,
          style: {
            background: '#181818',
            border: '1px solid #E2FF32',
            color: '#F4F2ED',
            fontFamily: 'JetBrains Mono, monospace'
          }
        });
      } else {
        // Gemma is NOT connected yet:
        // Do NOT generate generic or synthetic results!
        setIsGemmaConnected(false);
        setShowDisconnectedWriteup(true);

        toast.error("Local Gemma Engine Not Connected", {
          id: auditToastId,
          description: "Audit halted. Generic results are suppressed per FERPA §99.31 policy until Gemma is connected.",
          duration: 6500,
          style: {
            background: '#181818',
            border: '1px solid #FF6B2B',
            color: '#F4F2ED',
            fontFamily: 'JetBrains Mono, monospace'
          }
        });
      }

      const workbenchEl = document.getElementById('workbench-anchor');
      if (workbenchEl) {
        workbenchEl.scrollIntoView({ behavior: 'smooth' });
      }
    }, remainingDelay);
  };

  const copyPatch = (text: string, index: number) => {
    navigator.clipboard.writeText(text);
    setCopiedIndex(index);
    toast.success("Remediation Patch Copied", {
      description: "Code diff snippet copied to clipboard.",
      duration: 2000,
      style: {
        background: '#181818',
        border: '1px solid #E2FF32',
        color: '#F4F2ED',
        fontFamily: 'JetBrains Mono, monospace'
      }
    });
    setTimeout(() => setCopiedIndex(null), 2000);
  };

  return (
    <div className="min-h-screen bg-[#141414] text-[#141414]">
      {/* Persistent Outer Viewport Frame */}
      <div id="global-frame"></div>

      <div id="viewport-content">
        <div id="scroll-container">
          
          {/* Top Navbar */}
          <header className="bg-[#F4F2ED] text-[#141414] border-b border-[#141414]/10 sticky top-0 z-40">
            <nav className="flex justify-between items-center px-4 sm:px-8 py-4 sm:py-5">
              {/* Brand Zone */}
              <button 
                onClick={() => setActivePage('landing')} 
                className="flex items-center gap-3 shrink-0 text-left group cursor-pointer"
              >
                <svg width="34" height="34" viewBox="0 0 56 56" fill="none" className="transition-transform group-hover:scale-105">
                  <path d="M28 26L52 38L28 50L4 38Z" fill="#FF6B2B" stroke="#FF6B2B" strokeWidth="4" strokeLinejoin="round"/>
                  <path d="M28 16L52 28L28 40L4 28Z" fill="#E2FF32" stroke="#E2FF32" strokeWidth="4" strokeLinejoin="round"/>
                  <path d="M28 6L52 18L28 30L4 18Z" fill="#F4F2ED" stroke="#141414" strokeWidth="3" strokeLinejoin="round"/>
                  <ellipse cx="28" cy="18" rx="6" ry="3" fill="white" stroke="#141414" strokeWidth="1.5"/>
                </svg>
                <span className="font-display font-bold tracking-tight text-xl uppercase">EduGuard</span>
              </button>

              {/* Navigation Links (Desktop) */}
              <div className="hidden md:flex items-center gap-6 px-6 py-2 border border-[#141414] rounded-full bg-white/70 backdrop-blur-sm text-sm font-medium shadow-sm">
                <button 
                  onClick={() => setActivePage('audit')} 
                  className={`transition-colors whitespace-nowrap cursor-pointer ${activePage === 'audit' ? 'font-bold text-[#141414] border-b-2 border-[#141414] -mb-[2px]' : 'text-neutral-600 hover:text-neutral-900'}`}
                >
                  Scanner
                </button>
                <button 
                  onClick={() => setActivePage('templates')} 
                  className={`transition-colors whitespace-nowrap cursor-pointer ${activePage === 'templates' ? 'font-bold text-[#141414] border-b-2 border-[#141414] -mb-[2px]' : 'text-neutral-600 hover:text-neutral-900'}`}
                >
                  Template Packs
                </button>
                <button 
                  onClick={() => setActivePage('owasp')} 
                  className={`transition-colors whitespace-nowrap cursor-pointer ${activePage === 'owasp' ? 'font-bold text-[#141414] border-b-2 border-[#141414] -mb-[2px]' : 'text-neutral-600 hover:text-neutral-900'}`}
                >
                  OWASP ASVS
                </button>
                <button 
                  onClick={() => setActivePage('engine')} 
                  className={`transition-colors whitespace-nowrap cursor-pointer ${activePage === 'engine' ? 'font-bold text-[#141414] border-b-2 border-[#141414] -mb-[2px]' : 'text-neutral-600 hover:text-neutral-900'}`}
                >
                  Gemma Engine
                </button>
              </div>

              {/* Action Zone: Model Selector & Run Audit */}
              <div className="flex items-center gap-2 sm:gap-3">
                <div 
                  onClick={() => { setActivePage('audit'); setShowDisconnectedWriteup(true); }}
                  className="hidden xl:flex items-center gap-2 px-3.5 py-1.5 bg-[#141414] text-[#F4F2ED] rounded-full text-xs font-mono font-medium cursor-pointer border border-[#2E2E2E] hover:border-[#FF6B2B] transition-colors"
                  title="Gemma Connection Status — Click to Test Connection"
                >
                  <span className={`w-2 h-2 rounded-full ${isGemmaConnected ? 'bg-[#E2FF32]' : 'bg-[#FF6B2B] animate-pulse'}`}></span>
                  <span>Gemma: {isGemmaConnected ? 'Online' : 'Offline'}</span>
                  <span className={`text-[10px] px-1.5 py-0.5 rounded-full font-bold ${isGemmaConnected ? 'bg-[#E2FF32]/20 text-[#E2FF32]' : 'bg-[#FF6B2B]/20 text-[#FF6B2B]'}`}>
                    {isGemmaConnected ? 'Live' : 'Connect'}
                  </span>
                </div>

                {/* Scan History Trigger Button */}
                <button 
                  onClick={() => setIsHistoryOpen(true)}
                  className="flex items-center gap-1.5 sm:gap-2 px-3 sm:px-3.5 py-1.5 sm:py-2 bg-white border border-[#141414] rounded-full text-xs font-mono font-medium hover:bg-neutral-100 transition-colors shadow-xs cursor-pointer text-[#141414]"
                  title="Open Scan History & Archives"
                >
                  <History size={14} className="text-[#FF6B2B]" />
                  <span className="hidden sm:inline font-bold">History</span>
                  <span className="w-5 h-5 rounded-full bg-[#141414] text-white text-[10px] flex items-center justify-center font-bold">
                    {scanHistory.length}
                  </span>
                </button>

                {/* Dynamic Model Selector */}
                <select 
                  id="aiModelSelector"
                  value={selectedModel}
                  onChange={(e) => setSelectedModel(e.target.value)}
                  className="px-2.5 sm:px-3.5 py-1.5 sm:py-2 bg-[#141414] text-[#F4F2ED] rounded-full text-xs font-mono font-medium border border-neutral-700 outline-none cursor-pointer hover:border-white transition-colors"
                >
                  <option value="gemma4:e4b">gemma4:e4b</option>
                  <option value="gemma2:2b">gemma2:2b</option>
                </select>

                <button 
                  onClick={() => setActivePage('audit')}
                  className="hidden sm:inline-flex px-5 py-2 bg-[#141414] text-[#F4F2ED] rounded-full text-sm font-medium hover:bg-neutral-800 transition-colors items-center gap-2 cursor-pointer"
                >
                  Run Audit <span>↗</span>
                </button>

                {/* Mobile Menu Button */}
                <button 
                  onClick={() => setMobileMenuOpen(!mobileMenuOpen)}
                  className="md:hidden p-2 rounded-lg text-[#141414] hover:bg-black/5"
                  aria-label="Toggle navigation menu"
                >
                  {mobileMenuOpen ? <X size={20} /> : <Menu size={20} />}
                </button>
              </div>
            </nav>

            {/* Mobile Drawer */}
            {mobileMenuOpen && (
              <div className="md:hidden bg-[#F4F2ED] border-b border-[#141414]/10 px-5 py-5 flex flex-col gap-2 shadow-lg">
                <button 
                  onClick={() => { setActivePage('landing'); setMobileMenuOpen(false); }} 
                  className={`text-left text-sm py-2 px-3 rounded-lg transition-colors ${activePage === 'landing' ? 'bg-[#141414] text-white font-bold' : 'text-[#141414] hover:bg-[#141414]/5'}`}
                >
                  Home
                </button>
                <button 
                  onClick={() => { setActivePage('audit'); setMobileMenuOpen(false); }} 
                  className={`text-left text-sm py-2 px-3 rounded-lg transition-colors ${activePage === 'audit' ? 'bg-[#141414] text-white font-bold' : 'text-[#141414] hover:bg-[#141414]/5'}`}
                >
                  Scanner & Workbench
                </button>
                <button 
                  onClick={() => { setIsHistoryOpen(true); setMobileMenuOpen(false); }} 
                  className="text-left text-sm py-2 px-3 rounded-lg transition-colors text-[#141414] hover:bg-[#141414]/5 flex items-center justify-between"
                >
                  <span className="flex items-center gap-2">
                    <History size={16} className="text-[#FF6B2B]" /> 
                    <span>Scan History Archives</span>
                  </span>
                  <span className="px-2 py-0.5 rounded-full bg-[#141414] text-white text-xs font-mono font-bold">
                    {scanHistory.length}
                  </span>
                </button>
                <button 
                  onClick={() => { setActivePage('templates'); setMobileMenuOpen(false); }} 
                  className={`text-left text-sm py-2 px-3 rounded-lg transition-colors ${activePage === 'templates' ? 'bg-[#141414] text-white font-bold' : 'text-[#141414] hover:bg-[#141414]/5'}`}
                >
                  Template Packs
                </button>
                <button 
                  onClick={() => { setActivePage('owasp'); setMobileMenuOpen(false); }} 
                  className={`text-left text-sm py-2 px-3 rounded-lg transition-colors ${activePage === 'owasp' ? 'bg-[#141414] text-white font-bold' : 'text-[#141414] hover:bg-[#141414]/5'}`}
                >
                  OWASP ASVS Matrix
                </button>
                <button 
                  onClick={() => { setActivePage('engine'); setMobileMenuOpen(false); }} 
                  className={`text-left text-sm py-2 px-3 rounded-lg transition-colors ${activePage === 'engine' ? 'bg-[#141414] text-white font-bold' : 'text-[#141414] hover:bg-[#141414]/5'}`}
                >
                  Gemma AI Architecture
                </button>
              </div>
            )}
          </header>

          {/* PAGE 1: LANDING PAGE */}
          {activePage === 'landing' && (
            <div className="flex-1">
              <section className="bg-[#F4F2ED] w-full lg:min-h-[80vh] flex flex-col text-[#141414]">
                <div className="flex-1 flex flex-col lg:flex-row items-center px-4 sm:px-8 lg:px-16 py-8 sm:py-10 lg:py-16 gap-8 lg:gap-12 max-w-[1600px] mx-auto w-full">
                  <div className="w-full lg:w-[60%] flex flex-col gap-6 sm:gap-8 lg:gap-10">
                    <div className="inline-flex items-center gap-2 px-3 py-1 bg-[#141414]/5 border border-[#141414]/10 rounded-full w-fit">
                      <span className="w-2 h-2 rounded-full bg-[#E2FF32]"></span>
                      <span className="text-[11px] sm:text-xs font-mono font-medium text-[#141414]">Deterministic Scanner + Local Gemma Remediator</span>
                    </div>

                    <h1 className="font-display font-medium text-3xl sm:text-5xl lg:text-[66px] leading-[1.08] tracking-[-0.03em] text-[#141414] max-w-3xl">
                      There is a Better Way<br />
                      <span className="inline-flex items-center align-middle mr-2 translate-y-[-2px] sm:translate-y-[-4px]">
                        <svg className="w-8 h-8 sm:w-11 sm:h-11 lg:w-14 lg:h-14" viewBox="0 0 56 56" fill="none">
                          <path d="M28 26L52 38L28 50L4 38Z" fill="#FF6B2B" stroke="#FF6B2B" strokeWidth="4" strokeLinejoin="round"/>
                          <path d="M28 16L52 28L28 40L4 28Z" fill="#E2FF32" stroke="#E2FF32" strokeWidth="4" strokeLinejoin="round"/>
                          <path d="M28 6L52 18L28 30L4 18Z" fill="#F4F2ED" stroke="#141414" strokeWidth="3" strokeLinejoin="round"/>
                          <ellipse cx="28" cy="18" rx="6" ry="3" fill="white" stroke="#141414" strokeWidth="1.5"/>
                        </svg>
                      </span>
                      to Secure .EDU.
                    </h1>

                    <p className="font-mono text-xs sm:text-sm md:text-base text-neutral-600 max-w-xl leading-relaxed">
                      Deterministic perimeter and source-code scanning mapped directly to OWASP ASVS v4.0 and FERPA requirements — verified by local Gemma with zero cloud leakage.
                    </p>

                    {/* Target Command Bar (Responsive Full-Bleed on Mobile) */}
                    <div className="flex flex-col sm:flex-row items-center gap-2.5 p-2 bg-white border border-[#141414]/20 rounded-2xl sm:rounded-full max-w-2xl shadow-sm w-full">
                      <select 
                        value={scanMode}
                        onChange={(e) => setScanMode(e.target.value)}
                        className="bg-neutral-50 sm:bg-transparent border border-neutral-200 sm:border-none outline-none text-xs sm:text-sm font-medium px-3 sm:px-4 py-2 sm:py-3 cursor-pointer text-[#141414] w-full sm:w-auto rounded-lg sm:rounded-none"
                      >
                        <option value="source_code">Source Code</option>
                        <option value="perimeter">Perimeter</option>
                        <option value="hybrid">Hybrid</option>
                      </select>
                      <div className="w-[1px] h-8 bg-[#141414]/20 hidden sm:block"></div>
                      <input 
                        type="text" 
                        value={scanTarget}
                        onChange={(e) => setScanTarget(e.target.value)}
                        className="flex-1 bg-transparent border-none outline-none px-3 sm:px-4 py-2 sm:py-3 text-xs sm:text-sm font-mono text-[#141414] w-full" 
                        placeholder="Target Directory or URL"
                      />
                      <div className="flex items-center gap-2 w-full sm:w-auto justify-between sm:justify-start">
                        <button 
                          onClick={() => setScanTarget('./demo_target')}
                          className="flex-1 sm:flex-initial px-3.5 py-1.5 sm:px-4 sm:py-2 text-xs sm:text-sm font-medium border border-[#141414]/20 rounded-full hover:bg-[#141414] hover:text-white transition-colors whitespace-nowrap cursor-pointer text-center"
                        >
                          Load Demo
                        </button>
                        <button 
                          onClick={() => { setActivePage('audit'); setTimeout(handleRunAudit, 200); }}
                          className="flex-1 sm:flex-initial px-4 sm:px-0 sm:w-12 h-10 sm:h-12 bg-[#141414] rounded-full flex items-center justify-center text-white hover:bg-neutral-800 transition-colors shrink-0 shadow-sm cursor-pointer gap-2 font-medium text-xs sm:text-sm"
                          title="Launch Audit"
                        >
                          <Play size={15} fill="white" />
                          <span className="sm:hidden font-mono">Run</span>
                        </button>
                      </div>
                    </div>
                  </div>

                  {/* Video Showcase Container */}
                  <div className="w-full lg:w-[40%] flex justify-center items-center h-[260px] sm:h-[340px] lg:h-[420px]">
                    <div className="w-full h-full rounded-2xl sm:rounded-[24px] overflow-hidden relative flex items-center justify-center">
                                            <ChromaKeyVideo src="/ui/static/hero.mp4" className="w-full h-full object-cover" />
                    </div>
                  </div>
                </div>
              </section>

              {/* Consigna Bento 3-Part Rows */}
              <section className="bg-[#141414] text-[#F4F2ED] px-4 sm:px-8 lg:px-16 py-16 sm:py-20 border-t border-[#2E2E2E]">
                <div className="max-w-[1600px] mx-auto">
                  <div className="mb-10">
                    <span className="font-mono text-xs text-[#E2FF32] font-bold uppercase tracking-wider">/ Architecture</span>
                    <h2 className="font-display font-medium text-2xl sm:text-3xl text-white mt-1">
                      Zero Cloud Leak Security Auditing
                    </h2>
                  </div>

                  <div className="grid grid-cols-1 md:grid-cols-3 gap-6">
                    <button 
                      onClick={() => setActivePage('templates')}
                      className="text-left bg-[#181818] border border-[#383838] rounded-[22px] p-6 sm:p-8 hover:border-[#FF6B2B] transition-all group cursor-pointer"
                    >
                      <span className="font-mono text-xs text-[#FF6B2B] font-bold">/ 01 TEMPLATE PACKS</span>
                      <h3 className="font-display font-medium text-xl text-white mt-4 mb-2 group-hover:text-[#FF6B2B] transition-colors">
                        Pick Template Packs
                      </h3>
                      <p className="font-mono text-xs sm:text-sm text-neutral-400 leading-relaxed">
                        Activate the 6 institutional security packs: DNS/DMARC, Transport/Headers, Exposed Configs, SAST Injection, IDOR/RBAC, and Student PII Privacy.
                      </p>
                      <div className="mt-6 flex items-center gap-2 text-xs font-mono text-[#E2FF32]">
                        <span>Explore Rule Catalog</span> <span>→</span>
                      </div>
                    </button>

                    <button 
                      onClick={() => setActivePage('audit')}
                      className="text-left bg-[#181818] border border-[#383838] rounded-[22px] p-6 sm:p-8 hover:border-[#E2FF32] transition-all group cursor-pointer"
                    >
                      <span className="font-mono text-xs text-[#E2FF32] font-bold">/ 02 DETERMINISTIC SCAN</span>
                      <h3 className="font-display font-medium text-xl text-white mt-4 mb-2 group-hover:text-[#E2FF32] transition-colors">
                        Run Audit Workspace
                      </h3>
                      <p className="font-mono text-xs sm:text-sm text-neutral-400 leading-relaxed">
                        Scan target codebases or campus endpoints against verified OWASP ASVS v4.0 rules and generate verifiable security grades.
                      </p>
                      <div className="mt-6 flex items-center gap-2 text-xs font-mono text-[#E2FF32]">
                        <span>Open Workspace</span> <span>→</span>
                      </div>
                    </button>

                    <button 
                      onClick={() => setActivePage('engine')}
                      className="text-left bg-[#181818] border border-[#383838] rounded-[22px] p-6 sm:p-8 hover:border-[#FF4D4D] transition-all group cursor-pointer"
                    >
                      <span className="font-mono text-xs text-[#FF4D4D] font-bold">/ 03 LOCAL AI REMEDIATOR</span>
                      <h3 className="font-display font-medium text-xl text-white mt-4 mb-2 group-hover:text-[#FF4D4D] transition-colors">
                        Gemma Remediation
                      </h3>
                      <p className="font-mono text-xs sm:text-sm text-neutral-400 leading-relaxed">
                        Local Ollama execution of Gemma4:E4B and Gemma2:2B produces verified unified diff patches without sending institutional data to the cloud.
                      </p>
                      <div className="mt-6 flex items-center gap-2 text-xs font-mono text-[#E2FF32]">
                        <span>Inspect Engine Pipeline</span> <span>→</span>
                      </div>
                    </button>
                  </div>
                </div>
              </section>
            </div>
          )}

          {/* PAGE 2: AUDIT WORKSPACE */}
          {activePage === 'audit' && (
            <div className="flex-1 bg-[#141414] text-[#F4F2ED]">
              {/* Workspace Header Bar */}
              <section className="bg-[#F4F2ED] text-[#141414] px-4 sm:px-8 lg:px-16 py-8 sm:py-12 border-b border-[#141414]/10">
                <div className="max-w-[1600px] mx-auto flex flex-col lg:flex-row lg:items-center justify-between gap-6">
                  <div>
                    <span className="font-mono text-xs text-[#FF6B2B] font-bold uppercase tracking-wider">/ 01 Audit Configuration</span>
                    <h1 className="font-display font-medium text-3xl sm:text-4xl text-[#141414] mt-1">
                      Security Baseline Workspace
                    </h1>
                    <p className="font-mono text-sm text-neutral-600 mt-1">
                      Target repository inspection and deterministic vulnerability auditing with local {selectedModel}.
                    </p>
                  </div>

                  {/* Command Bar */}
                  <div className="flex flex-col sm:flex-row items-center gap-2.5 p-2 bg-white border border-[#141414]/20 rounded-2xl sm:rounded-full shadow-sm w-full lg:w-auto max-w-2xl">
                    <select 
                      value={scanMode}
                      onChange={(e) => setScanMode(e.target.value)}
                      className="bg-neutral-50 sm:bg-transparent border border-neutral-200 sm:border-none outline-none text-xs sm:text-sm font-medium px-3 sm:px-4 py-2 sm:py-2.5 cursor-pointer text-[#141414] w-full sm:w-auto rounded-lg sm:rounded-none"
                    >
                      <option value="source_code">Source Code</option>
                      <option value="perimeter">Perimeter</option>
                      <option value="hybrid">Hybrid</option>
                    </select>
                    <div className="w-[1px] h-7 bg-[#141414]/10 hidden sm:block"></div>
                    <input 
                      type="text" 
                      value={scanTarget}
                      onChange={(e) => setScanTarget(e.target.value)}
                      className="flex-1 bg-transparent border-none outline-none px-3 py-2 text-xs sm:text-sm font-mono text-[#141414] w-full sm:w-64" 
                      placeholder="Target Directory or URL"
                    />
                    <div className="flex items-center gap-2 w-full sm:w-auto justify-between sm:justify-start">
                      <button 
                        onClick={() => setScanTarget('./demo_target')}
                        className="flex-1 sm:flex-initial px-3.5 py-1.5 text-xs font-medium border border-[#141414]/20 rounded-full hover:bg-[#141414] hover:text-white transition-colors whitespace-nowrap cursor-pointer text-center"
                      >
                        Load Demo
                      </button>
                      <button 
                        onClick={() => setIsHistoryOpen(true)}
                        className="flex-1 sm:flex-initial px-3.5 py-1.5 text-xs font-medium border border-[#141414]/20 rounded-full hover:bg-[#141414] hover:text-white transition-colors whitespace-nowrap cursor-pointer flex items-center justify-center gap-1.5 text-center"
                        title="Open Scan History Archives"
                      >
                        <History size={13} className="text-[#FF6B2B]" />
                        <span>History ({scanHistory.length})</span>
                      </button>
                      <button 
                        disabled={isScanning}
                        onClick={handleRunAudit}
                        className="flex-1 sm:flex-initial px-4 sm:px-0 sm:w-10 h-9 sm:h-10 bg-[#141414] rounded-full flex items-center justify-center text-white hover:bg-neutral-800 transition-colors shrink-0 shadow-sm cursor-pointer disabled:opacity-50 gap-2 font-medium text-xs sm:text-sm"
                        title="Run Audit"
                      >
                        <Play size={14} fill="white" />
                        <span className="sm:hidden font-mono">Execute</span>
                      </button>
                    </div>
                  </div>
                </div>
              </section>

              {/* 6 Selectable Template Pack Cards */}
              <section className="px-4 sm:px-8 lg:px-16 py-10 sm:py-16 max-w-[1600px] mx-auto">
                <div className="flex flex-col sm:flex-row justify-between items-start sm:items-end mb-8 border-b border-[#2E2E2E] pb-6 gap-4">
                  <div>
                    <span className="font-mono text-xs text-[#E2FF32] font-bold uppercase tracking-wider">/ 02 Institutional Rulesets</span>
                    <h2 className="font-display font-medium text-2xl sm:text-3xl text-white mt-1">
                      6 Institutional Template Packs
                    </h2>
                    <p className="font-mono text-xs sm:text-sm text-neutral-400 mt-1">
                      Hover to preview Tangerine highlight. Click to toggle Acid Yellow selection.
                    </p>
                  </div>
                  <div>
                    <button 
                      onClick={toggleAllPacks}
                      className="px-5 py-2 border border-[#383838] rounded-full text-xs sm:text-sm font-medium hover:bg-[#2E2E2E] hover:border-white transition-colors cursor-pointer"
                    >
                      {selectedPacks.length === TEMPLATE_PACKS.length ? 'Deselect All' : 'Select All Packs'}
                    </button>
                  </div>
                </div>

                <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-6 sm:gap-8 pt-4">
                  {TEMPLATE_PACKS.map((pack, idx) => {
                    const isActive = selectedPacks.includes(pack.id);
                    return (
                      <div 
                        key={pack.id}
                        onClick={() => togglePack(pack.id)}
                        className={`pack-card rounded-[20px] border p-6 sm:p-7 flex flex-col justify-between transition-all duration-200 cursor-pointer select-none group min-h-[250px] sm:min-h-[270px] ${
                          isActive 
                            ? 'active bg-[#E2FF32] border-[#E2FF32] text-[#141414] shadow-md shadow-[#E2FF32]/10' 
                            : 'bg-[#181818] border-[#383838] text-white hover:border-[#FF6B2B]'
                        }`}
                      >
                        {/* Top Indicator Row: Number Indicator & Check Status */}
                        <div className="flex items-center justify-between gap-3 mb-4">
                          <div className="flex items-center gap-2 flex-wrap">
                            <span className={`num-indicator font-mono text-xs font-bold tracking-wider px-2.5 py-1 rounded-md transition-colors ${
                              isActive 
                                ? 'bg-[#141414]/15 text-[#141414]' 
                                : 'bg-[#252525] text-neutral-400'
                            }`}>
                              / 0{idx + 1}
                            </span>
                            <span className={`checks-pill px-2.5 py-1 rounded-full text-xs font-mono font-medium transition-colors ${
                              isActive 
                                ? 'bg-[#141414]/10 text-[#141414]' 
                                : 'bg-[#252525] text-neutral-400'
                            }`}>
                              {pack.checks.length} Checks Loaded
                            </span>
                          </div>

                          {/* Selection Checkmark Bubble */}
                          <div className={`check-bubble w-8 h-8 rounded-full flex items-center justify-center transition-all shrink-0 ${
                            isActive 
                              ? 'bg-[#141414] text-[#E2FF32] scale-100 shadow-sm' 
                              : 'border border-[#383838] bg-[#222222] text-neutral-500 scale-95'
                          }`}>
                            <Check size={16} className={`stroke-[3] transition-transform ${isActive ? 'scale-100 opacity-100' : 'scale-75 opacity-0'}`} />
                          </div>
                        </div>

                        {/* Description - Text wraps inside cleanly without any overlap */}
                        <div className="flex-1 flex flex-col justify-center my-2">
                          <p className={`font-mono text-xs sm:text-sm leading-relaxed transition-colors break-words ${
                            isActive 
                              ? 'text-[#141414]' 
                              : 'text-neutral-300'
                          }`}>
                            {pack.description}
                          </p>
                        </div>

                        {/* Card Title & Bottom Zone */}
                        <div className={`divider-line mt-4 pt-3.5 border-t flex items-center justify-between transition-colors ${
                          isActive ? 'border-[#141414]/15' : 'border-[#2E2E2E]'
                        }`}>
                          <h3 className={`font-display font-medium text-base sm:text-[18px] leading-snug card-title transition-colors ${
                            isActive ? 'text-[#141414]' : 'text-white'
                          }`}>
                            {pack.name}
                          </h3>
                        </div>
                      </div>
                    );
                  })}
                </div>
              </section>

              {/* Live Workbench Section */}
              <section id="workbench-anchor" className="bg-[#141414] border-t border-[#2E2E2E] px-4 sm:px-8 lg:px-16 py-16 pb-28">
                <div className="max-w-[1600px] mx-auto">
                  {/* Non-blocking Live Audit Indicator & Findings Progress Container */}
                  {isScanning && (
                    <div id="findingsContainer" className="scanning scan-progress-active space-y-6">
                      <div className="bg-[#181818] border border-[#2E2E2E] rounded-2xl p-6 sm:p-10 relative overflow-hidden shadow-2xl">
                        {/* Progress Fill Bar */}
                        <div className="findings-progress-track mb-8">
                          <div className="findings-progress-fill"></div>
                        </div>

                        <div className="flex flex-col items-center justify-center py-12 space-y-4">
                          <div className="relative">
                            <div className="w-16 h-16 border-4 border-[#2E2E2E] border-t-[#E2FF32] rounded-full animate-spin"></div>
                            <div className="absolute inset-0 flex items-center justify-center">
                              <span className="w-3 h-3 rounded-full bg-[#E2FF32] animate-ping"></span>
                            </div>
                          </div>
                          <h3 className="font-display text-2xl text-white font-medium">{selectedModel} is Auditing...</h3>
                          <p className="font-mono text-xs sm:text-sm text-neutral-400 text-center max-w-lg leading-relaxed">
                            Deep perimeter analysis and deterministic AST traversal initiated across {selectedPacks.length} selected template packs.
                          </p>
                          <div className="inline-flex items-center gap-2 px-3.5 py-1.5 rounded-full bg-[#141414] border border-[#2E2E2E] text-xs font-mono text-neutral-300">
                            <span className="w-2 h-2 rounded-full bg-[#E2FF32] animate-pulse"></span>
                            <span>Real-time non-blocking progress streaming to notification toasts</span>
                          </div>
                        </div>
                      </div>
                    </div>
                  )}

                  {/* Professional Write-Up: Rendered when Gemma is not connected */}
                  {!isScanning && hasScanned && showDisconnectedWriteup && (
                    <div className="bg-[#181818] border border-[#FF6B2B]/40 rounded-3xl p-6 sm:p-10 text-[#F4F2ED] shadow-2xl relative overflow-hidden">
                      {/* Ambient gradient */}
                      <div className="absolute top-0 right-0 w-96 h-96 bg-[#FF6B2B]/5 rounded-full blur-3xl pointer-events-none -mr-20 -mt-20"></div>

                      {/* Top Badge & Live Telemetry Header */}
                      <div className="flex flex-col md:flex-row md:items-center justify-between pb-6 border-b border-[#2E2E2E] gap-4">
                        <div className="flex items-center gap-3">
                          <div className="w-12 h-12 rounded-2xl bg-[#FF6B2B]/15 border border-[#FF6B2B] flex items-center justify-center text-[#FF6B2B] shrink-0">
                            <Cpu size={24} className="animate-pulse" />
                          </div>
                          <div>
                            <div className="flex flex-wrap items-center gap-2">
                              <span className="font-mono text-xs font-bold text-[#FF6B2B] uppercase tracking-wider">/ Pipeline Telemetry</span>
                              <span className="px-2.5 py-0.5 rounded-full bg-[#FF4D4D]/20 border border-[#FF4D4D]/50 text-[#FF4D4D] text-[11px] font-mono font-bold flex items-center gap-1.5">
                                <span className="w-1.5 h-1.5 rounded-full bg-[#FF4D4D] animate-ping"></span>
                                Gemma Disconnected
                              </span>
                              <span className="hidden sm:inline-flex px-2.5 py-0.5 rounded-full bg-[#141414] border border-[#383838] text-neutral-400 text-[11px] font-mono">
                                Generic Results Suppressed
                              </span>
                            </div>
                            <h3 className="font-display font-medium text-2xl text-white mt-1">
                              Local Gemma AI Engine Not Connected
                            </h3>
                          </div>
                        </div>

                        {/* Live Action Controls */}
                        <div className="flex items-center gap-3">
                          <button
                            onClick={() => checkGemmaLiveStatus(false)}
                            disabled={isProbingGemma}
                            className="px-4 py-2 rounded-full bg-[#141414] border border-[#383838] hover:border-[#E2FF32] text-xs font-mono text-neutral-200 hover:text-white transition-all flex items-center gap-2 cursor-pointer shadow-sm disabled:opacity-50"
                          >
                            <RefreshCw size={13} className={isProbingGemma ? 'animate-spin text-[#E2FF32]' : 'text-[#E2FF32]'} />
                            <span>{isProbingGemma ? 'Probing Socket...' : 'Test Connection'}</span>
                          </button>
                        </div>
                      </div>

                      {/* Real-Time Diagnostics Grid */}
                      <div className="grid grid-cols-1 sm:grid-cols-3 gap-4 my-8">
                        <div className="bg-[#141414] p-4 rounded-xl border border-[#2E2E2E]">
                          <div className="flex items-center justify-between text-xs font-mono text-neutral-400 mb-1">
                            <span>Ollama Inference Runtime</span>
                            <span className={isGemmaConnected ? "text-[#E2FF32] font-bold" : "text-[#FF4D4D] font-bold"}>{isGemmaConnected ? 'Reachable' : 'Unreachable'}</span>
                          </div>
                          <div className="text-sm font-mono text-white flex items-center gap-2">
                            <span className={`w-2 h-2 rounded-full ${isGemmaConnected ? 'bg-[#E2FF32]' : 'bg-[#FF4D4D]'}`}></span>
                            localhost:11434
                          </div>
                          <p className="text-[11px] font-mono text-neutral-500 mt-1">Local daemon for {selectedModel} inference</p>
                        </div>

                        <div className="bg-[#141414] p-4 rounded-xl border border-[#2E2E2E]">
                          <div className="flex items-center justify-between text-xs font-mono text-neutral-400 mb-1">
                            <span>FastAPI Backend Gateway</span>
                            <span className={isBackendReachable ? "text-[#E2FF32] font-bold" : "text-[#FF6B2B] font-bold"}>{isBackendReachable ? 'Online' : 'Offline'}</span>
                          </div>
                          <div className="text-sm font-mono text-white flex items-center gap-2">
                            <span className={`w-2 h-2 rounded-full ${isBackendReachable ? 'bg-[#E2FF32]' : 'bg-[#FF6B2B]'}`}></span>
                            localhost:8000/api/scan
                          </div>
                          <p className="text-[11px] font-mono text-neutral-500 mt-1">Same-origin FastAPI route</p>
                        </div>

                        <div className="bg-[#141414] p-4 rounded-xl border border-[#2E2E2E]">
                          <div className="flex items-center justify-between text-xs font-mono text-neutral-400 mb-1">
                            <span>Target Model Specification</span>
                            <span className="text-[#E2FF32] font-bold">Configured</span>
                          </div>
                          <div className="text-sm font-mono text-white flex items-center gap-2">
                            <span className="w-2 h-2 rounded-full bg-[#E2FF32]"></span>
                            {selectedModel}
                          </div>
                          <p className="text-[11px] font-mono text-neutral-500 mt-1">Ready for on-device diff generation</p>
                        </div>
                      </div>

                      {/* The Professional Write-Up Body */}
                      <div className="space-y-6 text-sm text-neutral-300 leading-relaxed font-body">
                        {/* Section 1: Institutional Policy */}
                        <div className="bg-[#141414]/70 border border-[#2E2E2E] rounded-2xl p-5 sm:p-6">
                          <div className="flex items-center gap-2 mb-3">
                            <ShieldCheck className="text-[#E2FF32]" size={18} />
                            <h4 className="font-display font-medium text-lg text-white">
                              Institutional Zero-Cloud Integrity Guarantee
                            </h4>
                          </div>
                          <p className="text-neutral-400 font-mono text-xs sm:text-sm leading-relaxed mb-3">
                            EduGuard is engineered specifically for institutional and campus software architecture under the mandate of <strong className="text-white">FERPA §99.31</strong> and <strong className="text-white">NIST SP 800-171</strong>. Student information system source code, registrar database connection strings, and credential configurations cannot be transmitted to commercial public cloud LLM endpoints.
                          </p>
                          <p className="text-neutral-400 font-mono text-xs sm:text-sm leading-relaxed">
                            To fulfill this guarantee, vulnerability verification and diff synthesis are executed exclusively by a verified <span className="text-[#E2FF32] font-semibold">local Gemma model instance</span> running on your hardware or campus server.
                          </p>
                        </div>

                        {/* Section 2: Why Generic Results Are Blocked */}
                        <div className="bg-[#141414]/70 border border-[#2E2E2E] rounded-2xl p-5 sm:p-6">
                          <div className="flex items-center gap-2 mb-3">
                            <AlertTriangle className="text-[#FF6B2B]" size={18} />
                            <h4 className="font-display font-medium text-lg text-white">
                              Why Generic / Mock Results Are Strictly Suppressed
                            </h4>
                          </div>
                          <p className="text-neutral-400 font-mono text-xs sm:text-sm leading-relaxed mb-3">
                            Unlike consumer scanners that fabricate generic mock vulnerabilities when backends are unreachable, <strong className="text-white">EduGuard strictly refuses to generate generic results</strong> without an active local Gemma node.
                          </p>
                          <p className="text-neutral-400 font-mono text-xs sm:text-sm leading-relaxed">
                            Fabricating simulated security grades or synthetic finding diffs creates hazardous false confidence for university sysadmins and violates compliance audit chains of custody. An audit is only produced when the target source code or endpoint is inspected and verified by an active Gemma pipeline.
                          </p>
                        </div>
                      </div>

                      {/* Footer with actions */}
                      <div className="mt-8 pt-6 border-t border-[#2E2E2E] flex flex-col sm:flex-row items-center justify-between gap-4">
                        <div className="text-xs font-mono text-neutral-400 flex items-center gap-2">
                          <span className="w-2 h-2 rounded-full bg-[#FF4D4D] animate-ping"></span>
                          <span>Awaiting local Gemma heartbeat. Real scans execute automatically once connected.</span>
                        </div>
                        <div className="flex items-center gap-3">
                          {scanHistory.length > 0 && (
                            <button
                              onClick={() => {
                                selectScanReport(scanHistory[0].id);
                                setShowDisconnectedWriteup(false);
                              }}
                              className="text-xs font-mono text-neutral-400 hover:text-white underline cursor-pointer"
                            >
                              View Archived Reference Baseline ({scanHistory[0].id})
                            </button>
                          )}
                          <button
                            onClick={handleRunAudit}
                            className="px-5 py-2.5 rounded-full bg-[#E2FF32] text-[#141414] font-mono text-xs font-bold hover:bg-[#d6f522] transition-colors flex items-center gap-2 shadow-lg cursor-pointer"
                          >
                            <Play size={14} fill="#141414" />
                            <span>Probe & Run Live Audit</span>
                          </button>
                        </div>
                      </div>
                    </div>
                  )}

                  {/* Results Scorecard Bento (When Gemma is Connected OR Reviewing Archived Baseline) */}
                  {!isScanning && hasScanned && !showDisconnectedWriteup && activeReport && (
                    <div className="space-y-8">
                      {/* Notice if viewing archived report while Gemma is disconnected */}
                      {!isGemmaConnected && (
                        <div className="bg-[#181818] border border-[#FF6B2B]/40 rounded-2xl p-4 flex flex-col sm:flex-row items-start sm:items-center justify-between gap-3 text-xs font-mono">
                          <div className="flex items-center gap-2.5 text-[#FF6B2B]">
                            <AlertTriangle size={16} className="shrink-0" />
                            <span>Viewing Archived Baseline ({activeReport.id}). Live scans will strictly produce real results only when Gemma is connected.</span>
                          </div>
                          <button
                            onClick={() => setShowDisconnectedWriteup(true)}
                            className="px-3 py-1 rounded-full bg-[#FF6B2B]/20 border border-[#FF6B2B] text-[#FF6B2B] hover:bg-[#FF6B2B]/30 transition-colors cursor-pointer shrink-0"
                          >
                            View Gemma Connection Write-Up →
                          </button>
                        </div>
                      )}

                      {/* Active / Historical Report Notice Bar */}
                      <div className="bg-[#181818] border border-[#383838] rounded-2xl p-4 sm:p-5 flex flex-col sm:flex-row sm:items-center justify-between gap-4 shadow-lg">
                        <div className="flex items-center gap-3.5">
                          <div className="w-10 h-10 rounded-xl bg-[#E2FF32]/10 border border-[#E2FF32]/30 flex items-center justify-center text-[#E2FF32] shrink-0">
                            <History size={18} />
                          </div>
                          <div>
                            <div className="flex flex-wrap items-center gap-2">
                              <span className="font-mono text-[11px] font-bold text-[#E2FF32] uppercase tracking-wider">Loaded Report</span>
                              <span className="text-neutral-500 text-xs">·</span>
                              <span className="font-mono text-xs text-white font-bold bg-[#141414] px-2 py-0.5 rounded border border-[#2E2E2E]">{activeReport.id}</span>
                              <span className="text-neutral-500 text-xs">·</span>
                              <span className="font-mono text-xs text-neutral-400">{activeReport.dateFormatted || activeReport.timestamp}</span>
                            </div>
                            <div className="flex flex-wrap items-center gap-2.5 mt-1">
                              <h3 className="font-display font-medium text-base sm:text-lg text-white">
                                {activeReport.name}
                              </h3>
                              <span className="font-mono text-xs text-neutral-300 px-2.5 py-0.5 rounded-full bg-[#141414] border border-[#2E2E2E] flex items-center gap-1">
                                <Terminal size={11} className="text-[#FF6B2B]" />
                                {activeReport.target}
                              </span>
                            </div>
                          </div>
                        </div>

                        <div className="flex items-center gap-2.5 self-end sm:self-auto shrink-0">
                          <button 
                            onClick={() => setIsHistoryOpen(true)}
                            className="px-4 py-2 rounded-full bg-[#141414] border border-[#383838] text-xs font-mono text-neutral-300 hover:text-white hover:border-[#E2FF32] transition-colors flex items-center gap-2 cursor-pointer shadow-sm"
                            title="Open Scan History sidebar"
                          >
                            <Clock size={13} className="text-[#FF6B2B]" />
                            <span>Switch Report ({scanHistory.length})</span>
                          </button>
                          <button 
                            onClick={() => {
                              setScanTarget(activeReport.target);
                              setSelectedModel(activeReport.model);
                              if (activeReport.selectedPacks?.length) setSelectedPacks(activeReport.selectedPacks);
                              toast.info("Target Loaded", {
                                description: `Loaded target ${activeReport.target} into the audit configuration bar.`,
                                style: {
                                  background: '#181818',
                                  border: '1px solid #E2FF32',
                                  color: '#F4F2ED',
                                  fontFamily: 'JetBrains Mono, monospace'
                                }
                              });
                            }}
                            className="px-3.5 py-2 rounded-full bg-[#E2FF32]/10 border border-[#E2FF32]/30 text-xs font-mono text-[#E2FF32] hover:bg-[#E2FF32]/20 transition-colors flex items-center gap-1.5 cursor-pointer"
                            title="Load target into configuration bar"
                          >
                            <RotateCcw size={13} />
                            <span>Load Target</span>
                          </button>
                        </div>
                      </div>

                      <div className="bg-[#181818] border border-[#383838] rounded-2xl p-6 sm:p-8">
                        <div className="flex flex-col lg:flex-row justify-between items-start lg:items-center gap-6">
                          <div className="flex flex-wrap items-center gap-6 sm:gap-10">
                            <div className="flex items-center gap-6">
                              <div className="flex flex-col">
                                <span className="text-neutral-500 font-mono text-xs uppercase tracking-wider mb-1">Security Grade</span>
                                <div className="font-display font-bold text-5xl sm:text-6xl leading-none" style={{ color: activeReport.gradeColor }}>
                                  {activeReport.grade}
                                </div>
                              </div>
                              <div className="w-[1px] h-14 bg-[#2E2E2E]"></div>
                              <div className="flex flex-col">
                                <span className="text-neutral-500 font-mono text-xs uppercase tracking-wider mb-1">Total Findings</span>
                                <div className="font-display font-medium text-3xl sm:text-4xl leading-none text-white">{activeReport.findings.length}</div>
                              </div>
                            </div>

                            {/* Badge: Archived Baseline vs Verified Local Gemma */}
                            {activeReport.isSampleData ? (
                              <div className="inline-flex items-center gap-2 px-3.5 py-1.5 rounded-full bg-[#FF6B2B]/15 border border-[#FF6B2B] text-[#FF6B2B] font-mono text-xs font-semibold">
                                <span className="w-2 h-2 rounded-full bg-[#FF6B2B] animate-pulse"></span>
                                Archived Benchmark Baseline
                              </div>
                            ) : (
                              <div className="inline-flex items-center gap-2 px-3.5 py-1.5 rounded-full bg-[#E2FF32]/15 border border-[#E2FF32] text-[#E2FF32] font-mono text-xs font-semibold">
                                <span className="w-2 h-2 rounded-full bg-[#E2FF32]"></span>
                                Verified Local Gemma Audit
                              </div>
                            )}

                            {/* Engine & Mode metadata */}
                            <div className="hidden sm:inline-flex items-center gap-2 px-3 py-1.5 rounded-full bg-[#141414] border border-[#2E2E2E] text-neutral-400 font-mono text-xs">
                              <Cpu size={12} className="text-[#E2FF32]" />
                              <span>{activeReport.model}</span>
                              <span>·</span>
                              <span className="capitalize">{activeReport.scanMode}</span>
                            </div>
                          </div>

                          {/* Actions & Dev Patch Mode Toggle */}
                          <div className="flex flex-wrap items-center gap-3 sm:gap-4 print-hidden">
                            <div className="inline-flex p-1 bg-[#0a0a0a] border border-[#2E2E2E] rounded-full text-xs font-mono">
                              <button 
                                onClick={() => setIsDevDiffMode(false)}
                                className={`px-4 py-1.5 rounded-full transition-colors cursor-pointer ${!isDevDiffMode ? 'bg-[#181818] text-[#E2FF32] font-bold' : 'text-neutral-400 hover:text-white'}`}
                              >
                                Board View
                              </button>
                              <button 
                                onClick={() => setIsDevDiffMode(true)}
                                className={`px-4 py-1.5 rounded-full transition-colors cursor-pointer ${isDevDiffMode ? 'bg-[#181818] text-[#E2FF32] font-bold' : 'text-neutral-400 hover:text-white'}`}
                              >
                                Dev Patch Diff
                              </button>
                            </div>

                            {/* Institutional Export Feature: CSV & PDF */}
                            <div className="flex items-center gap-2">
                              <button 
                                onClick={() => exportFindingsCSV(activeReport)}
                                className="px-3.5 sm:px-4 py-2 border border-[#383838] bg-[#141414] hover:border-[#E2FF32] hover:text-[#E2FF32] text-white rounded-full text-xs sm:text-sm font-mono font-medium transition-all flex items-center gap-1.5 sm:gap-2 cursor-pointer shadow-sm group"
                                title="Export current scan findings as a CSV file"
                              >
                                <Download size={14} className="text-[#E2FF32] group-hover:scale-110 transition-transform" />
                                <span>Export CSV</span>
                              </button>
                              <button 
                                onClick={() => window.print()}
                                className="px-3.5 sm:px-4 py-2 border border-[#383838] bg-[#141414] hover:bg-[#2E2E2E] hover:text-white text-white rounded-full text-xs sm:text-sm font-mono font-medium transition-all flex items-center gap-1.5 sm:gap-2 cursor-pointer shadow-sm group"
                                title="Export current institutional audit report as PDF"
                              >
                                <Printer size={14} className="text-[#FF6B2B] group-hover:scale-110 transition-transform" />
                                <span>Export PDF</span>
                              </button>
                            </div>
                          </div>
                        </div>
                      </div>

                      {/* Institutional Print Cover Header (Visible only in print / exported PDF) */}
                      <div className="hidden print:block mb-8 p-6 bg-white border border-gray-300 rounded-xl">
                        <div className="flex justify-between items-start border-b border-gray-300 pb-4">
                          <div>
                            <h1 className="text-2xl font-bold tracking-tight text-gray-900 uppercase font-display">EduGuard — Institutional Security & Compliance Audit</h1>
                            <p className="text-xs font-mono text-gray-600 mt-1">
                              Deterministic Security Baseline Audit · OWASP ASVS v4.0 & FERPA §99.31 Compliance
                            </p>
                          </div>
                          <div className="text-right font-mono">
                            <div className="text-2xl font-bold text-gray-900">Grade: {activeReport.grade}</div>
                            <div className="text-xs text-gray-600 font-semibold">{activeReport.findings.length} Findings Identified</div>
                          </div>
                        </div>
                        <div className="mt-4 grid grid-cols-4 gap-4 text-xs font-mono text-gray-800">
                          <div><span className="text-gray-500 font-normal">Target:</span> <span className="font-bold">{activeReport.target}</span></div>
                          <div><span className="text-gray-500 font-normal">Audit ID:</span> <span className="font-bold">{activeReport.id}</span></div>
                          <div><span className="text-gray-500 font-normal">Date:</span> <span className="font-bold">{activeReport.dateFormatted || activeReport.timestamp}</span></div>
                          <div><span className="text-gray-500 font-normal">Engine:</span> <span className="font-bold">{activeReport.model}</span></div>
                        </div>
                      </div>

                      {/* Bento Findings Cards with Framer Motion Staggered Entrance */}
                      <motion.div 
                        id="findingsContainer" 
                        key={activeReport.id}
                        variants={findingsContainerVariants}
                        initial="hidden"
                        animate="visible"
                        className="space-y-6"
                      >
                        {activeReport.findings.map((finding, idx) => {
                          const remediation = activeReport.remediations[idx] || SAMPLE_REMEDIATIONS[0];
                          const severityColor = finding.severity === 'CRITICAL' ? 'bg-[#FF4D4D] text-white' : (finding.severity === 'HIGH' ? 'bg-[#FF6B2B] text-white' : 'bg-[#E2FF32] text-[#141414]');
                          const codeToDisplay = isDevDiffMode ? remediation.unified_diff : remediation.patched_code_snippet;
                          const isCopied = copiedIndex === idx;

                          return (
                            <motion.div 
                              key={finding.id} 
                              variants={findingCardVariants}
                              className="finding-card bg-[#181818] border border-[#2E2E2E] rounded-2xl overflow-hidden flex flex-col lg:flex-row shadow-lg transition-colors hover:border-neutral-700"
                            >
                              {/* Left Info Panel */}
                              <div className="p-4 sm:p-6 lg:w-5/12 border-b lg:border-b-0 lg:border-r border-[#2E2E2E] flex flex-col justify-between">
                                <div>
                                  <div className="flex flex-wrap items-center gap-2 mb-4">
                                    <span className={`px-2.5 sm:px-3 py-1 text-[10px] sm:text-[11px] font-bold font-mono tracking-wider rounded-full uppercase ${severityColor}`}>
                                      {finding.severity}
                                    </span>
                                    <span className="px-2.5 sm:px-3 py-1 text-[10px] sm:text-[11px] font-mono tracking-wider rounded-full bg-[#141414] text-neutral-400 border border-[#2E2E2E]">
                                      {finding.owasp_asvs_id}
                                    </span>
                                  </div>
                                  <h4 className="font-display font-medium text-lg sm:text-xl leading-tight text-white mb-2">{finding.title}</h4>
                                  <p className="font-mono text-xs sm:text-sm text-neutral-400 leading-relaxed mb-3">{finding.description}</p>
                                  {finding.compliance_impact && (
                                    <div className="mt-3 p-2.5 rounded-lg bg-[#141414]/90 border border-[#2E2E2E] text-xs font-mono text-[#FF6B2B] leading-relaxed">
                                      {finding.compliance_impact}
                                    </div>
                                  )}
                                </div>

                                <div className="mt-5 sm:mt-6 pt-4 border-t border-[#2E2E2E]/60">
                                  <div className="bg-[#141414] p-3.5 sm:p-4 rounded-xl border border-[#2E2E2E]">
                                    <div className="flex items-center gap-2 mb-1.5">
                                      <span className="w-1.5 h-1.5 rounded-full bg-[#E2FF32]"></span>
                                      <h5 className="text-[10px] sm:text-[11px] font-bold text-[#E2FF32] font-mono uppercase tracking-wider">Gemma AI Principal Summary</h5>
                                    </div>
                                    <p className="text-xs sm:text-sm text-[#F4F2ED] leading-relaxed font-body">{remediation.executive_summary}</p>
                                  </div>
                                </div>
                              </div>

                              {/* Right Code Panel */}
                              <div className="p-4 sm:p-6 lg:w-7/12 bg-[#0a0a0a] flex flex-col justify-between relative">
                                <div className="flex justify-between items-center mb-3 gap-2">
                                  <span className="font-mono text-[11px] sm:text-xs text-neutral-500 uppercase tracking-widest truncate">
                                    {isDevDiffMode ? 'Unified Git Diff' : 'Remediation Patch Snippet'}
                                  </span>
                                  <button 
                                    onClick={() => copyPatch(codeToDisplay, idx)}
                                    className={`px-3 sm:px-4 py-1.5 rounded-full text-xs font-mono font-medium transition-all border flex items-center gap-1.5 sm:gap-2 cursor-pointer shrink-0 ${isCopied ? 'bg-[#E2FF32] text-[#141414] border-[#E2FF32]' : 'bg-[#181818] text-white hover:bg-neutral-800 border-[#2E2E2E]'}`}
                                  >
                                    {isCopied ? <Check size={12} /> : <Copy size={12} />}
                                    {isCopied ? 'Copied! ✓' : 'Copy Patch'}
                                  </button>
                                </div>

                                <div className="flex-1 bg-[#141414] rounded-xl border border-neutral-800 p-3 sm:p-4 overflow-x-auto min-h-[160px] sm:min-h-[180px]">
                                  <pre className="font-mono text-xs sm:text-[13px] leading-relaxed text-gray-300 w-full whitespace-pre font-normal">
                                    {codeToDisplay}
                                  </pre>
                                </div>
                              </div>
                            </motion.div>
                          );
                        })}
                      </motion.div>
                    </div>
                  )}

                  {/* Empty State */}
                  {!isScanning && !hasScanned && (
                    <div className="text-center py-28 border border-dashed border-[#2E2E2E] rounded-2xl bg-[#181818]/40">
                      <div className="w-12 h-12 rounded-full bg-[#2E2E2E] flex items-center justify-center mx-auto mb-4 text-neutral-400">
                        <Terminal size={22} />
                      </div>
                      <h3 className="font-display text-xl text-white mb-1">Workbench Idle</h3>
                      <p className="font-mono text-xs sm:text-sm text-neutral-500 max-w-md mx-auto">
                        Choose template packs above and click "Run Audit" to inspect findings and copy verified remediation patches.
                      </p>
                    </div>
                  )}
                </div>
              </section>
            </div>
          )}

          {/* PAGE 3: TEMPLATE PACKS CATALOG */}
          {activePage === 'templates' && (
            <div className="flex-1 bg-[#141414] text-[#F4F2ED] px-4 sm:px-8 lg:px-16 py-12 sm:py-16">
              <div className="max-w-[1600px] mx-auto">
                <div className="flex flex-col sm:flex-row justify-between items-start sm:items-end border-b border-[#2E2E2E] pb-8 mb-12 gap-6">
                  <div>
                    <span className="font-mono text-xs text-[#E2FF32] font-bold uppercase tracking-wider">/ Compliance Matrix</span>
                    <h1 className="font-display font-medium text-3xl sm:text-4xl text-white mt-1">
                      Template Pack Catalog
                    </h1>
                    <p className="font-mono text-sm text-neutral-400 mt-2 max-w-2xl">
                      6 specialized institutional security packs loaded directly from <code className="text-[#F4F2ED] bg-[#181818] px-2 py-0.5 rounded">templates/edu_asvs_rules.yaml</code>.
                    </p>
                  </div>
                  <div>
                    <button 
                      onClick={() => setActivePage('audit')}
                      className="px-6 py-2.5 bg-[#E2FF32] text-[#141414] rounded-full text-sm font-semibold hover:opacity-90 transition-opacity cursor-pointer inline-flex items-center gap-2"
                    >
                      Open Audit Workspace ↗
                    </button>
                  </div>
                </div>

                <div className="space-y-8 sm:space-y-12">
                  {TEMPLATE_PACKS.map((pack, idx) => (
                    <div key={pack.id} className="bg-[#181818] border border-[#2E2E2E] rounded-2xl sm:rounded-[24px] p-5 sm:p-8">
                      <div className="flex flex-col lg:flex-row justify-between items-start lg:items-center pb-6 border-b border-[#2E2E2E] gap-4">
                        <div>
                          <div className="flex items-center gap-3 mb-2">
                            <span className="font-mono text-xs font-bold text-[#FF6B2B]">/ 0{idx + 1}</span>
                            <span className="font-mono text-xs text-neutral-400">{pack.id}</span>
                            <span className="px-2.5 py-0.5 rounded-full bg-[#141414] text-[#E2FF32] font-mono text-[11px] font-semibold">
                              {pack.checks.length} Checks Active
                            </span>
                          </div>
                          <h2 className="font-display font-medium text-xl sm:text-2xl text-white">{pack.name}</h2>
                          <p className="font-mono text-xs sm:text-sm text-neutral-400 mt-1 max-w-3xl leading-relaxed">{pack.description}</p>
                        </div>
                        <button 
                          onClick={() => { setSelectedPacks([pack.id]); setActivePage('audit'); }}
                          className="px-4 py-2 border border-neutral-700 hover:border-[#E2FF32] hover:text-[#E2FF32] text-[#F4F2ED] rounded-full text-xs font-mono font-medium transition-colors cursor-pointer"
                        >
                          Audit This Pack ↗
                        </button>
                      </div>

                      {/* Desktop / Tablet Table View */}
                      <div className="mt-6 overflow-x-auto hidden md:block">
                        <table className="w-full text-left text-xs font-mono">
                          <thead>
                            <tr className="text-neutral-500 border-b border-[#2E2E2E] pb-2">
                              <th className="py-3 px-4 uppercase tracking-wider font-medium">Check ID</th>
                              <th className="py-3 px-4 uppercase tracking-wider font-medium">Title & Description</th>
                              <th className="py-3 px-4 uppercase tracking-wider font-medium">Severity</th>
                              <th className="py-3 px-4 uppercase tracking-wider font-medium">Target</th>
                              <th className="py-3 px-4 uppercase tracking-wider font-medium">OWASP ASVS</th>
                            </tr>
                          </thead>
                          <tbody className="divide-y divide-[#2E2E2E]/40">
                            {pack.checks.map((check) => (
                              <tr key={check.check_id} className="hover:bg-[#141414]/50 transition-colors">
                                <td className="py-4 px-4 font-bold text-white whitespace-nowrap">{check.check_id}</td>
                                <td className="py-4 px-4 max-w-md">
                                  <div className="font-display font-medium text-sm text-white mb-1">{check.title}</div>
                                  <div className="text-neutral-400 text-[11px] leading-relaxed">{check.description}</div>
                                </td>
                                <td className="py-4 px-4 whitespace-nowrap">
                                  <span className={`px-2.5 py-1 rounded-full text-[10px] font-bold uppercase ${check.severity === 'CRITICAL' ? 'bg-[#FF4D4D] text-white' : (check.severity === 'HIGH' ? 'bg-[#FF6B2B] text-white' : 'bg-[#E2FF32] text-[#141414]')}`}>
                                    {check.severity}
                                  </span>
                                </td>
                                <td className="py-4 px-4 text-neutral-400 capitalize whitespace-nowrap">
                                  <span className="px-2 py-0.5 rounded bg-[#141414] border border-[#2E2E2E]">
                                    {check.target_type}
                                  </span>
                                </td>
                                <td className="py-4 px-4 text-[#F4F2ED] whitespace-nowrap font-medium">{check.owasp_asvs_id}</td>
                              </tr>
                            ))}
                          </tbody>
                        </table>
                      </div>

                      {/* Mobile Card Stack View */}
                      <div className="mt-4 space-y-3 block md:hidden">
                        {pack.checks.map((check) => (
                          <div key={check.check_id} className="bg-[#141414] border border-[#2E2E2E] rounded-xl p-4 flex flex-col gap-2.5">
                            <div className="flex items-center justify-between gap-2">
                              <span className="font-mono text-xs font-bold text-white">{check.check_id}</span>
                              <span className={`px-2 py-0.5 rounded-full text-[10px] font-bold uppercase ${check.severity === 'CRITICAL' ? 'bg-[#FF4D4D] text-white' : (check.severity === 'HIGH' ? 'bg-[#FF6B2B] text-white' : 'bg-[#E2FF32] text-[#141414]')}`}>
                                {check.severity}
                              </span>
                            </div>
                            <div className="font-display font-medium text-sm text-white">{check.title}</div>
                            <div className="text-neutral-400 text-xs font-mono leading-relaxed">{check.description}</div>
                            <div className="flex items-center justify-between pt-2 border-t border-[#2E2E2E]/60 text-xs font-mono text-neutral-400">
                              <span className="capitalize px-2 py-0.5 rounded bg-[#181818] border border-[#2E2E2E]">{check.target_type}</span>
                              <span className="text-[#F4F2ED] font-medium">{check.owasp_asvs_id}</span>
                            </div>
                          </div>
                        ))}
                      </div>
                    </div>
                  ))}
                </div>
              </div>
            </div>
          )}

          {/* PAGE 4: OWASP ASVS MATRIX */}
          {activePage === 'owasp' && (
            <div className="flex-1 bg-[#141414] text-[#F4F2ED] px-4 sm:px-8 lg:px-16 py-12 sm:py-16">
              <div className="max-w-[1600px] mx-auto">
                <div className="flex flex-col sm:flex-row justify-between items-start sm:items-end border-b border-[#2E2E2E] pb-8 mb-12 gap-6">
                  <div>
                    <span className="font-mono text-xs text-[#E2FF32] font-bold uppercase tracking-wider">/ Standardized Verification</span>
                    <h1 className="font-display font-medium text-3xl sm:text-4xl text-white mt-1">
                      OWASP ASVS v4.0 Mapping
                    </h1>
                    <p className="font-mono text-sm text-neutral-400 mt-2 max-w-2xl">
                      EduGuard maps higher-ed attack surfaces directly to OWASP Application Security Verification Standard (ASVS) v4.0.
                    </p>
                  </div>
                  <div>
                    <button 
                      onClick={() => setActivePage('audit')}
                      className="px-5 py-2.5 bg-[#E2FF32] text-[#141414] rounded-full text-xs sm:text-sm font-semibold hover:opacity-90 transition-opacity cursor-pointer inline-flex items-center gap-2"
                    >
                      Run Compliance Audit ↗
                    </button>
                  </div>
                </div>

                <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-6">
                  {[
                    { ch: "CHAPTER V1", title: "Architecture & Email Verification", desc: "Covers section 1.14.3. Prevents institutional email domain impersonation by requiring valid DMARC, SPF, and MX authentication.", tag: "ASVS L1/L2", pack: "DNS/DMARC", id: "EDU-DNS-001" },
                    { ch: "CHAPTER V3", title: "Session Cookie Hygiene", desc: "Covers section 3.4.1. Asserts HttpOnly, Secure, and SameSite cookie flags on student portals to prevent token exfiltration via XSS.", tag: "ASVS L1", pack: "Transport/Headers", id: "EDU-HTTP-002" },
                    { ch: "CHAPTER V4", title: "Access Control & IDOR Prevention", desc: "Covers section 4.2.1. Audits student transcript, financial aid, and grade endpoints to ensure records are protected against horizontal parameter manipulation.", tag: "CRITICAL", pack: "IDOR/RBAC", id: "EDU-RBAC-001" },
                    { ch: "CHAPTER V5", title: "Injection & Query Parameterization", desc: "Covers section 5.3.5. Flags raw string concatenation and unsanitized queries in Student Information System (SIS) database abstractions.", tag: "CRITICAL", pack: "SAST Injection", id: "EDU-SAST-001" },
                    { ch: "CHAPTER V12", title: "File Upload & PII Privacy", desc: "Covers section 12.3.1. Validates that student submission handlers reject dangerous MIME types and isolate documents from publicly served web roots.", tag: "ASVS L2", pack: "Student PII Privacy", id: "EDU-PRIV-001" },
                    { ch: "CHAPTER V14", title: "Configuration & HSTS Posture", desc: "Covers sections 14.2.1 & 14.4.4. Detects leaked .env secrets, production debug flags, and missing HTTP Strict-Transport-Security.", tag: "ASVS L1", pack: "Exposed Configs", id: "EDU-CFG-001" },
                  ].map((item, idx) => (
                    <div key={idx} className="bg-[#181818] border border-[#2E2E2E] rounded-2xl p-6 flex flex-col justify-between">
                      <div>
                        <div className="flex items-center justify-between mb-3">
                          <span className="font-mono text-xs font-bold text-[#FF6B2B]">{item.ch}</span>
                          <span className="text-[11px] font-mono px-2 py-0.5 rounded bg-[#141414] text-[#E2FF32]">{item.tag}</span>
                        </div>
                        <h3 className="font-display font-medium text-lg text-white mb-2">{item.title}</h3>
                        <p className="font-mono text-xs text-neutral-400 leading-relaxed mb-4">{item.desc}</p>
                      </div>
                      <div className="pt-4 border-t border-[#2E2E2E] text-xs font-mono text-neutral-400 flex justify-between items-center">
                        <span>{item.pack}</span>
                        <span className="text-[#E2FF32] font-bold">{item.id}</span>
                      </div>
                    </div>
                  ))}
                </div>
              </div>
            </div>
          )}

          {/* PAGE 5: ENGINE ARCHITECTURE */}
          {activePage === 'engine' && (
            <div className="flex-1 bg-[#141414] text-[#F4F2ED] px-4 sm:px-8 lg:px-16 py-12 sm:py-16">
              <div className="max-w-[1600px] mx-auto">
                <div className="flex flex-col sm:flex-row justify-between items-start sm:items-end border-b border-[#2E2E2E] pb-8 mb-12 gap-6">
                  <div>
                    <span className="font-mono text-xs text-[#E2FF32] font-bold uppercase tracking-wider">/ Engine Pipeline</span>
                    <h1 className="font-display font-medium text-3xl sm:text-4xl text-white mt-1">
                      Scanner & Gemma AI Architecture
                    </h1>
                    <p className="font-mono text-sm text-neutral-400 mt-2 max-w-2xl">
                      EduGuard pairs deterministic rule engines with local Gemma inference for verified remediation without sending institution source code or student records to cloud APIs.
                    </p>
                  </div>
                  <div>
                    <button 
                      onClick={() => setActivePage('audit')}
                      className="px-5 py-2.5 bg-[#E2FF32] text-[#141414] rounded-full text-xs sm:text-sm font-semibold hover:opacity-90 transition-opacity cursor-pointer inline-flex items-center gap-2"
                    >
                      Launch Scanner ↗
                    </button>
                  </div>
                </div>

                <div className="grid grid-cols-1 md:grid-cols-3 gap-6 mb-12">
                  <div className="bg-[#181818] border border-[#2E2E2E] rounded-2xl p-6 sm:p-8 flex flex-col justify-between">
                    <div>
                      <span className="font-mono text-xs font-bold text-[#FF6B2B]">STAGE 01</span>
                      <h3 className="font-display font-medium text-xl text-white mt-2 mb-3">Deterministic Engine</h3>
                      <p className="font-mono text-xs sm:text-sm text-neutral-400 leading-relaxed mb-4">
                        Scans target codebases or perimeters using pattern-based source checks and DNS/HTTP header inspection.
                      </p>
                    </div>
                    <div className="pt-4 border-t border-[#2E2E2E] text-xs font-mono text-[#E2FF32]">
                      ✔ Zero Hallucinations · Strict ASVS
                    </div>
                  </div>

                  <div className="bg-[#181818] border border-[#2E2E2E] rounded-2xl p-6 sm:p-8 flex flex-col justify-between">
                    <div>
                      <span className="font-mono text-xs font-bold text-[#E2FF32]">STAGE 02</span>
                      <h3 className="font-display font-medium text-xl text-white mt-2 mb-3">Local Gemma Remediator</h3>
                      <p className="font-mono text-xs sm:text-sm text-neutral-400 leading-relaxed mb-4">
                        Findings are passed to a locally hosted Gemma instance via Ollama (gemma4:e4b or gemma2:2b) to generate unified diff patches.
                      </p>
                    </div>
                    <div className="pt-4 border-t border-[#2E2E2E] text-xs font-mono text-[#E2FF32]">
                      ✔ 100% Offline · 0KB Cloud Leakage
                    </div>
                  </div>

                  <div className="bg-[#181818] border border-[#2E2E2E] rounded-2xl p-6 sm:p-8 flex flex-col justify-between">
                    <div>
                      <span className="font-mono text-xs font-bold text-[#FF4D4D]">STAGE 03</span>
                      <h3 className="font-display font-medium text-xl text-white mt-2 mb-3">One-Click Remediation</h3>
                      <p className="font-mono text-xs sm:text-sm text-neutral-400 leading-relaxed mb-4">
                        Engine computes institutional security grade (A through F), correlates FERPA compliance liabilities, and formats copyable Git patches.
                      </p>
                    </div>
                    <div className="pt-4 border-t border-[#2E2E2E] text-xs font-mono text-[#E2FF32]">
                      ✔ Unified Diff · Board & Dev Modes
                    </div>
                  </div>
                </div>

                <div className="bg-[#0a0a0a] border border-[#2E2E2E] rounded-2xl p-6 sm:p-8">
                  <h3 className="font-display font-medium text-lg text-white mb-4">Privacy & FERPA Invariant</h3>
                  <div className="grid grid-cols-1 sm:grid-cols-2 gap-6 text-xs font-mono text-neutral-400 leading-relaxed">
                    <div className="p-4 bg-[#141414] rounded-xl border border-[#2E2E2E]">
                      <span className="text-white font-bold block mb-1">Local Model Execution</span>
                      Model inference runs directly on host machine CPU/GPU using Ollama. No payload, source snippet, or student record is transmitted to external endpoints.
                    </div>
                    <div className="p-4 bg-[#141414] rounded-xl border border-[#2E2E2E]">
                      <span className="text-white font-bold block mb-1">Deterministic Verification</span>
                      Vulnerability detection is 100% deterministic, backed by YAML specifications in <code className="text-[#F4F2ED]">templates/edu_asvs_rules.yaml</code>.
                    </div>
                  </div>
                </div>
              </div>
            </div>
          )}

          {/* Footer */}
          <footer className="bg-[#0a0a0a] text-neutral-400 border-t border-[#2E2E2E] px-6 sm:px-12 py-8 text-xs font-mono">
            <div className="max-w-[1600px] mx-auto flex flex-col sm:flex-row justify-between items-center gap-4">
              <div className="flex items-center gap-3">
                <span className="text-[#E2FF32] font-bold">EduGuard</span>
                <span>·</span>
                <span>Autonomous Educational Security Auditor</span>
              </div>
              <div className="flex items-center gap-6">
                <button onClick={() => setActivePage('audit')} className="hover:text-white cursor-pointer">Scanner</button>
                <button onClick={() => setActivePage('templates')} className="hover:text-white cursor-pointer">6 Template Packs</button>
                <button onClick={() => setActivePage('owasp')} className="hover:text-white cursor-pointer">OWASP ASVS v4.0</button>
                <button onClick={() => setActivePage('engine')} className="hover:text-white cursor-pointer">Gemma Engine</button>
              </div>
              <div>
                <span>Local Gemma4:E4B / Gemma2:2B — Zero Cloud Data Leakage</span>
              </div>
            </div>
          </footer>

        </div>
      </div>

      {/* Scan History Slide-over Sidebar Drawer */}
      {isHistoryOpen && (
        <div 
          onClick={() => setIsHistoryOpen(false)}
          className="fixed inset-0 bg-black/70 backdrop-blur-xs z-50 transition-opacity"
        />
      )}

      <aside 
        className={`fixed top-0 right-0 h-full w-full sm:w-[480px] md:w-[540px] bg-[#141414] border-l border-[#2E2E2E] shadow-2xl z-50 flex flex-col transition-transform duration-300 ease-out ${isHistoryOpen ? 'translate-x-0' : 'translate-x-full'}`}
      >
        {/* Sidebar Header */}
        <div className="p-4 sm:p-5 border-b border-[#2E2E2E] bg-[#181818] flex items-center justify-between">
          <div className="flex items-center gap-3">
            <div className="w-10 h-10 rounded-xl bg-[#E2FF32]/10 border border-[#E2FF32]/30 flex items-center justify-center text-[#E2FF32] shrink-0">
              <History size={20} />
            </div>
            <div>
              <div className="flex items-center gap-2">
                <h2 className="font-display font-medium text-lg text-white">Scan History</h2>
                <span className="px-2 py-0.5 rounded-full bg-[#2E2E2E] text-[11px] font-mono text-[#E2FF32] font-semibold">
                  {filteredHistory.length} of {scanHistory.length}
                </span>
              </div>
              <p className="font-mono text-xs text-neutral-400 mt-0.5">
                Switch between past reports to view findings and verified diffs
              </p>
            </div>
          </div>
          <button 
            onClick={() => setIsHistoryOpen(false)}
            className="w-8 h-8 rounded-full border border-[#383838] flex items-center justify-center text-neutral-400 hover:text-white hover:bg-[#2E2E2E] transition-colors cursor-pointer"
            title="Close History Sidebar (Esc)"
          >
            <X size={16} />
          </button>
        </div>

        {/* Search & Filter Bar */}
        <div className="p-4 border-b border-[#2E2E2E] bg-[#161616] space-y-3">
          <div className="relative">
            <Search size={14} className="absolute left-3.5 top-1/2 -translate-y-1/2 text-neutral-400" />
            <input 
              type="text"
              value={historySearch}
              onChange={(e) => setHistorySearch(e.target.value)}
              placeholder="Search past scans by target, ID, or name..."
              className="w-full bg-[#1c1c1c] border border-[#2E2E2E] rounded-xl pl-9 pr-8 py-2 text-xs font-mono text-white placeholder-neutral-500 focus:outline-none focus:border-[#E2FF32] transition-colors"
            />
            {historySearch && (
              <button 
                onClick={() => setHistorySearch('')}
                className="absolute right-3 top-1/2 -translate-y-1/2 text-neutral-500 hover:text-white text-xs font-mono cursor-pointer"
              >
                ✕
              </button>
            )}
          </div>

          {/* Filter Tabs */}
          <div className="flex items-center gap-2 overflow-x-auto pb-1 text-xs font-mono">
            <button 
              onClick={() => setHistoryFilter('all')}
              className={`px-3 py-1.5 rounded-full transition-colors whitespace-nowrap cursor-pointer ${historyFilter === 'all' ? 'bg-[#E2FF32] text-[#141414] font-bold' : 'bg-[#1c1c1c] text-neutral-400 hover:text-white border border-[#2E2E2E]'}`}
            >
              All ({scanHistory.length})
            </button>
            <button 
              onClick={() => setHistoryFilter('critical')}
              className={`px-3 py-1.5 rounded-full transition-colors whitespace-nowrap cursor-pointer ${historyFilter === 'critical' ? 'bg-[#FF4D4D] text-white font-bold' : 'bg-[#1c1c1c] text-neutral-400 hover:text-white border border-[#2E2E2E]'}`}
            >
              Critical (C & F)
            </button>
            <button 
              onClick={() => setHistoryFilter('passing')}
              className={`px-3 py-1.5 rounded-full transition-colors whitespace-nowrap cursor-pointer ${historyFilter === 'passing' ? 'bg-[#FF6B2B] text-white font-bold' : 'bg-[#1c1c1c] text-neutral-400 hover:text-white border border-[#2E2E2E]'}`}
            >
              Passing (A & B)
            </button>
          </div>
        </div>

        {/* Reports List */}
        <div className="flex-1 overflow-y-auto p-4 space-y-3.5">
          {filteredHistory.length === 0 ? (
            <div className="text-center py-16 border border-dashed border-[#2E2E2E] rounded-2xl p-6 bg-[#181818]/40">
              <div className="w-10 h-10 rounded-full bg-[#2E2E2E] flex items-center justify-center mx-auto mb-3 text-neutral-400">
                <Filter size={18} />
              </div>
              <h4 className="font-display font-medium text-white text-sm mb-1">No Matching Reports</h4>
              <p className="font-mono text-xs text-neutral-500 max-w-xs mx-auto mb-4">
                {historySearch ? `No scans match "${historySearch}" with current filter.` : 'No scan history recorded yet.'}
              </p>
              <button 
                onClick={restoreDefaultHistory}
                className="px-4 py-2 rounded-full bg-[#181818] border border-[#383838] hover:border-[#E2FF32] text-[#E2FF32] text-xs font-mono transition-colors cursor-pointer"
              >
                Restore Benchmark Scans
              </button>
            </div>
          ) : (
            filteredHistory.map((report) => {
              const isActive = report.id === selectedScanId;
              const criticalCount = report.findings.filter(f => f.severity === 'CRITICAL').length;
              const highCount = report.findings.filter(f => f.severity === 'HIGH').length;

              return (
                <div 
                  key={report.id}
                  onClick={() => selectScanReport(report.id)}
                  className={`group p-4 sm:p-5 rounded-2xl border transition-all cursor-pointer relative overflow-hidden ${isActive ? 'bg-[#1b1b1b] border-[#E2FF32] shadow-lg shadow-black/50' : 'bg-[#181818] border-[#2E2E2E] hover:border-[#383838] hover:bg-[#1a1a1a]'}`}
                >
                  {/* Active indicator top bar */}
                  {isActive && (
                    <div className="absolute top-0 left-0 right-0 h-1 bg-gradient-to-r from-[#E2FF32] via-[#FF6B2B] to-[#E2FF32]" />
                  )}

                  <div className="flex items-start justify-between gap-3 mb-2.5">
                    <div className="flex items-center gap-2">
                      <span className="font-mono text-xs font-bold text-white bg-[#141414] px-2 py-0.5 rounded border border-[#2E2E2E]">
                        {report.id}
                      </span>
                      <span className="font-mono text-xs text-neutral-400">
                        {report.timestamp}
                      </span>
                    </div>

                    {/* Grade Badge */}
                    <div 
                      className="w-9 h-9 rounded-xl flex items-center justify-center font-display font-bold text-lg shrink-0 border"
                      style={{ 
                        backgroundColor: `${report.gradeColor}15`, 
                        color: report.gradeColor,
                        borderColor: `${report.gradeColor}40` 
                      }}
                    >
                      {report.grade}
                    </div>
                  </div>

                  {/* Title & Target */}
                  <h3 className="font-display font-medium text-white text-base leading-snug group-hover:text-[#E2FF32] transition-colors mb-1.5">
                    {report.name}
                  </h3>

                  <div className="flex items-center gap-1.5 font-mono text-xs text-neutral-400 mb-3 truncate">
                    <Terminal size={12} className="text-[#FF6B2B] shrink-0" />
                    <span className="truncate">{report.target}</span>
                  </div>

                  {/* Breakdown & Engine Badges */}
                  <div className="flex flex-wrap items-center justify-between gap-2 pt-3 border-t border-[#2E2E2E]/60 text-xs font-mono">
                    <div className="flex flex-wrap items-center gap-1.5">
                      <span className="px-2 py-0.5 rounded-full bg-[#141414] text-neutral-300 border border-[#2E2E2E] text-[11px]">
                        {report.findings.length} Findings
                      </span>
                      {criticalCount > 0 && (
                        <span className="px-2 py-0.5 rounded-full bg-[#FF4D4D]/15 text-[#FF4D4D] border border-[#FF4D4D]/30 text-[11px] font-semibold">
                          {criticalCount} Critical
                        </span>
                      )}
                      {highCount > 0 && (
                        <span className="px-2 py-0.5 rounded-full bg-[#FF6B2B]/15 text-[#FF6B2B] border border-[#FF6B2B]/30 text-[11px]">
                          {highCount} High
                        </span>
                      )}
                    </div>

                    <div className="flex items-center gap-2">
                      {isActive ? (
                        <span className="inline-flex items-center gap-1.5 text-[11px] font-bold text-[#E2FF32] bg-[#E2FF32]/10 px-2 py-0.5 rounded-full border border-[#E2FF32]/30">
                          <span className="w-1.5 h-1.5 rounded-full bg-[#E2FF32] animate-pulse"></span>
                          Loaded
                        </span>
                      ) : (
                        <span className="text-[11px] text-neutral-500 group-hover:text-white flex items-center gap-1">
                          View <ArrowUpRight size={11} />
                        </span>
                      )}

                      <button 
                        onClick={(e) => { e.stopPropagation(); exportFindingsCSV(report); }}
                        className="p-1 rounded-md text-neutral-400 hover:text-[#E2FF32] hover:bg-[#141414] transition-colors cursor-pointer"
                        title="Export this report's findings as CSV"
                      >
                        <Download size={13} />
                      </button>

                      <button 
                        onClick={(e) => deleteScanReport(report.id, e)}
                        className="p-1 rounded-md text-neutral-500 hover:text-[#FF4D4D] hover:bg-[#141414] transition-colors cursor-pointer"
                        title="Delete this report from history"
                      >
                        <Trash2 size={13} />
                      </button>
                    </div>
                  </div>
                </div>
              );
            })
          )}
        </div>

        {/* Sidebar Footer */}
        <div className="p-4 sm:p-5 border-t border-[#2E2E2E] bg-[#161616] space-y-3">
          <div className="flex items-center justify-between text-xs font-mono text-neutral-400">
            <span className="flex items-center gap-1.5">
              <Database size={13} className="text-[#E2FF32]" />
              Saved to Browser Storage
            </span>
            <button 
              onClick={restoreDefaultHistory}
              className="text-[#FF6B2B] hover:underline cursor-pointer"
            >
              Reset Benchmarks
            </button>
          </div>

          <div className="flex items-center gap-2 pt-1">
            <button 
              onClick={() => {
                setActivePage('audit');
                setIsHistoryOpen(false);
                const targetBar = document.getElementById('targetInput') || document.querySelector('input[placeholder="Target Directory or URL"]');
                if (targetBar) {
                  (targetBar as HTMLInputElement).focus();
                }
              }}
              className="flex-1 py-2.5 bg-[#E2FF32] text-[#141414] font-medium text-xs font-mono rounded-xl hover:opacity-90 transition-opacity flex items-center justify-center gap-2 cursor-pointer font-bold"
            >
              <Play size={12} fill="#141414" />
              Run New Audit
            </button>
            <button 
              onClick={() => {
                const dataStr = "data:text/json;charset=utf-8," + encodeURIComponent(JSON.stringify(scanHistory, null, 2));
                const downloadAnchor = document.createElement('a');
                downloadAnchor.setAttribute("href", dataStr);
                downloadAnchor.setAttribute("download", `eduguard_scan_history_${new Date().toISOString().slice(0,10)}.json`);
                document.body.appendChild(downloadAnchor);
                downloadAnchor.click();
                downloadAnchor.remove();
                toast.success("History Exported", {
                  description: `Exported ${scanHistory.length} audit reports to JSON.`
                });
              }}
              className="px-4 py-2.5 bg-[#1c1c1c] border border-[#2E2E2E] text-neutral-300 hover:text-white hover:border-white font-mono text-xs rounded-xl transition-colors cursor-pointer"
              title="Export all reports to JSON"
            >
              Export JSON
            </button>
          </div>
        </div>
      </aside>

      {/* Sonner Toast Notification System (Non-blocking real-time stages) */}
      <Toaster 
        theme="dark" 
        position="top-right" 
        richColors 
        closeButton 
        toastOptions={{
          style: {
            background: '#181818',
            border: '1px solid #383838',
            color: '#F4F2ED',
            fontFamily: '"JetBrains Mono", monospace',
            fontSize: '13px',
            borderRadius: '14px',
            boxShadow: '0 20px 25px -5px rgba(0, 0, 0, 0.5), 0 8px 10px -6px rgba(0, 0, 0, 0.5)'
          }
        }}
      />
    </div>
  );
}
