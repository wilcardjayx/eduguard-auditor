OWASP_CHEATSHEETS = {
    "pack_1_dns": "OWASP Email Security & Domain Authentication Guidelines: Implement strict SPF, DMARC (p=reject or quarantine), and DKIM records to prevent spoofed institutional emails.",
    "pack_2_transport": "OWASP Transport Layer Protection & HTTP Security Headers Cheat Sheet: Enforce HSTS (max-age=31536000), CSP headers, and set Secure, HttpOnly, SameSite=Strict on all session cookies.",
    "pack_3_configs": "OWASP Attack Surface Analysis & Configuration Management: Never commit sensitive environment files (.env) or database backups to public web roots; disable production debug flags.",
    "pack_4_sast": "OWASP SQL Injection Prevention Cheat Sheet: Use parameterized queries, prepared statements, or ORMs (SQLAlchemy/Prisma) instead of string concatenation.",
    "pack_5_rbac": "OWASP Access Control Cheat Sheet: Enforce explicit session ownership checks and role-based middleware (`@login_required`, `@role_required`) on all student record endpoints.",
    "pack_6_privacy": "OWASP File Upload Cheat Sheet: Validate file extensions against an strict whitelist (e.g., PDF/DOCX), verify MIME types, randomize filenames, and store uploaded documents outside the web root."
}
