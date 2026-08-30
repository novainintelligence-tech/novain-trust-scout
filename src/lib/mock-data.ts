import type { Severity } from "@/components/severity-badge";

export interface CookieRow {
  name: string;
  domain: string;
  path: string;
  httpOnly: boolean;
  secure: boolean;
  sameSite: "Strict" | "Lax" | "None" | "Missing";
  expires: string;
  jsAccessible: boolean;
  severity: Severity;
}

export const mockCookies: CookieRow[] = [
  {
    name: "nsl_session",
    domain: "novain.app",
    path: "/",
    httpOnly: true,
    secure: true,
    sameSite: "Strict",
    expires: "Session",
    jsAccessible: false,
    severity: "pass",
  },
  {
    name: "csrf_token",
    domain: "novain.app",
    path: "/",
    httpOnly: false,
    secure: true,
    sameSite: "Lax",
    expires: "2h",
    jsAccessible: true,
    severity: "pass",
  },
  {
    name: "nsl_prefs",
    domain: ".novain.app",
    path: "/",
    httpOnly: false,
    secure: true,
    sameSite: "Lax",
    expires: "30d",
    jsAccessible: true,
    severity: "info",
  },
  {
    name: "legacy_auth",
    domain: "novain.app",
    path: "/",
    httpOnly: false,
    secure: false,
    sameSite: "None",
    expires: "7d",
    jsAccessible: true,
    severity: "fail",
  },
  {
    name: "analytics_id",
    domain: ".novain.app",
    path: "/",
    httpOnly: false,
    secure: true,
    sameSite: "Missing",
    expires: "1y",
    jsAccessible: true,
    severity: "warn",
  },
];

export interface HeaderRow {
  name: string;
  value: string | null;
  expected: string;
  severity: Severity;
  note: string;
}

export const mockHeaders: HeaderRow[] = [
  {
    name: "Content-Security-Policy",
    value: "default-src 'self'; script-src 'self' 'nonce-x1' https://cdn.novain.app",
    expected: "Strict CSP with nonce or hash based script-src",
    severity: "pass",
    note: "Nonce-based CSP present. No unsafe-inline detected.",
  },
  {
    name: "Strict-Transport-Security",
    value: "max-age=63072000; includeSubDomains; preload",
    expected: "max-age ≥ 15552000, includeSubDomains, preload",
    severity: "pass",
    note: "HSTS is enforced across subdomains and preload-eligible.",
  },
  {
    name: "X-Frame-Options",
    value: "SAMEORIGIN",
    expected: "DENY or SAMEORIGIN",
    severity: "pass",
    note: "Clickjacking protection is active.",
  },
  {
    name: "Referrer-Policy",
    value: "strict-origin-when-cross-origin",
    expected: "no-referrer or strict-origin-when-cross-origin",
    severity: "pass",
    note: "Referrer leakage minimized on cross-origin navigation.",
  },
  {
    name: "Permissions-Policy",
    value: "camera=(), microphone=(), geolocation=()",
    expected: "Explicit deny for unused features",
    severity: "warn",
    note: "Consider disabling additional features (payment, usb).",
  },
  {
    name: "X-Content-Type-Options",
    value: null,
    expected: "nosniff",
    severity: "fail",
    note: "Header missing. Browsers may MIME-sniff responses.",
  },
];

export interface XssCase {
  id: string;
  vector: string;
  payload: string;
  category: "Reflected" | "Stored" | "DOM" | "CSP" | "Encoding";
  severity: Severity;
  detail: string;
}

export const mockXss: XssCase[] = [
  {
    id: "R-001",
    vector: "Search query param `q`",
    payload: "<script>alert(1)</script>",
    category: "Reflected",
    severity: "pass",
    detail: "Payload output-encoded as HTML entities. Not executed.",
  },
  {
    id: "S-014",
    vector: "Comment body persisted to DB",
    payload: "<img src=x onerror=alert(1)>",
    category: "Stored",
    severity: "pass",
    detail: "Sanitized by DOMPurify allowlist on render.",
  },
  {
    id: "D-023",
    vector: "location.hash → innerHTML",
    payload: "#<svg/onload=alert(1)>",
    category: "DOM",
    severity: "warn",
    detail: "Sink identified. Sanitizer bypass possible with mutated markup.",
  },
  {
    id: "C-002",
    vector: "CSP nonce reuse",
    payload: "n/a",
    category: "CSP",
    severity: "pass",
    detail: "Nonces regenerated per request. strict-dynamic in effect.",
  },
  {
    id: "E-011",
    vector: "JSON embedded in <script>",
    payload: "</script><script>alert(1)</script>",
    category: "Encoding",
    severity: "fail",
    detail: "Server does not escape </script> in inline JSON.",
  },
];

export interface CsrfCheck {
  endpoint: string;
  method: "POST" | "PUT" | "DELETE" | "PATCH";
  tokenRequired: boolean;
  tokenValidated: boolean;
  sameSite: "Strict" | "Lax" | "None";
  severity: Severity;
  note: string;
}

export const mockCsrf: CsrfCheck[] = [
  {
    endpoint: "/api/account/email",
    method: "POST",
    tokenRequired: true,
    tokenValidated: true,
    sameSite: "Strict",
    severity: "pass",
    note: "Rejects requests without matching CSRF token.",
  },
  {
    endpoint: "/api/settings/mfa",
    method: "PUT",
    tokenRequired: true,
    tokenValidated: true,
    sameSite: "Strict",
    severity: "pass",
    note: "Double-submit cookie pattern verified.",
  },
  {
    endpoint: "/api/session/logout",
    method: "POST",
    tokenRequired: false,
    tokenValidated: false,
    sameSite: "Lax",
    severity: "warn",
    note: "Idempotent action but token still recommended.",
  },
  {
    endpoint: "/api/legacy/export",
    method: "POST",
    tokenRequired: false,
    tokenValidated: false,
    sameSite: "None",
    severity: "fail",
    note: "State-changing endpoint accepts cross-site requests.",
  },
];

export interface SessionCheck {
  name: string;
  status: Severity;
  observation: string;
}

export const mockSessions: SessionCheck[] = [
  { name: "Rotates session ID after login", status: "pass", observation: "New sid issued on auth." },
  { name: "Invalidates session on logout", status: "pass", observation: "Server-side revoked, Redis TTL cleared." },
  { name: "Idle timeout", status: "pass", observation: "15 min inactivity → forced re-auth." },
  { name: "Max lifetime", status: "warn", observation: "Absolute lifetime is 30 days — consider 7." },
  { name: "Concurrent device cap", status: "info", observation: "No cap configured. 4 active devices seen." },
  { name: "Session fixation guard", status: "pass", observation: "Cookie regenerated on privilege change." },
];

export interface TlsResult {
  host: string;
  ip: string;
  protocol: "TLS 1.3" | "TLS 1.2" | "TLS 1.1";
  cipher: string;
  issuer: string;
  validFrom: string;
  validTo: string;
  daysRemaining: number;
  hstsPreloaded: boolean;
  ocspStapling: boolean;
  chain: string[];
  severity: Severity;
}

export const mockTls: TlsResult = {
  host: "novain.app",
  ip: "203.0.113.24",
  protocol: "TLS 1.3",
  cipher: "TLS_AES_256_GCM_SHA384",
  issuer: "Let's Encrypt R3",
  validFrom: "2026-05-12",
  validTo: "2026-08-10",
  daysRemaining: 22,
  hstsPreloaded: true,
  ocspStapling: true,
  chain: ["novain.app", "Let's Encrypt R3", "ISRG Root X1"],
  severity: "warn",
};

export interface AuditEvent {
  id: string;
  time: string;
  actor: string;
  ip: string;
  event: string;
  result: "success" | "failure" | "info";
}

export const mockAudit: AuditEvent[] = [
  { id: "e_9821", time: "2026-07-19 14:22:11", actor: "sam@novain.app", ip: "203.0.113.10", event: "Login (password + TOTP)", result: "success" },
  { id: "e_9820", time: "2026-07-19 14:21:44", actor: "sam@novain.app", ip: "203.0.113.10", event: "MFA challenge issued", result: "info" },
  { id: "e_9819", time: "2026-07-19 13:58:02", actor: "unknown", ip: "198.51.100.44", event: "Login failed (bad password)", result: "failure" },
  { id: "e_9818", time: "2026-07-19 13:57:41", actor: "unknown", ip: "198.51.100.44", event: "Login failed (bad password)", result: "failure" },
  { id: "e_9817", time: "2026-07-19 12:10:19", actor: "ana@novain.app", ip: "192.0.2.55", event: "Password changed", result: "success" },
  { id: "e_9816", time: "2026-07-19 11:44:00", actor: "ana@novain.app", ip: "192.0.2.55", event: "Session revoked (device: iPad)", result: "info" },
  { id: "e_9815", time: "2026-07-19 09:03:12", actor: "system", ip: "-", event: "Rotated CSRF signing key", result: "info" },
];

export interface ScoreBreakdown {
  cookies: number;
  headers: number;
  sessions: number;
  tls: number;
  csrf: number;
  xss: number;
  auth: number;
}

export const mockScore: ScoreBreakdown = {
  cookies: 72,
  headers: 84,
  sessions: 88,
  tls: 78,
  csrf: 66,
  xss: 74,
  auth: 92,
};

export const overallScore = Math.round(
  Object.values(mockScore).reduce((a, b) => a + b, 0) / Object.values(mockScore).length,
);
