import { createServerFn } from "@tanstack/react-start";
import { z } from "zod";

import { requireSupabaseAuth } from "@/integrations/supabase/auth-middleware";
import type {
  CookieRow,
  CorsProbeEvidence,
  CrtShEntry,
  CsrfCheck,
  HeaderRow,
  HeadersDump,
  PathProbeEvidence,
  PrimaryResponseEvidence,
  ReconCheck,
  RedirectProbeEvidence,
  ScanEvidence,
  ScanResult,
  ScoreBreakdown,
  SessionCheck,
  TlsResult,
  XssCase,
  XssProbeEvidence,
} from "./scan-types";
import type { Severity } from "@/components/severity-badge";

const urlSchema = z.object({
  url: z.string().url().refine(
    (u) => u.startsWith("http://") || u.startsWith("https://"),
    "URL must start with http:// or https://",
  ),
});

const UA = "NSL-Scanner/1.2 (+https://novain-security-lab.dev)";

// ---------- helpers ----------

function dumpHeaders(h: Headers): HeadersDump {
  const out: HeadersDump = {};
  h.forEach((v, k) => {
    out[k] = out[k] ? `${out[k]}, ${v}` : v;
  });
  return out;
}

async function readSnippet(res: Response, cap: number): Promise<{ text: string; bytes: number; truncated: boolean }> {
  try {
    const raw = await res.text();
    const bytes = raw.length;
    if (bytes <= cap) return { text: raw, bytes, truncated: false };
    return { text: raw.slice(0, cap), bytes, truncated: true };
  } catch {
    return { text: "", bytes: 0, truncated: false };
  }
}

// ---------- Header analysis (unchanged rules) ----------

interface HeaderSpec {
  name: string;
  expected: string;
  evaluate: (value: string | null, all: Headers) => { severity: Severity; note: string };
}

const HEADER_SPECS: HeaderSpec[] = [
  {
    name: "Content-Security-Policy",
    expected: "Strict CSP without unsafe-inline / unsafe-eval / wildcards",
    evaluate: (v) => {
      if (!v) return { severity: "fail", note: "No CSP. Page can execute arbitrary inline/injected scripts." };
      const lower = v.toLowerCase();
      const bad: string[] = [];
      if (lower.includes("'unsafe-inline'")) bad.push("unsafe-inline");
      if (lower.includes("'unsafe-eval'")) bad.push("unsafe-eval");
      if (/(?:^|\s)\*(?:\s|;|$)/.test(lower)) bad.push("wildcard source");
      if (!/default-src|script-src/.test(lower)) bad.push("missing default-src/script-src");
      if (!/frame-ancestors/.test(lower)) bad.push("no frame-ancestors");
      if (bad.length) return { severity: "warn", note: `Present but weakened: ${bad.join(", ")}.` };
      return { severity: "pass", note: "Strict CSP detected." };
    },
  },
  {
    name: "Strict-Transport-Security",
    expected: "max-age ≥ 15552000; includeSubDomains; preload",
    evaluate: (v) => {
      if (!v) return { severity: "fail", note: "HSTS missing. Downgrade attacks are possible." };
      const m = /max-age=(\d+)/i.exec(v);
      const maxAge = m ? Number(m[1]) : 0;
      if (maxAge < 15552000) return { severity: "warn", note: `max-age=${maxAge} is below the 6-month minimum.` };
      const missing: string[] = [];
      if (!/includesubdomains/i.test(v)) missing.push("includeSubDomains");
      if (!/preload/i.test(v)) missing.push("preload");
      if (missing.length) return { severity: "warn", note: `HSTS present but missing: ${missing.join(", ")}.` };
      return { severity: "pass", note: `HSTS enforced (max-age=${maxAge}, includeSubDomains, preload).` };
    },
  },
  {
    name: "X-Frame-Options",
    expected: "DENY or SAMEORIGIN (or CSP frame-ancestors)",
    evaluate: (v, all) => {
      const csp = (all.get("content-security-policy") ?? "").toLowerCase();
      if (!v && csp.includes("frame-ancestors")) return { severity: "pass", note: "Handled by CSP frame-ancestors." };
      if (!v) return { severity: "warn", note: "Missing. No clickjacking protection." };
      const upper = v.toUpperCase();
      if (upper.includes("DENY") || upper.includes("SAMEORIGIN")) return { severity: "pass", note: "Clickjacking protection is active." };
      return { severity: "warn", note: `Unusual value: ${v}` };
    },
  },
  {
    name: "Referrer-Policy",
    expected: "no-referrer or strict-origin-when-cross-origin",
    evaluate: (v) => {
      if (!v) return { severity: "warn", note: "Missing. Browsers may leak full referrer URLs cross-origin." };
      const good = /(no-referrer|strict-origin-when-cross-origin|same-origin)/i.test(v);
      return { severity: good ? "pass" : "warn", note: `Referrer-Policy: ${v}` };
    },
  },
  {
    name: "Permissions-Policy",
    expected: "Explicit deny for unused features",
    evaluate: (v) => {
      if (!v) return { severity: "warn", note: "Missing. Camera/microphone/geolocation implicitly allowed." };
      return { severity: "pass", note: "Permissions-Policy present." };
    },
  },
  {
    name: "X-Content-Type-Options",
    expected: "nosniff",
    evaluate: (v) => {
      if (!v) return { severity: "fail", note: "Header missing. Browsers may MIME-sniff responses." };
      if (v.toLowerCase().includes("nosniff")) return { severity: "pass", note: "nosniff enforced." };
      return { severity: "warn", note: `Unexpected value: ${v}` };
    },
  },
  {
    name: "Cross-Origin-Opener-Policy",
    expected: "same-origin",
    evaluate: (v) => {
      if (!v) return { severity: "warn", note: "Missing. Popups can share browsing context with opener." };
      const good = /same-origin/i.test(v);
      return { severity: good ? "pass" : "warn", note: `COOP: ${v}` };
    },
  },
  {
    name: "Cross-Origin-Resource-Policy",
    expected: "same-site or same-origin",
    evaluate: (v) => {
      if (!v) return { severity: "warn", note: "Missing. Cross-origin sites may embed resources." };
      return { severity: "pass", note: `CORP: ${v}` };
    },
  },
  {
    name: "Cross-Origin-Embedder-Policy",
    expected: "require-corp (only if isolation needed)",
    evaluate: (v) => {
      if (!v) return { severity: "info", note: "COEP absent. Only required for cross-origin isolation." };
      return { severity: "pass", note: `COEP: ${v}` };
    },
  },
  {
    name: "Access-Control-Allow-Origin",
    expected: "Specific origin or absent (not '*' with credentials)",
    evaluate: (v, all) => {
      if (!v) return { severity: "pass", note: "No ACAO — API not exposed cross-origin by default." };
      const creds = (all.get("access-control-allow-credentials") ?? "").toLowerCase() === "true";
      if (v === "*" && creds) return { severity: "fail", note: "ACAO:* with credentials — invalid & dangerous intent." };
      if (v === "*") return { severity: "warn", note: "Wildcard ACAO — all responses exposed cross-origin." };
      return { severity: "pass", note: `ACAO scoped: ${v}` };
    },
  },
  {
    name: "Server",
    expected: "Absent or generic",
    evaluate: (v) => {
      if (!v) return { severity: "pass", note: "No Server header — no product/version leak." };
      if (/\d/.test(v)) return { severity: "warn", note: `Server version leak: "${v}".` };
      return { severity: "info", note: `Server header present: "${v}".` };
    },
  },
  {
    name: "X-Powered-By",
    expected: "Absent",
    evaluate: (v) => {
      if (!v) return { severity: "pass", note: "Not present." };
      return { severity: "warn", note: `Fingerprintable stack: "${v}".` };
    },
  },
];

function analyseHeaders(headers: Headers): HeaderRow[] {
  return HEADER_SPECS.map((spec) => {
    const value = headers.get(spec.name);
    const { severity, note } = spec.evaluate(value, headers);
    return { name: spec.name, value, expected: spec.expected, severity, note };
  });
}

// ---------- Cookie parsing ----------

function parseSetCookies(setCookies: string[], host: string): CookieRow[] {
  return setCookies.map((raw) => {
    const parts = raw.split(";").map((p) => p.trim());
    const [nameEq, ...attrs] = parts;
    const eqIdx = nameEq.indexOf("=");
    const name = eqIdx > 0 ? nameEq.slice(0, eqIdx) : nameEq;

    let httpOnly = false;
    let secure = false;
    let sameSite: CookieRow["sameSite"] = "Missing";
    let domain = host;
    let path = "/";
    let expires = "Session";
    let domainExplicit = false;

    for (const attr of attrs) {
      const [k, v] = attr.split("=").map((s) => s?.trim());
      const key = k.toLowerCase();
      if (key === "httponly") httpOnly = true;
      else if (key === "secure") secure = true;
      else if (key === "samesite" && v) {
        const norm = v.charAt(0).toUpperCase() + v.slice(1).toLowerCase();
        if (norm === "Strict" || norm === "Lax" || norm === "None") sameSite = norm;
      } else if (key === "domain" && v) { domain = v; domainExplicit = true; }
      else if (key === "path" && v) path = v;
      else if (key === "max-age" && v) expires = `${v}s`;
      else if (key === "expires" && v) expires = v;
    }

    let severity: Severity = "pass";
    const notes: string[] = [];
    if (!secure || sameSite === "None") severity = "fail";
    else if (!httpOnly || sameSite === "Missing") severity = "warn";

    if (name.startsWith("__Host-")) {
      if (!secure) { severity = "fail"; notes.push("__Host- prefix requires Secure."); }
      if (path !== "/") { severity = "fail"; notes.push("__Host- prefix requires Path=/."); }
      if (domainExplicit) { severity = "fail"; notes.push("__Host- prefix forbids Domain."); }
    } else if (name.startsWith("__Secure-") && !secure) {
      severity = "fail";
      notes.push("__Secure- prefix requires Secure.");
    }

    return {
      name, domain, path, httpOnly, secure, sameSite, expires,
      jsAccessible: !httpOnly, severity,
      note: notes.length ? notes.join(" ") : undefined,
      raw,
    };
  });
}

// ---------- TLS ----------

function analyseTls(url: URL, headers: Headers): TlsResult {
  const scheme = url.protocol === "https:" ? "https" : "http";
  const hstsHeader = headers.get("strict-transport-security");
  const maxAgeMatch = hstsHeader ? /max-age=(\d+)/i.exec(hstsHeader) : null;
  const hstsMaxAge = maxAgeMatch ? Number(maxAgeMatch[1]) : null;
  const includeSub = !!hstsHeader && /includesubdomains/i.test(hstsHeader);
  const preload = !!hstsHeader && /preload/i.test(hstsHeader);

  let severity: Severity = "pass";
  let note = "TLS enforced.";
  if (scheme === "http") { severity = "fail"; note = "Target is served over plain HTTP."; }
  else if (!hstsHeader) { severity = "warn"; note = "HTTPS in use, but no HSTS to prevent downgrade attacks."; }
  else if (!hstsMaxAge || hstsMaxAge < 15552000) { severity = "warn"; note = `HSTS present but max-age is only ${hstsMaxAge}s.`; }

  return {
    host: url.host, scheme,
    hstsPresent: !!hstsHeader, hstsPreloaded: preload, hstsMaxAge, hstsIncludeSubDomains: includeSub,
    issuer: null, validFrom: null, validTo: null, daysRemaining: null,
    severity, note,
    rawHstsHeader: hstsHeader,
  };
}

async function enrichTlsWithCert(tls: TlsResult): Promise<{ tls: TlsResult; entries: CrtShEntry[] | null }> {
  if (tls.scheme !== "https") return { tls, entries: null };
  try {
    const res = await fetch(
      `https://crt.sh/?q=${encodeURIComponent(tls.host)}&output=json`,
      { signal: AbortSignal.timeout(6000) },
    );
    if (!res.ok) return { tls, entries: null };
    const rows = (await res.json()) as CrtShEntry[];
    if (!Array.isArray(rows) || rows.length === 0) return { tls, entries: [] };
    const now = Date.now();
    const active = rows
      .filter((r) => r.not_after && new Date(r.not_after).getTime() > now)
      .sort((a, b) => new Date(b.not_before!).getTime() - new Date(a.not_before!).getTime());
    const chosen = active[0] ?? rows[0];
    if (!chosen?.not_after) return { tls, entries: rows.slice(0, 20) };
    const daysRemaining = Math.round((new Date(chosen.not_after).getTime() - now) / (1000 * 60 * 60 * 24));
    let severity = tls.severity;
    let note = tls.note;
    if (daysRemaining < 14) { severity = "fail"; note = `Certificate expires in ${daysRemaining} days.`; }
    else if (daysRemaining < 30 && severity === "pass") { severity = "warn"; note = `Certificate expires in ${daysRemaining} days.`; }
    return {
      tls: {
        ...tls,
        issuer:
          chosen.issuer_name?.split(",").find((p) => p.trim().startsWith("O="))?.replace(/^\s*O=/, "") ??
          chosen.issuer_name ?? null,
        validFrom: chosen.not_before ?? null,
        validTo: chosen.not_after ?? null,
        daysRemaining, severity, note,
      },
      entries: rows.slice(0, 20),
    };
  } catch { return { tls, entries: null }; }
}

// ---------- CSRF ----------

function analyseCsrf(html: string, cookies: CookieRow[], baseUrl: URL): { rows: CsrfCheck[]; forms: string[] } {
  const rows: CsrfCheck[] = [];
  const forms: string[] = [];
  const formRegex = /<form\b[^>]*>[\s\S]*?<\/form>/gi;
  const sessionCookie = cookies.find((c) => /session|sid|auth|jwt|token/i.test(c.name));
  const sameSiteHint: CsrfCheck["sameSiteHint"] = sessionCookie
    ? (sessionCookie.sameSite === "Missing" ? "Unknown" : sessionCookie.sameSite)
    : "Unknown";
  const metaTokenPresent = /<meta[^>]+name\s*=\s*["'](csrf-token|csrf_token|_csrf|_token|xsrf-token)["'][^>]*>/i.test(html);

  const matches = html.match(formRegex) ?? [];
  for (const full of matches) {
    forms.push(full.slice(0, 4000));
    const openTag = /<form\b([^>]*)>/i.exec(full)?.[1] ?? "";
    const body = full.replace(/<form\b[^>]*>/i, "").replace(/<\/form>$/i, "");
    const methodMatch = /method\s*=\s*["']?(\w+)/i.exec(openTag);
    const method = (methodMatch?.[1]?.toUpperCase() ?? "GET") as CsrfCheck["method"];
    const actionMatch = /action\s*=\s*["']([^"']*)/i.exec(openTag);
    const action = actionMatch?.[1] ?? "";
    let endpoint = action || baseUrl.pathname;
    try { endpoint = new URL(action || baseUrl.pathname, baseUrl).pathname; } catch { /* ignore */ }
    if (method === "GET") continue;

    const tokenFound =
      /<input[^>]+(name|id)\s*=\s*["'][^"']*(csrf|xsrf|token|authenticity|requestverification|nonce)[^"']*["']/i.test(body)
      || metaTokenPresent;

    let severity: Severity = "pass";
    let note = tokenFound ? "CSRF token detected (form field or meta)." : "No CSRF token located.";
    if (!tokenFound && sameSiteHint === "Strict") { severity = "warn"; note = "No token, but session cookie is SameSite=Strict."; }
    else if (!tokenFound && sameSiteHint === "Lax") { severity = "warn"; note = "No token; SameSite=Lax mitigates most cross-site POSTs but not top-level GET→POST."; }
    else if (!tokenFound) { severity = "fail"; note = "No CSRF token and session cookie SameSite is None/Missing."; }

    rows.push({ endpoint, method, tokenFound, sameSiteHint, severity, note, rawForm: full.slice(0, 4000) });
    if (rows.length >= 25) break;
  }

  if (rows.length === 0) {
    rows.push({
      endpoint: baseUrl.pathname, method: "POST", tokenFound: false, sameSiteHint,
      severity: "info", note: "No state-changing HTML forms found on this page.",
    });
  }
  return { rows, forms };
}

// ---------- XSS ----------

function analyseXss(headers: HeaderRow[]): XssCase[] {
  const csp = headers.find((h) => h.name === "Content-Security-Policy");
  const xcto = headers.find((h) => h.name === "X-Content-Type-Options");
  const cspVal = csp?.value?.toLowerCase() ?? "";
  const cases: XssCase[] = [];

  cases.push({
    id: "XSS-CSP-PRESENCE", vector: "Content-Security-Policy", category: "CSP",
    severity: !csp?.value ? "fail" : "pass",
    detail: csp?.value ? "CSP present — constrains injected scripts." : "No CSP — reflected/stored XSS payloads can execute freely.",
  });
  cases.push({
    id: "XSS-CSP-UNSAFE-INLINE", vector: "script-src 'unsafe-inline'", category: "CSP",
    severity: cspVal.includes("'unsafe-inline'") ? "warn" : "pass",
    detail: cspVal.includes("'unsafe-inline'") ? "CSP allows 'unsafe-inline' — inline injected scripts run." : "'unsafe-inline' not permitted.",
  });
  cases.push({
    id: "XSS-CSP-UNSAFE-EVAL", vector: "script-src 'unsafe-eval'", category: "CSP",
    severity: cspVal.includes("'unsafe-eval'") ? "warn" : "pass",
    detail: cspVal.includes("'unsafe-eval'") ? "eval() permitted — DOM XSS via string→code is possible." : "eval() blocked.",
  });
  cases.push({
    id: "XSS-HEADER-NOSNIFF", vector: "X-Content-Type-Options: nosniff", category: "Headers",
    severity: xcto?.value?.toLowerCase().includes("nosniff") ? "pass" : "warn",
    detail: xcto?.value?.toLowerCase().includes("nosniff") ? "MIME-sniffing disabled." : "Missing nosniff — user uploads may sniff as JS.",
  });
  return cases;
}

async function probeReflectedXss(url: URL): Promise<{ cases: XssCase[]; evidence: XssProbeEvidence | null }> {
  const canary = `nsl${Math.random().toString(36).slice(2, 10)}zz`;
  const payload = `<script>${canary}</script>`;
  const probeUrl = new URL(url.toString());
  probeUrl.searchParams.set("nsl_probe", payload);
  try {
    const res = await fetch(probeUrl.toString(), {
      redirect: "follow",
      headers: { "User-Agent": UA, Accept: "text/html" },
      signal: AbortSignal.timeout(10000),
    });
    const headers = dumpHeaders(res.headers);
    const contentType = res.headers.get("content-type");
    const snippet = await readSnippet(res, 12000);

    const raw = snippet.text.includes(payload);
    const encoded = snippet.text.includes(`&lt;script&gt;${canary}&lt;/script&gt;`) || snippet.text.includes(canary);

    let reflectionMatch: string | null = null;
    const idx = snippet.text.indexOf(canary);
    if (idx >= 0) reflectionMatch = snippet.text.slice(Math.max(0, idx - 80), Math.min(snippet.text.length, idx + 80));

    const evidence: XssProbeEvidence = {
      requestUrl: probeUrl.toString(),
      payload, canary,
      status: res.status, statusText: res.statusText,
      contentType, headers, reflectionMatch,
      bodySnippet: snippet.text,
    };

    let cases: XssCase[];
    if (raw) cases = [{ id: "XSS-REFLECT-RAW", vector: "?nsl_probe=<script>…</script>", category: "Reflected", severity: "fail", detail: "Payload reflected verbatim — reflected XSS sink." }];
    else if (encoded) cases = [{ id: "XSS-REFLECT-ENC", vector: "?nsl_probe=<script>…</script>", category: "Reflected", severity: "pass", detail: "Payload reflected but HTML-escaped." }];
    else cases = [{ id: "XSS-REFLECT-NONE", vector: "?nsl_probe=<script>…</script>", category: "Reflected", severity: "pass", detail: "Payload not reflected." }];
    return { cases, evidence };
  } catch { return { cases: [], evidence: null }; }
}

async function probeCors(url: URL): Promise<{ cases: XssCase[]; evidence: CorsProbeEvidence | null }> {
  const attacker = "https://nsl-scanner.example";
  try {
    const res = await fetch(url.toString(), {
      method: "GET", redirect: "manual",
      headers: { Origin: attacker, "User-Agent": UA },
      signal: AbortSignal.timeout(8000),
    });
    const headers = dumpHeaders(res.headers);
    const evidence: CorsProbeEvidence = {
      requestUrl: url.toString(), requestOrigin: attacker,
      status: res.status, statusText: res.statusText, headers,
    };
    // drain body (ignore)
    try { await res.arrayBuffer(); } catch { /* ignore */ }

    const acao = res.headers.get("access-control-allow-origin") ?? "";
    const acac = (res.headers.get("access-control-allow-credentials") ?? "").toLowerCase() === "true";
    let cases: XssCase[];
    if (!acao) cases = [{ id: "XSS-CORS-OK", vector: "Origin reflection probe", category: "CORS", severity: "pass", detail: "No CORS headers exposed to arbitrary origins." }];
    else if (acao === attacker && acac) cases = [{ id: "XSS-CORS-REFLECT", vector: "ACAO reflects Origin + credentials", category: "CORS", severity: "fail", detail: `Origin ${attacker} reflected with credentials — full CORS bypass.` }];
    else if (acao === attacker) cases = [{ id: "XSS-CORS-REFLECT-NC", vector: "ACAO reflects Origin", category: "CORS", severity: "warn", detail: "Arbitrary origin reflected (no credentials). Responses readable cross-origin." }];
    else if (acao === "*" && acac) cases = [{ id: "XSS-CORS-CRIT", vector: "ACAO:* + credentials", category: "CORS", severity: "fail", detail: "Dangerous CORS intent (browser blocks but signals misconfig)." }];
    else if (acao === "*") cases = [{ id: "XSS-CORS-WILD", vector: "ACAO:*", category: "CORS", severity: "warn", detail: "Wildcard CORS — safe without credentials but exposes all responses." }];
    else cases = [{ id: "XSS-CORS-SCOPED", vector: `ACAO: ${acao}`, category: "CORS", severity: "pass", detail: "CORS scoped to a specific origin." }];
    return { cases, evidence };
  } catch { return { cases: [], evidence: null }; }
}

// ---------- Sessions ----------

function analyseSessions(cookies: CookieRow[]): SessionCheck[] {
  const sessionCookies = cookies.filter((c) => /session|sid|auth|jwt|token/i.test(c.name));
  if (sessionCookies.length === 0) {
    return [{ name: "Session cookie detected", status: "info", observation: "No obvious session cookie set by the initial response." }];
  }
  return sessionCookies.flatMap<SessionCheck>((c) => [
    { name: `\`${c.name}\` — HttpOnly`, status: c.httpOnly ? "pass" : "fail",
      observation: c.httpOnly ? "Not readable from JavaScript." : "Readable from JavaScript — XSS can steal the session." },
    { name: `\`${c.name}\` — Secure`, status: c.secure ? "pass" : "fail",
      observation: c.secure ? "Only sent over HTTPS." : "Sent over plain HTTP — eavesdropping risk." },
    { name: `\`${c.name}\` — SameSite`, status: c.sameSite === "Strict" ? "pass" : c.sameSite === "Lax" ? "warn" : "fail",
      observation: `SameSite=${c.sameSite}. Strict is best for pure app-session cookies.` },
    { name: `\`${c.name}\` — Prefix`,
      status: c.name.startsWith("__Host-") ? "pass" : c.name.startsWith("__Secure-") ? "warn" : "info",
      observation: c.name.startsWith("__Host-")
        ? "__Host- prefix in use — strongest binding to origin."
        : c.name.startsWith("__Secure-")
          ? "__Secure- prefix in use — consider upgrading to __Host-."
          : "No cookie prefix — consider __Host-/__Secure- for defense-in-depth." },
  ]);
}

// ---------- Recon probes ----------

const EXPOSURE_PATHS: Array<{ p: string; name: string; critical: boolean }> = [
  { p: "/.env", name: ".env file", critical: true },
  { p: "/.git/HEAD", name: ".git/HEAD", critical: true },
  { p: "/.git/config", name: ".git/config", critical: true },
  { p: "/server-status", name: "Apache server-status", critical: true },
  { p: "/phpinfo.php", name: "phpinfo()", critical: true },
  { p: "/wp-login.php", name: "WordPress login", critical: false },
  { p: "/admin", name: "/admin path", critical: false },
  { p: "/actuator", name: "Spring actuator", critical: true },
];

async function probeExposure(base: URL): Promise<{ rows: ReconCheck[]; evidence: PathProbeEvidence[] }> {
  const results = await Promise.all(EXPOSURE_PATHS.map(async ({ p, name, critical }) => {
    const requestUrl = new URL(p, `${base.origin}/`).toString();
    try {
      const res = await fetch(requestUrl, {
        method: "GET", redirect: "manual",
        headers: { "User-Agent": UA, Range: "bytes=0-512" },
        signal: AbortSignal.timeout(6000),
      });
      const headers = dumpHeaders(res.headers);
      const snippet = await readSnippet(res, 800);
      let row: ReconCheck;
      if (res.status === 200 || res.status === 206) {
        row = { id: `EXP:${p}`, category: "exposure", name,
          severity: (critical ? "fail" : "warn") as Severity,
          note: `HTTP ${res.status} — endpoint served content. Verify it does not leak secrets or admin functionality.`,
          target: p };
      } else if (res.status === 401 || res.status === 403) {
        row = { id: `EXP:${p}`, category: "exposure", name, severity: "info",
          note: `HTTP ${res.status} — endpoint exists but is access-controlled.`, target: p };
      } else {
        row = { id: `EXP:${p}`, category: "exposure", name, severity: "pass",
          note: `HTTP ${res.status} — not exposed.`, target: p };
      }
      const evidence: PathProbeEvidence = {
        path: p, requestUrl, method: "GET",
        status: res.status, statusText: res.statusText,
        headers, bodySnippet: snippet.text, bodyBytes: snippet.bytes,
      };
      return { row, evidence };
    } catch (e) {
      const row: ReconCheck = { id: `EXP:${p}`, category: "exposure", name, severity: "pass",
        note: `Request failed: ${e instanceof Error ? e.message : "unknown error"}.`, target: p };
      const evidence: PathProbeEvidence = {
        path: p, requestUrl, method: "GET",
        status: 0, statusText: "network error",
        headers: {}, bodySnippet: "", bodyBytes: 0,
      };
      return { row, evidence };
    }
  }));
  return { rows: results.map((r) => r.row), evidence: results.map((r) => r.evidence) };
}

async function probeMeta(base: URL): Promise<{ rows: ReconCheck[]; evidence: PathProbeEvidence[] }> {
  const paths: Array<{ p: string; name: string; missingSev: Severity; missingNote: string }> = [
    { p: "/.well-known/security.txt", name: "security.txt", missingSev: "warn", missingNote: "No security.txt — vulnerability reporting channel is not published." },
    { p: "/robots.txt", name: "robots.txt", missingSev: "info", missingNote: "No robots.txt served." },
    { p: "/sitemap.xml", name: "sitemap.xml", missingSev: "info", missingNote: "No sitemap.xml served." },
  ];
  const results = await Promise.all(paths.map(async ({ p, name, missingSev, missingNote }) => {
    const requestUrl = new URL(p, `${base.origin}/`).toString();
    try {
      const res = await fetch(requestUrl, {
        method: "GET", redirect: "manual",
        headers: { "User-Agent": UA }, signal: AbortSignal.timeout(6000),
      });
      const headers = dumpHeaders(res.headers);
      const snippet = await readSnippet(res, 2000);
      const row: ReconCheck = res.status === 200
        ? { id: `META:${p}`, category: "meta", name, severity: "pass", note: `HTTP 200 — ${name} present.`, target: p }
        : { id: `META:${p}`, category: "meta", name, severity: missingSev, note: missingNote, target: p };
      const evidence: PathProbeEvidence = {
        path: p, requestUrl, method: "GET",
        status: res.status, statusText: res.statusText,
        headers, bodySnippet: snippet.text, bodyBytes: snippet.bytes,
      };
      return { row, evidence };
    } catch (e) {
      const row: ReconCheck = { id: `META:${p}`, category: "meta", name, severity: "info",
        note: `Probe failed: ${e instanceof Error ? e.message : "unknown error"}.`, target: p };
      const evidence: PathProbeEvidence = {
        path: p, requestUrl, method: "GET",
        status: 0, statusText: "network error",
        headers: {}, bodySnippet: "", bodyBytes: 0,
      };
      return { row, evidence };
    }
  }));
  return { rows: results.map((r) => r.row), evidence: results.map((r) => r.evidence) };
}

function analyseMixedContent(html: string, base: URL): { rows: ReconCheck[]; refs: string[] } {
  if (base.protocol !== "https:") return { rows: [], refs: [] };
  const refs = (html.match(/(?:src|href)\s*=\s*["']http:\/\/[^"']+/gi) ?? []).slice(0, 50);
  if (refs.length === 0) {
    return { rows: [{ id: "MIX:none", category: "mixed-content", name: "Mixed content", severity: "pass", note: "No http:// subresources found in initial HTML." }], refs: [] };
  }
  return { rows: [{ id: "MIX:found", category: "mixed-content", name: "Mixed content", severity: "fail",
    note: `${refs.length} http:// subresource references on an HTTPS page.` }], refs };
}

async function probeRedirect(base: URL): Promise<{ rows: ReconCheck[]; evidence: RedirectProbeEvidence | null }> {
  if (base.protocol !== "https:") {
    return { rows: [{ id: "RED:http", category: "redirect", name: "HTTPS enforcement", severity: "fail",
      note: "Target is served over http:// — no TLS enforcement." }], evidence: null };
  }
  const httpUrl = `http://${base.host}${base.pathname}`;
  try {
    const res = await fetch(httpUrl, {
      method: "HEAD", redirect: "manual",
      headers: { "User-Agent": UA }, signal: AbortSignal.timeout(6000),
    });
    const headers = dumpHeaders(res.headers);
    const location = res.headers.get("location");
    const evidence: RedirectProbeEvidence = {
      requestUrl: httpUrl, status: res.status, statusText: res.statusText, location, headers,
    };
    let rows: ReconCheck[];
    if (res.status >= 300 && res.status < 400 && location?.startsWith("https://")) {
      rows = [{ id: "RED:https", category: "redirect", name: "HTTP → HTTPS redirect", severity: "pass", note: `HTTP ${res.status} → ${location}` }];
    } else if (res.status >= 200 && res.status < 300) {
      rows = [{ id: "RED:plain", category: "redirect", name: "Plain HTTP accepted", severity: "fail",
        note: `HTTP ${res.status} on http:// — plaintext content served without upgrade.` }];
    } else {
      rows = [{ id: "RED:other", category: "redirect", name: "HTTP endpoint response", severity: "info", note: `HTTP ${res.status} on http:// endpoint.` }];
    }
    return { rows, evidence };
  } catch {
    return { rows: [{ id: "RED:closed", category: "redirect", name: "HTTP endpoint", severity: "pass", note: "http:// port not reachable — TLS-only." }], evidence: null };
  }
}

// ---------- Scoring ----------

function scoreRows(items: Array<{ severity: Severity }>): number {
  if (items.length === 0) return 100;
  let score = 100;
  for (const it of items) {
    if (it.severity === "fail") score -= 25;
    else if (it.severity === "warn") score -= 8;
  }
  return Math.max(0, Math.min(100, score));
}

// ---------- Full scan ----------

export async function performScan(rawUrl: string): Promise<Omit<ScanResult, "id" | "createdAt">> {
  const url = new URL(rawUrl);
  const start = Date.now();

  let response: Response;
  try {
    response = await fetch(url.toString(), {
      redirect: "manual",
      headers: { "User-Agent": UA, Accept: "text/html,application/xhtml+xml" },
      signal: AbortSignal.timeout(15000),
    });
  } catch (e) {
    const err = e instanceof Error ? e.message : String(e);
    return {
      targetUrl: url.toString(), targetHost: url.host, status: "error",
      durationMs: Date.now() - start, overallScore: 0,
      scores: { headers: 0, cookies: 0, tls: 0, sessions: 0, csrf: 0, xss: 0, recon: 0 },
      headers: [], cookies: [],
      tls: {
        host: url.host, scheme: url.protocol === "https:" ? "https" : "http",
        hstsPresent: false, hstsPreloaded: false, hstsMaxAge: null, hstsIncludeSubDomains: false,
        issuer: null, validFrom: null, validTo: null, daysRemaining: null,
        severity: "fail", note: `Fetch failed: ${err}`, rawHstsHeader: null,
      },
      csrf: [], xss: [], sessions: [], recon: [],
      evidence: {
        primary: null, setCookies: [], forms: [], mixedContentRefs: [],
        xssProbe: null, corsProbe: null, exposure: [], meta: [], redirect: null, crtsh: null,
      },
      error: `Fetch failed: ${err}`,
    };
  }

  const primaryHeadersDump = dumpHeaders(response.headers);
  const ct = response.headers.get("content-type") ?? "";
  const setCookies = (response.headers as unknown as { getSetCookie?: () => string[] }).getSetCookie?.() ?? [];

  let html = "";
  let bodyBytes = 0;
  let bodyTruncated = false;
  if (ct.includes("text/html") && response.status < 400) {
    const snippet = await readSnippet(response, 500_000);
    html = snippet.text;
    bodyBytes = snippet.bytes;
    bodyTruncated = snippet.truncated;
  } else {
    try { await response.arrayBuffer(); } catch { /* ignore */ }
  }

  const primaryEvidence: PrimaryResponseEvidence = {
    requestUrl: url.toString(),
    finalUrl: response.url || null,
    status: response.status,
    statusText: response.statusText,
    httpVersion: null,
    redirected: response.redirected,
    contentType: ct || null,
    bodyBytes, bodyTruncated,
    bodySnippet: html.slice(0, 12000),
    headers: primaryHeadersDump,
  };

  const headerRows = analyseHeaders(response.headers);
  const cookieRows = parseSetCookies(setCookies, url.host);
  let tls = analyseTls(url, response.headers);

  const [certResult, reflected, cors, exposure, meta, redirect] = await Promise.all([
    enrichTlsWithCert(tls),
    probeReflectedXss(url),
    probeCors(url),
    probeExposure(url),
    probeMeta(url),
    probeRedirect(url),
  ]);
  tls = certResult.tls;

  const csrfResult = analyseCsrf(html, cookieRows, url);
  const xssRows = [...analyseXss(headerRows), ...reflected.cases, ...cors.cases];
  const sessionRows = analyseSessions(cookieRows);
  const mixed = analyseMixedContent(html, url);
  const reconRows: ReconCheck[] = [...exposure.rows, ...meta.rows, ...mixed.rows, ...redirect.rows];

  const scores: ScoreBreakdown = {
    headers: scoreRows(headerRows),
    cookies: scoreRows(cookieRows),
    tls: tls.severity === "pass" ? 95 : tls.severity === "warn" ? 70 : 30,
    sessions: scoreRows(sessionRows.map((s) => ({ severity: s.status }))),
    csrf: scoreRows(csrfResult.rows.filter((c) => c.severity !== "info")),
    xss: scoreRows(xssRows),
    recon: scoreRows(reconRows.filter((r) => r.severity !== "info")),
  };
  const overallScore = Math.round(
    (scores.headers + scores.cookies + scores.tls + scores.sessions + scores.csrf + scores.xss + scores.recon) / 7,
  );

  const evidence: ScanEvidence = {
    primary: primaryEvidence,
    setCookies,
    forms: csrfResult.forms,
    mixedContentRefs: mixed.refs,
    xssProbe: reflected.evidence,
    corsProbe: cors.evidence,
    exposure: exposure.evidence,
    meta: meta.evidence,
    redirect: redirect.evidence,
    crtsh: certResult.entries,
  };

  return {
    targetUrl: url.toString(), targetHost: url.host, status: "complete",
    durationMs: Date.now() - start, overallScore, scores,
    headers: headerRows, cookies: cookieRows, tls,
    csrf: csrfResult.rows, xss: xssRows, sessions: sessionRows, recon: reconRows,
    evidence, error: null,
  };
}

export const runScan = createServerFn({ method: "POST" })
  .middleware([requireSupabaseAuth])
  .inputValidator((data: { url: string }) => urlSchema.parse(data))
  .handler(async ({ data, context }): Promise<ScanResult> => {
    const scan = await performScan(data.url);
    const payload = {
      user_id: context.userId,
      target_url: scan.targetUrl,
      target_host: scan.targetHost,
      status: scan.status,
      duration_ms: scan.durationMs,
      overall_score: scan.overallScore,
      scores: scan.scores,
      headers: scan.headers,
      cookies: scan.cookies,
      tls: scan.tls,
      csrf: scan.csrf,
      xss: scan.xss,
      sessions: scan.sessions,
      recon: scan.recon,
      evidence: scan.evidence,
      error: scan.error,
    };
    const { data: row, error } = await context.supabase
      .from("scans")
      // eslint-disable-next-line @typescript-eslint/no-explicit-any
      .insert(payload as any)
      .select("id, created_at")
      .single();
    if (error) throw new Error(error.message);
    return { ...scan, id: row.id as string, createdAt: row.created_at as string };
  });
