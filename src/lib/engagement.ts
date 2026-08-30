import type { ScanResult } from "./scan-types";
import type { Severity } from "@/components/severity-badge";
import { rateFinding, type Cvss31Metrics } from "./cvss";

export type RiskRating = "Critical" | "High" | "Medium" | "Low" | "Info";

export interface Finding {
  id: string;
  module: string;
  title: string;
  severity: Severity;
  risk: RiskRating;
  cvss: number;
  cvssVector: string;
  cvssMetrics: Cvss31Metrics;
  evidence: string;
  impact: string;
  remediation: string;
}

export interface PhaseEvidence {
  pass: number;
  warn: number;
  fail: number;
}

export interface PhaseStatus {
  id: string;
  phase: number;
  name: string;
  objective: string;
  outputs: string[];
  modules: string[];
  status: "not-started" | "in-progress" | "complete";
  evidence: PhaseEvidence;
  nextDecision: string;
}

export const PHASES: Omit<PhaseStatus, "status" | "evidence">[] = [
  {
    id: "scoping",
    phase: 1,
    name: "Scoping & Rules of Engagement",
    objective: "Define target, authorization, timing, and success criteria.",
    outputs: ["Scope document", "Authorization confirmation"],
    modules: ["Target Selector"],
    nextDecision: "Begin assessment once scope is confirmed.",
  },
  {
    id: "recon",
    phase: 2,
    name: "Reconnaissance",
    objective: "Identify assets, technologies, and attack surface.",
    outputs: ["Asset inventory", "Attack surface map"],
    modules: ["Reconnaissance", "TLS Checker"],
    nextDecision: "Prioritize targets by exposure.",
  },
  {
    id: "enumeration",
    phase: 3,
    name: "Enumeration",
    objective: "Detail exposed services, endpoints, and configurations.",
    outputs: ["Header inventory", "Cookie inventory", "Form / endpoint list"],
    modules: ["HTTP Headers", "Cookie Inspector", "CSRF Validator"],
    nextDecision: "Identify candidate weaknesses.",
  },
  {
    id: "vuln-id",
    phase: 4,
    name: "Vulnerability Identification",
    objective: "Flag potential weaknesses using passive and safe active checks.",
    outputs: ["Candidate findings with raw evidence"],
    modules: ["XSS Test Suite", "Session Security", "HTTP Headers"],
    nextDecision: "Validate each finding before reporting.",
  },
  {
    id: "validation",
    phase: 5,
    name: "Validation",
    objective: "Confirm which candidates are real and assess exploitability.",
    outputs: ["Confirmed vs. false-positive log"],
    modules: ["Raw Evidence blocks on every module"],
    nextDecision: "Rate confirmed findings by risk.",
  },
  {
    id: "analysis",
    phase: 6,
    name: "Post-Validation Analysis",
    objective: "Evaluate impact on confidentiality, integrity, and availability.",
    outputs: ["Risk-rated findings", "Business impact notes"],
    modules: ["Engagement Report"],
    nextDecision: "Recommend remediation ordered by risk.",
  },
  {
    id: "reporting",
    phase: 7,
    name: "Reporting",
    objective: "Document scope, methodology, findings, evidence, and fixes.",
    outputs: ["Executive summary", "Full report PDF", "Retest checklist"],
    modules: ["Engagement Report", "Scan History"],
    nextDecision: "Retest after remediation is deployed.",
  },
];

function severityCounts(items: { severity: Severity }[]): PhaseEvidence {
  const e: PhaseEvidence = { pass: 0, warn: 0, fail: 0 };
  for (const i of items) {
    if (i.severity === "pass") e.pass += 1;
    else if (i.severity === "warn") e.warn += 1;
    else if (i.severity === "fail") e.fail += 1;
  }
  return e;
}

function sessionsAsSeverity(scan: ScanResult): { severity: Severity }[] {
  return scan.sessions.map((s) => ({ severity: s.status }));
}

function statusFrom(ev: PhaseEvidence, gated: boolean): PhaseStatus["status"] {
  if (gated) return "not-started";
  const total = ev.pass + ev.warn + ev.fail;
  if (total === 0) return "not-started";
  return "complete";
}

export function computePhases(scan: ScanResult | null | undefined, scopeConfirmed: boolean): PhaseStatus[] {
  const empty: PhaseEvidence = { pass: 0, warn: 0, fail: 0 };
  return PHASES.map((p) => {
    let ev = empty;
    let status: PhaseStatus["status"] = "not-started";
    if (!scan) {
      status = p.id === "scoping" && scopeConfirmed ? "complete" : "not-started";
      return { ...p, evidence: empty, status };
    }
    switch (p.id) {
      case "scoping":
        status = scopeConfirmed ? "complete" : "in-progress";
        break;
      case "recon":
        ev = severityCounts(scan.recon);
        status = statusFrom(ev, false);
        break;
      case "enumeration":
        ev = severityCounts([...scan.headers, ...scan.cookies, ...scan.csrf]);
        status = statusFrom(ev, false);
        break;
      case "vuln-id":
        ev = severityCounts([...scan.xss, ...sessionsAsSeverity(scan)]);
        status = statusFrom(ev, false);
        break;
      case "validation": {
        ev = severityCounts([
          ...scan.headers, ...scan.cookies, ...scan.csrf,
          ...scan.xss, ...sessionsAsSeverity(scan), ...scan.recon,
        ]);
        status = statusFrom(ev, false);
        break;
      }
      case "analysis":
      case "reporting":
        ev = { pass: 0, warn: 0, fail: 0 };
        status = "in-progress";
        break;
    }
    return { ...p, evidence: ev, status };
  });
}

function ratingFor(severity: Severity, module: string): { risk: RiskRating; cvss: number; cvssVector: string; cvssMetrics: Cvss31Metrics } {
  const sev = severity === "pass" ? "pass" : severity === "warn" ? "warn" : "fail";
  const r = rateFinding(module, sev);
  return { risk: r.severity, cvss: r.score, cvssVector: r.vector, cvssMetrics: r.metrics };
}

const REMEDIATION: Record<string, string> = {
  Headers: "Set the missing or weak security header on the origin server or CDN edge. Use a strict CSP, HSTS with a long max-age and includeSubDomains, X-Content-Type-Options: nosniff, and a Referrer-Policy of no-referrer or strict-origin-when-cross-origin.",
  Cookies: "Recreate the session cookie with Secure, HttpOnly, SameSite=Strict (or Lax where cross-site navigation is required), a scoped Domain/Path, and a __Host- or __Secure- prefix.",
  TLS: "Enforce HTTPS with a permanent redirect, enable HSTS with preload, and rotate the certificate before expiry. Disable legacy protocol versions and weak cipher suites on the terminating server or CDN.",
  CSRF: "Add a per-request anti-CSRF token to every state-changing form and API endpoint. Verify origin/referer on the server, and set SameSite on session cookies.",
  XSS: "Deploy a strict Content-Security-Policy (nonce or hash based), escape all user-controlled output at the correct sink, and remove inline event handlers or eval usage.",
  Session: "Rotate the session identifier on privilege change, set idle and absolute timeouts, invalidate on logout, and bind cookies with Secure + HttpOnly + SameSite.",
  Recon: "Remove or protect the exposed path. If the resource must remain reachable, place it behind authentication and add allowlist rules at the CDN or WAF.",
};

export function buildFindings(scan: ScanResult): Finding[] {
  const out: Finding[] = [];

  for (const h of scan.headers) {
    if (h.severity === "pass") continue;
    const r = ratingFor(h.severity, "Headers");
    out.push({
      id: `hdr-${h.name}`, module: "HTTP Headers", title: `${h.name} — ${h.note}`,
      severity: h.severity, ...r,
      evidence: `${h.name}: ${h.value ?? "— missing —"}\nExpected: ${h.expected}`,
      impact: "Weakens the browser's built-in protections against XSS, clickjacking, transport downgrade, or MIME-sniffing attacks.",
      remediation: REMEDIATION.Headers,
    });
  }
  for (const c of scan.cookies) {
    if (c.severity === "pass") continue;
    const r = ratingFor(c.severity, "Cookies");
    out.push({
      id: `cookie-${c.name}`, module: "Cookies", title: `${c.name} — ${c.note ?? "insecure flags"}`,
      severity: c.severity, ...r,
      evidence: c.raw ?? `${c.name}  HttpOnly=${c.httpOnly} Secure=${c.secure} SameSite=${c.sameSite}`,
      impact: "Session or auth cookies may be stolen via network sniffing or scripts, enabling account takeover.",
      remediation: REMEDIATION.Cookies,
    });
  }
  if (scan.tls.severity !== "pass") {
    const r = ratingFor(scan.tls.severity, "TLS");
    out.push({
      id: "tls-posture", module: "TLS", title: `TLS / HSTS posture — ${scan.tls.note}`,
      severity: scan.tls.severity, ...r,
      evidence: `Scheme=${scan.tls.scheme} HSTS=${scan.tls.hstsPresent} max-age=${scan.tls.hstsMaxAge ?? "—"} preload=${scan.tls.hstsPreloaded}\nIssuer=${scan.tls.issuer ?? "—"} Valid=${scan.tls.validFrom ?? "—"} → ${scan.tls.validTo ?? "—"}`,
      impact: "Traffic can be intercepted, downgraded, or tampered with; users may be phished via cert or protocol issues.",
      remediation: REMEDIATION.TLS,
    });
  }
  for (const cs of scan.csrf) {
    if (cs.severity === "pass") continue;
    const r = ratingFor(cs.severity, "CSRF");
    out.push({
      id: `csrf-${cs.endpoint}`, module: "CSRF", title: `${cs.method} ${cs.endpoint}`,
      severity: cs.severity, ...r,
      evidence: `${cs.note}\nToken=${cs.tokenFound} SameSite=${cs.sameSiteHint}${cs.rawForm ? `\n\n${cs.rawForm.slice(0, 500)}` : ""}`,
      impact: "An authenticated user could be tricked into performing this action from an attacker-controlled page.",
      remediation: REMEDIATION.CSRF,
    });
  }
  for (const x of scan.xss) {
    if (x.severity === "pass") continue;
    const r = ratingFor(x.severity, "XSS");
    out.push({
      id: `xss-${x.id}`, module: "XSS", title: `${x.category} — ${x.vector}`,
      severity: x.severity, ...r, evidence: x.detail,
      impact: "Script execution in a victim's browser leads to session theft, credential capture, or full account takeover.",
      remediation: REMEDIATION.XSS,
    });
  }
  for (const s of scan.sessions) {
    if (s.status === "pass") continue;
    const r = ratingFor(s.status, "Session");
    out.push({
      id: `session-${s.name}`, module: "Session", title: s.name,
      severity: s.status, ...r, evidence: s.observation,
      impact: "Weak session handling can allow session fixation, hijacking, or prolonged access after logout.",
      remediation: REMEDIATION.Session,
    });
  }
  for (const rc of scan.recon) {
    if (rc.severity === "pass") continue;
    const r = ratingFor(rc.severity, rc.category === "exposure" ? "Exposure" : "Recon");
    out.push({
      id: `recon-${rc.id}`, module: `Recon · ${rc.category}`, title: `${rc.name}${rc.target ? ` (${rc.target})` : ""}`,
      severity: rc.severity, ...r, evidence: rc.note,
      impact: rc.category === "exposure"
        ? "Sensitive files or configuration data are reachable without authentication."
        : "Missing hardening or metadata expands the usable attack surface.",
      remediation: REMEDIATION.Recon,
    });
  }

  const order: Record<RiskRating, number> = { Critical: 0, High: 1, Medium: 2, Low: 3, Info: 4 };
  return out.sort((a, b) => order[a.risk] - order[b.risk]);
}

export interface EngagementSummary {
  targetHost: string;
  targetUrl: string;
  scannedAt: string;
  overallScore: number;
  totals: { critical: number; high: number; medium: number; low: number; info: number };
  findings: Finding[];
  strengths: string[];
  assets: string[];
}

export function buildEngagementSummary(scan: ScanResult): EngagementSummary {
  const findings = buildFindings(scan);
  const totals = { critical: 0, high: 0, medium: 0, low: 0, info: 0 };
  for (const f of findings) {
    if (f.risk === "Critical") totals.critical += 1;
    else if (f.risk === "High") totals.high += 1;
    else if (f.risk === "Medium") totals.medium += 1;
    else if (f.risk === "Low") totals.low += 1;
    else totals.info += 1;
  }
  const strengths: string[] = [];
  if (scan.tls.severity === "pass") strengths.push(`TLS/HSTS posture strong (issuer: ${scan.tls.issuer ?? "—"}).`);
  if (scan.headers.filter((h) => h.severity === "pass").length >= 4)
    strengths.push("Majority of security headers configured correctly.");
  if (scan.cookies.length > 0 && scan.cookies.every((c) => c.severity === "pass"))
    strengths.push("All observed cookies use secure attributes.");
  if (findings.length === 0) strengths.push("No confirmed findings from automated checks.");

  const assets = [
    `Primary host: ${scan.targetHost}`,
    `Scheme: ${scan.tls.scheme.toUpperCase()}`,
    scan.tls.issuer ? `Certificate issuer: ${scan.tls.issuer}` : null,
    `Cookies observed: ${scan.cookies.length}`,
    `State-changing forms observed: ${scan.csrf.length}`,
    scan.evidence.exposure.length ? `Exposure probes: ${scan.evidence.exposure.length}` : null,
  ].filter(Boolean) as string[];

  return {
    targetHost: scan.targetHost,
    targetUrl: scan.targetUrl,
    scannedAt: scan.createdAt,
    overallScore: scan.overallScore,
    totals,
    findings,
    strengths,
    assets,
  };
}
