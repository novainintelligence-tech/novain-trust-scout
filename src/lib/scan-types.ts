import type { Severity } from "@/components/severity-badge";

export interface HeaderRow {
  name: string;
  value: string | null;
  expected: string;
  severity: Severity;
  note: string;
}

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
  note?: string;
  raw?: string;
}

export interface TlsResult {
  host: string;
  scheme: "https" | "http";
  hstsPresent: boolean;
  hstsPreloaded: boolean;
  hstsMaxAge: number | null;
  hstsIncludeSubDomains: boolean;
  issuer: string | null;
  validFrom: string | null;
  validTo: string | null;
  daysRemaining: number | null;
  severity: Severity;
  note: string;
  rawHstsHeader?: string | null;
}

export interface CsrfCheck {
  endpoint: string;
  method: "POST" | "PUT" | "DELETE" | "PATCH" | "GET";
  tokenFound: boolean;
  sameSiteHint: "Strict" | "Lax" | "None" | "Unknown";
  severity: Severity;
  note: string;
  rawForm?: string;
}

export interface XssCase {
  id: string;
  vector: string;
  category: "CSP" | "Encoding" | "Headers" | "Reflected" | "CORS";
  severity: Severity;
  detail: string;
}

export interface SessionCheck {
  name: string;
  status: Severity;
  observation: string;
}

export type ReconCategory = "meta" | "exposure" | "mixed-content" | "redirect";

export interface ReconCheck {
  id: string;
  category: ReconCategory;
  name: string;
  severity: Severity;
  note: string;
  target?: string;
}

export interface ScoreBreakdown {
  headers: number;
  cookies: number;
  tls: number;
  sessions: number;
  csrf: number;
  xss: number;
  recon: number;
}

// ---- Raw evidence captured during the scan ----

export type HeadersDump = Record<string, string>;

export interface PrimaryResponseEvidence {
  requestUrl: string;
  finalUrl: string | null;
  status: number;
  statusText: string;
  httpVersion: string | null;
  redirected: boolean;
  contentType: string | null;
  bodyBytes: number;
  bodyTruncated: boolean;
  bodySnippet: string;
  headers: HeadersDump;
}

export interface PathProbeEvidence {
  path: string;
  requestUrl: string;
  method: string;
  status: number;
  statusText: string;
  headers: HeadersDump;
  bodySnippet: string;
  bodyBytes: number;
}

export interface XssProbeEvidence {
  requestUrl: string;
  payload: string;
  canary: string;
  status: number;
  statusText: string;
  contentType: string | null;
  headers: HeadersDump;
  reflectionMatch: string | null;
  bodySnippet: string;
}

export interface CorsProbeEvidence {
  requestUrl: string;
  requestOrigin: string;
  status: number;
  statusText: string;
  headers: HeadersDump;
}

export interface RedirectProbeEvidence {
  requestUrl: string;
  status: number;
  statusText: string;
  location: string | null;
  headers: HeadersDump;
}

export interface CrtShEntry {
  issuer_name?: string;
  not_before?: string;
  not_after?: string;
  common_name?: string;
  name_value?: string;
}

export interface ScanEvidence {
  primary: PrimaryResponseEvidence | null;
  setCookies: string[];
  forms: string[];
  mixedContentRefs: string[];
  xssProbe: XssProbeEvidence | null;
  corsProbe: CorsProbeEvidence | null;
  exposure: PathProbeEvidence[];
  meta: PathProbeEvidence[];
  redirect: RedirectProbeEvidence | null;
  crtsh: CrtShEntry[] | null;
}

export interface ScanResult {
  id: string;
  targetUrl: string;
  targetHost: string;
  status: "complete" | "error";
  durationMs: number | null;
  overallScore: number;
  scores: ScoreBreakdown;
  headers: HeaderRow[];
  cookies: CookieRow[];
  tls: TlsResult;
  csrf: CsrfCheck[];
  xss: XssCase[];
  sessions: SessionCheck[];
  recon: ReconCheck[];
  evidence: ScanEvidence;
  error: string | null;
  createdAt: string;
}
