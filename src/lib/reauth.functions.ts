import { createServerFn } from "@tanstack/react-start";
import { z } from "zod";

import { requireSupabaseAuth } from "@/integrations/supabase/auth-middleware";

const UA = "NSL-ReauthProbe/1.0";
const BODY_CAP = 12_000;

const InputSchema = z.object({
  loginUrl: z.string().url(),
  usernameField: z.string().min(1).max(200),
  passwordField: z.string().min(1).max(200),
  username: z.string().min(1).max(500),
  password: z.string().min(1).max(500),
  protectedUrl: z.string().url(),
  loggedOutMarker: z.string().max(500).optional(),
  loggedInMarker: z.string().max(500).optional(),
  logoutUrl: z.string().url().optional(),
  extraFields: z.record(z.string(), z.string()).optional(),
}).refine(
  (v) => v.loginUrl.startsWith("https://") && v.protectedUrl.startsWith("https://"),
  "URLs must use https://",
);

export interface CookieAttrs {
  name: string;
  value: string;
  domain: string | null;
  path: string | null;
  expires: string | null;
  maxAge: string | null;
  httpOnly: boolean;
  secure: boolean;
  sameSite: string | null;
  raw: string;
}

export interface ReauthStep {
  label: string;
  method: string;
  url: string;
  status: number | null;
  finalUrl: string | null;
  requestHeaders: Record<string, string>;
  responseHeaders: Record<string, string>;
  setCookies: string[];
  bodySnippet: string;
  bodyBytes: number;
  bodyTruncated: boolean;
  cookieJarBefore: string;
  cookieJarAfter: string;
  error: string | null;
}

export interface ReauthResult {
  ranAt: string;
  loginUrl: string;
  protectedUrl: string;
  steps: ReauthStep[];
  issuedCookies: CookieAttrs[];
  sessionRotated: boolean | null;
  preLoginSessionCookies: string[];
  postLoginSessionCookies: string[];
  reauthorized: boolean;
  reauthReason: string;
  logoutInvalidatesServerSide: boolean | null;
  logoutReason: string | null;
  markers: { loggedIn?: string; loggedOut?: string };
}

function parseSetCookie(line: string): CookieAttrs {
  const parts = line.split(";").map((p) => p.trim());
  const [nameValue, ...attrParts] = parts;
  const eq = nameValue.indexOf("=");
  const name = eq >= 0 ? nameValue.slice(0, eq).trim() : nameValue.trim();
  const value = eq >= 0 ? nameValue.slice(eq + 1).trim() : "";
  const attrs: Record<string, string | boolean> = {};
  for (const p of attrParts) {
    const i = p.indexOf("=");
    if (i < 0) attrs[p.toLowerCase()] = true;
    else attrs[p.slice(0, i).toLowerCase()] = p.slice(i + 1);
  }
  return {
    name,
    value,
    domain: (attrs["domain"] as string) ?? null,
    path: (attrs["path"] as string) ?? null,
    expires: (attrs["expires"] as string) ?? null,
    maxAge: (attrs["max-age"] as string) ?? null,
    httpOnly: attrs["httponly"] === true,
    secure: attrs["secure"] === true,
    sameSite: (attrs["samesite"] as string) ?? null,
    raw: line,
  };
}

/** Cloudflare Workers exposes multiple Set-Cookie via getSetCookie(). */
function getSetCookieLines(h: Headers): string[] {
  const withGetter = h as unknown as { getSetCookie?: () => string[] };
  if (typeof withGetter.getSetCookie === "function") return withGetter.getSetCookie();
  const raw = h.get("set-cookie");
  return raw ? [raw] : [];
}

const SESSION_HINTS = /(sess|sid|token|auth|jwt|csrf|xsrf|jsessionid|phpsessid|asp\.net_sessionid)/i;

function isSessionish(name: string): boolean {
  return SESSION_HINTS.test(name);
}

function dumpHeaders(h: Headers): Record<string, string> {
  const out: Record<string, string> = {};
  h.forEach((v, k) => { out[k] = out[k] ? `${out[k]}, ${v}` : v; });
  return out;
}

async function snippet(res: Response) {
  try {
    const raw = await res.text();
    const truncated = raw.length > BODY_CAP;
    return { text: truncated ? raw.slice(0, BODY_CAP) : raw, bytes: raw.length, truncated };
  } catch {
    return { text: "", bytes: 0, truncated: false };
  }
}

/** Merge Set-Cookie lines into a jar keyed by name (latest wins). */
function applyToJar(jar: Map<string, string>, lines: string[]) {
  for (const line of lines) {
    const parsed = parseSetCookie(line);
    if (!parsed.name) continue;
    // A cookie deleted by expiration/Max-Age=0
    if (parsed.maxAge === "0" || (parsed.expires && new Date(parsed.expires).getTime() < Date.now())) {
      jar.delete(parsed.name);
      continue;
    }
    jar.set(parsed.name, parsed.value);
  }
}

function jarString(jar: Map<string, string>): string {
  return [...jar.entries()].map(([k, v]) => `${k}=${v}`).join("; ");
}

async function step(
  label: string,
  method: string,
  url: string,
  init: RequestInit,
  jar: Map<string, string>,
): Promise<ReauthStep> {
  const cookieJarBefore = jarString(jar);
  const headers = new Headers(init.headers);
  if (cookieJarBefore) headers.set("cookie", cookieJarBefore);
  if (!headers.has("user-agent")) headers.set("user-agent", UA);
  if (!headers.has("accept")) headers.set("accept", "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8");

  const reqHeaders = dumpHeaders(headers);
  try {
    const res = await fetch(url, { ...init, method, headers, redirect: "manual" });
    const setCookies = getSetCookieLines(res.headers);
    applyToJar(jar, setCookies);
    const body = await snippet(res);
    return {
      label, method, url,
      status: res.status,
      finalUrl: res.headers.get("location") ?? url,
      requestHeaders: reqHeaders,
      responseHeaders: dumpHeaders(res.headers),
      setCookies,
      bodySnippet: body.text,
      bodyBytes: body.bytes,
      bodyTruncated: body.truncated,
      cookieJarBefore,
      cookieJarAfter: jarString(jar),
      error: null,
    };
  } catch (e) {
    return {
      label, method, url,
      status: null, finalUrl: null,
      requestHeaders: reqHeaders,
      responseHeaders: {},
      setCookies: [],
      bodySnippet: "",
      bodyBytes: 0,
      bodyTruncated: false,
      cookieJarBefore,
      cookieJarAfter: jarString(jar),
      error: e instanceof Error ? e.message : String(e),
    };
  }
}

export const runReauthProbe = createServerFn({ method: "POST" })
  .middleware([requireSupabaseAuth])
  .inputValidator((data: z.infer<typeof InputSchema>) => InputSchema.parse(data))
  .handler(async ({ data }): Promise<ReauthResult> => {
    const jar = new Map<string, string>();
    const steps: ReauthStep[] = [];

    // 1. Baseline GET login page (harvest any pre-login session cookie / hidden CSRF)
    const s1 = await step("Baseline GET login page", "GET", data.loginUrl, {}, jar);
    steps.push(s1);
    const preLoginSessionCookies = [...jar.keys()].filter(isSessionish);

    // 2. Submit credentials as urlencoded form
    const form = new URLSearchParams();
    form.set(data.usernameField, data.username);
    form.set(data.passwordField, data.password);
    if (data.extraFields) {
      for (const [k, v] of Object.entries(data.extraFields)) form.set(k, v);
    }
    const s2 = await step("POST login form", "POST", data.loginUrl, {
      body: form.toString(),
      headers: { "content-type": "application/x-www-form-urlencoded" },
    }, jar);
    steps.push(s2);

    const issuedFromLogin: CookieAttrs[] = s2.setCookies.map(parseSetCookie);
    const postLoginSessionCookies = [...jar.keys()].filter(isSessionish);

    // Follow one redirect if login returned 3xx (common pattern)
    if (s2.status && s2.status >= 300 && s2.status < 400) {
      const loc = s2.responseHeaders["location"];
      if (loc) {
        const next = new URL(loc, data.loginUrl).toString();
        steps.push(await step("Follow login redirect", "GET", next, {}, jar));
      }
    }

    // 3. Fresh replay against protected URL using ONLY the jar
    const s3 = await step("Replay cookies to protected URL", "GET", data.protectedUrl, {}, jar);
    steps.push(s3);

    // Determine reauth success
    let reauthorized = false;
    let reauthReason = "";
    const body = s3.bodySnippet;
    if (data.loggedInMarker && body.includes(data.loggedInMarker)) {
      reauthorized = true;
      reauthReason = `Body contains logged-in marker "${data.loggedInMarker}".`;
    } else if (data.loggedOutMarker && body.includes(data.loggedOutMarker)) {
      reauthorized = false;
      reauthReason = `Body contains logged-out marker "${data.loggedOutMarker}".`;
    } else if (s3.status && s3.status >= 200 && s3.status < 300) {
      reauthorized = true;
      reauthReason = `Protected URL returned ${s3.status} with cookies replayed.`;
    } else if (s3.status && s3.status >= 300 && s3.status < 400) {
      const loc = (s3.responseHeaders["location"] ?? "").toLowerCase();
      reauthorized = !/login|sign[-_ ]?in|auth/.test(loc);
      reauthReason = `Protected URL returned ${s3.status} → ${loc || "(no Location)"}.`;
    } else {
      reauthorized = false;
      reauthReason = `Protected URL returned ${s3.status ?? "no response"}.`;
    }

    // Session fixation check
    let sessionRotated: boolean | null = null;
    if (preLoginSessionCookies.length && postLoginSessionCookies.length) {
      sessionRotated = preLoginSessionCookies.some((n) => {
        const before = s1.setCookies.find((l) => parseSetCookie(l).name === n);
        const after = s2.setCookies.find((l) => parseSetCookie(l).name === n);
        return before && after && parseSetCookie(before).value !== parseSetCookie(after).value;
      }) || postLoginSessionCookies.some((n) => !preLoginSessionCookies.includes(n));
    }

    // 4. Optional logout + replay old cookies
    let logoutInvalidatesServerSide: boolean | null = null;
    let logoutReason: string | null = null;
    if (data.logoutUrl) {
      const snapshotJar = new Map(jar);
      const logoutStep = await step("Logout", "GET", data.logoutUrl, {}, jar);
      steps.push(logoutStep);
      // Replay pre-logout jar (server-side invalidation test)
      const replay = await step(
        "Replay pre-logout cookies to protected URL",
        "GET",
        data.protectedUrl,
        {},
        new Map(snapshotJar),
      );
      steps.push(replay);
      if (data.loggedOutMarker && replay.bodySnippet.includes(data.loggedOutMarker)) {
        logoutInvalidatesServerSide = true;
        logoutReason = `Replay body contains logged-out marker after logout.`;
      } else if (replay.status && replay.status >= 300 && replay.status < 400) {
        const loc = (replay.responseHeaders["location"] ?? "").toLowerCase();
        logoutInvalidatesServerSide = /login|sign[-_ ]?in|auth/.test(loc);
        logoutReason = `Replay redirected ${replay.status} → ${loc}.`;
      } else if (replay.status && replay.status >= 200 && replay.status < 300) {
        logoutInvalidatesServerSide = false;
        logoutReason = `Replay returned ${replay.status} with old cookies — session likely still valid server-side.`;
      } else {
        logoutInvalidatesServerSide = null;
        logoutReason = `Replay returned ${replay.status ?? "no response"} — indeterminate.`;
      }
    }

    return {
      ranAt: new Date().toISOString(),
      loginUrl: data.loginUrl,
      protectedUrl: data.protectedUrl,
      steps,
      issuedCookies: issuedFromLogin,
      sessionRotated,
      preLoginSessionCookies,
      postLoginSessionCookies,
      reauthorized,
      reauthReason,
      logoutInvalidatesServerSide,
      logoutReason,
      markers: { loggedIn: data.loggedInMarker, loggedOut: data.loggedOutMarker },
    };
  });
