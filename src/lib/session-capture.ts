import type { CookieRow } from "./scan-types";

export interface CapturedCookie {
  name: string;
  value: string;
  /** True when this cookie was visible to JS on the target (from document.cookie). */
  jsVisible: boolean;
  /** Attributes inferred from server-side Set-Cookie evidence, when available. */
  attributes?: {
    domain?: string;
    path?: string;
    httpOnly?: boolean;
    secure?: boolean;
    sameSite?: string;
    expires?: string;
  };
  classification: CookieClass[];
  jwt?: DecodedJwt | null;
}

export type CookieClass = "session" | "auth" | "csrf" | "preference" | "unknown";

export interface DecodedJwt {
  header: Record<string, unknown>;
  payload: Record<string, unknown>;
  signaturePresent: boolean;
  expiresAt: string | null;
  issuer: string | null;
  subject: string | null;
}

export interface CapturedStorageEntry {
  key: string;
  value: string;
  classification: CookieClass[];
  jwt?: DecodedJwt | null;
  bytes: number;
}

export interface SessionSnapshot {
  href?: string;
  origin?: string;
  ua?: string;
  at?: string;
  cookies?: string;
  localStorage?: Record<string, string>;
  sessionStorage?: Record<string, string>;
}

export interface CaptureAnalysis {
  capturedAt: string;
  origin: string | null;
  href: string | null;
  ua: string | null;
  cookies: CapturedCookie[];
  localStorage: CapturedStorageEntry[];
  sessionStorage: CapturedStorageEntry[];
  summary: {
    sessionCookies: number;
    authTokens: number;
    csrfTokens: number;
    jwts: number;
    httpOnlyKnown: number;
    localStorageEntries: number;
    sessionStorageEntries: number;
  };
  warnings: string[];
  raw: SessionSnapshot;
}

const SESSION_NAME = /^(JSESSIONID|PHPSESSID|ASP\.NET_SessionId|ASPSESSIONID[A-Z]*|connect\.sid|laravel_session|ci_session|session|sess|sid|SESSIONID|SSESS[A-Za-z0-9]*|_shopify_.*session|sessionid)$/i;
const AUTH_NAME = /(auth|token|jwt|bearer|access[_-]?token|id[_-]?token|refresh[_-]?token|__Secure-|__Host-)/i;
const CSRF_NAME = /(csrf|xsrf|_token$|antiforgery|__RequestVerificationToken)/i;
const PREF_NAME = /(theme|locale|lang|consent|cookie[_-]?consent|_ga|_gid|_fbp)/i;
const JWT_RE = /^ey[A-Za-z0-9_-]+\.ey[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+$/;

function b64urlDecode(s: string): string {
  const pad = s.length % 4 === 0 ? "" : "=".repeat(4 - (s.length % 4));
  const b64 = (s + pad).replace(/-/g, "+").replace(/_/g, "/");
  try {
    if (typeof atob === "function") return decodeURIComponent(escape(atob(b64)));
    return Buffer.from(b64, "base64").toString("utf8");
  } catch {
    return "";
  }
}

export function tryDecodeJwt(value: string): DecodedJwt | null {
  if (!JWT_RE.test(value)) return null;
  const [h, p, s] = value.split(".");
  let header: Record<string, unknown> = {};
  let payload: Record<string, unknown> = {};
  try { header = JSON.parse(b64urlDecode(h)); } catch { return null; }
  try { payload = JSON.parse(b64urlDecode(p)); } catch { return null; }
  const exp = typeof payload.exp === "number" ? new Date(payload.exp * 1000).toISOString() : null;
  const iss = typeof payload.iss === "string" ? payload.iss : null;
  const sub = typeof payload.sub === "string" ? payload.sub : null;
  return { header, payload, signaturePresent: Boolean(s), expiresAt: exp, issuer: iss, subject: sub };
}

function classify(name: string, value: string): CookieClass[] {
  const cls: CookieClass[] = [];
  if (SESSION_NAME.test(name)) cls.push("session");
  if (CSRF_NAME.test(name)) cls.push("csrf");
  if (AUTH_NAME.test(name) || JWT_RE.test(value)) cls.push("auth");
  if (cls.length === 0 && PREF_NAME.test(name)) cls.push("preference");
  if (cls.length === 0) cls.push("unknown");
  return cls;
}

function parseCookieString(raw: string): { name: string; value: string }[] {
  if (!raw) return [];
  return raw.split(/;\s*/).filter(Boolean).map((pair) => {
    const eq = pair.indexOf("=");
    if (eq === -1) return { name: pair, value: "" };
    return { name: pair.slice(0, eq).trim(), value: pair.slice(eq + 1) };
  });
}

function attrsFromServerCookies(name: string, serverCookies: CookieRow[] | undefined) {
  if (!serverCookies) return undefined;
  const match = serverCookies.find((c) => c.name === name);
  if (!match) return undefined;
  return {
    domain: match.domain,
    path: match.path,
    httpOnly: match.httpOnly,
    secure: match.secure,
    sameSite: match.sameSite,
    expires: match.expires,
  };
}

export function analyzeSnapshot(
  snap: SessionSnapshot,
  serverCookies?: CookieRow[],
): CaptureAnalysis {
  const parsed = parseCookieString(snap.cookies ?? "");
  const cookies: CapturedCookie[] = parsed.map(({ name, value }) => {
    const jwt = tryDecodeJwt(value);
    return {
      name, value,
      jsVisible: true,
      attributes: attrsFromServerCookies(name, serverCookies),
      classification: classify(name, value),
      jwt,
    };
  });

  // Add server-observed cookies not visible from JS (HttpOnly-inferred).
  if (serverCookies) {
    for (const s of serverCookies) {
      if (cookies.some((c) => c.name === s.name)) continue;
      cookies.push({
        name: s.name,
        value: "— not visible to JS (likely HttpOnly) —",
        jsVisible: false,
        attributes: attrsFromServerCookies(s.name, serverCookies),
        classification: classify(s.name, ""),
        jwt: null,
      });
    }
  }

  const toStorage = (obj: Record<string, string> | undefined): CapturedStorageEntry[] => {
    if (!obj) return [];
    return Object.entries(obj).map(([k, v]) => ({
      key: k,
      value: v,
      bytes: (v ?? "").length,
      classification: classify(k, v ?? ""),
      jwt: tryDecodeJwt(v ?? ""),
    }));
  };

  const local = toStorage(snap.localStorage);
  const session = toStorage(snap.sessionStorage);

  const summary = {
    sessionCookies: cookies.filter((c) => c.classification.includes("session")).length,
    authTokens: cookies.filter((c) => c.classification.includes("auth")).length
      + local.filter((s) => s.classification.includes("auth")).length
      + session.filter((s) => s.classification.includes("auth")).length,
    csrfTokens: cookies.filter((c) => c.classification.includes("csrf")).length,
    jwts: [...cookies, ...local, ...session].filter((x) => x.jwt).length,
    httpOnlyKnown: cookies.filter((c) => c.attributes?.httpOnly).length,
    localStorageEntries: local.length,
    sessionStorageEntries: session.length,
  };

  const warnings: string[] = [];
  if (!snap.cookies) warnings.push("No cookies field in snapshot — the bookmarklet may have run on the wrong origin.");
  if (parsed.length === 0 && cookies.length === 0)
    warnings.push("Zero cookies visible. Either the site sets only HttpOnly cookies (invisible to JS) or you weren't logged in when the bookmarklet ran.");
  if (!serverCookies || serverCookies.length === 0)
    warnings.push("No server-side Set-Cookie evidence found. Run a server scan for this target to enrich cookie attributes (HttpOnly / Secure / SameSite).");

  return {
    capturedAt: snap.at ?? new Date().toISOString(),
    origin: snap.origin ?? null,
    href: snap.href ?? null,
    ua: snap.ua ?? null,
    cookies,
    localStorage: local,
    sessionStorage: session,
    summary,
    warnings,
    raw: snap,
  };
}

/** JavaScript source of the bookmarklet users run on the target tab. */
export function buildBookmarklet(): string {
  const src = `(function(){try{var d={href:location.href,origin:location.origin,ua:navigator.userAgent,at:new Date().toISOString(),cookies:document.cookie,localStorage:{},sessionStorage:{}};try{for(var i=0;i<localStorage.length;i++){var k=localStorage.key(i);d.localStorage[k]=localStorage.getItem(k);}}catch(e){}try{for(var j=0;j<sessionStorage.length;j++){var m=sessionStorage.key(j);d.sessionStorage[m]=sessionStorage.getItem(m);}}catch(e){}var s=JSON.stringify(d,null,2);var done=function(){alert('NSL: snapshot copied ('+s.length+' bytes). Paste into NOVAIN Security Lab \u2192 Live Session.');};if(navigator.clipboard&&navigator.clipboard.writeText){navigator.clipboard.writeText(s).then(done,function(){var w=window.open('','_blank');w.document.body.innerHTML='<pre style=\\'white-space:pre-wrap;font:12px monospace;padding:12px\\'>'+s.replace(/[&<>]/g,function(c){return{'&':'&amp;','<':'&lt;','>':'&gt;'}[c];})+'</pre>';});}else{var w=window.open('','_blank');w.document.body.innerHTML='<pre style=\\'white-space:pre-wrap;font:12px monospace;padding:12px\\'>'+s.replace(/[&<>]/g,function(c){return{'&':'&amp;','<':'&lt;','>':'&gt;'}[c];})+'</pre>';}}catch(err){alert('NSL bookmarklet error: '+err.message);}})();`;
  return "javascript:" + encodeURIComponent(src);
}
