// Shared HTTP probe helpers used by validator / reauth server functions.
// Lives in a .server.ts module so it can be safely imported by
// createServerFn handlers without hitting the tss-serverfn-split rule.

export const PROBE_UA = "NSL-Validator/1.0";
export const BODY_CAP = 12_000;

export function dumpHeaders(h: Headers): Record<string, string> {
  const out: Record<string, string> = {};
  h.forEach((v, k) => {
    out[k] = out[k] ? `${out[k]}, ${v}` : v;
  });
  return out;
}

export function getSetCookieLines(h: Headers): string[] {
  const withGetter = h as unknown as { getSetCookie?: () => string[] };
  if (typeof withGetter.getSetCookie === "function") return withGetter.getSetCookie();
  const raw = h.get("set-cookie");
  return raw ? [raw] : [];
}

export async function readBodySnippet(res: Response): Promise<{ text: string; bytes: number; truncated: boolean }> {
  try {
    const raw = await res.text();
    const truncated = raw.length > BODY_CAP;
    return { text: truncated ? raw.slice(0, BODY_CAP) : raw, bytes: raw.length, truncated };
  } catch {
    return { text: "", bytes: 0, truncated: false };
  }
}

export interface ProbeStep {
  label: string;
  method: string;
  url: string;
  status: number | null;
  requestHeaders: Record<string, string>;
  responseHeaders: Record<string, string>;
  setCookies: string[];
  bodySnippet: string;
  bodyBytes: number;
  bodyTruncated: boolean;
  error: string | null;
}

export async function probeStep(
  label: string,
  method: string,
  url: string,
  init: RequestInit = {},
  timeoutMs = 8000,
): Promise<ProbeStep> {
  const headers = new Headers(init.headers);
  if (!headers.has("user-agent")) headers.set("user-agent", PROBE_UA);
  if (!headers.has("accept")) headers.set("accept", "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8");
  const reqHeaders = dumpHeaders(headers);
  const ctrl = new AbortController();
  const t = setTimeout(() => ctrl.abort(), timeoutMs);
  try {
    const res = await fetch(url, {
      ...init,
      method,
      headers,
      redirect: "manual",
      signal: ctrl.signal,
    });
    const setCookies = getSetCookieLines(res.headers);
    const body = await readBodySnippet(res);
    return {
      label,
      method,
      url,
      status: res.status,
      requestHeaders: reqHeaders,
      responseHeaders: dumpHeaders(res.headers),
      setCookies,
      bodySnippet: body.text,
      bodyBytes: body.bytes,
      bodyTruncated: body.truncated,
      error: null,
    };
  } catch (e) {
    return {
      label,
      method,
      url,
      status: null,
      requestHeaders: reqHeaders,
      responseHeaders: {},
      setCookies: [],
      bodySnippet: "",
      bodyBytes: 0,
      bodyTruncated: false,
      error: e instanceof Error ? e.message : String(e),
    };
  } finally {
    clearTimeout(t);
  }
}
