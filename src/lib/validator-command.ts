import type { ProbeStep } from "@/lib/http-probe.server";

/** Shell-quote a value for a single-quoted bash literal. */
function q(s: string): string {
  return `'${s.replace(/'/g, `'\\''`)}'`;
}

/**
 * Build the exact curl invocation that reproduces a probe step.
 * The scanner uses fetch() with redirect:"manual"; the equivalent curl flags are:
 *   -sS         quiet progress, still show errors
 *   -i          include response headers in output
 *   --max-redirs 0 + no -L  → do not follow redirects (matches redirect:"manual")
 *   -X METHOD   explicit method
 *   -H k:v      each request header captured by the probe
 *   --data-raw  raw body if the step had one
 */
export function toCurl(step: ProbeStep, body?: string): string {
  const parts = ["curl", "-sS", "-i", "--max-redirs", "0", "-X", step.method];
  for (const [k, v] of Object.entries(step.requestHeaders)) {
    parts.push("-H", q(`${k}: ${v}`));
  }
  if (body && step.method !== "GET" && step.method !== "HEAD") {
    parts.push("--data-raw", q(body));
  } else if (step.method === "POST" && !body) {
    parts.push("--data-raw", q(""));
  }
  parts.push(q(step.url));
  return parts.join(" ");
}

export function verdictLabel(v: string): string {
  switch (v) {
    case "confirmed": return "Confirmed";
    case "not-exploitable": return "Not exploitable";
    case "inconclusive": return "Inconclusive";
    case "skipped": return "Skipped";
    case "error": return "Error";
    default: return v;
  }
}
