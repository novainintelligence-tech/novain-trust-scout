// CVSS 3.1 Base metric vector + score generator.
// Reference: https://www.first.org/cvss/v3.1/specification-document

export type AV = "N" | "A" | "L" | "P"; // Attack Vector
export type AC = "L" | "H";              // Attack Complexity
export type PR = "N" | "L" | "H";        // Privileges Required
export type UI = "N" | "R";              // User Interaction
export type S = "U" | "C";               // Scope
export type CIA = "N" | "L" | "H";       // C / I / A impact

export interface Cvss31Metrics {
  AV: AV; AC: AC; PR: PR; UI: UI; S: S;
  C: CIA; I: CIA; A: CIA;
}

const AV_W: Record<AV, number> = { N: 0.85, A: 0.62, L: 0.55, P: 0.2 };
const AC_W: Record<AC, number> = { L: 0.77, H: 0.44 };
const UI_W: Record<UI, number> = { N: 0.85, R: 0.62 };
const CIA_W: Record<CIA, number> = { N: 0, L: 0.22, H: 0.56 };
// PR weight depends on Scope
const PR_W_UNCH: Record<PR, number> = { N: 0.85, L: 0.62, H: 0.27 };
const PR_W_CHG:  Record<PR, number> = { N: 0.85, L: 0.68, H: 0.5 };

function roundUp1(x: number): number {
  // CVSS 3.1 "roundup" to one decimal
  const i = Math.round(x * 100000);
  if (i % 10000 === 0) return i / 100000;
  return (Math.floor(i / 10000) + 1) / 10;
}

export function cvss31BaseScore(m: Cvss31Metrics): number {
  const iss = 1 - (1 - CIA_W[m.C]) * (1 - CIA_W[m.I]) * (1 - CIA_W[m.A]);
  const impact = m.S === "U"
    ? 6.42 * iss
    : 7.52 * (iss - 0.029) - 3.25 * Math.pow(iss - 0.02, 15);
  const prW = m.S === "C" ? PR_W_CHG[m.PR] : PR_W_UNCH[m.PR];
  const exploitability = 8.22 * AV_W[m.AV] * AC_W[m.AC] * prW * UI_W[m.UI];
  if (impact <= 0) return 0;
  const base = m.S === "U"
    ? Math.min(impact + exploitability, 10)
    : Math.min(1.08 * (impact + exploitability), 10);
  return roundUp1(base);
}

export function cvss31Vector(m: Cvss31Metrics): string {
  return `CVSS:3.1/AV:${m.AV}/AC:${m.AC}/PR:${m.PR}/UI:${m.UI}/S:${m.S}/C:${m.C}/I:${m.I}/A:${m.A}`;
}

export function severityFromScore(score: number): "Critical" | "High" | "Medium" | "Low" | "Info" {
  if (score >= 9.0) return "Critical";
  if (score >= 7.0) return "High";
  if (score >= 4.0) return "Medium";
  if (score > 0)    return "Low";
  return "Info";
}

// ---- Module → default metrics (tunable, tuned per severity) ----

export function metricsForModule(
  module: string,
  severity: "pass" | "warn" | "fail",
): Cvss31Metrics {
  if (severity === "pass") {
    return { AV: "N", AC: "H", PR: "H", UI: "R", S: "U", C: "N", I: "N", A: "N" };
  }
  const warn = severity === "warn";
  const mod = module.toLowerCase();

  if (mod.includes("tls")) {
    return warn
      ? { AV: "N", AC: "H", PR: "N", UI: "N", S: "U", C: "L", I: "L", A: "N" }
      : { AV: "N", AC: "H", PR: "N", UI: "N", S: "C", C: "H", I: "H", A: "N" };
  }
  if (mod.includes("xss")) {
    return warn
      ? { AV: "N", AC: "L", PR: "N", UI: "R", S: "C", C: "L", I: "N", A: "N" }
      : { AV: "N", AC: "L", PR: "N", UI: "R", S: "C", C: "H", I: "L", A: "N" };
  }
  if (mod.includes("csrf")) {
    return warn
      ? { AV: "N", AC: "L", PR: "L", UI: "R", S: "U", C: "N", I: "L", A: "N" }
      : { AV: "N", AC: "L", PR: "N", UI: "R", S: "U", C: "L", I: "H", A: "N" };
  }
  if (mod.includes("cookie")) {
    return warn
      ? { AV: "N", AC: "H", PR: "N", UI: "R", S: "U", C: "L", I: "N", A: "N" }
      : { AV: "N", AC: "H", PR: "N", UI: "N", S: "U", C: "H", I: "L", A: "N" };
  }
  if (mod.includes("session")) {
    return warn
      ? { AV: "N", AC: "H", PR: "L", UI: "N", S: "U", C: "L", I: "N", A: "N" }
      : { AV: "N", AC: "L", PR: "N", UI: "N", S: "U", C: "H", I: "L", A: "N" };
  }
  if (mod.includes("exposure") || mod.includes("recon")) {
    return warn
      ? { AV: "N", AC: "L", PR: "N", UI: "N", S: "U", C: "L", I: "N", A: "N" }
      : { AV: "N", AC: "L", PR: "N", UI: "N", S: "U", C: "H", I: "N", A: "N" };
  }
  // Headers / default hardening gap
  return warn
    ? { AV: "N", AC: "H", PR: "N", UI: "R", S: "C", C: "L", I: "N", A: "N" }
    : { AV: "N", AC: "L", PR: "N", UI: "R", S: "C", C: "L", I: "L", A: "N" };
}

export interface CvssRating {
  score: number;
  vector: string;
  severity: ReturnType<typeof severityFromScore>;
  metrics: Cvss31Metrics;
}

export function rateFinding(module: string, severity: "pass" | "warn" | "fail"): CvssRating {
  const metrics = metricsForModule(module, severity);
  const score = cvss31BaseScore(metrics);
  return { score, vector: cvss31Vector(metrics), severity: severityFromScore(score), metrics };
}
