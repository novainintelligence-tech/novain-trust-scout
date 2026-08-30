import type { ScanResult } from "./scan-types";
import { buildEngagementSummary, type Finding } from "./engagement";

// ---------- Plain JSON export ----------

export interface JsonReport {
  tool: { name: string; version: string };
  generatedAt: string;
  target: { url: string; host: string };
  scan: { id: string; createdAt: string; durationMs: number | null; overallScore: number };
  totals: ReturnType<typeof buildEngagementSummary>["totals"];
  strengths: string[];
  assets: string[];
  findings: Array<Finding & { cvss31: { score: number; vector: string } }>;
  raw: ScanResult;
}

export function buildJsonReport(scan: ScanResult): JsonReport {
  const s = buildEngagementSummary(scan);
  return {
    tool: { name: "NOVAIN Security Lab", version: "1.0.0" },
    generatedAt: new Date().toISOString(),
    target: { url: s.targetUrl, host: s.targetHost },
    scan: { id: scan.id, createdAt: scan.createdAt, durationMs: scan.durationMs, overallScore: s.overallScore },
    totals: s.totals,
    strengths: s.strengths,
    assets: s.assets,
    findings: s.findings.map((f) => ({ ...f, cvss31: { score: f.cvss, vector: f.cvssVector } })),
    raw: scan,
  };
}

// ---------- SARIF 2.1.0 export ----------
// https://docs.oasis-open.org/sarif/sarif/v2.1.0/os/sarif-v2.1.0-os.html

type SarifLevel = "error" | "warning" | "note" | "none";

function sarifLevel(risk: Finding["risk"]): SarifLevel {
  if (risk === "Critical" || risk === "High") return "error";
  if (risk === "Medium") return "warning";
  if (risk === "Low") return "note";
  return "none";
}

function ruleId(f: Finding): string {
  return `NSL-${f.module.replace(/[^A-Za-z0-9]+/g, "-").toUpperCase()}-${f.id
    .replace(/[^A-Za-z0-9]+/g, "-").toUpperCase()}`;
}

export function buildSarifReport(scan: ScanResult) {
  const s = buildEngagementSummary(scan);
  const rulesMap = new Map<string, {
    id: string; name: string; shortDescription: { text: string };
    fullDescription: { text: string }; help: { text: string };
    properties: { "security-severity": string; cvss31Vector: string };
    defaultConfiguration: { level: SarifLevel };
  }>();

  const results = s.findings.map((f) => {
    const id = ruleId(f);
    if (!rulesMap.has(id)) {
      rulesMap.set(id, {
        id,
        name: `${f.module}: ${f.title}`.slice(0, 200),
        shortDescription: { text: f.title },
        fullDescription: { text: f.impact },
        help: { text: f.remediation },
        properties: {
          "security-severity": f.cvss.toFixed(1),
          cvss31Vector: f.cvssVector,
        },
        defaultConfiguration: { level: sarifLevel(f.risk) },
      });
    }
    return {
      ruleId: id,
      level: sarifLevel(f.risk),
      message: { text: f.title },
      properties: {
        risk: f.risk,
        cvss31Score: f.cvss,
        cvss31Vector: f.cvssVector,
        module: f.module,
      },
      locations: [{
        physicalLocation: {
          artifactLocation: { uri: s.targetUrl },
        },
      }],
      partialFingerprints: { finding: f.id },
      // Evidence in the SARIF-standard 'attachments' as plain text.
      attachments: [{
        description: { text: "Evidence captured during scan" },
        artifactLocation: { uri: s.targetUrl },
        // Non-standard but harmless additional property
      }],
      // Also attach as message additional field
      analysisTarget: { uri: s.targetUrl },
      hostedViewerUri: undefined,
      // Verbose evidence
      properties_evidence: f.evidence,
    };
  });

  return {
    version: "2.1.0",
    $schema: "https://json.schemastore.org/sarif-2.1.0.json",
    runs: [{
      tool: {
        driver: {
          name: "NOVAIN Security Lab",
          version: "1.0.0",
          informationUri: "https://novain.security",
          rules: Array.from(rulesMap.values()),
        },
      },
      invocations: [{
        executionSuccessful: scan.status === "complete",
        endTimeUtc: scan.createdAt,
      }],
      originalUriBaseIds: {
        TARGET: { uri: s.targetUrl },
      },
      results,
      properties: {
        overallScore: s.overallScore,
        totals: s.totals,
      },
    }],
  };
}

// ---------- Download helpers ----------

function downloadBlob(name: string, mime: string, content: string) {
  const blob = new Blob([content], { type: mime });
  const url = URL.createObjectURL(blob);
  const a = document.createElement("a");
  a.href = url;
  a.download = name;
  document.body.appendChild(a);
  a.click();
  a.remove();
  setTimeout(() => URL.revokeObjectURL(url), 1000);
}

function ts(): string {
  return new Date().toISOString().replace(/[:.]/g, "-").slice(0, 19);
}

export function downloadJsonReport(scan: ScanResult) {
  downloadBlob(
    `nsl-report-${scan.targetHost}-${ts()}.json`,
    "application/json",
    JSON.stringify(buildJsonReport(scan), null, 2),
  );
}

export function downloadSarifReport(scan: ScanResult) {
  downloadBlob(
    `nsl-report-${scan.targetHost}-${ts()}.sarif`,
    "application/sarif+json",
    JSON.stringify(buildSarifReport(scan), null, 2),
  );
}
