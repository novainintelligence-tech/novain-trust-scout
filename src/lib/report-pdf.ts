import { jsPDF } from "jspdf";

import type { ScanResult } from "./scan-types";
import { buildEngagementSummary, type Finding } from "./engagement";

const M = 40;

interface Cursor { y: number }

function ensure(doc: jsPDF, c: Cursor, needed: number) {
  const pageH = doc.internal.pageSize.getHeight();
  if (c.y + needed > pageH - M) { doc.addPage(); c.y = M; }
}

function text(doc: jsPDF, c: Cursor, str: string, opts?: { size?: number; bold?: boolean; color?: [number, number, number] }) {
  const size = opts?.size ?? 10;
  doc.setFontSize(size);
  doc.setFont("helvetica", opts?.bold ? "bold" : "normal");
  const [r, g, b] = opts?.color ?? [30, 41, 59];
  doc.setTextColor(r, g, b);
  const pageW = doc.internal.pageSize.getWidth();
  const lines = doc.splitTextToSize(str, pageW - M * 2);
  ensure(doc, c, lines.length * (size + 2));
  doc.text(lines, M, c.y);
  c.y += lines.length * (size + 2);
}

function rule(doc: jsPDF, c: Cursor) {
  ensure(doc, c, 10);
  const pageW = doc.internal.pageSize.getWidth();
  doc.setDrawColor(203, 213, 225);
  doc.line(M, c.y, pageW - M, c.y);
  c.y += 8;
}

function h(doc: jsPDF, c: Cursor, title: string, level: 1 | 2 = 1) {
  c.y += level === 1 ? 10 : 6;
  text(doc, c, title, { size: level === 1 ? 13 : 11, bold: true, color: [15, 23, 42] });
  if (level === 1) rule(doc, c);
}

function riskColor(risk: string): [number, number, number] {
  if (risk === "Critical") return [140, 20, 20];
  if (risk === "High") return [190, 45, 45];
  if (risk === "Medium") return [180, 120, 20];
  if (risk === "Low") return [16, 122, 87];
  return [82, 96, 122];
}

function finding(doc: jsPDF, c: Cursor, i: number, f: Finding, variant: ReportVariant) {
  ensure(doc, c, 60);
  text(doc, c, `${i}. [${f.risk}] ${f.title}`, { size: 11, bold: true, color: riskColor(f.risk) });
  text(doc, c, `Module: ${f.module}  ·  CVSS 3.1: ${f.cvss.toFixed(1)}  ·  Severity: ${f.severity.toUpperCase()}`, { size: 9, color: [82, 96, 122] });
  if (variant === "technical") {
    text(doc, c, f.cvssVector, { size: 8, color: [110, 120, 140] });
  }
  text(doc, c, "Impact:", { size: 9, bold: true });
  text(doc, c, f.impact, { size: 9 });
  if (variant === "technical") {
    text(doc, c, "Evidence:", { size: 9, bold: true });
    text(doc, c, f.evidence, { size: 9, color: [70, 80, 100] });
  }
  text(doc, c, "Remediation:", { size: 9, bold: true });
  text(doc, c, f.remediation, { size: 9 });
  c.y += 6;
}

export type ReportVariant = "executive" | "technical";

export function generateEngagementPdf(scan: ScanResult, variant: ReportVariant = "technical"): jsPDF {
  const s = buildEngagementSummary(scan);
  const doc = new jsPDF({ unit: "pt", format: "a4" });
  const c: Cursor = { y: M };
  const isExec = variant === "executive";

  // Cover
  text(doc, c, "NOVAIN Security Lab", { size: 20, bold: true, color: [15, 23, 42] });
  text(doc, c, isExec ? "Executive Security Summary" : "Penetration Test Engagement Report", { size: 12, color: [82, 96, 122] });
  c.y += 10;
  text(doc, c, `Target: ${s.targetUrl}`, { bold: true });
  text(doc, c, `Host:   ${s.targetHost}`);
  text(doc, c, `Report date: ${new Date().toLocaleString()}`);
  text(doc, c, `Scan performed: ${new Date(s.scannedAt).toLocaleString()}`);
  text(doc, c, `Report variant: ${isExec ? "Executive (non-technical)" : "Technical (full evidence)"}`, { size: 9, color: [110, 120, 140] });
  rule(doc, c);

  // 1. Executive summary
  h(doc, c, "1. Executive Summary");
  text(doc, c,
    `Overall security posture score: ${s.overallScore}/100. This assessment identified ${s.findings.length} findings across HTTP headers, cookies, TLS, CSRF, XSS, session handling, and reconnaissance surfaces.`);
  text(doc, c,
    `Severity breakdown: Critical=${s.totals.critical}  High=${s.totals.high}  Medium=${s.totals.medium}  Low=${s.totals.low}  Info=${s.totals.info}.`);
  if (s.strengths.length) {
    h(doc, c, "Observed strengths", 2);
    for (const st of s.strengths) text(doc, c, `• ${st}`);
  }

  if (isExec) {
    // Executive: prioritized action list only, no evidence dump.
    h(doc, c, "2. Prioritized Actions");
    const top = s.findings.slice(0, 8);
    if (top.length === 0) {
      text(doc, c, "No actions required from automated coverage. Maintain current posture.");
    } else {
      top.forEach((f, i) => {
        text(doc, c, `${i + 1}. [${f.risk}] ${f.title}`, { bold: true, color: riskColor(f.risk) });
        text(doc, c, `Business impact: ${f.impact}`, { size: 9 });
        text(doc, c, `Recommended fix: ${f.remediation}`, { size: 9 });
        c.y += 4;
      });
    }

    h(doc, c, "3. Residual Risk & Next Steps");
    text(doc, c,
      "Automated scanning cannot confirm business-logic flaws, chained multi-step exploits, authenticated-only surfaces, or issues behind rate limits and WAFs. A manual engagement is recommended to cover authenticated workflows, privilege boundaries, and application-specific logic. Re-run the assessment after remediation to confirm resolution.");
  } else {
    // 2. Scope & methodology
    h(doc, c, "2. Scope & Methodology");
    text(doc, c, `In-scope target: ${s.targetUrl}`);
    text(doc, c,
      "Methodology follows a seven-phase workflow adapted from OWASP WSTG, OSSTMM, PTES, and NIST SP 800-115: Scoping & Rules of Engagement, Reconnaissance, Enumeration, Vulnerability Identification, Validation, Post-Validation Analysis, and Reporting. Testing was limited to passive and safe active checks issued by the NOVAIN Security Lab scanner against the authorized target only.");

    h(doc, c, "3. Asset Inventory");
    for (const a of s.assets) text(doc, c, `• ${a}`);

    h(doc, c, "4. Attack Surface Summary");
    text(doc, c, `Headers evaluated: ${scan.headers.length}`);
    text(doc, c, `Cookies observed: ${scan.cookies.length}`);
    text(doc, c, `Forms detected: ${scan.csrf.length}`);
    text(doc, c, `XSS test cases: ${scan.xss.length}`);
    text(doc, c, `Session checks: ${scan.sessions.length}`);
    text(doc, c, `Reconnaissance checks: ${scan.recon.length}`);

    h(doc, c, `5. Confirmed Findings (${s.findings.length})`);
    if (s.findings.length === 0) {
      text(doc, c, "No confirmed findings from automated checks. Manual testing recommended for business-logic coverage.");
    } else {
      s.findings.forEach((f, i) => finding(doc, c, i + 1, f, variant));
    }

    h(doc, c, "6. Risk Assessment (CVSS 3.1)");
    text(doc, c,
      "Findings are scored with CVSS 3.1 base metrics. Vectors are attached to each finding for re-scoring per environment. Ratings map to Critical (≥9.0), High (7.0–8.9), Medium (4.0–6.9), Low (0.1–3.9), Info (0.0).");

    h(doc, c, "7. Remediation Recommendations");
    if (s.findings.length === 0) {
      text(doc, c, "Maintain current posture. Re-run the scan after any material change to the origin, CDN, or auth stack.");
    } else {
      const groups = new Map<string, Finding[]>();
      for (const f of s.findings) {
        const arr = groups.get(f.module) ?? [];
        arr.push(f);
        groups.set(f.module, arr);
      }
      for (const [mod, arr] of groups) {
        text(doc, c, `${mod} (${arr.length})`, { bold: true });
        text(doc, c, arr[0].remediation, { size: 9 });
        c.y += 4;
      }
    }

    h(doc, c, "8. Residual Risks");
    text(doc, c,
      "Automated scanning cannot confirm business-logic flaws, chained multi-step exploits, authenticated-only surfaces, or issues behind rate limits and WAFs. Consider a manual engagement to cover authenticated workflows, privilege boundaries, and application-specific logic.");

    h(doc, c, "9. Retest Checklist");
    text(doc, c, "After remediation, re-run the scan for the target and confirm each finding above has been resolved. Attach the follow-up report to this document for change history.");
  }

  // Footer
  const pages = doc.getNumberOfPages();
  for (let i = 1; i <= pages; i++) {
    doc.setPage(i);
    doc.setFontSize(8);
    doc.setTextColor(150, 160, 180);
    doc.text(
      `NSL ${isExec ? "Executive Summary" : "Engagement Report"} · ${s.targetHost} · page ${i}/${pages}`,
      M, doc.internal.pageSize.getHeight() - 20,
    );
  }

  return doc;
}

export function downloadEngagementPdf(scan: ScanResult, variant: ReportVariant = "technical") {
  const doc = generateEngagementPdf(scan, variant);
  const ts = new Date().toISOString().replace(/[:.]/g, "-").slice(0, 19);
  doc.save(`nsl-${variant}-${scan.targetHost}-${ts}.pdf`);
}

