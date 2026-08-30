import { jsPDF } from "jspdf";

import type { Finding } from "@/lib/engagement";
import type { ValidationResult } from "@/lib/validator.functions";
import { toCurl, verdictLabel } from "@/lib/validator-command";

const M = 40;

interface Cursor { y: number }

function ensureSpace(doc: jsPDF, c: Cursor, needed: number) {
  const pageH = doc.internal.pageSize.getHeight();
  if (c.y + needed > pageH - M) {
    doc.addPage();
    c.y = M;
  }
}

function text(doc: jsPDF, c: Cursor, str: string, opts?: { size?: number; bold?: boolean; color?: [number, number, number]; mono?: boolean }) {
  const size = opts?.size ?? 10;
  doc.setFontSize(size);
  doc.setFont(opts?.mono ? "courier" : "helvetica", opts?.bold ? "bold" : "normal");
  const [r, g, b] = opts?.color ?? [30, 41, 59];
  doc.setTextColor(r, g, b);
  const pageW = doc.internal.pageSize.getWidth();
  const wrapped = doc.splitTextToSize(str, pageW - M * 2);
  ensureSpace(doc, c, wrapped.length * (size + 2));
  doc.text(wrapped, M, c.y);
  c.y += wrapped.length * (size + 2);
}

function rule(doc: jsPDF, c: Cursor) {
  ensureSpace(doc, c, 10);
  const pageW = doc.internal.pageSize.getWidth();
  doc.setDrawColor(203, 213, 225);
  doc.line(M, c.y, pageW - M, c.y);
  c.y += 8;
}

function verdictColor(v: string): [number, number, number] {
  if (v === "confirmed") return [190, 45, 45];
  if (v === "not-exploitable") return [16, 122, 87];
  if (v === "inconclusive") return [180, 120, 20];
  if (v === "error") return [190, 45, 45];
  return [82, 96, 122];
}

export function generateValidatorPdf(
  targetHost: string,
  targetUrl: string,
  entries: Array<{ finding: Finding; result: ValidationResult }>,
): jsPDF {
  const doc = new jsPDF({ unit: "pt", format: "a4" });
  const c: Cursor = { y: M };

  text(doc, c, "NOVAIN Security Lab", { size: 18, bold: true, color: [15, 23, 42] });
  text(doc, c, "PoC Validation Report", { size: 11, color: [82, 96, 122] });
  c.y += 4;
  text(doc, c, `Target:    ${targetUrl}`, { size: 10, bold: true });
  text(doc, c, `Host:      ${targetHost}`, { size: 10 });
  text(doc, c, `Generated: ${new Date().toLocaleString()}`, { size: 10 });
  text(doc, c, `Findings:  ${entries.length}`, { size: 10 });
  rule(doc, c);

  // Summary counts
  const counts: Record<string, number> = {};
  for (const e of entries) counts[e.result.verdict] = (counts[e.result.verdict] ?? 0) + 1;
  text(doc, c, "Summary", { size: 13, bold: true });
  for (const [k, v] of Object.entries(counts)) {
    text(doc, c, `  ${verdictLabel(k)}: ${v}`, { size: 10, color: verdictColor(k) });
  }
  rule(doc, c);

  entries.forEach((e, i) => {
    const { finding, result } = e;
    c.y += 6;
    text(doc, c, `${i + 1}. ${finding.title}`, { size: 12, bold: true, color: [15, 23, 42] });
    text(doc, c,
      `Risk: ${finding.risk} · CVSS ${finding.cvss.toFixed(1)} · Module: ${finding.module} · ID: ${finding.id}`,
      { size: 9, color: [82, 96, 122] });
    text(doc, c, `Verdict: ${verdictLabel(result.verdict)}${result.active ? "  (ACTIVE TEST)" : ""}`,
      { size: 10, bold: true, color: verdictColor(result.verdict) });
    text(doc, c, `Ran at:  ${new Date(result.ranAt).toLocaleString()}`, { size: 9, color: [82, 96, 122] });
    if (result.summary) {
      c.y += 2;
      text(doc, c, "Summary", { size: 10, bold: true });
      text(doc, c, result.summary, { size: 9 });
    }
    if (result.poc) {
      c.y += 2;
      text(doc, c, "Method", { size: 10, bold: true });
      text(doc, c, result.poc, { size: 9 });
    }

    result.steps.forEach((s, si) => {
      c.y += 4;
      text(doc, c, `Step ${si + 1}: ${s.label}`, { size: 10, bold: true, color: [15, 23, 42] });
      text(doc, c, `${s.method} ${s.url} → ${s.status ?? "no response"}${s.error ? ` (${s.error})` : ""}`,
        { size: 9, color: [82, 96, 122] });

      // Exact reproducible command
      c.y += 2;
      text(doc, c, "Command (reproduces this request exactly):", { size: 9, bold: true });
      text(doc, c, toCurl(s), { size: 8, mono: true, color: [15, 23, 42] });

      if (Object.keys(s.responseHeaders).length > 0) {
        c.y += 2;
        text(doc, c, "Response headers", { size: 9, bold: true });
        text(doc, c,
          Object.entries(s.responseHeaders).map(([k, v]) => `${k}: ${v}`).join("\n"),
          { size: 8, mono: true });
      }
      if (s.setCookies.length > 0) {
        c.y += 2;
        text(doc, c, "Set-Cookie", { size: 9, bold: true });
        text(doc, c, s.setCookies.join("\n"), { size: 8, mono: true });
      }
      if (s.bodySnippet) {
        c.y += 2;
        text(doc, c, `Body (${s.bodyBytes} bytes${s.bodyTruncated ? ", truncated" : ""})`,
          { size: 9, bold: true });
        // Cap body in PDF to keep the report manageable.
        const snippet = s.bodySnippet.length > 2000 ? s.bodySnippet.slice(0, 2000) + "\n… [truncated in report]" : s.bodySnippet;
        text(doc, c, snippet, { size: 8, mono: true, color: [60, 70, 90] });
      }
    });

    rule(doc, c);
  });

  // Footer
  const pageCount = doc.getNumberOfPages();
  for (let i = 1; i <= pageCount; i++) {
    doc.setPage(i);
    doc.setFontSize(8);
    doc.setFont("helvetica", "normal");
    doc.setTextColor(150, 160, 180);
    doc.text(`NSL PoC Validation · ${targetHost} · page ${i}/${pageCount}`, M,
      doc.internal.pageSize.getHeight() - 20);
  }

  return doc;
}

export function downloadValidatorPdf(
  targetHost: string,
  targetUrl: string,
  entries: Array<{ finding: Finding; result: ValidationResult }>,
) {
  const doc = generateValidatorPdf(targetHost, targetUrl, entries);
  const ts = new Date().toISOString().replace(/[:.]/g, "-").slice(0, 19);
  doc.save(`nsl-validation-${targetHost}-${ts}.pdf`);
}
