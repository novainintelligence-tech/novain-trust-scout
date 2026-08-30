import { jsPDF } from "jspdf";

import type { ScanResult } from "./scan-types";

const M = 40; // page margin
const LINE = 14;

interface Cursor { y: number; page: number }

function ensureSpace(doc: jsPDF, c: Cursor, needed: number) {
  const pageH = doc.internal.pageSize.getHeight();
  if (c.y + needed > pageH - M) {
    doc.addPage();
    c.page += 1;
    c.y = M;
  }
}

function text(doc: jsPDF, c: Cursor, str: string, opts?: { size?: number; bold?: boolean; color?: [number, number, number] }) {
  const size = opts?.size ?? 10;
  doc.setFontSize(size);
  doc.setFont("helvetica", opts?.bold ? "bold" : "normal");
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

function section(doc: jsPDF, c: Cursor, title: string) {
  ensureSpace(doc, c, 30);
  c.y += 6;
  text(doc, c, title, { size: 13, bold: true, color: [15, 23, 42] });
  rule(doc, c);
}

function sev(s: string): [number, number, number] {
  if (s === "pass") return [16, 122, 87];
  if (s === "warn") return [180, 120, 20];
  if (s === "fail") return [190, 45, 45];
  return [82, 96, 122];
}

function row(doc: jsPDF, c: Cursor, label: string, value: string, severity?: string) {
  ensureSpace(doc, c, LINE);
  doc.setFont("helvetica", "bold");
  doc.setFontSize(9);
  const [rr, gg, bb] = severity ? sev(severity) : [30, 41, 59];
  doc.setTextColor(rr, gg, bb);
  doc.text(`[${severity?.toUpperCase() ?? "•"}]`, M, c.y);
  doc.setFont("helvetica", "bold");
  doc.setTextColor(30, 41, 59);
  doc.text(label, M + 45, c.y);
  c.y += LINE;
  if (value) text(doc, c, value, { size: 9, color: [82, 96, 122] });
}

export function generateScanPdf(scan: ScanResult): jsPDF {
  const doc = new jsPDF({ unit: "pt", format: "a4" });
  const c: Cursor = { y: M, page: 1 };

  // Title block
  text(doc, c, "NOVAIN Security Lab", { size: 18, bold: true, color: [15, 23, 42] });
  text(doc, c, "Penetration Test Report", { size: 11, color: [82, 96, 122] });
  c.y += 6;
  text(doc, c, `Target: ${scan.targetUrl}`, { size: 10, bold: true });
  text(doc, c, `Host:   ${scan.targetHost}`, { size: 10 });
  text(doc, c, `Scanned: ${new Date(scan.createdAt).toLocaleString()}`, { size: 10 });
  text(doc, c, `Duration: ${scan.durationMs ?? "—"} ms · Status: ${scan.status}`, { size: 10 });
  if (scan.error) text(doc, c, `Error: ${scan.error}`, { size: 10, color: [190, 45, 45] });
  rule(doc, c);

  // Scores
  section(doc, c, `Overall score — ${scan.overallScore}/100`);
  for (const [k, v] of Object.entries(scan.scores)) {
    text(doc, c, `${k.padEnd(10)} ${v}/100`, { size: 10 });
  }

  // Headers
  section(doc, c, `HTTP Security Headers (${scan.headers.length})`);
  for (const h of scan.headers) {
    row(doc, c, h.name, `${h.value ?? "— missing —"}  ·  ${h.note}`, h.severity);
  }

  // Cookies
  section(doc, c, `Cookies (${scan.cookies.length})`);
  if (scan.cookies.length === 0) text(doc, c, "No cookies set.", { size: 9 });
  for (const ck of scan.cookies) {
    row(doc, c, ck.name,
      `Domain=${ck.domain}  Path=${ck.path}  HttpOnly=${ck.httpOnly}  Secure=${ck.secure}  SameSite=${ck.sameSite}  Expires=${ck.expires}${ck.note ? ` · ${ck.note}` : ""}`,
      ck.severity);
  }

  // TLS
  section(doc, c, "TLS / HSTS");
  row(doc, c, `${scan.tls.host} (${scan.tls.scheme.toUpperCase()})`, scan.tls.note, scan.tls.severity);
  text(doc, c,
    `HSTS: present=${scan.tls.hstsPresent}  max-age=${scan.tls.hstsMaxAge ?? "—"}  includeSubDomains=${scan.tls.hstsIncludeSubDomains}  preload=${scan.tls.hstsPreloaded}`,
    { size: 9 });
  text(doc, c,
    `Issuer: ${scan.tls.issuer ?? "—"}  ·  Valid: ${scan.tls.validFrom ?? "—"} → ${scan.tls.validTo ?? "—"}  ·  Days remaining: ${scan.tls.daysRemaining ?? "—"}`,
    { size: 9 });

  // CSRF
  section(doc, c, `CSRF findings (${scan.csrf.length})`);
  for (const cs of scan.csrf) {
    row(doc, c, `${cs.method} ${cs.endpoint}`,
      `Token=${cs.tokenFound}  SameSite=${cs.sameSiteHint}  ·  ${cs.note}`, cs.severity);
  }

  // XSS
  section(doc, c, `XSS test suite (${scan.xss.length})`);
  for (const x of scan.xss) {
    row(doc, c, `${x.category} · ${x.id}`, `${x.vector}\n${x.detail}`, x.severity);
  }

  // Sessions
  section(doc, c, `Session security (${scan.sessions.length})`);
  for (const s of scan.sessions) row(doc, c, s.name, s.observation, s.status);

  // Recon
  section(doc, c, `Reconnaissance (${scan.recon.length})`);
  for (const r of scan.recon) {
    row(doc, c, `${r.category} · ${r.name}${r.target ? ` (${r.target})` : ""}`, r.note, r.severity);
  }

  // Footer
  const pageCount = doc.getNumberOfPages();
  for (let i = 1; i <= pageCount; i++) {
    doc.setPage(i);
    doc.setFontSize(8);
    doc.setTextColor(150, 160, 180);
    doc.text(`NSL Report · ${scan.targetHost} · page ${i}/${pageCount}`, M,
      doc.internal.pageSize.getHeight() - 20);
  }

  return doc;
}

export function downloadScanPdf(scan: ScanResult) {
  const doc = generateScanPdf(scan);
  const ts = new Date(scan.createdAt).toISOString().replace(/[:.]/g, "-").slice(0, 19);
  doc.save(`nsl-${scan.targetHost}-${ts}.pdf`);
}
