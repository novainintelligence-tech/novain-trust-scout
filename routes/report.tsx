import { createFileRoute } from "@tanstack/react-router";
import { FileDown, FileJson, FileText, GitCompare } from "lucide-react";
import { useMemo, useState } from "react";
import { toast } from "sonner";

import { PageHeader, PageShell } from "@/components/page-header";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { Badge } from "@/components/ui/badge";
import { Separator } from "@/components/ui/separator";
import {
  DropdownMenu, DropdownMenuContent, DropdownMenuItem, DropdownMenuTrigger,
  DropdownMenuLabel, DropdownMenuSeparator,
} from "@/components/ui/dropdown-menu";
import {
  Select, SelectContent, SelectItem, SelectTrigger, SelectValue,
} from "@/components/ui/select";
import { ScanRunner } from "@/components/scan-runner";
import { EmptyScanState } from "@/components/empty-scan-state";
import { RawBlock } from "@/components/raw-block";
import { FindingValidator } from "@/components/finding-validator";
import { useLatestScan, useRecentScans } from "@/hooks/use-scans";
import { buildEngagementSummary, type RiskRating } from "@/lib/engagement";
import { downloadEngagementPdf } from "@/lib/report-pdf";
import { downloadJsonReport, downloadSarifReport } from "@/lib/report-exports";
import { diffScans, type DiffStatus } from "@/lib/report-diff";

export const Route = createFileRoute("/report")({
  head: () => ({
    meta: [
      { title: "Engagement Report · NOVAIN Security Lab" },
      { name: "description", content: "Full penetration test engagement report with executive & technical PDF, SARIF, JSON, CVSS 3.1 vectors, and scan-to-scan diff." },
    ],
  }),
  component: ReportPage,
});

const riskClass: Record<RiskRating, string> = {
  Critical: "border-critical/50 text-critical bg-critical/10",
  High: "border-critical/40 text-critical bg-critical/5",
  Medium: "border-warning/40 text-warning bg-warning/5",
  Low: "border-success/40 text-success bg-success/5",
  Info: "border-border text-muted-foreground",
};

const diffClass: Record<DiffStatus, string> = {
  new: "border-critical/40 text-critical bg-critical/5",
  changed: "border-warning/40 text-warning bg-warning/5",
  resolved: "border-success/40 text-success bg-success/5",
  unchanged: "border-border text-muted-foreground",
};

function ReportPage() {
  const { data: scan } = useLatestScan();
  const { data: history } = useRecentScans();
  const [baseId, setBaseId] = useState<string>("");

  const baselineOptions = useMemo(() => {
    if (!scan || !history) return [];
    return history.filter((s) => s.targetHost === scan.targetHost && s.id !== scan.id);
  }, [scan, history]);

  const baseScan = useMemo(
    () => baselineOptions.find((s) => s.id === baseId) ?? null,
    [baselineOptions, baseId],
  );

  const diff = useMemo(
    () => (scan && baseScan ? diffScans(baseScan, scan) : null),
    [scan, baseScan],
  );

  if (!scan) {
    return (
      <PageShell>
        <PageHeader
          eyebrow="Reporting"
          title="Engagement report"
          description="Executive & technical PDF, SARIF/JSON export, CVSS 3.1 vectors, and scan-to-scan diff."
          actions={<ScanRunner label="Run scan" />}
        />
        <EmptyScanState context="the engagement report" />
      </PageShell>
    );
  }

  const summary = buildEngagementSummary(scan);

  return (
    <PageShell>
      <PageHeader
        eyebrow="Reporting"
        title="Engagement report"
        description={`${summary.targetHost} · report generated from the latest scan.`}
        actions={
          <>
            <ScanRunner label="Rescan" />
            <DropdownMenu>
              <DropdownMenuTrigger asChild>
                <Button size="sm">
                  <FileDown className="h-4 w-4" /> Export
                </Button>
              </DropdownMenuTrigger>
              <DropdownMenuContent align="end">
                <DropdownMenuLabel>PDF</DropdownMenuLabel>
                <DropdownMenuItem onClick={() => { downloadEngagementPdf(scan, "executive"); toast.success("Executive PDF exported"); }}>
                  <FileText className="h-4 w-4" /> Executive summary
                </DropdownMenuItem>
                <DropdownMenuItem onClick={() => { downloadEngagementPdf(scan, "technical"); toast.success("Technical PDF exported"); }}>
                  <FileText className="h-4 w-4" /> Technical report
                </DropdownMenuItem>
                <DropdownMenuSeparator />
                <DropdownMenuLabel>Machine-readable</DropdownMenuLabel>
                <DropdownMenuItem onClick={() => { downloadSarifReport(scan); toast.success("SARIF exported"); }}>
                  <FileJson className="h-4 w-4" /> SARIF 2.1.0
                </DropdownMenuItem>
                <DropdownMenuItem onClick={() => { downloadJsonReport(scan); toast.success("JSON exported"); }}>
                  <FileJson className="h-4 w-4" /> JSON report
                </DropdownMenuItem>
              </DropdownMenuContent>
            </DropdownMenu>
          </>
        }
      />

      {/* Scan-to-scan diff */}
      <Card>
        <CardHeader className="pb-2 flex-row items-center justify-between gap-4 space-y-0">
          <CardTitle className="text-sm flex items-center gap-2">
            <GitCompare className="h-4 w-4" /> Scan diff
          </CardTitle>
          <div className="flex items-center gap-2">
            <span className="font-mono text-[10px] uppercase tracking-widest text-muted-foreground">Baseline</span>
            <Select value={baseId} onValueChange={setBaseId}>
              <SelectTrigger className="h-8 w-[260px] text-xs">
                <SelectValue placeholder={baselineOptions.length ? "Choose a previous scan" : "No previous scans"} />
              </SelectTrigger>
              <SelectContent>
                {baselineOptions.map((s) => (
                  <SelectItem key={s.id} value={s.id} className="text-xs">
                    {new Date(s.createdAt).toLocaleString()} · score {s.overallScore}
                  </SelectItem>
                ))}
              </SelectContent>
            </Select>
          </div>
        </CardHeader>
        <CardContent className="space-y-3 text-sm">
          {!diff ? (
            <p className="text-muted-foreground">
              {baselineOptions.length === 0
                ? "Run another scan on this host to enable diffing."
                : "Pick a baseline scan to compare against the current one."}
            </p>
          ) : (
            <>
              <div className="flex flex-wrap items-center gap-3">
                <span className="font-mono text-xs">
                  Score {diff.base.overallScore} → {diff.head.overallScore}{" "}
                  <span className={diff.scoreDelta >= 0 ? "text-success" : "text-critical"}>
                    ({diff.scoreDelta >= 0 ? "+" : ""}{diff.scoreDelta})
                  </span>
                </span>
                <Badge variant="outline" className={diffClass.new}>New: {diff.totals.added}</Badge>
                <Badge variant="outline" className={diffClass.resolved}>Resolved: {diff.totals.resolved}</Badge>
                <Badge variant="outline" className={diffClass.changed}>Changed: {diff.totals.changed}</Badge>
                <Badge variant="outline" className={diffClass.unchanged}>Unchanged: {diff.totals.unchanged}</Badge>
              </div>
              <div className="rounded-md border border-border/60 divide-y divide-border/60">
                {diff.rows.slice(0, 40).map((r) => (
                  <div key={`${r.status}-${r.id}`} className="flex items-start gap-3 p-2">
                    <Badge variant="outline" className={`${diffClass[r.status]} shrink-0 uppercase text-[10px]`}>
                      {r.status}
                    </Badge>
                    <div className="min-w-0 flex-1">
                      <div className="text-sm truncate">{r.title}</div>
                      <div className="font-mono text-[10px] text-muted-foreground">
                        {r.module}
                        {r.status === "changed" && r.before && r.after && (
                          <> · CVSS {r.before.cvss.toFixed(1)} → {r.after.cvss.toFixed(1)} · {r.before.risk} → {r.after.risk}</>
                        )}
                      </div>
                    </div>
                  </div>
                ))}
                {diff.rows.length > 40 && (
                  <div className="p-2 text-xs text-muted-foreground">+{diff.rows.length - 40} more rows — export JSON/SARIF for full diff.</div>
                )}
              </div>
            </>
          )}
        </CardContent>
      </Card>

      <Card>
        <CardHeader className="pb-2"><CardTitle className="text-sm">1. Executive Summary</CardTitle></CardHeader>
        <CardContent className="space-y-3 text-sm">
          <p>
            Overall security posture score: <span className="font-mono font-semibold">{summary.overallScore}/100</span>.
            This assessment identified <b>{summary.findings.length}</b> findings across HTTP headers, cookies, TLS, CSRF, XSS,
            session handling, and reconnaissance surfaces.
          </p>
          <div className="flex flex-wrap gap-2">
            {(["Critical", "High", "Medium", "Low", "Info"] as RiskRating[]).map((r) => {
              const count = summary.totals[r.toLowerCase() as keyof typeof summary.totals];
              return (
                <Badge key={r} variant="outline" className={riskClass[r]}>
                  {r}: {count}
                </Badge>
              );
            })}
          </div>
          {summary.strengths.length > 0 && (
            <div>
              <div className="mb-1 font-mono text-[10px] uppercase tracking-widest text-muted-foreground">Observed strengths</div>
              <ul className="space-y-1">
                {summary.strengths.map((s) => <li key={s}>• {s}</li>)}
              </ul>
            </div>
          )}
        </CardContent>
      </Card>

      {/* 2. Scope & methodology */}
      <Card>
        <CardHeader className="pb-2"><CardTitle className="text-sm">2. Scope & Methodology</CardTitle></CardHeader>
        <CardContent className="space-y-2 text-sm">
          <p><b>In-scope target:</b> <span className="font-mono">{summary.targetUrl}</span></p>
          <p>
            Methodology follows a seven-phase workflow adapted from OWASP WSTG, OSSTMM, PTES, and NIST SP 800-115:
            Scoping &amp; Rules of Engagement, Reconnaissance, Enumeration, Vulnerability Identification, Validation,
            Post-Validation Analysis, and Reporting. Testing is limited to passive and safe active checks issued by the
            NOVAIN Security Lab scanner against the authorized target only.
          </p>
        </CardContent>
      </Card>

      {/* 3. Asset inventory */}
      <Card>
        <CardHeader className="pb-2"><CardTitle className="text-sm">3. Asset Inventory</CardTitle></CardHeader>
        <CardContent>
          <ul className="space-y-1 text-sm">
            {summary.assets.map((a) => <li key={a}>• {a}</li>)}
          </ul>
        </CardContent>
      </Card>

      {/* 4. Attack surface summary */}
      <Card>
        <CardHeader className="pb-2"><CardTitle className="text-sm">4. Attack Surface Summary</CardTitle></CardHeader>
        <CardContent className="grid grid-cols-2 gap-3 text-sm md:grid-cols-3">
          <div><span className="text-muted-foreground">Headers:</span> {scan.headers.length}</div>
          <div><span className="text-muted-foreground">Cookies:</span> {scan.cookies.length}</div>
          <div><span className="text-muted-foreground">Forms:</span> {scan.csrf.length}</div>
          <div><span className="text-muted-foreground">XSS cases:</span> {scan.xss.length}</div>
          <div><span className="text-muted-foreground">Session checks:</span> {scan.sessions.length}</div>
          <div><span className="text-muted-foreground">Recon checks:</span> {scan.recon.length}</div>
        </CardContent>
      </Card>

      {/* 5. Findings */}
      <Card>
        <CardHeader className="pb-2">
          <CardTitle className="text-sm">5. Confirmed Findings ({summary.findings.length})</CardTitle>
        </CardHeader>
        <CardContent className="space-y-4">
          {summary.findings.length === 0 ? (
            <p className="text-sm text-muted-foreground">
              No confirmed findings from automated checks. Manual testing recommended for business-logic coverage.
            </p>
          ) : (
            summary.findings.map((f, i) => (
              <div key={f.id} className="rounded-md border border-border/60 bg-surface/40 p-4">
                <div className="flex flex-wrap items-center gap-2">
                  <Badge variant="outline" className={riskClass[f.risk]}>{f.risk}</Badge>
                  <span className="font-mono text-xs text-muted-foreground">CVSS 3.1 {f.cvss.toFixed(1)}</span>
                  <span className="font-mono text-xs text-muted-foreground">·</span>
                  <span className="font-mono text-xs text-muted-foreground">{f.module}</span>
                </div>
                <div className="mt-1 font-mono text-[10px] text-muted-foreground/80 break-all">{f.cvssVector}</div>
                <h3 className="mt-1 text-sm font-semibold">{i + 1}. {f.title}</h3>
                <Separator className="my-3" />
                <div className="grid gap-3 md:grid-cols-3">
                  <div>
                    <div className="mb-1 font-mono text-[10px] uppercase tracking-widest text-muted-foreground">Impact</div>
                    <p className="text-sm">{f.impact}</p>
                  </div>
                  <div className="md:col-span-2">
                    <div className="mb-1 font-mono text-[10px] uppercase tracking-widest text-muted-foreground">Evidence</div>
                    <RawBlock title="evidence">{f.evidence}</RawBlock>
                  </div>
                  <div className="md:col-span-3">
                    <div className="mb-1 font-mono text-[10px] uppercase tracking-widest text-muted-foreground">Remediation</div>
                    <p className="text-sm">{f.remediation}</p>
                  </div>
                  <div className="md:col-span-3">
                    <div className="mb-1 font-mono text-[10px] uppercase tracking-widest text-muted-foreground">Proof of concept</div>
                    <FindingValidator finding={f} targetUrl={scan.targetUrl} />
                  </div>
                </div>
              </div>
            ))
          )}
        </CardContent>
      </Card>

      {/* 6. Risk assessment */}
      <Card>
        <CardHeader className="pb-2"><CardTitle className="text-sm">6. Risk Assessment</CardTitle></CardHeader>
        <CardContent className="text-sm">
          Ratings combine automated severity with typical business impact: authentication and transport issues are treated as
          High, cookie flag issues and exposed endpoints as High/Medium, and hardening gaps (headers, meta files) as Low.
          CVSS values are indicative and should be re-scored per environment.
        </CardContent>
      </Card>

      {/* 7. Residual risks */}
      <Card>
        <CardHeader className="pb-2"><CardTitle className="text-sm">7. Residual Risks</CardTitle></CardHeader>
        <CardContent className="text-sm">
          Automated scanning cannot confirm business-logic flaws, chained multi-step exploits, authenticated-only surfaces,
          or issues behind rate limits and WAFs. A manual engagement is recommended to cover authenticated workflows,
          privilege boundaries, and application-specific logic.
        </CardContent>
      </Card>
    </PageShell>
  );
}
