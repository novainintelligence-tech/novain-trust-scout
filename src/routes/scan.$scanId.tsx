import { createFileRoute, Link } from "@tanstack/react-router";
import { ArrowLeft } from "lucide-react";

import { PageHeader, PageShell } from "@/components/page-header";
import { SeverityBadge } from "@/components/severity-badge";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Progress } from "@/components/ui/progress";
import { ExportPdfButton } from "@/components/export-pdf-button";
import { useScanById } from "@/hooks/use-scans";

export const Route = createFileRoute("/scan/$scanId")({
  head: () => ({
    meta: [
      { title: "Scan Review · NSL" },
      { name: "description", content: "Full detailed review of a saved security scan." },
    ],
  }),
  component: ScanReviewPage,
});

function ScanReviewPage() {
  const { scanId } = Route.useParams();
  const { data: scan, isLoading } = useScanById(scanId);

  if (isLoading) {
    return (
      <PageShell>
        <Card><CardContent className="p-8 text-center text-sm text-muted-foreground">Loading scan…</CardContent></Card>
      </PageShell>
    );
  }
  if (!scan) {
    return (
      <PageShell>
        <Card>
          <CardContent className="p-8 text-center">
            <p className="text-sm">Scan not found or not accessible.</p>
            <Button asChild variant="outline" size="sm" className="mt-3">
              <Link to="/audit"><ArrowLeft className="h-4 w-4" />Back to history</Link>
            </Button>
          </CardContent>
        </Card>
      </PageShell>
    );
  }

  return (
    <PageShell>
      <PageHeader
        eyebrow={`Scan · ${new Date(scan.createdAt).toLocaleString()}`}
        title={scan.targetHost}
        description={scan.targetUrl}
        actions={
          <>
            <Button asChild variant="outline" size="sm">
              <Link to="/audit"><ArrowLeft className="h-4 w-4" />History</Link>
            </Button>
            <ExportPdfButton scan={scan} />
          </>
        }
      />

      <Card>
        <CardHeader className="pb-2">
          <CardTitle className="text-sm">Overall score · {scan.overallScore}/100</CardTitle>
        </CardHeader>
        <CardContent className="grid gap-3 sm:grid-cols-4 lg:grid-cols-7">
          {Object.entries(scan.scores).map(([k, v]) => (
            <div key={k} className="rounded-md border border-border/60 bg-surface/40 p-3">
              <p className="font-mono text-[10px] uppercase tracking-widest text-muted-foreground">{k}</p>
              <p className="mt-1 font-mono text-xl">{v}<span className="text-xs text-muted-foreground">/100</span></p>
              <Progress value={v} className="mt-2 h-1" />
            </div>
          ))}
        </CardContent>
      </Card>

      <Section title={`HTTP Headers (${scan.headers.length})`}>
        {scan.headers.map((h) => (
          <FindingRow key={h.name} label={h.name} sev={h.severity}
            body={<>
              <div className="font-mono text-xs">{h.value ?? <span className="italic text-critical">missing</span>}</div>
              <div className="mt-1 text-xs text-muted-foreground">{h.note}</div>
            </>} />
        ))}
      </Section>

      <Section title={`Cookies (${scan.cookies.length})`}>
        {scan.cookies.length === 0 && <p className="text-xs text-muted-foreground">No cookies set.</p>}
        {scan.cookies.map((c) => (
          <FindingRow key={`${c.name}-${c.domain}-${c.path}`} label={c.name} sev={c.severity}
            body={<div className="font-mono text-xs text-muted-foreground">
              Domain={c.domain} · Path={c.path} · HttpOnly={String(c.httpOnly)} · Secure={String(c.secure)} · SameSite={c.sameSite} · Expires={c.expires}
              {c.note && <div className="mt-1 text-critical">{c.note}</div>}
            </div>} />
        ))}
      </Section>

      <Section title="TLS / HSTS">
        <FindingRow label={`${scan.tls.host} · ${scan.tls.scheme.toUpperCase()}`} sev={scan.tls.severity}
          body={<div className="text-xs text-muted-foreground">
            <div>{scan.tls.note}</div>
            <div className="mt-1 font-mono">
              HSTS present={String(scan.tls.hstsPresent)} · max-age={scan.tls.hstsMaxAge ?? "—"} · includeSubDomains={String(scan.tls.hstsIncludeSubDomains)} · preload={String(scan.tls.hstsPreloaded)}
            </div>
            <div className="mt-1 font-mono">
              Issuer: {scan.tls.issuer ?? "—"} · Valid: {scan.tls.validFrom ?? "—"} → {scan.tls.validTo ?? "—"} · {scan.tls.daysRemaining ?? "—"} days
            </div>
          </div>} />
      </Section>

      <Section title={`CSRF (${scan.csrf.length})`}>
        {scan.csrf.map((r, i) => (
          <FindingRow key={i} label={<><Badge className="font-mono mr-2">{r.method}</Badge>{r.endpoint}</>} sev={r.severity}
            body={<div className="text-xs text-muted-foreground">Token={String(r.tokenFound)} · SameSite={r.sameSiteHint} · {r.note}</div>} />
        ))}
      </Section>

      <Section title={`XSS (${scan.xss.length})`}>
        {scan.xss.map((x) => (
          <FindingRow key={x.id} label={<><Badge variant="secondary" className="mr-2 text-[10px]">{x.category}</Badge>{x.vector}</>} sev={x.severity}
            body={<div className="text-xs text-muted-foreground">{x.detail}</div>} />
        ))}
      </Section>

      <Section title={`Sessions (${scan.sessions.length})`}>
        {scan.sessions.map((s, i) => (
          <FindingRow key={i} label={s.name} sev={s.status}
            body={<div className="text-xs text-muted-foreground">{s.observation}</div>} />
        ))}
      </Section>

      <Section title={`Recon (${scan.recon.length})`}>
        {scan.recon.map((r) => (
          <FindingRow key={r.id} label={<>{r.name}{r.target && <Badge variant="secondary" className="ml-2 font-mono text-[10px]">{r.target}</Badge>}</>} sev={r.severity}
            body={<div className="text-xs text-muted-foreground">{r.note}</div>} />
        ))}
      </Section>
    </PageShell>
  );
}

function Section({ title, children }: { title: string; children: React.ReactNode }) {
  return (
    <Card>
      <CardHeader className="pb-2"><CardTitle className="text-sm">{title}</CardTitle></CardHeader>
      <CardContent className="space-y-2">{children}</CardContent>
    </Card>
  );
}

function FindingRow({ label, sev, body }:
  { label: React.ReactNode; sev: "pass" | "warn" | "fail" | "info"; body: React.ReactNode }) {
  return (
    <div className="rounded-md border border-border/60 bg-surface/40 p-3">
      <div className="flex flex-wrap items-center justify-between gap-2">
        <div className="text-sm font-medium">{label}</div>
        <SeverityBadge severity={sev} />
      </div>
      <div className="mt-1">{body}</div>
    </div>
  );
}
