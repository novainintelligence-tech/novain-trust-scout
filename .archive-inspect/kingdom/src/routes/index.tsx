import { createFileRoute, Link } from "@tanstack/react-router";
import {
  Activity,
  ArrowUpRight,
  Cookie,
  Bug,
  ShieldAlert,
  KeyRound,
  ServerCog,
  LockKeyhole,
  Radar,
} from "lucide-react";

import { PageHeader, PageShell } from "@/components/page-header";
import { SeverityBadge, type Severity } from "@/components/severity-badge";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Progress } from "@/components/ui/progress";
import { Button } from "@/components/ui/button";
import { Badge } from "@/components/ui/badge";
import { ScanRunner } from "@/components/scan-runner";
import { EmptyScanState } from "@/components/empty-scan-state";
import { ExportPdfButton } from "@/components/export-pdf-button";
import { useLatestScan, useRecentScans } from "@/hooks/use-scans";

export const Route = createFileRoute("/")({
  head: () => ({
    meta: [
      { title: "Dashboard · NOVAIN Security Lab" },
      {
        name: "description",
        content: "Overall posture, module scores, and recent scan history for your web targets.",
      },
    ],
  }),
  component: Dashboard,
});

const moduleLinks = [
  { key: "cookies", title: "Cookie Inspector", href: "/cookies", icon: Cookie },
  { key: "headers", title: "HTTP Headers", href: "/headers", icon: ServerCog },
  { key: "tls", title: "TLS Checker", href: "/tls", icon: LockKeyhole },
  { key: "sessions", title: "Session Security", href: "/sessions", icon: KeyRound },
  { key: "csrf", title: "CSRF Validator", href: "/csrf", icon: ShieldAlert },
  { key: "xss", title: "XSS Test Suite", href: "/xss", icon: Bug },
  { key: "recon", title: "Reconnaissance", href: "/recon", icon: Radar },
] as const;

function severityForScore(score: number): Severity {
  if (score >= 85) return "pass";
  if (score >= 70) return "warn";
  return "fail";
}

function Dashboard() {
  const { data: latest } = useLatestScan();
  const { data: history } = useRecentScans();

  return (
    <PageShell>
      <PageHeader
        eyebrow="Overview"
        title="Security posture"
        description="Real scans of the target URL you set in the header. Results are saved to your account."
        actions={
          <>
            <ScanRunner label="Run scan" />
            <ExportPdfButton scan={latest} />
            <Button size="sm" variant="outline" disabled={!history || history.length === 0}>
              <Activity className="h-4 w-4" />
              {history?.length ?? 0} in history
            </Button>
          </>
        }
      />

      {!latest ? (
        <EmptyScanState context="the dashboard" />
      ) : (
        <>
          <div className="grid gap-4 lg:grid-cols-3">
            <Card className="lg:col-span-1">
              <CardHeader className="pb-2">
                <CardTitle className="text-sm font-medium text-muted-foreground">
                  Overall score · {latest.targetHost}
                </CardTitle>
              </CardHeader>
              <CardContent className="space-y-3">
                <div className="flex items-baseline gap-3">
                  <span className="font-mono text-5xl font-semibold tracking-tight">
                    {latest.overallScore}
                  </span>
                  <span className="text-sm text-muted-foreground">/ 100</span>
                  <SeverityBadge severity={severityForScore(latest.overallScore)} className="ml-auto">
                    {severityForScore(latest.overallScore) === "pass"
                      ? "Healthy"
                      : severityForScore(latest.overallScore) === "warn"
                      ? "Attention"
                      : "At risk"}
                  </SeverityBadge>
                </div>
                <Progress value={latest.overallScore} className="h-2" />
                <p className="text-xs text-muted-foreground">
                  Last scan {new Date(latest.createdAt).toLocaleString()} ·{" "}
                  {latest.durationMs ? `${latest.durationMs}ms` : "—"}
                </p>
              </CardContent>
            </Card>

            <Card className="lg:col-span-2">
              <CardHeader className="pb-2">
                <CardTitle className="text-sm font-medium text-muted-foreground">
                  Module breakdown
                </CardTitle>
              </CardHeader>
              <CardContent className="grid gap-3 sm:grid-cols-2">
                {Object.entries(latest.scores).map(([k, v]) => {
                  const s = severityForScore(v);
                  return (
                    <div key={k} className="rounded-md border border-border/60 bg-surface/50 p-3">
                      <div className="flex items-center justify-between text-xs text-muted-foreground">
                        <span className="font-mono uppercase tracking-widest">{k}</span>
                        <SeverityBadge severity={s} />
                      </div>
                      <div className="mt-2 flex items-baseline gap-2">
                        <span className="font-mono text-2xl font-semibold">{v}</span>
                        <span className="text-xs text-muted-foreground">/ 100</span>
                      </div>
                      <Progress value={v} className="mt-2 h-1.5" />
                    </div>
                  );
                })}
              </CardContent>
            </Card>
          </div>

          <div>
            <div className="mb-3 flex items-center justify-between">
              <h2 className="text-sm font-medium text-muted-foreground">Modules</h2>
            </div>
            <div className="grid gap-3 sm:grid-cols-2 lg:grid-cols-3">
              {moduleLinks.map((m) => {
                const score = latest.scores[m.key as keyof typeof latest.scores];
                const s = severityForScore(score);
                return (
                  <Link
                    key={m.href}
                    to={m.href}
                    className="group panel relative flex flex-col gap-3 p-4 transition hover:border-primary/40"
                  >
                    <div className="flex items-start justify-between">
                      <div className="flex h-9 w-9 items-center justify-center rounded-md bg-primary/10 ring-1 ring-primary/30">
                        <m.icon className="h-4 w-4 text-primary" />
                      </div>
                      <ArrowUpRight className="h-4 w-4 text-muted-foreground transition group-hover:text-primary" />
                    </div>
                    <div>
                      <div className="text-sm font-semibold">{m.title}</div>
                    </div>
                    <div className="flex items-center justify-between">
                      <span className="font-mono text-lg">
                        {score}
                        <span className="text-xs text-muted-foreground">/100</span>
                      </span>
                      <SeverityBadge severity={s} />
                    </div>
                  </Link>
                );
              })}
            </div>
          </div>
        </>
      )}

      {history && history.length > 0 && (
        <Card>
          <CardHeader className="flex flex-row items-center justify-between pb-3">
            <div>
              <CardTitle className="text-sm font-medium">Recent scans</CardTitle>
              <p className="mt-1 text-xs text-muted-foreground">
                Latest {Math.min(history.length, 10)} scans across all targets.
              </p>
            </div>
            <Button asChild variant="ghost" size="sm">
              <Link to="/audit">View full history</Link>
            </Button>
          </CardHeader>
          <CardContent className="p-0">
            <div className="divide-y divide-border">
              {history.slice(0, 10).map((e) => (
                <div key={e.id} className="grid grid-cols-12 items-center gap-3 px-4 py-2.5 text-sm">
                  <span className="col-span-3 font-mono text-xs text-muted-foreground">
                    {new Date(e.createdAt).toLocaleString()}
                  </span>
                  <span className="col-span-5 truncate font-mono">{e.targetHost}</span>
                  <span className="col-span-2 truncate text-muted-foreground">
                    {e.status === "complete" ? `${e.overallScore}/100` : "error"}
                  </span>
                  <span className="col-span-2 text-right">
                    <Badge
                      variant="outline"
                      className={
                        e.status === "complete"
                          ? "border-success/40 text-success"
                          : "border-critical/40 text-critical"
                      }
                    >
                      {e.status}
                    </Badge>
                  </span>
                </div>
              ))}
            </div>
          </CardContent>
        </Card>
      )}
    </PageShell>
  );
}
