import { createFileRoute, Link } from "@tanstack/react-router";
import { useEffect, useState } from "react";
import { CheckCircle2, Circle, CircleDashed, ArrowRight } from "lucide-react";

import { PageHeader, PageShell } from "@/components/page-header";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { Badge } from "@/components/ui/badge";
import { Checkbox } from "@/components/ui/checkbox";
import { SeverityBadge } from "@/components/severity-badge";
import { ScanRunner } from "@/components/scan-runner";
import { EmptyScanState } from "@/components/empty-scan-state";
import { useLatestScan } from "@/hooks/use-scans";
import { useTarget } from "@/components/target-selector";
import { computePhases, type PhaseStatus } from "@/lib/engagement";

export const Route = createFileRoute("/methodology")({
  head: () => ({
    meta: [
      { title: "Workflow · NOVAIN Security Lab" },
      { name: "description", content: "Seven-phase penetration testing workflow tracker with per-target progress and evidence." },
    ],
  }),
  component: MethodologyPage,
});

const ROE_ITEMS = [
  "Target ownership / written authorization confirmed",
  "Testing window and rate limits agreed",
  "Emergency contact & rollback plan documented",
  "Success criteria and out-of-scope items listed",
];

function useScopeChecklist(host: string) {
  const key = `nsl:scope:${host}`;
  const [state, setState] = useState<boolean[]>(() => ROE_ITEMS.map(() => false));
  useEffect(() => {
    if (typeof window === "undefined" || !host) return;
    try {
      const raw = window.localStorage.getItem(key);
      if (raw) setState(JSON.parse(raw));
      else setState(ROE_ITEMS.map(() => false));
    } catch {
      setState(ROE_ITEMS.map(() => false));
    }
  }, [key, host]);
  const toggle = (i: number) => {
    setState((prev) => {
      const next = prev.slice();
      next[i] = !next[i];
      try { window.localStorage.setItem(key, JSON.stringify(next)); } catch { /* ignore */ }
      return next;
    });
  };
  const complete = state.every(Boolean);
  return { state, toggle, complete };
}

function StatusIcon({ status }: { status: PhaseStatus["status"] }) {
  if (status === "complete") return <CheckCircle2 className="h-5 w-5 text-success" />;
  if (status === "in-progress") return <CircleDashed className="h-5 w-5 text-warning" />;
  return <Circle className="h-5 w-5 text-muted-foreground" />;
}

function MethodologyPage() {
  const { target } = useTarget();
  let host = "";
  try { host = new URL(target).host; } catch { /* ignore */ }
  const { data: scan } = useLatestScan();
  const { state: roe, toggle, complete: scopeConfirmed } = useScopeChecklist(host);

  const phases = computePhases(scan ?? null, scopeConfirmed);
  const completed = phases.filter((p) => p.status === "complete").length;

  return (
    <PageShell>
      <PageHeader
        eyebrow="Workflow"
        title="Penetration test methodology"
        description="Seven phases adapted from OWASP WSTG, OSSTMM, PTES, and NIST SP 800-115. Progress is derived from your latest scan for the active target."
        actions={
          <>
            <ScanRunner label="Run scan" />
            <Button asChild size="sm" variant="outline">
              <Link to="/report">Open engagement report <ArrowRight className="h-3.5 w-3.5" /></Link>
            </Button>
          </>
        }
      />

      <Card>
        <CardHeader className="pb-2">
          <CardTitle className="text-sm">Progress · {host || "no target"}</CardTitle>
        </CardHeader>
        <CardContent className="text-sm text-muted-foreground">
          {completed} of {phases.length} phases complete for this target.
        </CardContent>
      </Card>

      <EmptyScanState context="the workflow tracker" />

      <div className="grid gap-4">
        {phases.map((p) => (
          <Card key={p.id}>
            <CardHeader className="flex flex-row items-start justify-between gap-3 pb-2">
              <div className="flex items-start gap-3">
                <StatusIcon status={p.status} />
                <div>
                  <div className="flex items-center gap-2">
                    <Badge variant="outline" className="font-mono text-[10px]">Phase {p.phase}</Badge>
                    <CardTitle className="text-base">{p.name}</CardTitle>
                  </div>
                  <p className="mt-1 text-sm text-muted-foreground">{p.objective}</p>
                </div>
              </div>
              <div className="flex flex-wrap gap-1.5">
                {p.evidence.pass > 0 && <SeverityBadge severity="pass">{p.evidence.pass} pass</SeverityBadge>}
                {p.evidence.warn > 0 && <SeverityBadge severity="warn">{p.evidence.warn} warn</SeverityBadge>}
                {p.evidence.fail > 0 && <SeverityBadge severity="fail">{p.evidence.fail} fail</SeverityBadge>}
              </div>
            </CardHeader>
            <CardContent className="grid gap-3 text-sm md:grid-cols-3">
              <div>
                <div className="mb-1 font-mono text-[10px] uppercase tracking-widest text-muted-foreground">Outputs</div>
                <ul className="space-y-1">
                  {p.outputs.map((o) => <li key={o}>• {o}</li>)}
                </ul>
              </div>
              <div>
                <div className="mb-1 font-mono text-[10px] uppercase tracking-widest text-muted-foreground">NSL modules</div>
                <ul className="space-y-1">
                  {p.modules.map((m) => <li key={m}>• {m}</li>)}
                </ul>
              </div>
              <div>
                <div className="mb-1 font-mono text-[10px] uppercase tracking-widest text-muted-foreground">Next decision</div>
                <p>{p.nextDecision}</p>
              </div>

              {p.id === "scoping" && (
                <div className="md:col-span-3 rounded-md border border-border/60 bg-surface/40 p-3">
                  <div className="mb-2 font-mono text-[10px] uppercase tracking-widest text-muted-foreground">
                    Rules of Engagement checklist · {host || "set a target"}
                  </div>
                  <div className="grid gap-2 sm:grid-cols-2">
                    {ROE_ITEMS.map((label, i) => (
                      <label key={label} className="flex cursor-pointer items-start gap-2 text-sm">
                        <Checkbox checked={roe[i]} onCheckedChange={() => toggle(i)} disabled={!host} />
                        <span className={roe[i] ? "text-muted-foreground line-through" : ""}>{label}</span>
                      </label>
                    ))}
                  </div>
                </div>
              )}
            </CardContent>
          </Card>
        ))}
      </div>
    </PageShell>
  );
}
