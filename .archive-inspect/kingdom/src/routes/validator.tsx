import { createFileRoute } from "@tanstack/react-router";
import { useMemo, useState } from "react";
import { PlayCircle, Loader2, FileDown, Target, ShieldAlert, Radar, Link2 } from "lucide-react";

import { PageHeader, PageShell } from "@/components/page-header";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { Badge } from "@/components/ui/badge";
import { Checkbox } from "@/components/ui/checkbox";
import { Label } from "@/components/ui/label";
import { Input } from "@/components/ui/input";
import { Separator } from "@/components/ui/separator";
import { RawBlock } from "@/components/raw-block";
import { ScanRunner } from "@/components/scan-runner";
import { EmptyScanState } from "@/components/empty-scan-state";
import { FindingValidator, isActiveFinding } from "@/components/finding-validator";
import { useLatestScan } from "@/hooks/use-scans";
import { buildFindings, type RiskRating } from "@/lib/engagement";
import { useServerFn } from "@tanstack/react-start";
import {
  runValidation, runStandalonePoc, discoverRestrictedLinks, POC_LIBRARY,
  type ValidationResult, type Verdict, type DiscoveredLink,
} from "@/lib/validator.functions";
import { toCurl } from "@/lib/validator-command";
import { downloadValidatorPdf } from "@/lib/validator-pdf";
import { toast } from "sonner";

export const Route = createFileRoute("/validator")({
  head: () => ({
    meta: [
      { title: "PoC Validator · NOVAIN Security Lab" },
      { name: "description", content: "Discover restricted URLs and execute the full PoC library against every finding and every discovered link." },
    ],
  }),
  component: ValidatorPage,
});

const riskClass: Record<RiskRating, string> = {
  Critical: "border-critical/50 text-critical bg-critical/10",
  High: "border-critical/40 text-critical bg-critical/5",
  Medium: "border-warning/40 text-warning bg-warning/5",
  Low: "border-success/40 text-success bg-success/5",
  Info: "border-border text-muted-foreground",
};

const verdictClass: Record<Verdict, string> = {
  confirmed: "border-critical/50 text-critical bg-critical/10",
  "not-exploitable": "border-success/40 text-success bg-success/5",
  inconclusive: "border-warning/40 text-warning bg-warning/5",
  skipped: "border-border text-muted-foreground",
  error: "border-critical/50 text-critical bg-critical/10",
};

type PerLinkResults = Record<string, Record<string, ValidationResult>>; // url -> pocId -> result

function ValidatorPage() {
  const { data: scan } = useLatestScan();
  const [authorize, setAuthorize] = useState(false);
  const [findingResults, setFindingResults] = useState<Record<string, ValidationResult>>({});
  const [batchBusy, setBatchBusy] = useState(false);
  const run = useServerFn(runValidation);
  const runStandalone = useServerFn(runStandalonePoc);
  const discover = useServerFn(discoverRestrictedLinks);

  const findings = useMemo(() => (scan ? buildFindings(scan) : []), [scan]);

  // Standalone probe state
  const [standaloneUrl, setStandaloneUrl] = useState<string>(scan?.targetUrl ?? "https://");
  const [standaloneResults, setStandaloneResults] = useState<Record<string, ValidationResult>>({});
  const [standaloneBusy, setStandaloneBusy] = useState<string | null>(null);

  // Discovery + per-link fanout
  const [discovering, setDiscovering] = useState(false);
  const [discovered, setDiscovered] = useState<DiscoveredLink[]>([]);
  const [fanoutBusy, setFanoutBusy] = useState(false);
  const [fanoutProgress, setFanoutProgress] = useState<{ done: number; total: number }>({ done: 0, total: 0 });
  const [perLink, setPerLink] = useState<PerLinkResults>({});

  const runOnePoc = async (pocId: string) => {
    try { new URL(standaloneUrl); } catch { toast.error("Enter a valid URL"); return; }
    setStandaloneBusy(pocId);
    try {
      const r = await runStandalone({ data: { url: standaloneUrl, pocId, authorizeActive: authorize } });
      setStandaloneResults((prev) => ({ ...prev, [pocId]: r }));
      if (r.verdict === "confirmed") toast.error(`Confirmed: ${pocId}`);
      else if (r.verdict === "not-exploitable") toast.success(`Not exploitable: ${pocId}`);
      else toast.info(`${pocId}: ${r.verdict}`);
    } catch (e) {
      toast.error(`Failed ${pocId}: ${e instanceof Error ? e.message : String(e)}`);
    } finally {
      setStandaloneBusy(null);
    }
  };

  // Runs entire PoC library against the standalone URL AND every scan finding in one shot.
  const runEverything = async () => {
    try { new URL(standaloneUrl); } catch { toast.error("Enter a valid URL"); return; }
    setBatchBusy(true);
    // Standalone library
    for (const p of POC_LIBRARY) {
      if (p.active && !authorize) continue;
      try {
        const r = await runStandalone({ data: { url: standaloneUrl, pocId: p.id, authorizeActive: authorize } });
        setStandaloneResults((prev) => ({ ...prev, [p.id]: r }));
      } catch { /* keep going */ }
    }
    // Scan findings
    if (scan) {
      for (const f of findings) {
        if (isActiveFinding(f) && !authorize) continue;
        try {
          const pathHint = f.id.startsWith("csrf-") ? f.id.slice(5)
            : f.id.startsWith("recon-") ? f.evidence.match(/https?:\/\/[^\s]+/)?.[0]
            : undefined;
          const r = await run({ data: { findingId: f.id, targetUrl: scan.targetUrl, path: pathHint, authorizeActive: authorize } });
          setFindingResults((prev) => ({ ...prev, [f.id]: r }));
        } catch { /* keep going */ }
      }
    }
    setBatchBusy(false);
    toast.success("Combined run complete");
  };

  const runDiscovery = async () => {
    try { new URL(standaloneUrl); } catch { toast.error("Enter a valid URL first"); return; }
    setDiscovering(true);
    try {
      const res = await discover({ data: { targetUrl: standaloneUrl, includeWordlist: true, maxLinks: 40 } });
      setDiscovered(res.links);
      toast.success(`Discovered ${res.links.length} candidate link${res.links.length === 1 ? "" : "s"}`);
    } catch (e) {
      toast.error(`Discovery failed: ${e instanceof Error ? e.message : String(e)}`);
    } finally {
      setDiscovering(false);
    }
  };

  // Run entire PoC library against every discovered link (skip active PoCs unless authorized).
  const runLibraryOnAllLinks = async () => {
    if (discovered.length === 0) { toast.error("Run discovery first"); return; }
    const libs = POC_LIBRARY.filter((p) => !p.active || authorize);
    const total = discovered.length * libs.length;
    setFanoutBusy(true);
    setFanoutProgress({ done: 0, total });
    let done = 0;
    for (const link of discovered) {
      for (const p of libs) {
        try {
          const r = await runStandalone({ data: { url: link.url, pocId: p.id, authorizeActive: authorize } });
          setPerLink((prev) => ({
            ...prev,
            [link.url]: { ...(prev[link.url] ?? {}), [p.id]: r },
          }));
        } catch { /* keep going */ }
        done++;
        setFanoutProgress({ done, total });
      }
    }
    setFanoutBusy(false);
    toast.success(`Ran ${libs.length} PoCs against ${discovered.length} links`);
  };

  const exportPdf = () => {
    if (!scan) return;
    const entries = findings
      .map((f) => ({ finding: f, result: findingResults[f.id] }))
      .filter((e): e is { finding: typeof e.finding; result: ValidationResult } => Boolean(e.result));
    if (entries.length === 0) { toast.error("No validations to export", { description: "Run at least one PoC first." }); return; }
    try {
      downloadValidatorPdf(scan.targetHost, scan.targetUrl, entries);
      toast.success(`Exported ${entries.length} validation${entries.length === 1 ? "" : "s"}`);
    } catch (e) { toast.error("PDF export failed", { description: e instanceof Error ? e.message : String(e) }); }
  };

  return (
    <PageShell>
      <PageHeader
        eyebrow="Validation"
        title="PoC Validator"
        description={scan ? `${scan.targetHost} · combined runner across scan findings, standalone URL, and discovered restricted links.` : "Run proof-of-concept probes against any authorized URL."}
        actions={
          <>
            <ScanRunner label={scan ? "Rescan" : "Run scan"} />
            <Button size="sm" variant="default" disabled={batchBusy} onClick={runEverything}>
              {batchBusy ? <Loader2 className="h-4 w-4 animate-spin" /> : <PlayCircle className="h-4 w-4" />}
              Run everything (library + findings)
            </Button>
            {scan && (
              <Button size="sm" variant="outline" disabled={Object.keys(findingResults).length === 0} onClick={exportPdf}>
                <FileDown className="h-4 w-4" />
                Export PDF
              </Button>
            )}
          </>
        }
      />

      <Card>
        <CardHeader className="pb-2">
          <CardTitle className="text-sm">Rules of engagement</CardTitle>
        </CardHeader>
        <CardContent className="space-y-2 text-sm">
          <p className="text-muted-foreground">
            Only run PoCs against systems you own or have explicit written authorization to test.
            Enabling this checkbox unlocks every PoC in the library (including active probes) for both the standalone URL and each discovered link.
          </p>
          <div className="flex items-center gap-2">
            <Checkbox id="auth-global" checked={authorize} onCheckedChange={(v) => setAuthorize(v === true)} />
            <Label htmlFor="auth-global" className="text-sm">
              I own or have written authorization to test the target and authorize all active probes.
            </Label>
          </div>
        </CardContent>
      </Card>

      {/* Standalone URL probes */}
      <Card>
        <CardHeader className="pb-2">
          <div className="flex items-center justify-between gap-2 flex-wrap">
            <CardTitle className="text-sm flex items-center gap-2">
              <Target className="h-4 w-4 text-primary" /> Standalone probes · run against any URL
            </CardTitle>
          </div>
        </CardHeader>
        <CardContent className="space-y-4">
          <div className="flex flex-wrap items-center gap-2">
            <Input
              value={standaloneUrl}
              onChange={(e) => setStandaloneUrl(e.target.value)}
              placeholder="https://example.com/path?query"
              className="h-9 font-mono text-xs flex-1 min-w-[280px]"
            />
            <Button size="sm" variant="outline" disabled={discovering} onClick={runDiscovery}>
              {discovering ? <Loader2 className="h-4 w-4 animate-spin" /> : <Radar className="h-4 w-4" />}
              Discover restricted links
            </Button>
          </div>
          <div className="grid gap-3 sm:grid-cols-2">
            {POC_LIBRARY.map((p) => {
              const r = standaloneResults[p.id];
              const busy = standaloneBusy === p.id;
              const disabled = busy || (p.active && !authorize);
              return (
                <div key={p.id} className="rounded-md border border-border/60 bg-surface/40 p-3 space-y-2">
                  <div className="flex items-start justify-between gap-2">
                    <div>
                      <div className="flex items-center gap-2 flex-wrap">
                        <span className="text-sm font-medium">{p.label}</span>
                        {p.active && (
                          <Badge variant="outline" className="border-critical/40 text-critical bg-critical/5 gap-1 text-[10px]">
                            <ShieldAlert className="h-3 w-3" /> Active
                          </Badge>
                        )}
                        {r && <Badge variant="outline" className={`${verdictClass[r.verdict]} text-[10px]`}>{r.verdict}</Badge>}
                      </div>
                      <p className="text-xs text-muted-foreground mt-0.5">{p.desc}</p>
                    </div>
                    <Button size="sm" variant={p.active ? "destructive" : "outline"} disabled={disabled} onClick={() => runOnePoc(p.id)}>
                      {busy ? <Loader2 className="h-3.5 w-3.5 animate-spin" /> : <PlayCircle className="h-3.5 w-3.5" />}
                      Run
                    </Button>
                  </div>
                  {r && (
                    <div className="space-y-2 border-t border-border/60 pt-2">
                      <div className="text-xs">{r.summary}</div>
                      {r.steps.map((s, i) => (
                        <div key={i} className="space-y-1">
                          <div className="text-[11px] font-mono">{s.method} {s.url} → {s.status ?? "no response"}{s.error ? ` (${s.error})` : ""}</div>
                          <RawBlock title="curl">{toCurl(s)}</RawBlock>
                          {Object.keys(s.responseHeaders).length > 0 && (
                            <RawBlock title="response headers" maxHeight={140}>
                              {Object.entries(s.responseHeaders).map(([k, v]) => `${k}: ${v}`).join("\n")}
                            </RawBlock>
                          )}
                          {s.bodySnippet && (
                            <RawBlock title={`body (${s.bodyBytes}b${s.bodyTruncated ? " truncated" : ""})`} maxHeight={140}>{s.bodySnippet}</RawBlock>
                          )}
                        </div>
                      ))}
                    </div>
                  )}
                </div>
              );
            })}
          </div>
        </CardContent>
      </Card>

      {/* Discovered restricted links */}
      {discovered.length > 0 && (
        <Card>
          <CardHeader className="pb-2">
            <div className="flex items-center justify-between gap-2 flex-wrap">
              <CardTitle className="text-sm flex items-center gap-2">
                <Link2 className="h-4 w-4 text-primary" /> Discovered restricted-looking links ({discovered.length})
              </CardTitle>
              <Button size="sm" variant="default" disabled={fanoutBusy} onClick={runLibraryOnAllLinks}>
                {fanoutBusy
                  ? <><Loader2 className="h-4 w-4 animate-spin" /> {fanoutProgress.done}/{fanoutProgress.total}</>
                  : <><PlayCircle className="h-4 w-4" /> Run entire library on every link</>}
              </Button>
            </div>
          </CardHeader>
          <CardContent className="space-y-3">
            <p className="text-xs text-muted-foreground">
              Crawled the target for anchors matching admin / manager / dashboard / etc., plus a common-path wordlist.
              Each link was HEAD-probed to classify whether it looks restricted (401/403/redirect) or publicly reachable.
              Clicking the batch button will run every enabled PoC against every URL below.
            </p>
            <div className="space-y-2">
              {discovered.map((l) => {
                const results = perLink[l.url] ?? {};
                const confirmedCount = Object.values(results).filter((r) => r.verdict === "confirmed").length;
                return (
                  <div key={l.url} className="rounded-md border border-border/60 bg-surface/40 p-3 space-y-2">
                    <div className="flex flex-wrap items-center gap-2">
                      <Badge variant="outline" className={l.looksRestricted ? "border-warning/40 text-warning bg-warning/5" : "border-border text-muted-foreground"}>
                        {l.looksRestricted ? "restricted" : "reachable"}
                      </Badge>
                      <Badge variant="outline" className="text-[10px]">{l.source}</Badge>
                      <Badge variant="outline" className="text-[10px]">kw: {l.keyword}</Badge>
                      <span className="font-mono text-xs break-all">{l.url}</span>
                      <span className="ml-auto text-xs text-muted-foreground">{l.reason}</span>
                    </div>
                    {Object.keys(results).length > 0 && (
                      <div className="flex flex-wrap gap-1 pt-1 border-t border-border/60">
                        {confirmedCount > 0 && (
                          <Badge variant="outline" className={verdictClass.confirmed}>
                            {confirmedCount} confirmed
                          </Badge>
                        )}
                        {Object.entries(results).map(([pocId, r]) => (
                          <Badge key={pocId} variant="outline" className={`${verdictClass[r.verdict]} text-[10px]`} title={r.summary}>
                            {pocId}: {r.verdict}
                          </Badge>
                        ))}
                      </div>
                    )}
                  </div>
                );
              })}
            </div>
          </CardContent>
        </Card>
      )}

      {/* Scan-driven findings section */}
      {scan ? (
        <Card>
          <CardHeader className="pb-2">
            <CardTitle className="text-sm">Findings from latest scan ({findings.length})</CardTitle>
          </CardHeader>
          <CardContent className="space-y-4">
            {findings.length === 0 ? (
              <p className="text-sm text-muted-foreground">No findings to validate. The latest scan is clean.</p>
            ) : (
              findings.map((f, i) => (
                <div key={f.id} className="rounded-md border border-border/60 bg-surface/40 p-4">
                  <div className="flex flex-wrap items-center gap-2">
                    <Badge variant="outline" className={riskClass[f.risk]}>{f.risk}</Badge>
                    <span className="font-mono text-xs text-muted-foreground">CVSS {f.cvss.toFixed(1)}</span>
                    <span className="font-mono text-xs text-muted-foreground">·</span>
                    <span className="font-mono text-xs text-muted-foreground">{f.module}</span>
                  </div>
                  <h3 className="mt-1 text-sm font-semibold">{i + 1}. {f.title}</h3>
                  <Separator className="my-3" />
                  <FindingValidator
                    finding={f}
                    targetUrl={scan.targetUrl}
                    globalAuthorize={authorize}
                    presetResult={findingResults[f.id] ?? null}
                    onResult={(r) => setFindingResults((prev) => ({ ...prev, [f.id]: r }))}
                  />
                </div>
              ))
            )}
          </CardContent>
        </Card>
      ) : (
        <EmptyScanState context="scan-driven findings" />
      )}
    </PageShell>
  );
}
