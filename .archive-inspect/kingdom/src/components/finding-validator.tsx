import { useState } from "react";
import { useServerFn } from "@tanstack/react-start";
import { Loader2, PlayCircle, ShieldAlert } from "lucide-react";
import { toast } from "sonner";

import { Button } from "@/components/ui/button";
import { Badge } from "@/components/ui/badge";
import { Checkbox } from "@/components/ui/checkbox";
import { Label } from "@/components/ui/label";
import { RawBlock } from "@/components/raw-block";
import type { Finding } from "@/lib/engagement";
import { runValidation, type ValidationResult, type Verdict } from "@/lib/validator.functions";
import { toCurl } from "@/lib/validator-command";

const ACTIVE_PREFIXES = ["csrf-"];

export function isActiveFinding(f: Finding): boolean {
  return ACTIVE_PREFIXES.some((p) => f.id.startsWith(p));
}

const verdictClass: Record<Verdict, string> = {
  confirmed: "border-critical/50 text-critical bg-critical/10",
  "not-exploitable": "border-success/40 text-success bg-success/5",
  inconclusive: "border-warning/40 text-warning bg-warning/5",
  skipped: "border-border text-muted-foreground",
  error: "border-critical/50 text-critical bg-critical/10",
};

const verdictLabel: Record<Verdict, string> = {
  confirmed: "Confirmed",
  "not-exploitable": "Not exploitable",
  inconclusive: "Inconclusive",
  skipped: "Skipped",
  error: "Error",
};

interface Props {
  finding: Finding;
  targetUrl: string;
  /** Global authorization flag (from /validator). If undefined, per-card checkbox is shown. */
  globalAuthorize?: boolean;
  /** Optional pre-loaded result to display (used by batch run). */
  presetResult?: ValidationResult | null;
  onResult?: (r: ValidationResult) => void;
}

export function FindingValidator({ finding, targetUrl, globalAuthorize, presetResult, onResult }: Props) {
  const [result, setResult] = useState<ValidationResult | null>(presetResult ?? null);
  const [busy, setBusy] = useState(false);
  const [localAuthorize, setLocalAuthorize] = useState(false);
  const run = useServerFn(runValidation);
  const active = isActiveFinding(finding);
  const authorizeActive = globalAuthorize ?? localAuthorize;

  // Extract path hint for csrf-/recon- findings so the server knows what to hit.
  const pathHint =
    finding.id.startsWith("csrf-") ? finding.id.slice(5) :
    finding.id.startsWith("recon-") ? finding.evidence.match(/https?:\/\/[^\s]+/)?.[0] :
    undefined;

  const onRun = async () => {
    setBusy(true);
    try {
      const r = await run({ data: { findingId: finding.id, targetUrl, path: pathHint, authorizeActive } });
      setResult(r);
      onResult?.(r);
      if (r.verdict === "confirmed") toast.error(`Confirmed: ${finding.title}`);
      else if (r.verdict === "not-exploitable") toast.success("PoC did not exploit — control effective");
      else toast.info(verdictLabel[r.verdict]);
    } catch (e) {
      const msg = e instanceof Error ? e.message : String(e);
      const r: ValidationResult = { findingId: finding.id, ranAt: new Date().toISOString(), verdict: "error", summary: msg, poc: "", active, steps: [] };
      setResult(r);
      onResult?.(r);
      toast.error(`PoC error: ${msg}`);
    } finally {
      setBusy(false);
    }
  };

  const canRun = !active || authorizeActive;

  return (
    <div className="space-y-3">
      <div className="flex flex-wrap items-center gap-2">
        <Button size="sm" variant={active ? "destructive" : "outline"} disabled={busy || !canRun} onClick={onRun}>
          {busy ? <Loader2 className="h-3.5 w-3.5 animate-spin" /> : <PlayCircle className="h-3.5 w-3.5" />}
          {active ? "Run active PoC" : "Validate"}
        </Button>
        {active && (
          <Badge variant="outline" className="border-critical/40 text-critical bg-critical/5 gap-1">
            <ShieldAlert className="h-3 w-3" /> Active test
          </Badge>
        )}
        {result && (
          <Badge variant="outline" className={verdictClass[result.verdict]}>
            {verdictLabel[result.verdict]}
          </Badge>
        )}
        {active && globalAuthorize === undefined && (
          <div className="flex items-center gap-2">
            <Checkbox
              id={`auth-${finding.id}`}
              checked={localAuthorize}
              onCheckedChange={(v) => setLocalAuthorize(v === true)}
            />
            <Label htmlFor={`auth-${finding.id}`} className="text-xs text-muted-foreground">
              I authorize active exploitation on this target I own
            </Label>
          </div>
        )}
      </div>

      {result && (
        <div className="space-y-2 rounded-md border border-border/60 bg-surface/40 p-3">
          <div className="text-sm">{result.summary}</div>
          {result.poc && (
            <div className="text-xs text-muted-foreground">
              <span className="font-mono uppercase tracking-widest text-[10px]">PoC</span> · {result.poc}
            </div>
          )}
          {result.steps.map((s, i) => (
            <div key={i} className="space-y-1">
              <div className="text-xs font-mono">
                {s.method} {s.url} → {s.status ?? "no response"}{s.error ? ` (${s.error})` : ""}
              </div>
              <RawBlock title="command · reproduces this request exactly (curl)">
                {toCurl(s)}
              </RawBlock>
              <div className="text-[11px] text-muted-foreground">
                Runtime: <code>fetch()</code> with <code>redirect: "manual"</code>, 8s timeout, response headers &amp; body captured verbatim.
              </div>
              {Object.keys(s.responseHeaders).length > 0 && (
                <RawBlock title="response headers">
                  {Object.entries(s.responseHeaders).map(([k, v]) => `${k}: ${v}`).join("\n")}
                </RawBlock>
              )}
              {s.setCookies.length > 0 && (
                <RawBlock title="set-cookie">{s.setCookies.join("\n")}</RawBlock>
              )}
              {s.bodySnippet && (
                <RawBlock title={`body (${s.bodyBytes} bytes${s.bodyTruncated ? ", truncated" : ""})`}>
                  {s.bodySnippet}
                </RawBlock>
              )}
            </div>
          ))}
        </div>
      )}
    </div>
  );
}
