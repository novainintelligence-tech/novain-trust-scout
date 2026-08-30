import { createFileRoute } from "@tanstack/react-router";
import { useEffect, useMemo, useState } from "react";
import {
  Bookmark,
  ClipboardPaste,
  Copy,
  Download,
  FileWarning,
  KeyRound,
  Puzzle,
  ShieldAlert,
  Trash2,
} from "lucide-react";
import { toast } from "sonner";

import { PageHeader, PageShell } from "@/components/page-header";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { Textarea } from "@/components/ui/textarea";
import { Badge } from "@/components/ui/badge";
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs";
import { RawBlock, formatJson } from "@/components/raw-block";
import { SeverityBadge } from "@/components/severity-badge";
import { useTarget } from "@/components/target-selector";
import { useLatestScan } from "@/hooks/use-scans";
import {
  analyzeSnapshot,
  buildBookmarklet,
  type CaptureAnalysis,
  type CookieClass,
  type SessionSnapshot,
} from "@/lib/session-capture";

export const Route = createFileRoute("/live-session")({
  head: () => ({
    meta: [
      { title: "Live Session · NOVAIN Security Lab" },
      { name: "description", content: "Capture cookies, JWTs, and browser storage from an authenticated browser session on the target." },
    ],
  }),
  component: LiveSessionPage,
});

const STORAGE_PREFIX = "nsl:capture:";

function classBadge(c: CookieClass): { label: string; className: string } {
  if (c === "session") return { label: "session", className: "border-critical/40 text-critical" };
  if (c === "auth") return { label: "auth", className: "border-primary/40 text-primary" };
  if (c === "csrf") return { label: "csrf", className: "border-warning/40 text-warning" };
  if (c === "preference") return { label: "pref", className: "border-border text-muted-foreground" };
  return { label: "other", className: "border-border text-muted-foreground" };
}

function LiveSessionPage() {
  const { target } = useTarget();
  let host = "";
  try { host = new URL(target).host; } catch { /* ignore */ }
  const { data: scan } = useLatestScan();

  const [pasted, setPasted] = useState("");
  const [analysis, setAnalysis] = useState<CaptureAnalysis | null>(null);
  const [error, setError] = useState<string | null>(null);

  const key = `${STORAGE_PREFIX}${host}`;

  useEffect(() => {
    if (typeof window === "undefined" || !host) { setAnalysis(null); return; }
    try {
      const raw = window.localStorage.getItem(key);
      if (raw) setAnalysis(JSON.parse(raw) as CaptureAnalysis);
      else setAnalysis(null);
    } catch { setAnalysis(null); }
  }, [key, host]);

  // Re-enrich with server-side cookie attributes when scan loads/changes.
  useEffect(() => {
    if (!analysis) return;
    if (!scan?.cookies?.length) return;
    const refreshed = analyzeSnapshot(analysis.raw, scan.cookies);
    setAnalysis(refreshed);
    try { window.localStorage.setItem(key, JSON.stringify(refreshed)); } catch { /* ignore */ }
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [scan?.id]);

  const bookmarklet = useMemo(() => buildBookmarklet(), []);

  const analyze = () => {
    setError(null);
    let snap: SessionSnapshot;
    try {
      const parsed = JSON.parse(pasted);
      // Extension "All tabs" produces an array — pick the one matching the current target, else the first.
      const one = Array.isArray(parsed)
        ? (parsed.find((s: SessionSnapshot) => host && (s.origin || "").includes(host)) ?? parsed[0])
        : parsed;
      snap = one as SessionSnapshot;
    } catch {
      // Fallback: treat as a raw document.cookie string
      snap = { cookies: pasted, at: new Date().toISOString() };
    }
    if (!snap.origin && host) snap.origin = `https://${host}`;
    const a = analyzeSnapshot(snap, scan?.cookies);
    setAnalysis(a);
    try { window.localStorage.setItem(key, JSON.stringify(a)); } catch { /* ignore */ }
    toast.success("Snapshot analyzed", {
      description: `${a.cookies.length} cookies · ${a.localStorage.length} localStorage · ${a.sessionStorage.length} sessionStorage`,
    });
    setPasted("");
  };

  const clear = () => {
    setAnalysis(null);
    try { window.localStorage.removeItem(key); } catch { /* ignore */ }
    toast.success("Capture cleared");
  };

  const copyBookmarklet = async () => {
    try {
      await navigator.clipboard.writeText(bookmarklet);
      toast.success("Bookmarklet copied", { description: "Create a new bookmark and paste as the URL." });
    } catch {
      toast.error("Copy failed — drag the button to your bookmarks bar instead.");
    }
  };

  const downloadExtension = async () => {
    try {
      const res = await fetch("/nsl-extension.zip");
      if (!res.ok) throw new Error(`Download failed: ${res.status}`);
      const blob = await res.blob();
      const a = document.createElement("a");
      a.href = URL.createObjectURL(blob);
      a.download = "nsl-extension.zip";
      a.click();
      URL.revokeObjectURL(a.href);
      toast.success("Extension downloaded", { description: "Unzip, then load unpacked at chrome://extensions" });
    } catch (e) {
      toast.error((e as Error).message);
    }
  };

  const originMatches = !host || !analysis?.origin || analysis.origin.includes(host);

  return (
    <PageShell>
      <PageHeader
        eyebrow="Live Session"
        title="Live browser-session capture"
        description="Capture cookies, JWTs, and browser storage from an authenticated tab on the target. Cross-origin JS cannot read another site's storage, so this runs on the target page via a bookmarklet."
      />

      <Card className="border-warning/40 bg-warning/5">
        <CardContent className="flex gap-3 p-4 text-sm">
          <FileWarning className="mt-0.5 h-4 w-4 shrink-0 text-warning" />
          <div className="space-y-1 text-muted-foreground">
            <p className="text-foreground"><b>Browser security</b> prevents NSL from reading another origin's cookies or storage directly.</p>
            <p>The bookmarklet runs on the target tab and captures only what JavaScript on that page can see: <code className="font-mono">document.cookie</code> (non-HttpOnly only), <code className="font-mono">localStorage</code>, and <code className="font-mono">sessionStorage</code>. Attributes such as HttpOnly / Secure / SameSite are enriched from the server-side scan's <code className="font-mono">Set-Cookie</code> evidence.</p>
            <p><b>Only run this on sites you own or are authorized to test.</b> The snapshot may contain live session tokens — treat it like a password.</p>
          </div>
        </CardContent>
      </Card>

      <Card className="border-primary/40 bg-primary/5">
        <CardHeader className="pb-2">
          <CardTitle className="flex items-center gap-2 text-sm">
            <Puzzle className="h-4 w-4 text-primary" /> Browser extension (recommended)
          </CardTitle>
        </CardHeader>
        <CardContent className="space-y-3 text-sm">
          <p className="text-muted-foreground">
            The bookmarklet cannot see <b>HttpOnly</b> cookies. The NSL Capture extension uses the browser's <code className="font-mono">chrome.cookies</code> API to read every cookie — including HttpOnly — plus <code className="font-mono">localStorage</code> and <code className="font-mono">sessionStorage</code> — from your active tab or every open tab in one click.
          </p>
          <div className="flex flex-wrap gap-2">
            <Button size="sm" onClick={downloadExtension}>
              <Download className="h-3.5 w-3.5" /> Download NSL Capture (.zip)
            </Button>
          </div>
          <ol className="ml-4 list-decimal space-y-1 text-xs text-muted-foreground">
            <li>Unzip the downloaded file.</li>
            <li>Open <code className="font-mono">chrome://extensions</code> (Chrome, Edge, Brave, Arc, Opera).</li>
            <li>Enable <b>Developer mode</b> (top-right toggle).</li>
            <li>Click <b>Load unpacked</b> and pick the unzipped folder.</li>
            <li>Open the extension popup on your logged-in tab → <b>Active tab</b> or <b>All open tabs</b> → <b>Copy JSON</b>.</li>
            <li>Paste the JSON into Step 2 below.</li>
          </ol>
          <p className="text-xs text-warning">Only run against sites you own or are authorized to test. The capture contains live session tokens.</p>
        </CardContent>
      </Card>

      <div className="grid gap-4 lg:grid-cols-2">
        <Card>
          <CardHeader className="pb-2">
            <CardTitle className="flex items-center gap-2 text-sm">
              <Bookmark className="h-4 w-4 text-primary" /> Step 1 · Install the bookmarklet
            </CardTitle>
          </CardHeader>
          <CardContent className="space-y-3 text-sm">
            <p className="text-muted-foreground">
              Drag this button to your bookmarks bar, or click <b>Copy</b> and create a bookmark manually with this URL.
            </p>
            <div className="flex flex-wrap items-center gap-2">
              <a
                href={bookmarklet}
                onClick={(e) => e.preventDefault()}
                draggable
                className="inline-flex items-center gap-1.5 rounded-md border border-primary/50 bg-primary/10 px-3 py-1.5 font-mono text-xs text-primary hover:bg-primary/20"
              >
                <Bookmark className="h-3.5 w-3.5" /> NSL · Capture session
              </a>
              <Button size="sm" variant="outline" onClick={copyBookmarklet}>
                <Copy className="h-3.5 w-3.5" /> Copy bookmarklet URL
              </Button>
            </div>
            <p className="text-xs text-muted-foreground">
              Then open the target site in another tab, sign in, and click the bookmarklet. It copies a JSON snapshot to your clipboard.
            </p>
          </CardContent>
        </Card>

        <Card>
          <CardHeader className="pb-2">
            <CardTitle className="flex items-center gap-2 text-sm">
              <ClipboardPaste className="h-4 w-4 text-primary" /> Step 2 · Paste snapshot
            </CardTitle>
          </CardHeader>
          <CardContent className="space-y-3">
            <Textarea
              value={pasted}
              onChange={(e) => setPasted(e.target.value)}
              placeholder='{"href":"...","cookies":"...","localStorage":{...}}  — or a raw document.cookie string'
              className="min-h-[140px] font-mono text-xs"
            />
            <div className="flex flex-wrap items-center gap-2">
              <Button size="sm" onClick={analyze} disabled={!pasted.trim()}>Analyze snapshot</Button>
              {analysis && (
                <Button size="sm" variant="ghost" onClick={clear}>
                  <Trash2 className="h-3.5 w-3.5" /> Clear stored capture
                </Button>
              )}
            </div>
            {error && <p className="text-xs text-critical">{error}</p>}
          </CardContent>
        </Card>
      </div>

      {analysis && (
        <>
          <Card>
            <CardHeader className="pb-2">
              <CardTitle className="text-sm">Capture summary</CardTitle>
            </CardHeader>
            <CardContent className="grid gap-3 text-sm sm:grid-cols-2 md:grid-cols-4">
              <SummaryStat label="Session cookies" value={analysis.summary.sessionCookies} tone="critical" />
              <SummaryStat label="Auth tokens" value={analysis.summary.authTokens} tone="primary" />
              <SummaryStat label="CSRF tokens" value={analysis.summary.csrfTokens} tone="warning" />
              <SummaryStat label="JWTs decoded" value={analysis.summary.jwts} tone="primary" />
              <SummaryStat label="localStorage" value={analysis.summary.localStorageEntries} />
              <SummaryStat label="sessionStorage" value={analysis.summary.sessionStorageEntries} />
              <SummaryStat label="HttpOnly known" value={analysis.summary.httpOnlyKnown} />
              <SummaryStat label="Cookies total" value={analysis.cookies.length} />
              <div className="md:col-span-4 flex flex-wrap gap-3 text-xs text-muted-foreground">
                <span>Origin captured: <span className="font-mono">{analysis.origin ?? "—"}</span></span>
                <span>Captured at: <span className="font-mono">{new Date(analysis.capturedAt).toLocaleString()}</span></span>
                {!originMatches && (
                  <SeverityBadge severity="warn">Origin doesn't match target ({host})</SeverityBadge>
                )}
              </div>
            </CardContent>
          </Card>

          {analysis.warnings.length > 0 && (
            <Card className="border-warning/40">
              <CardHeader className="pb-2">
                <CardTitle className="flex items-center gap-2 text-sm">
                  <ShieldAlert className="h-4 w-4 text-warning" /> Notes on this capture
                </CardTitle>
              </CardHeader>
              <CardContent>
                <ul className="space-y-1 text-sm text-muted-foreground">
                  {analysis.warnings.map((w) => <li key={w}>• {w}</li>)}
                </ul>
              </CardContent>
            </Card>
          )}

          <Tabs defaultValue="cookies">
            <TabsList>
              <TabsTrigger value="cookies">Cookies ({analysis.cookies.length})</TabsTrigger>
              <TabsTrigger value="local">localStorage ({analysis.localStorage.length})</TabsTrigger>
              <TabsTrigger value="session">sessionStorage ({analysis.sessionStorage.length})</TabsTrigger>
              <TabsTrigger value="raw">Raw snapshot</TabsTrigger>
            </TabsList>

            <TabsContent value="cookies" className="space-y-3">
              {analysis.cookies.length === 0 && <EmptyBlock text="No cookies observed." />}
              {analysis.cookies.map((c, idx) => (
                <Card key={`${c.name}-${idx}`}>
                  <CardHeader className="pb-2">
                    <div className="flex flex-wrap items-center gap-2">
                      <span className="font-mono text-sm font-semibold">{c.name}</span>
                      {c.classification.map((cl) => {
                        const b = classBadge(cl);
                        return <Badge key={cl} variant="outline" className={b.className}>{b.label}</Badge>;
                      })}
                      {!c.jsVisible && <Badge variant="outline" className="border-info/40 text-info">HttpOnly (server-only)</Badge>}
                      {c.attributes?.secure && <Badge variant="outline" className="border-success/40 text-success">Secure</Badge>}
                      {c.attributes?.sameSite && <Badge variant="outline" className="border-border">SameSite={c.attributes.sameSite}</Badge>}
                    </div>
                  </CardHeader>
                  <CardContent className="space-y-2 text-sm">
                    <div className="grid gap-2 sm:grid-cols-2 md:grid-cols-3 text-xs">
                      <Attr label="Domain" value={c.attributes?.domain} />
                      <Attr label="Path" value={c.attributes?.path} />
                      <Attr label="Expires" value={c.attributes?.expires} />
                      <Attr label="HttpOnly" value={c.attributes ? String(c.attributes.httpOnly) : undefined} />
                      <Attr label="Secure" value={c.attributes ? String(c.attributes.secure) : undefined} />
                      <Attr label="SameSite" value={c.attributes?.sameSite} />
                    </div>
                    <div>
                      <div className="mb-1 font-mono text-[10px] uppercase tracking-widest text-muted-foreground">Value</div>
                      <RawBlock title={`${c.name} value`}>{c.value}</RawBlock>
                    </div>
                    {c.jwt && <JwtBlock title={`${c.name} — decoded JWT`} jwt={c.jwt} />}
                  </CardContent>
                </Card>
              ))}
            </TabsContent>

            <TabsContent value="local" className="space-y-3">
              {analysis.localStorage.length === 0 && <EmptyBlock text="No localStorage entries captured." />}
              {analysis.localStorage.map((s) => <StorageCard key={s.key} entry={s} />)}
            </TabsContent>

            <TabsContent value="session" className="space-y-3">
              {analysis.sessionStorage.length === 0 && <EmptyBlock text="No sessionStorage entries captured." />}
              {analysis.sessionStorage.map((s) => <StorageCard key={s.key} entry={s} />)}
            </TabsContent>

            <TabsContent value="raw">
              <RawBlock title="raw snapshot JSON" maxHeight={500}>{formatJson(analysis.raw)}</RawBlock>
            </TabsContent>
          </Tabs>
        </>
      )}
    </PageShell>
  );
}

function SummaryStat({ label, value, tone }: { label: string; value: number; tone?: "critical" | "primary" | "warning" }) {
  const toneClass =
    tone === "critical" ? "text-critical"
    : tone === "primary" ? "text-primary"
    : tone === "warning" ? "text-warning"
    : "text-foreground";
  return (
    <div className="rounded-md border border-border/60 bg-surface/40 p-3">
      <div className="font-mono text-[10px] uppercase tracking-widest text-muted-foreground">{label}</div>
      <div className={`mt-1 font-mono text-2xl font-semibold ${toneClass}`}>{value}</div>
    </div>
  );
}

function Attr({ label, value }: { label: string; value: string | undefined }) {
  return (
    <div className="rounded border border-border/60 bg-background/40 px-2 py-1">
      <div className="font-mono text-[9px] uppercase tracking-widest text-muted-foreground">{label}</div>
      <div className="font-mono text-[11px]">{value ?? "—"}</div>
    </div>
  );
}

function JwtBlock({ title, jwt }: { title: string; jwt: NonNullable<CaptureAnalysis["cookies"][number]["jwt"]> }) {
  return (
    <div className="rounded-md border border-primary/30 bg-primary/5 p-3">
      <div className="mb-2 flex flex-wrap items-center gap-2">
        <KeyRound className="h-3.5 w-3.5 text-primary" />
        <span className="font-mono text-[10px] uppercase tracking-widest text-primary">{title}</span>
        {jwt.expiresAt && <Badge variant="outline" className="border-border text-xs">exp {new Date(jwt.expiresAt).toLocaleString()}</Badge>}
        {jwt.issuer && <Badge variant="outline" className="border-border text-xs">iss {jwt.issuer}</Badge>}
        {jwt.subject && <Badge variant="outline" className="border-border text-xs">sub {jwt.subject}</Badge>}
      </div>
      <div className="grid gap-2 md:grid-cols-2">
        <RawBlock title="header">{formatJson(jwt.header)}</RawBlock>
        <RawBlock title="payload">{formatJson(jwt.payload)}</RawBlock>
      </div>
    </div>
  );
}

function StorageCard({ entry }: { entry: CaptureAnalysis["localStorage"][number] }) {
  return (
    <Card>
      <CardHeader className="pb-2">
        <div className="flex flex-wrap items-center gap-2">
          <span className="font-mono text-sm font-semibold">{entry.key}</span>
          <Badge variant="outline" className="border-border text-xs">{entry.bytes} bytes</Badge>
          {entry.classification.map((cl) => {
            const b = classBadge(cl);
            return <Badge key={cl} variant="outline" className={b.className}>{b.label}</Badge>;
          })}
        </div>
      </CardHeader>
      <CardContent className="space-y-2">
        <RawBlock title="value">{entry.value}</RawBlock>
        {entry.jwt && <JwtBlock title="decoded JWT" jwt={entry.jwt} />}
      </CardContent>
    </Card>
  );
}

function EmptyBlock({ text }: { text: string }) {
  return (
    <Card>
      <CardContent className="p-6 text-center text-sm text-muted-foreground">{text}</CardContent>
    </Card>
  );
}
