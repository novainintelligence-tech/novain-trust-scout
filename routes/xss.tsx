import { createFileRoute } from "@tanstack/react-router";

import { PageHeader, PageShell } from "@/components/page-header";
import { SeverityBadge } from "@/components/severity-badge";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { ScanRunner } from "@/components/scan-runner";
import { EmptyScanState } from "@/components/empty-scan-state";
import { RawBlock, formatHeaders } from "@/components/raw-block";
import { useLatestScan } from "@/hooks/use-scans";

export const Route = createFileRoute("/xss")({
  head: () => ({
    meta: [
      { title: "XSS Test Suite · NSL" },
      { name: "description", content: "Evaluates CSP, MIME-sniffing, reflected-payload behavior, and CORS reflection against XSS execution paths." },
    ],
  }),
  component: XssPage,
});

function XssPage() {
  const { data: latest } = useLatestScan();

  return (
    <PageShell>
      <PageHeader
        eyebrow="Module · XSS"
        title="XSS Test Suite"
        description="Active reflected-payload probe plus CSP, MIME-sniffing, and CORS reflection posture."
        actions={<ScanRunner />}
      />

      {!latest ? (
        <EmptyScanState context="XSS" />
      ) : (
        <>
          <Card>
            <CardHeader className="pb-3">
              <CardTitle className="text-sm">Findings for {latest.targetHost}</CardTitle>
            </CardHeader>
            <CardContent className="space-y-3">
              {latest.xss.map((r) => (
                <div key={r.id} className="rounded-md border border-border/60 bg-surface/40 p-3">
                  <div className="flex flex-wrap items-center justify-between gap-2">
                    <div className="flex items-center gap-2">
                      <span className="font-mono text-xs text-muted-foreground">{r.id}</span>
                      <Badge variant="secondary" className="text-[10px]">{r.category}</Badge>
                      <span className="text-sm">{r.vector}</span>
                    </div>
                    <SeverityBadge severity={r.severity} />
                  </div>
                  <p className="mt-2 text-xs text-muted-foreground">{r.detail}</p>
                </div>
              ))}
            </CardContent>
          </Card>

          {latest.evidence.xssProbe && (
            <Card>
              <CardHeader className="pb-2">
                <CardTitle className="text-sm">Reflected-XSS probe — raw evidence</CardTitle>
                <p className="text-xs text-muted-foreground">
                  Request URL: <span className="font-mono">{latest.evidence.xssProbe.requestUrl}</span> · HTTP{" "}
                  {latest.evidence.xssProbe.status} {latest.evidence.xssProbe.statusText} ·{" "}
                  {latest.evidence.xssProbe.contentType ?? "no content-type"}
                </p>
              </CardHeader>
              <CardContent className="space-y-3">
                <RawBlock title={`Payload injected (canary=${latest.evidence.xssProbe.canary})`} maxHeight={90}>
                  {latest.evidence.xssProbe.payload}
                </RawBlock>
                <RawBlock title="Response headers" maxHeight={260}>
                  {formatHeaders(latest.evidence.xssProbe.headers)}
                </RawBlock>
                {latest.evidence.xssProbe.reflectionMatch && (
                  <RawBlock title="Reflection context (± 80 chars around canary)" maxHeight={140}>
                    {latest.evidence.xssProbe.reflectionMatch}
                  </RawBlock>
                )}
                <RawBlock title="Response body (first 12 000 chars)" maxHeight={360}>
                  {latest.evidence.xssProbe.bodySnippet}
                </RawBlock>
              </CardContent>
            </Card>
          )}

          {latest.evidence.corsProbe && (
            <Card>
              <CardHeader className="pb-2">
                <CardTitle className="text-sm">CORS reflection probe — raw evidence</CardTitle>
                <p className="text-xs text-muted-foreground">
                  Request URL: <span className="font-mono">{latest.evidence.corsProbe.requestUrl}</span> · Origin:{" "}
                  <span className="font-mono">{latest.evidence.corsProbe.requestOrigin}</span> · HTTP{" "}
                  {latest.evidence.corsProbe.status} {latest.evidence.corsProbe.statusText}
                </p>
              </CardHeader>
              <CardContent>
                <RawBlock title="Response headers" maxHeight={320}>
                  {formatHeaders(latest.evidence.corsProbe.headers)}
                </RawBlock>
              </CardContent>
            </Card>
          )}
        </>
      )}
    </PageShell>
  );
}
