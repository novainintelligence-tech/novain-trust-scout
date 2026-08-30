import { createFileRoute } from "@tanstack/react-router";

import { PageHeader, PageShell } from "@/components/page-header";
import { SeverityBadge } from "@/components/severity-badge";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { ScanRunner } from "@/components/scan-runner";
import { EmptyScanState } from "@/components/empty-scan-state";
import { RawBlock, formatHeaders } from "@/components/raw-block";
import { useLatestScan } from "@/hooks/use-scans";

export const Route = createFileRoute("/headers")({
  head: () => ({
    meta: [
      { title: "HTTP Security Scanner · NSL" },
      { name: "description", content: "Audit response headers: CSP, HSTS, X-Frame-Options, Referrer-Policy, Permissions-Policy, X-Content-Type-Options." },
    ],
  }),
  component: HeadersPage,
});

function HeadersPage() {
  const { data: latest } = useLatestScan();

  return (
    <PageShell>
      <PageHeader
        eyebrow="Module · Headers"
        title="HTTP Security Scanner"
        description="Response header audit against modern hardening baselines."
        actions={<ScanRunner />}
      />

      {!latest ? (
        <EmptyScanState context="header" />
      ) : (
        <>
          <div className="grid gap-3">
            {latest.headers.map((h) => (
              <Card key={h.name}>
                <CardHeader className="flex flex-row items-start justify-between gap-3 pb-2">
                  <div>
                    <CardTitle className="font-mono text-sm">{h.name}</CardTitle>
                    <p className="mt-1 font-mono text-xs text-muted-foreground">
                      expected · {h.expected}
                    </p>
                  </div>
                  <SeverityBadge severity={h.severity} />
                </CardHeader>
                <CardContent className="space-y-2">
                  {h.value ? (
                    <RawBlock title={`${h.name} (raw value)`} maxHeight={140}>{h.value}</RawBlock>
                  ) : (
                    <p className="font-mono text-xs italic text-critical">— header not present in response —</p>
                  )}
                  <p className="text-xs text-muted-foreground">{h.note}</p>
                </CardContent>
              </Card>
            ))}
          </div>

          {latest.evidence.primary && (
            <Card>
              <CardHeader className="pb-2">
                <CardTitle className="text-sm">Raw response — {latest.evidence.primary.requestUrl}</CardTitle>
                <p className="text-xs text-muted-foreground">
                  HTTP {latest.evidence.primary.status} {latest.evidence.primary.statusText} ·{" "}
                  {latest.evidence.primary.contentType ?? "no content-type"} · {latest.evidence.primary.bodyBytes} bytes
                  {latest.evidence.primary.bodyTruncated ? " (truncated)" : ""}
                </p>
              </CardHeader>
              <CardContent className="space-y-3">
                <RawBlock title="All response headers" maxHeight={400}>
                  {formatHeaders(latest.evidence.primary.headers)}
                </RawBlock>
                {latest.evidence.primary.bodySnippet && (
                  <RawBlock title="Response body (first 12 000 chars)" maxHeight={400}>
                    {latest.evidence.primary.bodySnippet}
                  </RawBlock>
                )}
              </CardContent>
            </Card>
          )}
        </>
      )}
    </PageShell>
  );
}
