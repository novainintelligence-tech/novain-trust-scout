import { createFileRoute } from "@tanstack/react-router";

import { PageHeader, PageShell } from "@/components/page-header";
import { SeverityBadge } from "@/components/severity-badge";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { ScanRunner } from "@/components/scan-runner";
import { EmptyScanState } from "@/components/empty-scan-state";
import { RawBlock, formatHeaders } from "@/components/raw-block";
import { useLatestScan } from "@/hooks/use-scans";
import type { PathProbeEvidence, ReconCategory } from "@/lib/scan-types";

export const Route = createFileRoute("/recon")({
  head: () => ({
    meta: [
      { title: "Reconnaissance · NSL" },
      { name: "description", content: "Exposed files, security.txt, robots, mixed content, and HTTP→HTTPS redirect posture." },
    ],
  }),
  component: ReconPage,
});

const CATEGORY_LABEL: Record<ReconCategory, string> = {
  meta: "Metadata & Disclosure",
  exposure: "Sensitive Path Exposure",
  "mixed-content": "Mixed Content",
  redirect: "Redirect / TLS Enforcement",
};

function ReconPage() {
  const { data: latest } = useLatestScan();

  const findEvidence = (path?: string): PathProbeEvidence | undefined => {
    if (!path || !latest) return undefined;
    return latest.evidence.exposure.find((e) => e.path === path)
      ?? latest.evidence.meta.find((e) => e.path === path);
  };

  return (
    <PageShell>
      <PageHeader
        eyebrow="Module · Recon"
        title="Reconnaissance"
        description="Active probes for exposed files, security metadata, mixed content, and HTTP-to-HTTPS enforcement."
        actions={<ScanRunner />}
      />

      {!latest ? (
        <EmptyScanState context="reconnaissance" />
      ) : (
        <div className="grid gap-4">
          {(Object.keys(CATEGORY_LABEL) as ReconCategory[]).map((cat) => {
            const items = latest.recon.filter((r) => r.category === cat);
            if (items.length === 0) return null;
            return (
              <Card key={cat}>
                <CardHeader className="pb-2">
                  <CardTitle className="text-sm">{CATEGORY_LABEL[cat]}</CardTitle>
                </CardHeader>
                <CardContent className="space-y-3">
                  {items.map((r) => {
                    const ev = findEvidence(r.target);
                    return (
                      <div key={r.id} className="rounded-md border border-border/60 bg-surface/40 p-3">
                        <div className="flex flex-wrap items-center justify-between gap-2">
                          <div className="flex items-center gap-2">
                            <span className="text-sm font-medium">{r.name}</span>
                            {r.target && (
                              <Badge variant="secondary" className="font-mono text-[10px]">{r.target}</Badge>
                            )}
                          </div>
                          <SeverityBadge severity={r.severity} />
                        </div>
                        <p className="mt-1 text-xs text-muted-foreground">{r.note}</p>
                        {ev && (
                          <div className="mt-3 space-y-2">
                            <p className="font-mono text-[10px] text-muted-foreground">
                              {ev.method} {ev.requestUrl} → HTTP {ev.status} {ev.statusText} · {ev.bodyBytes} bytes
                            </p>
                            <RawBlock title="Response headers" maxHeight={200}>
                              {formatHeaders(ev.headers)}
                            </RawBlock>
                            <RawBlock title="Response body (captured bytes)" maxHeight={220}>
                              {ev.bodySnippet}
                            </RawBlock>
                          </div>
                        )}
                      </div>
                    );
                  })}
                </CardContent>
              </Card>
            );
          })}

          {latest.evidence.redirect && (
            <Card>
              <CardHeader className="pb-2">
                <CardTitle className="text-sm">HTTP → HTTPS redirect probe — raw response</CardTitle>
              </CardHeader>
              <CardContent className="space-y-3">
                <p className="font-mono text-[10px] text-muted-foreground">
                  HEAD {latest.evidence.redirect.requestUrl} → HTTP {latest.evidence.redirect.status}{" "}
                  {latest.evidence.redirect.statusText}
                  {latest.evidence.redirect.location ? ` · Location: ${latest.evidence.redirect.location}` : ""}
                </p>
                <RawBlock title="Response headers" maxHeight={220}>
                  {formatHeaders(latest.evidence.redirect.headers)}
                </RawBlock>
              </CardContent>
            </Card>
          )}

          {latest.evidence.mixedContentRefs.length > 0 && (
            <Card>
              <CardHeader className="pb-2">
                <CardTitle className="text-sm">Mixed-content references ({latest.evidence.mixedContentRefs.length})</CardTitle>
                <p className="text-xs text-muted-foreground">Every http:// src/href found in the HTTPS response body.</p>
              </CardHeader>
              <CardContent>
                <RawBlock title="http:// references" maxHeight={320}>
                  {latest.evidence.mixedContentRefs.join("\n")}
                </RawBlock>
              </CardContent>
            </Card>
          )}
        </div>
      )}
    </PageShell>
  );
}
