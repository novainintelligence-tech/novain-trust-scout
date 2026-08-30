import { createFileRoute } from "@tanstack/react-router";

import { PageHeader, PageShell } from "@/components/page-header";
import { SeverityBadge } from "@/components/severity-badge";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Progress } from "@/components/ui/progress";
import { ScanRunner } from "@/components/scan-runner";
import { EmptyScanState } from "@/components/empty-scan-state";
import { RawBlock, formatJson } from "@/components/raw-block";
import { useLatestScan } from "@/hooks/use-scans";

export const Route = createFileRoute("/tls")({
  head: () => ({
    meta: [
      { title: "TLS Checker · NSL" },
      { name: "description", content: "HTTPS enforcement, HSTS posture, and certificate expiration for the target host." },
    ],
  }),
  component: TlsPage,
});

function TlsPage() {
  const { data: latest } = useLatestScan();

  return (
    <PageShell>
      <PageHeader
        eyebrow="Module · TLS"
        title="TLS Checker"
        description="HTTPS enforcement, HSTS posture, and certificate expiration for the current target."
        actions={<ScanRunner />}
      />

      {!latest ? (
        <EmptyScanState context="TLS" />
      ) : (
        <>
          <div className="grid gap-4 lg:grid-cols-3">
            <Card className="lg:col-span-2">
              <CardHeader className="flex flex-row items-center justify-between pb-2">
                <div>
                  <p className="font-mono text-[10px] uppercase tracking-widest text-muted-foreground">Host</p>
                  <CardTitle className="font-mono text-lg">{latest.tls.host}</CardTitle>
                  <p className="font-mono text-xs text-muted-foreground">{latest.tls.scheme.toUpperCase()}</p>
                </div>
                <SeverityBadge severity={latest.tls.severity} />
              </CardHeader>
              <CardContent className="grid gap-4 sm:grid-cols-2">
                <Field label="Scheme" value={latest.tls.scheme} good={latest.tls.scheme === "https"} />
                <Field label="HSTS" value={latest.tls.hstsPresent ? "present" : "missing"} good={latest.tls.hstsPresent} />
                <Field label="HSTS max-age" value={latest.tls.hstsMaxAge ? `${latest.tls.hstsMaxAge}s` : "—"} mono />
                <Field label="includeSubDomains" value={latest.tls.hstsIncludeSubDomains ? "yes" : "no"} good={latest.tls.hstsIncludeSubDomains} />
                <Field label="Preloaded" value={latest.tls.hstsPreloaded ? "yes" : "no"} good={latest.tls.hstsPreloaded} />
                <Field label="Issuer" value={latest.tls.issuer ?? "unknown"} mono />
                <Field label="Valid from" value={latest.tls.validFrom ?? "—"} mono />
                <Field label="Valid to" value={latest.tls.validTo ?? "—"} mono />
              </CardContent>
            </Card>

            <Card>
              <CardHeader className="pb-2">
                <CardTitle className="text-sm">Expiration</CardTitle>
              </CardHeader>
              <CardContent className="space-y-3">
                {latest.tls.daysRemaining != null ? (
                  <>
                    <div className="flex items-baseline gap-2">
                      <span
                        className={`font-mono text-4xl font-semibold ${
                          latest.tls.daysRemaining < 14 ? "text-critical"
                          : latest.tls.daysRemaining < 30 ? "text-warning" : "text-success"
                        }`}
                      >
                        {latest.tls.daysRemaining}
                      </span>
                      <span className="text-sm text-muted-foreground">days remaining</span>
                    </div>
                    <Progress value={Math.max(0, Math.min(100, (latest.tls.daysRemaining / 90) * 100))} className="h-2" />
                  </>
                ) : (
                  <p className="text-sm text-muted-foreground">Certificate details unavailable (crt.sh lookup did not return data).</p>
                )}
                <p className="text-xs text-muted-foreground">{latest.tls.note}</p>
              </CardContent>
            </Card>
          </div>

          <Card>
            <CardHeader className="pb-2">
              <CardTitle className="text-sm">Raw evidence</CardTitle>
              <p className="text-xs text-muted-foreground">
                Exact bytes and payloads returned by the target and by crt.sh — unedited.
              </p>
            </CardHeader>
            <CardContent className="space-y-3">
              <RawBlock title="Strict-Transport-Security header" maxHeight={140}>
                {latest.tls.rawHstsHeader ?? ""}
              </RawBlock>
              <RawBlock title={`crt.sh certificate log (${latest.evidence.crtsh?.length ?? 0} entries)`} maxHeight={400}>
                {latest.evidence.crtsh ? formatJson(latest.evidence.crtsh) : ""}
              </RawBlock>
            </CardContent>
          </Card>
        </>
      )}
    </PageShell>
  );
}

function Field({ label, value, mono, good }: { label: string; value: string; mono?: boolean; good?: boolean }) {
  return (
    <div>
      <p className="font-mono text-[10px] uppercase tracking-widest text-muted-foreground">{label}</p>
      <p className={`mt-1 text-sm ${mono ? "font-mono" : ""} ${
        good === true ? "text-success" : good === false ? "text-critical" : ""
      }`}>{value}</p>
    </div>
  );
}
