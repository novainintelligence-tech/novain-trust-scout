import { createFileRoute } from "@tanstack/react-router";

import { PageHeader, PageShell } from "@/components/page-header";
import { SeverityBadge } from "@/components/severity-badge";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { ScanRunner } from "@/components/scan-runner";
import { EmptyScanState } from "@/components/empty-scan-state";
import { RawBlock } from "@/components/raw-block";
import { useLatestScan } from "@/hooks/use-scans";

export const Route = createFileRoute("/sessions")({
  head: () => ({
    meta: [
      { title: "Session Security · NSL" },
      { name: "description", content: "HttpOnly, Secure, SameSite, and prefix posture for the target's session cookies." },
    ],
  }),
  component: SessionsPage,
});

function SessionsPage() {
  const { data: latest } = useLatestScan();

  const sessionRaw = latest
    ? latest.evidence.setCookies.filter((line) => /session|sid|auth|jwt|token/i.test(line.split("=")[0] ?? ""))
    : [];

  return (
    <PageShell>
      <PageHeader
        eyebrow="Module · Sessions"
        title="Session Security"
        description="Flag-by-flag posture for cookies that look like session identifiers on the target."
        actions={<ScanRunner />}
      />

      {!latest ? (
        <EmptyScanState context="session" />
      ) : (
        <>
          <div className="grid gap-3 md:grid-cols-2">
            {latest.sessions.map((s) => (
              <Card key={s.name}>
                <CardHeader className="flex flex-row items-center justify-between pb-2">
                  <CardTitle className="text-sm">{s.name}</CardTitle>
                  <SeverityBadge severity={s.status} />
                </CardHeader>
                <CardContent>
                  <p className="text-xs text-muted-foreground">{s.observation}</p>
                </CardContent>
              </Card>
            ))}
          </div>

          <Card>
            <CardHeader className="pb-2">
              <CardTitle className="text-sm">Raw session Set-Cookie headers ({sessionRaw.length})</CardTitle>
              <p className="text-xs text-muted-foreground">
                Filtered to cookies whose name matches session / sid / auth / jwt / token — exact bytes from the target.
              </p>
            </CardHeader>
            <CardContent className="space-y-2">
              {sessionRaw.length === 0 ? (
                <RawBlock title="Set-Cookie">{""}</RawBlock>
              ) : (
                sessionRaw.map((line, i) => (
                  <RawBlock key={i} title={`Set-Cookie #${i + 1}`}>{line}</RawBlock>
                ))
              )}
            </CardContent>
          </Card>
        </>
      )}
    </PageShell>
  );
}
