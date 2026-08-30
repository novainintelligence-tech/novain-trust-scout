import { createFileRoute } from "@tanstack/react-router";
import { Check, X } from "lucide-react";

import { PageHeader, PageShell } from "@/components/page-header";
import { SeverityBadge } from "@/components/severity-badge";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import {
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
} from "@/components/ui/table";
import { ScanRunner } from "@/components/scan-runner";
import { EmptyScanState } from "@/components/empty-scan-state";
import { RawBlock } from "@/components/raw-block";
import { useLatestScan } from "@/hooks/use-scans";

export const Route = createFileRoute("/cookies")({
  head: () => ({
    meta: [
      { title: "Cookie Inspector · NSL" },
      { name: "description", content: "Inspect cookie flags: HttpOnly, Secure, SameSite, domain, path, expiration, JS reachability." },
    ],
  }),
  component: CookiesPage,
});

function Flag({ on }: { on: boolean }) {
  return on ? <Check className="h-4 w-4 text-success" /> : <X className="h-4 w-4 text-critical" />;
}

function CookiesPage() {
  const { data: latest } = useLatestScan();

  return (
    <PageShell>
      <PageHeader
        eyebrow="Module · Cookies"
        title="Cookie Inspector"
        description="Every cookie set by the target's initial response, with flag audit and JavaScript-accessibility status."
        actions={<ScanRunner />}
      />

      {!latest ? (
        <EmptyScanState context="cookie" />
      ) : latest.cookies.length === 0 ? (
        <Card>
          <CardContent className="p-6 text-sm text-muted-foreground">
            No cookies were set by the target's initial response.
          </CardContent>
        </Card>
      ) : (
        <>
          <div className="grid gap-3 sm:grid-cols-3">
            {[
              { label: "Total cookies", value: latest.cookies.length },
              {
                label: "Compliant",
                value: latest.cookies.filter((c) => c.severity === "pass").length,
                tone: "text-success",
              },
              {
                label: "Failing",
                value: latest.cookies.filter((c) => c.severity === "fail").length,
                tone: "text-critical",
              },
            ].map((s) => (
              <Card key={s.label}>
                <CardContent className="pt-6">
                  <p className="font-mono text-[10px] uppercase tracking-widest text-muted-foreground">
                    {s.label}
                  </p>
                  <p className={`mt-1 font-mono text-3xl font-semibold ${s.tone ?? ""}`}>
                    {s.value}
                  </p>
                </CardContent>
              </Card>
            ))}
          </div>

          <Card>
            <CardHeader>
              <CardTitle className="text-sm">Cookies from {latest.targetHost}</CardTitle>
            </CardHeader>
            <CardContent className="p-0">
              <div className="overflow-x-auto">
                <Table>
                  <TableHeader>
                    <TableRow>
                      <TableHead>Name</TableHead>
                      <TableHead>Domain</TableHead>
                      <TableHead>Path</TableHead>
                      <TableHead className="text-center">HttpOnly</TableHead>
                      <TableHead className="text-center">Secure</TableHead>
                      <TableHead>SameSite</TableHead>
                      <TableHead>Expires</TableHead>
                      <TableHead className="text-right">Status</TableHead>
                    </TableRow>
                  </TableHeader>
                  <TableBody>
                    {latest.cookies.map((c) => (
                      <TableRow key={`${c.name}-${c.domain}-${c.path}`}>
                        <TableCell className="font-mono text-xs">{c.name}</TableCell>
                        <TableCell className="font-mono text-xs text-muted-foreground">
                          {c.domain}
                        </TableCell>
                        <TableCell className="font-mono text-xs text-muted-foreground">
                          {c.path}
                        </TableCell>
                        <TableCell className="text-center"><Flag on={c.httpOnly} /></TableCell>
                        <TableCell className="text-center"><Flag on={c.secure} /></TableCell>
                        <TableCell>
                          <span
                            className={
                              c.sameSite === "Missing" || c.sameSite === "None"
                                ? "font-mono text-xs text-warning"
                                : "font-mono text-xs"
                            }
                          >
                            {c.sameSite}
                          </span>
                        </TableCell>
                        <TableCell className="font-mono text-xs text-muted-foreground">
                          {c.expires}
                        </TableCell>
                        <TableCell className="text-right">
                          <SeverityBadge severity={c.severity} />
                        </TableCell>
                      </TableRow>
                    ))}
                  </TableBody>
                </Table>
              </div>
            </CardContent>
          </Card>

          <Card>
            <CardHeader className="pb-2">
              <CardTitle className="text-sm">Raw Set-Cookie headers</CardTitle>
              <p className="text-xs text-muted-foreground">
                Exact bytes returned by the target — unedited, in the order received.
              </p>
            </CardHeader>
            <CardContent className="space-y-2">
              {latest.evidence.setCookies.length === 0 ? (
                <RawBlock title="Set-Cookie">{""}</RawBlock>
              ) : (
                latest.evidence.setCookies.map((line, i) => (
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
