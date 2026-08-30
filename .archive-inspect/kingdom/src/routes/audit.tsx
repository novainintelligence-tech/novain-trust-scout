import { createFileRoute, Link } from "@tanstack/react-router";
import { Download, Eye, FileDown, Search } from "lucide-react";
import { useMemo, useState } from "react";

import { PageHeader, PageShell } from "@/components/page-header";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Input } from "@/components/ui/input";
import {
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
} from "@/components/ui/table";
import { EmptyScanState } from "@/components/empty-scan-state";
import { useRecentScans } from "@/hooks/use-scans";
import { downloadScanPdf } from "@/lib/pdf-export";
import type { ScanResult } from "@/lib/scan-types";

export const Route = createFileRoute("/audit")({
  head: () => ({
    meta: [
      { title: "Scan History · NSL" },
      { name: "description", content: "Immutable log of every security scan run from this account." },
    ],
  }),
  component: AuditPage,
});

function AuditPage() {
  const [q, setQ] = useState("");
  const { data: history } = useRecentScans();

  const filtered = useMemo(
    () =>
      (history ?? []).filter((e) =>
        q
          ? [e.targetHost, e.targetUrl, e.status, String(e.overallScore)]
              .join(" ").toLowerCase().includes(q.toLowerCase())
          : true,
      ),
    [q, history],
  );

  const latestPerHost = useMemo(() => {
    const map = new Map<string, ScanResult>();
    for (const s of history ?? []) {
      if (!map.has(s.targetHost)) map.set(s.targetHost, s);
    }
    return Array.from(map.values());
  }, [history]);

  const exportCsv = () => {
    const rows = [
      ["time", "host", "url", "status", "score", "duration_ms"],
      ...filtered.map((e) => [
        e.createdAt, e.targetHost, e.targetUrl, e.status,
        String(e.overallScore), String(e.durationMs ?? ""),
      ]),
    ];
    const csv = rows.map((r) => r.map((c) => `"${c.replace(/"/g, '""')}"`).join(",")).join("\n");
    const blob = new Blob([csv], { type: "text/csv" });
    const url = URL.createObjectURL(blob);
    const a = document.createElement("a");
    a.href = url;
    a.download = `nsl-scans-${new Date().toISOString().slice(0, 10)}.csv`;
    a.click();
    URL.revokeObjectURL(url);
  };

  return (
    <PageShell>
      <PageHeader
        eyebrow="Module · Audit"
        title="Scan History"
        description="Every scan you have run, saved to your account. Review or export any past result."
        actions={
          <Button size="sm" variant="outline" onClick={exportCsv} disabled={filtered.length === 0}>
            <Download className="h-4 w-4" /> Export CSV
          </Button>
        }
      />

      {!history || history.length === 0 ? (
        <EmptyScanState context="audit" />
      ) : (
        <>
          <Card>
            <CardHeader className="pb-3">
              <CardTitle className="text-sm">Latest scan per target</CardTitle>
              <p className="text-xs text-muted-foreground">Jump to the most recent scan for each distinct host.</p>
            </CardHeader>
            <CardContent className="grid gap-2 sm:grid-cols-2 lg:grid-cols-3">
              {latestPerHost.map((s) => (
                <div key={s.targetHost} className="flex items-center justify-between gap-2 rounded-md border border-border/60 bg-surface/40 p-3">
                  <div className="min-w-0">
                    <div className="truncate font-mono text-xs font-semibold">{s.targetHost}</div>
                    <div className="text-[11px] text-muted-foreground">
                      {new Date(s.createdAt).toLocaleString()} · {s.overallScore}/100
                    </div>
                  </div>
                  <div className="flex shrink-0 gap-1">
                    <Button asChild size="sm" variant="outline">
                      <Link to="/scan/$scanId" params={{ scanId: s.id }}>
                        <Eye className="h-3.5 w-3.5" /> Review
                      </Link>
                    </Button>
                    <Button size="sm" variant="ghost" onClick={() => downloadScanPdf(s)} title="Export PDF">
                      <FileDown className="h-3.5 w-3.5" />
                    </Button>
                  </div>
                </div>
              ))}
            </CardContent>
          </Card>

          <Card>
            <CardContent className="p-0">
              <div className="flex items-center gap-2 border-b border-border p-3">
                <Search className="h-4 w-4 text-muted-foreground" />
                <Input
                  value={q}
                  onChange={(e) => setQ(e.target.value)}
                  placeholder="Filter by host, URL, or status"
                  className="h-8 border-0 bg-transparent px-0 font-mono text-xs shadow-none focus-visible:ring-0"
                />
              </div>
              <div className="overflow-x-auto">
                <Table>
                  <TableHeader>
                    <TableRow>
                      <TableHead>Time</TableHead>
                      <TableHead>Host</TableHead>
                      <TableHead>URL</TableHead>
                      <TableHead className="text-right">Score</TableHead>
                      <TableHead className="text-right">Status</TableHead>
                      <TableHead className="text-right">Actions</TableHead>
                    </TableRow>
                  </TableHeader>
                  <TableBody>
                    {filtered.map((e) => (
                      <TableRow key={e.id}>
                        <TableCell className="font-mono text-xs text-muted-foreground">
                          {new Date(e.createdAt).toLocaleString()}
                        </TableCell>
                        <TableCell className="font-mono text-xs">{e.targetHost}</TableCell>
                        <TableCell className="truncate font-mono text-xs text-muted-foreground max-w-[380px]">
                          {e.targetUrl}
                        </TableCell>
                        <TableCell className="text-right font-mono">{e.overallScore}</TableCell>
                        <TableCell className="text-right">
                          <Badge
                            variant="outline"
                            className={
                              e.status === "complete"
                                ? "border-success/40 text-success"
                                : "border-critical/40 text-critical"
                            }
                          >
                            {e.status}
                          </Badge>
                        </TableCell>
                        <TableCell className="text-right">
                          <div className="flex justify-end gap-1">
                            <Button asChild size="sm" variant="ghost">
                              <Link to="/scan/$scanId" params={{ scanId: e.id }}>
                                <Eye className="h-3.5 w-3.5" /> Review
                              </Link>
                            </Button>
                            <Button size="sm" variant="ghost" onClick={() => downloadScanPdf(e)} title="Export PDF">
                              <FileDown className="h-3.5 w-3.5" />
                            </Button>
                          </div>
                        </TableCell>
                      </TableRow>
                    ))}
                  </TableBody>
                </Table>
              </div>
            </CardContent>
          </Card>
        </>
      )}
    </PageShell>
  );
}
