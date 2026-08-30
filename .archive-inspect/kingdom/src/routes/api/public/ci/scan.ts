import { createFileRoute } from "@tanstack/react-router";
import { createHmac, timingSafeEqual } from "node:crypto";
import { performScan } from "@/lib/scanner.functions";

// POST /api/public/ci/scan
// Headers:
//   x-nsl-signature: hex HMAC-SHA256 of the raw body using NSL_CI_SECRET
// Body (JSON):
//   { "url": "https://target.example.com", "persist": true }
// Optional: set NSL_CI_USER_ID to persist scans under a specific NSL user.
// Response: { ok, id?, summary, findings, sarif } — perfect for CI artifacts.

type Severity = "critical" | "high" | "medium" | "low" | "info";
const RANK: Record<Severity, number> = { critical: 4, high: 3, medium: 2, low: 1, info: 0 };

function verify(sig: string | null, body: string, secret: string) {
  if (!sig) return false;
  const expected = createHmac("sha256", secret).update(body).digest("hex");
  const a = Buffer.from(sig, "hex");
  const b = Buffer.from(expected, "hex");
  return a.length === b.length && timingSafeEqual(a, b);
}

function toSarif(target: string, rows: Array<{ id?: string; title?: string; name?: string; severity?: string; description?: string; evidence?: unknown }>) {
  return {
    version: "2.1.0",
    $schema: "https://json.schemastore.org/sarif-2.1.0.json",
    runs: [{
      tool: { driver: { name: "NOVAIN Security Lab", informationUri: "https://novain.security", version: "1.0.0" } },
      results: rows.map((r) => ({
        ruleId: r.id ?? r.name ?? r.title ?? "nsl.finding",
        level: r.severity === "critical" || r.severity === "high" ? "error" : r.severity === "medium" ? "warning" : "note",
        message: { text: r.title ?? r.name ?? "Finding" },
        properties: { severity: r.severity, description: r.description, evidence: r.evidence },
        locations: [{ physicalLocation: { artifactLocation: { uri: target } } }],
      })),
    }],
  };
}

export const Route = createFileRoute("/api/public/ci/scan")({
  server: {
    handlers: {
      POST: async ({ request }) => {
        const secret = process.env.NSL_CI_SECRET;
        if (!secret) return new Response(JSON.stringify({ error: "NSL_CI_SECRET not configured" }), { status: 500, headers: { "content-type": "application/json" } });

        const raw = await request.text();
        if (!verify(request.headers.get("x-nsl-signature"), raw, secret)) {
          return new Response(JSON.stringify({ error: "invalid signature" }), { status: 401, headers: { "content-type": "application/json" } });
        }

        let body: { url?: string; persist?: boolean; failOn?: Severity };
        try { body = JSON.parse(raw); } catch { return new Response(JSON.stringify({ error: "invalid json" }), { status: 400, headers: { "content-type": "application/json" } }); }
        if (!body.url || !/^https?:\/\//i.test(body.url)) {
          return new Response(JSON.stringify({ error: "url required (http/https)" }), { status: 400, headers: { "content-type": "application/json" } });
        }

        const scan = await performScan(body.url);

        // Collect findings across modules
        const all: Array<{ id?: string; title?: string; name?: string; severity?: string; description?: string; evidence?: unknown }> = [
          ...(scan.headers ?? []), ...(scan.cookies ?? []), ...(scan.csrf ?? []),
          ...(scan.xss ?? []), ...(scan.sessions ?? []), ...(scan.recon ?? []),
        ] as never;

        const counts: Record<Severity, number> = { critical: 0, high: 0, medium: 0, low: 0, info: 0 };
        for (const r of all) {
          const s = (r.severity ?? "info") as Severity;
          if (s in counts) counts[s]++;
        }

        let id: string | undefined;
        let createdAt: string | undefined;
        const persist = body.persist !== false;
        const ciUserId = process.env.NSL_CI_USER_ID;
        if (persist && ciUserId) {
          const { supabaseAdmin } = await import("@/integrations/supabase/client.server");
          const { data: row, error } = await supabaseAdmin.from("scans").insert({
            user_id: ciUserId,
            target_url: scan.targetUrl, target_host: scan.targetHost,
            status: scan.status, duration_ms: scan.durationMs,
            overall_score: scan.overallScore, scores: scan.scores,
            headers: scan.headers, cookies: scan.cookies, tls: scan.tls,
            csrf: scan.csrf, xss: scan.xss, sessions: scan.sessions,
            recon: scan.recon, evidence: scan.evidence, error: scan.error,
            // eslint-disable-next-line @typescript-eslint/no-explicit-any
          } as any).select("id, created_at").single();
          if (!error && row) { id = row.id as string; createdAt = row.created_at as string; }
        }

        const failOn = body.failOn ?? "high";
        const failed = Object.entries(counts).some(([sev, n]) => n > 0 && RANK[sev as Severity] >= RANK[failOn]);

        return new Response(JSON.stringify({
          ok: !failed,
          id, createdAt,
          summary: {
            target: scan.targetUrl, score: scan.overallScore, scores: scan.scores,
            durationMs: scan.durationMs, counts, failOn, failed,
          },
          findings: all,
          sarif: toSarif(scan.targetUrl, all),
        }, null, 2), {
          status: failed ? 409 : 200,
          headers: { "content-type": "application/json" },
        });
      },
    },
  },
});
