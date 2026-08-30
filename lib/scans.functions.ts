import { createServerFn } from "@tanstack/react-start";
import { z } from "zod";

import { requireSupabaseAuth } from "@/integrations/supabase/auth-middleware";
import type { ReconCheck, ScanEvidence, ScanResult } from "./scan-types";

interface DbScanRow {
  id: string;
  target_url: string;
  target_host: string;
  status: string;
  duration_ms: number | null;
  overall_score: number;
  scores: ScanResult["scores"];
  headers: ScanResult["headers"];
  cookies: ScanResult["cookies"];
  tls: ScanResult["tls"];
  csrf: ScanResult["csrf"];
  xss: ScanResult["xss"];
  sessions: ScanResult["sessions"];
  recon: ReconCheck[] | null;
  evidence: Partial<ScanEvidence> | null;
  error: string | null;
  created_at: string;
}

const EMPTY_EVIDENCE: ScanEvidence = {
  primary: null, setCookies: [], forms: [], mixedContentRefs: [],
  xssProbe: null, corsProbe: null, exposure: [], meta: [], redirect: null, crtsh: null,
};

function toResult(row: DbScanRow): ScanResult {
  const scores = row.scores as Partial<ScanResult["scores"]> | null;
  const ev = row.evidence ?? {};
  return {
    id: row.id,
    targetUrl: row.target_url,
    targetHost: row.target_host,
    status: row.status as "complete" | "error",
    durationMs: row.duration_ms,
    overallScore: row.overall_score,
    scores: {
      headers: scores?.headers ?? 0,
      cookies: scores?.cookies ?? 0,
      tls: scores?.tls ?? 0,
      sessions: scores?.sessions ?? 0,
      csrf: scores?.csrf ?? 0,
      xss: scores?.xss ?? 0,
      recon: scores?.recon ?? 100,
    },
    headers: row.headers ?? [],
    cookies: row.cookies ?? [],
    tls: row.tls,
    csrf: row.csrf ?? [],
    xss: row.xss ?? [],
    sessions: row.sessions ?? [],
    recon: row.recon ?? [],
    evidence: { ...EMPTY_EVIDENCE, ...ev } as ScanEvidence,
    error: row.error,
    createdAt: row.created_at,
  };
}

export const getLatestScanForHost = createServerFn({ method: "POST" })
  .middleware([requireSupabaseAuth])
  .inputValidator((data: { host: string }) => z.object({ host: z.string().min(1) }).parse(data))
  .handler(async ({ data, context }): Promise<ScanResult | null> => {
    const { data: rows, error } = await context.supabase
      .from("scans").select("*").eq("target_host", data.host)
      .order("created_at", { ascending: false }).limit(1);
    if (error) throw new Error(error.message);
    if (!rows || rows.length === 0) return null;
    return toResult(rows[0] as unknown as DbScanRow);
  });

export const listRecentScans = createServerFn({ method: "GET" })
  .middleware([requireSupabaseAuth])
  .handler(async ({ context }): Promise<ScanResult[]> => {
    const { data: rows, error } = await context.supabase
      .from("scans").select("*")
      .order("created_at", { ascending: false }).limit(100);
    if (error) throw new Error(error.message);
    return (rows ?? []).map((r) => toResult(r as unknown as DbScanRow));
  });

export const getScanById = createServerFn({ method: "POST" })
  .middleware([requireSupabaseAuth])
  .inputValidator((data: { id: string }) => z.object({ id: z.string().uuid() }).parse(data))
  .handler(async ({ data, context }): Promise<ScanResult | null> => {
    const { data: row, error } = await context.supabase
      .from("scans").select("*").eq("id", data.id).maybeSingle();
    if (error) throw new Error(error.message);
    if (!row) return null;
    return toResult(row as unknown as DbScanRow);
  });

export const deleteScan = createServerFn({ method: "POST" })
  .middleware([requireSupabaseAuth])
  .inputValidator((data: { id: string }) => z.object({ id: z.string().uuid() }).parse(data))
  .handler(async ({ data, context }) => {
    const { error } = await context.supabase.from("scans").delete().eq("id", data.id);
    if (error) throw new Error(error.message);
    return { ok: true };
  });
