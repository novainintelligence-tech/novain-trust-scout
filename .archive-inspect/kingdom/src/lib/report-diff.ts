import type { ScanResult } from "./scan-types";
import { buildFindings, type Finding, type RiskRating } from "./engagement";

export type DiffStatus = "new" | "resolved" | "unchanged" | "changed";

export interface FindingDiffRow {
  id: string;
  status: DiffStatus;
  module: string;
  title: string;
  before: Finding | null;
  after: Finding | null;
}

export interface ScanDiff {
  base: { id: string; createdAt: string; overallScore: number };
  head: { id: string; createdAt: string; overallScore: number };
  scoreDelta: number;
  totals: {
    added: number;
    resolved: number;
    unchanged: number;
    changed: number;
  };
  bySeverity: {
    added: Record<RiskRating, number>;
    resolved: Record<RiskRating, number>;
  };
  rows: FindingDiffRow[];
}

function emptyRiskCounts(): Record<RiskRating, number> {
  return { Critical: 0, High: 0, Medium: 0, Low: 0, Info: 0 };
}

function fingerprint(f: Finding): string {
  return `${f.module}::${f.id}`;
}

export function diffScans(base: ScanResult, head: ScanResult): ScanDiff {
  const baseF = buildFindings(base);
  const headF = buildFindings(head);
  const baseMap = new Map(baseF.map((f) => [fingerprint(f), f]));
  const headMap = new Map(headF.map((f) => [fingerprint(f), f]));

  const rows: FindingDiffRow[] = [];
  const added = emptyRiskCounts();
  const resolved = emptyRiskCounts();
  let unchanged = 0;
  let changed = 0;

  for (const [key, f] of headMap) {
    const prev = baseMap.get(key);
    if (!prev) {
      added[f.risk] += 1;
      rows.push({ id: key, status: "new", module: f.module, title: f.title, before: null, after: f });
    } else if (prev.risk !== f.risk || prev.cvss !== f.cvss || prev.evidence !== f.evidence) {
      changed += 1;
      rows.push({ id: key, status: "changed", module: f.module, title: f.title, before: prev, after: f });
    } else {
      unchanged += 1;
      rows.push({ id: key, status: "unchanged", module: f.module, title: f.title, before: prev, after: f });
    }
  }
  for (const [key, f] of baseMap) {
    if (!headMap.has(key)) {
      resolved[f.risk] += 1;
      rows.push({ id: key, status: "resolved", module: f.module, title: f.title, before: f, after: null });
    }
  }

  const statusOrder: Record<DiffStatus, number> = { new: 0, changed: 1, resolved: 2, unchanged: 3 };
  rows.sort((a, b) => statusOrder[a.status] - statusOrder[b.status]);

  const totalAdded = Object.values(added).reduce((a, b) => a + b, 0);
  const totalResolved = Object.values(resolved).reduce((a, b) => a + b, 0);

  return {
    base: { id: base.id, createdAt: base.createdAt, overallScore: base.overallScore },
    head: { id: head.id, createdAt: head.createdAt, overallScore: head.overallScore },
    scoreDelta: head.overallScore - base.overallScore,
    totals: { added: totalAdded, resolved: totalResolved, unchanged, changed },
    bySeverity: { added, resolved },
    rows,
  };
}
