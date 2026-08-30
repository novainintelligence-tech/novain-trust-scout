#!/usr/bin/env python3
"""
Offline calibration runner (Phase A2).
Calls a running NOVAIN TRUST API and summarizes score distributions by label.
Does not invent labels — uses evaluation/labeled_domains.json only.
"""
from __future__ import annotations
import argparse
import json
import statistics
import sys
import urllib.request


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--base", default="http://127.0.0.1:8000")
    ap.add_argument("--token", required=True, help="Bearer API key")
    ap.add_argument("--dataset", default="evaluation/labeled_domains.json")
    args = ap.parse_args()

    with open(args.dataset) as f:
        data = json.load(f)

    rows = []
    for sample in data["samples"]:
        target = sample["target"]
        req = urllib.request.Request(
            f"{args.base}/api/public/v1/verify/website",
            data=json.dumps({"target": target}).encode(),
            headers={
                "Authorization": f"Bearer {args.token}",
                "Content-Type": "application/json",
            },
            method="POST",
        )
        try:
            with urllib.request.urlopen(req, timeout=60) as resp:
                body = json.load(resp)
            score = body["assessment"]["score"]
            rows.append({**sample, "score": score, "status": body["assessment"]["status"], "recommendation": body["recommendation"]})
            print(f"OK {target} score={score} status={body['assessment']['status']}")
        except Exception as e:
            print(f"ERR {target} {e}", file=sys.stderr)
            rows.append({**sample, "score": None, "error": str(e)})

    by_label = {}
    for r in rows:
        if r.get("score") is None:
            continue
        by_label.setdefault(r["label"], []).append(r["score"])

    print("\n=== Calibration summary ===")
    for label, scores in sorted(by_label.items()):
        print(
            f"{label}: n={len(scores)} mean={statistics.mean(scores):.1f} "
            f"min={min(scores)} max={max(scores)}"
        )
    out = {"rows": rows, "summary": {k: {"n": len(v), "mean": statistics.mean(v)} for k, v in by_label.items()}}
    with open("evaluation/last_run.json", "w") as f:
        json.dump(out, f, indent=2)
    print("Wrote evaluation/last_run.json")


if __name__ == "__main__":
    main()
