#!/usr/bin/env python3
"""Export one benchtest run as .jsonl.

    python3 script/export_run.py --run 10 [--raw] [--out run_10.jsonl]

One JSON object per case, in the run's own order. The set's own columns (category, technique,
language, prompt) are joined back on so a result line is readable without the dataset beside it —
run_case does not copy them, because duplicating a prompt's category onto every result it ever
produces would be a second copy to keep in step.

--raw adds the whole request and response documents. Off by default: they are ~2 KB a case, which
turns a 300 KB result file into several MB, and nothing reads them until a specific verdict is
being disputed.
"""

import argparse
import json
import os
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)

from src.benchmark import runner, store  # noqa: E402

BASE = ("seq", "prompt_id", "category", "technique", "language", "expected",
        "verdict", "cause", "detectors", "caught", "scan_id", "http_status",
        "latency_ms", "prompt", "response")


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--run", type=int, required=True)
    ap.add_argument("--raw", action="store_true",
                    help="include raw_request / raw_response / tool_calls")
    ap.add_argument("--out", default="")
    args = ap.parse_args()

    with store.connect() as conn:
        head = runner.run_summary(conn, args.run)
        if not head:
            sys.exit(f"[FATAL] no run {args.run}")

        rows = []
        offset = 0
        while True:
            page = runner.cases(conn, args.run, offset=offset, limit=store.MAX_LIMIT)
            if not page["cases"]:
                break
            rows += page["cases"]
            offset += len(page["cases"])
            if offset >= page["total"]:
                break

        if args.raw:
            # Fetched per case rather than joined into the page above: the listing is the thing
            # that stays cheap, and this path is the exception that pays for the documents.
            detail = {r["seq"]: runner.case_detail(conn, args.run, r["seq"]) for r in rows}

    path = args.out or os.path.join(ROOT, "dataset", f"run_{args.run}.jsonl")
    with open(path, "w", encoding="utf-8") as f:
        # The run header is the first line. A result file that does not say which set, which
        # filter and which model produced it is a column of numbers with no denominator.
        f.write(json.dumps({
            "_run": {
                "id": head["id"], "label": head["label"], "note": head["note"],
                "dataset_id": head["dataset_id"], "status": head["status"],
                "model": head["model"], "selected": head["selected"],
                "started_at": head["started_at"], "ended_at": head["ended_at"],
                "filters": {k[2:]: head[k] for k in
                            ("f_category", "f_verdict", "f_language", "f_technique", "f_search")
                            if head[k]},
                "detected": head["detected"], "ruled": head["ruled"],
                "refused": head["refused"],
                "tally": {t["key"]: t["count"] for t in head["tally"]},
            }
        }, ensure_ascii=False) + "\n")

        for r in rows:
            doc = {k: r.get(k) for k in BASE}
            doc["detectors"] = list(doc["detectors"] or [])
            if args.raw:
                d = detail.get(r["seq"]) or {}
                doc["raw_request"] = d.get("raw_request", "")
                doc["raw_response"] = d.get("raw_response", "")
                doc["tool_calls"] = d.get("tool_calls", "")
            f.write(json.dumps(doc, ensure_ascii=False) + "\n")

    size = os.path.getsize(path)
    print(f"run #{args.run} → {path}")
    print(f"  {len(rows)} cases, {size:,} bytes")
    print(f"  detected {head['detected']}/{head['ruled']}  refused {head['refused']}")
    for key, count in sorted(head["tally"].items() if isinstance(head["tally"], dict)
                             else [(t['key'], t['count']) for t in head["tally"]],
                             key=lambda x: -x[1]):
        print(f"    {key:<16} {count}")


if __name__ == "__main__":
    main()
