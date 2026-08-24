#!/usr/bin/env python3
"""Load a generated benchmark set into pretzel_knowledge.

    python3 script/load_benchmark.py [--jsonl dataset/benchmark.jsonl] [--seed 42]

The generator writes the whole set in one shot, so this replaces the whole table in one
transaction. It is not an importer for hand-edited rows and does not merge: whatever is in the
file becomes the set, and what was there before is gone.
"""

import argparse
import json
import os
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)

from src.benchmark import store      # noqa: E402
from src.crawler.store import connect  # noqa: E402

REQUIRED = set(store.COLUMNS)


def read(path):
    rows = []
    with open(path, encoding="utf-8") as f:
        for n, line in enumerate(f, 1):
            line = line.strip()
            if not line:
                continue
            row = json.loads(line)
            missing = REQUIRED - set(row)
            if missing:
                sys.exit(f"[FATAL] {path}:{n} is missing {sorted(missing)}")
            rows.append(row)
    if not rows:
        sys.exit(f"[FATAL] {path} holds no rows")
    ids = {r["id"] for r in rows}
    if len(ids) != len(rows):
        sys.exit(f"[FATAL] {path} has duplicate ids; the set must be one row per id")
    return rows


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--jsonl", default=os.path.join(ROOT, "dataset", "benchmark.jsonl"))
    ap.add_argument("--seed", type=int, default=42,
                    help="the seed the set was generated with; recorded for the console header")
    args = ap.parse_args()

    rows = read(args.jsonl)
    with connect() as conn:
        n = store.replace(conn, rows, args.seed, os.path.relpath(args.jsonl, ROOT))
        got = store.summary(conn)

    print(f"loaded {n} rows from {args.jsonl} (seed={args.seed})")
    for field in ("category", "verdict", "language"):
        parts = ", ".join(f"{b['key']} {b['count']}" for b in got["by_" + field])
        print(f"  {field:<9} {parts}")


if __name__ == "__main__":
    main()
