#!/usr/bin/env python3
"""run_bench_v2.py 가 낸 결과를 benchmark.run / run_case 에 적재한다.

콘솔의 Test '실행' 기능이 아직 없으므로, CLI 로 돌린 결과를 Result 탭이 읽을 수 있는 자리에
넣어 주는 다리다. 실행 기능이 붙으면 러너가 같은 테이블에 같은 모양으로 쓰게 되고 이 스크립트는
사라진다 — 그때까지 두 경로가 서로 다른 모양으로 쓰지 않도록, 컬럼 의미는 여기서 한 번만 정한다.

    python3 load_run_v2.py --run run_v2.jsonl --dataset benchmark_v2 --label "CLI 실행"

`outcome` 다섯 갈래가 이 화면의 요점이다. 스캔 1회가 모든 디텍터를 돌리므로 차단 여부만으로는
커버리지를 알 수 없고, '차단은 됐는데 기대한 디텍터는 안 뜬' 경우를 정탐과 갈라 두어야 실질
커버리지가 보인다(v1 에서 헤드라인 차단율이 실제 성능을 가렸던 자리).
"""

import argparse
import json
import sys

sys.path.insert(0, "/home/jinho/pretzel-ai")

from psycopg.types.json import Jsonb                        # noqa: E402

from src.benchmark.store import connect                     # noqa: E402

# 러너의 한글 채점명 → 스키마의 outcome 값. 러너는 사람이 읽는 리포트를 내고, 테이블은 필터에
# 쓸 안정된 키를 원한다. 그 변환을 한 곳에 둔다.
OUTCOME = {
    "정탐": "hit",
    "오분류": "misclassified",
    "미탐": "miss",
    "오탐": "false_positive",
    "정상통과": "clean_pass",
}

# `ok` 는 "이 케이스가 기대대로 처리됐나"의 불리언이다. 오분류는 차단은 됐지만 기대한 디텍터가
# 뜨지 않은 것이라 참으로 셀 수 없고, 오류는 판정 자체가 없었으므로 NULL 로 두어 비율에서 뺀다.
OK = {"hit": True, "clean_pass": True,
      "misclassified": False, "miss": False, "false_positive": False}


def load(path):
    return [json.loads(line) for line in open(path) if line.strip()]


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--run", default="run_v2.jsonl")
    ap.add_argument("--dataset", default="benchmark_v2",
                    help="benchmark.dataset.name 의 일부. 하나만 맞아야 한다")
    ap.add_argument("--label", default="CLI 실행")
    ap.add_argument("--note", default="run_bench_v2.py 로 실행한 결과를 적재")
    args = ap.parse_args()

    results = load(args.run)
    if not results:
        sys.exit(f"{args.run} 이 비어 있다")

    with connect() as conn, conn.cursor() as cur:
        cur.execute("SELECT id, name FROM benchmark.dataset WHERE name ILIKE %s ORDER BY id",
                    (f"%{args.dataset}%",))
        found = cur.fetchall()
        if len(found) != 1:
            sys.exit(f"세트가 {len(found)}개 맞았다: {[n for _, n in found]}")
        dataset_id, dataset_name = found[0]

        # 행 번호는 세트에서 가져온다. 결과 파일은 prompt_id 만 들고 있고, run_case.row_no 는
        # 케이스를 세트의 행에 되짚는 주소라 여기서 채워야 한다.
        cur.execute("SELECT prompt_id, row_no FROM benchmark.row WHERE dataset_id = %s",
                    (dataset_id,))
        row_no = dict(cur.fetchall())

        missing = [r["id"] for r in results if r["id"] not in row_no]
        if missing:
            sys.exit(f"세트에 없는 id {len(missing)}건 (예: {missing[:3]}). "
                     f"결과 파일과 세트가 서로 다른 판이다")

        latencies = [r.get("latency_ms", 0) for r in results if r.get("latency_ms")]
        cur.execute(
            "INSERT INTO benchmark.run (dataset_id, label, note, selected, status, model, "
            "                           started_at, ended_at) "
            "VALUES (%s, %s, %s, %s, 'done', %s, now(), now()) RETURNING id",
            (dataset_id, args.label, args.note, len(results), "airs-scan-api"))
        run_id = cur.fetchone()[0]

        rows = []
        for seq, r in enumerate(sorted(results, key=lambda x: x["id"]), 1):
            outcome = OUTCOME.get(r.get("result"), "")
            rows.append((
                run_id, seq, r["id"], row_no[r["id"]],
                r.get("expected_action", ""), r.get("observed_action", ""),
                r.get("result", ""),                     # cause: 사람이 읽는 한글 그대로 보존
                OK.get(outcome),                         # None 이면 비율에서 빠진다
                r.get("scan_id", ""), r.get("observed_detector") or [],
                "", r.get("http_status") or None, r.get("latency_ms") or None,
                Jsonb(r["raw_request"]) if r.get("raw_request") else None,
                Jsonb(r["raw_response"]) if r.get("raw_response") else None,
                "", None,
                r.get("expected_detector") or [], r.get("checkpoint", ""),
                r.get("threats") or [], outcome))

        cur.executemany(
            "INSERT INTO benchmark.run_case ("
            "  run_id, seq, prompt_id, row_no, expected_action, observed_action, cause, ok,"
            "  scan_id, observed_detector, caught, http_status, latency_ms, raw_request,"
            "  raw_response, response, tool_calls, expected_detector, checkpoint, threats, outcome"
            ") VALUES (" + ", ".join(["%s"] * 21) + ")", rows)
        conn.commit()

    tally = {}
    for r in results:
        tally[r.get("result", "?")] = tally.get(r.get("result", "?"), 0) + 1
    avg = sum(latencies) // len(latencies) if latencies else 0
    print(f"run {run_id} — 세트 '{dataset_name}'(id {dataset_id})에 {len(rows)}건 적재")
    print(f"채점: {tally}")
    print(f"평균 지연 {avg} ms")


if __name__ == "__main__":
    main()
