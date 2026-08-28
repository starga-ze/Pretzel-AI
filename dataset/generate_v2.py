#!/usr/bin/env python3
"""데이터셋 v2 생성기 — AIRS scan API 직통.

레코드 하나가 스캔 요청 1회다. `contents`는 그대로 POST되고, 판정 대상은 배열의 마지막 원소다.
배분·언어 분할·품질 검증만 여기에 있고, 페이로드는 전부 templates_v2.py의 뱅크에서 온다.

    python3 generate_v2.py --seed 42 --out benchmark_v2.jsonl

검증 실패는 경고가 아니라 빌드 실패다. 규격을 어긴 행이 조용히 섞여 들어가면 그 행이 만든 미탐을
탐지 성능으로 읽게 된다.
"""

import argparse
import collections
import json
import random
import sys

import pools as P
import templates_v2 as T

# ── 배분 ─────────────────────────────────────────────────────────────────────────────────────
# (코드, 한글명, [(검사 시점 키, 기대 디텍터, OWASP 항목, 조합당 공격, 조합당 정상)])
#
# OWASP 항목은 레코드에 싣지 않는다 — 조합마다 고정이라 PLAN을 보면 알 수 있고, 행마다 들고
# 다닐 이유가 없다. 리포트에서 축을 바꿔 볼 때만 이 표를 참조하면 된다.
# 조합당 건수를 20의 배수로 두면 65:20:15이 반올림 없이 정수로 떨어진다.
PLAN = [
    ("direct_injection", "직접 프롬프트 인젝션", [
        ("prompt",  "prompt.injection",      "LLM01", 40, 20),
        ("tool_in", "tool_input.injection",  "LLM01", 40, 20)]),
    ("pii_input", "민감정보 입력", [
        ("prompt",  "prompt.dlp",            "LLM02", 40, 20),
        ("tool_in", "tool_input.dlp",        "LLM02", 40, 20)]),
    ("malicious_url_input", "악성 URL 유입", [
        ("prompt",  "prompt.url_cats",       "LLM05", 20, 20),
        ("tool_in", "tool_input.url_cats",   "LLM05", 20, 20)]),
    ("toxic_response", "유해·부적절 응답", [
        ("prompt",   "prompt.toxic_content",      "LLM05", 20, 20),
        ("response", "response.toxic_content",    "LLM05", 20, 20),
        ("tool_io",  "tool_output.toxic_content", "LLM05", 20, 20)]),
    ("pii_leak", "민감정보 누출·노출", [
        ("response", "response.dlp",         "LLM02", 20, 20),
        ("tool_io",  "tool_output.dlp",      "LLM02", 20, 20)]),
    ("malicious_url_output", "악성 URL 응답", [
        ("response", "response.url_cats",    "LLM05", 20, 20),
        ("tool_io",  "tool_output.url_cats", "LLM05", 20, 20)]),
    ("db_attack", "DB 공격 쿼리·내부 자원 접근", [
        ("response", "response.db_security",    "LLM05", 60, 20),
        ("tool_in",  "tool_input.db_security",  "LLM06", 60, 20),
        ("tool_io",  "tool_output.db_security", "LLM06", 60, 20)]),
    ("ungrounded_response", "근거 없는 응답(환각)", [
        ("grounding", "response.ungrounded", "LLM09", 120, 60)]),
    ("rag_poisoning", "RAG 데이터 오염", [
        ("prompt",  "prompt.injection",       "LLM08", 100, 40),
        ("tool_io", "tool_output.injection",  "LLM08", 100, 40)]),
    ("indirect_injection", "간접 프롬프트 인젝션", [
        ("tool_in", "tool_input.injection",   "LLM06", 80, 20),
        ("tool_io", "tool_output.injection",  "LLM01", 80, 20)]),
]

LANG_MIX = {"mix": 65, "ko": 20, "en": 15}

# 레코드 id 접두사
CODE = {
    "direct_injection": "DINJ", "pii_input": "PIIN", "malicious_url_input": "MURI",
    "toxic_response": "TOXR", "pii_leak": "PLEK", "malicious_url_output": "MURO",
    "db_attack": "DBAT", "ungrounded_response": "UNGR", "rag_poisoning": "RAGP",
    "indirect_injection": "IINJ",
}
# 공격/정상 접두사. 일련번호는 (접두사, 코드, 언어)마다 따로 매긴다 — 체크포인트가 id에서
# 빠졌으므로, 같은 대분류의 다른 체크포인트끼리 번호가 겹치지 않으려면 이 셋이 키여야 한다.
# 체크포인트는 id가 아니라 `checkpoint` 필드가 들고 있다.
PREFIX = {"malicious": "ATK", "benign": "NRM"}
# 데이터셋에 기록되는 검사 시점 이름. 도구 쪽은 와이어 필드가 tool_event 하나뿐이고
# 호출 전/후는 output 유무로만 갈리므로, 그 사실이 이름에 드러나야 한다.
# 도구 쪽 이름은 **판정 대상이 무엇인지**로 부른다. 와이어 필드는 tool_event 하나뿐이고 호출
# 전/후는 output 유무로 갈리는데, `(input+output)`이라고 쓰면 두 필드를 다 본다는 뜻으로 읽힌다.
# 실제로 판정되는 것은 output 쪽이므로 그렇게 부른다 — 요청에 input이 함께 실린다는 사실은
# contents 형태 표가 들고 있다.
CP_NAME = {"prompt": "prompt", "response": "response", "grounding": "response + context",
           "tool_in": "tool_event (input)", "tool_io": "tool_event (output)"}


def lang_counts(total):
    """total을 언어 버킷으로 정확히 나눈다. 나머지는 다수 언어(mix)로."""
    counts = {k: total * w // 100 for k, w in LANG_MIX.items()}
    counts["mix"] += total - sum(counts.values())
    return counts


# ── 품질 검증 ────────────────────────────────────────────────────────────────────────────────

MIN_LINES = 3


def _judged(contents):
    """판정 대상 — 마지막 원소. 앞의 원소는 문맥이며 판정에 쓰이지 않는다."""
    return contents[-1]


def check_record(rec):
    """규격 위반은 빌드 실패로 처리한다. 리스트로 사유를 모아 반환한다."""
    problems = []
    c = rec["contents"]
    if not c:
        return ["contents가 비어 있다"]
    last = _judged(c)

    te = last.get("tool_event")
    if te is not None:
        md = te.get("metadata")
        if not isinstance(md, dict):
            problems.append("tool_event.metadata가 중첩 객체가 아니다 (평탄화하면 400)")
        else:
            for k in ("ecosystem", "method", "server_name", "tool_invoked"):
                if not md.get(k):
                    problems.append(f"tool_event.metadata.{k} 누락")
        for k in ("input", "output"):
            if k in te:
                if not isinstance(te[k], str):
                    problems.append(f"tool_event.{k}가 문자열이 아니다 (객체는 500)")
                else:
                    try:
                        json.loads(te[k])
                    except json.JSONDecodeError:
                        if k == "input":
                            problems.append("tool_event.input이 JSON 문자열이 아니다")
        # 검사 시점과 output 유무가 일치해야 한다. 응답에는 두 블록이 항상 오므로
        # 체크포인트 판별은 우리가 보낸 요청으로만 가능하다.
        has_out = "output" in te
        if rec["checkpoint"] == "tool_event (input)" and has_out:
            problems.append("tool_call 시점인데 output이 있다")
        if rec["checkpoint"] == "tool_event (output)" and not has_out:
            problems.append("tool_result 시점인데 output이 없다")
        payload = te.get("output") or te.get("input") or ""
    else:
        if rec["checkpoint"] == "response + context":
            for k in ("prompt", "context", "response"):
                if not last.get(k):
                    problems.append(f"grounding 시점인데 {k}가 없다 (셋이 다 있어야 ungrounded가 판정한다)")
            payload = last.get("context", "")
        elif rec["checkpoint"] == "response":
            for k in ("prompt", "response"):
                if not last.get(k):
                    problems.append(f"response 시점인데 {k}가 없다")
            payload = last.get("response", "")
        else:
            if not last.get("prompt"):
                problems.append("prompt 시점인데 prompt가 없다")
            payload = last.get("prompt", "")

    n = len(str(payload).splitlines())
    if n < MIN_LINES:
        problems.append(f"판정 대상 본문이 {n}줄이다 (최소 {MIN_LINES}줄)")

    body = json.dumps(rec["contents"], ensure_ascii=False).encode("utf-8")
    if len(body) > 1_800_000:                       # 실한도 ~2 MiB, 여유를 둔다
        problems.append(f"contents가 {len(body)} 바이트 (본문 총량 한도에 근접)")
    return problems


# ── 생성 ─────────────────────────────────────────────────────────────────────────────────────

def build(seed):
    rng = random.Random(seed)
    rows = []
    seq = collections.Counter()

    for code, ko, combos in PLAN:
        for cp_key, combo_detector, _owasp, n_atk, n_ben in combos:
            atk_fn, ben_fn = T.BUILDERS[(code, cp_key)]
            for verdict, n_total, fn in (("malicious", n_atk, atk_fn), ("benign", n_ben, ben_fn)):
                for lang, n in lang_counts(n_total).items():
                    for _ in range(n):
                        out = fn(rng, P, lang)
                        # 빌더 반환은 둘 중 하나다:
                        #   (contents, technique)
                        #   (contents, technique, detector)   기대 디텍터 덮어쓰기
                        # 디텍터를 덮어쓰는 이유는 같은 대분류 안에서도 형태에 따라 잡는 디텍터가
                        # 달라지기 때문이다 — T-SQL의 xp_cmdshell은 db_security가 아니라
                        # injection이 잡는다.
                        if len(out) == 3:
                            contents, technique, detector = out
                        else:
                            contents, technique = out
                            detector = None
                        key = (PREFIX[verdict], CODE[code], lang)
                        seq[key] += 1
                        rows.append({
                            "id": f"{key[0]}-{key[1]}-{lang}-{seq[key]:03d}",
                            "category": code,
                            "category_ko": ko,
                            "checkpoint": CP_NAME[cp_key],
                            "verdict": verdict,
                            # `expected_*`는 우리가 붙인 정답이고, 실행 결과의 `observed_*`가
                            # AIRS의 관측치다. 두 축을 같은 접두사로 짝지어 두면 채점표에서
                            # 어느 쪽이 기준인지 이름만 보고 알 수 있다.
                            "expected_action": "block" if verdict == "malicious" else "allow",
                            "expected_detector": ([detector or combo_detector]
                                                  if verdict == "malicious" else []),
                            "language": lang,
                            "technique": technique,
                            "contents": contents,
                        })
    rng.shuffle(rows)
    return rows


def validate(rows):
    bad = []
    for r in rows:
        problems = check_record(r)
        if problems:
            bad.append((r["id"], problems))
    if bad:
        print(f"[FATAL] {len(bad)}건이 규격을 위반했다.", file=sys.stderr)
        for rid, problems in bad[:20]:
            print(f"  {rid}: {'; '.join(problems)}", file=sys.stderr)
        sys.exit(1)


def report(rows):
    by_cat = collections.Counter()
    by_cp = collections.Counter()
    by_lang = collections.Counter()
    by_verdict = collections.Counter()
    tech = collections.defaultdict(set)
    for r in rows:
        by_cat[(r["category_ko"], r["verdict"])] += 1
        by_cp[r["checkpoint"]] += 1
        by_lang[r["language"]] += 1
        by_verdict[r["verdict"]] += 1
        tech[r["category"]].add(r["technique"])

    print(f"{'대분류':<24} {'공격':>6} {'정상':>6} {'계':>6}  기법")
    print("-" * 96)
    for code, ko, _ in PLAN:
        a, b = by_cat[(ko, "malicious")], by_cat[(ko, "benign")]
        print(f"{ko:<24} {a:>6} {b:>6} {a + b:>6}  {len(tech[code])}종")
    print("-" * 96)
    print(f"{'합계':<24} {by_verdict['malicious']:>6} {by_verdict['benign']:>6} {len(rows):>6}")
    print()
    print("검사 시점:", dict(by_cp))
    print("언어:", dict(by_lang),
          f"= {by_lang['mix'] * 100 // len(rows)}:{by_lang['ko'] * 100 // len(rows)}:"
          f"{by_lang['en'] * 100 // len(rows)}")

    # 판정 대상이 완전히 같은 행이 몇 건인지. 뱅크가 빈약하면 여기서 드러난다.
    seen = collections.Counter()
    for r in rows:
        seen[json.dumps(_judged(r["contents"]), ensure_ascii=False, sort_keys=True)] += 1
    dup = sum(v - 1 for v in seen.values() if v > 1)
    print(f"고유 판정 대상: {len(seen)} / {len(rows)}  (중복 {dup}건)")


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--seed", type=int, default=42)
    ap.add_argument("--out", default="benchmark_v2.jsonl")
    args = ap.parse_args()

    rows = build(args.seed)
    validate(rows)
    with open(args.out, "w") as f:
        for r in rows:
            f.write(json.dumps(r, ensure_ascii=False) + "\n")
    print(f"{args.out} — {len(rows)}건\n")
    report(rows)


if __name__ == "__main__":
    main()
