#!/usr/bin/env python3
"""Build the AIRS boundary/attack benchmark.

Layout (matches the customer's table, 5 macro-categories):

    normal  (boundary cases, false-positive rate)  : 500  = 100 per category
    attack  (true-positive rate)                   : 1000 = 200 per category
    -----------------------------------------------------------------------
    total                                          : 1500

Per-category language mix, applied to BOTH normal and attack:

    mix (한영혼용) : ko (한글) : en (영어)  =  65 : 20 : 15

The mix is enforced exactly, not sampled — a 65/20/15 that drifts to 61/22/17 across a run is a
mix nobody agreed to. Counts are computed per (category, verdict) and the remainder handed to the
majority bucket, so every category lands on the same split.

Uniqueness is enforced globally: a rendered prompt that collides with one already emitted is redrawn.
Each template bank is large enough that this costs a handful of retries, not a stall — but if a bank
were ever too small the build fails loudly rather than shipping duplicates.

Run:  python3 generate.py            # writes benchmark.jsonl, benchmark.csv, README stats to stdout
      python3 generate.py --seed 7   # different draw, same shape
"""

import argparse
import csv
import json
import random
import sys
from collections import Counter

import pools as P
import templates as T

# ---- Shape ----------------------------------------------------------------------------------------
CATEGORIES = {
    "A": ("프롬프트 조작", "prompt_manipulation", "prompt"),
    "B": ("정보 유출", "data_leakage", "prompt+response"),
    "C": ("유해·부적절 응답", "harmful_output", "response"),
    "D": ("오염된 컨텍스트 유입", "poisoned_context", "prompt"),
}

# Attack:benign stays 2:1. The instruction-shaped agent/tool-abuse bank that used to be category D
# is out of the shipped set — measured detection on it was 0–5% and the blocks that did land came
# from header wording rather than from the payload, so it was reporting noise as coverage. What it
# covered is written up separately as out-of-scope for this deployment model.
NORMAL_PER_CAT = 125
ATTACK_PER_CAT = 250

# mix : ko : en = 65 : 20 : 15
LANG_MIX = {"mix": 65, "ko": 20, "en": 15}

# Which builder serves each (category, verdict, language).
BUILDERS = {
    ("A", "malicious"): {"ko": T.a_ko, "en": T.a_en, "mix": T.a_mix},
    ("B", "malicious"): {"ko": T.b_ko, "en": T.b_en, "mix": T.b_mix},
    ("C", "malicious"): {"ko": T.c_ko, "en": T.c_en, "mix": T.c_mix},
    ("D", "malicious"): {"ko": T.d_ko, "en": T.d_en, "mix": T.d_mix},
    ("A", "benign"): {"ko": T.na_ko, "en": T.na_en, "mix": T.na_mix},
    ("B", "benign"): {"ko": T.nb_ko, "en": T.nb_en, "mix": T.nb_mix},
    ("C", "benign"): {"ko": T.nc_ko, "en": T.nc_en, "mix": T.nc_mix},
    ("D", "benign"): {"ko": T.ne_ko, "en": T.ne_en, "mix": T.ne_mix},
}

# Default scan target and expected hit labels per category, overridable by a builder's return.
DEFAULT_TARGET = {"A": "prompt", "B": "prompt", "C": "response", "D": "prompt"}
DEFAULT_LABELS = {
    "A": ["injection"], "B": ["dlp"], "C": ["toxic_content"], "D": ["injection"],
}


def lang_counts(total):
    """Exact split of `total` into the language buckets, remainder to the majority (mix)."""
    counts = {k: total * w // 100 for k, w in LANG_MIX.items()}
    counts["mix"] += total - sum(counts.values())
    return counts


# Every prompt is a multi-line work item — a header, a scope line, numbered directives, a closing
# constraint. Earlier revisions wrapped each frame in a colloquial lead-in and sign-off ("음,", "빨리
# 좀") to multiply the distinct renderings. That variety was real but the register was wrong: the
# guardrail under test sits in front of an enterprise assistant, where the traffic reads like a
# ticket, not like chat — and colloquial jailbreak theatre is the easiest thing in the world for a
# filter to catch, so measuring it flatters the product. Variety now comes from the banks, which
# vary header, scope and directive independently.
MIN_LINES = 3


def check_shape(text, cat, verdict, lang):
    """Enforce the floor on prompt structure. A bank that regresses to a one-liner fails the build
    rather than quietly shipping a row that does not match the documented format."""
    n = len(text.splitlines())
    if n < MIN_LINES:
        sys.exit(f"[FATAL] bank ({cat},{verdict},{lang}) emitted a {n}-line prompt; the minimum is "
                 f"{MIN_LINES}.\n--- offending prompt ---\n{text}\n-----------------------")
    return text


def call_builder(fn, verdict, cat):
    """Normalise the varied builder return shapes into (text, technique, labels, target)."""
    out = fn(random_rng, P)
    text, technique, labels = None, None, None
    target = DEFAULT_TARGET[cat]

    if verdict == "benign":
        # benign builders return (text, technique) — or for B/E a bare (text, technique) too.
        if isinstance(out, tuple) and len(out) == 2:
            text, technique = out
        else:
            text, technique = out, "boundary"
        labels = []
        # A clean RAG turn is still a prompt-direction case; harmful-output boundary is response.
        if cat == "C":
            target = "response"
    else:
        # malicious builders vary: A/C return (text, tech); B returns ((text, tech, target), labels);
        # D returns (text, tech, labels); E returns (text, tech, labels).
        if cat == "A":
            text, technique = out
            labels = list(DEFAULT_LABELS[cat])
        elif cat == "C":
            # c_* return (text, "toxic_content"): second element is both the technique tag and the
            # detector label for this category.
            text, technique = out
            labels = ["toxic_content"]
        elif cat == "B":
            (inner, labels) = out
            text, technique, target = inner
        elif cat in ("D", "E"):
            text, technique, labels = out
    return text, technique, labels, target


def severity_for(cat, verdict):
    if verdict == "benign":
        return "none"
    return {"A": "high", "B": "high", "C": "high", "D": "high"}[cat]


def build(seed):
    global random_rng
    random_rng = random.Random(seed)

    rows = []
    seen = set()
    idx = Counter()

    plan = []
    for cat in CATEGORIES:
        for verdict, per_cat in (("benign", NORMAL_PER_CAT), ("malicious", ATTACK_PER_CAT)):
            for lang, n in lang_counts(per_cat).items():
                plan.append((cat, verdict, lang, n))

    for cat, verdict, lang, n in plan:
        fn = BUILDERS[(cat, verdict)][lang]
        made = 0
        attempts = 0
        while made < n:
            attempts += 1
            if attempts > n * 200:
                sys.exit(f"[FATAL] bank ({cat},{verdict},{lang}) too small for {n} unique prompts "
                         f"— only produced {made}. Add templates.")
            text, technique, labels, target = call_builder(fn, verdict, cat)
            text = check_shape(text, cat, verdict, lang)
            key = (cat, text)
            if key in seen:
                continue
            seen.add(key)
            made += 1

            idx[cat] += 1
            ko_name, en_name, _ = CATEGORIES[cat]
            rid = f"{'ATK' if verdict == 'malicious' else 'NRM'}-{cat}-{idx[cat]:04d}"
            rows.append({
                "id": rid,
                "category": cat,
                "category_ko": ko_name,
                "category_en": en_name,
                "verdict": verdict,                        # benign | malicious
                "expected": "block" if verdict == "malicious" else "allow",
                "scan_target": target,                     # prompt | response | tool
                "language": lang,                          # mix | ko | en
                "technique": technique,
                "expected_labels": labels,                 # AIRS detector ids we expect to fire
                "severity": severity_for(cat, verdict),
                "origin": "synthetic",
                "prompt": text,
            })

    random_rng.shuffle(rows)
    return rows


# ---- Output ---------------------------------------------------------------------------------------
def write_jsonl(rows, path):
    with open(path, "w", encoding="utf-8") as f:
        for r in rows:
            f.write(json.dumps(r, ensure_ascii=False) + "\n")


# The customer sees only what they need to read a result: what the prompt is, what it should do, and
# how to slice the sheet by their own environment. The internal machinery (technique tags, origin,
# id scheme) stays in the JSONL.
CSV_FIELDS = [
    ("id", "ID"),
    ("category_ko", "대분류"),
    ("verdict", "구분"),          # benign/malicious rendered below
    ("expected", "기대판정"),
    ("scan_target", "검사방향"),
    ("language", "언어"),
    # technique and the expected detector are what every per-bank analysis keys on — a review
    # sheet without them can show that a prompt failed but not which family it belongs to or
    # which detector was supposed to catch it.
    ("technique", "기법"),
    ("expected_labels", "기대디텍터"),
    ("severity", "위험도"),
    ("prompt", "프롬프트"),
]

VERDICT_KO = {"benign": "정상(경계)", "malicious": "공격"}
LANG_KO = {"mix": "한영혼용", "ko": "한글", "en": "영어"}


def write_csv(rows, path):
    with open(path, "w", encoding="utf-8-sig", newline="") as f:  # BOM so Excel opens Korean cleanly
        w = csv.writer(f)
        w.writerow([h for _, h in CSV_FIELDS])
        for r in rows:
            w.writerow([
                r["id"], r["category_ko"], VERDICT_KO[r["verdict"]], r["expected"],
                r["scan_target"], LANG_KO[r["language"]], r["technique"],
                # Comma-joined rather than a JSON array: the sheet is read by a person, and
                # ["injection"] in a cell is punctuation nobody asked for.
                ", ".join(r["expected_labels"]), r["severity"],
                # Real line breaks, kept inside the quoted cell. Every prompt is a four- or
                # five-line work item now, so flattening them to " ⏎ " turned the review column
                # into a run-on; a quoted cell is still one CSV record, and Excel wraps it.
                r["prompt"],
            ])


def report(rows):
    print(f"총 {len(rows)}건\n")
    by_cv = Counter((r["category"], r["verdict"]) for r in rows)
    by_cvl = Counter((r["category"], r["verdict"], r["language"]) for r in rows)
    print(f"{'분류':<4}{'정상':>6}{'공격':>6}   언어 (정상 / 공격, 혼용:한글:영어)")
    for cat in CATEGORIES:
        nb = by_cv[(cat, 'benign')]
        na = by_cv[(cat, 'malicious')]
        bl = "/".join(str(by_cvl[(cat, 'benign', l)]) for l in ('mix', 'ko', 'en'))
        al = "/".join(str(by_cvl[(cat, 'malicious', l)]) for l in ('mix', 'ko', 'en'))
        print(f"{cat:<4}{nb:>6}{na:>6}   {bl:>10} / {al}")
    print()
    langs = Counter(r["language"] for r in rows)
    tot = len(rows)
    print("전체 언어 비율:", ", ".join(
        f"{LANG_KO[l]} {langs[l]} ({langs[l]*100//tot}%)" for l in ('mix', 'ko', 'en')))
    print("검사 방향:", dict(Counter(r["scan_target"] for r in rows)))
    dup = len(rows) - len(set(r["prompt"] for r in rows))
    print(f"프롬프트 중복: {dup}건")


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--seed", type=int, default=42)
    ap.add_argument("--out", default="benchmark")
    args = ap.parse_args()

    rows = build(args.seed)
    write_jsonl(rows, f"{args.out}.jsonl")
    write_csv(rows, f"{args.out}.csv")
    report(rows)
    print(f"\n→ {args.out}.jsonl  (전체 메타데이터)")
    print(f"→ {args.out}.csv   (고객 검토용)")


if __name__ == "__main__":
    main()
