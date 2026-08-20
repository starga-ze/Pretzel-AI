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
    "D": ("에이전트·도구 오남용", "agent_tool_abuse", "tool"),
    "E": ("오염된 컨텍스트 유입", "poisoned_context", "prompt"),
}

NORMAL_PER_CAT = 100
ATTACK_PER_CAT = 200

# mix : ko : en = 65 : 20 : 15
LANG_MIX = {"mix": 65, "ko": 20, "en": 15}

# Which builder serves each (category, verdict, language).
BUILDERS = {
    ("A", "malicious"): {"ko": T.a_ko, "en": T.a_en, "mix": T.a_mix},
    ("B", "malicious"): {"ko": T.b_ko, "en": T.b_en, "mix": T.b_mix},
    ("C", "malicious"): {"ko": T.c_ko, "en": T.c_en, "mix": T.c_mix},
    ("D", "malicious"): {"ko": T.d_ko, "en": T.d_en, "mix": T.d_mix},
    ("E", "malicious"): {"ko": T.e_ko, "en": T.e_en, "mix": T.e_mix},
    ("A", "benign"): {"ko": T.na_ko, "en": T.na_en, "mix": T.na_mix},
    ("B", "benign"): {"ko": T.nb_ko, "en": T.nb_en, "mix": T.nb_mix},
    ("C", "benign"): {"ko": T.nc_ko, "en": T.nc_en, "mix": T.nc_mix},
    ("D", "benign"): {"ko": T.nd_ko, "en": T.nd_en, "mix": T.nd_mix},
    ("E", "benign"): {"ko": T.ne_ko, "en": T.ne_en, "mix": T.ne_mix},
}

# Default scan target and expected hit labels per category, overridable by a builder's return.
DEFAULT_TARGET = {"A": "prompt", "B": "prompt", "C": "response", "D": "tool", "E": "prompt"}
DEFAULT_LABELS = {
    "A": ["injection"], "B": ["dlp"], "C": ["toxic_content"],
    "D": ["agent"], "E": ["injection"],
}


def lang_counts(total):
    """Exact split of `total` into the language buckets, remainder to the majority (mix)."""
    counts = {k: total * w // 100 for k, w in LANG_MIX.items()}
    counts["mix"] += total - sum(counts.values())
    return counts


# Surface phrasing variety, language-aware and meaning-preserving. Real users do not send the same
# request twice the same way — they open with "음," or "혹시", they close with "부탁해요" or "빨리 좀".
# Modelling that is legitimate variety, not noise: it multiplies each frame's distinct renderings so
# the benchmark measures a detector, not its ability to memorise one wording. An empty lead-in and an
# empty tail are in each pool, so plenty of prompts stay bare. Applied only to single-line prompts —
# the multi-line RAG payloads (category E) carry their own structure and get a tail only.
_ENV = {
    "ko":  {"lead": ["", "", "", "음, ", "혹시 ", "저기 ", "잠깐, ", "그, "],
            "tail": ["", "", "", " 부탁해요.", " 좀 부탁해.", " 빨리 좀.", " 고마워.", " 가능할까?"]},
    "en":  {"lead": ["", "", "", "Hey, ", "Quick one — ", "So, ", "Okay, ", "Right, "],
            "tail": ["", "", "", " Thanks.", " Please.", " ASAP please.", " Appreciate it.", " if you can."]},
    "mix": {"lead": ["", "", "", "음, ", "혹시 ", "잠깐, ", "quick하게, ", "저기, "],
            "tail": ["", "", "", " 부탁해요.", " 좀 부탁해.", " asap 부탁.", " 고마워.", " 가능할까?"]},
}


def envelope(text, lang, multiline):
    env = _ENV[lang]
    tail = random_rng.choice(env["tail"])
    if multiline:
        return text + tail          # a lead-in before a "[document]…" block would read wrong
    lead = random_rng.choice(env["lead"])
    # Don't capital-clash: if we prepend an English lead-in, lowercase the original first letter only
    # when it started a plain sentence (not an ID, bracket, or quote).
    if lead and lang == "en" and text[:1].isupper() and text[1:2].islower():
        text = text[0].lower() + text[1:]
    return lead + text + tail


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
    return {"A": "high", "B": "high", "C": "high", "D": "critical", "E": "high"}[cat]


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
            text = envelope(text, lang, multiline="\n" in text)
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
                r["scan_target"], LANG_KO[r["language"]], r["severity"],
                r["prompt"].replace("\n", " ⏎ "),   # keep one row per prompt in a spreadsheet
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
