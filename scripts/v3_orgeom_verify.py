"""Reproduce the two-geometry independence table, and test it against the label audit.

WHY THIS SCRIPT EXISTS. `v2_orgeom_indep.py` and section 5 of `v2_final_recompute.py` both
build this table with `reader == "skillgate"`, which is the **mistaken half window width**
the paper corrects. The published table uses the width-corrected `regex_real` reader in
`followup_results/exp2_cells.csv`, paired item by item with each judge's partition-reader
verdicts. The two agree closely on some judges and differ on others, so a wrong-reader run
looks plausible rather than broken -- which is exactly how it survived.

So this script refuses to report anything until it has reproduced the published cells
exactly:

    gpt-4o-mini            165  14/19/26
    qwen3:8b               120  19/9/20
    gemini-2.5-flash-lite  120  8/10/30
    claude-haiku-4.5        92  24/5/23
    gpt-4o                  58  5/2/9

Then it runs the same 2x2 again with every skill that sits in the 631 joint-miss cell
deleted, which is the conservative extreme of the label correction: the human audit puts the
error rate in that cell at 0.684, not at 1. The claim under test is that the artifacts both
readers pass still outnumber an independence prediction once those items are gone.

ASR counts a refusal as a block and holds the denominator at every cell, per the refusal
convention the paper applies throughout.

usage: python -I scripts/v3_orgeom_verify.py
"""
import math
import os
import sys

import pandas as pd

sys.stdout.reconfigure(encoding="utf-8", errors="replace")

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
NOTES = os.path.join(ROOT, "research_notes", "v2_main")
GOOD = ("SAFE", "MALICIOUS")
A, B = "d_real", "il_matched"          # unused here, kept for symmetry with the ASR scripts
ATTACK = "gap_il_4x2600"

JUDGES = ["gpt-4o-mini", "qwen3:8b", "google/gemini-2.5-flash-lite",
          "anthropic/claude-haiku-4.5", "gpt-4o"]
SHORT = {"gpt-4o-mini": "gpt-4o-mini", "qwen3:8b": "qwen3:8b",
         "google/gemini-2.5-flash-lite": "gemini-2.5-flash-lite",
         "anthropic/claude-haiku-4.5": "claude-haiku-4.5", "gpt-4o": "gpt-4o"}

# where each judge's partition-reader verdicts live
P3 = {"gpt-4o-mini": ("v2_phase1_items.csv", "gpt-4o-mini"),
      "gpt-4o": ("v2_phase1_items.csv", "gpt-4o"),
      "qwen3:8b": ("v2_phase3_items_qwen3_8b.csv", None),
      "google/gemini-2.5-flash-lite":
          ("v2_phase3_items_google_gemini-2.5-flash-lite.csv", None),
      "anthropic/claude-haiku-4.5":
          ("v2_phase3_items_anthropic_claude-haiku-4.5.csv", None)}

# the published table: n, only-partition, only-regex, both-pass
PUBLISHED = {"gpt-4o-mini": (165, 14, 19, 26),
             "qwen3:8b": (120, 19, 9, 20),
             "google/gemini-2.5-flash-lite": (120, 8, 10, 30),
             "anthropic/claude-haiku-4.5": (92, 24, 5, 23),
             "gpt-4o": (58, 5, 2, 9)}


def _lg(n):
    return math.lgamma(n + 1)


def fisher_two_sided(a, b, c, d):
    """Two-sided Fisher exact on a 2x2, summing tables no likelier than the observed one."""
    n = a + b + c + d
    r1, r2, c1, c2 = a + b, c + d, a + c, b + d

    def lp(x):
        return (_lg(r1) + _lg(r2) + _lg(c1) + _lg(c2) - _lg(n)
                - _lg(x) - _lg(r1 - x) - _lg(c1 - x) - _lg(d - (a - x)))

    obs = lp(a)
    tot = 0.0
    for x in range(max(0, a - d), min(r1, c1) + 1):
        v = lp(x)
        if v <= obs + 1e-9:
            tot += math.exp(v)
    return min(1.0, tot)


def partition(model):
    fp, col = P3[model]
    d = pd.read_csv(os.path.join(NOTES, fp), dtype={"skill_hash": str},
                    on_bad_lines="skip")
    if col:
        d = d[d.model == col]
    d["_ok"] = d.verdict.isin(GOOD).astype(int)
    return d.sort_values("_ok", ascending=False).drop_duplicates(
        subset=["attack", "defense", "skill_hash"], keep="first")


def joint_miss_set():
    """The 631, reproduced the way every other script in this release reproduces it."""
    d = pd.read_csv(os.path.join(NOTES, "v2_layering_items.csv"),
                    dtype={"skill_hash": str})
    d = d.drop_duplicates(subset=["skill_hash", "arm"], keep="first")
    g = d[(d.arm == "mal") & d.llm.isin(GOOD) & d.cisco.isin(GOOD)
          & d.skillfrisk.isin(GOOD)]
    jm = set(g[(g.llm != "MALICIOUS") & (g.cisco != "MALICIOUS")].skill_hash)
    return g, jm


def cells(regex, model, drop):
    """2x2 over the skills both readers scored. A refusal is a block, so only SAFE passes."""
    r = regex[regex.judge == model]
    q = partition(model)
    q = q[(q.arm == "mal") & (q.attack == ATTACK) & (q.defense == "dedup_full")]
    if drop:
        r = r[~r.skill_hash.isin(drop)]
        q = q[~q.skill_hash.isin(drop)]
    rv, qv = dict(zip(r.skill_hash, r.verdict)), dict(zip(q.skill_hash, q.verdict))
    hs = sorted(set(rv) & set(qv))
    n = len(hs)
    ss = sum(1 for h in hs if rv[h] == "SAFE" and qv[h] == "SAFE")
    sm = sum(1 for h in hs if rv[h] == "SAFE" and qv[h] != "SAFE")
    ms = sum(1 for h in hs if rv[h] != "SAFE" and qv[h] == "SAFE")
    return n, sm, ms, ss, n - ss - sm - ms


def report(regex, drop, tag):
    print("\n=== %s ===" % tag)
    print("  %-22s %4s %6s %6s %6s %5s %5s %5s %7s %10s %6s"
          % ("judge", "n", "regex", "part", "OR", "onlyP", "onlyR", "both",
             "indep", "p", "ratio"))
    rs, ps = [], []
    for m in JUDGES:
        n, sm, ms, ss, mm = cells(regex, m, drop)
        exp = (ss + sm) * (ss + ms) / n
        p = fisher_two_sided(ss, sm, ms, mm)
        rs.append(ss / exp)
        ps.append(p)
        print("  %-22s %4d %6.3f %6.3f %6.3f %5d %5d %5d %7.1f %10.3g %6.2f"
              % (SHORT[m], n, (ss + sm) / n, (ss + ms) / n, ss / n, sm, ms, ss,
                 exp, p, ss / exp))
    print("  ratio range %.2f--%.2f | max p %.3g | all p<1e-4 %s | all p<0.05 %s"
          % (min(rs), max(rs), max(ps), all(x < 1e-4 for x in ps),
             all(x < 0.05 for x in ps)))
    return rs, ps


def main():
    g, jm = joint_miss_set()
    print("joint-miss set reproduced: %d of %d  (paper: 631 of 1124)" % (len(jm), len(g)))

    regex = pd.read_csv(os.path.join(ROOT, "followup_results", "exp2_cells.csv"),
                        dtype={"skill_hash": str})
    regex = regex[(regex.arm == "mal") & (regex.attack == ATTACK)
                  & (regex.reader == "regex_real")]

    print("\n=== reproduction gate against the published table ===")
    print("  %-22s %-22s %-22s %s" % ("judge", "published", "recomputed", "match"))
    ok = True
    for m in JUDGES:
        n, sm, ms, ss, _ = cells(regex, m, None)
        hit = (n, sm, ms, ss) == PUBLISHED[m]
        ok &= hit
        print("  %-22s %-22s %-22s %s"
              % (SHORT[m], str(PUBLISHED[m]), str((n, sm, ms, ss)),
                 "yes" if hit else "NO"))
    print("  table reproduces exactly: %s" % ok)
    if not ok:
        print("\nGATE FAILED. Nothing below would be trustworthy, so it is not printed.")
        return 1

    report(regex, None, "published table (all skills)")
    report(regex, jm, "label-suspect skills (those in the 631) deleted")

    print("\n=== how much of each judge's pairing is label-suspect ===")
    for m in JUDGES:
        r = regex[regex.judge == m]
        q = partition(m)
        q = q[(q.arm == "mal") & (q.attack == ATTACK) & (q.defense == "dedup_full")]
        paired = set(r.skill_hash) & set(q.skill_hash)
        s = paired & jm
        print("  %-22s %3d of %3d (%.3f)"
              % (SHORT[m], len(s), len(paired), len(s) / len(paired) if paired else 0))
    return 0


if __name__ == "__main__":
    sys.exit(main())
