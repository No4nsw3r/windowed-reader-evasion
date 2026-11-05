"""Re-derive the paper numbers that no other recompute script prints.

A full sweep of paper_v2.tex (703 numeric mentions, 331 distinct values) found that 311
of the 331 are printed verbatim by v2_final_recompute.py, v2_phase5_audit_score.py,
v2_label_robustness.py, v2_dispute_by_judge_model.py or one of the generated reports
under research_notes.  This script covers the remaining 20, so that every number in the
paper has a script behind it.  It writes nothing.

Blocks:
  1  the layering independence block (4.3) - 152 / 87 / 631 / 566 / 0.496 / 92 / 8.2 / 3.5
  2  tab:cost - all four rows, including the 1,443 denominator that dedup_lmax has
     because 57 benign artifacts overflow it
  3  window counts under attack - 12.5 over the six padding-family attacks, 33.4 at 50k
  4  the regex reader's two benign draws - 1,484 and 1,499 with Wilson intervals
  5  the screening draw - the last caught position for each of the four screened judges
  6  small derived quantities - 1,153, 820, 16.2, 55.9%

usage:  python -I scripts/v2_number_audit.py
"""
import os, sys, math, itertools

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
N = os.path.join(ROOT, "research_notes", "v2_main")
sys.path.insert(0, os.path.join(ROOT, "scripts"))
import pandas as pd

GOOD = ("SAFE", "MALICIOUS")
PASS, FAIL = [], []


def wilson(k, n, z=1.96):
    p = k / n
    d = 1 + z * z / n
    c = (p + z * z / (2 * n)) / d
    hw = z * math.sqrt(p * (1 - p) / n + z * z / (4 * n * n)) / d
    return round(p, 3), round(max(0, c - hw), 3), round(min(1, c + hw), 3)


def chk(label, paper, got, tol=0.0):
    ok = got is not None and abs(float(paper) - float(got)) <= tol + 1e-9
    (PASS if ok else FAIL).append(label)
    print("  %s %-50s paper %-10s computed %s"
          % ("ok  " if ok else "FAIL", label, paper, got))


def head(s):
    print("\n" + "-" * 78 + "\n%s\n" % s + "-" * 78)


p1 = pd.read_csv(os.path.join(N, "v2_phase1_items.csv"), dtype={"skill_hash": str})
p2 = pd.read_csv(os.path.join(N, "v2_phase2_items.csv"), dtype={"skill_hash": str})
sg = pd.read_csv(os.path.join(N, "v2_skillgate_items.csv"), dtype={"skill_hash": str})

head("1. layering independence (4.3), from the exact counts in v2_layering.md")
n, cm, cs, cu = 1124, 401, 244, 493
print("  judge %d/%d, cisco %d/%d, disjunction %d/%d" % (cm, n, cs, n, cu, n))
chk("caught by both", 152, cm + cs - cu)
chk("independence predicts both", 87, round(cm * cs / n))
chk("missed by both", 631, n - cu)
chk("independence predicts miss-both", 566, round((n - cm) * (n - cs) / n))
chk("independent disjunction", 0.496, round(1 - (n - cm) * (n - cs) / n / n, 3))
chk("share missed by both", 56, round(100 * (n - cu) / n))
chk("scanner catches the judge misses", 92, cs - (cm + cs - cu))
chk("that share of the pool", 8.2, round(100 * (cs - (cm + cs - cu)) / n, 1))
chk("recall points layering buys", 8.2, round(100 * (0.439 - 0.357), 1))
chk("false positive points it costs", 3.5, round(100 * (0.085 - 0.050), 1))

head("2. tab:cost - OVERFLOW rows are excluded, which is why dedup_lmax has n=1443")
op = p2[(p2.block == "opcost") & (p2.arm == "ben")]
for cfg, fpr_w, calls_w in (("none", 0.047, 1.00), ("dedup_small", 0.110, 3.81),
                            ("dedup_lmax", 0.112, 4.43), ("dedup_full", 0.129, 5.10)):
    g = op[(op.config == cfg) & op.verdict.isin(GOOD)]
    ovf = int((op[op.config == cfg].verdict == "OVERFLOW").sum())
    k = int((g.verdict == "MALICIOUS").sum())
    p, lo, hi = wilson(k, len(g))
    print("  %-12s scored %4d (+%2d overflow)  FPR %3d/%4d = %.3f [%.3f, %.3f]"
          % (cfg, len(g), ovf, k, len(g), p, lo, hi))
    chk("tab:cost FPR %s" % cfg, fpr_w, p)
    chk("tab:cost calls/artifact %s" % cfg, calls_w, round(g.n_calls.mean(), 2),
        tol=0.005)

head("3. windows under attack, uncapped reader, gpt-4o-mini malicious arm")
mini = p1[(p1.model == "gpt-4o-mini") & (p1.arm == "mal") &
          (p1.defense == "dedup_full")]
PADDING = ["uniq_pad_10k", "uniq_pad_20k", "uniq_pad_50k",
           "rep_pad_10k", "neardup_10k", "topical_10k"]
per = {a: round(mini[mini.attack == a].n_windows.mean(), 2) for a in PADDING}
print("  per attack: %s" % per)
chk("mean over the six padding-family attacks", 12.5,
    round(sum(per.values()) / len(per), 1))
chk("mean under uniq_pad_50k", 33.4, round(per["uniq_pad_50k"], 1))

head("4. the regex reader's two benign draws")
b = sg[(sg.arm == "ben") & (sg.reader == "skillgate") &
       sg.verdict.isin(GOOD)].reset_index(drop=True)
print("  skillgate benign rows %d, all with a verdict, split in file order" % len(b))
for name, g, n_w, fpr_w in (("draw 1", b.iloc[:1484], 1484, 0.108),
                            ("draw 2", b.iloc[1484:], 1499, 0.129)):
    k = int((g.verdict == "MALICIOUS").sum())
    p, lo, hi = wilson(k, len(g))
    print("  %s  n=%4d  FPR %3d/%4d = %.3f [%.3f, %.3f]"
          % (name, len(g), k, len(g), p, lo, hi))
    chk("%s size" % name, n_w, len(g))
    chk("%s FPR" % name, fpr_w, p)

head("5. the screening draw - position of each screened judge's last catch")
import pilot_dil2 as D
cand = D.load_candidates()
cand = cand.assign(skill_hash=[D.skill_hash(t) for t in cand.skill_text])
chk("candidate pool", 1124, len(cand))
caught = {
    "gpt-4o-mini": set(p1[(p1.model == "gpt-4o-mini") & (p1.arm == "mal")].skill_hash),
    "gpt-4o": set(p1[(p1.model == "gpt-4o") & (p1.arm == "mal")].skill_hash)}
for mdl, fn in (("qwen3:8b", "v2_phase3_items_qwen3_8b.csv"),
                ("gemini-2.5-flash-lite",
                 "v2_phase3_items_google_gemini-2.5-flash-lite.csv")):
    d = pd.read_csv(os.path.join(N, fn), dtype={"skill_hash": str})
    caught[mdl] = set(d[d.arm == "mal"].skill_hash)
for mdl, screen_n, pos_w in (("gpt-4o-mini", 460, 460), ("gpt-4o", 250, 243),
                             ("gemini-2.5-flash-lite", 543, 543),
                             ("qwen3:8b", 1124, 908)):
    draw = cand.sample(n=min(screen_n, len(cand)),
                       random_state=D.SEED).reset_index(drop=True)
    pos = [i + 1 for i, h in enumerate(draw.skill_hash) if h in caught[mdl]]
    print("  %-22s caught %3d of %4d screened" % (mdl, len(caught[mdl]), screen_n))
    chk("last caught position, %s" % mdl, pos_w, pos[-1] if pos else None)

head("6. small derived quantities")
chk("1124 candidates + 29 withheld families", 1153, 1124 + 29)
chk("extra reviews per 10,000 at FPR 0.047 -> 0.129", 820,
    round((0.129 - 0.047) * 10000))
pub = p1[(p1.model == "gpt-4o-mini") & (p1.arm == "mal") &
         (p1.attack == "uniq_pad_10k") & (p1.defense == "dedup_small")]
chk("payload delivered under uniq_pad_10k, capped reader", 16.2,
    round(100 * pub.read_frac.mean(), 1))
chk("claude-haiku-4.5 first-pass attrition, 3613 of 6463", 55.9,
    round(100 * 3613 / 6463, 1))

head("7. filler lengths, against the nominal names the paper uses in prose")
und = p1[(p1.model == "gpt-4o-mini") & (p1.arm == "mal") & (p1.defense == "none")]
for atk, nominal in (("uniq_pad_10k", 10000), ("uniq_pad_20k", 20000),
                     ("uniq_pad_50k", 50000), ("uniq_suf_20k", 20000)):
    g = und[und.attack == atk]
    if not len(g):
        continue
    filler = (g.artifact_len - g.payload_len).mode().iloc[0]
    print("  %-14s nominal %6d   actual filler %6d   (+%d for the separator)"
          % (atk, nominal, filler, filler - nominal))

print("\n" + "=" * 78)
print("passed %d   failed %d" % (len(PASS), len(FAIL)))
for f in FAIL:
    print("   FAIL  %s" % f)
print("Nothing was written.")
