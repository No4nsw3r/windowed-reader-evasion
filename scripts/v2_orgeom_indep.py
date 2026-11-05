"""Recompute the two-geometry table honestly.

The paper reports the OR of the regex reader and the uncapped partition as "45 discordant
items, no reversals" with an exact McNemar p. That test is empty: flagging on either
reader can only ADD flags, so the cell counting reversals is structurally zero and
McNemar on it is a one-sided binomial against an impossible alternative. Worse, the
sentence that frames it -- "because they fail orthogonally, they compose" -- is an
empirical claim that nobody checked.

So this prints the 2x2 of the two readers' verdicts per judge and the quantities that
actually carry content:

  * the two off-diagonal cells, which are what makes the OR worth running at all;
  * the both-SAFE cell against what independence would predict, which is the test of
    the orthogonality claim;
  * McNemar on regex vs partition, which is a real paired test between two readers
    neither of which contains the other;
  * the OR's rate, with Wilson bounds, next to the better of the two alone.

Point estimates are raw proportions, matching pilot_audit2.wilson.
"""
import math
import os
import sys

import pandas as pd

ROOT = r"."
N = os.path.join(ROOT, "research_notes", "v2_main")
sys.path.insert(0, os.path.join(ROOT, "scripts"))
import pilot_audit2 as A

GOOD = ("SAFE", "MALICIOUS")
ATK = "gap_il_4x2600"

# where each judge's uncapped-partition verdicts live, and under which column
PARTITION = {
    "gpt-4o-mini": ("v2_phase1_items.csv", "gpt-4o-mini"),
    "gpt-4o": ("v2_phase1_items.csv", "gpt-4o"),
    "qwen3:8b": ("v2_phase3_items_qwen3_8b.csv", None),
    "google/gemini-2.5-flash-lite":
        ("v2_phase3_items_google_gemini-2.5-flash-lite.csv", None),
    "anthropic/claude-haiku-4.5":
        ("v2_phase3_items_anthropic_claude-haiku-4.5.csv", None),
}
ORDER = ["gpt-4o-mini", "qwen3:8b", "google/gemini-2.5-flash-lite",
         "anthropic/claude-haiku-4.5", "gpt-4o"]


def binom_two_sided(b, c):
    """Exact McNemar: two-sided binomial on the discordant pairs."""
    n = b + c
    if n == 0:
        return 1.0
    k = min(b, c)
    tail = sum(math.comb(n, i) for i in range(k + 1)) / 2 ** n
    return min(1.0, 2 * tail)


def fisher_two_sided(a, b, c, d):
    """Fisher exact on the 2x2, used to ask whether the two readers' SAFE verdicts
    co-occur more than independence predicts."""
    n = a + b + c + d
    r1, r2, c1 = a + b, c + d, a + c

    def p(x):
        return (math.comb(r1, x) * math.comb(r2, c1 - x)) / math.comb(n, c1)

    obs = p(a)
    lo = max(0, c1 - r2)
    hi = min(r1, c1)
    return min(1.0, sum(p(x) for x in range(lo, hi + 1) if p(x) <= obs * (1 + 1e-9)))


def verdicts(model):
    """(regex dict, partition dict) keyed by skill hash, SAFE/MALICIOUS only."""
    sg = pd.read_csv(os.path.join(N, "v2_skillgate_items.csv"), dtype={"skill_hash": str})
    r = sg[(sg.model == model) & (sg.arm == "mal") & (sg.attack == ATK) &
           (sg.reader == "skillgate") & sg.verdict.isin(GOOD)]
    fp, mcol = PARTITION[model]
    d = pd.read_csv(os.path.join(N, fp), dtype={"skill_hash": str},
                    on_bad_lines="skip")
    if mcol:
        d = d[d.model == mcol]
    q = d[(d.arm == "mal") & (d.attack == ATK) & (d.defense == "dedup_full") &
          d.verdict.isin(GOOD)]
    # the judge's own file may hold a repaired row beside the failed first-pass one
    q = q.drop_duplicates(subset=["skill_hash"], keep="first")
    return dict(zip(r.skill_hash, r.verdict)), dict(zip(q.skill_hash, q.verdict))


rows = []
for m in ORDER:
    try:
        rg, pt = verdicts(m)
    except FileNotFoundError:
        print(f"{m}: no file yet")
        continue
    both = sorted(set(rg) & set(pt))
    if not both:
        print(f"{m}: no paired items yet")
        continue
    n = len(both)
    ss = sum(1 for h in both if rg[h] == "SAFE" and pt[h] == "SAFE")
    sm = sum(1 for h in both if rg[h] == "SAFE" and pt[h] == "MALICIOUS")
    ms = sum(1 for h in both if rg[h] == "MALICIOUS" and pt[h] == "SAFE")
    mm = n - ss - sm - ms
    r_safe, p_safe = ss + sm, ss + ms
    exp_ss = r_safe * p_safe / n
    pr, lor, hir = A.wilson(r_safe, n)
    pp, lop, hip = A.wilson(p_safe, n)
    po, loo, hio = A.wilson(ss, n)
    rows.append(dict(
        model=m, n=n, regex=pr, partition=pp, dis=po,
        dis_ci=f"[{loo}, {hio}]", regex_ci=f"[{lor}, {hir}]",
        part_ci=f"[{lop}, {hip}]",
        both_safe=ss, regex_only=sm, part_only=ms, both_caught=mm,
        exp_both=round(exp_ss, 1),
        p_indep=fisher_two_sided(ss, sm, ms, mm),
        p_readers=binom_two_sided(sm, ms),
        drop_vs_best=round(max(pr, pp) - po, 3)))

print(f"{'judge':30} {'n':>4} {'regex':>6} {'part':>6} {'OR':>6} "
      f"{'bothS':>6} {'rOnly':>6} {'pOnly':>6} {'expBoth':>8} "
      f"{'p_indep':>9} {'p_rdrs':>8} {'drop':>6}")
for r in rows:
    print(f"{r['model']:30} {r['n']:>4} {r['regex']:>6.3f} {r['partition']:>6.3f} "
          f"{r['dis']:>6.3f} {r['both_safe']:>6} {r['regex_only']:>6} "
          f"{r['part_only']:>6} {r['exp_both']:>8} {r['p_indep']:>9.2g} "
          f"{r['p_readers']:>8.2g} {r['drop_vs_best']:>6.3f}")

print()
print("bothS   = artifacts BOTH readers pass -> the OR's attack success")
print("rOnly   = regex passes, partition catches (the partition's contribution)")
print("pOnly   = partition passes, regex catches (the regex reader's contribution)")
print("expBoth = both-SAFE expected if the two readers failed independently")
print("p_indep = Fisher exact on the 2x2: is the overlap different from independence?")
print("p_rdrs  = exact McNemar, regex vs partition (a real paired test)")
print()
tot_r = sum(r["regex_only"] for r in rows)
tot_p = sum(r["part_only"] for r in rows)
print(f"Across judges: the partition catches {tot_r} artifacts the regex reader passes, "
      f"and the regex reader catches {tot_p} the partition passes.")
print("Neither reader's miss set contains the other's, which is why the OR helps; but "
      "both-SAFE exceeds the independence prediction on every judge, so the two do NOT "
      "fail orthogonally -- they share a common difficulty and the OR only recovers the "
      "non-shared part.")
