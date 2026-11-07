r"""Build the `dedup_small` vs `trunc10k` pairing behind section 6.3, and print which way
the disagreement runs.

WHY THIS SCRIPT EXISTS. Section 6.3 answers the coverage-equivalence objection with a
single scalar: on the cells where both readers returned a verdict they agree at $0.827$.
Read on its own that number argues the sceptic's case -- 83% agreement between a six-window
OR and one call on the same $[0, 10{,}000)$ span is agreement, not difference -- and nothing
in the release shows how the 3,291-cell pairing was built, so a reviewer who rebuilds it
gets a different n and cannot tell whose pairing is wrong.

The stronger statement is already in the data and was never printed: the disagreement is
almost one-directional. `dedup_small` flags artifacts `trunc10k` passes 8.3 times more
often than the reverse, which is what "a different reader" means operationally, and the
agreement rate is the wrong statistic for the claim because it pools the two directions.

The pairing is not obvious, so this script fixes it in code rather than in prose:

  left    every `dedup_small` row in the six per-item tables that carry that reader --
          `v2_phase1_items.csv` (column `defense`), `v2_phase2_items.csv` (column
          `config`), and the four `v2_phase3_items_*.csv` cross-judge tables (`defense`).
  right   every `trunc10k` row in `v2_skillgate_items.csv` (column `reader`).
  key     (model, skill_hash, attack, arm, payload_len), inner join.
  filter  both sides in {SAFE, MALICIOUS}. OVERFLOW is a routing decision and ERR is not
          a verdict, so neither is a cell where "both returned a verdict".

`payload_len` is load-bearing in that key, not decoration. Without it the join also admits
`v2_phase2_items.csv`'s operating-point block, whose benign draw re-measures the same
hashes against different artifacts, and n goes to 3,472. With it, phase 2 drops out and the
published 3,291 falls out exactly -- which is also why the four-column join a reviewer
would try first does not reproduce the paper.

The script refuses to report until it has reproduced the published cell:

    n = 3291    agree = 2721    rate = 0.827

Inside a built artifact tree the benign arm's per-item rows are replaced by counts, so the
300 benign pairs cannot be formed there. The script detects that, reports the 2,991
malicious pairs, and says so rather than printing a number it cannot stand behind.

McNemar is the exact two-sided sign test on the discordant pairs, the same statistic the
rest of the paper uses. Clopper-Pearson bounds are bisected on an exact binomial CDF summed
in log space, so the 3,291-trial tail does not underflow. No scipy, no API calls.

usage: python -I scripts/v3_reader_disagreement.py
"""
import glob
import math
import os
import sys

import pandas as pd

sys.stdout.reconfigure(encoding="utf-8", errors="replace")

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
NOTES = os.path.join(ROOT, "research_notes", "v2_main")

GOOD = ("SAFE", "MALICIOUS")
KEY = ["model", "skill_hash", "attack", "arm", "payload_len"]
LEFT_READER = "dedup_small"
RIGHT_READER = "trunc10k"
RIGHT_FILE = "v2_skillgate_items.csv"

# the published cell this script has to reproduce before it prints anything
PUB_N, PUB_AGREE, PUB_RATE = 3291, 2721, 0.827
# and the malicious-arm subset, which is all a built artifact tree can form
PUB_MAL_N, PUB_MAL_AGREE = 2991, 2436

SHORT = {"gpt-4o-mini": "gpt-4o-mini", "gpt-4o": "gpt-4o", "qwen3:8b": "qwen3:8b",
         "google/gemini-2.5-flash-lite": "gemini-2.5-flash-lite",
         "anthropic/claude-haiku-4.5": "claude-haiku-4.5",
         "gemini-flash-lite-latest": "gemini-flash-lite-latest"}


# ---------------------------------------------------------------- exact statistics
def log_binom_cdf(k, n, p):
    """log P[X <= k] for X ~ Bin(n, p), summed in log space."""
    if p <= 0.0:
        return 0.0
    if p >= 1.0:
        return 0.0 if k >= n else float("-inf")
    terms = [math.lgamma(n + 1) - math.lgamma(i + 1) - math.lgamma(n - i + 1)
             + i * math.log(p) + (n - i) * math.log1p(-p) for i in range(k + 1)]
    m = max(terms)
    return m + math.log(sum(math.exp(t - m) for t in terms))


def binom_cdf(k, n, p):
    return math.exp(log_binom_cdf(k, n, p))


def _bisect(f, a=0.0, b=1.0, it=200):
    fa = f(a)
    for _ in range(it):
        m = (a + b) / 2
        if (f(m) < 0) == (fa < 0):
            a = m
        else:
            b = m
    return (a + b) / 2


def cp(k, n, alpha=0.05):
    """Clopper-Pearson, bisected on the exact binomial CDF."""
    if n == 0:
        return float("nan"), float("nan")
    lo = 0.0 if k == 0 else _bisect(lambda p: 1 - binom_cdf(k - 1, n, p) - alpha / 2)
    hi = 1.0 if k == n else _bisect(lambda p: binom_cdf(k, n, p) - alpha / 2)
    return lo, hi


def mcnemar(b, c):
    """Exact two-sided sign test on the discordant pairs.

    `2 * sum(comb(...)) / 2 ** n` stays exact: both sides are Python ints and int/int
    true division is correctly rounded at any magnitude, so n = 570 does not overflow.
    """
    n = b + c
    if n == 0:
        return 1.0
    k = min(b, c)
    return min(1.0, 2 * sum(math.comb(n, i) for i in range(k + 1)) / 2 ** n)


# ---------------------------------------------------------------- the pairing
def left_sources():
    """The per-item tables that carry a `dedup_small` row, and the column it lives in."""
    out = [("v2_phase1_items.csv", "defense"), ("v2_phase2_items.csv", "config")]
    for p in sorted(glob.glob(os.path.join(NOTES, "v2_phase3_items_*.csv"))):
        out.append((os.path.basename(p), "defense"))
    return out


def _read(name):
    fp = os.path.join(NOTES, name)
    if not os.path.exists(fp):
        return None
    d = pd.read_csv(fp, dtype=str, on_bad_lines="skip", low_memory=False)
    return d if len(d) else None


def build():
    frames = []
    for name, col in left_sources():
        d = _read(name)
        if d is None or col not in d.columns:
            print(f"  skip {name}: {'absent or empty' if d is None else 'no ' + col}")
            continue
        sel = d[d[col] == LEFT_READER].copy()
        sel["_src"] = name
        print(f"  {name:48s} {col:8s} {LEFT_READER} rows: {len(sel):5d}")
        if len(sel):
            frames.append(sel[KEY + ["verdict", "_src"]])
    if not frames:
        raise SystemExit(f"no {LEFT_READER} rows found under {NOTES}")
    left = pd.concat(frames, ignore_index=True)

    d = _read(RIGHT_FILE)
    if d is None:
        raise SystemExit(f"{RIGHT_FILE} is missing; the pairing cannot be formed")
    right = d[d["reader"] == RIGHT_READER][KEY + ["verdict"]].copy()
    print(f"  {RIGHT_FILE:48s} {'reader':8s} {RIGHT_READER} rows: {len(right):5d}")

    j = left.merge(right, on=KEY, how="inner", suffixes=("_small", "_t10"))
    both = j[j.verdict_small.isin(GOOD) & j.verdict_t10.isin(GOOD)].reset_index(drop=True)
    return left, right, j, both


def table(both, label, indent="  "):
    n = len(both)
    if n == 0:
        print(f"{indent}{label:34s} n = 0")
        return 0, 0, 0
    ss = int(((both.verdict_small == "SAFE") & (both.verdict_t10 == "SAFE")).sum())
    mm = int(((both.verdict_small == "MALICIOUS") & (both.verdict_t10 == "MALICIOUS")).sum())
    b = int(((both.verdict_small == "MALICIOUS") & (both.verdict_t10 == "SAFE")).sum())
    c = int(((both.verdict_small == "SAFE") & (both.verdict_t10 == "MALICIOUS")).sum())
    agree = ss + mm
    print(f"{indent}{label:34s} n = {n:5d}  agree = {agree:5d} ({agree / n:.4f})   "
          f"small-only = {b:4d}   t10-only = {c:4d}   p = {mcnemar(b, c):.3e}")
    return agree, b, c


def main():
    print(f"reading {NOTES}\n")
    left, right, j, both = build()

    n = len(both)
    agree, b, c = (int(((both.verdict_small == "SAFE") & (both.verdict_t10 == "SAFE")).sum())
                   + int(((both.verdict_small == "MALICIOUS")
                          & (both.verdict_t10 == "MALICIOUS")).sum()),
                   int(((both.verdict_small == "MALICIOUS")
                        & (both.verdict_t10 == "SAFE")).sum()),
                   int(((both.verdict_small == "SAFE")
                        & (both.verdict_t10 == "MALICIOUS")).sum()))
    has_benign = bool((both.arm == "ben").any())

    print(f"\njoined pairs on {'+'.join(KEY)}: {len(j)}")
    print(f"both sides in {GOOD}: {n}")
    if not has_benign:
        print("\nNOTE: no benign per-item rows in this tree -- the release replaces them\n"
              "      with aggregate counts, so the 300 benign pairs cannot be formed here\n"
              "      and only the malicious arm is checked against the paper.")
        if (n, agree) != (PUB_MAL_N, PUB_MAL_AGREE):
            raise SystemExit(f"malicious-arm pairing is {n}/{agree}, published is "
                             f"{PUB_MAL_N}/{PUB_MAL_AGREE}; not reporting")
    else:
        if (n, agree) != (PUB_N, PUB_AGREE):
            raise SystemExit(f"pairing is n={n} agree={agree}, published is n={PUB_N} "
                             f"agree={PUB_AGREE}; the pairing or the tables changed, "
                             f"not reporting")
        assert abs(agree / n - PUB_RATE) < 5e-4, f"rate {agree / n:.4f} != {PUB_RATE}"
        print(f"reproduces the published cell: n = {PUB_N}, agree = {PUB_AGREE}, "
              f"rate = {agree / n:.4f}")

    lo, hi = cp(agree, n)
    print(f"\n{'=' * 78}\nTHE 2x2\n{'=' * 78}")
    print(f"{'':26s} {RIGHT_READER + ' MALICIOUS':>22s} {RIGHT_READER + ' SAFE':>22s}")
    for v in ("MALICIOUS", "SAFE"):
        row = [int(((both.verdict_small == v) & (both.verdict_t10 == w)).sum())
               for w in ("MALICIOUS", "SAFE")]
        print(f"{LEFT_READER + ' ' + v:26s} {row[0]:22d} {row[1]:22d}")
    print(f"\nagreement        {agree}/{n} = {agree / n:.4f}  CP95 [{lo:.4f}, {hi:.4f}]")
    print(f"discordant       {b + c}")
    print(f"  {LEFT_READER} MALICIOUS, {RIGHT_READER} SAFE   {b}")
    print(f"  {LEFT_READER} SAFE, {RIGHT_READER} MALICIOUS   {c}")
    print(f"ratio            {b / c:.2f} : 1 in favour of {LEFT_READER}"
          if c else f"ratio            all {b} one way")
    print(f"exact two-sided McNemar sign test   p = {mcnemar(b, c):.3e}")
    print("\nThe agreement rate pools the two directions and so understates the "
          "difference\nbetween the readers. The direction is the finding.")

    print(f"\n{'=' * 78}\nBY ARM\n{'=' * 78}")
    for arm in ("mal", "ben"):
        table(both[both.arm == arm], arm)

    print(f"\n{'=' * 78}\nBY ATTACK\n{'=' * 78}")
    for atk in sorted(both.attack.unique()):
        table(both[both.attack == atk], atk)

    print(f"\n{'=' * 78}\nBY JUDGE\n{'=' * 78}")
    for m in sorted(both.model.unique()):
        table(both[both.model == m], SHORT.get(m, m))

    print(f"\n{'=' * 78}\nBY SOURCE TABLE\n{'=' * 78}")
    for s in sorted(both._src.unique()):
        table(both[both._src == s], s)

    print(f"\n{'=' * 78}\nWHERE A FOUR-COLUMN JOIN LANDS INSTEAD\n{'=' * 78}")
    k4 = [x for x in KEY if x != "payload_len"]
    j4 = left.merge(right, on=k4, how="inner", suffixes=("_small", "_t10"))
    b4 = j4[j4.verdict_small.isin(GOOD) & j4.verdict_t10.isin(GOOD)]
    print(f"  key {'+'.join(k4)}")
    table(b4, "dropping payload_len")
    print("  the extra cells are v2_phase2_items.csv's operating-point block, whose benign\n"
          "  draw re-measures the same hashes against different artifacts.")
    sub = both[(both._src == "v2_phase1_items.csv") & (both.arm == "mal")]
    print("\n  the slice a reviewer rebuilding phase 1 alone would get:")
    table(sub, "v2_phase1_items.csv, mal only", indent="    ")


if __name__ == "__main__":
    main()
