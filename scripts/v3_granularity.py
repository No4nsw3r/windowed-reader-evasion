r"""Recompute Appendix~\ref{sec:appgran}: fragment granularity at fixed filler volume.

WHY THIS SCRIPT EXISTS. `followup_results/exp4_il_granularity.csv` is 3,300 judged cells
that were run and then cited nowhere. A v4 reviewer asked for exactly this sweep -- the
fragment gap varied with the filler volume held fixed -- and it was already on disk. This
script derives every number the appendix prints, so the table is recomputable without a
model call.

WHAT THE SWEEP IS. One judge (`gpt-4o-mini`), the malicious arm, 165 skills, five fragment
counts and four readers, fully crossed at exactly 165 cells each. The transform is
`v2_coverage.segs_interleave(S, 4500, nseg)`: the filler volume is pinned at 4,500
characters and only the number of pieces changes, so the payload's text, its length and its
share of the artifact are all held fixed and the gap between fragments is
4500 // (nseg + 1). `nseg = 8` is the paper's `il_matched`, so the sweep brackets the
body's volume-matched cell.

THE RESULT THAT MATTERS. At the `none` reader the whole artifact fits one window -- the
longest is 7,493 characters against the 8,000-character cap -- so the window count, the
call count and the payload's share of the window are fixed by construction, and attack
success still moves 15 points across the sweep. Whatever that is, it is not reader
geometry, and this script prints the check rather than asserting it.

Statistics are exact and scipy-free: Clopper-Pearson by bisection on a binomial CDF summed
in LOG space (`math.comb` overflows at these n), Fisher exact two-sided by summing tables
no more probable than the observed one, a chi-square on the 2x5 table with a closed-form
even-df survival function, and Spearman with a normal approximation on 825 rows.

usage: python -I scripts/v3_granularity.py
"""
import collections
import csv
import math
import os
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
FP = os.path.join(ROOT, "followup_results", "exp4_il_granularity.csv")
NSEG = (2, 4, 8, 16, 32)
FILLER = 4500
CAP = 8000

sys.stdout.reconfigure(encoding="utf-8", errors="replace")


# ---------------------------------------------------------------- exact statistics
def _binom_cdf(k, n, p):
    """P(X <= k) for X ~ Bin(n, p), summed in log space."""
    if p <= 0.0:
        return 1.0
    if p >= 1.0:
        return 1.0 if k >= n else 0.0
    lp, lq, lg = math.log(p), math.log1p(-p), math.lgamma
    tot = 0.0
    for i in range(k + 1):
        tot += math.exp(lg(n + 1) - lg(i + 1) - lg(n - i + 1) + i * lp + (n - i) * lq)
    return min(1.0, tot)


def _bisect(f, a=0.0, b=1.0, it=90):
    """Root of a monotone f on [a, b], direction read from the endpoint rather than
    assumed -- hard-coding one direction is how an earlier script in this repo printed
    every lower bound as 1.0."""
    fa = f(a)
    for _ in range(it):
        m = (a + b) / 2
        if (f(m) < 0) == (fa < 0):
            a = m
        else:
            b = m
    return (a + b) / 2


def clopper_pearson(k, n, alpha=0.05):
    lo = 0.0 if k == 0 else _bisect(lambda p: _binom_cdf(k - 1, n, p) - (1 - alpha / 2))
    hi = 1.0 if k == n else _bisect(lambda p: _binom_cdf(k, n, p) - alpha / 2)
    return lo, hi


def _lchoose(n, k):
    return math.lgamma(n + 1) - math.lgamma(k + 1) - math.lgamma(n - k + 1)


def fisher(a, b, c, d):
    """Two-sided Fisher exact on [[a, b], [c, d]]."""
    r1, r2, c1 = a + b, c + d, a + c
    n = r1 + r2

    def lp(x):
        return _lchoose(r1, x) + _lchoose(r2, c1 - x) - _lchoose(n, c1)

    obs = lp(a)
    tot = 0.0
    for x in range(max(0, c1 - r2), min(r1, c1) + 1):
        v = lp(x)
        if v <= obs + 1e-9:
            tot += math.exp(v)
    return min(1.0, tot)


def chisq(table):
    rn = len(table)
    cn = len(table[0])
    rt = [sum(r) for r in table]
    ct = [sum(table[i][j] for i in range(rn)) for j in range(cn)]
    n = sum(rt)
    s = 0.0
    for i in range(rn):
        for j in range(cn):
            e = rt[i] * ct[j] / n
            if e > 0:
                s += (table[i][j] - e) ** 2 / e
    return s


def chisq_sf(x, df):
    """Survival function for even df, closed form."""
    assert df % 2 == 0, "this form is for even df only"
    k = df // 2
    t = math.exp(-x / 2)
    s = t
    for i in range(1, k):
        t *= x / 2 / i
        s += t
    return min(1.0, s)


def spearman(xs, ys):
    def rank(v):
        order = sorted(range(len(v)), key=lambda i: v[i])
        r = [0.0] * len(v)
        i = 0
        while i < len(order):
            j = i
            while j + 1 < len(order) and v[order[j + 1]] == v[order[i]]:
                j += 1
            avg = (i + j) / 2 + 1
            for t in range(i, j + 1):
                r[order[t]] = avg
            i = j + 1
        return r

    rx, ry = rank(xs), rank(ys)
    n = len(xs)
    mx, my = sum(rx) / n, sum(ry) / n
    num = sum((a - mx) * (b - my) for a, b in zip(rx, ry))
    den = math.sqrt(sum((a - mx) ** 2 for a in rx) * sum((b - my) ** 2 for b in ry))
    rho = num / den if den else 0.0
    t = rho * math.sqrt((n - 2) / max(1e-12, 1 - rho * rho))
    return rho, math.erfc(abs(t) / math.sqrt(2))


# ---------------------------------------------------------------- the sweep
def main():
    if not os.path.exists(FP):
        sys.exit(f"missing {FP}")
    with open(FP, newline="", encoding="utf-8") as f:
        rows = list(csv.DictReader(f))
    readers = sorted({r["defense"] for r in rows})
    print(f"{os.path.basename(FP)}: {len(rows)} cells, "
          f"judges={sorted({r['model'] for r in rows})}, "
          f"skills={len({r['skill_hash'] for r in rows})}")
    print(f"  nseg={sorted({int(r['nseg']) for r in rows})}  readers={readers}")
    mix = collections.Counter(r["verdict"] for r in rows)
    print(f"  verdicts={dict(mix)}")
    assert set(mix) <= {"SAFE", "MALICIOUS"}, (
        "this sweep is expected to carry no ERR and no OVERFLOW cell; it now does, so the "
        "ASR denominator below would silently change")

    by = collections.defaultdict(list)
    for r in rows:
        by[(r["defense"], int(r["nseg"]))].append(r["verdict"])
    for key, vs in by.items():
        assert len(vs) == 165, f"{key} has {len(vs)} cells, expected 165"

    # the payload share is pinned at the single-window reader: check it rather than claim it
    lens = [int(r["len"]) for r in rows]
    per_skill = collections.defaultdict(set)
    for r in rows:
        per_skill[r["skill_hash"]].add(int(r["len"]))
    assert all(len(v) == 1 for v in per_skill.values()), (
        "payload length varies within a skill across the sweep, so the share is not pinned")
    shares = [sorted(v)[0] / (sorted(v)[0] + FILLER) for v in per_skill.values()]
    print(f"  payload: min {min(lens)}  mean {sum(lens) / len(lens):.0f}  max {max(lens)}")
    print(f"  longest artifact at `none` = {max(lens) + FILLER} characters "
          f"against the {CAP}-character cap "
          f"({'inside' if max(lens) + FILLER < CAP else 'OVER -- the sweep truncates'})")
    print(f"  payload share of the single window: mean {sum(shares) / len(shares):.4f}, "
          f"fixed per skill by construction")

    print(f"\n{'reader':14s}{'nseg':>5s}{'gap':>6s}{'piece':>7s}{'n':>5s}"
          f"{'SAFE':>6s}{'ASR':>8s}{'CP95':>18s}")
    for d in readers:
        for ns in NSEG:
            vs = by[(d, ns)]
            n = len(vs)
            k = sum(1 for v in vs if v == "SAFE")
            lo, hi = clopper_pearson(k, n)
            gap = FILLER // (ns + 1)
            piece = int(round(sum(lens) / len(lens) / ns))
            print(f"{d:14s}{ns:5d}{gap:6d}{piece:7d}{n:5d}{k:6d}{k / n:8.3f}"
                  f"   [{lo:.3f},{hi:.3f}]")

    print("\npooled over the four readers:")
    pool = collections.defaultdict(list)
    for r in rows:
        pool[int(r["nseg"])].append(r["verdict"])
    for ns in NSEG:
        vs = pool[ns]
        k = sum(1 for v in vs if v == "SAFE")
        lo, hi = clopper_pearson(k, len(vs))
        print(f"  nseg {ns:2d}  {k}/{len(vs)} = {k / len(vs):.3f}  [{lo:.3f},{hi:.3f}]")

    print("\nbest against worst granularity within each reader, exact Fisher two-sided,")
    print("and the heterogeneity across all five:")
    for d in readers:
        rates = {ns: sum(1 for v in by[(d, ns)] if v == "SAFE") / 165 for ns in NSEG}
        hi_ns, lo_ns = max(rates, key=rates.get), min(rates, key=rates.get)
        a = sum(1 for v in by[(d, hi_ns)] if v == "SAFE")
        c = sum(1 for v in by[(d, lo_ns)] if v == "SAFE")
        p = fisher(a, 165 - a, c, 165 - c)
        tab = [[sum(1 for v in by[(d, ns)] if v == "SAFE") for ns in NSEG],
               [165 - sum(1 for v in by[(d, ns)] if v == "SAFE") for ns in NSEG]]
        x = chisq(tab)
        print(f"  {d:14s} nseg {hi_ns:2d} {rates[hi_ns]:.3f} vs nseg {lo_ns:2d} "
              f"{rates[lo_ns]:.3f}  Fisher p = {p:.4f}   "
              f"chi2(4) = {x:5.2f}, p = {chisq_sf(x, 4):.4f}"
              f"{'   <- nseg 8 at or next to the minimum' if abs(lo_ns - 8) <= 4 else ''}")

    print("\nthe sign of the granularity effect, Spearman on the cell-level rows:")
    for d in readers:
        sub = [r for r in rows if r["defense"] == d]
        rho, p = spearman([int(r["nseg"]) for r in sub],
                          [1 if r["verdict"] == "SAFE" else 0 for r in sub])
        print(f"  {d:14s} rho = {rho:+.3f}  p = {p:.4f}  n = {len(sub)}   "
              f"{'more fragments help the attacker' if rho > 0 else 'more fragments help the defender'}")

    vs2 = by[("none", 4)]
    vs8 = by[("none", 8)]
    k2 = sum(1 for v in vs2 if v == "SAFE")
    k8 = sum(1 for v in vs8 if v == "SAFE")
    print("\nthe pinned-geometry check, which is the point of the appendix:")
    print(f"  at `none` the artifact is ONE window, so the window count, the call count and")
    print(f"  the payload's share of the window are all constant across the sweep, and")
    print(f"  attack success still moves {k8 / 165:.3f} -> {k2 / 165:.3f} "
          f"(Fisher p = {fisher(k2, 165 - k2, k8, 165 - k8):.4f}).")
    return 0


if __name__ == "__main__":
    sys.exit(main())
