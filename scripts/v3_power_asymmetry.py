r"""Section 6.3's "under 0.03" is a point estimate, not a bound. This computes the bound.

The paper compares two reader geometries on the same volume-matched contrast
(`d_real` against `il_matched`, same filler volume, differing only in placement):

  * STRUCTURAL / position-addressed: the uncapped partition `dedup_full`, three judges,
    about 332 paired artifacts. Reported effect +0.022, +0.025, +0.033, no judge
    significant.
  * CONTENT-ADDRESSED: the regex-anchored reader `regex_real`, nine judges. Reported
    effects +0.024 to +0.175, six of nine significant under Bonferroni 0.05/9.

A reviewer's objection, which is correct: "the structural effect is under 0.03" is the
point estimate restated, and a non-significant result at this sample size does not bound
the effect anywhere near 0.03. So three things are computed here and none of them is a
rephrasing:

  1. The exact two-sided interval on each paired difference, per judge and pooled, by the
     standard conditional construction -- Clopper-Pearson on the gained share of the
     discordant pairs, mapped back through delta = (2*pi - 1) * d / n. This is the
     construction the paper's own three published intervals use, so it is gated on
     reproducing them.
  2. The MINIMUM DETECTABLE EFFECT: the smallest true delta the design has 80% power
     against, two-sided alpha 0.05, under the exact McNemar test, with the discordance
     rate held at its observed value. That is the sentence the paper can actually defend --
     "this design could not have found an effect smaller than X" -- in place of a bound it
     does not have.
  3. The same two quantities for the content-addressed arm, so the asymmetry between the
     geometries is stated in power and not only in significance.

ASR counts a refusal as a block and holds the denominator at all cells, so only SAFE is a
pass; "gained" means the attack turned a block into a pass. No scipy: the binomial CDF is
summed in log space, Clopper-Pearson is bisected on it, McNemar is the exact two-sided
sign test on the discordant pairs, and the power integral is enumerated exactly.

usage: python -I scripts/v3_power_asymmetry.py
"""
import csv
import math
import os
import sys

sys.stdout.reconfigure(encoding="utf-8", errors="replace")

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
NOTES = os.path.join(ROOT, "research_notes", "v2_main")
FR = os.path.join(ROOT, "followup_results")
GOOD = ("SAFE", "MALICIOUS")
BASE, ATK = "d_real", "il_matched"
ALPHA = 0.05
POWER = 0.80

STRUCTURAL = [                                  # judge -> phase3 file, at dedup_full
    ("claude-haiku-4.5", "anthropic/claude-haiku-4.5",
     "v2_phase3_items_anthropic_claude-haiku-4.5.csv"),
    ("gemini-2.5-f-l", "google/gemini-2.5-flash-lite",
     "v2_phase3_items_google_gemini-2.5-flash-lite.csv"),
    ("qwen3:8b", "qwen3:8b", "v2_phase3_items_qwen3_8b.csv"),
]
REGEX_JUDGES = ["gpt-4o-mini", "qwen3:8b", "anthropic/claude-haiku-4.5", "gpt-4o",
                "google/gemini-2.5-flash-lite", "claude-sonnet-5-5", "claude-opus-5-5",
                "claude-haiku-5-5", "gpt-5.1"]
RSHORT = {"anthropic/claude-haiku-4.5": "claude-haiku-4.5",
          "google/gemini-2.5-flash-lite": "gemini-2.5-f-l"}

# the published cells each arm is gated on: judge -> (n, gained, lost)
PUB_STRUCT = {"claude-haiku-4.5": (92, 10, 8), "gemini-2.5-f-l": (120, 12, 9),
              "qwen3:8b": (120, 17, 13)}
PUB_STRUCT_CI = {"claude-haiku-4.5": (-0.075, 0.111), "gemini-2.5-f-l": (-0.056, 0.099),
                 "qwen3:8b": (-0.063, 0.123)}
PUB_REGEX = {"gpt-4o-mini": (165, 27, 3), "qwen3:8b": (120, 27, 6),
             "claude-haiku-4.5": (92, 17, 3), "gpt-4o": (58, 6, 2),
             "gemini-2.5-f-l": (120, 12, 5), "claude-sonnet-5-5": (165, 17, 1),
             "claude-opus-5-5": (165, 20, 4), "claude-haiku-5-5": (165, 18, 4),
             "gpt-5.1": (165, 14, 10)}


# ------------------------------------------------------------------ statistics
def _lchoose(n, k):
    return math.lgamma(n + 1) - math.lgamma(k + 1) - math.lgamma(n - k + 1)


def binom_cdf(k, n, p):
    """Exact binomial CDF, summed in log space.

    math.comb(n, k) * p**k overflows before the small p**k can cancel it once n passes a
    few hundred, and n here reaches 1215. Summing exp(log C + k log p + (n-k) log q) keeps
    every term in range.
    """
    if k < 0:
        return 0.0
    if k >= n:
        return 1.0
    if p <= 0.0:
        return 1.0
    if p >= 1.0:
        return 0.0
    lp, lq = math.log(p), math.log1p(-p)
    return min(1.0, sum(math.exp(_lchoose(n, i) + i * lp + (n - i) * lq)
                        for i in range(k + 1)))


def _bisect(f, a=0.0, b=1.0, it=90):
    """Root of a monotone f on [a, b], direction read from the endpoint rather than
    assumed -- the Clopper-Pearson lower bound solves an increasing function of p and the
    upper bound a decreasing one, and a one-directional bisection silently returns the far
    endpoint for the other."""
    fa = f(a)
    for _ in range(it):
        m = (a + b) / 2
        if (f(m) < 0) == (fa < 0):
            a = m
        else:
            b = m
    return (a + b) / 2


def cp(k, n, alpha=ALPHA):
    """Clopper-Pearson, bisected on the exact binomial CDF."""
    if n == 0:
        return float("nan"), float("nan")
    lo = 0.0 if k == 0 else _bisect(lambda p: 1 - binom_cdf(k - 1, n, p) - alpha / 2)
    hi = 1.0 if k == n else _bisect(lambda p: binom_cdf(k, n, p) - alpha / 2)
    return lo, hi


def mcnemar(b, c):
    """Exact two-sided sign test on the discordant pairs."""
    d = b + c
    if d == 0:
        return 1.0
    k = min(b, c)
    return min(1.0, 2 * sum(math.comb(d, i) for i in range(k + 1)) / 2 ** d)


def paired_ci(n, gained, lost, alpha=ALPHA):
    """Exact two-sided interval on the paired difference, conditional construction.

    delta = (c - b) / n. Conditional on the d = b + c discordant pairs, c ~ Binom(d, pi)
    and delta = (2 pi - 1) d / n, which is increasing in pi, so a Clopper-Pearson interval
    on pi maps term by term onto an interval on delta. The width therefore comes entirely
    from the discordant pairs, which is the honest accounting: the concordant pairs carry
    no information about the difference.
    """
    d = gained + lost
    delta = (gained - lost) / n
    if d == 0:
        return delta, -1.0, 1.0           # no information at all
    lo, hi = cp(gained, d, alpha)
    return delta, (2 * lo - 1) * d / n, (2 * hi - 1) * d / n


_LOG2 = math.log(2.0)
_CRIT = {}


def crit(d, alpha=ALPHA):
    """The largest k for which an exact two-sided p is still <= alpha when min(b, c) = k.

    -1 means the test can never reject at that discordant count, which is the whole reason
    a small sample has no power: at d <= 5, even 0 against d is not significant. Summed in
    log space because math.comb(1215, 600) is a 365-digit integer.
    """
    if d in _CRIT:
        return _CRIT[d]
    kc, cum = -1, 0.0
    for k in range(d // 2 + 1):
        cum += math.exp(_lchoose(d, k) - d * _LOG2)
        if 2 * cum <= alpha:
            kc = k
        else:
            break
    _CRIT[d] = kc
    return kc


def power_at(n, pi_d, delta, alpha=ALPHA):
    """Exact power of the two-sided McNemar test against a true difference `delta`.

    The design is: each of n pairs is discordant with probability pi_d -- held at the
    observed rate, which is the standard nuisance-parameter treatment for this test -- and
    a discordant pair is a gain with probability pi_g = (1 + delta/pi_d)/2. The test
    rejects when min(b, c) <= crit(d). Nothing is normal-approximated; the only
    approximation is that the outer sum over d is truncated once the binomial weight is
    below 1e-14, which cannot move the result in the fourth decimal.
    """
    if pi_d <= 0:
        return 0.0
    pi_g = min(1.0, max(0.0, (1 + delta / pi_d) / 2))
    lpd, lqd = math.log(pi_d), math.log1p(-pi_d)
    mu = n * pi_d
    sd = math.sqrt(n * pi_d * (1 - pi_d)) or 1.0
    lo_d = max(0, int(mu - 9 * sd) - 1)
    hi_d = min(n, int(mu + 9 * sd) + 1)
    tot = 0.0
    for d in range(lo_d, hi_d + 1):
        kc = crit(d, alpha)
        if kc < 0:
            continue
        w = math.exp(_lchoose(n, d) + d * lpd + (n - d) * lqd)
        if w < 1e-14:
            continue
        if 2 * kc >= d:                                   # rejection region is everything
            tot += w
            continue
        # P(c <= kc) + P(c >= d - kc), disjoint because 2*kc < d
        tot += w * (binom_cdf(kc, d, pi_g) + 1.0 - binom_cdf(d - kc - 1, d, pi_g))
    return tot


def mde(n, pi_d, target=POWER, alpha=ALPHA):
    """Smallest |delta| the design has `target` power against. None if unreachable.

    Power rises monotonically in |delta| at fixed pi_d, and |delta| cannot exceed pi_d
    (every discordant pair would have to move the same way), so the search is a bisection
    on (0, pi_d]. If even delta = pi_d -- a perfect effect, every discordant pair a gain --
    falls short of the target, the design cannot reach it at any effect size, and that is
    reported rather than extrapolated.
    """
    best = power_at(n, pi_d, pi_d, alpha)
    if best < target:
        return None, best
    lo, hi = 0.0, pi_d
    for _ in range(40):
        mid = (lo + hi) / 2
        if power_at(n, pi_d, mid, alpha) < target:
            lo = mid
        else:
            hi = mid
    return hi, None


# ------------------------------------------------------------------ data
def read(path):
    with open(path, newline="", encoding="utf-8") as fh:
        return list(csv.DictReader(fh))


def structural_arm():
    """The uncapped partition `dedup_full`, each judge on its own caught set."""
    out = {}
    for short, model, fn in STRUCTURAL:
        best = {}
        for r in read(os.path.join(NOTES, fn)):
            if r.get("arm") != "mal" or r.get("defense") != "dedup_full":
                continue
            if r.get("attack") not in (BASE, ATK, "clean"):
                continue
            k = (r["attack"], r["skill_hash"])
            prev = best.get(k)
            if prev is None or (prev["verdict"] not in GOOD and r["verdict"] in GOOD):
                best[k] = r
        v = {a: {k[1]: r["verdict"] for k, r in best.items() if k[0] == a}
             for a in ("clean", BASE, ATK)}
        out[short] = v
    return out


def regex_arm():
    """The regex-anchored reader at its corrected width, from the published cell table.

    Restricted to the nine judges Tables 2 and `tab:rulesetjudge` publish. A tenth name,
    `gpt-5.1-high`, appears in the cell table as the reasoning-effort probe of
    Appendix `exp5` and was never run on `d_real`, so it has no volume-matched contrast
    and is dropped here rather than silently contributing a half-populated row.
    """
    keep = set(REGEX_JUDGES)
    out = {}
    for r in read(os.path.join(FR, "exp2_cells.csv")):
        if r["reader"] != "regex_real" or r["arm"] != "mal":
            continue
        if r["attack"] not in (BASE, ATK, "clean") or r["judge"] not in keep:
            continue
        j = RSHORT.get(r["judge"], r["judge"])
        out.setdefault(j, {}).setdefault(r["attack"], {})[r["skill_hash"]] = r["verdict"]
    missing = [j for j, v in out.items() if BASE not in v or ATK not in v]
    for j in missing:
        del out[j]
    if missing:
        print(f"  (dropped for want of a paired condition: {', '.join(missing)})")
    return out


def contrast(v):
    """n paired artifacts, gained, lost, and the two rates. Pass = SAFE."""
    hs = sorted(set(v[BASE]) & set(v[ATK]))
    gained = sum(1 for h in hs if v[BASE][h] != "SAFE" and v[ATK][h] == "SAFE")
    lost = sum(1 for h in hs if v[BASE][h] == "SAFE" and v[ATK][h] != "SAFE")
    r0 = sum(1 for h in hs if v[BASE][h] == "SAFE") / len(hs)
    r1 = sum(1 for h in hs if v[ATK][h] == "SAFE") / len(hs)
    return len(hs), gained, lost, r0, r1


# ------------------------------------------------------------------ report
def arm_report(name, cells, published, published_ci=None):
    print("\n" + "=" * 100)
    print(name)
    print("=" * 100)
    fails = []
    print(f"  {'judge':20s}{'n':>5s}{'base':>7s}{'atk':>7s}{'delta':>9s}"
          f"{'gain':>6s}{'lost':>6s}{'p':>10s}{'exact 95% CI':>22s}"
          f"{'MDE@80%':>10s}")
    tn = tg = tl = 0
    rows = []
    for j, v in cells.items():
        n, g, l, r0, r1 = contrast(v)
        tn += n
        tg += g
        tl += l
        p = mcnemar(l, g)
        delta, lo, hi = paired_ci(n, g, l)
        m, reach = mde(n, (g + l) / n)
        rows.append((j, n, g, l, delta, lo, hi, p, m, reach))
        ms = "never" if m is None else f"{m:+.4f}"
        print(f"  {j:20s}{n:5d}{r0:7.3f}{r1:7.3f}{delta:+9.4f}{g:6d}{l:6d}{p:10.4g}"
              f"{'[' + f'{lo:+.4f}' + ', ' + f'{hi:+.4f}' + ']':>22s}{ms:>10s}")
        if j in published and (n, g, l) != published[j]:
            fails.append(f"{name}: {j} recomputes (n={n}, gained={g}, lost={l}) against "
                         f"the published {published[j]}")
        if published_ci and j in published_ci:
            plo, phi = published_ci[j]
            if abs(lo - plo) > 0.0015 or abs(hi - phi) > 0.0015:
                fails.append(f"{name}: {j} interval recomputes [{lo:+.4f}, {hi:+.4f}] "
                             f"against the published [{plo:+.3f}, {phi:+.3f}]")

    delta, lo, hi = paired_ci(tn, tg, tl)
    p = mcnemar(tl, tg)
    m, reach = mde(tn, (tg + tl) / tn)
    ms = "never" if m is None else f"{m:+.4f}"
    print(f"  {'-' * 98}")
    print(f"  {'POOLED (unstratified)':20s}{tn:5d}{'':7s}{'':7s}{delta:+9.4f}"
          f"{tg:6d}{tl:6d}{p:10.4g}"
          f"{'[' + f'{lo:+.4f}' + ', ' + f'{hi:+.4f}' + ']':>22s}{ms:>10s}")
    wd = sum(r[1] * r[4] for r in rows) / tn
    print(f"  {'POOLED (n-weighted mean of the per-judge deltas)':<58s}{wd:+9.4f}")
    print(f"  discordance rate {(tg + tl) / tn:.4f} over {tn} pairs; "
          f"observed power at the measured delta = "
          f"{power_at(tn, (tg + tl) / tn, abs(delta)):.3f}")
    return dict(n=tn, gained=tg, lost=tl, delta=delta, lo=lo, hi=hi, p=p, mde=m,
                pi_d=(tg + tl) / tn, rows=rows), fails


def main():
    print("=" * 100)
    print("THE TWO-MECHANISM POWER ASYMMETRY")
    print(f"contrast: ASR({ATK}) - ASR({BASE}), volume matched, paired by artifact")
    print(f"exact two-sided McNemar, alpha = {ALPHA}, MDE at {POWER:.0%} power")
    print("=" * 100)

    s, f1 = arm_report("STRUCTURAL / position-addressed: the uncapped partition "
                       "`dedup_full`", structural_arm(), PUB_STRUCT, PUB_STRUCT_CI)
    r, f2 = arm_report("CONTENT-ADDRESSED: the regex-anchored reader `regex_real` at its "
                       "corrected width", regex_arm(), PUB_REGEX)

    fails = f1 + f2
    print("\n" + "=" * 100)
    print("GATE")
    print("=" * 100)
    if fails:
        for x in fails:
            print("  FAIL  " + x)
        print("\nThe published cells did not reproduce, so the bounds above are not the "
              "paper's. Nothing further is printed.")
        return 1
    print("  every published cell and every published interval reproduces exactly:")
    print("  the three partition contrasts (10/8, 12/9, 17/13 at n = 92, 120, 120) with")
    print("  their three intervals, and all nine regex contrasts (27/3, 27/6, 17/3, 6/2,")
    print("  12/5, 17/1, 20/4, 18/4, 14/10).")

    # ------------------------------------------------------------- what to say instead
    print("\n" + "=" * 100)
    print("WHAT SECTION 6.3 CAN SAY INSTEAD OF \"UNDER 0.03\"")
    print("=" * 100)
    worst = max(r_[6] for r_ in s["rows"])
    print(f"  Per judge, the exact upper limit reaches {worst:+.3f}, and pooled over all")
    print(f"  {s['n']} paired artifacts it is {s['hi']:+.4f}. The point estimate is "
          f"{s['delta']:+.4f}.")
    print(f"  The design's minimum detectable effect is {s['mde']:+.4f} pooled")
    print(f"  ({', '.join(f'{x[0]} {x[8]:+.3f}' for x in s['rows'])} per judge), so an")
    print(f"  effect anywhere below that would have been missed more often than not.")
    print()
    print("  Defensible sentence:")
    print(f'    "The volume-matched placement effect at the uncapped partition is')
    print(f'     {s["delta"]:+.3f} [{s["lo"]:+.3f}, {s["hi"]:+.3f}] over {s["n"]} paired '
          f'artifacts. The design has')
    print(f'     80% power only against effects of {s["mde"]:.3f} or larger, so it cannot')
    print(f'     distinguish a small effect from none; what it rules out is an effect of')
    print(f'     the size seen at the content-addressed reader."')

    # ------------------------------------------------------------- the asymmetry
    print("\n" + "=" * 100)
    print("THE ASYMMETRY, IN ONE SENTENCE")
    print("=" * 100)
    big = [x for x in r["rows"] if x[7] < 0.05 / len(r["rows"])]
    print(f"  structural:        n = {s['n']:5d}   delta {s['delta']:+.3f}  "
          f"CI [{s['lo']:+.3f}, {s['hi']:+.3f}]  MDE {s['mde']:.3f}  "
          f"significant judges 0 of {len(s['rows'])}")
    print(f"  content-addressed: n = {r['n']:5d}   delta {r['delta']:+.3f}  "
          f"CI [{r['lo']:+.3f}, {r['hi']:+.3f}]  MDE {r['mde']:.3f}  "
          f"significant judges {len(big)} of {len(r['rows'])} at 0.05/{len(r['rows'])}")
    print()
    print(f"  > The two geometries are not tested with equal power: the structural")
    print(f"  > comparison rests on {s['n']} paired artifacts across {len(s['rows'])} "
          f"judges and has 80%")
    print(f"  > power only against an effect of {s['mde']:.3f} or larger, while the "
          f"content-addressed")
    print(f"  > comparison rests on {r['n']} across {len(r['rows'])} and reaches the same "
          f"power at {r['mde']:.3f}, so")
    print(f"  > the structural null is a statement about {s['n']} artifacts as much as "
          f"about the")
    print(f"  > geometry.")
    print()
    print("  Overlap check, which is what the \"differ severalfold\" claim rests on.")
    print("  How many content-addressed point estimates lie strictly ABOVE the")
    print("  structural upper limit, and so are separated from it:")
    nj = len(r["rows"])
    for lab, lim in (("worst single judge  ", worst), ("pooled over all 332", s["hi"])):
        above = [x for x in r["rows"] if x[4] > lim]
        below = [x for x in r["rows"] if x[4] <= lim]
        print(f"    {lab} {lim:+.3f}:  {len(above)} of {nj} above "
              f"({', '.join(f'{x[0]} {x[4]:+.3f}' for x in above) if above else 'none'})")
        print(f"    {'':20s}          {len(below)} of {nj} covered "
              f"({', '.join(f'{x[0]} {x[4]:+.3f}' for x in below) if below else 'none'})")
    print()
    print("  Section 6.3 currently says the +0.12 limit \"overlaps the two smallest")
    print("  effects at the content-addressed reader (+0.058 and +0.069)\". It covers")
    print(f"  {len([x for x in r['rows'] if x[4] <= worst])} of the {nj}, not two -- the "
          f"four frontier-panel effects added later")
    print("  (+0.024, +0.085, +0.097, +0.097) are all below it as well. Pooling the")
    print(f"  structural arm fixes the sentence instead of weakening it: at {s['hi']:+.3f}")
    print(f"  the separation holds against "
          f"{len([x for x in r['rows'] if x[4] > s['hi']])} of the {nj} rather than three.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
