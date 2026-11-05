"""v2 Phase 0-2 / 0-3 / 0-4 / 0-5: the statistics the reviewers asked for.

0-2  "delta = 0.000" for d_real vs il_matched is two marginal counts that happen to be
     equal. Equivalence needs a PAIRED test: exact McNemar on the discordant pairs plus
     a TOST-style check that the paired difference CI sits inside a stated margin.
0-3  ASR stratified by provenance and by payload length, inside the caught subset.
0-4  cross-model statements need the INTERSECTION of the two caught sets, because
     gpt-4o and gpt-4o-mini catch different skills.
0-5  family-clustered bootstrap for every paired contrast, since one skill per
     structural family is the sampling unit.

TEXT ONLY, reads the per-item CSVs, no API, no skill text printed.

usage: python -I scripts/v2_stats.py
"""
import os, sys, math, random
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import pilot_audit2 as A
import pandas as pd
import numpy as np

NOTES = os.path.join(A.ROOT, "research_notes", "pilot")
OUTDIR = os.path.join(A.ROOT, "research_notes", "v2_main")
DIL = os.path.join(NOTES, "pilot_dil2_items.csv")
REAL = os.path.join(NOTES, "pilot_realism_items.csv")
OUT = os.path.join(OUTDIR, "v2_stats.md")

B = 5000           # bootstrap resamples
MARGIN = 0.05      # equivalence margin for TOST, pre-stated
RNG = random.Random(20261025)


def wilson(k, n, z=1.96):
    if n == 0:
        return (float("nan"),) * 3
    p = k / n
    d = 1 + z * z / n
    c = (p + z * z / (2 * n)) / d
    h = z * math.sqrt(p * (1 - p) / n + z * z / (4 * n * n)) / d
    return p, max(0.0, c - h), min(1.0, c + h)


def binom_two_sided(b, n):
    """Exact McNemar: P(|X - n/2| >= |b - n/2|) under X ~ Bin(n, 0.5)."""
    if n == 0:
        return float("nan")
    from math import comb
    tgt = abs(b - n / 2)
    tot = 2.0 ** n
    return sum(comb(n, i) for i in range(n + 1) if abs(i - n / 2) >= tgt - 1e-12) / tot


def paired(df, model, cond_a, cond_b, defense, event="SAFE"):
    """Return per-family paired outcomes for two conditions under the same defense."""
    def grab(cond):
        g = df[(df.model == model) & (df.condition == cond) & (df.defense == defense)]
        g = g[g.verdict.isin(["SAFE", "MALICIOUS"])]
        return g.set_index("skill_hash")
    ga, gb = grab(cond_a), grab(cond_b)
    common = ga.index.intersection(gb.index)
    if len(common) == 0:
        return None
    a = (ga.loc[common, "verdict"] == event).astype(int).values
    b = (gb.loc[common, "verdict"] == event).astype(int).values
    fam = ga.loc[common, "structural_family_id"].astype(str).values
    return a, b, fam


def cluster_boot_diff(a, b, fam):
    """Family-clustered bootstrap CI for mean(b) - mean(a)."""
    idx = {}
    for i, f in enumerate(fam):
        idx.setdefault(f, []).append(i)
    fams = list(idx)
    diffs = []
    for _ in range(B):
        pick = []
        for _ in range(len(fams)):
            pick.extend(idx[fams[RNG.randrange(len(fams))]])
        pick = np.array(pick)
        diffs.append(b[pick].mean() - a[pick].mean())
    diffs = np.sort(np.array(diffs))
    return diffs[int(.025 * B)], diffs[int(.975 * B)]


def main():
    df = pd.read_csv(DIL)
    df["skill_hash"] = df["skill_hash"].astype(str)
    L, W = [], None
    W = L.append

    W("# v2 Phase 0-2 / 0-3 / 0-4 / 0-5 — paired statistics\n")
    W(f"Source: `{os.path.basename(DIL)}`. Bootstrap B={B}, clustered on "
      f"`structural_family_id`. Equivalence margin ±{MARGIN:.2f}, pre-stated.\n")

    # ---- 0-2 paired contrasts -------------------------------------------------
    W("\n## 0-2 — paired contrasts (exact McNemar + clustered CI on the difference)\n")
    W("`b01` = flipped only in the first condition, `b10` = only in the second. "
      "McNemar uses the discordant pairs alone. Equivalence holds only when the whole "
      "difference CI lies inside the margin.\n")
    W("| model | defense | contrast | n pairs | ASR a | ASR b | diff | b01 | b10 | McNemar p | diff 95% CI | equivalent at ±0.05 |")
    W("|---|---|---|---|---|---|---|---|---|---|---|---|")

    CONTRASTS = [("d_real", "il_matched"), ("d_real", "il_heavy"),
                 ("il_matched", "il_heavy"), ("d_real", "pa_real")]
    for model in sorted(df.model.unique()):
        for defense in ["none", "big_chunk", "small_chunk", "dedup_small"]:
            for ca, cb in CONTRASTS:
                r = paired(df, model, ca, cb, defense)
                if r is None:
                    continue
                a, b, fam = r
                n = len(a)
                if n < 10:
                    continue
                b01 = int(((a == 1) & (b == 0)).sum())
                b10 = int(((a == 0) & (b == 1)).sum())
                nd = b01 + b10
                p = binom_two_sided(b10, nd) if nd else float("nan")
                lo, hi = cluster_boot_diff(a, b, fam)
                eq = "yes" if (lo > -MARGIN and hi < MARGIN) else "no"
                W(f"| {model} | {defense} | {ca} vs {cb} | {n} | {a.mean():.3f} | "
                  f"{b.mean():.3f} | {b.mean()-a.mean():+.3f} | {b01} | {b10} | "
                  f"{p:.4f} | [{lo:+.3f}, {hi:+.3f}] | {eq} |")

    # ---- 0-4 intersection caught set -----------------------------------------
    W("\n## 0-4 — cross-model comparison on the intersection of caught sets\n")
    base = df[(df.condition == "baseline") & (df.defense == "none")]
    caught = {m: set(g[g.verdict == "MALICIOUS"].skill_hash)
              for m, g in base.groupby("model")}
    models = sorted(caught)
    if len(models) == 2:
        m1, m2 = models
        inter = caught[m1] & caught[m2]
        W(f"- caught by {m1}: {len(caught[m1])}")
        W(f"- caught by {m2}: {len(caught[m2])}")
        W(f"- **intersection: {len(inter)}**  (jaccard "
          f"{len(inter)/max(1,len(caught[m1]|caught[m2])):.3f})\n")
        W("| condition | defense | model | n | SAFE | ASR | 95% CI |")
        W("|---|---|---|---|---|---|---|")
        for cond in ["d_real", "il_matched", "il_heavy", "pa_real"]:
            for defense in ["none", "dedup_small"]:
                for m in models:
                    g = df[(df.model == m) & (df.condition == cond) &
                           (df.defense == defense) & (df.skill_hash.isin(inter))]
                    g = g[g.verdict.isin(["SAFE", "MALICIOUS"])]
                    if len(g) < 5:
                        continue
                    k = int((g.verdict == "SAFE").sum())
                    p, lo, hi = wilson(k, len(g))
                    W(f"| {cond} | {defense} | {m} | {len(g)} | {k} | {p:.3f} | "
                      f"[{lo:.3f}, {hi:.3f}] |")

    # ---- 0-3 stratified by length, and by provenance where joinable ----------
    W("\n## 0-3 — ASR by payload length inside the caught subset\n")
    W("| model | condition | defense | len bucket | n | SAFE | ASR |")
    W("|---|---|---|---|---|---|---|")
    buckets = [(0, 1000), (1000, 2000), (2000, 3001)]
    for model in sorted(df.model.unique()):
        for cond in ["d_real", "il_matched", "il_heavy"]:
            for defense in ["none", "dedup_small"]:
                for lo_, hi_ in buckets:
                    g = df[(df.model == model) & (df.condition == cond) &
                           (df.defense == defense) & (df.len >= lo_) & (df.len < hi_)]
                    g = g[g.verdict.isin(["SAFE", "MALICIOUS"])]
                    if len(g) < 5:
                        continue
                    k = int((g.verdict == "SAFE").sum())
                    W(f"| {model} | {cond} | {defense} | {lo_}-{hi_} | {len(g)} | {k} | "
                      f"{k/len(g):.3f} |")

    W("\n## 0-3b — provenance, joined from the realism CSV\n")
    try:
        rl = pd.read_csv(REAL)
        key = "skill_hash_or_name"
        rl[key] = rl[key].astype(str)
        prov = rl.drop_duplicates(key).set_index(key)["provenance"]
        hit = df.skill_hash.isin(prov.index)
        W(f"- dil2 rows whose hash is present in the realism CSV: "
          f"{int(hit.sum())}/{len(df)} ({hit.mean():.3f})\n")
        if hit.sum() > 50:
            d2 = df[hit].copy()
            d2["provenance"] = d2.skill_hash.map(prov)
            W("| model | condition | defense | provenance | n | SAFE | ASR |")
            W("|---|---|---|---|---|---|---|")
            for model in sorted(d2.model.unique()):
                for cond in ["d_real", "il_matched", "il_heavy"]:
                    for defense in ["none", "dedup_small"]:
                        for pv, g in d2[(d2.model == model) & (d2.condition == cond) &
                                        (d2.defense == defense)].groupby("provenance"):
                            g = g[g.verdict.isin(["SAFE", "MALICIOUS"])]
                            if len(g) < 5:
                                continue
                            k = int((g.verdict == "SAFE").sum())
                            W(f"| {model} | {cond} | {defense} | {pv} | {len(g)} | {k} | "
                              f"{k/len(g):.3f} |")
        else:
            W("Too few hashes join across the two CSVs to stratify by provenance. "
              "The realism pool keys on a hash-or-name field and was drawn separately, "
              "so provenance must be re-attached at the source parquet instead.\n")
    except Exception as e:
        W(f"join failed: {type(e).__name__}: {e}\n")

    # ---- ERR accounting -------------------------------------------------------
    W("\n## ERR accounting\n")
    bad = df[~df.verdict.isin(["SAFE", "MALICIOUS"])]
    W(f"- non-verdict rows: {len(bad)}/{len(df)} ({len(bad)/len(df):.4f})")
    if len(bad):
        W("- by value: " + ", ".join(f"`{k}`×{v}" for k, v in
                                     bad.verdict.value_counts().items()))

    os.makedirs(OUTDIR, exist_ok=True)
    open(OUT, "w", encoding="utf-8").write("\n".join(L) + "\n")
    print("wrote", OUT)

    r = paired(df, "gpt-4o-mini", "d_real", "il_matched", "dedup_small")
    if r:
        a, b, fam = r
        b01 = int(((a == 1) & (b == 0)).sum()); b10 = int(((a == 0) & (b == 1)).sum())
        lo, hi = cluster_boot_diff(a, b, fam)
        print(f"KEY (mini, dedup_small, d_real vs il_matched): n={len(a)} "
              f"ASR {a.mean():.3f} vs {b.mean():.3f} | discordant {b01}/{b10} | "
              f"diff CI [{lo:+.3f}, {hi:+.3f}] | equivalent at ±{MARGIN}: "
              f"{'yes' if (lo > -MARGIN and hi < MARGIN) else 'NO'}")


if __name__ == "__main__":
    main()
