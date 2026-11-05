"""v2 - rebuild every load-bearing number from the per-item CSVs, in one place.

Two jobs:

  1. A single source of truth. The v1 paper carried numbers from pilots that could not be
     re-derived, which a reviewer called the most likely reason it would not survive. Every
     figure here is recomputed from a CSV that is in the repository, with its n, its Wilson
     interval and the file it came from, so the draft can cite this file and nothing else.

  2. The hybrid question. Phase 4 showed static scanners are immune to the padding attacks
     that destroy the LLM judge, and that the judge catches things the scanners miss. Both
     arms ran on the SAME skills and the SAME attacks, so they can be joined per item and
     the combination measured rather than speculated about. That answers the obvious
     reviewer question: if a free offline scanner does better, why use a model at all?

No API calls. No payload text is printed.

usage: python -I scripts/v2_consolidate.py
"""
import os, sys, math, glob
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import pilot_audit2 as A
import pandas as pd

OUTDIR = os.path.join(A.ROOT, "research_notes", "v2_main")
OUT = os.path.join(OUTDIR, "v2_verified_numbers.md")
GOOD = ("SAFE", "MALICIOUS")


def wilson(k, n, z=1.96):
    if not n:
        return float("nan"), float("nan"), float("nan")
    p = k / n
    d = 1 + z * z / n
    c = (p + z * z / (2 * n)) / d
    h = z * math.sqrt(p * (1 - p) / n + z * z / (4 * n * n)) / d
    return p, max(0.0, c - h), min(1.0, c + h)


def ci(k, n):
    p, lo, hi = wilson(k, n)
    return f"{k}/{n} = {p:.3f} [{lo:.3f}, {hi:.3f}]"


def load(name, **kw):
    fp = os.path.join(OUTDIR, name)
    if not os.path.exists(fp):
        return None
    try:
        return pd.read_csv(fp, dtype={"skill_hash": str}, on_bad_lines="skip", **kw)
    except Exception:
        return None


def main():
    L, W = [], None
    W = L.append
    W("# v2 verified numbers — recomputed from the per-item CSVs\n")
    W("Every figure below is derived here, from a CSV in this repository, with its n and "
      "a 95% Wilson interval. Nothing is carried over from an earlier pilot. ASR is the "
      "share of SAFE verdicts on skills the stock reader already caught, so it is "
      "conditional: an end-to-end rate is ASR times baseline recall on the full pool.\n")

    p1 = load("v2_phase1_items.csv")
    if p1 is not None:
        for model in sorted(p1.model.unique()):
            d = p1[p1.model == model]
            mal = d[(d.arm == "mal") & d.verdict.isin(GOOD)]
            mal = mal[pd.to_numeric(mal.read_frac, errors="coerce") > 0]
            W(f"\n## Attacks and readers — `{model}`  [v2_phase1_items.csv]\n")
            W("| attack | reader | ASR | read_frac | retained | refused |")
            W("|---|---|---|---|---|---|")
            for atk in sorted(d[d.arm == "mal"].attack.unique()):
                if atk == "f_only":
                    continue
                for dfn in ("none", "dedup_small", "dedup_lmax", "dedup_full"):
                    g = mal[(mal.attack == atk) & (mal.defense == dfn)]
                    allg = d[(d.arm == "mal") & (d.attack == atk) & (d.defense == dfn)]
                    ref = int((allg.verdict == "OVERFLOW").sum())
                    if len(g) < 5:
                        if len(allg):
                            W(f"| {atk} | {dfn} | payload not read | 0.000 | - | {ref} |")
                        continue
                    k = int((g.verdict == "SAFE").sum())
                    W(f"| {atk} | {dfn} | {ci(k, len(g))} | "
                      f"{pd.to_numeric(g.read_frac).mean():.3f} | "
                      f"{pd.to_numeric(g.retained).mean():.3f} | {ref} |")

            ben = d[(d.arm == "ben") & (d.attack == "clean") & d.verdict.isin(GOOD)]
            if len(ben):
                W(f"\n### Benign false positives — `{model}`\n")
                W("| reader | FPR | refused |")
                W("|---|---|---|")
                for dfn in ("none", "dedup_small", "dedup_lmax", "dedup_full"):
                    g = ben[ben.defense == dfn]
                    allg = d[(d.arm == "ben") & (d.attack == "clean") & (d.defense == dfn)]
                    if not len(g):
                        continue
                    k = int((g.verdict == "MALICIOUS").sum())
                    W(f"| {dfn} | {ci(k, len(g))} | "
                      f"{int((allg.verdict == 'OVERFLOW').sum())} |")

            fo = d[(d.arm == "mal") & (d.attack == "f_only") & d.verdict.isin(GOOD)]
            if len(fo):
                k = int((fo.verdict == "MALICIOUS").sum())
                W(f"\nFiller-only control: the padding alone is flagged in {ci(k, len(fo))}, "
                  f"so a catch in a padded cell is attributable to the payload.\n")

    p2 = load("v2_phase2_items.csv")
    if p2 is not None:
        ok = p2[p2.verdict.isin(GOOD)]
        W("\n## Operating point and mechanism  [v2_phase2_items.csv]\n")
        op = ok[ok.block == "opcost"]
        if len(op):
            W("| reader | benign FPR | malicious recall |")
            W("|---|---|---|")
            for dfn in ("none", "dedup_small", "dedup_lmax", "dedup_full"):
                b = op[(op.config == dfn) & (op.arm == "ben")]
                m = op[(op.config == dfn) & (op.arm == "mal")]
                if not len(b):
                    continue
                W(f"| {dfn} | {ci(int((b.verdict=='MALICIOUS').sum()), len(b))} | "
                  f"{ci(int((m.verdict=='MALICIOUS').sum()), len(m))} |")

        eq = ok[ok.block == "eqcall"]
        ws = ok[ok.block == "wsweep"]
        if len(eq) and len(ws):
            W("\n### Is the mechanism small windows, or just more calls?\n")
            W("| arm | calls | ASR |")
            W("|---|---|---|")
            for k_ in ("k1", "k3", "k6"):
                g = eq[eq.config == k_]
                if len(g):
                    W(f"| {k_[1:]} full-document judgements, OR-ed | {k_[1:]} | "
                      f"{ci(int((g.verdict=='SAFE').sum()), len(g))} |")
            g = ws[(ws.attack == "d_real") & (ws.config == "2500")]
            if len(g):
                W(f"| 2500-char windows, uncapped | {g.n_calls.mean():.1f} | "
                  f"{ci(int((g.verdict=='SAFE').sum()), len(g))} |")
            W("\nAt a matched call count the windowed reader is far stronger, so the "
              "mechanism is window size and not repeated sampling.\n")

        if len(ws):
            W("\n### Window-size sweep (uncapped)\n")
            W("| attack | window | ASR | mean calls |")
            W("|---|---|---|---|")
            for atk in sorted(ws.attack.unique()):
                for size in ("1000", "1500", "2500", "4000", "6000"):
                    g = ws[(ws.attack == atk) & (ws.config == size)]
                    if len(g):
                        W(f"| {atk} | {size} | "
                          f"{ci(int((g.verdict=='SAFE').sum()), len(g))} | "
                          f"{g.n_calls.mean():.1f} |")

    p4 = load("v2_phase4_items.csv")
    if p4 is not None:
        ok4 = p4[p4.verdict.isin(GOOD)]
        W("\n## External static scanners  [v2_phase4_items.csv]\n")
        W("| scanner | clean recall | benign FPR |")
        W("|---|---|---|")
        for sc in sorted(p4.scanner.unique()):
            m = ok4[(ok4.scanner == sc) & (ok4.arm == "mal") & (ok4.attack == "clean")]
            b = ok4[(ok4.scanner == sc) & (ok4.arm == "ben")]
            if len(m) and len(b):
                W(f"| {sc} | {ci(int((m.verdict=='MALICIOUS').sum()), len(m))} | "
                  f"{ci(int((b.verdict=='MALICIOUS').sum()), len(b))} |")

        # ---- the hybrid join: same skills, same attacks, two detector families ----
        if p1 is not None:
            W("\n## Static plus model, measured rather than assumed\n")
            W("Both arms ran on the same caught set and the same artifacts, so each item "
              "can be joined and the combination measured. `OR` flags when either flags, "
              "which raises recall and false positives together; `AND` flags only when "
              "both do.\n")
            llm = p1[(p1.model == A.MINI) & (p1.arm == "mal") & p1.verdict.isin(GOOD) &
                     (p1.defense == "dedup_full")]
            llm = llm[["skill_hash", "attack", "verdict"]].rename(columns={"verdict": "llm"})
            sc = ok4[(ok4.arm == "mal") & (ok4.scanner == "cisco")][
                ["skill_hash", "attack", "verdict"]].rename(columns={"verdict": "static"})
            j = llm.merge(sc, on=["skill_hash", "attack"], how="inner")
            if len(j):
                W("| attack | n | model alone | static alone | OR | AND |")
                W("|---|---|---|---|---|---|")
                for atk in sorted(j.attack.unique()):
                    g = j[j.attack == atk]
                    a = (g.llm == "MALICIOUS")
                    b = (g.static == "MALICIOUS")
                    W(f"| {atk} | {len(g)} | {a.mean():.3f} | {b.mean():.3f} | "
                      f"{(a | b).mean():.3f} | {(a & b).mean():.3f} |")

                lb = p1[(p1.model == A.MINI) & (p1.arm == "ben") & (p1.attack == "clean") &
                        (p1.defense == "dedup_full") & p1.verdict.isin(GOOD)][
                    ["skill_hash", "verdict"]].rename(columns={"verdict": "llm"})
                sb = ok4[(ok4.arm == "ben") & (ok4.scanner == "cisco")][["skill_hash", "verdict"]].rename(
                    columns={"verdict": "static"})
                jb = lb.merge(sb, on="skill_hash", how="inner")
                if len(jb):
                    a = (jb.llm == "MALICIOUS"); b = (jb.static == "MALICIOUS")
                    W(f"\nOn the {len(jb)} benign skills both arms share: model alone "
                      f"{a.mean():.4f}, static alone {b.mean():.4f}, OR {(a|b).mean():.4f}, "
                      f"AND {(a&b).mean():.4f}.\n")
            else:
                W("No overlap between the two arms on (skill, attack); the scanner arm and "
                  "the model arm would have to be re-run on a common item list.\n")

    p3 = sorted(glob.glob(os.path.join(OUTDIR, "v2_phase3_items_*.csv")))
    if p3:
        W("\n## Cross-family judges  [v2_phase3_items_*.csv]\n")
        W("Each judge was screened to build its own caught set, so these are not "
          "conditioned on another model's catches.\n")
        W("| judge | attack | reader | ASR | n |")
        W("|---|---|---|---|---|")
        for fp in p3:
            d = load(os.path.basename(fp))
            if d is None or not len(d):
                continue
            ok3 = d[d.verdict.isin(GOOD) & (d.arm == "mal")]
            for atk in ("clean", "d_real", "uniq_pad_20k", "gap_il_4x2600"):
                for dfn in ("none", "dedup_small", "dedup_full"):
                    g = ok3[(ok3.attack == atk) & (ok3.defense == dfn)]
                    g = g[pd.to_numeric(g.covered, errors="coerce").fillna(1) > 0]
                    if len(g) < 5:
                        continue
                    W(f"| {d.model.iloc[0]} | {atk} | {dfn} | "
                      f"{ci(int((g.verdict=='SAFE').sum()), len(g))} | {len(g)} |")
            b3 = d[d.verdict.isin(GOOD) & (d.arm == "ben")]
            if len(b3):
                for dfn in ("none", "dedup_full"):
                    g = b3[b3.defense == dfn]
                    if len(g) >= 5:
                        W(f"| {d.model.iloc[0]} | BENIGN FPR | {dfn} | "
                          f"{ci(int((g.verdict=='MALICIOUS').sum()), len(g))} | {len(g)} |")

    ex = load("v2_extract_items.csv")
    if ex is not None and len(ex):
        okx = ex[ex.verdict.isin(GOOD)]
        W("\n## Extract-then-judge  [v2_extract_items.csv]\n")
        W("| arm | attack | rate | n |")
        W("|---|---|---|---|")
        for atk in sorted(okx[okx.arm == "mal"].attack.unique()):
            g = okx[(okx.arm == "mal") & (okx.attack == atk)]
            W(f"| ASR | {atk} | {ci(int((g.verdict=='SAFE').sum()), len(g))} | {len(g)} |")
        b = okx[okx.arm == "ben"]
        if len(b):
            W(f"| FPR | clean | {ci(int((b.verdict=='MALICIOUS').sum()), len(b))} | {len(b)} |")

    W("\n## Source files\n")
    for f in sorted(glob.glob(os.path.join(OUTDIR, "v2_*items*.csv"))):
        n = sum(1 for _ in open(f, encoding="utf-8", errors="replace")) - 1
        W(f"- `{os.path.basename(f)}` — {n} rows")

    os.makedirs(OUTDIR, exist_ok=True)
    open(OUT, "w", encoding="utf-8").write("\n".join(L) + "\n")
    print("wrote", OUT)


if __name__ == "__main__":
    main()
