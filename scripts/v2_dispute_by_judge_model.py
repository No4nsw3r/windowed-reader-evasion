"""Phase 5 side-check - caught-set dispute rate split by which model version judged.

Backs the limitations sentence in paper_v2.tex 4.2: caught-set items were disputed
at 0.020 (3 of 151) under the predecessor judge model against 0.083 (11 of 132)
under the current model alone, and the refusal fallback is a separate, smaller
matter (13 caught-set items had a refused call, 9 of them fell back to a smaller
model, none of those 9 is disputed).

Consensus is built exactly as v2_phase5_audit_score.py builds it: every filled
sheet must agree, an adjudicated verdict overrides, otherwise UNCLEAR.  "Disputed"
is consensus BENIGN against an upstream malicious label, matching that script's
`wrong = nb` for stratum A.  An item counts to the predecessor if ANY of its
judgeA / judgeB / adjudicator calls used that model - dropping the adjudicator
column moves the split to 0.008 against 0.080, so the definition matters.

Reads counts only; no evidence quote, rationale or payload field is printed.

Usage:  python -I scripts/v2_dispute_by_judge_model.py
"""
import os, glob
import pandas as pd

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
AUD = os.path.join(ROOT, "audit")
TRAIL = os.path.join(ROOT, "final", "results", "llm_audit_trail.csv")
OLD, NEW = "claude-opus-4-8", "claude-opus-5-5"
VALID = {"MALICIOUS", "BENIGN", "UNCLEAR"}


def load_sheets():
    out = {}
    for fp in sorted(glob.glob(os.path.join(AUD, "sheets", "sheet_*.csv"))):
        name = os.path.basename(fp).replace("sheet_", "").replace(".csv", "")
        d = pd.read_csv(fp)
        d["verdict"] = d["verdict"].fillna("").astype(str).str.strip().str.upper()
        bad = set(d.verdict) - VALID - {""}
        if bad:
            raise SystemExit(f"{name}: unrecognized verdict(s) {sorted(bad)}")
        d = d[d.verdict != ""]
        if len(d):
            out[name] = d[["item_id", "verdict"]].copy()
    return out


def consensus():
    sheets = load_sheets()
    adj = sheets.pop("adjudicated", None)
    v = None
    for nm, d in sheets.items():
        ser = d.set_index("item_id").verdict.rename(nm)
        v = ser.to_frame() if v is None else v.join(ser, how="outer")
    c = v.apply(lambda r: r.dropna().iloc[0]
                if len(r.dropna()) and r.dropna().nunique() == 1 else "UNCLEAR",
                axis=1).rename("consensus")
    if adj is not None:
        over = adj.set_index("item_id").verdict
        c = c.reindex(c.index.union(over.index))
        c.loc[over.index] = over
        c = c.fillna("UNCLEAR").rename("consensus")
    return c


def main():
    key = pd.read_csv(os.path.join(AUD, "key", "key.csv"), encoding="utf-8-sig")
    j = key.set_index("item_id").join(consensus(), how="inner")

    tr = pd.read_csv(TRAIL, encoding="utf-8-sig")[
        ["item_id", "judgeA_model", "judgeB_model", "adjudicator_model",
         "fallback_models", "refused_calls"]].fillna("")
    A = j[j.stratum == "A"].join(tr.set_index("item_id"), how="left").fillna("")

    nb = int((A.consensus == "BENIGN").sum())
    nu = int((A.consensus == "UNCLEAR").sum())
    print(f"caught set (stratum A): n={len(A)}  disputed={nb}  unclear={nu}  "
          f"share={nb / len(A):.4f}")

    tag = A.judgeA_model + "|" + A.judgeB_model + "|" + A.adjudicator_model
    for label, g in (("predecessor (%s) anywhere" % OLD, A[tag.str.contains(OLD, regex=False)]),
                     ("current (%s) alone" % NEW, A[~tag.str.contains(OLD, regex=False)])):
        k = int((g.consensus == "BENIGN").sum())
        print(f"  {label:<40} n={len(g):>3}  disputed={k:>2}  share={k / len(g):.4f}")

    ref = A[A.refused_calls.str.strip() != ""]
    son = A[A.fallback_models.str.strip() != ""]
    print(f"\nrefusals:          {len(ref)} caught-set items had a refused call, "
          f"{int((ref.consensus == 'BENIGN').sum())} disputed")
    print(f"refusal fallback:  {len(son)} fell back to a smaller model, "
          f"{int((son.consensus == 'BENIGN').sum())} disputed")
    print(f"  overlap with the predecessor group: "
          f"{int(ref.index.isin(A[tag.str.contains(OLD, regex=False)].index).sum())} "
          f"of {len(ref)}  (the refusal story is NOT the version story)")

    print("\nprovenance mix per group (the groups are not randomly assigned):")
    grp = tag.str.contains(OLD, regex=False).map({True: "predecessor", False: "current only"})
    print(pd.crosstab(A.provenance, grp).to_string())


if __name__ == "__main__":
    main()
