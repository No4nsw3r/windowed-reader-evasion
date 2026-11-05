"""Build the blinded HUMAN audit packet for the 631 unattacked joint-miss set.

Why this packet exists
----------------------
paper_v2.tex reports that an LLM judge and a deployed static scanner, with no attack
applied to anything, jointly miss 631 of 1124 malicious skills (56%), and that their
errors are positively correlated (Fisher exact p = 9e-22).  That 56% is the paper's
strongest unprecedented result and the floor its attacks start from.

Its weakness is that all 631 labels are inherited from the upstream benchmark.  The only
audit of never-caught items so far covered 60 of them, was performed by LLM pipelines,
and disputed 29/60 (48%).  So the floor could sit anywhere between roughly 29% and 56%
depending on how many of the 631 are mislabeled -- and because the auditor and the
audited were both LLMs, the existing audit cannot settle it.

A HUMAN audit of a random sample of the 631 settles it.  That is the only thing in this
paper no model can do, because the circularity objection is precisely that a model did it.

Design
------
  J  120  random sample of the 631 joint-miss skills   <- the estimand
  P   15  caught-set items the prior audit called MALICIOUS at confidence 3  (positive control)
  N   15  benign-corpus skills no judge ever flagged                         (negative control)

The 30 controls do not enter the estimate.  They measure the auditor, not the corpus:
if P items come back BENIGN the threshold is too narrow, if N items come back MALICIOUS
it is too broad, and either way J has to be discounted by the same amount.

Items are renumbered, shuffled, and stripped of stratum, provenance, upstream attack
category, and every detector verdict.  All of that lives in key/key.csv, which must stay
shut until the last row is judged.

The 631 is reproduced with the exact dedup and filter that scripts/v2_layering.py uses
for the published number: drop_duplicates(["skill_hash","arm"], keep="first"), then keep
only rows where all three detectors returned SAFE or MALICIOUS.

usage:  python -I scripts/v3_jointmiss_audit_pack.py
"""
import csv
import os
import random
import sys

import pandas as pd

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
sys.path.insert(0, HERE)
import pilot_dil2 as D  # noqa: E402  (authoritative pool + hash function)

NOTES = os.path.join(ROOT, "research_notes", "v2_main")
LAYER_FP = os.path.join(NOTES, "v2_layering_items.csv")
PRIMARY = os.path.join(ROOT, "data", "malicious_skill_bench", "primary.parquet")
OLD_AUDIT = os.path.join(ROOT, "audit")
OUT = os.path.join(ROOT, "audit_jointmiss")

GOOD = ("SAFE", "MALICIOUS")
SEED = 631
N_J, N_P, N_N = 120, 15, 15
TIER1 = {"J": 60, "P": 8, "N": 7}

SHEET_COLS = ["item_id", "file", "chars", "tier",
              "verdict", "confidence", "evidence_quote", "attack_type", "notes"]


def joint_miss():
    """The 631, reproduced exactly as scripts/v2_layering.py computes the published row."""
    d = pd.read_csv(LAYER_FP)
    d["llm"] = d.llm.astype(str)
    d["skill_hash"] = d.skill_hash.astype(str)
    d = d.drop_duplicates(subset=["skill_hash", "arm"], keep="first")
    g = d[(d.arm == "mal") & d.llm.isin(GOOD)
          & d.cisco.isin(GOOD) & d.skillfrisk.isin(GOOD)]
    jm = g[(g.llm != "MALICIOUS") & (g.cisco != "MALICIOUS")]
    print(f"malicious pool after dedup+filter: {len(g)}   (paper: 1124)")
    print(f"judge AND cisco both miss:         {len(jm)}   (paper: 631)")
    if len(g) != 1124 or len(jm) != 631:
        raise SystemExit("pool/joint-miss count does not reproduce the paper; stop and "
                         "find out why before building a packet on it")
    return jm


def s(v):
    """Stringify a parquet cell that may be None, NaN, or a numpy array of categories."""
    if v is None:
        return ""
    if hasattr(v, "tolist"):
        v = v.tolist()
    if isinstance(v, (list, tuple)):
        return ";".join(str(x) for x in v)
    v = str(v)
    return "" if v.lower() in ("nan", "none", "<na>") else v


def pool_metadata():
    """hash -> (text, benchmark_id, provenance, source_name, attack_categories, family)."""
    cand = D.load_candidates()
    extra = pd.read_parquet(PRIMARY, columns=[
        "normalized_hash", "benchmark_id", "provenance", "source_name",
        "attack_categories"]).drop_duplicates(subset=["normalized_hash"])
    cand = cand.merge(extra, on="normalized_hash", how="left")
    out = {}
    for r in cand.itertuples(index=False):
        t = str(r.skill_text)
        out[D.skill_hash(t)] = dict(
            text=t,
            benchmark_id=s(getattr(r, "benchmark_id", None)),
            provenance=s(getattr(r, "provenance", None)),
            source_name=s(getattr(r, "source_name", None)),
            attack_categories=s(getattr(r, "attack_categories", None)),
            family=s(getattr(r, "structural_family_id", None)))
    print(f"pool metadata built for {len(out)} skills")
    return out


def controls():
    """Positive and negative control items, taken from the prior audit packet on disk."""
    k = pd.read_csv(os.path.join(OLD_AUDIT, "key", "key.csv"))
    a = pd.read_csv(os.path.join(OLD_AUDIT, "sheets", "sheet_annot1.csv"))
    m = k.merge(a[["item_id", "verdict", "confidence"]], on="item_id", how="left")
    m["confidence"] = m.confidence.astype(str)
    pos = m[(m.stratum == "A") & (m.verdict == "MALICIOUS") & (m.confidence == "3")]
    neg = m[(m.stratum == "D") & (m.verdict == "BENIGN")]
    print(f"control candidates: positive {len(pos)}, negative {len(neg)}")
    return pos, neg


def read_old_item(item_id):
    fp = os.path.join(OLD_AUDIT, "items", f"{item_id}.md")
    with open(fp, encoding="utf-8") as f:
        return f.read()


def main():
    rng = random.Random(SEED)
    os.makedirs(os.path.join(OUT, "items"), exist_ok=True)
    os.makedirs(os.path.join(OUT, "key"), exist_ok=True)

    jm = joint_miss()
    meta = pool_metadata()
    pos, neg = controls()

    # ---- which of the 631 the prior LLM audit already saw (stratum C overlap) -----
    k = pd.read_csv(os.path.join(OLD_AUDIT, "key", "key.csv"))
    a = pd.read_csv(os.path.join(OLD_AUDIT, "sheets", "sheet_annot1.csv"))
    prior = k.merge(a[["item_id", "verdict"]], on="item_id", how="left")
    prior["skill_hash"] = prior.skill_hash.astype(str)
    prior_by_hash = {r.skill_hash: (r.item_id, str(r.verdict))
                     for r in prior.itertuples(index=False)}
    jm_hashes = list(jm.skill_hash)
    overlap_all = [h for h in jm_hashes if h in prior_by_hash]
    print(f"of the 631, the prior LLM audit already judged {len(overlap_all)}")

    # ---- sample ------------------------------------------------------------------
    missing = [h for h in jm_hashes if h not in meta]
    if missing:
        raise SystemExit(f"{len(missing)} joint-miss hashes have no text in the pool; "
                         f"first = {missing[0]}")
    pick_j = rng.sample(sorted(jm_hashes), N_J)
    pick_p = rng.sample(sorted(pos.item_id), N_P)
    pick_n = rng.sample(sorted(neg.item_id), N_N)

    recs = []
    for h in pick_j:
        m = meta[h]
        recs.append(dict(stratum="J", text=m["text"], skill_hash=h,
                         benchmark_id=m["benchmark_id"], provenance=m["provenance"],
                         source_name=m["source_name"],
                         attack_categories=m["attack_categories"], family=m["family"],
                         prior_item=prior_by_hash.get(h, ("", ""))[0],
                         prior_verdict=prior_by_hash.get(h, ("", ""))[1]))
    for st, picks in (("P", pick_p), ("N", pick_n)):
        src = pos if st == "P" else neg
        src = src.set_index("item_id")
        for iid in picks:
            r = src.loc[iid]
            recs.append(dict(stratum=st, text=read_old_item(iid),
                             skill_hash=s(r.get("skill_hash")),
                             benchmark_id=s(r.get("benchmark_id")),
                             provenance=s(r.get("provenance")),
                             source_name=s(r.get("source_name")),
                             attack_categories="", family=s(r.get("family")),
                             prior_item=iid, prior_verdict=s(r.get("verdict"))))

    # ---- tier, shuffle, renumber -------------------------------------------------
    by_stratum = {}
    for r in recs:
        by_stratum.setdefault(r["stratum"], []).append(r)
    for st in by_stratum:
        rng.shuffle(by_stratum[st])
        for i, r in enumerate(by_stratum[st]):
            r["tier"] = 1 if i < TIER1[st] else 2

    t1 = [r for r in recs if r["tier"] == 1]
    t2 = [r for r in recs if r["tier"] == 2]
    rng.shuffle(t1)
    rng.shuffle(t2)
    ordered = t1 + t2
    for i, r in enumerate(ordered, 1):
        r["item_id"] = f"J{i:03d}"

    # ---- write -------------------------------------------------------------------
    for r in ordered:
        with open(os.path.join(OUT, "items", f"{r['item_id']}.md"),
                  "w", encoding="utf-8") as f:
            f.write(r["text"])

    with open(os.path.join(OUT, "sheet.csv"), "w", newline="",
              encoding="utf-8-sig") as f:
        w = csv.writer(f)
        w.writerow(SHEET_COLS)
        for r in ordered:
            w.writerow([r["item_id"], f"items/{r['item_id']}.md",
                        len(r["text"]), r["tier"], "", "", "", "", ""])

    kcols = ["item_id", "tier", "stratum", "chars", "skill_hash", "benchmark_id",
             "provenance", "source_name", "attack_categories", "family",
             "prior_item", "prior_verdict"]
    with open(os.path.join(OUT, "key", "key.csv"), "w", newline="",
              encoding="utf-8-sig") as f:
        w = csv.DictWriter(f, fieldnames=kcols, extrasaction="ignore")
        w.writeheader()
        for r in ordered:
            w.writerow(dict(r, chars=len(r["text"])))

    # ---- report ------------------------------------------------------------------
    n_over = sum(1 for r in ordered if r["stratum"] == "J" and r["prior_item"])
    n_cat = sum(1 for r in ordered
                if r["stratum"] == "J" and r["attack_categories"].strip()
                not in ("", "[]", "nan", "None"))
    print(f"\nwrote {len(ordered)} items to {os.path.join(OUT, 'items')}")
    print(f"  J {N_J}  P {N_P}  N {N_N}")
    print(f"  tier 1: {len(t1)} rows   tier 2: {len(t2)} rows")
    print(f"  of the 120 J items, {n_over} were also judged by the prior LLM audit "
          f"(human-vs-LLM agreement is computable on those)")
    print(f"  of the 120 J items, {n_cat} carry an upstream attack category and "
          f"{N_J - n_cat} do not (post-stratification axis)")
    print(f"\nsheet: {os.path.join(OUT, 'sheet.csv')}")
    print(f"key:   {os.path.join(OUT, 'key', 'key.csv')}  <- do not open until done")


if __name__ == "__main__":
    main()
