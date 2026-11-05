"""Phase 5 - build the blinded label-audit packet.

Writes one text file per item under audit/items/, a blinded annotation sheet per
annotator, and a separate unblinding key.  The item text is written to disk and is
never printed, so nothing malicious enters a transcript.

Strata (all mixed and shuffled into one blinded pool):
  A  caught set union across every judge             upstream label = malicious
  B  benign-corpus skills flagged by >= 1 judge       upstream label = benign
  C  low-recall provenance items no judge flagged     upstream label = malicious
  D  benign-corpus skills no judge flagged (control)  upstream label = benign

Usage:  python -I scripts/v2_phase5_audit_pack.py
"""
import os, sys, glob, hashlib, csv, random
import pandas as pd

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
NOTES = os.path.join(ROOT, "research_notes", "v2_main")
BENCH = os.path.join(ROOT, "data", "malicious_skill_bench", "primary.parquet")
BENIGN = os.path.join(ROOT, "data", "skillmd_138k", "train.parquet")
REALISM = os.path.join(ROOT, "research_notes", "pilot", "pilot_realism_items.csv")
OUT = os.path.join(ROOT, "audit")
SEED = 11
N_C, N_D = 60, 30
TIER1_A = 40          # how many A items land in tier 1
TIER1_D = 15          # how many benign controls land in tier 1
N_OVERLAP = 100       # reliability subsample the second annotator scores

def h(s):
    return hashlib.md5(s.encode("utf-8", "replace")).hexdigest()

def verdict_tables():
    """caught hashes, flagged-benign hashes, and who caught/flagged each."""
    caught, flagged = {}, {}
    files = [os.path.join(NOTES, "v2_phase1_items.csv")] + \
            sorted(glob.glob(os.path.join(NOTES, "v2_phase3_items_*.csv")))
    for fp in files:
        d = pd.read_csv(fp)
        for _, r in d[d.arm == "mal"].iterrows():
            caught.setdefault(str(r.skill_hash), set()).add(str(r.model))
        for _, r in d[(d.arm == "ben") & (d.verdict == "MALICIOUS")].iterrows():
            flagged.setdefault(str(r.skill_hash), set()).add(str(r.model))
    return caught, flagged

def main():
    rng = random.Random(SEED)
    os.makedirs(os.path.join(OUT, "items"), exist_ok=True)
    os.makedirs(os.path.join(OUT, "sheets"), exist_ok=True)
    os.makedirs(os.path.join(OUT, "key"), exist_ok=True)

    caught, flagged = verdict_tables()
    print(f"caught union {len(caught)}  flagged-benign union {len(flagged)}")

    # ---- malicious side -------------------------------------------------
    p = pd.read_parquet(BENCH, columns=["benchmark_id", "label", "skill_text",
        "text_available", "text_redacted", "structural_family_id",
        "normalized_hash", "provenance", "source_name", "evidence_type",
        "attack_categories"])
    p["skill_text"] = p["skill_text"].fillna("")
    by_hash = {}
    for r in p.itertuples(index=False):
        if r.skill_text:
            by_hash.setdefault(h(r.skill_text), r)

    rows = []           # (stratum, hash, text, meta dict)
    miss = 0
    for hh in sorted(caught):
        r = by_hash.get(hh)
        if r is None:
            miss += 1; continue
        rows.append(("A", hh, r.skill_text, dict(upstream="malicious",
            benchmark_id=r.benchmark_id, provenance=r.provenance,
            source_name=r.source_name, evidence_type=r.evidence_type,
            family=r.structural_family_id, judges=";".join(sorted(caught[hh]))))) 
    print(f"A: {len(rows)} resolved, {miss} unresolved")

    # C: low-recall provenance, never flagged by either OpenAI judge
    rl = pd.read_csv(REALISM)
    safe = rl[(rl.verdict != "MALICIOUS") &
              (rl.provenance.isin(["backdoored", "injected"]))]
    ids = list(dict.fromkeys(safe.benchmark_id.astype(str)))
    rng.shuffle(ids)
    bid = {str(r.benchmark_id): r for r in p.itertuples(index=False)}
    nC = 0
    for b in ids:
        if nC >= N_C: break
        r = bid.get(b)
        if r is None or not r.skill_text: continue
        hh = h(r.skill_text)
        if any(x[1] == hh for x in rows): continue
        rows.append(("C", hh, r.skill_text, dict(upstream="malicious",
            benchmark_id=r.benchmark_id, provenance=r.provenance,
            source_name=r.source_name, evidence_type=r.evidence_type,
            family=r.structural_family_id, judges="")))
        nC += 1
    print(f"C: {nC}")

    # ---- benign side ----------------------------------------------------
    bn = pd.read_parquet(BENIGN, columns=["content"])["content"].dropna().astype(str)
    want = set(flagged)
    got, unflagged = {}, []
    for t in bn:
        hh = h(t)
        if hh in want and hh not in got:
            got[hh] = t
        elif len(unflagged) < 4000:
            unflagged.append((hh, t))
    print(f"B: {len(got)}/{len(want)} benign flagged texts resolved")
    for hh, t in got.items():
        rows.append(("B", hh, t, dict(upstream="benign", benchmark_id="",
            provenance="skillmd_138k", source_name="skillmd_138k",
            evidence_type="", family="", judges=";".join(sorted(flagged[hh])))))
    rng.shuffle(unflagged)
    for hh, t in unflagged[:N_D]:
        rows.append(("D", hh, t, dict(upstream="benign", benchmark_id="",
            provenance="skillmd_138k", source_name="skillmd_138k",
            evidence_type="", family="", judges="")))

    # ---- blind, shuffle, write -----------------------------------------
    rng.shuffle(rows)
    seen = {"A": 0, "D": 0}
    recs = []
    for i, (st, hh, text, meta) in enumerate(rows, 1):
        iid = f"S{i:04d}"
        fn = f"{iid}.md"
        with open(os.path.join(OUT, "items", fn), "w", encoding="utf-8") as f:
            f.write(text)
        if st == "B":
            t1 = True
        elif st == "A":
            t1 = seen["A"] < TIER1_A; seen["A"] += 1
        elif st == "D":
            t1 = seen["D"] < TIER1_D; seen["D"] += 1
        else:
            t1 = False
        recs.append(dict(item_id=iid, file=f"items/{fn}", chars=len(text),
                         tier=1 if t1 else 2, stratum=st, skill_hash=hh, **meta))

    # reliability subsample: stratified, drawn from tier 1 first
    pool = sorted(recs, key=lambda r: (r["tier"], r["item_id"]))
    per = {}
    overlap = []
    quota = {"A": 50, "B": 25, "C": 15, "D": 10}
    for r in pool:
        st = r["stratum"]
        if per.get(st, 0) < quota.get(st, 0) and len(overlap) < N_OVERLAP:
            overlap.append(r["item_id"]); per[st] = per.get(st, 0) + 1
    ov = set(overlap)
    for r in recs:
        r["overlap"] = 1 if r["item_id"] in ov else 0

    recs.sort(key=lambda r: (r["tier"], r["item_id"]))
    head = ["item_id", "file", "chars", "tier", "verdict", "confidence",
            "evidence_quote", "attack_type", "notes"]
    for ann, rs in (("annot1", recs),
                    ("annot2", [r for r in recs if r["overlap"]])):
        fp = os.path.join(OUT, "sheets", f"sheet_{ann}.csv")
        with open(fp, "w", newline="", encoding="utf-8-sig") as f:
            w = csv.writer(f)
            w.writerow(head)
            for r in rs:
                w.writerow([r["item_id"], r["file"], r["chars"], r["tier"],
                            "", "", "", "", ""])
    with open(os.path.join(OUT, "key", "key.csv"), "w", newline="",
              encoding="utf-8-sig") as f:
        cols = ["item_id", "stratum", "upstream", "skill_hash", "benchmark_id",
                "provenance", "source_name", "evidence_type", "family", "judges",
                "chars", "tier", "overlap"]
        w = csv.DictWriter(f, fieldnames=cols, extrasaction="ignore")
        w.writeheader()
        for r in recs: w.writerow(r)

    df = pd.DataFrame(recs)
    print(df.groupby(["tier", "stratum"]).agg(n=("item_id", "size"),
          chars=("chars", "sum")).to_string())
    print(f"overlap subsample: {int(df.overlap.sum())} items, "
          f"{int(df[df.overlap == 1].chars.sum()):,} chars")
    print(f"tier 1: {int((df.tier == 1).sum())} items, "
          f"{int(df[df.tier == 1].chars.sum()):,} chars")
    print(f"\nwrote {len(recs)} items to {os.path.join(OUT, 'items')}")

if __name__ == "__main__":
    main()
