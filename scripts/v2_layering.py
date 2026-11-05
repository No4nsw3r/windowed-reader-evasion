"""Measure what layering an LLM judge with a static scanner is actually worth, on a pool
that is NOT conditioned on the judge's own catches.

The reported layering numbers were computed on gpt-4o-mini's caught set, so skills the
scanner catches and the judge misses were excluded by construction and the disjunction
gain could only be a lower bound (reviewer finding §4.6). This runs both families over the
whole one-per-family candidate pool (1124 malicious) and the benign set the scanners
already cover, so recall, FPR and the disjunction are measured rather than bounded.

Scanner verdicts already produced by Phase 4 are reused; only the skills Phase 4 never saw
are scanned. Judge verdicts are a single raw read, the `none` reader.

usage: python -I scripts/v2_layering.py [max_usd]
"""
import csv
import hashlib
import os
import shutil
import sys
import tempfile
import threading
import time
from concurrent.futures import ThreadPoolExecutor

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import pandas as pd
import pilot_audit2 as A
import pilot_dil2 as D
import v2_phase4_scanners as P4

OUTDIR = os.path.join(A.ROOT, "research_notes", "v2_main")
ROWS_FP = os.path.join(OUTDIR, "v2_layering_items.csv")
OUT = os.path.join(OUTDIR, "v2_layering.md")
P4_FP = os.path.join(OUTDIR, "v2_phase4_items.csv")
MODEL = A.MINI
FIELDS = ["skill_hash", "arm", "source", "llm", "cisco", "skillfrisk"]
GOOD = ("SAFE", "MALICIOUS")
WORKERS = 6

_lock = threading.Lock()
_usage_guard = threading.Lock()


def spend():
    r = A.RATES[MODEL]
    u = A._usage.get(MODEL, {"in": 0, "out": 0})
    return (u["in"] * r[0] + u["out"] * r[1]) / 1e6


def scan_both(text):
    """Run both scanners on one skill in a scratch directory. Static analysis only."""
    d = tempfile.mkdtemp(prefix="lay_")
    try:
        P4.write_skill(d, text)
        out = {}
        for name, fn in P4.SCANNERS.items():
            try:
                out[name] = fn(d)[0]
            except Exception as e:
                out[name] = f"ERR:{type(e).__name__}"
        return out
    finally:
        shutil.rmtree(d, ignore_errors=True)


def main():
    max_usd = float(sys.argv[1]) if len(sys.argv) > 1 else 2.0

    # ---- what Phase 4 already decided, so no scan is repeated -----------------
    prior = {}
    if os.path.exists(P4_FP):
        p4 = pd.read_csv(P4_FP)
        for r in p4.itertuples(index=False):
            prior.setdefault(str(r.skill_hash), {})[r.scanner] = r.verdict
    print(f"reusing Phase 4 scanner verdicts for {len(prior)} skills", flush=True)

    done = {}
    if os.path.exists(ROWS_FP):
        prev = pd.read_csv(ROWS_FP)
        for r in prev.itertuples(index=False):
            done[str(r.skill_hash)] = r
        print(f"resuming: {len(done)} rows complete", flush=True)
    else:
        with open(ROWS_FP, "w", newline="", encoding="utf-8") as f:
            csv.writer(f).writerow(FIELDS)

    cand = D.load_candidates()
    mal = [(D.skill_hash(t), t) for t in cand.skill_text]
    ben_hashes = set(h for h, v in prior.items()) if prior else set()
    # the benign arm is the set Phase 4 scanned; pull their text back by hash
    bn = pd.read_parquet(A.BENIGN_FP, columns=["content"])["content"].dropna().astype(str)
    ben = []
    want = set(ben_hashes)
    for t in bn:
        h = D.skill_hash(t)
        if h in want:
            ben.append((h, t))
            want.discard(h)
            if not want:
                break
    ben = [(h, t) for h, t in ben if h not in {m[0] for m in mal}]
    print(f"pool: {len(mal)} malicious (one per family), {len(ben)} benign", flush=True)

    jobs = [("mal", h, t) for h, t in mal if h not in done] + \
           [("ben", h, t) for h, t in ben if h not in done]
    print(f"jobs: {len(jobs)}  budget=${max_usd:.2f}", flush=True)
    if not jobs:
        summarise()
        return

    fh = open(ROWS_FP, "a", newline="", encoding="utf-8")
    wr = csv.writer(fh)
    n = [0]
    t0 = time.time()
    stop = threading.Event()

    def work(j):
        arm, h, t = j
        if stop.is_set():
            return
        v = A.call(MODEL, t)
        sc = prior.get(h)
        if sc is None or "cisco" not in sc or "skillfrisk" not in sc:
            sc = scan_both(t)
            src = "scanned"
        else:
            src = "phase4"
        with _lock:
            wr.writerow([h, arm, src, v, sc.get("cisco", ""), sc.get("skillfrisk", "")])
            fh.flush()
            n[0] += 1
            if n[0] % 50 == 0:
                print(f"  {n[0]}/{len(jobs)}  ${spend():.3f}  "
                      f"{time.time() - t0:.0f}s", flush=True)
            if spend() > max_usd and not stop.is_set():
                print(f"!! budget ${max_usd:.2f} reached at {n[0]}", flush=True)
                stop.set()

    with ThreadPoolExecutor(max_workers=WORKERS) as ex:
        list(ex.map(work, jobs))
    fh.close()
    summarise()


def rate(mask, n):
    k = int(mask.sum())
    p, lo, hi = A.wilson(k, n)
    return f"{k}/{n} = {p} [{lo}, {hi}]"


def summarise():
    d = pd.read_csv(ROWS_FP)
    d["llm"] = d.llm.astype(str)
    d["skill_hash"] = d.skill_hash.astype(str)
    # Two processes appended to this file concurrently, so most skills were judged twice.
    # The repeats are a free rejudge control at temperature 0; keep the first of each and
    # report how often the two disagreed.
    rep_n = rep_dis = 0
    for _, gg in d.groupby(["skill_hash", "arm"]):
        if len(gg) > 1:
            rep_n += 1
            if (gg.llm.nunique() > 1 or gg.cisco.nunique() > 1
                    or gg.skillfrisk.nunique() > 1):
                rep_dis += 1
    d = d.drop_duplicates(subset=["skill_hash", "arm"], keep="first")
    L = ["# Layering measured on an unconditioned pool\n",
         "The published layering numbers were computed on `gpt-4o-mini`'s caught set, so "
         "skills the scanner catches and the judge misses could not appear. Here both "
         "families see the whole one-per-family candidate pool, so the disjunction is "
         "measured rather than bounded. Judge reader: `none`, one raw read. Scanner "
         "verdicts flag only CRITICAL or HIGH, the calibration Phase 4 uses.\n"]
    for arm, label, ev in (("mal", "Recall on malicious", "MALICIOUS"),
                           ("ben", "False positives on benign", "MALICIOUS")):
        g = d[(d.arm == arm) & d.llm.isin(GOOD) &
              d.cisco.isin(GOOD) & d.skillfrisk.isin(GOOD)]
        if not g.empty:
            a = g.llm == ev
            b = g.cisco == ev
            c = g.skillfrisk == ev
            L += [f"\n## {label} (n = {len(g)})\n",
                  "| detector | rate |", "|---|---|",
                  f"| judge alone | {rate(a, len(g))} |",
                  f"| cisco alone | {rate(b, len(g))} |",
                  f"| skillfrisk alone | {rate(c, len(g))} |",
                  f"| judge OR cisco | {rate(a | b, len(g))} |",
                  f"| judge AND cisco | {rate(a & b, len(g))} |",
                  f"| judge OR either scanner | {rate(a | b | c, len(g))} |"]
            if arm == "mal":
                only = int((b & ~a).sum())
                L.append(f"\nSkills cisco catches that the judge misses: {only} "
                         f"({round(only / len(g), 4)}). On the caught set this count is "
                         f"zero by construction, which is the bias this run removes.")
    drop = len(d) - len(d[d.llm.isin(GOOD) & d.cisco.isin(GOOD) & d.skillfrisk.isin(GOOD)])
    L.append(f"\nSkills {len(d)}, dropped for a missing verdict {drop}. "
             f"Reused Phase 4 scans: {int((d.source == 'phase4').sum())}.")
    if rep_n:
        p, lo, hi = A.wilson(rep_dis, rep_n)
        L.append(f"\n{rep_n} of these skills were independently judged twice, and the two "
                 f"passes disagreed on {rep_dis} ({p} [{lo}, {hi}]). That is a rejudge "
                 f"control at temperature 0 on identical input, and it bounds how much of "
                 f"any difference below is instability rather than signal.")
    L.append(f"\nSpend this run ${spend():.3f}.\n")
    with open(OUT, "w", encoding="utf-8") as f:
        f.write("\n".join(L))
    print("\n".join(L))


if __name__ == "__main__":
    main()
