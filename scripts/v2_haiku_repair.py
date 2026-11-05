"""Recover the claude-haiku-4.5 cells the paper actually prints.

That judge returned no usable verdict on 55.9% of its calls, against 0.2% for the other
hosted judges, which left its reported cells resting on 59-85 of the 92 skills it caught
and left its undefended and uncapped columns measured on different item sets. A retry
probe recovered 15 of 15 failed calls, so the losses were transient rather than refusals.

Full recovery would cost more than the remaining credit on that provider, so this repairs
only the cells the paper reports, which is what makes the row paired.

Rows are appended to the judge's existing per-item CSV, so the normal analysis picks them
up; the file is read back and deduplicated on (attack, defense, skill_hash) keeping the
usable verdict.

usage: OPENROUTER_API_KEY must be in the environment.
       python scripts/v2_haiku_repair.py [max_usd]
"""
import csv
import os
import sys
import threading
import time
from concurrent.futures import ThreadPoolExecutor

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import pandas as pd
import pilot_audit2 as A
import pilot_dil2 as D
import v2_phase1_kill as P1
import v2_phase3_cross as P3

OUTDIR = os.path.join(A.ROOT, "research_notes", "v2_main")
ROWS_FP = os.path.join(OUTDIR, "v2_phase3_items_anthropic_claude-haiku-4.5.csv")
OUT = os.path.join(OUTDIR, "v2_haiku_repair.md")
MODEL = "anthropic/claude-haiku-4.5"
RATES = (1.00, 5.00)
GOOD = ("SAFE", "MALICIOUS")
# the cells Table 2 and the cap table print for this judge
CELLS = [("d_real", "none"), ("d_real", "dedup_full"),
         ("gap_il_4x2600", "none"), ("gap_il_4x2600", "dedup_full"),
         ("uniq_pad_20k", "dedup_full")]
WORKERS = 1   # serialised: concurrency is what lost the rows
_lock = threading.Lock()


def spend():
    u = A._usage.get(MODEL, {"in": 0, "out": 0})
    return (u["in"] * RATES[0] + u["out"] * RATES[1]) / 1e6


def judge(text, tries=4):
    """Retry a non-verdict. The losses on this provider are throughput, not refusal: the
    windows of a row that never completed all answer when called one at a time, so a row
    of fifteen windows under three concurrent workers was simply being rate limited."""
    for i in range(tries):
        v = A.call(MODEL, text)
        if v in GOOD:
            return v
        time.sleep(1.5 * (i + 1))
    return v


def or_scan(reqs):
    vs = [judge(r) for r in reqs]
    if any(v not in GOOD for v in vs):
        return "ERR"
    return "MALICIOUS" if "MALICIOUS" in vs else "SAFE"


def main():
    if not os.environ.get("OPENROUTER_API_KEY"):
        sys.exit("OPENROUTER_API_KEY is not in the environment; export it first")
    max_usd = float(sys.argv[1]) if len(sys.argv) > 1 else 4.0

    d = pd.read_csv(ROWS_FP)
    d["skill_hash"] = d.skill_hash.astype(str)
    usable = {(r.attack, r.defense, r.skill_hash)
              for r in d.itertuples(index=False) if r.verdict in GOOD}
    caught = sorted(set(d[d.arm == "mal"].skill_hash))
    by_hash = {D.skill_hash(t): t for t in D.load_candidates().skill_text}
    A.load_pool()

    jobs = []
    for atk, dfn in CELLS:
        for h in caught:
            if (atk, dfn, h) in usable or h not in by_hash:
                continue
            jobs.append((h, by_hash[h], atk, dfn))
    print(f"caught set {len(caught)}; repairing {len(CELLS)} cells; "
          f"missing verdicts {len(jobs)}; budget ${max_usd:.2f}", flush=True)
    if not jobs:
        summarise()
        return

    fh = open(ROWS_FP, "a", newline="", encoding="utf-8")
    wr = csv.writer(fh)
    n, t0 = [0], time.time()
    stop = threading.Event()

    def work(j):
        h, S, atk, dfn = j
        if stop.is_set():
            return
        segs = P3.segments_for(S, atk, D.md5seed(S, "p3"))
        art = "".join(t for t, _ in segs)
        reqs, flag = P1.reader_requests(dfn, art)
        verdict = "OVERFLOW" if flag else or_scan(reqs)
        cov = round(P1.covered_fraction(segs, dfn), 4)
        with _lock:
            wr.writerow([MODEL, h, "mal", atk, dfn, len(S), len(art),
                         len(reqs), cov, verdict])
            fh.flush()
            n[0] += 1
            if n[0] % 25 == 0 or n[0] == len(jobs):
                print(f"  {n[0]}/{len(jobs)}  ${spend():.3f}  "
                      f"{time.time() - t0:.0f}s", flush=True)
            if spend() > max_usd and not stop.is_set():
                print(f"!! budget ${max_usd:.2f} reached at {n[0]}", flush=True)
                stop.set()

    with ThreadPoolExecutor(max_workers=WORKERS) as ex:
        list(ex.map(work, jobs))
    fh.close()
    summarise()


def summarise():
    d = pd.read_csv(ROWS_FP)
    d["skill_hash"] = d.skill_hash.astype(str)
    d["_ok"] = d.verdict.isin(GOOD).astype(int)
    d = d.sort_values("_ok", ascending=False).drop_duplicates(
        subset=["attack", "defense", "skill_hash"], keep="first")
    L = ["# claude-haiku-4.5: repaired cells\n",
         "That judge lost 55.9% of its calls to transient failures. A retry probe "
         "recovered 15 of 15, so the cells the paper prints were re-run. Rows below are "
         "deduplicated on (attack, defense, skill) keeping any usable verdict.\n",
         "| attack | reader | items with a verdict | k | rate | 95% Wilson |",
         "|---|---|---|---|---|---|"]
    for atk, dfn in CELLS:
        g = d[(d.attack == atk) & (d.defense == dfn) & d.verdict.isin(GOOD)]
        if g.empty:
            continue
        ev = "SAFE"
        k = int((g.verdict == ev).sum())
        p, lo, hi = A.wilson(k, len(g))
        L.append(f"| {atk} | `{dfn}` | {len(g)} | {k} | {p} | [{lo}, {hi}] |")
    paired = []
    for atk in ("d_real", "gap_il_4x2600"):
        a = set(d[(d.attack == atk) & (d.defense == "none") &
                  d.verdict.isin(GOOD)].skill_hash)
        b = set(d[(d.attack == atk) & (d.defense == "dedup_full") &
                  d.verdict.isin(GOOD)].skill_hash)
        paired.append(f"{atk}: {len(a & b)} skills measured under both readers "
                      f"({len(a)} and {len(b)} individually)")
    L.append("\nPairing after repair -- " + "; ".join(paired) + ".")
    tot = len(pd.read_csv(ROWS_FP))
    L.append(f"\nRows in the judge's file {tot}, distinct cells after dedup {len(d)}. "
             f"Spend this run ${spend():.3f}.\n")
    with open(OUT, "w", encoding="utf-8") as f:
        f.write("\n".join(L))
    print("\n".join(L))


if __name__ == "__main__":
    main()
