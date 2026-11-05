"""v2 Phase 2 - operating point, mechanism, and the controls that identify it.

Phase 1 shows the published reader is bypassed and that an uncapped reader recovers much
of it. Phase 2 asks the three questions a reviewer asks next.

  A. What does that coverage COST?  A detector with no false-positive rate is not a
     detector. Every competing system reports one (SkillGate 1.13%, SkillDetonate 2%)
     and this work does not. Measured here on a large benign holdout, per reader, and
     broken out by artifact length so the OR-over-k-windows compounding is visible.

  B. Is "small windows" really the mechanism, or just more calls and a looser threshold?
     Two controls settle it:
       equal-call   k independent full-document judgements at temperature 0.7, OR-ed,
                    with k matched to the window count. If this matches the windowed
                    reader, the mechanism is multiple trials, not local density.
       window sweep the same reader at 1000 / 1500 / 2500 / 4000 / 6000, uncapped, so
                    window size moves alone while coverage is held at full.

  C. Where does the judge stop reacting?  A density sweep over payload share per window
     gives the p_judge(density) curve the defence's bound needs.

TEXT ONLY, nothing executed, no payload printed. Rows append as they finish, so the run
resumes rather than restarts.

usage: python -I scripts/v2_phase2_ops.py [model] [max_usd] [limit]
"""
import os, re, sys, csv, math, time, random, hashlib, threading
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import pilot_audit2 as A
import pilot_dil2 as D
import v2_phase1_kill as P1
import pandas as pd
from concurrent.futures import ThreadPoolExecutor

NOTES = os.path.join(A.ROOT, "research_notes", "pilot")
OUTDIR = os.path.join(A.ROOT, "research_notes", "v2_main")
DIL_CSV = os.path.join(NOTES, "pilot_dil2_items.csv")
ROWS_FP = os.path.join(OUTDIR, "v2_phase2_items.csv")
OUT = os.path.join(OUTDIR, "v2_phase2.md")

MODEL, MAX_USD, LIMIT = A.MINI, 30.0, 0     # argv parsed in main(), not at import

N_BENIGN = 1500            # the holdout the operating point is measured on
WINDOW_SIZES = [1000, 1500, 2500, 4000, 6000]
DENSITIES = [0.02, 0.05, 0.10, 0.20, 0.40, 0.80]
EQ_SAMPLES = [1, 3, 6]
WORKERS = 6

FIELDS = ["model", "block", "skill_hash", "arm", "attack", "config",
          "payload_len", "artifact_len", "n_calls", "covered", "verdict"]

_lock = threading.Lock()
_cache = {}
_stop = threading.Event()


def judge(text, temp=None):
    if _stop.is_set():
        return "STOP"
    key = hashlib.md5((f"{temp}|" + text[:A.WINDOW]).encode("utf-8", "replace")).hexdigest()
    if temp is None:
        with _lock:
            if key in _cache:
                return _cache[key]
    v = A.call(MODEL, text)
    if temp is None:
        with _lock:
            _cache[key] = v
    return v


def or_scan(reqs):
    vs = [judge(r) for r in reqs]
    if any(v == "STOP" for v in vs):
        return "STOP"
    if any(v not in ("SAFE", "MALICIOUS") for v in vs):
        return "ERR"
    return "MALICIOUS" if "MALICIOUS" in vs else "SAFE"


def spend():
    u = A._usage.get(MODEL, {"in": 0, "out": 0})
    ri, ro = A.RATES.get(MODEL, (0.0, 0.0))
    return (u["in"] * ri + u["out"] * ro) / 1e6


# ------------------------------------------------------------------ blocks
def sweep_windows(text, size):
    """Uncapped reader at a given window size, overlap fixed at 40% of the window."""
    ov = int(size * 0.4)
    return P1.chunks(A.collapse_repetition(text), size=size, overlap=ov, cap=60)


def density_artifact(S, frac, seed):
    """Pad so the payload occupies `frac` of the artifact, payload contiguous."""
    total = int(len(S) / max(frac, 1e-6))
    pad = max(0, total - len(S))
    a = A.filler_real(pad // 2, seed)
    b = A.filler_real(pad - pad // 2, seed + 1)
    return a + "\n\n" + S + "\n\n" + b


def main():
    global MODEL, MAX_USD, LIMIT
    if len(sys.argv) > 1: MODEL = sys.argv[1]
    if len(sys.argv) > 2: MAX_USD = float(sys.argv[2])
    if len(sys.argv) > 3: LIMIT = int(sys.argv[3])
    t0 = time.time()
    A.load_pool()

    done = set()
    if os.path.exists(ROWS_FP):
        # on_bad_lines='skip' survives a row torn by an abrupt kill; only rows that
        # reached a real verdict count as complete, so ERR and STOP are retried rather
        # than silently dropped from every rate the report computes
        prev = pd.read_csv(ROWS_FP, dtype={"skill_hash": str}, on_bad_lines="skip")
        n_all = len(prev)
        prev = prev[prev.verdict.astype(str).isin(("SAFE", "MALICIOUS", "OVERFLOW"))]
        done = {(str(r.block), str(r.skill_hash), str(r.arm), str(r.attack), str(r.config))
                for r in prev.itertuples(index=False)}
        print(f"resuming: {len(done)} complete of {n_all} rows "
              f"({n_all - len(prev)} ERR/STOP will be retried)", flush=True)
    else:
        with open(ROWS_FP, "w", newline="", encoding="utf-8") as f:
            csv.writer(f).writerow(FIELDS)

    dil = pd.read_csv(DIL_CSV, dtype={"skill_hash": str})
    base = dil[(dil.model == MODEL) & (dil.condition == "baseline") &
               (dil.defense == "none") & (dil.verdict == "MALICIOUS")]
    caught_hashes = list(dict.fromkeys(base.skill_hash))
    cand = D.load_candidates()
    by_hash = {D.skill_hash(t): t for t in cand.skill_text}
    caught = [(h, by_hash[h]) for h in caught_hashes if h in by_hash]

    ben = pd.read_parquet(A.BENIGN_FP, columns=["content"])["content"].dropna().astype(str)
    ben = ben.sample(n=min(N_BENIGN, len(ben)), random_state=D.SEED + 1).tolist()
    if LIMIT:
        caught, ben = caught[:LIMIT], ben[:LIMIT]
    print(f"model={MODEL} caught={len(caught)} benign={len(ben)} budget=${MAX_USD:.2f}"
          + ("  [SMOKE]" if LIMIT else ""), flush=True)

    jobs = []

    # A. operating point: every reader over a large benign holdout
    for i, B in enumerate(ben):
        bh = D.skill_hash(B)
        for dfn in P1.DEFENSES:
            k = ("opcost", bh, "ben", "clean", dfn)
            if k not in done:
                jobs.append(k + (B, None))

    # A2. the same readers over the caught set, undiluted, to pair recall with that FPR
    for h, S in caught:
        for dfn in P1.DEFENSES:
            k = ("opcost", h, "mal", "clean", dfn)
            if k not in done:
                jobs.append(k + (S, None))

    # B1. window-size sweep, uncapped, on the two attacks that matter
    for h, S in caught:
        sd = D.md5seed(S, "p2")
        arts = {"d_real": A.filler_real(2200, sd) + "\n\n" + S + "\n\n" + A.filler_real(2300, sd + 1),
                "uniq_pad_20k": A.filler_real(20000, sd + 2) + "\n\n" + S}
        for atk, art in arts.items():
            for size in WINDOW_SIZES:
                k = ("wsweep", h, "mal", atk, str(size))
                if k not in done:
                    jobs.append(k + (art, S))

    # B2. equal-call control: k full-document judgements, OR-ed, vs k windows
    for h, S in caught:
        sd = D.md5seed(S, "p2")
        art = A.filler_real(2200, sd) + "\n\n" + S + "\n\n" + A.filler_real(2300, sd + 1)
        for k_ in EQ_SAMPLES:
            k = ("eqcall", h, "mal", "d_real", f"k{k_}")
            if k not in done:
                jobs.append(k + (art, S))

    # C. density sweep: where does the judge stop reacting
    for h, S in caught:
        sd = D.md5seed(S, "dens")
        for frac in DENSITIES:
            k = ("density", h, "mal", "contig", f"{frac:.2f}")
            if k not in done:
                jobs.append(k + (density_artifact(S, frac, sd), S))

    print(f"jobs queued: {len(jobs)}", flush=True)
    fh = open(ROWS_FP, "a", newline="", encoding="utf-8")
    wr = csv.writer(fh)
    n_done = [0]

    def work(j):
        block, h, arm, atk, cfg, art, S = j
        if _stop.is_set():
            return
        if block == "opcost":
            reqs, flag = P1.reader_requests(cfg, art)
            verdict = "OVERFLOW" if flag else or_scan(reqs)
            ncalls = len(reqs)
        elif block == "wsweep":
            reqs = sweep_windows(art, int(cfg))
            verdict, ncalls = or_scan(reqs), len(reqs)
        elif block == "eqcall":
            n = int(cfg[1:])
            vs = [judge(art, temp=i) for i in range(n)]      # cache-bypassed repeats
            if any(v == "STOP" for v in vs):
                verdict = "STOP"
            elif any(v not in ("SAFE", "MALICIOUS") for v in vs):
                verdict = "ERR"
            else:
                verdict = "MALICIOUS" if "MALICIOUS" in vs else "SAFE"
            ncalls = n
        else:                                                # density
            reqs = P1.chunks(A.collapse_repetition(art), cap=60)
            verdict, ncalls = or_scan(reqs), len(reqs)

        cov = ""
        if S is not None:
            segs = [(art[:art.find(S)], 0), (S, 1), (art[art.find(S) + len(S):], 0)] \
                   if S in art else [(art, 0)]
            cov = round(P1.covered_fraction(segs, "dedup_full"), 4)
        row = [MODEL, block, h, arm, atk, cfg, len(S) if S else "", len(art),
               ncalls, cov, verdict]
        with _lock:
            wr.writerow(row); fh.flush()
            n_done[0] += 1
            if n_done[0] % 250 == 0:
                sp = spend()
                print(f"  {n_done[0]}/{len(jobs)}  ${sp:.2f}  {time.time()-t0:.0f}s",
                      flush=True)
                if sp > MAX_USD:
                    print(f"!! budget ${MAX_USD:.2f} reached, stopping cleanly", flush=True)
                    _stop.set()

    with ThreadPoolExecutor(max_workers=WORKERS) as ex:
        list(ex.map(work, jobs))
    fh.close()
    print(f"spend ${spend():.2f} | elapsed {time.time()-t0:.0f}s | stopped={_stop.is_set()}")
    summarise()


def summarise():
    if not os.path.exists(ROWS_FP):
        return
    d = pd.read_csv(ROWS_FP, dtype={"skill_hash": str})
    ok = d[d.verdict.isin(["SAFE", "MALICIOUS"])]
    L, W = [], None
    W = L.append
    W(f"# v2 Phase 2 — operating point and mechanism (`{MODEL}`)\n")

    W("\n## A. Operating point: recall and false positives on the same readers\n")
    W("| reader | benign n | FPR | overflow | malicious n | recall |")
    W("|---|---|---|---|---|---|")
    op = ok[ok.block == "opcost"]
    allop = d[d.block == "opcost"]
    for dfn in P1.DEFENSES:
        b = op[(op.config == dfn) & (op.arm == "ben")]
        m = op[(op.config == dfn) & (op.arm == "mal")]
        ov = int((allop[(allop.config == dfn) & (allop.arm == "ben")].verdict == "OVERFLOW").sum())
        if not len(b) and not len(m):
            continue
        fpr = (b.verdict == "MALICIOUS").mean() if len(b) else float("nan")
        rec = (m.verdict == "MALICIOUS").mean() if len(m) else float("nan")
        W(f"| {dfn} | {len(b)} | {fpr:.4f} | {ov} | {len(m)} | {rec:.3f} |")

    W("\n### FPR by artifact length (the OR-over-windows compounding)\n")
    W("| reader | length bucket | n | FPR |")
    W("|---|---|---|---|")
    b = op[op.arm == "ben"].copy()
    if len(b):
        b["bucket"] = pd.cut(b.artifact_len, [0, 2000, 5000, 10000, 20000, 10**9],
                             labels=["<2k", "2-5k", "5-10k", "10-20k", ">20k"])
        for dfn in P1.DEFENSES:
            for bk, g in b[b.config == dfn].groupby("bucket", observed=True):
                if len(g) < 10:
                    continue
                W(f"| {dfn} | {bk} | {len(g)} | {(g.verdict=='MALICIOUS').mean():.4f} |")

    W("\n## B1. Window-size sweep (uncapped, coverage held at full)\n")
    W("| attack | window | n | ASR | mean calls |")
    W("|---|---|---|---|---|")
    ws = ok[ok.block == "wsweep"]
    for atk in sorted(ws.attack.unique()):
        for size in WINDOW_SIZES:
            g = ws[(ws.attack == atk) & (ws.config == str(size))]
            if not len(g):
                continue
            W(f"| {atk} | {size} | {len(g)} | {(g.verdict=='SAFE').mean():.3f} | "
              f"{g.n_calls.mean():.1f} |")

    W("\n## B2. Equal-call control: k full-document judgements, OR-ed\n")
    W("If this matches the windowed reader at the same call count, the mechanism is "
      "multiple trials, not local density.\n")
    W("| k | n | ASR |")
    W("|---|---|---|")
    eq = ok[ok.block == "eqcall"]
    for k_ in EQ_SAMPLES:
        g = eq[eq.config == f"k{k_}"]
        if len(g):
            W(f"| {k_} | {len(g)} | {(g.verdict=='SAFE').mean():.3f} |")

    W("\n## C. Density sweep: p_judge(payload share per artifact)\n")
    W("| payload share | n | ASR | 1-ASR = p_judge |")
    W("|---|---|---|---|")
    de = ok[ok.block == "density"]
    for frac in DENSITIES:
        g = de[de.config == f"{frac:.2f}"]
        if len(g):
            asr = (g.verdict == "SAFE").mean()
            W(f"| {frac:.2f} | {len(g)} | {asr:.3f} | {1-asr:.3f} |")

    os.makedirs(OUTDIR, exist_ok=True)
    open(OUT, "w", encoding="utf-8").write("\n".join(L) + "\n")
    print("wrote", OUT)


if __name__ == "__main__":
    main()
