"""v2 Phase 4 - external scanner baselines on the same attacks.

Reviewers asked the obvious question we never answered: how does a real deployed scanner
do on these artifacts? Without that, the only baseline is our own 8000-char truncating
read, which is a baseline we chose.

Two scanners are installed and run fully offline and statically:
  Cisco Skill Scanner 2.3.1  static + bytecode + pipeline analyzers, no API key
  skillfrisk 0.3.0           static, "no LLM, no network, no Docker"

Both read the whole file (Cisco's documented per-file cap is 10 MB, far above our
largest 52 KB artifact), so by construction they should be IMMUNE to the truncation and
dilution attacks that defeat a windowed LLM judge. The interesting number is what they
cost in recall on the undiluted payload: that is the real trade-off the paper should show.

SAFETY. Nothing is executed. We never call `scan-repo` (which git-clones) and never pass
--use-llm / --use-virustotal / --use-aidefense. I verified the behavioral analyzer is AST
and taint analysis, not sandboxed execution, and that the only real subprocess calls in
the package are the CEL policy runtime, repo_fetcher and the pre-commit hook. Artifacts
are written to an isolated scratch directory and deleted after each scan.

usage: python -I scripts/v2_phase4_scanners.py [limit] [attacks_csv]
"""
import os, re, sys, csv, json, time, shutil, tempfile, subprocess, threading
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import pilot_audit2 as A
import pilot_dil2 as D
import v2_phase1_kill as P1
import pandas as pd
from concurrent.futures import ThreadPoolExecutor

NOTES = os.path.join(A.ROOT, "research_notes", "pilot")
OUTDIR = os.path.join(A.ROOT, "research_notes", "v2_main")
DIL_CSV = os.path.join(NOTES, "pilot_dil2_items.csv")
ROWS_FP = os.path.join(OUTDIR, "v2_phase4_items.csv")
OUT = os.path.join(OUTDIR, "v2_phase4.md")
SCRATCH = os.path.join(tempfile.gettempdir(), "v2_scan_isolated")

MODEL = A.MINI                      # only used to pick the same caught set
# argv is parsed in main(), not here: this module is imported by v2_layering.py, and a
# module-level parse made the import inherit the importer own flags and crash.
LIMIT = 0
ATTACKS = ["clean", "uniq_pad_20k", "neardup_10k", "gap_il_4x2600"]
N_BENIGN = 200
WORKERS = 4
TIMEOUT = 180

FIELDS = ["scanner", "skill_hash", "arm", "attack", "artifact_len", "verdict",
          "n_crit", "n_high", "n_med", "n_low", "n_info", "risk_score",
          "categories", "seconds", "note"]
_lock = threading.Lock()

# Calibrated on 6 benign + 6 malicious skills: benign artifacts produce only
# (INFO, policy_violation) findings such as MANIFEST_MISSING_LICENSE, while malicious
# ones add HIGH findings in data_exfiltration / obfuscation / autonomy_abuse. So a
# finding count is not a verdict; severity is. Counts are stored per level so the
# threshold can be moved after the fact.
FLAG_AT = {"CRITICAL", "HIGH"}


def write_skill(d, text):
    os.makedirs(d, exist_ok=True)
    with open(os.path.join(d, "SKILL.md"), "w", encoding="utf-8", errors="replace") as f:
        f.write(text)


def _tally(findings):
    """Counts per severity level, plus the categories seen. Never returns snippet text."""
    c = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0, "INFO": 0}
    cats = set()
    for f in findings or []:
        if not isinstance(f, dict):
            continue
        s = str(f.get("severity", "")).upper()
        s = {"MED": "MEDIUM", "CRIT": "CRITICAL", "WARNING": "MEDIUM"}.get(s, s)
        if s in c:
            c[s] += 1
        cat = f.get("category") or f.get("rule_id") or f.get("rule") or f.get("id")
        if cat and s in FLAG_AT:
            cats.add(str(cat)[:40])
    return c, cats


def run_cisco(d):
    """Static path only: no --use-llm, no --use-virustotal, no --use-aidefense,
    and never scan-repo, so nothing is fetched and nothing is executed."""
    p = subprocess.run(["skill-scanner", "scan", d, "--format", "json"],
                       capture_output=True, text=True, timeout=TIMEOUT,
                       encoding="utf-8", errors="replace")
    out = p.stdout or ""
    i = out.find("{")
    if i < 0:
        return "ERR", {}, set(), "", (p.stderr or out)[:110]
    try:
        o = json.loads(out[i:])
    except Exception as e:
        return "ERR", {}, set(), "", f"json: {e}"
    findings = o.get("findings") or o.get("results") or []
    if isinstance(findings, dict):
        findings = findings.get("items", []) or []
    c, cats = _tally(findings)
    verdict = "MALICIOUS" if sum(c[k] for k in FLAG_AT) > 0 else "SAFE"
    return verdict, c, cats, "", ""


def run_frisk(d):
    p = subprocess.run(["skillfrisk", "scan", d, "--json"],
                       capture_output=True, text=True, timeout=TIMEOUT,
                       encoding="utf-8", errors="replace")
    out = p.stdout or ""
    i = out.find("{")
    if i < 0:
        return "ERR", {}, set(), "", (p.stderr or out)[:110]
    try:
        o = json.loads(out[i:])
    except Exception as e:
        return "ERR", {}, set(), "", f"json: {e}"
    findings = o.get("findings") or []
    c, cats = _tally(findings)
    risk = o.get("risk_score", "")
    # skillfrisk exits non-zero on a high finding unless --no-fail-on-high
    verdict = "MALICIOUS" if (sum(c[k] for k in FLAG_AT) > 0 or p.returncode != 0) else "SAFE"
    return verdict, c, cats, risk, ("rc=%d" % p.returncode if p.returncode else "")


SCANNERS = {"cisco": run_cisco, "skillfrisk": run_frisk}


def main():
    global LIMIT, ATTACKS
    if len(sys.argv) > 1:
        LIMIT = int(sys.argv[1])
    if len(sys.argv) > 2:
        ATTACKS = sys.argv[2].split(",")
    t0 = time.time()
    A.load_pool()
    os.makedirs(SCRATCH, exist_ok=True)

    done = set()
    if os.path.exists(ROWS_FP):
        prev = pd.read_csv(ROWS_FP, dtype={"skill_hash": str})
        done = {(str(r.scanner), str(r.skill_hash), str(r.arm), str(r.attack))
                for r in prev.itertuples(index=False)}
        print(f"resuming: {len(done)} rows done", flush=True)
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

    # Same seed as the Phase 1 benign arm on purpose: the two detector families have to
    # be joined per skill to price a combined reader, and a different seed left only two
    # shared benign skills, which is no false-positive rate at all.
    ben = pd.read_parquet(A.BENIGN_FP, columns=["content"])["content"].dropna().astype(str)
    ben = ben.sample(n=min(N_BENIGN, len(ben)), random_state=D.SEED).tolist()
    if LIMIT:
        caught, ben = caught[:LIMIT], ben[:min(LIMIT, len(ben))]
    print(f"caught={len(caught)} benign={len(ben)} attacks={ATTACKS}", flush=True)

    jobs = []
    for h, S in caught:
        arts = {"clean": S}
        built = P1.build_attacks(S, h)
        for a in ATTACKS:
            if a != "clean" and a in built:
                arts[a] = "".join(t for t, _ in built[a])
        for atk, art in arts.items():
            if atk not in ATTACKS:
                continue
            for sc in SCANNERS:
                if (sc, h, "mal", atk) not in done:
                    jobs.append((sc, h, "mal", atk, art))
    for B in ben:
        bh = D.skill_hash(B)
        for sc in SCANNERS:
            if (sc, bh, "ben", "clean") not in done:
                jobs.append((sc, bh, "ben", "clean", B))

    print(f"jobs: {len(jobs)}", flush=True)
    fh = open(ROWS_FP, "a", newline="", encoding="utf-8")
    wr = csv.writer(fh)
    n_done = [0]

    def work(j):
        sc, h, arm, atk, art = j
        d = os.path.join(SCRATCH, f"{sc}_{h[:12]}_{atk}")
        s0 = time.time()
        try:
            write_skill(d, art)
            verdict, c, cats, risk, note = SCANNERS[sc](d)
        except subprocess.TimeoutExpired:
            verdict, c, cats, risk, note = "TIMEOUT", {}, set(), "", f">{TIMEOUT}s"
        except Exception as e:
            verdict, c, cats, risk, note = "ERR", {}, set(), "", type(e).__name__
        finally:
            shutil.rmtree(d, ignore_errors=True)
        g = lambda k: c.get(k, 0)
        row = [sc, h, arm, atk, len(art), verdict,
               g("CRITICAL"), g("HIGH"), g("MEDIUM"), g("LOW"), g("INFO"), risk,
               "|".join(sorted(cats)), round(time.time() - s0, 2), note]
        with _lock:
            wr.writerow(row); fh.flush()
            n_done[0] += 1
            if n_done[0] % 50 == 0:
                print(f"  {n_done[0]}/{len(jobs)}  {time.time()-t0:.0f}s", flush=True)

    with ThreadPoolExecutor(max_workers=WORKERS) as ex:
        list(ex.map(work, jobs))
    fh.close()
    shutil.rmtree(SCRATCH, ignore_errors=True)
    print(f"elapsed {time.time()-t0:.0f}s")
    summarise()


def summarise():
    if not os.path.exists(ROWS_FP):
        return
    d = pd.read_csv(ROWS_FP, dtype={"skill_hash": str})
    ok = d[d.verdict.isin(["SAFE", "MALICIOUS"])]
    L, W = [], None
    W = L.append
    W("# v2 Phase 4 — external scanner baselines\n")
    W("Cisco Skill Scanner 2.3.1 and skillfrisk 0.3.0, both static and fully offline. "
      "Nothing was executed; no network analyzer was enabled. A scanner flags an artifact "
      "when it emits at least one finding.\n")
    W("\nBoth read the whole file, so a truncation or dilution attack should not move them. "
      "The number that matters is their recall on the undiluted payload, which is the price "
      "of that immunity.\n")

    W(f"\nA scanner flags an artifact when it emits a finding at {'/'.join(sorted(FLAG_AT))} "
      "severity. Finding COUNT is not a verdict: benign skills reliably produce "
      "`INFO / policy_violation` findings such as a missing manifest licence, so counting "
      "findings gives a 100% false-positive rate. Per-severity counts are kept in the CSV "
      "so the threshold can be moved without re-running.\n")

    W("\n## Recall on malicious skills, and the effect of each attack\n")
    W("| scanner | attack | n | flagged | recall | mean HIGH+ | mean INFO | ERR |")
    W("|---|---|---|---|---|---|---|---|")
    for sc in sorted(d.scanner.unique()):
        for atk in sorted(d[d.arm == "mal"].attack.unique()):
            g = ok[(ok.scanner == sc) & (ok.arm == "mal") & (ok.attack == atk)]
            bad = d[(d.scanner == sc) & (d.arm == "mal") & (d.attack == atk) &
                    (~d.verdict.isin(["SAFE", "MALICIOUS"]))]
            if not len(g):
                continue
            k = int((g.verdict == "MALICIOUS").sum())
            hi = (g.n_crit + g.n_high).mean()
            W(f"| {sc} | {atk} | {len(g)} | {k} | {k/len(g):.3f} | {hi:.2f} | "
              f"{g.n_info.mean():.2f} | {len(bad)} |")

    W("\n## False positive rate on benign skills\n")
    W("| scanner | n | flagged | FPR | mean HIGH+ | mean INFO |")
    W("|---|---|---|---|---|---|")
    for sc in sorted(d.scanner.unique()):
        g = ok[(ok.scanner == sc) & (ok.arm == "ben")]
        if not len(g):
            continue
        k = int((g.verdict == "MALICIOUS").sum())
        W(f"| {sc} | {len(g)} | {k} | {k/len(g):.3f} | "
          f"{(g.n_crit+g.n_high).mean():.2f} | {g.n_info.mean():.2f} |")

    W("\n## What the scanners actually fire on\n")
    W("| scanner | top categories at HIGH+ |")
    W("|---|---|")
    for sc in sorted(d.scanner.unique()):
        cats = (ok[(ok.scanner == sc) & (ok.arm == "mal")].categories
                .dropna().astype(str).str.split("|").explode())
        cats = cats[cats.str.len() > 0]
        if len(cats):
            top = ", ".join(f"{k} x{v}" for k, v in cats.value_counts().head(6).items())
            W(f"| {sc} | {top} |")

    W("\n## Attack sensitivity: recall relative to the clean payload\n")
    W("A static reader that sees the whole file should show no drop. Any drop is evidence "
      "that even a full-file scanner is affected by how the payload is presented.\n")
    W("| scanner | attack | recall | delta vs clean |")
    W("|---|---|---|---|")
    for sc in sorted(d.scanner.unique()):
        base = ok[(ok.scanner == sc) & (ok.arm == "mal") & (ok.attack == "clean")]
        if not len(base):
            continue
        b = (base.verdict == "MALICIOUS").mean()
        for atk in sorted(d[d.arm == "mal"].attack.unique()):
            g = ok[(ok.scanner == sc) & (ok.arm == "mal") & (ok.attack == atk)]
            if not len(g):
                continue
            r = (g.verdict == "MALICIOUS").mean()
            W(f"| {sc} | {atk} | {r:.3f} | {r-b:+.3f} |")

    W("\n## Latency\n")
    W("| scanner | mean s/scan | max |")
    W("|---|---|---|")
    for sc in sorted(d.scanner.unique()):
        g = d[d.scanner == sc]
        W(f"| {sc} | {g.seconds.mean():.2f} | {g.seconds.max():.2f} |")

    os.makedirs(OUTDIR, exist_ok=True)
    open(OUT, "w", encoding="utf-8").write("\n".join(L) + "\n")
    print("wrote", OUT)


if __name__ == "__main__":
    main()
