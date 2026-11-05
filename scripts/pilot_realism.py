"""E-REALISM part A: provenance-stratified baseline recall on EvasionBench (primary.parquet).
Answers 'is the ~38% baseline recall driven by synthetic/injected rows?'. Malicious rows are drawn per
stratum (provenance, evidence_type, source_name), up to 80 each, one per structural_family_id before any
family repeats; strata share one global shuffle so overlapping strata reuse verdicts. Each item is judged
once per model (pilot_audit2.call, temp 0, 8000-char window, raw text, no defense); gpt-4o confirms 25 per
provenance stratum. Benign rows (~300, stratified by provenance) give per-stratum FPR. Per-item CSV keeps
stratum membership so every cell is recomputable offline. Text only. usage: validate | run"""
import os, sys, io, math, random, time, csv
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import pandas as pd
import pilot_audit2 as A  # reuse: call, par, wilson, cost, MINI, BIG

NOTES = os.path.join(A.ROOT, "research_notes", "pilot")
OUT = os.path.join(NOTES, "pilot_realism_results.md")
CSV = os.path.join(NOTES, "pilot_realism_items.csv")
MINI, BIG = A.MINI, A.BIG
CAP = {MINI: 2000, BIG: 200}
_n = {MINI: 0, BIG: 0}
SEED, PER = 7, 80
BIG_PER_PROV = 25
BEN_PLAN = {"wild": 100, "injected": 80, "synthetic": 70, "test_fixture": 53}

def call(model, text):
    with A._lock:
        if _n[model] >= CAP[model]: return "CAP"
        _n[model] += 1
    return A.call(model, text)

def load():
    p = pd.read_parquet(os.path.join(A.BASE, "primary.parquet"),
        columns=["benchmark_id", "label", "skill_text", "text_available", "text_redacted", "source_id",
                 "source_name", "provenance", "evidence_type", "structural_family_id", "exact_hash"])
    p["skill_text"] = p["skill_text"].fillna("")
    p["lab"] = p.label.astype(str).str.strip()
    p["len"] = p.skill_text.str.len()
    p = p[(p.text_available == True) & (p.text_redacted == False) & (p.len > 120)].copy()
    p["order"] = p.benchmark_id.map(dict(zip(p.benchmark_id, random.Random(SEED).sample(range(len(p)), len(p)))))
    return p.sort_values("order")

def fam_sample(df, n):
    """First n rows in global-shuffle order, one per family before any family repeats."""
    d = df.copy()
    d["frk"] = d.groupby(d.structural_family_id.fillna(d.benchmark_id)).cumcount()
    return d.sort_values(["frk", "order"]).head(n)

def strata(mal):
    S = {}
    for col in ["provenance", "evidence_type"]:
        for v, g in mal.groupby(col): S[(col, v)] = fam_sample(g, PER)
    for v, g in mal.groupby("source_name"):
        if len(g) >= 20: S[("source_name", v)] = fam_sample(g, PER)
    return S

def boot_ci(sub, hit, B=2000, seed=1):
    """Family-clustered bootstrap CI for a proportion (resample families with replacement)."""
    fam = sub.structural_family_id.fillna(sub.benchmark_id).values; h = hit.values.astype(float)
    groups = {}
    for f, x in zip(fam, h): groups.setdefault(f, []).append(x)
    g = [(sum(v), len(v)) for v in groups.values()]
    if len(g) < 2: return (float("nan"), float("nan"))
    r = random.Random(seed); est = []
    for _ in range(B):
        k = n = 0
        for _ in range(len(g)):
            a, b = g[r.randrange(len(g))]; k += a; n += b
        est.append(k / n)
    est.sort(); return (round(est[int(0.025 * B)], 3), round(est[int(0.975 * B) - 1], 3))

def cell(sub, model, V, want="MALICIOUS"):
    v = sub.benchmark_id.map(lambda i: V[model].get(i))
    ok = v.isin(["SAFE", "MALICIOUS"]); s = sub[ok]; hit = (v[ok] == want)
    k, n = int(hit.sum()), int(ok.sum())
    w = A.wilson(k, n); b = boot_ci(s, hit) if n else (float("nan"),) * 2
    fams = s.structural_family_id.nunique()
    return k, n, w, b, fams, int((~ok).sum())

def row(name, c, extra=""):
    k, n, w, b, fams, bad = c
    return f"| {name} | {n} | {fams} | {k}/{n} = {w[0]} | {w[1]}~{w[2]} | {b[0]}~{b[1]} |{extra}"

def judge(df, model, V, workers=6):
    todo = [i for i in df.benchmark_id if i not in V[model]]
    txt = dict(zip(df.benchmark_id, df.skill_text))
    res = A.par([lambda i=i: call(model, txt[i]) for i in todo], workers=workers)
    V[model].update(zip(todo, res))

def bucket(L): return "<=3000" if L <= 3000 else "3001-8000" if L <= 8000 else ">8000"

def validate():
    p = load(); mal = p[p.lab == "1"]; ben = p[p.lab == "0"]
    picks = [fam_sample(g, 1) for _, g in mal.groupby("provenance")][:5]
    xs = pd.concat(picks + [ben.head(3)])
    for _, r in xs.iterrows():
        print(r.lab, r.provenance, r.evidence_type, r.len, "mini:", call(MINI, r.skill_text))
    for _, r in xs.head(2).iterrows():
        print(r.lab, r.provenance, "4o:", call(BIG, r.skill_text))
    S = strata(mal)
    u = pd.concat(S.values()).benchmark_id.nunique()
    print("strata:", {f"{k[0]}={k[1]}": len(v) for k, v in S.items()})
    print("unique malicious to judge (mini):", u, "| calls so far", _n, "| cost $%.4f" % A.cost())

def run():
    t0 = time.time()
    p = load(); mal = p[p.lab == "1"]; ben = p[p.lab == "0"]
    S = strata(mal)
    pool = pd.concat(S.values()).drop_duplicates("benchmark_id")
    bpool = pd.concat([ben[ben.provenance == k].head(n) for k, n in BEN_PLAN.items()])
    V = {MINI: {}, BIG: {}}
    judge(pool, MINI, V); judge(bpool, MINI, V)
    big = pd.concat([S[("provenance", v)].head(BIG_PER_PROV) for v in sorted(mal.provenance.unique())])
    judge(big, BIG, V, workers=4)
    bbig = bpool[bpool.provenance == "wild"].head(25)
    judge(bbig, BIG, V, workers=4)

    mem = {}
    for (col, v), g in S.items():
        for i in g.benchmark_id: mem.setdefault(i, []).append(f"{col}={v}")
    allr = pd.concat([pool, bpool]).drop_duplicates("benchmark_id")
    with io.open(CSV, "w", encoding="utf-8", newline="") as fh:
        w = csv.writer(fh)
        w.writerow(["skill_hash_or_name", "structural_family_id", "source_id", "provenance", "evidence_type",
                    "len", "condition", "defense", "verdict", "model", "label", "source_name", "benchmark_id", "strata"])
        for _, r in allr.iterrows():
            for m in (MINI, BIG):
                if r.benchmark_id in V[m]:
                    w.writerow([r.exact_hash, r.structural_family_id, r.source_id, r.provenance, r.evidence_type,
                                r.len, "raw", "none", V[m][r.benchmark_id], m, r.lab, r.source_name, r.benchmark_id,
                                ";".join(mem.get(r.benchmark_id, ["benign_sample"] if r.lab == "0" else []))])

    H = "| stratum | n | families | recall | Wilson 95% | family-bootstrap 95% |\n|---|---|---|---|---|---|"
    with io.open(OUT, "w", encoding="utf-8") as f:
        W = lambda *a: print(*a, file=f) or f.flush()
        W("# E-REALISM part A: provenance-stratified baseline recall (EvasionBench)")
        W(f"Raw skill text, no attack, no defense; pilot_audit2 scanner prompt, temp 0, {A.WINDOW}-char window. "
          f"Malicious usable rows only (text_available, not redacted, >120 chars). Each stratum: up to {PER} rows, "
          "one per structural_family_id before any family repeats (global shuffle seed 7). "
          "Recall = MALICIOUS verdicts / judged. Family-bootstrap CI resamples families (2000 draws).\n")
        W(f"Population (usable malicious {len(mal)}, benign {len(ben)}); verdict failures excluded from n.\n")
        for col, title in [("provenance", "A1. Recall by provenance"), ("evidence_type", "A2. Recall by evidence_type"),
                           ("source_name", "A3. Recall by source_name (sources with >=20 usable malicious rows)")]:
            W(f"\n## {title} — gpt-4o-mini\n" + H.replace("| stratum |", "| stratum (population) |"))
            for (c, v), g in sorted(S.items(), key=lambda kv: -int((mal[kv[0][0]] == kv[0][1]).sum())):
                if c != col: continue
                W(row(f"{v} ({int((mal[col] == v).sum())})", cell(g, MINI, V)))
        # post-stratified overall recall (weights = population share per provenance)
        tot, acc = len(mal), 0.0
        for v in mal.provenance.unique():
            k, n, *_ = cell(S[("provenance", v)], MINI, V); acc += (k / n if n else 0) * (mal.provenance == v).sum() / tot
        W(f"\nPost-stratified overall mini recall (provenance strata weighted by population share): **{acc:.3f}**")
        W("\n## A4. gpt-4o confirmation (first 25 of each provenance sample)\n"
          "| provenance | n | mini recall (same items) | gpt-4o recall | Wilson 95% (gpt-4o) |\n|---|---|---|---|---|")
        for v in sorted(mal.provenance.unique(), key=lambda v: -int((mal.provenance == v).sum())):
            g = S[("provenance", v)].head(BIG_PER_PROV)
            km, nm, *_ = cell(g, MINI, V); kb, nb, wb, *_ = cell(g, BIG, V)
            W(f"| {v} | {nb} | {km}/{nm} = {round(km/nm,3) if nm else 'na'} | {kb}/{nb} = {wb[0]} | {wb[1]}~{wb[2]} |")
        # length confound: is a stratum's low recall just long skills cut at the window?
        W("\n## A5. Length confound — mini recall by provenance x length bucket (designated provenance samples)\n"
          "| provenance | <=3000 | 3001-8000 | >8000 | median len |\n|---|---|---|---|---|")
        for v in sorted(mal.provenance.unique(), key=lambda v: -int((mal.provenance == v).sum())):
            g = S[("provenance", v)].copy(); g["b"] = g.len.map(bucket); cells = []
            for b in ["<=3000", "3001-8000", ">8000"]:
                k, n, w, *_ = cell(g[g.b == b], MINI, V); cells.append(f"{k}/{n}" + (f" = {w[0]}" if n else ""))
            W(f"| {v} | " + " | ".join(cells) + f" | {int(g.len.median())} |")
        allm = pool.copy(); allm["b"] = allm.len.map(bucket)
        W("\nAll judged malicious items pooled, by length: " + "; ".join(
            f"{b}: {cell(allm[allm.b == b], MINI, V)[0]}/{cell(allm[allm.b == b], MINI, V)[1]}"
            for b in ["<=3000", "3001-8000", ">8000"]))
        # benign FPR
        W("\n## A6. Benign FPR (label 0), raw text — gpt-4o-mini\n"
          "| stratum (population) | n | FPR | Wilson 95% |\n|---|---|---|---|")
        for col in ["provenance", "evidence_type", "source_name"]:
            for v, g in bpool.groupby(col):
                k, n, w, *_ = cell(g, MINI, V)
                W(f"| {col}={v} ({int((ben[col] == v).sum())}) | {n} | {k}/{n} = {w[0]} | {w[1]}~{w[2]} |")
        k, n, w, *_ = cell(bpool, MINI, V)
        W(f"| ALL benign sampled | {n} | {k}/{n} = {w[0]} | {w[1]}~{w[2]} |")
        k, n, w, *_ = cell(bbig, BIG, V); km, nm, *_ = cell(bbig, MINI, V)
        W(f"\ngpt-4o benign FPR on 25 wild benign: {k}/{n} = {w[0]} ({w[1]}~{w[2]}); mini on the same items {km}/{nm}.")
        bad = sum(1 for m in V for x in V[m].values() if x not in ("SAFE", "MALICIOUS"))
        W(f"\n---\nCalls: gpt-4o-mini {_n[MINI]}, gpt-4o {_n[BIG]}; verdict failures {bad}; "
          f"cost ${A.cost():.3f}; {int(time.time() - t0)} s. Per-item CSV: pilot_realism_items.csv")
    print(f"done -> {OUT} | calls {_n} | cost ${A.cost():.3f}")

def report(cost_note=""):
    """Rebuild the results file from the per-item CSV (no API calls). Verdicts other than SAFE/MALICIOUS
    (ERR, HTTPxxx, ?, CAP) are excluded from every n and counted in the 'excl' column."""
    p = load(); mal = p[p.lab == "1"]; ben = p[p.lab == "0"]
    d = pd.read_csv(CSV, dtype={"label": str, "structural_family_id": str})
    d["strata"] = d.strata.fillna("")
    V = {m: dict(zip(g.benchmark_id, g.verdict)) for m, g in d.groupby("model")}
    for m in (MINI, BIG): V.setdefault(m, {})
    items = d.drop_duplicates("benchmark_id").set_index("benchmark_id")
    def grp(tag): return items[items.strata.str.split(";").map(lambda t: tag in t)].reset_index()
    def line(name, sub, model):
        k, n, w, b, fams, bad = cell(sub, model, V)
        return f"| {name} | {n} | {bad} | {fams} | {k}/{n} = {w[0]} | {w[1]}~{w[2]} | {b[0]}~{b[1]} |"
    H = ("| stratum (population) | n | excl | families | recall | Wilson 95% | family-bootstrap 95% |\n"
         "|---|---|---|---|---|---|---|")
    order = lambda col: sorted(mal[col].unique(), key=lambda v: -int((mal[col] == v).sum()))
    with io.open(OUT, "w", encoding="utf-8") as f:
        W = lambda *a: print(*a, file=f) or f.flush()
        W("# E-REALISM part A: provenance-stratified baseline recall (EvasionBench)")
        W(f"Raw skill text, no attack, no defense; pilot_audit2 scanner prompt, temp 0, {A.WINDOW}-char window "
          "(text past 8000 chars is not seen, as in every prior baseline). Usable rows only (text_available, not "
          f"redacted, >120 chars): malicious {len(mal)}, benign {len(ben)}. Each malicious stratum = up to {PER} rows, "
          "one per structural_family_id before any family repeats (one global shuffle, seed 7, so overlapping "
          "strata share items and verdicts). Recall = MALICIOUS / n. n counts valid verdicts only; 'excl' = "
          "ERR/HTTP/unparsed verdicts dropped from the cell (never counted as SAFE). Family-bootstrap CI resamples "
          "structural families (2000 draws).\n")
        for col, title in [("provenance", "A1. Recall by provenance"), ("evidence_type", "A2. Recall by evidence_type"),
                           ("source_name", "A3. Recall by source_name (sources with >=20 usable malicious rows; all rows when <80)")]:
            W(f"\n## {title} — gpt-4o-mini\n" + H)
            for v in order(col):
                g = grp(f"{col}={v}")
                if len(g): W(line(f"{v} ({int((mal[col] == v).sum())})", g, MINI))
        acc, wsum = 0.0, 0
        for v in mal.provenance.unique():
            k, n, *_ = cell(grp(f"provenance={v}"), MINI, V)
            if n: acc += k / n * int((mal.provenance == v).sum()); wsum += int((mal.provenance == v).sum())
        W(f"\nPost-stratified overall mini recall (provenance-sample recalls weighted by population counts): **{acc / wsum:.3f}**")
        W("\n## A4. gpt-4o confirmation (first 25 of each provenance sample; same items under mini)\n"
          "| provenance | n (4o) | excl (4o) | mini recall, same items | gpt-4o recall | Wilson 95% (gpt-4o) |\n|---|---|---|---|---|---|")
        for v in order("provenance"):
            g = items[(items.label == "1") & (items.provenance == v) & items.index.isin(list(V[BIG]))].reset_index()
            km, nm, *_ = cell(g, MINI, V); kb, nb, wb, _, _, bb = cell(g, BIG, V)
            W(f"| {v} | {nb} | {bb} | {km}/{nm} = {round(km / nm, 3) if nm else 'na'} | {kb}/{nb} = {wb[0]} | {wb[1]}~{wb[2]} |")
        W("\n## A5. Length confound — mini recall by provenance x skill length (designated provenance samples)\n"
          "| provenance | <=3000 | 3001-8000 | >8000 (tail unseen) | median len |\n|---|---|---|---|---|")
        for v in order("provenance"):
            g = grp(f"provenance={v}"); g["b"] = g.len.map(bucket); cs = []
            for b in ["<=3000", "3001-8000", ">8000"]:
                k, n, w, *_ = cell(g[g.b == b], MINI, V); cs.append(f"{k}/{n}" + (f" = {w[0]}" if n else ""))
            W(f"| {v} | " + " | ".join(cs) + f" | {int(g.len.median())} |")
        am = items[items.label == "1"].reset_index(); am["b"] = am.len.map(bucket); cs = []
        for b in ["<=3000", "3001-8000", ">8000"]:
            k, n, w, *_ = cell(am[am.b == b], MINI, V); cs.append(f"{b}: {k}/{n} = {w[0]} ({w[1]}~{w[2]})")
        W("\nAll judged malicious items pooled (union of strata, not a population estimate), by length: " + "; ".join(cs))
        W("\n## A6. Benign FPR (label 0), raw text — gpt-4o-mini\n"
          "| stratum (population) | n | excl | FPR | Wilson 95% |\n|---|---|---|---|---|")
        bi = items[items.label == "0"].reset_index()
        for col in ["provenance", "evidence_type", "source_name"]:
            for v, g in bi.groupby(col):
                k, n, w, _, _, bad = cell(g, MINI, V)
                W(f"| {col}={v} ({int((ben[col] == v).sum())}) | {n} | {bad} | {k}/{n} = {w[0]} | {w[1]}~{w[2]} |")
        k, n, w, _, _, bad = cell(bi, MINI, V)
        W(f"| ALL benign sampled | {n} | {bad} | {k}/{n} = {w[0]} | {w[1]}~{w[2]} |")
        bb = bi[bi.benchmark_id.isin(list(V[BIG]))]
        k, n, w, _, _, bad = cell(bb, BIG, V); km, nm, *_ = cell(bb, MINI, V)
        W(f"\ngpt-4o benign FPR on {len(bb)} wild benign rows: {k}/{n} = {w[0]} ({w[1]}~{w[2]}), excl {bad}; mini on the same rows {km}/{nm}.")
        W("\n## Part B. Real-skill anchor — not run (stopped)\n"
          "- Dataset fact: per the DataDog malicious-software-packages-dataset README, a manifest entry of `null` "
          "means the package has malicious intent and all versions can be considered malicious. Our "
          "data/datadog_ai_skills/manifest.json has 204 entries, all `null`, and is byte-identical to the "
          "upstream file, so every entry carries a DataDog weak label of MALICIOUS. This corrects the earlier "
          "note that the names were unresolved.\n"
          "- Status: Part B was stopped before any package was resolved or fetched, and it will not be run by "
          "any other route. No skill files were downloaded; the only network reads were the DataDog README and "
          "one directory listing. This run gives no real-skill verdicts, truncation or recovery numbers.\n"
          "- Consequence: the paper does not claim a DataDog-based real-skill anchor; the 4 Trail-of-Bits "
          "skills remain the real anchor.")
        nbad = int((~d.verdict.isin(["SAFE", "MALICIOUS"])).sum())
        W(f"\n---\nCalls in this run (CSV rows): gpt-4o-mini {int((d.model == MINI).sum())}, gpt-4o {int((d.model == BIG).sum())}; "
          f"plus 10 validation calls (8 mini, 2 gpt-4o). Excluded verdicts overall: {nbad}. {cost_note}")
    print("report ->", OUT)

if __name__ == "__main__":
    mode = sys.argv[1] if len(sys.argv) > 1 else "run"
    if mode == "report": report(" ".join(sys.argv[2:])); sys.exit(0)
    if not A.KEY: print("NO KEY"); sys.exit(1)
    (validate if mode == "validate" else run)()
