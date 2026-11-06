r"""Two readers the panel asked for, on the attack grid the paper already uses.

1. `skillgate530` -- the content-addressed reader with SkillGate's RELEASED 530-pattern
   ruleset and its own window rule, replacing the 49-group stand-in of
   `scripts/v2_skillgate.py`. The novelty review's strongest objection is that the paper's
   largest effect is measured against a prefilter one-eleventh the size of the deployed
   one, and that the fix "is not writing -- it is running the 530-pattern ruleset".
   `scripts/v3_real_ruleset.py` already did the prefilter side with no judge calls and
   found the released ruleset is the NARROWER prefilter here (fires on 0.612 of malicious
   clean artifacts against our 0.909, covers 0.378 against 0.692). This arm supplies the
   judge side.

2. `fullfile` -- ONE untruncated call on the whole artifact. The attack review's
   "obvious defense the paper did not test": section 2 quotes the prior art's mitigation as
   "full-file or chunked review", the paper instantiates only the chunked branch, and its
   own numbers favour a single read on clean inputs (`clean` 0.048 for `none` against
   0.091 for `dedup_full`). Every attacked artifact here is 1.9k-23k characters, inside
   every judge's context window, so the single read is available and was never measured.

CRITICAL: `pilot_audit2.call` truncates every prompt to `WINDOW = 8000` characters. That
truncation is the thing this paper attacks, so `fullfile` would be measuring the 8000-char
reader if the cap were left in place. This module raises `A.WINDOW` for its own process and
asserts the artifact survived. Nothing else in the project is affected, because that global
is read at call time inside this process only.

Routing follows the published runs so the reader is the only thing that changed: the five
main judges keep their existing transports (gpt-4o-mini and gpt-4o on OpenAI,
claude-haiku-4.5 and gemini-2.5-flash-lite on OpenRouter, qwen3:8b local), and the four
frontier judges go to the Anthropic API direct under the bare ids `claude-sonnet-5-5`,
`claude-opus-5-5`, `claude-haiku-5-5` -- which is where the bare ids in
`followup_results/exp2_cells.csv` came from -- with `gpt-5.1` on OpenRouter.

usage:
  python -I scripts/v3_newreaders.py plan                   # no calls at all
  python -I scripts/v3_newreaders.py smoke                  # one call per judge
  python -I scripts/v3_newreaders.py run <sel> <max_usd>    # sel: main|frontier|all
"""
import ast
import csv
import hashlib
import json
import os
import re
import sys
import threading
import time
import urllib.error
import urllib.request
from concurrent.futures import ThreadPoolExecutor

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import pandas as pd
import pilot_audit2 as A
import pilot_dil2 as D
import v2_skillgate as SG

sys.stdout.reconfigure(encoding="utf-8", errors="replace")

# ---------------------------------------------------------------- the truncation cap
_ORIG_WINDOW = A.WINDOW
A.WINDOW = 10 ** 9          # see the module docstring; without this `fullfile` is trunc8k

ROOT = A.ROOT
PATDIR = os.path.join(ROOT, "data", "skillgate_patterns")
OUTDIR = os.path.join(ROOT, "followup_results")
ROWS_FP = os.path.join(OUTDIR, "v3_newreaders_cells.csv")
FIELDS = ["judge", "skill_hash", "arm", "attack", "reader", "ruleset_n", "payload_len",
          "artifact_len", "n_hits", "prompt_len", "n_calls", "saturated", "covered",
          "verdict"]
GOOD = ("SAFE", "MALICIOUS")

ATTACKS7 = ["clean", "d_real", "uniq_pad_20k", "neardup_10k", "topical_10k",
            "gap_il_4x2600", "il_matched"]
ATTACKS2 = ["clean", "il_matched"]
READERS = ["skillgate530", "fullfile"]

MAIN = ["gpt-4o-mini", "qwen3:8b", "google/gemini-2.5-flash-lite",
        "anthropic/claude-haiku-4.5", "gpt-4o"]
FRONTIER = ["claude-sonnet-5-5", "claude-opus-5-5", "claude-haiku-5-5", "openai/gpt-5.1"]

# published $/1M (input, output). OpenRouter rows from its live /models endpoint on
# 2026-11-06; Anthropic rows are that provider's list price for the same models.
RATES = {
    "gpt-4o-mini":                  (0.15, 0.60),
    "gpt-4o":                       (2.50, 10.00),
    "qwen3:8b":                     (0.00, 0.00),
    "google/gemini-2.5-flash-lite": (0.10, 0.40),
    "anthropic/claude-haiku-4.5":   (1.00, 5.00),
    "openai/gpt-5.1":               (1.25, 10.00),
    "claude-haiku-5-5":             (0.10, 0.50),
    "claude-sonnet-5-5":            (2.00, 10.00),
    "claude-opus-5-5":              (4.00, 20.00),
}
# a cap per provider, so one runaway arm cannot drain a balance that another arm needs
PROVIDER_CAP = {"anthropic": 90.0, "openrouter": 43.0, "openai": 28.0, "local": 0.0}
BENIGN_N = 2983


def provider(m):
    if m.startswith("claude-"):
        return "anthropic"
    if ":" in m and "/" not in m:
        return "local"
    return "openrouter" if "/" in m else "openai"


# ---------------------------------------------------------------- the released ruleset
def _extract(path, var):
    """Pull element [1] of every tuple in a top-level list assignment, by walking the AST.
    The two files are third-party downloads that import from a package which is not here,
    and one is 107 KB of regex: they are parsed, never imported or executed."""
    out = []
    tree = ast.parse(open(path, encoding="utf-8").read(), filename=path)
    for node in tree.body:
        tg = (node.targets if isinstance(node, ast.Assign)
              else [node.target] if isinstance(node, ast.AnnAssign) else [])
        if not any(isinstance(t, ast.Name) and t.id == var for t in tg):
            continue
        if isinstance(node.value, ast.List):
            for e in node.value.elts:
                if isinstance(e, ast.Tuple) and len(e.elts) >= 2 \
                        and isinstance(e.elts[0], ast.Constant) \
                        and isinstance(e.elts[1], ast.Constant):
                    out.append((e.elts[0].value, e.elts[1].value))
    return out


def load_ruleset(d=PATDIR):
    raw = (_extract(os.path.join(d, "attack_patterns.py"), "ATTACK_PATTERNS")
           + _extract(os.path.join(d, "sigma_patterns.py"), "SIGMA_PATTERNS"))
    live, dropped = [], []
    for pid, pat in raw:
        try:
            live.append(re.compile(pat, re.IGNORECASE | re.MULTILINE))
        except re.error as e:
            dropped.append((pid, str(e)))      # their own loader does exactly this
    return live, dropped, len(raw)


RULES, DROPPED, RAW_N = load_ruleset()
RULESET_N = len(RULES)

CW, MS = 500, 20            # SkillGate's own geometry: 500 chars each side, first 20 windows


def skillgate530(art):
    """(prompt or None, n_hits). None means the prefilter did not fire, which in the
    deployed design means no call and a clean verdict."""
    spans = []
    for rx in RULES:
        for m in rx.finditer(art):
            spans.append((max(0, m.start() - CW), min(len(art), m.end() + CW)))
    if not spans:
        return None, 0
    nh = len(spans)
    spans.sort()
    merged = [list(spans[0])]
    for s, e in spans[1:]:
        if s <= merged[-1][1]:
            merged[-1][1] = max(merged[-1][1], e)
        else:
            merged.append([s, e])
    body = "\n---\n".join(art[s:e] for s, e in merged[:MS])
    return SG.PREAMBLE + "\n\n" + body, nh


def fullfile(art):
    return art, -1          # -1 marks "no prefilter", as the harness does for trunc readers


def reader(name, art):
    if name == "skillgate530":
        p, nh = skillgate530(art)
        return ([] if p is None else [p]), nh
    return [art], -1


def covered(name, segs):
    """Share of payload characters the reader actually puts in front of the judge, by the
    same 50-character probe walk the harness uses, so the two are comparable."""
    total = sum(len(t) for t, f in segs if f)
    if not total:
        return ""
    prompts, _ = reader(name, "".join(t for t, _ in segs))
    if not prompts:
        return 0.0
    seen = prompts[0]
    got = 0
    for t, f in segs:
        if not f:
            continue
        for i in range(0, len(t), 50):
            c = t[i:i + 50]
            if c and c in seen:
                got += len(c)
    return round(got / total, 4)


# ---------------------------------------------------------------- Anthropic transport
_ant_lock = threading.Lock()
_ant_last = [0.0]
ANT_MIN_INTERVAL = 0.08


def anthropic_call(model, text):
    """Messages API. Mirrors pilot_audit2.call's verdict parsing and usage accounting so
    the two paths are scored identically, and returns '?' when no verdict can be read --
    which is how a refusal reaches the caller."""
    # No `temperature`. The API rejects it outright for this family -- HTTP 400,
    # "`temperature` is deprecated for this model" -- which is why section 8 records that
    # "The Claude 5 judges run at the API's default sampling, because that family rejects
    # an explicit temperature setting". Sending it is how this arm failed its smoke test.
    body = json.dumps({
        "model": model, "max_tokens": 200,
        "system": A.SCAN_SYS,
        "messages": [{"role": "user",
                      "content": "SKILL CONTENT:\n" + text[:A.WINDOW] + "\n\nClassify."}],
    }).encode()
    req = urllib.request.Request(
        "https://api.anthropic.com/v1/messages", data=body, method="POST",
        headers={"x-api-key": os.environ["ANTHROPIC_API_KEY"],
                 "anthropic-version": "2023-06-01",
                 "content-type": "application/json"})
    for a in range(6):
        try:
            with _ant_lock:
                w = ANT_MIN_INTERVAL - (time.time() - _ant_last[0])
                if w > 0:
                    time.sleep(w)
                _ant_last[0] = time.time()
            with urllib.request.urlopen(req, timeout=120) as r:
                o = json.loads(r.read())
            u = o.get("usage", {})
            with A._lock:
                d = A._usage.setdefault(model, {"in": 0, "out": 0})
                d["in"] += u.get("input_tokens", 0)
                d["out"] += u.get("output_tokens", 0)
            content = "".join(b.get("text", "") for b in o.get("content", [])
                              if b.get("type") == "text")
            v = ""
            m = re.search(r"\{.*\}", content, re.S)
            if m:
                try:
                    v = str(json.loads(m.group(0)).get("verdict", "")).upper()
                except Exception:
                    v = ""
            if not v:
                m2 = re.search(r'"?verdict"?\s*[:=]\s*"?([A-Za-z]+)', content)
                v = m2.group(1).upper() if m2 else ""
            return "MALICIOUS" if "MAL" in v else "SAFE" if "SAFE" in v else "?"
        except urllib.error.HTTPError as e:
            if e.code in (429, 500, 502, 503, 529):
                time.sleep(1.5 * (a + 1))
                continue
            return "HTTP%d" % e.code
        except Exception:
            time.sleep(1.5 * (a + 1))
    return "ERR"


def call_any(model, text):
    return anthropic_call(model, text) if provider(model) == "anthropic" \
        else A.call(model, text)


_cache_lock = threading.Lock()
_cache = {}


def judge(model, text):
    k = (model, hashlib.md5(text.encode("utf-8", "replace")).hexdigest())
    with _cache_lock:
        if k in _cache:
            return _cache[k]
    v = call_any(model, text)
    if v in GOOD or v == "?":
        with _cache_lock:
            _cache[k] = v
    return v


def or_scan(model, prompts):
    """A refusal is recorded as its own outcome, never folded into SAFE or MALICIOUS."""
    if not prompts:
        return "SAFE", 0            # prefilter silent: no call, clean verdict
    vs = [judge(model, p) for p in prompts]
    if any(v not in GOOD and v != "?" for v in vs):
        return "ERR", len(prompts)
    if "MALICIOUS" in vs:
        return "MALICIOUS", len(prompts)
    if any(v == "?" for v in vs):
        return "REFUSAL", len(prompts)
    return "SAFE", len(prompts)


def spend(model=None):
    tot = 0.0
    for m, u in A._usage.items():
        if model and m != model:
            continue
        ri, ro = RATES.get(m, (0.0, 0.0))
        tot += (u["in"] * ri + u["out"] * ro) / 1e6
    return tot


def spend_by_provider():
    out = {}
    for m, u in A._usage.items():
        ri, ro = RATES.get(m, (0.0, 0.0))
        out[provider(m)] = out.get(provider(m), 0.0) + (u["in"] * ri + u["out"] * ro) / 1e6
    return out


# ---------------------------------------------------------------- the grid
def benign_union():
    """The union of the two 1500-skill draws, which is the 2983 the published
    false-positive rates are over.

    The two draws dedup to 2984, one more than the published 2983. The extra skill is
    `84db57956e5f744702553e931495048c`, item S0367 in audit/key/key.csv: a MalSkillBench
    *malicious* artifact, stratum A, human+runtime evidence, 283 characters, carrying an
    `IMPORTANT READ! <system>` injection. It is present in the SkillMD-138K benign parquet
    as well, so a naive draw pulls it into the benign arm.

    The published run excluded it, but by accident rather than by design: v2_skillgate's
    resume key is (MODEL, hash, attack, reader) with no arm, so the malicious `clean` cell
    for the same hash and reader, which ran first, suppressed the benign one. Excluding it
    is nonetheless the right answer -- a known-malicious artifact cannot sit in a
    false-positive denominator -- so it is excluded here deliberately and by name, and the
    denominator stays comparable to the published rates. Any additional overlap would be
    caught by the assertion rather than silently dropped.
    """
    contaminated = {"84db57956e5f744702553e931495048c"}
    bn = pd.read_parquet(A.BENIGN_FP, columns=["content"])["content"].dropna().astype(str)
    a = bn.sample(n=1500, random_state=D.SEED).tolist()
    b = bn.sample(n=1500, random_state=D.SEED + 1).tolist()
    seen, out, dropped = set(), [], []
    for t in a + b:
        h = D.skill_hash(t)
        if h in seen:
            continue
        seen.add(h)
        (dropped if h in contaminated else out).append((h, t))
    assert len(out) == BENIGN_N, (
        f"benign union is {len(out)} after dropping {len(dropped)}, expected {BENIGN_N}; "
        "the draw or the parquet changed -- do not run a priced arm against it")
    return out


def jobs_for(sel):
    """`sel` is <who>[:<arm>]. who: main | frontier | all | qwen | hosted | pubben.
    arm: mal | ben, both when omitted. The grid is 62k cells and the benign arm is 86% of
    it, so it is run in phases that can each be reported and resumed rather than as one
    half-day job."""
    who, _, arm = sel.partition(":")
    A.load_pool()
    assert len(A._POOL) >= 100, "filler pool too small"
    want_mal = arm in ("", "mal")
    want_ben = arm in ("", "ben")
    sets = {"main": MAIN, "frontier": FRONTIER, "all": MAIN + FRONTIER,
            "qwen": ["qwen3:8b"],
            "hosted": [m for m in MAIN + FRONTIER if m != "qwen3:8b"],
            # Exactly the judges the published benign arm covers, which is also exactly the
            # five rows of the paper's frontier table that carry a benign FPR. Table 3 has
            # no benign column, so the other four judges have no published rate for a new
            # reader to be compared against, and running them would buy nothing. Ordered by
            # measured cost, cheapest first: run() maps workers over this order, so the
            # load-bearing rate (gpt-4o-mini, the 0.101 the paper quotes) lands in minutes
            # rather than behind forty dollars of opus.
            "pubben": ["gpt-4o-mini", "claude-haiku-5-5", "openai/gpt-5.1",
                       "claude-sonnet-5-5", "claude-opus-5-5"]}
    if who not in sets:
        raise SystemExit(f"who must be one of {sorted(sets)}; got {who!r}")
    chosen = sets[who]
    mini_set = SG.caught_set(A.MINI) if any(m in FRONTIER for m in chosen) else None
    ben = benign_union() if want_ben else []
    jobs = []
    for m in chosen:
        atks = ATTACKS2 if m in FRONTIER else ATTACKS7
        if want_mal:
            cs = mini_set if m in FRONTIER else SG.caught_set(m)
            for h, S in cs:
                sd = D.md5seed(S, "p3")
                for atk in atks:
                    for rd in READERS:
                        jobs.append((m, "mal", h, S, atk, sd, rd))
        for h, B in ben:
            for rd in READERS:
                jobs.append((m, "ben", h, B, "clean", 0, rd))
    return jobs


def shard_paths():
    """Every `v3_newreaders_cells*.csv` in followup_results. Two jobs must never append to
    one file -- buffered appends from separate processes interleave mid-line -- so each run
    writes its own shard and resume reads them all."""
    return [os.path.join(OUTDIR, f) for f in sorted(os.listdir(OUTDIR))
            if f.startswith("v3_newreaders_cells") and f.endswith(".csv")]


def done_set():
    dn = set()
    for fp in shard_paths():
        try:
            p = pd.read_csv(fp, dtype={"skill_hash": str})
        except Exception:
            continue
        dn |= {(r.judge, str(r.skill_hash), r.arm, r.attack, r.reader)
               for r in p.itertuples(index=False)
               if r.verdict in GOOD or r.verdict == "REFUSAL"}
    return dn


def segments(arm, S, atk, sd):
    return [(S, 0)] if arm == "ben" else SG.segments_for(S, atk, sd)


# ---------------------------------------------------------------- modes
def plan(sel):
    print(f"ruleset: {RULESET_N} live patterns of {RAW_N} parsed, "
          f"{len(DROPPED)} dropped as invalid regex "
          f"({', '.join(p for p, _ in DROPPED) or 'none'})")
    print(f"A.WINDOW raised {_ORIG_WINDOW} -> {A.WINDOW} for this process\n")
    js = jobs_for(sel)
    dn = done_set()
    todo = [j for j in js if (j[0], j[2], j[1], j[4], j[6]) not in dn]
    print(f"grid: {len(js)} cells, {len(dn)} already complete, {len(todo)} to run\n")
    by = {}
    for m, arm, h, S, atk, sd, rd in todo:
        by[(m, rd, arm)] = by.get((m, rd, arm), 0) + 1
    print(f"{'judge':30s} {'reader':14s} {'arm':4s} {'cells':>7} {'provider':>11}")
    for (m, rd, arm), n in sorted(by.items()):
        print(f"{m:30s} {rd:14s} {arm:4s} {n:7d} {provider(m):>11}")
    print()
    # one prompt per (reader, attack) so sizes and the payload assertion are checked
    print("prompt sizes, built without calling anything")
    _, S0 = SG.caught_set(A.MINI)[0]
    sd0 = D.md5seed(S0, "p3")
    for atk in ATTACKS7:
        segs = SG.segments_for(S0, atk, sd0)
        art = "".join(t for t, _ in segs)
        assert S0 in art or atk in ("il_matched", "gap_il_4x2600"), "payload lost"
        row = []
        for rd in READERS:
            ps, nh = reader(rd, art)
            row.append(f"{rd}={len(ps[0]) if ps else 0}")
        print(f"  {atk:16s} artifact={len(art):6d}  " + "  ".join(row))
    print()
    print("every judge id resolves to a provider and a rate:")
    for m in MAIN + FRONTIER:
        ok = "rate ok" if m in RATES else "NO RATE"
        print(f"  {m:30s} {provider(m):>11}  {ok}")
    miss = [m for m in MAIN + FRONTIER if m not in RATES]
    if miss:
        print("\nFAIL: no published rate for", miss)
        return 1
    if not os.environ.get("ANTHROPIC_API_KEY"):
        print("\nFAIL: ANTHROPIC_API_KEY is not set")
        return 1
    print("\nper-provider caps:", PROVIDER_CAP)
    print("dry run complete. No request was issued.")
    return 0


def smoke():
    """One real call per judge on a tiny benign string: proves transport, auth, model id
    and verdict parsing. Costs a fraction of a cent."""
    probe = ("# Hello\n\nThis skill prints a greeting. Usage: run `echo hello`.\n")
    print("one call per judge, tiny prompt\n")
    bad = []
    for m in MAIN + FRONTIER:
        t0 = time.time()
        v = call_any(m, probe)
        ok = v in GOOD or v == "?"
        print(f"  {m:30s} {provider(m):>11}  -> {v:10s} "
              f"{time.time() - t0:5.1f}s  {'ok' if ok else 'FAIL'}")
        if not ok:
            bad.append((m, v))
    print(f"\nspend so far: ${spend():.4f}  {spend_by_provider()}")
    if bad:
        print("FAIL:", bad)
        return 1
    print("all transports good.")
    return 0


def run(sel, max_usd, shard="", hosted_workers=4):
    js = jobs_for(sel)
    dn = done_set()
    todo = [j for j in js if (j[0], j[2], j[1], j[4], j[6]) not in dn]
    out = os.path.join(OUTDIR, f"v3_newreaders_cells{shard}.csv")
    print(f"{len(todo)} cells to run -> {os.path.basename(out)}, "
          f"global cap ${max_usd:.2f}, per-provider caps {PROVIDER_CAP}", flush=True)
    if not todo:
        print("nothing to do")
        return 0
    new = not os.path.exists(out)
    fh = open(out, "a", newline="", encoding="utf-8")
    wr = csv.writer(fh)
    if new:
        wr.writerow(FIELDS)
    lock = threading.Lock()
    stop = threading.Event()
    n = [0]
    t0 = time.time()

    def work(j):
        m, arm, h, S, atk, sd, rd = j
        if stop.is_set():
            return
        segs = segments(arm, S, atk, sd)
        art = "".join(t for t, _ in segs)
        if arm == "mal":
            assert S in art or atk in ("il_matched", "gap_il_4x2600"), "payload lost"
        prompts, hits = reader(rd, art)
        if rd == "fullfile" and prompts:
            assert len(prompts[0]) == len(art), "fullfile prompt was truncated"
        verdict, ncalls = or_scan(m, prompts)
        cov = covered(rd, segs) if arm == "mal" else ""
        with lock:
            wr.writerow([m, h, arm, atk, rd, RULESET_N, len(S), len(art), hits,
                         len(prompts[0]) if prompts else 0, ncalls,
                         1 if (rd == "skillgate530" and hits >= MS) else 0,
                         cov, verdict])
            n[0] += 1
            if n[0] % 50 == 0:
                fh.flush()
                sp = spend()
                print(f"  {n[0]}/{len(todo)}  ${sp:.2f}  "
                      f"{(time.time() - t0) / 60:.1f}m  {spend_by_provider()}", flush=True)
            if spend() >= max_usd:
                print(f"  global cap ${max_usd:.2f} reached, stopping", flush=True)
                stop.set()
            for p, v in spend_by_provider().items():
                if v >= PROVIDER_CAP.get(p, 0.0) and p != "local":
                    print(f"  {p} cap ${PROVIDER_CAP[p]:.2f} reached, stopping", flush=True)
                    stop.set()

    # Hosted judges FIRST. The local judge has one GPU and one worker, so its ~1700 cells
    # take about 1.7 hours; putting it first leaves every paid judge -- and every number the
    # paper's tables need -- queued behind a free one. Run `qwen:mal` as its own job in
    # parallel instead, which costs nothing but GPU.
    # `hosted_workers` is a parameter because the benign arm is 29,830 cells against the
    # malicious arm's 3,540: at the four workers that arm used, 44 cells a minute, it would
    # take eleven hours. A 429 is not lost work either way -- done_set() counts only GOOD
    # and REFUSAL, so an errored cell is simply re-run on resume.
    for group, workers in (([m for m in MAIN + FRONTIER if m != "qwen3:8b"], hosted_workers),
                           (["qwen3:8b"], 1)):
        part = [j for j in todo if j[0] in group]
        if not part:
            continue
        with ThreadPoolExecutor(max_workers=workers) as ex:
            list(ex.map(work, part))
        if stop.is_set():
            break
    fh.close()
    print(f"\nwrote {n[0]} cells to {out}")
    print(f"spend ${spend():.2f}  {spend_by_provider()}")
    return 0


if __name__ == "__main__":
    mode = sys.argv[1] if len(sys.argv) > 1 else "plan"
    if mode == "plan":
        sys.exit(plan(sys.argv[2] if len(sys.argv) > 2 else "all"))
    if mode == "smoke":
        sys.exit(smoke())
    if mode == "run":
        sys.exit(run(sys.argv[2] if len(sys.argv) > 2 else "all",
                     float(sys.argv[3]) if len(sys.argv) > 3 else 5.0,
                     sys.argv[4] if len(sys.argv) > 4 else "",
                     int(sys.argv[5]) if len(sys.argv) > 5 else 4))
    sys.exit("modes: plan | smoke | run <who[:arm]> <max_usd> [shard] [workers]")
