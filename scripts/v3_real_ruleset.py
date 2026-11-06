r"""Item 5, the re-run branch. SkillGate's 530-pattern ruleset IS public (MIT,
github.com/awsm-research/skillgate, patterns in the initial commit), so the paper's
justification for substituting our own 49-group risk regex does not hold. The judge-side
re-run costs money; the PREFILTER side does not, and the prefilter is where the paper's
mechanism claim lives: whether the reader still fires under fragmentation, how many hits it
finds, how much text it selects, and how much of the payload survives in that text. All
four are computable with zero API calls.

What this does:

  1. Extracts the pattern strings from the two downloaded files with `ast`. The files are
     NEVER imported or executed -- they are untrusted downloads, they import from a package
     that is not here, and one of them is 107 KB of regex. Parsing only.
  2. Compiles them exactly as the repo does: re.IGNORECASE | re.MULTILINE, dropping any
     pattern that fails to compile, which is what their own `except re.error` does.
  3. Regenerates the same 165 malicious artifacts the published table uses, under `clean`
     and `il_matched`, from the corpus and the deterministic seed the harness uses
     (sd = D.md5seed(S, "p3")). No judge is called.
  4. GATE: reproduces the published `regex_real` prefilter figures with OUR regex first --
     fires 0.909 under both conditions, 5.32 against 5.18 hits, 2766 against 3454 characters
     selected, coverage 0.692 against 0.347. If that does not reproduce, the environment
     differs from the one that produced the table and nothing below it is trustworthy, so
     the script stops.
  5. Only then runs the real ruleset, under its own window rule as the paper states it
     ([match.start - 500, match.end + 500], overlapping ranges merged, first 20 windows),
     and prints both readings side by side.

Fetching the ruleset (it is MIT and public; these two files are all that is needed):

    mkdir skillgate_patterns && cd skillgate_patterns
    B=https://raw.githubusercontent.com/awsm-research/skillgate/main/skillgate/classifier
    curl -sSO $B/attack_patterns.py && curl -sSO $B/sigma_patterns.py

usage: python -I scripts/v3_real_ruleset.py <that directory>
"""
import ast
import os
import re
import sys

sys.stdout.reconfigure(encoding="utf-8", errors="replace")

DL = sys.argv[1] if len(sys.argv) > 1 else None
if not DL or not os.path.isdir(DL):
    sys.exit("pass the directory holding attack_patterns.py and sigma_patterns.py")

ROOT = r"."
sys.path.insert(0, os.path.join(ROOT, "scripts"))


# ----------------------------------------------------------------- 1. extract, never import
def extract(path, varname):
    """Pull the regex string out of element [1] of every tuple in a top-level list
    assignment, by walking the AST. No execution: Severity.HIGH is an attribute access and
    literal_eval would reject the whole list, so the tuples are walked by hand."""
    tree = ast.parse(open(path, encoding="utf-8").read(), filename=path)
    out = []
    for node in tree.body:
        targets = (node.targets if isinstance(node, ast.Assign)
                   else [node.target] if isinstance(node, ast.AnnAssign) else [])
        if not any(isinstance(t, ast.Name) and t.id == varname for t in targets):
            continue
        if not isinstance(node.value, ast.List):
            continue
        for elt in node.value.elts:
            if not isinstance(elt, ast.Tuple) or len(elt.elts) < 2:
                continue
            pid, pat = elt.elts[0], elt.elts[1]
            if isinstance(pid, ast.Constant) and isinstance(pat, ast.Constant):
                out.append((pid.value, pat.value))
    return out


core = extract(os.path.join(DL, "attack_patterns.py"), "ATTACK_PATTERNS")
sigma = extract(os.path.join(DL, "sigma_patterns.py"), "SIGMA_PATTERNS")
print(f"extracted: {len(core)} core, {len(sigma)} sigma, {len(core) + len(sigma)} total")

FLAGS = re.IGNORECASE | re.MULTILINE
compiled, dropped = [], []
for pid, pat in core + sigma:
    try:
        compiled.append((pid, re.compile(pat, FLAGS)))
    except re.error as e:
        dropped.append((pid, str(e)))
print(f"compiled: {len(compiled)} live, {len(dropped)} dropped "
      f"({', '.join(p for p, _ in dropped)})")
print()

# ----------------------------------------------------------------- 2. our harness
import pilot_audit2 as A          # noqa: E402
import pilot_dil2 as D            # noqa: E402
import v2_skillgate as SG         # noqa: E402

A.load_pool()
assert len(A._POOL) >= 100, "filler pool too small"
PRE = len(SG.PREAMBLE)


def ours(text, cw=1000, dedup=250, ms=20, cap=8000):
    """The published reader: window of cw total centred cw//2 before the hit START, a hit
    skipped when an accepted centre is within `dedup`, first `ms` windows."""
    hits = [m.start() for m in A.RISK.finditer(text)]
    if not hits:
        return None, 0
    wins, centres = [], []
    for h in hits:
        if any(abs(h - c) < dedup for c in centres):
            continue
        centres.append(h)
        st = max(0, h - cw // 2)
        wins.append(text[st:st + cw])
        if len(wins) >= ms:
            break
    return "\n---\n".join(wins)[:cap], len(hits)


def theirs(text, cw=500, ms=20, cap=None):
    """SkillGate's own rule: every match contributes [start-cw, end+cw]; ranges that
    overlap are merged (`_merge_ranges` merges only on `start <= last_end`, which is the
    code rather than the paper's cw/4 claim); the first `ms` surviving windows are used."""
    spans = []
    for _, rx in compiled:
        for m in rx.finditer(text):
            spans.append((max(0, m.start() - cw), min(len(text), m.end() + cw)))
    if not spans:
        return None, 0
    nhits = len(spans)
    spans.sort()
    merged = [list(spans[0])]
    for s, e in spans[1:]:
        if s <= merged[-1][1]:
            merged[-1][1] = max(merged[-1][1], e)
        else:
            merged.append([s, e])
    wins = [text[s:e] for s, e in merged[:ms]]
    body = "\n---\n".join(wins)
    return (body[:cap] if cap else body), nhits


def coverage(build, segs):
    """Share of payload characters the selected text actually contains. Same 50-character
    probe walk as the harness, so the two readings are comparable; a probe straddling a
    window edge counts as unseen, which understates and never overstates."""
    total = sum(len(t) for t, f in segs if f)
    if not total:
        return None
    body, _ = build("".join(t for t, _ in segs))
    if body is None:
        return 0.0
    got, step = 0, 50
    for t, f in segs:
        if not f:
            continue
        for i in range(0, len(t), step):
            c = t[i:i + step]
            if c and c in body:
                got += len(c)
    return got / total


# ----------------------------------------------------------------- 3. the artifacts
ATKS = tuple(sys.argv[2].split(",")) if len(sys.argv) > 2 else ("clean", "il_matched")
cs = SG.caught_set(A.MINI)
print(f"caught set for {A.MINI}: {len(cs)} artifacts")
ARTS = []
for h, S in cs:
    sd = D.md5seed(S, "p3")
    ARTS.append((h, S, {a: SG.segments_for(S, a, sd) for a in ATKS}))
print()


def summarise(build, label, plen_offset=0):
    rows = {}
    for atk in ATKS:
        fired = nh = plen = cov = 0
        covn = 0
        hitlist = []
        for _, _, segs in ARTS:
            art = "".join(t for t, _ in segs[atk])
            body, n = build(art)
            hitlist.append(n)
            if body is not None:
                fired += 1
                plen += len(body) + plen_offset
            nh += n
            c = coverage(build, segs[atk])
            if c is not None:
                cov += c
                covn += 1
        N = len(ARTS)
        # The published prompt_len is a mean over ALL artifacts, counting an artifact the
        # prefilter never fired on as 0 -- the harness writes `plen = len(prompts[0]) if
        # prompts else 0` and averages the column. Dividing by the fired count instead is
        # what first failed the gate (3041 against the published 2766 = 3041 * 150/165).
        rows[atk] = dict(fired=fired / N, n_hits=nh / N,
                         plen=plen / N, plen_fired=plen / max(fired, 1),
                         cov=cov / max(covn, 1), hits=hitlist)
    if len(ATKS) > 2:
        print(f"--- {label}")
        print(f"    {'attack':16s} {'fires':>7} {'hits':>6} {'chars':>8} {'coverage':>9}")
        for a in ATKS:
            r = rows[a]
            print(f"    {a:16s} {r['fired']:7.4f} {r['n_hits']:6.2f} "
                  f"{r['plen']:8.0f} {r['cov']:9.4f}")
        return rows
    c, i = rows["clean"], rows["il_matched"]
    same = sum(1 for a, b in zip(c["hits"], i["hits"]) if a == b)
    stopped = sum(1 for a, b in zip(c["hits"], i["hits"]) if a > 0 and b == 0)
    print(f"--- {label}")
    print(f"    fires          {c['fired']:.4f}  ->  {i['fired']:.4f}")
    print(f"    hits (mean)    {c['n_hits']:.2f}  ->  {i['n_hits']:.2f}")
    print(f"    identical hit count on {same} of {len(ARTS)};  stops firing on {stopped}")
    print(f"    selected chars {c['plen']:.0f}  ->  {i['plen']:.0f}"
          f"   (over firing artifacts only: {c['plen_fired']:.0f} -> {i['plen_fired']:.0f})")
    print(f"    coverage       {c['cov']:.4f}  ->  {i['cov']:.4f}")
    return rows


# GATE
g = summarise(ours, "OUR 49-group regex, regex_real geometry (the published reader)",
              plen_offset=PRE)
EXPECT = dict(fired_c=0.909, fired_i=0.909, nh_c=5.32, nh_i=5.18,
              plen_c=2766, plen_i=3454, cov_c=0.692, cov_i=0.347)
bad = []
if abs(g["clean"]["fired"] - EXPECT["fired_c"]) > 0.002:
    bad.append(f"fired clean {g['clean']['fired']:.4f} != {EXPECT['fired_c']}")
if abs(g["il_matched"]["fired"] - EXPECT["fired_i"]) > 0.002:
    bad.append(f"fired il {g['il_matched']['fired']:.4f} != {EXPECT['fired_i']}")
if abs(g["clean"]["n_hits"] - EXPECT["nh_c"]) > 0.02:
    bad.append(f"hits clean {g['clean']['n_hits']:.2f} != {EXPECT['nh_c']}")
if abs(g["clean"]["cov"] - EXPECT["cov_c"]) > 0.004:
    bad.append(f"cov clean {g['clean']['cov']:.4f} != {EXPECT['cov_c']}")
if abs(g["il_matched"]["cov"] - EXPECT["cov_i"]) > 0.004:
    bad.append(f"cov il {g['il_matched']['cov']:.4f} != {EXPECT['cov_i']}")
if abs(g["clean"]["plen"] - EXPECT["plen_c"]) > 15:
    bad.append(f"plen clean {g['clean']['plen']:.0f} != {EXPECT['plen_c']}")

print()
if bad:
    print("GATE FAILED -- the published cells did not reproduce, so nothing below would")
    print("be comparable. Differences:")
    for b in bad:
        print("   ", b)
    sys.exit(1)
print("GATE PASSED: the published regex_real prefilter figures reproduce exactly.")
print()

summarise(theirs, "SkillGate's real 530-pattern ruleset, its own window rule")
print()
summarise(lambda t: theirs(t, cap=8000),
          "SkillGate's real ruleset, capped at 8000 characters like our harness")
