r"""Artifact integrity gate: do the SHIPPED tables still reproduce the PUBLISHED
prefilter cells?

Why this exists. The artifact promises that "every number recomputes offline", and several
scripts in this release gate themselves on reproducing a published cell before they print
anything derived from it (`v3_real_ruleset.py`, `v3_orgeom_verify.py`,
`v3_jointmiss_audit_score.py`). Those gates each cover one result. Nothing covered the
prefilter columns themselves -- firing rate, hit count, selected length, payload coverage --
which are the common ancestor of the mechanism claim, every ASR table at a content-addressed
reader, and the operating points. This script is that gate, over EVERY reader present in the
shipped data, and it is deliberately standalone: no project import, no model call, no
network, pure stdlib.

What it checks, and the three ways it can fail:

  FAIL     a published cell reproduces on neither convention. Hard error.
  BASIS    every cell reproduces, but two cells printed in the SAME published table are on
           different conventions for "selected characters" -- one counting the 674-character
           judge preamble and one not. A reader who recomputes the table from this artifact
           gets a different number for one column than for the other, which is exactly the
           failure this script exists to catch, so it is also a non-zero exit.
  DRIFT    two published copies of the same cell disagree between themselves. Reported, and
           non-zero only if neither copy reproduces.

The one assumption worth naming: the prefilter is judge-blind. A cell is keyed on
(reader, arm, attack, skill_hash) and every judge that saw that artifact recorded the same
prefilter columns, so the script asserts that invariant before it averages anything.

`data/skillgate_patterns/*.py` are untrusted third-party downloads. They are parsed with
`ast` and never imported, never executed, and never compiled as regex here -- the count of
patterns that COMPILE is taken from the shipped `ruleset_n` column, not by compiling them.

usage: python -I scripts/v3_artifact_integrity.py
       python -I scripts/v3_artifact_integrity.py --verbose
"""
import ast
import collections
import csv
import glob
import os
import sys

sys.stdout.reconfigure(encoding="utf-8", errors="replace")

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
FR = os.path.join(ROOT, "followup_results")
PATTERNS = os.path.join(ROOT, "data", "skillgate_patterns")
VERBOSE = "--verbose" in sys.argv

# The judge instruction that precedes the selected windows. The shipped `prompt_len`
# column is len(preamble) + len(selected text) on a firing artifact and 0 on a silent one,
# so "selected characters" has two defensible readings and the published tables use both.
PREAMBLE_LEN = 674

# Every published "characters selected" figure was produced by regenerating the artifacts
# (`v3_real_ruleset.py`) rather than by reading the shipped column, and the two assembly
# paths differ by a fixed small number of characters per FIRING artifact -- the same
# offset, in the same direction, at every reader and every attack. So a chars cell is
# checked against a tolerance scaled by the firing rate instead of a flat one, and the
# residual is reported rather than hidden. Anything beyond this is a hard failure.
ASSEMBLY_DRIFT = 2.5          # characters per firing artifact

FAILS, BASIS, DRIFT, NOTES = [], [], [], []
CHAR_DRIFT = []               # (label, published, recomputed, per-firing-artifact delta)


# ------------------------------------------------------------------ shipped data
def read(path):
    with open(path, newline="", encoding="utf-8") as fh:
        return list(csv.DictReader(fh))


def cellkey(r):
    return (r["reader"], r["arm"], r["attack"], r["skill_hash"])


PREFILTER_COLS = ("n_hits", "prompt_len", "covered")


def collapse(rows, src, require_blind=True):
    """One row per (reader, arm, attack, skill_hash), asserting judge-blindness.

    A failed call (`verdict == ERR`) still carries real prefilter columns, so ERR rows are
    kept for this purpose; what is NOT tolerated is two judges disagreeing about what the
    prefilter did on the same artifact, because every mean below would then depend on which
    judge happened to be loaded first.
    """
    out, clash = {}, []
    for r in rows:
        k = cellkey(r)
        prev = out.get(k)
        if prev is None:
            out[k] = r
        elif require_blind:
            for c in PREFILTER_COLS:
                if c in r and c in prev and r[c] != prev[c] and not (
                        r[c] == "" or prev[c] == ""):
                    clash.append((k, c, prev[c], r[c]))
    if clash:
        FAILS.append(f"{src}: the prefilter is not judge-blind on "
                     f"{len({c[0] for c in clash})} artifact(s); first clash "
                     f"{clash[0][0]} column {clash[0][1]}: "
                     f"{clash[0][2]!r} vs {clash[0][3]!r}")
    return out


def summarise(cells, reader, arm, attack, keep=None):
    """The four prefilter columns over the artifacts matching a cell description."""
    rows = [r for k, r in cells.items()
            if k[0] == reader and k[1] == arm and k[2] == attack
            and (keep is None or k[3] in keep)]
    if not rows:
        return None
    n = len(rows)

    def fired(r):
        if "fired" in r and r["fired"] != "":
            return int(r["fired"]) == 1
        return int(r["n_calls"]) > 0

    nf = sum(1 for r in rows if fired(r))
    hits = [int(r["n_hits"]) for r in rows]
    plen = sum(int(r["prompt_len"]) for r in rows)
    cov = [float(r["covered"]) for r in rows if r["covered"] not in ("", "nan")]
    has_ruleset = all(h >= 0 for h in hits)
    return dict(
        n=n, fired=nf,
        fires=nf / n,
        hits=(sum(hits) / n) if has_ruleset else None,
        # "prompt": as the column ships, preamble included, silent artifact counted as 0.
        # "body":   the selected text alone, which is what a caption saying "selected
        #           text" denotes. These differ by PREAMBLE_LEN on every firing artifact.
        chars_prompt=plen / n,
        chars_body=(plen - PREAMBLE_LEN * nf) / n,
        chars_prompt_fired=(plen / nf) if nf else 0.0,
        chars_body_fired=((plen - PREAMBLE_LEN * nf) / nf) if nf else 0.0,
        coverage=(sum(cov) / len(cov)) if cov else None,
        hitlist={k[3]: int(r["n_hits"]) for k, r in cells.items()
                 if k[0] == reader and k[1] == arm and k[2] == attack
                 and (keep is None or k[3] in keep)},
    )


def summarise_benign_aggregate(reader, attack="clean"):
    """The same four prefilter columns, rebuilt from the shipped aggregate sums.

    In a built artifact the benign arm's per-item rows are withheld by design, so
    `summarise` finds nothing and every published benign prefilter figure would read as a
    failure. `build_artifact.py` therefore ships aggregate sums per judge, reader and
    attack -- counts and totals over 2983 artifacts, which identify no artifact -- and this
    rebuilds the means from them. Returns None if those sums are absent too, in which case
    the caller degrades to a note rather than a failure.
    """
    agg = os.path.join(FR, "_benign_aggregate")
    if not os.path.isdir(agg):
        return None
    # The sums are per judge. The prefilter is judge-blind -- the script asserts that over
    # the malicious arm before reaching here -- so ONE judge's rows describe the arm, and
    # adding them across judges would give n = 2983 times the panel size.
    per = collections.defaultdict(lambda: [0, 0, 0, 0, 0, 0, 0.0])
    for p in sorted(glob.glob(os.path.join(agg, "*.prefilter.csv"))):
        with open(p, encoding="utf-8", newline="") as fh:
            for r in csv.DictReader(fh):
                if r.get("reader") != reader or r.get("attack", attack) != attack:
                    continue
                a = per[r.get("judge") or r.get("model") or ""]
                a[0] += int(r["n"])
                a[1] += int(r.get("n_fired") or 0)
                a[2] += int(r.get("sum_prompt_len") or 0)
                a[3] += int(r.get("n_hits_rows") or 0)
                a[4] += int(r.get("sum_n_hits") or 0)
                a[5] += int(r.get("n_covered") or 0)
                a[6] += float(r.get("sum_covered") or 0.0)
    if not per:
        return None
    n, nf, plen, hrows, hsum, ncov, csum = max(per.values(), key=lambda a: a[0])
    off = {j: a[0] for j, a in per.items() if a[0] != n}
    if off:
        NOTES.append(f"benign prefilter aggregate at {reader}: judges disagree on the "
                     f"artifact count ({n} against {sorted(set(off.values()))}), so the "
                     f"largest is used")
    return dict(
        n=n, fired=nf, fires=nf / n,
        hits=(hsum / hrows) if hrows else None,
        chars_prompt=plen / n,
        chars_body=(plen - PREAMBLE_LEN * nf) / n,
        chars_prompt_fired=(plen / nf) if nf else 0.0,
        chars_body_fired=((plen - PREAMBLE_LEN * nf) / nf) if nf else 0.0,
        coverage=(csum / ncov) if ncov else None,
        hitlist={},                      # per-artifact, and withheld with the rows
        from_aggregate=True,
    )


# ------------------------------------------------------------------ the published cells
# source, reader, attack, column, published value, tolerance, basis
#   basis is meaningful only for `chars`: "prompt" includes PREAMBLE_LEN, "body" does not.
MAL = [
    # Section 6.3 body text and tab:ruleset column 1, on the 165 gpt-4o-mini caught set.
    ("tab:ruleset/6.3", "regex_real",   "clean",      "fires",    0.909,  0.002, None),
    ("tab:ruleset/6.3", "regex_real",   "il_matched", "fires",    0.909,  0.002, None),
    ("tab:ruleset/6.3", "regex_real",   "clean",      "hits",     5.32,   0.02,  None),
    ("tab:ruleset/6.3", "regex_real",   "il_matched", "hits",     5.18,   0.02,  None),
    ("sec:position 6.3", "regex_real",  "clean",      "chars",    2766,   None,  "prompt"),
    ("sec:position 6.3", "regex_real",  "il_matched", "chars",    3454,   None,  "prompt"),
    ("tab:ruleset/6.3", "regex_real",   "clean",      "coverage", 0.692,  0.002, None),
    ("tab:ruleset/6.3", "regex_real",   "il_matched", "coverage", 0.347,  0.002, None),
    # tab:ruleset column 2, the released 530-pattern ruleset at its own window rule.
    ("tab:ruleset",     "skillgate530", "clean",      "fires",    0.612,  0.002, None),
    ("tab:ruleset",     "skillgate530", "il_matched", "fires",    0.873,  0.002, None),
    ("tab:ruleset",     "skillgate530", "clean",      "hits",     2.22,   0.02,  None),
    ("tab:ruleset",     "skillgate530", "il_matched", "hits",     3.19,   0.02,  None),
    # Restated on the prompt basis 2026-11-07, so that both halves of tab:ruleset's
    # "chars selected" row mean the same thing. They used to be 714 / 1865 on the selected
    # text alone while the left-hand columns were on the prompt as issued, a 674-character
    # difference per firing artifact that this script is what found.
    ("tab:ruleset",     "skillgate530", "clean",      "chars",    1128,   None,  "prompt"),
    ("tab:ruleset",     "skillgate530", "il_matched", "chars",    2455,   None,  "prompt"),
    ("tab:ruleset",     "skillgate530", "clean",      "coverage", 0.378,  0.002, None),
    ("tab:ruleset",     "skillgate530", "il_matched", "coverage", 0.281,  0.002, None),
    # Appendix sec:width, the superseded half-width reader. Published for the correction
    # it documents, so it has to keep reproducing or the correction is unverifiable.
    ("sec:width",       "skillgate",    "clean",      "coverage", 0.507,  0.002, None),
    # No window at all. Structural rather than measured, which is the point of checking it.
    ("sec:appruleset",  "fullfile",     "clean",      "fires",    1.000,  0.0,   None),
    ("sec:appruleset",  "fullfile",     "il_matched", "fires",    1.000,  0.0,   None),
    ("sec:appruleset",  "fullfile",     "clean",      "coverage", 1.000,  0.0,   None),
    ("sec:appruleset",  "fullfile",     "il_matched", "coverage", 1.000,  0.0,   None),
]

# A second published copy of two of the cells above: tab:ruleset prints them as well as the
# body text of 6.3. They disagreed until 2026-11-07 -- the table had been regenerated by
# `v3_real_ruleset.py` rather than read from the shipped column, and the two prompt-assembly
# paths differ by about two characters per firing artifact -- so the table was restated to
# the shipped value. Keep the check: it is what catches one copy being edited and not the
# other.
SECOND_COPY = [
    ("tab:ruleset", "regex_real", "clean",      "chars", 2766, "prompt"),
    ("tab:ruleset", "regex_real", "il_matched", "chars", 3454, "prompt"),
]

# The benign arm. n = 2983 per reader; `covered` is undefined with no payload.
BEN = [
    ("sec:regex '0.64 calls'",  "regex_real",   "fires", 0.644,  0.002),
    ("changelog 2026-11-06",    "skillgate530", "fires", 0.530,  0.002),
    ("changelog 2026-11-06",    "fullfile",     "fires", 1.000,  0.0),
]
BEN_CHARS_FIRED = [            # mean selected text over FIRING artifacts only
    ("v3_newreaders_benarm.txt", "regex_real",   4478, None, "prompt"),
    ("v3_newreaders_benarm.txt", "skillgate530", 3307, None, "prompt"),
]

STRUCTURAL = [
    # (label, reader, published value) -- artifacts whose hit count is unchanged by
    # fragmentation, and artifacts on which the prefilter stops firing. Both are load
    # bearing for the mechanism claim: the second being 0 is what retires "anchor denial".
    ("identical hit count, clean vs il_matched", "regex_real",   147),
    ("stops firing under il_matched",            "regex_real",   0),
    ("stops firing under il_matched",            "skillgate530", 0),
]


# ------------------------------------------------------------------ the checker
def check(label, got, want, tol, unit=""):
    ok = got is not None and abs(got - want) <= tol
    mark = "ok  " if ok else "FAIL"
    fmt = "%10.4f" if abs(want) < 10 else "%10.1f"
    print(f"  [{mark}] {label:58s} published {fmt % want}   "
          f"recomputed {'   none  ' if got is None else fmt % got}{unit}")
    if not ok:
        FAILS.append(f"{label}: published {want}, recomputed "
                     f"{'none' if got is None else round(got, 4)} (tolerance "
                     f"{round(tol, 2)})")
    return ok


def check_chars(label, got, want, scale):
    """A chars cell, tolerant of the fixed assembly offset and only of that.

    `scale` is the number of firing artifacts the published mean divides by, expressed as a
    share of the denominator: 1.0 for a mean over firing artifacts, the firing rate for a
    mean over all artifacts. The residual is then reported in characters per firing
    artifact, where it should be the same constant everywhere.
    """
    tol = ASSEMBLY_DRIFT * scale
    ok = check(label, got, want, tol)
    if got is not None and scale > 0 and abs(got - want) > 0.05 * scale:
        CHAR_DRIFT.append((label, want, got, (got - want) / scale))
    return ok


def main():
    print("=" * 96)
    print("ARTIFACT INTEGRITY: the published prefilter cells, recomputed from the shipped")
    print("tables alone. No project import, no model call, no network.")
    print("=" * 96)

    # ---------------------------------------------------------------- load
    geo_path = os.path.join(FR, "exp2_geometry.csv")
    cells_path = os.path.join(FR, "exp2_cells.csv")
    new_paths = sorted(glob.glob(os.path.join(FR, "v3_newreaders_cells*.csv")))
    for p in [geo_path, cells_path] + new_paths:
        if not os.path.exists(p):
            print(f"\nMISSING shipped table: {p}")
            return 2
    geo = collapse(read(geo_path), "exp2_geometry.csv")
    pub = collapse(read(cells_path), "exp2_cells.csv")
    new = collapse([r for p in new_paths for r in read(p)], "v3_newreaders_cells*.csv")
    shipped = dict(geo)
    shipped.update(new)

    readers = sorted({k[0] for k in shipped})
    print(f"\nshipped rows collapsed to artifact-level cells: "
          f"{len(geo):,} (exp2_geometry) + {len(new):,} (new readers); "
          f"{len(pub):,} judge-level cells cross-checked")
    print(f"readers present: {', '.join(readers)}")

    # The 165-artifact caught set the published malicious prefilter table is computed on,
    # taken from the shipped data rather than asserted.
    H165 = {k[3] for k in geo if k[0] == "regex_real" and k[1] == "mal"
            and k[2] == "clean"}
    if len(H165) != 165:
        FAILS.append(f"the gpt-4o-mini caught set is {len(H165)} artifacts, expected 165")
    print(f"malicious evaluation set: {len(H165)} artifacts (expected 165)")

    # ---------------------------------------------------------------- the ruleset itself
    print("\n" + "-" * 96)
    print("THE RULESET  (parsed with ast; the files are never imported or executed)")
    print("-" * 96)
    if os.path.isdir(PATTERNS):
        counts = {}
        for fn, var in (("attack_patterns.py", "ATTACK_PATTERNS"),
                        ("sigma_patterns.py", "SIGMA_PATTERNS")):
            fp = os.path.join(PATTERNS, fn)
            if not os.path.exists(fp):
                counts[var] = None
                continue
            with open(fp, encoding="utf-8") as fh:
                tree = ast.parse(fh.read(), filename=fp)
            found = 0
            for node in tree.body:
                tgts = (node.targets if isinstance(node, ast.Assign)
                        else [node.target] if isinstance(node, ast.AnnAssign) else [])
                if not any(isinstance(t, ast.Name) and t.id == var for t in tgts):
                    continue
                if not isinstance(node.value, ast.List):
                    continue
                for elt in node.value.elts:
                    if (isinstance(elt, ast.Tuple) and len(elt.elts) >= 2
                            and isinstance(elt.elts[0], ast.Constant)
                            and isinstance(elt.elts[1], ast.Constant)):
                        found += 1
            counts[var] = found
        check("core patterns declared (sec:appruleset: 428)",
              counts.get("ATTACK_PATTERNS"), 428, 0)
        check("sigma entries declared (428+105=533, 3 invalid)",
              counts.get("SIGMA_PATTERNS"), 105, 0)
    else:
        NOTES.append(f"{PATTERNS} is absent, so the declared pattern count is unchecked; "
                     "the shipped `ruleset_n` column is still verified below.")
        print(f"  [note] {PATTERNS} absent -- declared counts unchecked")

    rn = {r["ruleset_n"] for k, r in new.items() if k[0] == "skillgate530"}
    check("ruleset_n recorded on every skillgate530 cell (530)",
          float(next(iter(rn))) if len(rn) == 1 and next(iter(rn)) != "" else None,
          530, 0)

    # ---------------------------------------------------------------- malicious arm
    print("\n" + "-" * 96)
    print(f"MALICIOUS ARM: the {len(H165)} artifacts of Table 2's caught set, every reader")
    print("-" * 96)
    seen_basis = collections.defaultdict(set)
    tbl = {}
    for reader in readers:
        for attack in ("clean", "il_matched"):
            tbl[(reader, attack)] = summarise(shipped, reader, "mal", attack, H165)

    print(f"  {'reader':14s}{'attack':13s}{'n':>5s}{'fires':>8s}{'hits':>8s}"
          f"{'chars(prompt)':>15s}{'chars(body)':>13s}{'coverage':>10s}")
    for (reader, attack), s in sorted(tbl.items()):
        if s is None:
            continue
        print(f"  {reader:14s}{attack:13s}{s['n']:5d}{s['fires']:8.4f}"
              f"{('%8.2f' % s['hits']) if s['hits'] is not None else '     n/a'}"
              f"{s['chars_prompt']:15.1f}{s['chars_body']:13.1f}"
              f"{('%10.4f' % s['coverage']) if s['coverage'] is not None else '       n/a'}")
    print()

    for src, reader, attack, col, want, tol, basis in MAL:
        s = tbl.get((reader, attack))
        if s is None:
            FAILS.append(f"{src} {reader} mal/{attack}: no shipped rows at all")
            print(f"  [FAIL] {src} {reader} {attack} {col}: no shipped rows")
            continue
        if col == "chars":
            got = s["chars_prompt"] if basis == "prompt" else s["chars_body"]
            other = s["chars_body"] if basis == "prompt" else s["chars_prompt"]
            lab = f"{src} | {reader} {attack} chars [{basis}]"
            if check_chars(lab, got, want, s["fires"]):
                seen_basis[src].add(basis)
            elif abs(other - want) <= ASSEMBLY_DRIFT * s["fires"]:
                FAILS[-1] += (f" -- but it DOES match the other convention "
                              f"({'body' if basis == 'prompt' else 'prompt'}"
                              f" = {other:.1f}); the declared basis is wrong")
        else:
            check(f"{src} | {reader} {attack} {col}", s[col], want, tol)

    print("\n  a second published copy of two of the same cells:")
    for src, reader, attack, col, want, basis in SECOND_COPY:
        s = tbl[(reader, attack)]
        got = s["chars_prompt"] if basis == "prompt" else s["chars_body"]
        d = got - want
        print(f"  [drift] {src:12s} | {reader} {attack} {col} [{basis}]  "
              f"printed {want}, shipped {got:.1f}  (delta {d:+.1f})")
        if abs(d) > 1.5:
            DRIFT.append(f"{src} prints {reader} {attack} {col} = {want} where the shipped "
                         f"column gives {got:.1f} ({d:+.1f}), and the body text of the "
                         f"same paper prints the shipped value: two published copies of "
                         f"one cell, differing by the assembly offset below")
        seen_basis[src].add(basis)

    # structural invariants
    print("\n  structural invariants of the mechanism claim:")
    for lab, reader, want in STRUCTURAL:
        c = tbl.get((reader, "clean"))
        i = tbl.get((reader, "il_matched"))
        if not c or not i or c["hits"] is None:
            print(f"  [skip] {lab} at {reader}: no ruleset on this reader")
            continue
        hs = [(c["hitlist"][h], i["hitlist"][h]) for h in H165
              if h in c["hitlist"] and h in i["hitlist"]]
        got = (sum(1 for a, b in hs if a == b) if lab.startswith("identical")
               else sum(1 for a, b in hs if a > 0 and b == 0))
        check(f"{lab} at {reader} (of {len(hs)})", float(got), float(want), 0)

    # ---------------------------------------------------------------- benign arm
    print("\n" + "-" * 96)
    print("BENIGN ARM: the 2983-skill union, every reader that saw it")
    print("-" * 96)
    bt = {}
    for reader in readers:
        bt[reader] = (summarise(shipped, reader, "ben", "clean")
                      or summarise_benign_aggregate(reader))
    if any(v is not None and v.get("from_aggregate") for v in bt.values()):
        NOTES.append("the benign arm's per-item rows are withheld here, so its prefilter "
                     "figures come from the aggregate sums in "
                     "followup_results/_benign_aggregate/*.prefilter.csv")
    print(f"  {'reader':14s}{'n':>6s}{'fires':>8s}{'hits':>8s}"
          f"{'chars/artifact':>16s}{'chars/firing':>14s}")
    for reader, s in sorted(bt.items()):
        if s is None:
            continue
        if s["n"] != 2983:
            FAILS.append(f"benign arm at {reader} has n = {s['n']}, expected 2983")
        print(f"  {reader:14s}{s['n']:6d}{s['fires']:8.4f}"
              f"{('%8.2f' % s['hits']) if s['hits'] is not None else '     n/a'}"
              f"{s['chars_body']:16.1f}{s['chars_body_fired']:14.1f}")
    print()
    for src, reader, col, want, tol in BEN:
        s = bt.get(reader)
        check(f"{src} | {reader} benign {col}", None if s is None else s[col], want, tol)
    for src, reader, want, tol, basis in BEN_CHARS_FIRED:
        s = bt.get(reader)
        got = None if s is None else (s["chars_body_fired"] if basis == "body"
                                      else s["chars_prompt_fired"])
        if check_chars(f"{src} | {reader} benign chars/firing [{basis}]",
                       got, want, 1.0):
            seen_basis[src].add(basis)

    # ---------------------------------------------------------------- cross-check
    print("\n" + "-" * 96)
    print("CROSS-CHECK: exp2_cells.csv against exp2_geometry.csv on the shared reader")
    print("-" * 96)
    mism = 0
    for k, r in pub.items():
        if k[0] != "regex_real":
            continue
        g = geo.get(k)
        if g is None:
            continue
        for a, b in (("n_hits", "n_hits"), ("prompt_len", "prompt_len"),
                     ("covered", "covered")):
            if r[a] != "" and g[b] != "" and r[a] != g[b]:
                mism += 1
                if VERBOSE and mism <= 5:
                    print(f"  mismatch {k} {a}: cells={r[a]} geometry={g[b]}")
    shared = sum(1 for k in pub if k[0] == "regex_real" and k in geo)
    print(f"  {shared:,} cells appear in both tables; "
          f"{mism} column disagreement(s)")
    if mism:
        FAILS.append(f"exp2_cells.csv and exp2_geometry.csv disagree on {mism} prefilter "
                     f"column value(s) for the same artifact")

    # ---------------------------------------------------------------- verdict
    # within-table basis conflict, now that every chars cell has declared its convention
    for src, bases in sorted(seen_basis.items()):
        if len(bases) > 1:
            BASIS.append(f"{src} prints 'selected characters' on BOTH conventions at once "
                         f"({', '.join(sorted(bases))}); the two differ by "
                         f"{PREAMBLE_LEN} characters on every firing artifact, so the "
                         f"columns of one table are not comparable to each other")

    if CHAR_DRIFT:
        print("\n" + "-" * 96)
        print("THE ASSEMBLY OFFSET, which every chars cell carries and no other cell does")
        print("-" * 96)
        print(f"  {'cell':68s}{'pub':>8s}{'shipped':>10s}{'per firing artifact':>21s}")
        for lab, want, got, per in CHAR_DRIFT:
            print(f"  {lab[:68]:68s}{want:8.0f}{got:10.1f}{per:+21.2f}")
        pf = [p for _, _, _, p in CHAR_DRIFT]
        print(f"\n  residual spans {min(pf):+.2f} to {max(pf):+.2f} characters per firing "
              f"artifact. Its cause is")
        print("  that the shipped `prompt_len` column records about two characters more")
        print("  than `v3_real_ruleset.py`'s regeneration of the same prompt, so a cell")
        print("  quoted from the shipped column lands within rounding while one quoted")
        print("  from the regeneration carries the whole offset. Every published cell is")
        print("  now quoted from the shipped column, which is why the residual is small;")
        print("  it is printed rather than absorbed into a tolerance so that a reader")
        print("  recomputing from this artifact sees what we saw.")

    print("\n" + "=" * 96)
    for n in NOTES:
        print(f"NOTE   {n}")
    for d in DRIFT:
        print(f"DRIFT  {d}")
    for b in BASIS:
        print(f"BASIS  {b}")
    for f in FAILS:
        print(f"FAIL   {f}")
    print("=" * 96)
    if FAILS:
        print(f"INTEGRITY CHECK FAILED: {len(FAILS)} published cell(s) do not reproduce "
              f"from the shipped artifact. No derived number should be trusted until "
              f"these are resolved.")
        return 1
    if BASIS:
        print(f"INTEGRITY CHECK FAILED ON CONVENTION: every published cell reproduces, "
              f"but {len(BASIS)} published table mixes two definitions of 'selected "
              f"characters' across its own columns. The numbers are right and the table "
              f"is not self-consistent; fix the caption or restate one column.")
        return 1
    print("INTEGRITY CHECK PASSED: every published prefilter cell reproduces from the "
          "shipped tables, on one stated convention each.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
