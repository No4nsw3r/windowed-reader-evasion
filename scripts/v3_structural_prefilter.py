r"""Is the fragmentation attack visible to a check that never reads the payload?

WHY THIS SCRIPT EXISTS. Every defense this paper evaluates is a reader: it decides which
spans of an artifact to put in front of a judge. A reviewer on the attack axis pointed out
that the paper never considers the cheapest defense available against the attack it says
defeats every reader -- a check on whether the artifact is a well-formed `SKILL.md` at all
-- and that such a check appears to separate the interleaving conditions from real benign
bodies almost completely. If that is true it bounds the attack: interleaved fragmentation
survives every reader we built and does not survive looking at the file's shape.

WHAT THE CHECK IS. Six structural features, none of which reads the payload and none of
which is tuned on this corpus:

  h1          count of level-1 ATX headings. A real SKILL.md has one title.
  fence_odd   whether fenced code blocks are unbalanced.
  fm          count of YAML front-matter delimiters beyond the opening pair.
  blankrun    the longest run of blank lines.
  dupline     the share of non-blank lines that occur more than once in the file.
  stutter     count of places where a line ends mid-sentence and the next line starts a
              new block, which is what splicing filler between payload fragments does.

Each is computed on the artifact exactly as the reader receives it. The script reports
every feature's distribution on each condition and on real benign `SKILL.md` bodies, then
the simplest possible detector -- one threshold on one feature, chosen on the benign arm
alone at a 1% false-positive budget -- and what it catches.

HOW TO READ IT. A high catch rate here is a result against this paper's own attack, not
for it. The honest reading is the one the numbers support: if a one-feature check at a 1%
false-positive rate flags the fragmentation conditions, then the attack is a reader
problem and not a detection problem, and the paper's claim has to be scoped to readers.

No model calls, no API key, no network. Needs the benign corpus
(`python -I scripts/acquire_data.py`).

usage: python -I scripts/v3_structural_prefilter.py
"""
import collections
import os
import re
import statistics as st
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(ROOT, "scripts"))
sys.stdout.reconfigure(encoding="utf-8", errors="replace")

import pilot_audit2 as A            # noqa: E402
import pilot_dil2 as D              # noqa: E402
import v2_skillgate as SG           # noqa: E402
import v2_phase3_cross as X3        # noqa: E402

CONDS = ["clean", "d_real", "uniq_pad_20k", "uniq_suf_20k", "neardup_10k",
         "topical_10k", "gap_il_4x2600", "gap_il_6x3000", "il_matched", "il_heavy"]
FRAG = {"il_matched", "il_heavy", "gap_il_4x2600", "gap_il_6x3000"}
FEATS = ["h1", "fence_odd", "fm", "blankrun", "dupline", "stutter"]

_H1 = re.compile(r"^#\s+\S", re.M)
_FENCE = re.compile(r"^\s*(```|~~~)", re.M)
_FM = re.compile(r"^---\s*$", re.M)
_ENDS_MID = re.compile(r"[a-z0-9,;:\-]$")


def features(text):
    lines = text.split("\n")
    nonblank = [l.strip() for l in lines if l.strip()]
    c = collections.Counter(nonblank)
    dup = sum(n for v, n in c.items() if n > 1)
    run = best = 0
    for l in lines:
        run = run + 1 if not l.strip() else 0
        best = max(best, run)
    stutter = 0
    for i in range(len(lines) - 2):
        if (_ENDS_MID.search(lines[i].rstrip())
                and not lines[i + 1].strip()
                and lines[i + 2].strip()):
            stutter += 1
    return {"h1": len(_H1.findall(text)),
            "fence_odd": 1 if len(_FENCE.findall(text)) % 2 else 0,
            "fm": max(0, len(_FM.findall(text)) - 2),
            "blankrun": best,
            "dupline": (dup / len(nonblank)) if nonblank else 0.0,
            "stutter": stutter}


def main():
    A.load_pool()
    skills = SG.caught_set(A.MINI)
    assert len(skills) == 165, len(skills)

    # ---- the attack artifacts
    vals = {c: collections.defaultdict(list) for c in CONDS}
    for c in CONDS:
        for h, S in skills:
            sd = D.md5seed(S, "p3")
            art = "".join(t for t, _ in X3.segments_for(S, c, sd))
            f = features(art)
            for k in FEATS:
                vals[c][k].append(f[k])

    # ---- real benign SKILL.md bodies, the population a false positive is charged against
    import pandas as pd
    fp = os.path.join(ROOT, "data", "skillmd_138k", "train.parquet")
    assert os.path.exists(fp), (
        "the benign corpus is not here; run `python -I scripts/acquire_data.py` first, or "
        "see the README on fetching train.parquet")
    ben = pd.read_parquet(fp, columns=["content"])
    bodies = [str(t) for t in ben["content"].values]
    print("benign SKILL.md bodies:", len(bodies))
    bvals = collections.defaultdict(list)
    for t in bodies:
        f = features(t)
        for k in FEATS:
            bvals[k].append(f[k])
    print()

    # ---- distributions
    print("Median of each structural feature, by condition")
    print("=" * 94)
    print("  %-16s %7s %10s %5s %9s %9s %9s" % ("condition", "h1", "fence_odd",
                                                "fm", "blankrun", "dupline", "stutter"))
    print("  %-16s %7.1f %10.3f %5.1f %9.1f %9.4f %9.1f"
          % (("BENIGN (n=%d)" % len(bodies)),
             st.median(bvals["h1"]), st.mean(bvals["fence_odd"]),
             st.median(bvals["fm"]), st.median(bvals["blankrun"]),
             st.median(bvals["dupline"]), st.median(bvals["stutter"])))
    for c in CONDS:
        v = vals[c]
        print("  %-16s %7.1f %10.3f %5.1f %9.1f %9.4f %9.1f"
              % (c + (" *" if c in FRAG else ""),
                 st.median(v["h1"]), st.mean(v["fence_odd"]),
                 st.median(v["fm"]), st.median(v["blankrun"]),
                 st.median(v["dupline"]), st.median(v["stutter"])))
    print("  * = the condition fragments the payload")
    print()

    # ---- the simplest detector: one feature, one threshold, calibrated on benign only
    print("One feature, one threshold, calibrated on the benign arm at a 1% budget")
    print("=" * 94)
    print("  %-10s %9s %8s   %s" % ("feature", "threshold", "benign", "share of each "
                                    "condition flagged"))
    best = None
    for k in FEATS:
        b = sorted(bvals[k])
        thr = b[int(0.99 * (len(b) - 1))]
        # flag strictly above the 99th percentile of benign
        fpr = sum(1 for x in bvals[k] if x > thr) / len(bvals[k])
        rates = {c: sum(1 for x in vals[c][k] if x > thr) / 165 for c in CONDS}
        frag = st.mean([rates[c] for c in CONDS if c in FRAG])
        nonfrag = st.mean([rates[c] for c in CONDS if c not in FRAG])
        print("  %-10s %9.4f %8.4f   frag mean %.3f   non-frag mean %.3f"
              % (k, thr, fpr, frag, nonfrag))
        if best is None or frag - nonfrag > best[1]:
            best = (k, frag - nonfrag, thr, fpr, rates)
    print()
    k, sep, thr, fpr, rates = best
    print("  The feature that separates fragmentation best is %r at threshold %.4f,"
          % (k, thr))
    print("  with a benign false-positive rate of %.4f on %d real bodies." % (fpr, len(bodies)))
    print()
    print("  %-16s %s" % ("condition", "flagged"))
    for c in CONDS:
        print("  %-16s %.3f%s" % (c, rates[c], "   <- fragments" if c in FRAG else ""))
    print()
    print("  Read this against the reader results, not instead of them. A structural check")
    print("  never reads the payload, so it cannot replace a judge; what it bounds is the")
    print("  claim that interleaved fragmentation defeats every defense. It defeats every")
    print("  defense that is a READER. Whether it survives a deployment that also checks")
    print("  the file's shape is a different question, and this is the cheapest form of it.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
