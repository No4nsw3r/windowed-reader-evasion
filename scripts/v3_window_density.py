r"""Recompute the per-window payload density that \S\ref{sec:regex} quotes.

WHY THIS SCRIPT EXISTS. A v4 reviewer argued that the position-addressed partition loses
more payload density under interleaving than the content-addressed reader does, while
showing the smaller effect, and concluded that \S\ref{sec:regex} names the wrong mechanism.
The two figures being compared were not the same quantity: theirs for the content-addressed
reader was a share of the WHOLE PROMPT, read off `followup_results/exp2_geometry.csv` as
mean(covered * payload_len) / mean(prompt_len), set against a BEST-WINDOW share at the
partition. This script computes one statistic at both geometries so the comparison can be
made, and prints both statistics side by side so the mixing cannot be repeated.

    best-window payload share = max over the reader's windows of
        (payload characters in that window) / (characters in that window)

the densest evidence any single judge call receives. The whole-prompt share is the same
numerator pooled over every window the judge is shown at once, which is the right quantity
for a reader that concatenates its windows into one prompt and the wrong one for comparing
geometries, because the two geometries differ in exactly how many calls they split that
text across.

NOTHING IS REIMPLEMENTED HERE. The windows come from `scripts/v3_span_read_frac.py`'s
`partition_views` and `regex_views`, each of which asserts at run time that its window
offsets match the deployed function -- `v2_phase1_kill.reader_requests` for the partition,
`v2_skillgate.skillgate_prompt` for the regex reader -- so a silent divergence from the
measured reader is not reachable. Artifacts are rebuilt from the corpus and the harness's
own seed, so the geometry is judge-independent and no model is called.

POPULATION. The 165-artifact caught set behind Tables~\ref{tab:regex} and~\ref{tab:deploy},
which is the population the sentences quoting these numbers are about. At the regex reader
the mean is over the artifacts the prefilter fires on; the rest receive no call at all and
have no window to take a share of.

usage: python -I scripts/v3_window_density.py
"""
import os
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(ROOT, "scripts"))

import pilot_audit2 as A                                          # noqa: E402
import v2_skillgate as SG                                         # noqa: E402
import v3_span_read_frac as SRF                                   # noqa: E402

sys.stdout.reconfigure(encoding="utf-8", errors="replace")

ATTACKS = ("clean", "d_real", "il_matched")
PARTITIONS = ("dedup_full", "dedup_small")
REGEXES = ("regex_real", "skillgate")


def collect(geom, kind, attack, skills):
    bws, pro, npw, nw, n = [], [], [], [], 0
    for _h, S in skills:
        segs = SRF.segs_p3(S, attack, None)
        if segs is None:
            continue
        art, src = SRF.assemble_with_map(segs)
        if kind == "partition":
            views, texts, nwin, overflow = SRF.partition_views(art, src, geom)
            if overflow or not views:
                continue
        else:
            views, texts, _nhits, fired = SRF.regex_views(art, src, SRF.REGEX[geom])
            if not fired or not views:
                continue
            nwin = len(views)
        per = [(len(v), len(t)) for v, t in zip(views, texts) if len(t)]
        if not per:
            continue
        bws.append(max(a / b for a, b in per))
        pro.append(sum(a for a, _ in per) / sum(b for _, b in per))
        npw.append(sum(1 for v in views if len(v) > 0))
        nw.append(nwin)
        n += 1
    if not n:
        return None
    return (n, sum(bws) / n, sum(pro) / n, sum(npw) / n, sum(nw) / n)


def main():
    A.load_pool()
    assert len(A._POOL) >= 100, "filler pool too small"
    skills = SG.caught_set(A.MINI)
    print(f"population: {len(skills)} artifacts, the caught set behind the regex and "
          f"frontier tables\n")

    rows = {}
    for geom, kind in ([(g, "partition") for g in PARTITIONS]
                       + [(g, "regex") for g in REGEXES]):
        for atk in ATTACKS:
            r = collect(geom, kind, atk, skills)
            if r:
                rows[(geom, atk)] = r

    print(f"{'geometry':14s}{'attack':12s}{'n':>5s}{'bestWinShare':>14s}"
          f"{'wholePrompt':>13s}{'payWin':>8s}{'nWin':>7s}")
    for (g, a), (n, b, p, pw, w) in rows.items():
        print(f"{g:14s}{a:12s}{n:5d}{b:14.4f}{p:13.4f}{pw:8.3f}{w:7.3f}")

    print("\nwhat the two statistics say about the same two geometries:")
    print(f"  {'geometry':14s}{'statistic':16s}{'clean->il_matched':>20s}"
          f"{'d_real->il_matched':>21s}")
    for g in list(PARTITIONS) + list(REGEXES):
        c, d, i = (rows.get((g, a)) for a in ATTACKS)
        if not (c and d and i):
            continue
        for lbl, idx in (("best window", 1), ("whole prompt", 2)):
            f1 = c[idx] / i[idx] if i[idx] else float("nan")
            f2 = d[idx] / i[idx] if i[idx] else float("nan")
            print(f"  {g:14s}{lbl:16s}{f1:19.2f}x{f2:20.2f}x")

    print("\nthe sentence this supports: on the BEST-WINDOW statistic the content-addressed")
    print("reader loses MORE than the partition, on both baselines, which is the order of")
    print("the two measured effects. On the WHOLE-PROMPT statistic the content-addressed")
    print("reader appears to lose less, because it concatenates its windows into one")
    print("prompt and the partition does not. Comparing one geometry on one statistic")
    print("against the other on the other is what inverts the comparison.")

    for g in PARTITIONS[:1]:
        for atk in ("clean", "il_matched"):
            under = tot = 0
            for _h, S in skills:
                segs = SRF.segs_p3(S, atk, None)
                art, src = SRF.assemble_with_map(segs)
                views, texts, _nw, over = SRF.partition_views(art, src, g)
                if over or not views:
                    continue
                per = [len(v) / len(t) for v, t in zip(views, texts) if len(t)]
                if not per:
                    continue
                tot += 1
                under += 1 if max(per) < 0.5 else 0
            print(f"  {g} {atk:12s}: best window below half payload on {under} of {tot}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
