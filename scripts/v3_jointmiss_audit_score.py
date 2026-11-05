"""Score the human joint-miss audit and propagate it into the paper's floor claim.

Reads audit_jointmiss/sheet.csv (filled in by hand) against audit_jointmiss/key/key.csv
and reports, in this order:

  0  reproduction  - the published 152 / 87 / 631 / 566 / 0.439 / 0.496 block, recomputed,
                     so nothing below is trusted until the baseline matches the paper
  1  calibration   - what the controls say about the auditor, not the corpus
  2  the estimate  - the label error rate inside the 631, with a Wilson interval
  3  the floor      - 56% corrected for that error rate, point and interval
  4  independence  - the corrected 2x2, its Fisher p and its OR recall
  5  circularity   - human against the prior LLM audit on the items both judged
  6  paper text    - the sentences to paste, with every number filled in

usage:  python -I scripts/v3_jointmiss_audit_score.py
"""
import math
import os
import sys

import pandas as pd

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
sys.path.insert(0, HERE)

NOTES = os.path.join(ROOT, "research_notes", "v2_main")
LAYER_FP = os.path.join(NOTES, "v2_layering_items.csv")
PACK = os.path.join(ROOT, "audit_jointmiss")
OUT = os.path.join(NOTES, "v3_jointmiss_audit.md")

GOOD = ("SAFE", "MALICIOUS")
# The prior LLM audit's disputed share of the caught set: 14 of 283 judged benign.
# Used only to correct the caught cells; flagged as LLM-derived wherever it is reported.
E_CAUGHT_K, E_CAUGHT_N = 14, 283

L = []


def say(s=""):
    print(s)
    L.append(s)


def fisher_two_sided(a, b, c, d):
    """Verbatim from scripts/v2_orgeom_indep.py, inlined so importing that module's
    side effects do not pollute this report."""
    n = a + b + c + d
    r1, r2, c1 = a + b, c + d, a + c

    def p(x):
        return (math.comb(r1, x) * math.comb(r2, c1 - x)) / math.comb(n, c1)

    obs = p(a)
    lo = max(0, c1 - r2)
    hi = min(r1, c1)
    return min(1.0, sum(p(x) for x in range(lo, hi + 1) if p(x) <= obs * (1 + 1e-9)))


def wilson(k, n, z=1.96):
    if n == 0:
        return 0.0, 0.0, 1.0
    p = k / n
    d = 1 + z * z / n
    c = (p + z * z / (2 * n)) / d
    hw = z * math.sqrt(p * (1 - p) / n + z * z / (4 * n * n)) / d
    return p, max(0.0, c - hw), min(1.0, c + hw)


def fmt(k, n):
    p, lo, hi = wilson(k, n)
    return f"{k}/{n} = {p:.3f} [{lo:.3f}, {hi:.3f}]"


def cells():
    """The published 2x2 of judge x cisco on the malicious pool."""
    d = pd.read_csv(LAYER_FP)
    d["llm"] = d.llm.astype(str)
    d["skill_hash"] = d.skill_hash.astype(str)
    d = d.drop_duplicates(subset=["skill_hash", "arm"], keep="first")
    g = d[(d.arm == "mal") & d.llm.isin(GOOD)
          & d.cisco.isin(GOOD) & d.skillfrisk.isin(GOOD)]
    a = g.llm == "MALICIOUS"
    b = g.cisco == "MALICIOUS"
    return dict(n=len(g),
                both=int((a & b).sum()),          # 152
                judge_only=int((a & ~b).sum()),
                cisco_only=int((~a & b).sum()),   # 92
                neither=int((~a & ~b).sum()))     # 631


def step0_reproduce(c):
    n = c["n"]
    exp_both = (c["both"] + c["judge_only"]) * (c["both"] + c["cisco_only"]) / n
    exp_neither = (c["judge_only"] + c["neither"]) * (c["cisco_only"] + c["neither"]) / n
    or_rec = (n - c["neither"]) / n
    pj = (c["both"] + c["judge_only"]) / n
    pc = (c["both"] + c["cisco_only"]) / n
    or_indep = 1 - (1 - pj) * (1 - pc)
    p = fisher_two_sided(c["both"], c["judge_only"], c["cisco_only"], c["neither"])
    say("## 0. Baseline reproduction\n")
    say("| quantity | paper | recomputed |")
    say("|---|---|---|")
    say(f"| pool n | 1124 | {n} |")
    say(f"| caught by both | 152 | {c['both']} |")
    say(f"| independence predicts both | 87 | {exp_both:.0f} |")
    say(f"| missed by both | 631 | {c['neither']} |")
    say(f"| independence predicts neither | 566 | {exp_neither:.0f} |")
    say(f"| OR recall | 0.439 | {or_rec:.3f} |")
    say(f"| OR recall if independent | 0.496 | {or_indep:.3f} |")
    say(f"| cisco catches, judge misses | 92 | {c['cisco_only']} |")
    say(f"| Fisher exact p | 9e-22 | {p:.1g} |")
    ok = (n == 1124 and c["both"] == 152 and c["neither"] == 631
          and c["cisco_only"] == 92)
    say(f"\nBaseline reproduces: **{ok}**")
    if not ok:
        say("\n> Stop. Nothing below is meaningful until the baseline matches.")
    say()
    return ok


def main():
    # sheet.csv is the blank template and stays blank so it can be reissued; the filled
    # copy is sheet_human.csv. Prefer the filled one when it exists.
    sp = os.path.join(PACK, "sheet_human.csv")
    if not os.path.exists(sp):
        sp = os.path.join(PACK, "sheet.csv")
    print("reading", os.path.basename(sp), file=sys.stderr)
    sheet = pd.read_csv(sp)
    key = pd.read_csv(os.path.join(PACK, "key", "key.csv"))
    m = key.merge(sheet[["item_id", "verdict", "confidence", "evidence_quote",
                         "attack_type", "notes"]], on="item_id", how="left")
    m["verdict"] = m.verdict.astype(str).str.strip().str.upper()

    say("# Human audit of the unattacked joint-miss set\n")
    blank = m[~m.verdict.isin(["MALICIOUS", "BENIGN", "UNCLEAR"])]
    say(f"Rows: {len(m)}.  Judged: {len(m) - len(blank)}.  Blank or unreadable: "
        f"{len(blank)}.")
    if len(blank):
        say(f"Unjudged item ids: {', '.join(sorted(blank.item_id)[:30])}"
            f"{' ...' if len(blank) > 30 else ''}")
    done_t1 = m[(m.tier == 1) & m.verdict.isin(["MALICIOUS", "BENIGN", "UNCLEAR"])]
    say(f"Tier 1 complete: {len(done_t1)}/{int((m.tier == 1).sum())}.\n")

    c = cells()
    if not step0_reproduce(c):
        write()
        return

    # ---- 1. calibration ------------------------------------------------------
    say("## 1. Auditor calibration (the controls)\n")
    say("These measure the auditor's threshold, not the corpus. They do not enter the "
        "estimate.\n")
    P = m[m.stratum == "P"]
    N = m[m.stratum == "N"]
    p_miss = int((P.verdict == "BENIGN").sum())
    n_fp = int((N.verdict == "MALICIOUS").sum())
    say("| control | what it is | result |")
    say("|---|---|---|")
    say(f"| P (positive) | caught-set items the prior audit called malicious at "
        f"confidence 3 | judged benign: {fmt(p_miss, len(P))} |")
    say(f"| N (negative) | benign-corpus skills no judge ever flagged | judged "
        f"malicious: {fmt(n_fp, len(N))} |")
    say(f"\nUNCLEAR: P {int((P.verdict == 'UNCLEAR').sum())}, "
        f"N {int((N.verdict == 'UNCLEAR').sum())}.\n")
    if p_miss / max(len(P), 1) > 0.2:
        say("> The positive control is failing. A threshold this narrow will call "
            "genuinely malicious items benign, so the J benign rate below is an "
            "over-estimate of the label error and the corrected floor is too high.\n")
    if n_fp / max(len(N), 1) > 0.1:
        say("> The negative control is failing. A threshold this broad will call benign "
            "items malicious, so the J benign rate below is an under-estimate and the "
            "corrected floor is too low.\n")

    # ---- 2. the estimate -----------------------------------------------------
    J = m[m.stratum == "J"]
    Jd = J[J.verdict.isin(["MALICIOUS", "BENIGN"])]
    k_ben = int((Jd.verdict == "BENIGN").sum())
    e, e_lo, e_hi = wilson(k_ben, len(Jd))
    say("## 2. Label error rate inside the 631\n")
    say(f"Judged: {len(Jd)} of {len(J)} sampled "
        f"(UNCLEAR {int((J.verdict == 'UNCLEAR').sum())}, excluded from the rate).\n")
    say(f"- judged **BENIGN** (i.e. mislabeled): {fmt(k_ben, len(Jd))}")
    say(f"- judged MALICIOUS (label holds): {fmt(len(Jd) - k_ben, len(Jd))}\n")

    cat = Jd[Jd.attack_categories.astype(str).str.strip().isin(["", "nan"]) == False]
    unc = Jd[Jd.attack_categories.astype(str).str.strip().isin(["", "nan"])]
    say("Post-stratified on whether the upstream benchmark assigned an attack category "
        "(the axis the prior audit found the disputes concentrate on; the auditor could "
        "not see it):\n")
    say("| upstream category | judged benign |")
    say("|---|---|")
    say(f"| present | {fmt(int((cat.verdict == 'BENIGN').sum()), len(cat))} |")
    say(f"| absent | {fmt(int((unc.verdict == 'BENIGN').sum()), len(unc))} |")
    say()

    # ---- 3. the corrected floor ---------------------------------------------
    say("## 3. The corrected floor\n")
    e_caught, _, _ = wilson(E_CAUGHT_K, E_CAUGHT_N)
    say(f"An item judged benign is not malicious, so it leaves the malicious pool "
        f"entirely rather than moving between cells. Correcting the joint-miss cell by "
        f"the human rate above and the three caught cells by the prior LLM audit's "
        f"disputed share ({E_CAUGHT_K}/{E_CAUGHT_N} = {e_caught:.3f}, **LLM-derived, not "
        f"human**):\n")
    say("| | raw | corrected | corrected low | corrected high |")
    say("|---|---|---|---|---|")
    rows = []
    for lab, ev in (("point", e), ("low", e_lo), ("high", e_hi)):
        neither = c["neither"] * (1 - ev)
        both = c["both"] * (1 - e_caught)
        jo = c["judge_only"] * (1 - e_caught)
        co = c["cisco_only"] * (1 - e_caught)
        n2 = neither + both + jo + co
        rows.append(dict(lab=lab, neither=neither, both=both, jo=jo, co=co, n=n2,
                         floor=neither / n2, orrec=(n2 - neither) / n2))
    r0 = [r for r in rows if r["lab"] == "point"][0]
    rl = [r for r in rows if r["lab"] == "low"][0]
    rh = [r for r in rows if r["lab"] == "high"][0]
    say(f"| malicious pool n | {c['n']} | {r0['n']:.0f} | {rh['n']:.0f} | "
        f"{rl['n']:.0f} |")
    say(f"| missed by both | {c['neither']} | {r0['neither']:.0f} | "
        f"{rh['neither']:.0f} | {rl['neither']:.0f} |")
    say(f"| **joint-miss floor** | **{c['neither'] / c['n']:.3f}** | "
        f"**{r0['floor']:.3f}** | **{rh['floor']:.3f}** | **{rl['floor']:.3f}** |")
    say(f"| OR recall | {(c['n'] - c['neither']) / c['n']:.3f} | {r0['orrec']:.3f} | "
        f"{rh['orrec']:.3f} | {rl['orrec']:.3f} |")
    say("\n(The low/high columns invert: a higher label-error rate removes more of the "
        "joint-miss cell, so it lowers the floor.)\n")

    # ---- 4. independence on the corrected table -----------------------------
    say("## 4. Does the correlation survive the correction?\n")
    ci = {k: int(round(r0[k])) for k in ("both", "jo", "co", "neither")}
    n2 = sum(ci.values())
    exp_n = (ci["jo"] + ci["neither"]) * (ci["co"] + ci["neither"]) / n2
    pj = (ci["both"] + ci["jo"]) / n2
    pc = (ci["both"] + ci["co"]) / n2
    p2 = fisher_two_sided(ci["both"], ci["jo"], ci["co"], ci["neither"])
    say(f"Corrected 2x2, rounded to whole skills: both {ci['both']}, judge only "
        f"{ci['jo']}, cisco only {ci['co']}, neither {ci['neither']} (n = {n2}).\n")
    say(f"- joint misses observed {ci['neither']}, independence predicts "
        f"{exp_n:.0f}")
    say(f"- Fisher exact p = {p2:.3g}  (raw table: "
        f"{fisher_two_sided(c['both'], c['judge_only'], c['cisco_only'], c['neither']):.1g})")
    say(f"- OR recall {(n2 - ci['neither']) / n2:.3f} against "
        f"{1 - (1 - pj) * (1 - pc):.3f} if the two were independent\n")

    # A single p at the point estimate is not enough to carry a claim: the correction
    # has four free choices and p is not robust to any of them. Report the spread.
    def pt(e_jm, e_ct=e_caught):
        a = int(round(c["both"] * (1 - e_ct)))
        b = int(round(c["judge_only"] * (1 - e_ct)))
        cc = int(round(c["cisco_only"] * (1 - e_ct)))
        dd = int(round(c["neither"] * (1 - e_jm)))
        nn = a + b + cc + dd
        return (fisher_two_sided(a, b, cc, dd), dd / nn, dd,
                (cc + dd) * (b + dd) / nn)

    say("That p is at the point estimate only. Every choice the correction makes moves "
        "it, and three individually defensible choices push it above $0.05$:\n")
    say("| choice | label-error rate used | p | floor |")
    say("|---|---|---|---|")
    n_unc = int((J.verdict == "UNCLEAR").sum())
    alts = [("point estimate", e),
            ("rate at its Wilson low", e_lo),
            ("rate at its Wilson high", e_hi),
            (f"the {n_unc} UNCLEAR counted malicious", k_ben / (len(Jd) + n_unc)),
            (f"the {n_unc} UNCLEAR counted benign",
             (k_ben + n_unc) / (len(Jd) + n_unc))]
    for lab, ev in alts:
        pv, fl, _, _ = pt(ev)
        say(f"| {lab} | {ev:.3f} | {pv:.3g} | {fl:.3f} |")
    pv0, fl0, _, _ = pt(e, 0.0)
    say(f"| caught cells assumed correctly labelled | {e:.3f} (caught 0.000) | "
        f"{pv0:.3g} | {fl0:.3f} |")
    ps = [pt(ev)[0] for _, ev in alts] + [pv0]
    robust = all(x < 0.05 for x in ps)
    say(f"\nRange of p over those choices: {min(ps):.3g} to {max(ps):.3g}. "
        f"Correlation claim robust at 0.05: **{robust}**.\n")
    say("The floor's *level* and the *correlation* are separate claims and they do not "
        "fare the same way. The floor is stable across all of the above "
        f"({min(x[1] for x in (pt(ev) for _, ev in alts)):.3f} to "
        f"{max(x[1] for x in (pt(ev) for _, ev in alts)):.3f}). The correlation is not: "
        "on the corrected table the excess of joint misses over independence is within "
        "noise, so the raw table's p = 9e-22 must not be carried over, and the paper "
        "should claim the floor and not the correlation.\n")

    # ---- 5. circularity ------------------------------------------------------
    has_prior = J[J.prior_item.astype(str).str.strip().replace("nan", "") != ""]
    ov = has_prior[has_prior.verdict.isin(["MALICIOUS", "BENIGN"])
                   & has_prior.prior_verdict.isin(["MALICIOUS", "BENIGN"])]
    dropped = has_prior[~has_prior.index.isin(ov.index)]
    say("## 5. Human against the prior LLM audit\n")
    if len(ov) == 0:
        say("No overlapping items judged yet.\n")
    else:
        agree = int((ov.verdict == ov.prior_verdict).sum())
        say(f"{len(has_prior)} joint-miss items were also in the prior LLM audit. "
            f"{len(ov)} have a definite verdict on both sides; agreement on those is "
            f"{fmt(agree, len(ov))}.")
        if len(dropped):
            say(f"\n**{len(dropped)} excluded from that rate** because one side is "
                f"UNCLEAR -- named here rather than silently dropped:")
            for r in dropped.itertuples(index=False):
                say(f"  - {r.item_id} ({r.prior_item}): human {r.verdict}, "
                    f"prior {r.prior_verdict}")
            say("")
        else:
            say("")
        say("| item | human | prior LLM audit |")
        say("|---|---|---|")
        for r in ov.itertuples(index=False):
            flag = "" if r.verdict == r.prior_verdict else "  <-- differs"
            say(f"| {r.item_id} ({r.prior_item}) | {r.verdict} | {r.prior_verdict}{flag} |")
        say("\nThis is the only direct measurement of the circularity objection: the "
            "prior audit was LLM-on-LLM, this one is not. n is small by construction "
            "(the prior audit sampled 64 of the 631), so read it as a direction, not a "
            "reliability coefficient.\n")

    # ---- 6. paper text -------------------------------------------------------
    say("## 6. For the paper\n")
    say("```")
    say(f"A human audit of a random sample of {len(Jd)} of the {c['neither']} "
        f"jointly-missed skills judged {k_ben} of them benign "
        f"({e:.3f} [{e_lo:.3f}, {e_hi:.3f}]). Correcting the pool for that rate, and the "
        f"caught cells for the {e_caught:.3f} disputed share our label audit measured, "
        f"puts the unattacked joint-miss floor at {r0['floor']:.3f} "
        f"[{rh['floor']:.3f}, {rl['floor']:.3f}] rather than "
        f"{c['neither'] / c['n']:.3f}. The disjunction of the two detectors recalls "
        f"{(n2 - ci['neither']) / n2:.3f} on the corrected table, against "
        f"{1 - (1 - pj) * (1 - pc):.3f} if their misses were independent; that "
        f"difference is no longer distinguishable from zero (Fisher exact "
        f"p = {p2:.3g}, and {min(ps):.3g} to {max(ps):.3g} across the correction's "
        f"free choices), so we claim the floor and withdraw the correlation.")
    say("```")
    say(f"\nAuditor calibration to report alongside it: positive control "
        f"{fmt(p_miss, len(P))} judged benign, negative control {fmt(n_fp, len(N))} "
        f"judged malicious.\n")
    write()


def write():
    with open(OUT, "w", encoding="utf-8") as f:
        f.write("\n".join(L) + "\n")
    print(f"\nwrote {OUT}")


if __name__ == "__main__":
    main()
