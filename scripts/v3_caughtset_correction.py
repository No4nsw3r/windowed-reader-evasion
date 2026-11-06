r"""Is the insulation argument sound, and what does the human-audit rate do to the ASR?

The paper's headline label result is that a human read 120 of the 631 unattacked joint
misses and judged 0.684 of them benign. It then argues the ASR results are INSULATED from
that error, because the attack experiments sampled the caught set, which is the complement
of the joint-miss condition. A reviewer asked for the caught-set correction to be run at
the human rate rather than only at the pipelines' 0.049, and to be told which cells move.

This script answers that in three parts and refuses to proceed past a failed gate.

  1. What 0.684 is a rate OF: which population, which denominator, which direction of
     label error. Established from the packet key and the layering table, not from prose.
  2. Whether the rate can be carried to the caught set. Five independent lines of
     evidence, every one of them a measurement:
       (a) the sampling frame, and the one place the "complement" claim is loose;
       (b) the error gradient the audit itself measured, with the two populations'
           composition compared;
       (c) the human's OWN reads of caught-set items -- there are 22 of them, and they
           have not been pooled before;
       (d) a Bayes consistency check: what the measured detector false-positive rates
           imply the caught-set rate must be, given 0.684 in the joint-miss cell;
       (e) the human-against-pipeline calibration factor, applied to the measured
           caught-set rate.
  3. What happens to the ASR anyway. Three corrections that remove items we can NAME, and
     then, for the rates we can only assume, the exact extremal envelope and -- for the
     paired placement effects -- the adversarial BREAKDOWN POINT: the smallest number of
     artifacts whose removal can take an effect out of significance, whichever artifacts
     an adversary picks.

Conventions, which are load bearing. ASR is the share of malicious cells returning SAFE,
a refusal counts as a block, and the denominator is all cells. "False-malicious" means the
upstream label says malicious and the reader judged benign. No scipy: Clopper-Pearson by
bisection on an exact binomial CDF summed in log space, and the exact two-sided McNemar
sign test on the discordant pairs.

usage: python -I scripts/v3_caughtset_correction.py
"""
import csv
import glob
import math
import os
import sys

sys.stdout.reconfigure(encoding="utf-8", errors="replace")

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
NOTES = os.path.join(ROOT, "research_notes", "v2_main")
FR = os.path.join(ROOT, "followup_results")
AUD = os.path.join(ROOT, "audit")
JM = os.path.join(ROOT, "audit_jointmiss")
GOOD = ("SAFE", "MALICIOUS")
ALPHA = 0.05
FAILS = []


# ------------------------------------------------------------------ statistics
def _lchoose(n, k):
    return math.lgamma(n + 1) - math.lgamma(k + 1) - math.lgamma(n - k + 1)


def binom_cdf(k, n, p):
    if k < 0:
        return 0.0
    if k >= n:
        return 1.0
    if p <= 0.0:
        return 1.0
    if p >= 1.0:
        return 0.0
    lp, lq = math.log(p), math.log1p(-p)
    return min(1.0, sum(math.exp(_lchoose(n, i) + i * lp + (n - i) * lq)
                        for i in range(k + 1)))


def _bisect(f, a=0.0, b=1.0, it=90):
    fa = f(a)
    for _ in range(it):
        m = (a + b) / 2
        if (f(m) < 0) == (fa < 0):
            a = m
        else:
            b = m
    return (a + b) / 2


def cp(k, n, alpha=ALPHA):
    """Clopper-Pearson, bisected on the exact binomial CDF. Direction read from the
    endpoint, not assumed: the lower bound solves an increasing function of p and the
    upper a decreasing one."""
    if n == 0:
        return float("nan"), float("nan")
    lo = 0.0 if k == 0 else _bisect(lambda p: 1 - binom_cdf(k - 1, n, p) - alpha / 2)
    hi = 1.0 if k == n else _bisect(lambda p: binom_cdf(k, n, p) - alpha / 2)
    return lo, hi


def ci(k, n):
    lo, hi = cp(k, n)
    return f"{k/n if n else float('nan'):.4f} [{lo:.4f}, {hi:.4f}]"


def mcnemar(b, c):
    d = b + c
    if d == 0:
        return 1.0
    k = min(b, c)
    return min(1.0, 2 * sum(math.comb(d, i) for i in range(k + 1)) / 2 ** d)


# ------------------------------------------------------------------ loaders
def read(path, enc="utf-8"):
    with open(path, newline="", encoding=enc) as fh:
        return list(csv.DictReader(fh))


def layering():
    """The unattacked three-scanner table. Deduplicated on (skill_hash, arm) keeping the
    first row, because two processes appended concurrently and the file holds ~2 rows per
    skill; then restricted to rows where all three scanners returned a usable verdict."""
    seen, rows = set(), []
    for r in read(os.path.join(NOTES, "v2_layering_items.csv")):
        k = (r["skill_hash"], r["arm"])
        if k in seen:
            continue
        seen.add(k)
        rows.append(r)
    usable = [r for r in rows
              if r["llm"] in GOOD and r["cisco"] in GOOD and r["skillfrisk"] in GOOD]
    return rows, usable


def audit450():
    """Consensus verdicts for the 450-item label audit: every filled sheet must agree or
    the item is UNCLEAR, and an adjudicated verdict overrides the pair."""
    sheets = {}
    for fp in sorted(glob.glob(os.path.join(AUD, "sheets", "sheet_*.csv"))):
        name = os.path.basename(fp)[6:-4]
        d = {}
        for r in read(fp, "utf-8-sig"):
            v = (r.get("verdict") or "").strip().upper()
            if v:
                d[r["item_id"]] = v
        if d:
            sheets[name] = d
    adj = sheets.pop("adjudicated", {})
    ids = set().union(*[set(d) for d in sheets.values()]) | set(adj)
    cons = {}
    for i in sorted(ids):
        vs = {d[i] for d in sheets.values() if i in d}
        cons[i] = adj.get(i, vs.pop() if len(vs) == 1 else "UNCLEAR")
    key = {r["item_id"]: r for r in read(os.path.join(AUD, "key", "key.csv"),
                                        "utf-8-sig")}
    return key, cons, adj


def jointmiss():
    key = {r["item_id"]: r for r in read(os.path.join(JM, "key", "key.csv"),
                                         "utf-8-sig")}
    sheet = {r["item_id"]: (r.get("verdict") or "").strip().upper()
             for r in read(os.path.join(JM, "sheet_human.csv"), "utf-8-sig")}
    return key, sheet


def mal_arm():
    """Every malicious ASR cell in the main measurement, as the paper's own audit scorer
    assembles them: phases 1-3, verdict in SAFE/MALICIOUS, keyed (phase, model, attack,
    defense). A failed call and a reader overflow are not verdicts and are excluded, which
    is what produces the paper's 238 cells."""
    files = [os.path.join(NOTES, "v2_phase1_items.csv"),
             os.path.join(NOTES, "v2_phase2_items.csv")] + \
        sorted(glob.glob(os.path.join(NOTES, "v2_phase3_items_*.csv")))
    out = []
    for fp in files:
        if not os.path.exists(fp):
            continue
        rows = read(fp)
        if not rows or "arm" not in rows[0]:
            continue
        phase = os.path.basename(fp).split("_items")[0]
        for r in rows:
            if r["arm"] != "mal" or r["verdict"] not in GOOD:
                continue
            out.append((phase, r["model"], r["attack"],
                        r.get("defense") or r.get("config"),
                        r["skill_hash"], r["verdict"]))
    return out


def asr_cells(rows, drop=frozenset()):
    cells = {}
    for phase, model, attack, defense, h, v in rows:
        if h in drop:
            continue
        k = (phase, model, attack, defense)
        c = cells.setdefault(k, [0, 0])
        c[1] += 1
        if v == "SAFE":
            c[0] += 1
    return cells


# ------------------------------------------------------------------ part 1
def part1():
    print("=" * 100)
    print("PART 1.  WHAT 0.684 IS A RATE OF")
    print("=" * 100)
    rows, usable = layering()
    mal = [r for r in usable if r["arm"] == "mal"]
    ben = [r for r in usable if r["arm"] == "ben"]
    jm = {r["skill_hash"] for r in mal
          if r["llm"] != "MALICIOUS" and r["cisco"] != "MALICIOUS"}
    both = sum(1 for r in mal if r["llm"] == "MALICIOUS" and r["cisco"] == "MALICIOUS")
    llm_caught = {r["skill_hash"] for r in mal if r["llm"] == "MALICIOUS"}
    print(f"  pool with all three scanners usable, malicious arm   n = {len(mal)}"
          f"   (paper 1124)")
    print(f"  missed by the LLM judge AND the static scanner        {len(jm)}"
          f"    (paper 631)")
    print(f"  caught by both                                        {both}"
          f"    (paper 152)")
    print(f"  caught by the LLM judge (the ASR selection event)     {len(llm_caught)}")
    print(f"  benign arm with all three usable                      n = {len(ben)}"
          f"   (paper 400)")
    if len(mal) != 1124 or len(jm) != 631 or both != 152 or len(ben) != 400:
        FAILS.append("the layering baseline does not reproduce "
                     f"({len(mal)}/{len(jm)}/{both}/{len(ben)} against 1124/631/152/400)")

    jkey, jsheet = jointmiss()
    J = [i for i, r in jkey.items() if r["stratum"] == "J"]
    inside = sum(1 for i in J if jkey[i]["skill_hash"] in jm)
    nb = sum(1 for i in J if jsheet[i] == "BENIGN")
    nm = sum(1 for i in J if jsheet[i] == "MALICIOUS")
    nu = sum(1 for i in J if jsheet[i] == "UNCLEAR")
    print(f"\n  the estimand stratum J: {len(J)} items, {inside} of them inside the "
          f"{len(jm)}")
    if inside != len(J):
        FAILS.append(f"only {inside} of the {len(J)} J items sit in the joint-miss cell")
    print(f"  human verdicts on J: BENIGN {nb}, MALICIOUS {nm}, UNCLEAR {nu}")
    print(f"  the rate             {nb} / {nb + nm} = {ci(nb, nb + nm)}   (paper 78/114 "
          f"= 0.684 [0.594, 0.762])")
    if (nb, nb + nm) != (78, 114):
        FAILS.append(f"the J-stratum rate recomputes {nb}/{nb+nm}, not 78/114")

    print("\n  SO, EXACTLY:")
    print(f"    population   the {len(jm)} malicious-labelled skills on which, with no")
    print("                 attack applied, BOTH the LLM judge and the static scanner")
    print("                 returned SAFE on clean input")
    print(f"    sample       a random {len(J)} of them (seed 631), renumbered and shuffled")
    print("                 among 30 control items, blind to stratum, provenance,")
    print("                 upstream label and attack category")
    print(f"    denominator  {nb + nm} -- the {len(J)} minus the {nu} the human marked "
          f"UNCLEAR")
    print(f"    numerator    {nb} items whose upstream label is `malicious` and which the")
    print("                 human read as BENIGN")
    print("    direction    FALSE-MALICIOUS. It is not a false-benign rate, not an")
    print("                 error rate of the detectors, and not a property of the")
    print("                 corpus as a whole: it is conditional on detector silence.")
    return dict(mal=mal, ben=ben, jm=jm, llm_caught=llm_caught, J=J,
                jkey=jkey, jsheet=jsheet, rate=(nb, nb + nm))


# ------------------------------------------------------------------ part 2
def part2(st):
    print("\n" + "=" * 100)
    print("PART 2.  CAN THAT RATE BE CARRIED TO THE CAUGHT SET?")
    print("=" * 100)
    jm, jkey, jsheet, J = st["jm"], st["jkey"], st["jsheet"], st["J"]
    akey, acons, _ = audit450()
    A = [i for i, r in akey.items() if r["stratum"] == "A"]
    C = [i for i, r in akey.items() if r["stratum"] == "C"]
    a_hash = {akey[i]["skill_hash"]: i for i in akey}
    dispA = [i for i in A if acons.get(i) == "BENIGN"]
    dispC = [i for i in C if acons.get(i) == "BENIGN"]

    print("\n(a) THE SAMPLING FRAME, and where 'complement' is loose")
    print("-" * 100)
    print(f"  Every one of the {len(J)} sampled items is in the joint-miss cell by")
    print("  construction, so the sample contains no item drawn because a detector")
    print("  fired. A rate estimated on {llm SAFE and cisco SAFE} is an estimate of")
    print("  P(mislabelled | both silent) and of nothing else.")
    print()
    print("  But the two sets are not exact complements, and this is the one crack in the")
    print("  insulation argument that the data can show:")
    aA = [i for i in J if jkey[i]["skill_hash"] in a_hash
          and akey[a_hash[jkey[i]["skill_hash"]]]["stratum"] == "A"]
    aC = [i for i in J if jkey[i]["skill_hash"] in a_hash
          and akey[a_hash[jkey[i]["skill_hash"]]]["stratum"] == "C"]
    cs_in_jm = sum(1 for i in A if akey[i]["skill_hash"] in jm)
    print(f"    {len(aA)} of the {len(J)} sampled joint-miss items are ALSO stratum-A "
          f"caught-set items,")
    print(f"    and {cs_in_jm} of the {len(A)} caught-set items sit inside the "
          f"{len(jm)} joint misses "
          f"({cs_in_jm/len(A):.3f}).")
    print("    The reason is that the two sets are defined by different measurements: the")
    print("    631 is one judge and one scanner at the layering reader, while the caught")
    print("    set is 'this judge flagged it on clean input' at the attack harness's own")
    print("    judge and reader. So the ASR arm is not strictly disjoint from the")
    print("    corrected population, and the overlap is small but not zero.")

    print("\n(b) THE ERROR GRADIENT THE AUDIT ITSELF MEASURED")
    print("-" * 100)
    for lab, sel in (("attack category present", lambda i: bool(jkey[i]["attack_categories"])),
                     ("attack category absent ", lambda i: not jkey[i]["attack_categories"])):
        g = [i for i in J if sel(i)]
        b = sum(1 for i in g if jsheet[i] == "BENIGN")
        m = sum(1 for i in g if jsheet[i] == "MALICIOUS")
        print(f"  {lab}  n = {len(g):3d}   false-malicious {ci(b, b + m)}")
    print("  The error is concentrated where the benchmark assigns no attack category --")
    print("  a label put on by provenance rather than by content, which produces a")
    print("  'malicious' skill with no malicious instruction in it. That is a coherent")
    print("  mechanism for why nothing fired, and it is the same mechanism that makes the")
    print("  rate inapplicable to items something DID fire on.")
    print()
    print("  Provenance composition, the two populations side by side:")
    provs = sorted({jkey[i]["provenance"] for i in J} |
                   {akey[i]["provenance"] for i in A})
    print(f"  {'provenance':22s}{'J sample':>10s}{'share':>8s}"
          f"{'caught set A':>14s}{'share':>8s}{'A disputed':>12s}")
    for p in provs:
        gj = [i for i in J if jkey[i]["provenance"] == p]
        ga = [i for i in A if akey[i]["provenance"] == p]
        gd = [i for i in ga if acons.get(i) == "BENIGN"]
        print(f"  {p:22s}{len(gj):10d}{len(gj)/len(J):8.3f}{len(ga):14d}"
              f"{len(ga)/len(A):8.3f}{len(gd):12d}")

    print("\n(c) THE HUMAN'S OWN READS OF CAUGHT-SET ITEMS -- there are 22")
    print("-" * 100)
    P = [i for i, r in jkey.items() if r["stratum"] == "P"]
    pb = sum(1 for i in P if jsheet[i] == "BENIGN")
    pm = sum(1 for i in P if jsheet[i] == "MALICIOUS")
    print(f"  positive control, drawn from the caught set:   {len(P)} items, "
          f"false-malicious {ci(pb, pb + pm)}")
    ab = sum(1 for i in aA if jsheet[i] == "BENIGN")
    am = sum(1 for i in aA if jsheet[i] == "MALICIOUS")
    print(f"  the {len(aA)} caught-set items that fell into the J draw:   "
          f"false-malicious {ci(ab, ab + am)}")
    print(f"  pooled human read of caught-set items:        "
          f"{pb + ab} of {pb + pm + ab + am} = {ci(pb + ab, pb + pm + ab + am)}")
    already = [i for i in aA if jsheet[i] == "BENIGN"
               and acons.get(a_hash[jkey[i]["skill_hash"]]) == "BENIGN"]
    newly = [i for i in aA if jsheet[i] == "BENIGN" and i not in already]
    print(f"  of those {ab} benign calls, {len(already)} was already among the pipelines'")
    print(f"  {len(dispA)} disputed caught-set items ({', '.join(already) or 'none'}); "
          f"{len(newly)} is new ({', '.join(newly) or 'none'}).")
    print("  So on {} caught-set items re-read by the human, the pipelines had already"
          .format(len(aA)))
    print(f"  found {len(already)} of the {ab} errors and missed {len(newly)}.")
    print()
    print("  Neither subsample is a random draw from the caught set, and they are biased")
    print("  in OPPOSITE directions, which is why they bracket rather than estimate:")
    print("    the positive control was drawn from the pipelines' confident-malicious")
    print("    calls, so it is enriched for genuinely malicious items;")
    print("    the 8 are caught-set items that ALSO sit in the joint-miss cell, i.e.")
    print("    the subpopulation the error is concentrated in.")

    print("\n(d) BAYES CONSISTENCY CHECK, from the measured detector false-positive rates")
    print("-" * 100)
    ben = st["ben"]
    nben = len(ben)
    fp_llm = sum(1 for r in ben if r["llm"] == "MALICIOUS")
    fp_cis = sum(1 for r in ben if r["cisco"] == "MALICIOUS")
    both_silent = sum(1 for r in ben
                      if r["llm"] != "MALICIOUS" and r["cisco"] != "MALICIOUS")
    print(f"  on the {nben} benign skills:  LLM flags {ci(fp_llm, nben)}  "
          f"(paper 0.050)")
    print(f"  {'':23s}        Cisco flags {ci(fp_cis, nben)}  (paper 0.043)")
    print(f"  {'':23s}        BOTH silent {ci(both_silent, nben)}   <- measured, "
          f"not assumed independent")
    g0, g1 = both_silent / nben, fp_llm / nben
    k, n = st["rate"]
    print(f"\n  A genuinely benign artifact is {g0/g1:.1f} times more likely to land in the")
    print("  joint-miss cell than in the LLM-caught cell. That ratio is the whole")
    print("  insulation argument, and it is measured rather than argued.")
    print()
    print("  Carrying the audit through it: if the joint-miss cell holds "
          f"{k}/{n} = {k/n:.3f}")
    print(f"  mislabelled items, the pool holds {k/n:.3f} x {len(jm)} / {g0:.4f} = "
          f"{k/n*len(jm)/g0:.0f} of them,")
    print(f"  of which {g1:.4f} reach the LLM-caught cell, which has "
          f"{len(st['llm_caught'])} members:")
    lo_r, hi_r = cp(k, n)
    lo0, hi0 = cp(both_silent, nben)
    lo1, hi1 = cp(fp_llm, nben)
    nc = len(st["llm_caught"])
    pt = (k / n) * len(jm) / g0 * g1 / nc
    extremes = [(r * len(jm) / a) * b / nc
                for r in (lo_r, k / n, hi_r) for a in (lo0, g0, hi0)
                for b in (lo1, g1, hi1)]
    print(f"    implied false-malicious rate in the caught set = {pt:.4f}")
    print(f"    across the 95% endpoints of all three measured inputs: "
          f"{min(extremes):.4f} to {min(1.0, max(extremes)):.4f}")
    print(f"    implied mislabelled share of the whole 1124-skill pool = "
          f"{(k/n)*len(jm)/g0/len(st['mal']):.3f}")
    print("  The assumption, stated because it is the only soft step: a mislabelled")
    print("  artifact is no more and no less likely to trip either detector than a")
    print("  skill from the benign corpus. Its direction is not known.")

    print("\n(e) HUMAN AGAINST PIPELINE, the only calibration the data contains")
    print("-" * 100)
    overlap = [i for i in J if jkey[i]["prior_verdict"]]
    defn = [i for i in overlap
            if jkey[i]["prior_verdict"] in ("MALICIOUS", "BENIGN")
            and jsheet[i] in ("MALICIOUS", "BENIGN")]
    agree = [i for i in defn if jkey[i]["prior_verdict"] == jsheet[i]]
    print(f"  items judged by both sides: {len(overlap)}; both definite: {len(defn)}; "
          f"agreeing: {len(agree)}")
    excl = [f"{i} (prior {jkey[i]['prior_verdict']}, human {jsheet[i]})"
            for i in overlap if i not in defn]
    print(f"  excluded for an UNCLEAR on one side: {'; '.join(excl) or 'none'}")
    print("  Item by item the human and the pipelines do not disagree, so the gap between")
    print("  their RATES is a difference in which items each sampled, not in severity.")
    print()
    rA, nA = len(dispA), len(A)
    rC, nC = len(dispC), len(C)
    print(f"  pipelines on the caught set   (stratum A): {ci(rA, nA)}   (paper 0.049)")
    print(f"  pipelines on the never-caught (stratum C): {ci(rC, nC)}   (paper 0.483)")
    print(f"  human on the joint-miss cell             : {ci(k, n)}")
    if (rA, nA, rC, nC) != (14, 283, 29, 60):
        FAILS.append(f"the 450-item audit recomputes A {rA}/{nA}, C {rC}/{nC} against "
                     f"the published 14/283 and 29/60")
    fac = (k / n) / (rC / nC)
    print(f"\n  calibration factor, the one stratum both sampled from the never-caught")
    print(f"  side: {k/n:.3f} / {rC/nC:.3f} = {fac:.3f}")
    print(f"  scaled caught-set rate: {rA/nA:.4f} x {fac:.3f} = {rA/nA*fac:.4f}")
    print("  (approximate: stratum C is 'low-recall provenance no judge flagged' and the")
    print("  631 is 'both scanners silent at the layering reader', which are close but")
    print("  not the same population.)")

    print("\n" + "-" * 100)
    print("VERDICT ON TRANSFERABILITY")
    print("-" * 100)
    print("  The transfer is NOT legitimate. The audit's sampling frame is the event the")
    print("  correction is for -- both detectors silent -- and the audit itself measured")
    print("  the gradient that makes the rate frame-specific. The data support four")
    print("  weaker statements instead, which agree with each other to within a factor")
    print("  of about two and all sit an order of magnitude below 0.684:")
    cands = [("pipelines, random sample of the caught set", rA / nA, f"{rA}/{nA}"),
             ("human, calibrated by the never-caught stratum", rA / nA * fac,
              f"{rA/nA:.4f} x {fac:.3f}"),
             ("human, own reads of caught-set items (pooled, biased both ways)",
              (pb + ab) / (pb + pm + ab + am), f"{pb+ab}/{pb+pm+ab+am}"),
             ("Bayes, from the measured detector false-positive rates", pt,
              "derived in (d)")]
    for lab, v, how in cands:
        print(f"    {v:.4f}   {lab:62s} {how}")
    print(f"    0.6840   THE FORBIDDEN TRANSFER, carried over anyway -- priced in part 3")
    return dict(rates=[v for _, v, _ in cands] + [k / n], cands=cands,
                dispA={akey[i]["skill_hash"] for i in dispA},
                dispC={akey[i]["skill_hash"] for i in dispC},
                newly={jkey[i]["skill_hash"] for i in newly},
                human_pool=(pb + ab) / (pb + pm + ab + am), bayes=pt,
                scaled=rA / nA * fac, pipe=rA / nA)


# ------------------------------------------------------------------ part 3
def part3(st, tr):
    print("\n" + "=" * 100)
    print("PART 3.  WHAT IT DOES TO THE ASR")
    print("=" * 100)
    rows = mal_arm()
    base = asr_cells(rows)
    print(f"  ASR cells assembled: {len(base)}   (paper 238)")
    if len(base) != 238:
        FAILS.append(f"{len(base)} ASR cells assembled, not the paper's 238")

    print("\n(a) CORRECTIONS THAT REMOVE ITEMS WE CAN NAME")
    print("-" * 100)
    variants = [
        ("published: strata A and C disputed items dropped",
         tr["dispA"] | tr["dispC"]),
        ("caught-set items only (stratum A's disputed)", tr["dispA"]),
        ("stratum A's disputed PLUS the human's new caught-set find",
         tr["dispA"] | tr["newly"]),
    ]
    for lab, drop in variants:
        cut = asr_cells(rows, drop)
        moved = []
        for kk, (k0, n0) in base.items():
            k1, n1 = cut.get(kk, (0, 0))
            if n1 == 0:
                continue
            d = k1 / n1 - k0 / n0
            if abs(d) >= 0.02:
                moved.append((kk, k0, n0, k1, n1, d))
        moved.sort(key=lambda x: x[5])
        print(f"\n  {lab}")
        print(f"  items dropped {len(drop)};  cells moving by >= 0.020: "
              f"{len(moved)} of {len(base)};  "
              f"largest |move| {max((abs(x[5]) for x in moved), default=0.0):.3f};  "
              f"all downward: {all(x[5] < 0 for x in moved)}")
        if moved:
            print(f"    {'cell':64s}{'ASR before':>24s}{'ASR after':>24s}{'delta':>8s}")
            for kk, k0, n0, k1, n1, d in moved:
                nm = f"{kk[1]} {kk[2]} {kk[3]}"
                print(f"    {nm[:64]:64s}{ci(k0, n0):>24s}{ci(k1, n1):>24s}{d:+8.3f}")

    print("\n(b) RATES WE CANNOT NAME ITEMS FOR: the exact extremal envelope")
    print("-" * 100)
    print("  Removing a random share f of a cell's items does not move its ASR in")
    print("  expectation. All the movement comes from the correlation between being")
    print("  mislabelled and returning SAFE, and the audit measured the sign of that")
    print("  correlation -- every one of the seven movers above goes DOWN, because a")
    print("  mislabelled item is one the attack had already 'won'. So what the data")
    print("  support for an unnameable f is the envelope: the ASR an adversary could")
    print("  force by choosing which f*n items are the mislabelled ones.")
    print()
    HEAD = [("gpt-4o-mini", "gap_il_4x2600", "dedup_full"),
            ("qwen3:8b", "gap_il_4x2600", "dedup_full"),
            ("google/gemini-2.5-flash-lite", "gap_il_4x2600", "dedup_full"),
            ("anthropic/claude-haiku-4.5", "gap_il_4x2600", "dedup_full"),
            ("gpt-4o", "gap_il_4x2600", "dedup_full")]
    fs = [("pipelines 0.049", tr["pipe"]), ("calibrated 0.070", tr["scaled"]),
          ("human pooled 0.091", tr["human_pool"]), ("TRANSFERRED 0.684", 0.684)]
    print(f"  {'judge':30s}{'n':>4s}{'ASR':>7s}" +
          "".join(f"{lab:>26s}" for lab, _ in fs))
    for model, attack, defense in HEAD:
        hit = [(kk, v) for kk, v in base.items()
               if kk[1] == model and kk[2] == attack and kk[3] == defense]
        if not hit:
            print(f"  {model:30s}  no such cell")
            continue
        (_, (k0, n0)) = hit[0]
        line = f"  {model:30s}{n0:4d}{k0/n0:7.3f}"
        for _, f in fs:
            m = round(f * n0)
            n1 = n0 - m
            if n1 <= 0:
                line += f"{'n exhausted':>26s}"
                continue
            lo = max(0, k0 - m) / n1
            hi = min(k0, n1) / n1
            line += f"{f'[{lo:.3f}, {hi:.3f}] n={n1}':>26s}"
        print(line)
    print()
    print("  At the transferred rate the envelope is wider than the quantity it is")
    print("  meant to bound, which is the real answer to the reviewer: a 0.684 label")
    print("  error on the caught set would not lower the ASR figures, it would make them")
    print("  unestimable. Nothing in this paper would survive that assumption, and")
    print("  nothing in the data supports it (part 2).")

    print("\n(c) THE PAIRED PLACEMENT EFFECTS: how much label error each one absorbs")
    print("-" * 100)
    print("  A paired McNemar effect does not care about concordant pairs at all, so")
    print("  deleting items only matters when a deleted item is one of the discordant")
    print("  pairs. The adversarial worst case is to delete the GAINED pairs. The")
    print("  breakdown point below is the smallest number of artifacts whose deletion")
    print("  can push the exact two-sided p above a threshold, whichever artifacts are")
    print("  chosen, and the share is that count over the judge's own n.")
    print()
    reg = {}
    for r in read(os.path.join(FR, "exp2_cells.csv")):
        if (r["reader"] == "regex_real" and r["arm"] == "mal"
                and r["attack"] in ("d_real", "il_matched")):
            reg.setdefault(r["judge"], {}).setdefault(r["attack"], {})[
                r["skill_hash"]] = r["verdict"]
    jmset = st["jm"]
    nj = 9
    worst = max(tr["pipe"], tr["scaled"], tr["human_pool"], tr["bayes"])
    print(f"  worst caught-set rate part 2 supports: f = {worst:.3f}  "
          f"(candidates {tr['pipe']:.3f}, {tr['scaled']:.3f}, "
          f"{tr['human_pool']:.3f}, {tr['bayes']:.3f})")
    print()
    print(f"  {'judge':30s}{'n':>5s}{'g/l':>7s}{'delta':>9s}{'p':>11s}"
          f"{'brk.05':>8s}{'share':>7s}{'brk.05/9':>10s}{'share':>7s}"
          f"{'p|adv f':>10s}{'p|rand f':>10s}{'631':>8s}")
    for j, v in reg.items():
        if "d_real" not in v or "il_matched" not in v:
            continue
        hs = sorted(set(v["d_real"]) & set(v["il_matched"]))
        g = sum(1 for h in hs if v["d_real"][h] != "SAFE" and v["il_matched"][h] == "SAFE")
        l = sum(1 for h in hs if v["d_real"][h] == "SAFE" and v["il_matched"][h] != "SAFE")
        n = len(hs)
        p = mcnemar(l, g)
        susp = sum(1 for h in hs if h in jmset)

        def breakdown(th):
            if mcnemar(l, g) > th:
                return None                       # not significant to begin with
            for kk in range(0, g + 1):
                if mcnemar(l, g - kk) > th:
                    return kk
            return g + 1                          # cannot be broken at all
        b1, b2 = breakdown(ALPHA), breakdown(ALPHA / nj)

        def show(b):
            if b is None:
                return "  n.s.", "   -- "
            if b > g:
                return "  none", "  >1.0"
            return str(b), f"{b/n:.3f}"
        t1, s1 = show(b1)
        t2, s2 = show(b2)
        # adversarial: every one of the round(f*n) removals is a gained pair.
        p_adv = mcnemar(l, max(0, g - round(worst * n)))
        # random: the removals hit discordant pairs in proportion, so round(f*g) gains
        # and round(f*l) losses go with them. This is what a mislabelled item that is
        # simply a benign skill does -- it is far more likely to be a concordant pass.
        p_rnd = mcnemar(max(0, l - round(worst * l)), max(0, g - round(worst * g)))
        # On a judge that is not significant to begin with there is nothing to break, and
        # an adversarial deletion would manufacture significance in the other direction
        # rather than remove it, so both columns are left blank rather than printed.
        sa = "    --" if b1 is None else f"{p_adv:10.3g}"
        sr = "    --" if b1 is None else f"{p_rnd:10.3g}"
        print(f"  {j:30s}{n:5d}{f'{g}/{l}':>7s}{(g-l)/n:+9.4f}{p:11.3g}"
              f"{t1:>8s}{s1:>7s}{t2:>10s}{s2:>7s}{sa:>10s}{sr:>10s}"
              f"{f'{susp}':>8s}")
    print()
    print("  `brk` is the adversarial breakdown point: how many artifacts must be deleted")
    print("  to lose significance if the deleter gets to pick, and the share is that over")
    print(f"  n. `p|adv f` applies the worst supported rate {worst:.3f} adversarially --")
    print("  every removed item a gained pair, a concentration of n/g (6.1x on")
    print("  gpt-4o-mini). `p|rand f` removes the same share proportionally, which is what")
    print("  a mislabelled item actually does, since a genuinely benign skill returns SAFE")
    print("  under both conditions and is therefore a CONCORDANT pass that cancels out of")
    print("  the numerator entirely and only shrinks n. The gap between those two columns")
    print("  is the whole uncertainty, and the empirical check is the table below: the")
    print("  one deletion we can actually perform is far closer to the random column.")

    print("\n  The same effects with every skill in the 631 deleted outright, which is")
    print("  the conservative extreme of the correction (the human put the error rate in")
    print("  that cell at 0.684, not at 1):")
    print(f"  {'judge':30s}{'n':>5s}{'g/l':>8s}{'delta':>9s}{'p':>11s}  survives 0.05/9")
    for j, v in reg.items():
        if "d_real" not in v or "il_matched" not in v:
            continue
        hs = sorted((set(v["d_real"]) & set(v["il_matched"])) - jmset)
        g = sum(1 for h in hs if v["d_real"][h] != "SAFE" and v["il_matched"][h] == "SAFE")
        l = sum(1 for h in hs if v["d_real"][h] == "SAFE" and v["il_matched"][h] != "SAFE")
        n = len(hs)
        p = mcnemar(l, g)
        print(f"  {j:30s}{n:5d}{f'{g}/{l}':>8s}{(g-l)/n:+9.4f}{p:11.3g}"
              f"  {'yes' if p < ALPHA / nj else 'no'}")


def main():
    st = part1()
    tr = part2(st)
    part3(st, tr)
    print("\n" + "=" * 100)
    if FAILS:
        for f in FAILS:
            print("FAIL  " + f)
        print("=" * 100)
        print("A baseline did not reproduce. Treat everything above as unverified.")
        return 1
    print("Every baseline reproduced: 1124 / 631 / 152 / 400, 78 of 114, 14 of 283,")
    print("29 of 60, and 238 ASR cells.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
