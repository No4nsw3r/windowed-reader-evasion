r"""How much can the frontier full-read grid actually resolve?

WHY THIS SCRIPT EXISTS. Appendix~\ref{sec:appfrontier} reports that no attack in the
seven-attack subgrid exceeds the unattacked baseline on any of the four frontier judges,
and the body treats that as answering the attack-coverage objection. A reviewer on the
attack axis checked the claim against two corrections the paper itself owns and found it
does not survive either of them on `claude-haiku-5-5` --- the one row the paper singles out
as the only one whose ranking does not depend on how refusals are counted. This script is
that check, run by us, on all four combinations of the two conventions and the two
populations, so the claim is stated at the strength it actually has.

THE TWO CORRECTIONS, BOTH THE PAPER'S OWN.

  Convention. Attack success counts a refusal as a block (\S\ref{sec:refusal}). The
  alternative discards refused cells. The paper reports both for the deployment table and
  says the ordering reverses; it did not apply the second to the per-attack ranking.

  Population. The label audit disputes 14 of the 283 caught-set items it scored, a share of
  0.0495 (\S\ref{sec:audit}). Nine of those 14 are inside this grid's 165 artifacts. An
  item that is not malicious cannot be an attack success, so dropping them is the same
  correction \S\ref{sec:floor} applies to the floor. The consensus rule and the stratum are
  the project's own: `v2_phase5_audit_score.py` lines 160-175 for the consensus and line
  207 for the caught-set stratum, and `followup_results/v3_disputed_in_grid.json` records
  the hashes this script drops together with the rule that selected them.

WHAT IT FINDS. The nine disputed artifacts are 5.5% of the population and carry a large
share of the three Claude judges' entire measured attack success, because an item whose
label is wrong is exactly an item a judge reads as benign. The script prints that share
rather than asserting it. Where "no attack exceeds clean" fails, it names the cell.

THE SECOND MEASUREMENT. Every attack in this grid lengthens the artifact, refusal is the
mechanism behind most of the Claude judges' blocks, and attack success counts a refusal as
a block -- so an attack that raises refusal lowers attack success without the judge having
detected anything. The script reports per-attack refusal at this reader, which the paper
does not publish, and the rank correlation between refusal and artifact length. Statistics
are scipy-free and reused from `v3_granularity`.

usage: python -I scripts/v3_grid_robustness.py
exit:  0 always; this script reports, and the assertions guard only its own inputs
"""
import collections
import csv
import glob
import io
import json
import os
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
FR = os.path.join(ROOT, "followup_results")
sys.path.insert(0, os.path.join(ROOT, "scripts"))

from v3_granularity import clopper_pearson, spearman      # noqa: E402

JUDGES = ["claude-opus-5-5", "claude-sonnet-5-5", "claude-haiku-5-5", "openai/gpt-5.1"]
ATTACKS = ["clean", "d_real", "neardup_10k", "topical_10k", "uniq_pad_20k",
           "gap_il_4x2600", "il_matched",
           # added after the first seven, when the four conditions the paper had named as
           # unmeasured at this reader were run
           "uniq_suf_20k", "uniq_pad_50k", "gap_il_6x3000", "il_heavy"]
DEC = ("SAFE", "MALICIOUS", "REFUSAL")
N_CELL = 165

sys.stdout.reconfigure(encoding="utf-8", errors="replace")


def load():
    rows = []
    for fp in sorted(glob.glob(os.path.join(FR, "v3_frontier_fullfile*.csv"))):
        with io.open(fp, encoding="utf-8") as fh:
            rows += [r for r in csv.DictReader(fh) if r["verdict"] in DEC]
    assert rows, "no frontier grid shards found"
    seen, dedup = set(), []
    for r in rows:
        k = (r["judge"], r["attack"], r["skill_hash"])
        if k in seen:
            continue            # an interrupted resume wrote some cells twice; keep the first
        seen.add(k)
        dedup.append(r)
    by = collections.defaultdict(list)
    for r in dedup:
        by[(r["judge"], r["attack"])].append(r)
    bad = {k: len(v) for k, v in by.items() if len(v) != N_CELL}
    assert not bad, "grid cells not at n=%d: %s" % (N_CELL, bad)
    return by


def drop_set():
    fp = os.path.join(FR, "v3_disputed_in_grid.json")
    assert os.path.exists(fp), (
        "followup_results/v3_disputed_in_grid.json is missing; it records which audit-"
        "disputed artifacts this grid contains and the rule that selected them")
    d = json.loads(io.open(fp, encoding="utf-8").read())
    assert d["n_grid"] == N_CELL
    return set(d["hashes"]), d["rule"]


def asr(rows, discard=False, drop=frozenset()):
    """Attack success. `discard` drops refused cells; `drop` removes artifacts."""
    v = [r for r in rows if r["skill_hash"] not in drop]
    if discard:
        v = [r for r in v if r["verdict"] != "REFUSAL"]
    if not v:
        return None, 0, 0
    k = sum(1 for r in v if r["verdict"] == "SAFE")
    return k / len(v), k, len(v)


def main():
    by = load()
    drop, rule = drop_set()
    short = [j.split("/")[-1] for j in JUDGES]

    print("Can the frontier full-read grid rank its attacks?")
    print("=" * 78)
    print("  grid: 4 judges x %d conditions x %d artifacts" % (len(ATTACKS), N_CELL))
    print("  audit-disputed artifacts inside it: %d (%.1f%% of the population)"
          % (len(drop), 100.0 * len(drop) / N_CELL))
    print("  selection rule: %s" % rule)
    print()

    # ---- how much of the measured attack success sits on the disputed artifacts
    print("Share of each judge's measured attack success carried by those %d artifacts"
          % len(drop))
    print("-" * 78)
    print("  %-20s %8s %10s %9s" % ("judge", "SAFE", "of which", "share"))
    for i, j in enumerate(JUDGES):
        tot = dis = 0
        for a in ATTACKS:
            for r in by[(j, a)]:
                if r["verdict"] == "SAFE":
                    tot += 1
                    if r["skill_hash"] in drop:
                        dis += 1
        sh = ("%.3f" % (dis / tot)) if tot else "--"
        print("  %-20s %8d %10d %9s" % (short[i], tot, dis, sh))
    print()
    print("  An item whose label the audit disputes is an item a judge reads as benign, so")
    print("  this is where attack success concentrates by construction. The question the")
    print("  table below asks is what is left once they are removed.")
    print()

    # ---- the four readings
    for discard in (False, True):
        for corrected in (False, True):
            dp = drop if corrected else frozenset()
            conv = "refusal DISCARDED" if discard else "refusal as BLOCK"
            pop = ("corrected, n=%d" % (N_CELL - len(drop))) if corrected \
                else ("as published, n=%d" % N_CELL)
            print("%s | %s" % (conv, pop))
            print("-" * 78)
            print("  " + "attack".ljust(16) + "".join(s[:13].rjust(16) for s in short))
            cells = {}
            for a in ATTACKS:
                line = "  " + a.ljust(16)
                for j in JUDGES:
                    v, k, n = asr(by[(j, a)], discard, dp)
                    cells[(j, a)] = v
                    line += ("--" if v is None else "%.4f (%d/%d)" % (v, k, n)).rjust(16)
                print(line)
            worse = []
            for i, j in enumerate(JUDGES):
                base = cells[(j, "clean")]
                if base is None:
                    continue
                for a in ATTACKS[1:]:
                    v = cells[(j, a)]
                    if v is not None and v > base + 1e-12:
                        worse.append("%s: %s %.4f > clean %.4f" % (short[i], a, v, base))
            if worse:
                print("  ATTACKS ABOVE THE UNATTACKED BASELINE:")
                for w in worse:
                    print("    " + w)
            else:
                print("  no attack exceeds the unattacked baseline on any judge")
            print()

    # ---- refusal: the channel the grid's attack signal actually moves
    print("Per-attack refusal at this reader, which the paper does not publish")
    print("=" * 78)
    print("  " + "attack".ljust(16) + "".join(s[:13].rjust(16) for s in short)
          + "   mean artifact")
    lens, refs = collections.defaultdict(list), collections.defaultdict(list)
    for a in ATTACKS:
        line = "  " + a.ljust(16)
        al = []
        for j in JUDGES:
            rows = by[(j, a)]
            rr = sum(1 for r in rows if r["verdict"] == "REFUSAL") / len(rows)
            line += ("%.3f" % rr).rjust(16)
            lens[j].append(sum(float(r["artifact_len"]) for r in rows) / len(rows))
            refs[j].append(rr)
            al += [float(r["artifact_len"]) for r in rows]
        print(line + "   %12.0f" % (sum(al) / len(al)))
    print()
    print("  Rank correlation between a condition's refusal rate and its artifact length,")
    print("  over the %d conditions:" % len(ATTACKS))
    for i, j in enumerate(JUDGES):
        rho, p = spearman(lens[j], refs[j])
        print("    %-20s rho = %+.3f   p = %.4f   (n = %d conditions)"
              % (short[i], rho, p, len(ATTACKS)))
    print()
    print("  Every attack in the grid lengthens the artifact, and attack success counts a")
    print("  refusal as a block, so a condition that raises refusal lowers attack success")
    print("  whether or not the judge read the payload. That is a property of the metric")
    print("  and the judge, not evidence that the reader resisted the attack.")
    print()

    # ---- how thin is the answered population
    print("Cells the judge actually answered, by judge, pooled over all %d conditions"
          % len(ATTACKS))
    print("-" * 78)
    for i, j in enumerate(JUDGES):
        tot = sum(len(by[(j, a)]) for a in ATTACKS)
        ans = sum(1 for a in ATTACKS for r in by[(j, a)] if r["verdict"] != "REFUSAL")
        mal = sum(1 for a in ATTACKS for r in by[(j, a)] if r["verdict"] == "MALICIOUS")
        print("  %-20s answered %4d of %4d (%.3f)   explicit MALICIOUS %4d"
              % (short[i], ans, tot, ans / tot, mal))
    print()
    print("Done.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
