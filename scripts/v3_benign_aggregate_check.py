r"""Does the shipped benign AGGREGATE reproduce the released-ruleset benign table?

The artifact README now claims it does: all twenty values, five judges x two readers x the
strict and blocked conventions, over the 29,830 cells, counting ERR as no verdict. That is
a claim about the tree a reviewer downloads, so it is checked against the tree and not
against the source CSVs.

The two shards overlap by design: thirteen cells errored in the first run and succeeded on
retry in the second. Dropping ERR and summing both files has to land on exactly 2983 per
judge x reader, or the denominator is wrong and every rate with it.
"""
import collections
import csv
import glob
import os
import sys

# usage: python -I scripts/v3_benign_aggregate_check.py <built-artifact-root>
# Build one first with:  python -I scripts/build_artifact.py <dir>
if len(sys.argv) < 2:
    sys.exit("usage: python -I scripts/v3_benign_aggregate_check.py "
             "<built-artifact-root>; build one first with "
             "python -I scripts/build_artifact.py <dir>")
AGG = os.path.join(sys.argv[1], "followup_results", "_benign_aggregate")

# What the paper's appendix table prints, to 3 decimals: (strict, blocked).
WANT = {
    ("gpt-4o-mini", "skillgate530"):       (0.068, 0.068),
    ("gpt-4o-mini", "fullfile"):           (0.043, 0.043),
    ("openai/gpt-5.1", "skillgate530"):    (0.029, 0.029),
    ("openai/gpt-5.1", "fullfile"):        (0.047, 0.047),
    ("claude-haiku-5-5", "skillgate530"):  (0.001, 0.030),
    ("claude-haiku-5-5", "fullfile"):      (0.001, 0.063),
    ("claude-sonnet-5-5", "skillgate530"): (0.001, 0.007),
    ("claude-sonnet-5-5", "fullfile"):     (0.001, 0.008),
    ("claude-opus-5-5", "skillgate530"):   (0.000, 0.005),
    ("claude-opus-5-5", "fullfile"):       (0.001, 0.007),
}

cnt = collections.defaultdict(collections.Counter)
files = [p for p in sorted(glob.glob(os.path.join(AGG, "v3_newreaders_cells_pubben*.csv")))
         if not p.endswith(".prefilter.csv")]   # those carry sums, not verdict counts
if not files:
    sys.exit("no pubben aggregate in the built tree: " + AGG)
for p in files:
    with open(p, newline="", encoding="utf-8") as f:
        rdr = csv.DictReader(f)
        assert "skill_hash" not in rdr.fieldnames, (
            "the aggregate still carries skill_hash; the withholding is not in effect")
        for r in rdr:
            if r["arm"] != "ben" or r["verdict"] == "ERR":
                continue
            cnt[(r["judge"], r["reader"])][r["verdict"]] += int(r["n"])

print(f"aggregated {len(files)} file(s) from the built tree\n")
print(f"{'judge':20s}{'reader':14s}{'n':>6s}{'strict':>9s}{'want':>8s}"
      f"{'blocked':>10s}{'want':>8s}  ok")
bad = 0
for (j, rd), want in WANT.items():
    c = cnt[(j, rd)]
    n = sum(c.values())
    s = c["MALICIOUS"] / n
    b = (c["MALICIOUS"] + c["REFUSAL"]) / n
    ok = n == 2983 and round(s, 3) == want[0] and round(b, 3) == want[1]
    bad += not ok
    print(f"{j:20s}{rd:14s}{n:6d}{s:9.4f}{want[0]:8.3f}{b:10.4f}{want[1]:8.3f}"
          f"  {'yes' if ok else 'NO'}")
total = sum(sum(c.values()) for c in cnt.values())
print(f"\ntotal cells recovered: {total:,} (expected 29,830)")
print("ALL TWENTY VALUES REPRODUCE" if not bad and total == 29830
      else f"{bad} cell(s) wrong")
sys.exit(1 if bad or total != 29830 else 0)
