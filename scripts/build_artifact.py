"""Build the public artifact tree from the working directory.

Three jobs, in this order:

  1. Select. The working directory is 647 MB and most of it is not an artifact: the two
     corpora are 589 MB of redistributable-but-fetchable public data, `reports/` holds the
     paper source and the vendor notices, `.venv_cisco/` is a virtualenv. What ships is
     scripts, per-item result tables, the two audit packets, and a README.

  2. Withhold the benign arm's per-item rows. The paper's Open Science statement releases
     per-item tables for every number except the false-positive arm, because those rows name
     real third-party skills a detector flagged in error. For every table carrying an `arm`
     column, the `mal` rows ship unchanged and the `ben` rows are replaced by counts over an
     ALLOWLIST of design factors and verdict columns -- an allowlist, not a denylist, so a
     per-skill column cannot survive by being forgotten. The same rule removes stratum B
     (the 77 flagged benign skills) from the label-audit packet.

  3. De-identify. Every absolute path carries the author's Windows username, which is also
     their GitHub login, so the project root is rewritten to `.` and the two Korean result
     directories are renamed to ASCII. The build then re-scans its own output and FAILS if
     any identifying token survives; it never writes a tree it has not cleared.

usage: python -I scripts/build_artifact.py [outdir]
"""
import hashlib
import io
import os
import re
import shutil
import sys

import pandas as pd

sys.stdout.reconfigure(encoding="utf-8", errors="replace")

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
OUT = (sys.argv[1] if len(sys.argv) > 1 else
       os.path.join(os.path.dirname(ROOT), "artifact_windowed_reader_evasion"))

# ---------------------------------------------------------------- de-identification
# SUBS and FORBIDDEN live in scripts/_deident_terms.py, which is the only file this build
# withholds: it is the author's name, so shipping it would defeat the point. The artifact
# therefore carries this builder but not its term list, and re-running the build needs a
# term list of your own.
sys.path.insert(0, os.path.join(ROOT, "scripts"))
from _deident_terms import FORBIDDEN, SUBS     # noqa: E402

# Scripts that must not ship: the paper build names the author, the deck and the Korean
# paper build are not artifacts, and the diagnostics are throwaway probes.
SKIP_SCRIPTS = {"to_usenix_v3.py", "build_ko_pdf.py", "diag_openai.py",
                "diag_attacker.py", "_deident_terms.py"}

# ---------------------------------------------------------------- benign-arm allowlist
FACTORS = ["model", "judge", "arm", "attack", "reader", "defense", "phase", "ruleset_n",
           "dose", "share", "granularity", "effort", "condition", "k", "geometry"]
VERDICTS = ["verdict", "llm", "cisco", "skillfrisk", "fired", "decision", "outcome"]

# Prose files that ship. The measurement reports are regenerable by running the scripts,
# so only the two the shipped scripts actually read are included, plus the followup
# analyses that have no script of their own.
MD_OK = {"README.md", "exp1_distinct_looks.md", "exp2_real_geometry.md",
         "exp2_verdicts.md", "exp2_all_judges_summary.md", "exp5_reasoning_effort.md",
         "verified_numbers.md", "v3_jointmiss_audit.md"}

BENIGN_README = """# Benign arm: aggregate counts

Every table in the parent directory ships its malicious rows unchanged. The benign rows are
here instead, as counts.

The reason is in the paper's Open Science statement: a benign row names a real third-party
skill that a detector flagged in error, and a per-skill false-positive label is a lasting
accusation against code whose authors are not participants in the study. The counts keep
every false-positive rate and interval the paper reports reachable; what is withheld is the
mapping from skill to verdict.

How these were produced (`scripts/build_artifact.py`):

1. the benign rows were de-duplicated on `skill_hash` plus the design factors, keep-first,
   because two processes appended to some source files concurrently and left about two rows
   per skill -- the same de-duplication every analysis script applies;
2. the rows were then grouped by an ALLOWLIST of design factors and verdict columns and
   counted. An allowlist, not a denylist, so no per-skill column can survive by being
   overlooked. `skill_hash`, `benchmark_id`, lengths and coverage fractions are all gone.

Worked example, `v2_layering_items.csv`: summing `n` over rows where all three scanners
returned a usable verdict gives 400, and the verdict marginals give 0.050 for the LLM
judge, 0.043 for Cisco, 0.087 for skillfrisk, 0.085 for the two-way disjunction and 0.130
for the three-way -- the five rates in the paper.
"""


def subst(text):
    for a, b in SUBS:
        text = text.replace(a, b)
    return text


def copy_text(src, dst):
    os.makedirs(os.path.dirname(dst), exist_ok=True)
    t = io.open(src, encoding="utf-8", errors="replace").read()
    io.open(dst, "w", encoding="utf-8", newline="\n").write(subst(t))


def split_arm(src, dst_dir, name):
    """Malicious rows ship as they are; benign rows ship only as counts."""
    os.makedirs(dst_dir, exist_ok=True)
    try:
        d = pd.read_csv(src, on_bad_lines="skip", low_memory=False, dtype=str)
    except Exception as e:
        print("  READ FAIL %s (%s)" % (name, e))
        return 0, 0
    if "arm" not in d.columns:
        d.to_csv(os.path.join(dst_dir, name), index=False)
        return len(d), 0
    ben = d[d.arm == "ben"]
    keep = d[d.arm != "ben"]
    if "skill_hash" in d.columns:
        # The malicious rows ship with skill_hash, so a reviewer can de-duplicate them.
        # The benign aggregate drops it, so the de-duplication every analysis applies has
        # to happen HERE or the published rates become unreachable: two processes appended
        # to some of these files concurrently and left about two rows per skill. Verified
        # against v2_layering_items.csv, where this takes the benign arm to n = 400 and
        # reproduces 0.050 / 0.043 / 0.087 / 0.085 / 0.130 exactly.
        ben = ben.drop_duplicates(
            subset=["skill_hash"] + [c for c in FACTORS if c in d.columns], keep="first")
    keep.to_csv(os.path.join(dst_dir, name), index=False)
    if ben.empty:
        return len(keep), 0
    cols = ([c for c in FACTORS if c in ben.columns]
            + [c for c in VERDICTS if c in ben.columns])
    agg_dir = os.path.join(dst_dir, "_benign_aggregate")
    os.makedirs(agg_dir, exist_ok=True)
    if not cols:                      # nothing safe to group on: emit the row count only
        io.open(os.path.join(agg_dir, name.replace(".csv", ".txt")), "w",
                encoding="utf-8").write("benign rows withheld: %d\n" % len(ben))
        return len(keep), len(ben)
    agg = ben.groupby(cols, dropna=False).size().reset_index(name="n")
    agg.to_csv(os.path.join(agg_dir, name), index=False)
    io.open(os.path.join(agg_dir, "README.md"), "w", encoding="utf-8",
            newline=chr(10)).write(BENIGN_README)
    return len(keep), len(ben)


def main():
    # Clear the tree but keep .git: once the artifact has been pushed, the output
    # directory IS the working copy, and wiping its history on every rebuild would also
    # fail outright, since git marks pack files read-only.
    if os.path.exists(OUT):
        for e in os.listdir(OUT):
            if e == ".git":
                continue
            p = os.path.join(OUT, e)
            shutil.rmtree(p) if os.path.isdir(p) else os.remove(p)
    os.makedirs(OUT, exist_ok=True)
    print("building into", OUT)

    # ---- scripts
    n = 0
    for f in sorted(os.listdir(os.path.join(ROOT, "scripts"))):
        if not f.endswith(".py") or f in SKIP_SCRIPTS:
            continue
        copy_text(os.path.join(ROOT, "scripts", f), os.path.join(OUT, "scripts", f))
        n += 1
    print("  scripts: %d copied, %d withheld" % (n, len(SKIP_SCRIPTS)))

    # ---- result tables
    TABLES = [(os.path.join(ROOT, "research_notes", "v2_main"),
               os.path.join(OUT, "research_notes", "v2_main")),
              (os.path.join(ROOT, "research_notes", "pilot"),
               os.path.join(OUT, "research_notes", "pilot")),
              (os.path.join(ROOT, "followup_results"),
               os.path.join(OUT, "followup_results"))]
    kept = held = 0
    for sd, dd in TABLES:
        for f in sorted(os.listdir(sd)):
            p = os.path.join(sd, f)
            if not os.path.isfile(p):
                continue
            if f.endswith(".csv"):
                k, h = split_arm(p, dd, f)
                kept += k
                held += h
            elif f in MD_OK:
                copy_text(p, os.path.join(dd, f))
    print("  result rows: %d shipped, %d benign rows replaced by counts" % (kept, held))

    # ---- label audit (450 items): stratum B is the flagged-benign arm and is withheld
    key = pd.read_csv(os.path.join(ROOT, "audit", "key", "key.csv"), dtype=str)
    bad = set(key[key.stratum == "B"].item_id)
    key[key.stratum != "B"].to_csv(os.path.join(_mk(OUT, "audit", "key"), "key.csv"),
                                   index=False)
    ni = 0
    for f in sorted(os.listdir(os.path.join(ROOT, "audit", "items"))):
        if f.replace(".md", "") in bad:
            continue
        copy_text(os.path.join(ROOT, "audit", "items", f),
                  os.path.join(OUT, "audit", "items", f))
        ni += 1
    for sub, names in (("sheets", None), ("라벨감사_1차", None), ("라벨감사_2차", None)):
        sp = os.path.join(ROOT, "audit", sub)
        if not os.path.isdir(sp):
            continue
        dst_sub = {"라벨감사_1차": "pass1", "라벨감사_2차": "pass2"}.get(sub, sub)
        for f in sorted(os.listdir(sp)):
            p = os.path.join(sp, f)
            if not os.path.isfile(p):
                continue
            dst = os.path.join(OUT, "audit", dst_sub, _ascii(f))
            if f.endswith(".csv"):
                d = pd.read_csv(p, dtype=str)
                if "item_id" in d.columns:
                    d = d[~d.item_id.isin(bad)]
                os.makedirs(os.path.dirname(dst), exist_ok=True)
                d.to_csv(dst, index=False)
            else:
                copy_text(p, dst)
    copy_text(os.path.join(ROOT, "audit", "README.md"),
              os.path.join(OUT, "audit", "README.md"))
    copy_text(os.path.join(ROOT, "audit", "PHASE5_지침.md"),
              os.path.join(OUT, "audit", "rubric_ko.md"))
    copy_text(os.path.join(ROOT, "audit", "rubric_en.md"),
              os.path.join(OUT, "audit", "rubric_en.md"))
    print("  label audit: %d of 450 items shipped, %d stratum-B withheld"
          % (ni, len(bad)))

    # ---- human audit (150 items), shipped whole: no flagged-benign skill is in it
    src = os.path.join(ROOT, "audit_jointmiss")
    nj = 0
    for f in sorted(os.listdir(os.path.join(src, "items"))):
        copy_text(os.path.join(src, "items", f),
                  os.path.join(OUT, "audit_jointmiss", "items", f))
        nj += 1
    for rel, dst in (("key/key.csv", "key/key.csv"),
                     ("sheet.csv", "sheet_blank.csv"),
                     ("sheet_human.csv", "sheet_human.csv"),
                     ("START_HERE.md", "GUIDE_ko.md"),
                     ("GUIDE_en.md", "GUIDE_en.md")):
        copy_text(os.path.join(src, rel), os.path.join(OUT, "audit_jointmiss", dst))
    print("  human audit: %d items, the filled sheet and the key" % nj)

    # ---- corpora: checksums and fetch instructions, not the data
    lines = []
    for rel in ("data/malicious_skill_bench/primary.parquet",
                "data/skillmd_138k/train.parquet"):
        p = os.path.join(ROOT, rel)
        if not os.path.exists(p):
            continue
        h = hashlib.sha256()
        with open(p, "rb") as fh:
            for blk in iter(lambda: fh.read(1 << 20), b""):
                h.update(blk)
        lines.append("%s  %d bytes  %s" % (h.hexdigest(), os.path.getsize(p), rel))
    io.open(os.path.join(_mk(OUT, "data"), "checksums.txt"), "w",
            encoding="utf-8", newline="\n").write("\n".join(lines) + "\n")
    print("  corpora: %d checksums, data not redistributed" % len(lines))

    copy_text(os.path.join(ROOT, "scripts", "artifact_LICENSE"),
              os.path.join(OUT, "LICENSE"))
    copy_text(os.path.join(ROOT, "scripts", "artifact_README.md"),
              os.path.join(OUT, "README.md"))
    print("  README and LICENSE: copied from scripts/artifact_*")

    io.open(os.path.join(OUT, ".gitignore"), "w", encoding="utf-8", newline="\n").write(
        "__pycache__/\n*.pyc\n_scratch/\ndata/malicious_skill_bench/\n"
        "data/skillmd_138k/\n")

    # ---- the gate: re-scan the output and refuse to leave a tree that leaks
    # .git is skipped: it is local metadata, never served by Anonymous GitHub, and its
    # config necessarily holds the remote URL. The commits themselves are authored as
    # "Anonymous Author", so the history carries no name either.
    hits = []
    for dp, dirs, fs in os.walk(OUT):
        dirs[:] = [d for d in dirs if d != ".git"]
        for f in fs:
            p = os.path.join(dp, f)
            rel = os.path.relpath(p, OUT)
            for tok in FORBIDDEN:
                if tok in rel:
                    hits.append("%s  (in the path)  %s" % (tok, rel))
            try:
                t = io.open(p, encoding="utf-8", errors="replace").read()
            except Exception:
                continue
            for tok in FORBIDDEN:
                if tok in t:
                    ln = next((i for i, l in enumerate(t.split("\n"), 1) if tok in l), 0)
                    hits.append("%s  %s:%d" % (tok, rel, ln))
    print()
    if hits:
        print("IDENTITY SCAN FAILED -- %d hits, tree left in place for inspection:"
              % len(hits))
        for h in hits[:40]:
            print("  " + h)
        sys.exit(1)
    def shipped():
        for d, dirs, fs in os.walk(OUT):
            dirs[:] = [x for x in dirs if x != ".git"]
            for f in fs:
                yield os.path.join(d, f)
    files = list(shipped())
    nf = len(files)
    sz = sum(os.path.getsize(p) for p in files)
    print("identity scan clean: 0 hits over %d files" % nf)
    print("tree: %d files, %.1f MB" % (nf, sz / 1e6))
    print("non-ASCII paths left:",
          [os.path.relpath(p, OUT) for p in files
           if not all(ord(c) < 128 for c in os.path.basename(p))] or "none")


def _mk(*parts):
    p = os.path.join(*parts)
    os.makedirs(p, exist_ok=True)
    return p


def _ascii(name):
    m = {"판정_1차.csv": "verdicts_pass1.csv", "판정_2차.csv": "verdicts_pass2.csv",
         "정답키.csv": "key.csv", "판정.csv": "verdicts.csv"}
    if name in m:
        return m[name]
    return re.sub(r"[^\x00-\x7f]+", "_", name)


if __name__ == "__main__":
    main()
