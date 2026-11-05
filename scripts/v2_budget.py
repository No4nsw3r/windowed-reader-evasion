"""v2 Phase 0-9 + 0-10: pick L_max, and price the fail-closed policy.

Phase 1 redesigns the reader as "read uncapped up to L_max, route anything longer to
human review". Two numbers decide whether that policy is affordable:

  0-9   the benign length distribution, which fixes L_max and tells us what share of
        honest skills would be routed to a human at each candidate value;
  0-10  the share of benign skills that reference something outside the bundle
        (URL, package install, remote fetch), because M2 fails closed on those and
        that cost has never been measured.

Also reports how many benign bodies each reader can hold today, which is the
cost side of lifting the cap.

TEXT ONLY, local parquet, no API. No skill text is printed.

usage: python -I scripts/v2_budget.py
"""
import os, re, sys
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import pilot_audit2 as A
import pandas as pd
import numpy as np

OUTDIR = os.path.join(A.ROOT, "research_notes", "v2_main")
OUT = os.path.join(OUTDIR, "v2_budget.md")

# out-of-bundle references: the things M2 cannot resolve statically
PATTERNS = {
    "http(s) URL":      r"https?://",
    "pip install":      r"\bpip3?\s+install\b",
    "npm/yarn install": r"\b(npm|yarn|pnpm)\s+(i|install|add)\b",
    "curl/wget":        r"\b(curl|wget)\b",
    "git clone":        r"\bgit\s+clone\b",
    "remote script run": r"\|\s*(bash|sh|python3?)\b",
    "apt/brew install": r"\b(apt-get|apt|brew)\s+install\b",
}
ANY = re.compile("|".join(f"(?:{p})" for p in PATTERNS.values()), re.I)

CANDIDATES = [8000, 10000, 16000, 22500, 32000, 50000, 100000]


def main():
    s = pd.read_parquet(A.BENIGN_FP, columns=["content"])["content"].dropna().astype(str)
    n = len(s)
    L = s.str.len()

    out = []
    W = out.append
    W("# v2 Phase 0-9 / 0-10 — L_max and the cost of failing closed\n")
    W(f"Corpus: `{os.path.basename(A.BENIGN_FP)}`, {n:,} benign SKILL.md bodies.\n")

    W("\n## Benign length distribution\n")
    W("| statistic | chars |")
    W("|---|---|")
    for lab, v in [("min", L.min()), ("p25", L.quantile(.25)), ("median", L.median()),
                   ("mean", L.mean()), ("p75", L.quantile(.75)), ("p90", L.quantile(.90)),
                   ("p95", L.quantile(.95)), ("p99", L.quantile(.99)),
                   ("p99.9", L.quantile(.999)), ("max", L.max())]:
        W(f"| {lab} | {int(v):,} |")

    W("\n## 0-9 — candidate L_max: what share of benign skills is routed to a human\n")
    W("A skill longer than L_max is not judged by the model at all; it is sent to review. "
      "That share is the direct cost of removing the window cap.\n")
    W("| L_max | benign routed to review | n routed | reader calls at 1500 stride |")
    W("|---|---|---|---|")
    for c in CANDIDATES:
        over = (L > c)
        calls = max(1, int(np.ceil((c - 2500) / 1500)) + 1)
        W(f"| {c:,} | {over.mean():.4f} | {int(over.sum()):,} | {calls} |")

    W("\n## Current readers against the same distribution\n")
    W("Share of benign bodies that already exceed what each reader covers today.\n")
    W("| reader | window union | benign exceeding |")
    W("|---|---|---|")
    for name, end in [("none (stock 8000)", 8000), ("small_chunk / dedup_small", 10000),
                      ("big_chunk", 22500)]:
        W(f"| {name} | {end:,} | {(L > end).mean():.4f} |")

    W("\n## 0-10 — fail-closed cost: benign skills that reference out-of-bundle targets\n")
    W("M2 marks a reference it cannot resolve as UNKNOWN and never SAFE. Every benign "
      "skill matching these patterns would be routed to review under that rule.\n")
    W("| pattern | benign matching | n |")
    W("|---|---|---|")
    for lab, pat in PATTERNS.items():
        m = s.str.contains(pat, case=False, regex=True, na=False)
        W(f"| {lab} | {m.mean():.4f} | {int(m.sum()):,} |")
    anym = s.str.contains(ANY, na=False)
    W(f"| **any of the above** | **{anym.mean():.4f}** | **{int(anym.sum()):,}** |")

    W("\n## Combined policy cost\n")
    W("| L_max | routed by length | routed by fail-closed | routed by either |")
    W("|---|---|---|---|")
    for c in CANDIDATES:
        over = (L > c)
        either = over | anym
        W(f"| {c:,} | {over.mean():.4f} | {anym.mean():.4f} | {either.mean():.4f} |")

    W("\n## Reading\n")
    W("- If the 'any of the above' share is large, 'the residual is made safe by failing "
      "closed' cannot stand as written: the policy would route a large share of honest "
      "skills to a human, which is the same alert-volume problem the paper warns about.\n")
    W("- L_max should be read together with that column: the length cap is cheap only "
      "where the benign tail is thin.\n")

    os.makedirs(OUTDIR, exist_ok=True)
    open(OUT, "w", encoding="utf-8").write("\n".join(out) + "\n")
    print("wrote", OUT)
    print(f"benign n={n:,} median={int(L.median()):,} p99={int(L.quantile(.99)):,}")
    print(f"fail-closed share (any out-of-bundle reference): {anym.mean():.4f}")
    for c in (10000, 22500, 50000):
        print(f"L_max {c:,}: routed by length {(L > c).mean():.4f}")


if __name__ == "__main__":
    main()
