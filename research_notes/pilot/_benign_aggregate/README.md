# Benign arm: aggregate counts

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
