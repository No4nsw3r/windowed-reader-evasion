# What the Judge Never Sees — research artifact

Artifact for the paper *What the Judge Never Sees: Context-Window Evasion of LLM Skill
Scanners and the Limits of Windowed Defenses.*

Agent "skills" are a natural-language `SKILL.md` plus bundled scripts, installed from public
marketplaces and screened by LLM-based scanners. This artifact holds the per-item result
tables behind every number in the paper, the scripts that derive each number from those
tables, and the two label audits the paper's claims rest on — including the human audit of
the never-caught stratum.

> **Anonymous submission.** This tree is de-identified for double-blind review: absolute
> paths are rewritten to `.`, and the build refuses to emit a tree in which any identifying
> token survives. Please do not try to attribute it.

---

## Quick start

Nothing here calls a model. Every number in the paper is recomputed from the shipped CSVs.

```bash
python -I scripts/v3_jointmiss_audit_score.py     # the human audit and the corrected floor
python -I scripts/v2_phase5_audit_score.py        # the 450-item label audit
python -I scripts/v2_label_robustness.py          # the multiply-caught restrictions
python -I scripts/v2_orgeom_indep.py              # the two-geometry independence table
```

Run them **from the repository root**: the paths are relative to it. `pandas` is the only
hard dependency for the scoring scripts; fetching the corpora additionally needs
`huggingface_hub` and `pyarrow`.

The first script is the one to run if you only run one. It refuses to report anything
unless the paper's eight published baseline figures reproduce exactly from the shipped
table, and it prints that check first:

```
| pool n                          | 1124 | 1124 |
| missed by both                  |  631 |  631 |
| OR recall                       | 0.439 | 0.439 |
...
Baseline reproduces: **True**
```

---

## Where each claim comes from

| Paper claim | Script | Data |
|---|---|---|
| Joint-miss floor: 631 of 1124 under the benchmark's labels; **0.298 [0.242, 0.353]** after the human audit; the withdrawn error correlation and its sensitivity table | `scripts/v3_jointmiss_audit_score.py` | `research_notes/v2_main/v2_layering_items.csv`, `audit_jointmiss/sheet_human.csv` |
| How the human audit packet was drawn and blinded (seed 631) | `scripts/v3_jointmiss_audit_pack.py` | `audit_jointmiss/key/key.csv` |
| Layering recall and false-positive rates for the judge, Cisco Skill Scanner and skillfrisk | `scripts/v2_layering.py` | `research_notes/v2_main/v2_layering_items.csv` + `_benign_aggregate/` |
| 450-item label audit: the disputed share of the caught set, agreement, the syntactic floor | `scripts/v2_phase5_audit_score.py` | `audit/` |
| The defense ordering under the multiply-caught restrictions, 30 comparisons of 30 | `scripts/v2_label_robustness.py` | `research_notes/v2_main/v2_phase*_items.csv` |
| The two reader geometries, their window arithmetic, and the regex-anchored reader | `scripts/v2_skillgate.py` | `research_notes/v2_main/v2_skillgate_items.csv` |
| Composing the two geometries, and the independence test on the artifacts both readers pass | `scripts/v2_orgeom_indep.py` | `followup_results/exp2_cells.csv` + the per-judge partition tables |
| Prompt Overflow's contiguity gate, swept over its calibration threshold | `scripts/v3_gate_score.py`, `scripts/v3_gate_analyze.py` | `followup_results/`, per-window scores |
| Span-level reader coverage: whether a whole malicious instruction lands in a window | `scripts/v3_span_read_frac.py` | `research_notes/v2_main/v3_span_read_frac_*.csv` |
| Cross-judge replication | `scripts/v2_phase3_cross.py`, `scripts/v2_final_recompute.py` | `research_notes/v2_main/v2_phase3_items_*.csv` |
| Figures | `scripts/make_figures.py` | `research_notes/v2_main/verified_numbers.md` |

---

## Layout

```
scripts/                     57 scripts; the analysis scripts read only the CSVs here
research_notes/v2_main/      per-item tables for the main measurement
  _benign_aggregate/         the benign arm, as counts (see below)
research_notes/pilot/        the earlier pilot measurements
followup_results/            the content-addressed geometry and the judge panel
audit/                       the 450-item label audit: items, key, rubric, both passes
audit_jointmiss/             the 150-item human audit: items, key, filled sheet
data/checksums.txt           SHA-256 of the two corpora, which are fetched, not shipped
```

`research_notes/` keeps its working name so that no script path had to be rewritten beyond
the project root; it holds result tables, not notes.

---

## What is deliberately withheld

Three things, each for a stated reason rather than by oversight.

**1. The benign arm's per-item rows.** A benign row names a real third-party skill that a
detector flagged in error, and a per-skill false-positive label is a lasting accusation
against code whose authors are not participants in this study. Every table ships its
malicious rows unchanged; the benign rows are in `_benign_aggregate/` as counts over an
allowlist of design factors and verdict columns. The counts keep every false-positive rate
and interval in the paper reachable — summing `v2_layering_items.csv` over rows where all
three scanners returned a usable verdict gives n = 400 and the five published rates,
0.050 / 0.043 / 0.087 / 0.085 / 0.130 — and `_benign_aggregate/README.md` shows that
calculation. What is gone is the mapping from skill to verdict. The benign corpus is public
and every judge is named and pinned, so a determined reader can reconstruct it by
re-issuing the calls; we decline to ship it ready-made.

**2. Stratum B of the label audit**, which is those same 77 flagged benign skills: 373 of
the 450 items ship, and the stratum-B rows are removed from the key and from both annotation
passes. The paper's finding about that stratum is a single aggregate — none of the 77 was
judged malicious, so all 24 false-positive cells stand.

**3. The de-identification term list** (`scripts/_deident_terms.py`), because it is the
authors' names. `scripts/build_artifact.py` ships and shows exactly what was rewritten and
what the build refused to emit; re-running it needs a term list of your own.

Nothing else is held back. The malicious items ship with their text, the audit sheets with
their verdicts and evidence quotes, and the human audit with its filled sheet, its blank
template and its unblinding key.

---

## The corpora

Both are CC-BY-4.0 and are fetched rather than redistributed — one of the two parquet files
is 560 MB, past GitHub's per-file limit.

```bash
python -I scripts/acquire_data.py     # MaliciousSkillBench, and a bounded SkillMD-138K sample
```

`data/checksums.txt` carries the SHA-256 and byte length of each file as measured, so you
can confirm you fetched what was measured. Most scoring scripts need no corpus at all; the
packet builders and the readers do.

---

## Known gaps, stated rather than left to be found

- **`audit/rubric_ko.md` and `audit_jointmiss/GUIDE_ko.md` are in Korean.** These are the
  two audit instruments as actually administered, so they ship unaltered rather than
  paraphrased. An English translation is not yet included; the original remains
  authoritative if one is added.
- **`scripts/v2_final_recompute.py` section 5 is a v2 computation.** It builds the
  two-geometry table with the `skillgate` reader, which is the **mistaken half window
  width** the paper corrects. The published table uses the width-corrected `regex_real`
  reader in `followup_results/exp2_cells.csv`. The two agree closely on two of the five
  judges and differ on the others, so a wrong-reader run looks plausible; gate any
  recomputation on reproducing the published cells
  (165/14/19/26, 120/19/9/20, 120/8/10/30, 92/24/5/23, 58/5/2/9) before trusting it.
  `scripts/v2_orgeom_indep.py` is the correct entry point.
- **The pilot tables in `research_notes/pilot/` are superseded.** They are included because
  the paper reports a correction to its own earlier measurement, and that correction is only
  checkable against them.
- **Per-window verdicts were not stored** for the two readers of the main measurement; both
  OR in memory and discard. Offline re-aggregation at a different threshold is therefore
  possible for the contiguity gate, which was re-scored for that purpose, and not for the
  v2 readers.

---

## Licence

A licence for the scripts and result tables is not yet chosen; it will be set before the
camera-ready release. The redistributed corpus items under `audit/items`
and `audit_jointmiss/items` come from MaliciousSkillBench and SkillMD-138K, both CC-BY-4.0,
and are included under those terms with attribution. Skill text in this artifact is inert
data: nothing here executes it, and neither should you.
