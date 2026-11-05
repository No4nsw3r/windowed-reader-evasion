<div align="center">

# What the Judge Never Sees

**Context-window evasion of LLM skill scanners, and the limits of windowed defenses**

[![license](https://img.shields.io/badge/code-MIT-blue.svg)](LICENSE)
[![data](https://img.shields.io/badge/data-CC--BY--4.0-4c1.svg)](#licence)
[![python](https://img.shields.io/badge/python-3.14%20tested-3776AB.svg)](#quick-start)
[![review](https://img.shields.io/badge/review-double--blind-lightgrey.svg)](#anonymity)
[![model calls](https://img.shields.io/badge/model%20calls-none%20needed-4c1.svg)](#quick-start)

Research artifact: the per-item tables behind every number in the paper, the scripts that
derive each number from them, and both label audits — including the human audit that
corrects the paper's headline claim downward.

**Every number recomputes offline. No API key, no model call, no network.**

</div>

---

Agent "skills" are a natural-language `SKILL.md` plus bundled scripts, installed from public
marketplaces and screened by LLM-based scanners. The paper's first result needs no attack to
reach it, and this artifact is how you check it.

| | under the benchmark's labels | after the human audit |
|---|---|---|
| malicious skills in the pool | 1124 | 668 |
| missed by **both** the LLM judge and the static scanner | 631 (56%) | 199 |
| **joint-miss floor** | 0.561 | **0.298** `[0.242, 0.353]` |
| disjunction recall | 0.439 | 0.702 |
| errors correlated beyond independence | Fisher *p* = 9e-22 | **withdrawn** — *p* runs 0.00043 to 0.80 |

The audit is the point. A random 120 of the 631 were re-read by a person, blind to stratum,
provenance, upstream label and attack category, with two control strata to measure the
reader rather than the corpus. Both controls came back clean (0/15 and 0/15), and **78 of
the 114 items that got a definite verdict are benign** — 0.684 `[0.594, 0.762]`. The floor
survives that correction; one of the paper's claims does not, and the artifact carries the
sensitivity analysis that killed it.

```
                    1124 malicious skills, nothing attacked
                                     |
                 +-------------------+-------------------+
            LLM judge                              static scanner
                 +-------------------+-------------------+
                                     |
                         631 missed by both  (56%)
                                     |
                       random sample of 120, blinded
                                     |
                 human audit  --  2 control strata, 0/15 and 0/15
                                     |
                      78 of 114 benign  =  0.684 [0.594, 0.762]
                                     |
                     corrected floor  0.298 [0.242, 0.353]
```

---

## Quick start

`pandas` is the only hard dependency of the scoring scripts. Run them **from the repository
root**; the paths are relative to it.

```bash
python -I scripts/v3_jointmiss_audit_score.py     # the human audit and the corrected floor
python -I scripts/v2_phase5_audit_score.py        # the 450-item label audit
python -I scripts/v2_label_robustness.py          # the multiply-caught restrictions
python -I scripts/v3_orgeom_verify.py             # the two-geometry independence table
```

Run the first one if you only run one. It refuses to report anything unless the paper's
eight published baseline figures reproduce exactly from the shipped table, and it prints
that check before anything else:

```
| quantity         | paper | recomputed |
| pool n           |  1124 |       1124 |
| caught by both   |   152 |        152 |
| missed by both   |   631 |        631 |
| OR recall        | 0.439 |      0.439 |
| Fisher exact p   | 9e-22 |      9e-22 |

Baseline reproduces: **True**
```

Fetching the corpora additionally needs `huggingface_hub` and `pyarrow`:

```bash
python -I scripts/acquire_data.py     # MaliciousSkillBench, and a bounded SkillMD-138K sample
```

---

## Where each claim comes from

| Paper claim | Script | Data |
|---|---|---|
| Joint-miss floor: 631 of 1124 under the benchmark's labels, **0.298** `[0.242, 0.353]` after the audit, and the withdrawn error correlation with its sensitivity table | `scripts/v3_jointmiss_audit_score.py` | `research_notes/v2_main/v2_layering_items.csv`, `audit_jointmiss/sheet_human.csv` |
| How the human audit packet was drawn and blinded (seed 631) | `scripts/v3_jointmiss_audit_pack.py` | `audit_jointmiss/key/key.csv` |
| Layering recall and false-positive rates for the judge, Cisco Skill Scanner and skillfrisk | `scripts/v2_layering.py` | `research_notes/v2_main/v2_layering_items.csv` + `_benign_aggregate/` |
| 450-item label audit: the disputed share of the caught set, agreement, the syntactic floor | `scripts/v2_phase5_audit_score.py` | `audit/` |
| The defense ordering under the multiply-caught restrictions, 30 comparisons of 30 | `scripts/v2_label_robustness.py` | `research_notes/v2_main/v2_phase*_items.csv` |
| The two reader geometries, their window arithmetic, and the regex-anchored reader | `scripts/v2_skillgate.py` | `research_notes/v2_main/v2_skillgate_items.csv` |
| Composing the two geometries, and the independence test on the artifacts both readers pass | `scripts/v3_orgeom_verify.py` | `followup_results/exp2_cells.csv` + the per-judge partition tables |
| Prompt Overflow's contiguity gate, swept over its calibration threshold | `scripts/v3_gate_score.py`, `scripts/v3_gate_analyze.py` | `followup_results/`, per-window scores |
| Span-level reader coverage: whether a whole malicious instruction lands in a window | `scripts/v3_span_read_frac.py` | `research_notes/v2_main/v3_span_read_frac_*.csv` |
| Cross-judge replication | `scripts/v2_phase3_cross.py`, `scripts/v2_final_recompute.py` | `research_notes/v2_main/v2_phase3_items_*.csv` |
| Figures | `scripts/make_figures.py` | `research_notes/v2_main/verified_numbers.md` |

---

## Layout

```
.
|-- scripts/                     57 scripts; the analysis scripts read only the CSVs here
|-- research_notes/
|   |-- v2_main/                 per-item tables for the main measurement
|   |   `-- _benign_aggregate/   the benign arm, as counts -- see "What is withheld"
|   `-- pilot/                   the earlier pilot measurements
|-- followup_results/            the content-addressed geometry and the judge panel
|-- audit/                       the 450-item label audit: items, key, rubric, both passes
|-- audit_jointmiss/             the 150-item human audit: items, key, filled sheet
`-- data/checksums.txt           SHA-256 of the two corpora, which are fetched, not shipped
```

`research_notes/` keeps its working name so that no script path had to be rewritten beyond
the project root. It holds result tables, not notes.

---

## What is withheld

Three things, each for a stated reason rather than by oversight.

<table>
<tr><th align="left">What</th><th align="left">Why, and what replaces it</th></tr>
<tr>
<td><b>The benign arm's<br>per-item rows</b></td>
<td>A benign row names a real third-party skill that a detector flagged in error, and a
per-skill false-positive label is a lasting accusation against code whose authors are not
participants in this study. Every table ships its malicious rows unchanged; the benign rows
are in <code>_benign_aggregate/</code> as counts over an <i>allowlist</i> of design factors
and verdict columns, so no per-skill column can survive by being overlooked. The counts keep
every published rate reachable: summing <code>v2_layering_items.csv</code> over rows where
all three scanners returned a usable verdict gives n = 400 and
0.050 / 0.043 / 0.087 / 0.085 / 0.130, the five rates in the paper.
<code>_benign_aggregate/README.md</code> shows that calculation.</td>
</tr>
<tr>
<td><b>Stratum B of the<br>label audit</b></td>
<td>The same 77 flagged benign skills. 373 of the 450 items ship; stratum B is removed from
the key and from both annotation passes. The paper's finding about that stratum is a single
aggregate: none of the 77 was judged malicious, so all 24 false-positive cells stand.</td>
</tr>
<tr>
<td><b>The de-identification<br>term list</b></td>
<td><code>scripts/_deident_terms.py</code>, because it is the authors' names.
<code>scripts/build_artifact.py</code> ships and shows exactly what was rewritten and what
the build refused to emit; re-running it needs a term list of your own.</td>
</tr>
</table>

Nothing else is held back. The malicious items ship with their text, the audit sheets with
their verdicts and evidence quotes, and the human audit with its filled sheet, its blank
template and its unblinding key.

---

## Anonymity

This tree is de-identified for double-blind review. Absolute paths are rewritten to `.`, the
two non-ASCII result directories are renamed, and `scripts/build_artifact.py` re-scans its
own output for identifying tokens in file contents *and* in paths, exiting non-zero rather
than leaving a tree that leaks. Please do not try to attribute it.

---

## Known gaps, stated rather than left to be found

- **Both audit instruments were administered in Korean.** They ship unaltered, as
  `audit/rubric_ko.md` and `audit_jointmiss/GUIDE_ko.md`, each with an English translation
  beside it: `audit/rubric_en.md` and `audit_jointmiss/GUIDE_en.md`. The translations were
  written after the audits were complete and carry everything that governed a verdict — the
  strata, the criteria, the boundary rules, the prohibitions, the recording conventions and
  the order of work — plus, for the human audit, the interpretation that was fixed before any
  item was read. They omit sections of the originals that did not bear on judging, and say
  which. The Korean originals remain authoritative.
- **Two shipped scripts build the two-geometry table with the superseded reader.**
  `scripts/v2_orgeom_indep.py` and section 5 of `scripts/v2_final_recompute.py` both read
  `reader == "skillgate"`, which is the *mistaken half window width* the paper corrects. The
  published table uses the width-corrected `regex_real` reader in
  `followup_results/exp2_cells.csv`, paired item by item with each judge's partition
  verdicts. The two agree closely on some judges and differ on others, so a wrong-reader run
  looks plausible rather than broken, which is how it survived. **Use
  `scripts/v3_orgeom_verify.py`**: it refuses to print anything until it has reproduced the
  published cells exactly (`165/14/19/26`, `120/19/9/20`, `120/8/10/30`, `92/24/5/23`,
  `58/5/2/9`), and then runs the same table with the label-suspect skills deleted. The two
  older scripts are left in place because they produced numbers in the v2 record, not
  because they should be run now.
- **Two figures cannot be recomputed here, both because of the benign-arm withholding, and
  neither is an error in the paper.** First, the reliability subsample behind Cohen's kappa
  is 100 items stratified across the four strata, 25 of them stratum B; with B withheld,
  `scripts/v2_phase5_audit_score.py` computes kappa over the 75 that remain and prints
  $0.903$ and $0.899$ where the paper reports $0.942$ and $0.940$ over all 100. The stratum-A
  disputed share, 14 of 283 at $0.049$ $[0.030, 0.081]$, does reproduce exactly. Second,
  `scripts/v3_gate_analyze.py` keeps only cells whose every window is present and decides
  that by joining against the published verdicts in `v2_phase1_items.csv`, whose benign rows
  are withheld, so every benign cell drops and it cannot calibrate $\theta_b$. The benign
  window scores themselves do ship, under surrogate ids in `v3_gate_windows.jsonl`, so the
  quantity is directly computable: the 99th percentile of those 11,651 scores is $0.9975$.
- **The per-window gate scores ship with the benign arm's skill identities replaced.** Each
  record keeps its score, window index, length and label; a benign record's `skill_hash` is a
  surrogate assigned in order of first appearance, because the real one together with the
  per-window label is the benign arm's per-skill verdict. Malicious records are verbatim.
  `scripts/build_artifact.py` does this in `copy_gate_windows`.
- **The pilot tables in `research_notes/pilot/` are superseded.** They ship because the paper
  reports a correction to its own earlier measurement, and that correction is only checkable
  against them.
- **Per-window verdicts were not stored** for the two readers of the main measurement; both
  OR in memory and discard. Offline re-aggregation at a different threshold is therefore
  possible for the contiguity gate, which was re-scored for that purpose, and not for the v2
  readers.

---

## Licence

| What | Terms |
|---|---|
| `scripts/` | MIT, see [`LICENSE`](LICENSE) |
| the result tables under `research_notes/` and `followup_results/`, and the audit sheets and keys | CC-BY-4.0 |
| the corpus items under `audit/items` and `audit_jointmiss/items` | CC-BY-4.0, from MaliciousSkillBench and SkillMD-138K, redistributed under those terms with attribution |

The copyright line in `LICENSE` reads `The Authors` for the duration of anonymous review and
is replaced with the named authors in the archival release.

> **Skill text in this artifact is inert data.** Nothing here executes it, and neither should
> you.
