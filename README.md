<div align="center">

# What the Judge Never Sees

**Context-window evasion of LLM skill scanners, and the limits of windowed defenses**

[![license](https://img.shields.io/badge/code-MIT-blue.svg)](LICENSE)
[![data](https://img.shields.io/badge/data-CC--BY--4.0-4c1.svg)](#licence)
[![python](https://img.shields.io/badge/python-3.14%20tested-3776AB.svg)](#quick-start)
[![review](https://img.shields.io/badge/review-double--blind-lightgrey.svg)](#anonymity)
[![malicious arm](https://img.shields.io/badge/malicious%20arm-recomputes%20offline-4c1.svg)](#what-recomputes-and-what-does-not)
[![benign arm](https://img.shields.io/badge/benign%20arm-aggregates%20only-orange.svg)](#what-is-withheld)

Research artifact: the per-item tables behind the paper's malicious-arm numbers, the
scripts that derive each number from them, and both label audits — including the human
audit that corrects the paper's headline claim downward.

**The malicious arm recomputes offline: no API key, no model call, no network.** That
covers the headline floor, the two-geometry table, the whole contiguity-gate sweep, and the
10,410 judge-side cells at the vendor's released 530-pattern ruleset and the no-window
reader. The
benign (false-positive) arm ships as aggregate counts instead of per-item rows, by the
explicit decision in [What is withheld](#what-is-withheld), so its published rates stay
reachable but are not re-derivable per item. Five scripts need the two corpora fetched
first, and regenerating any judge verdict needs API keys and money.
**[Exactly which, script by script.](#what-recomputes-and-what-does-not)**

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
python -I scripts/v3_gate_analyze.py              # the contiguity gate and its theta_b sweep
python -I scripts/v3_malarm_analyze.py            # the two new readers, malicious arm
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

## What recomputes, and what does not

Established by building this tree and running each script in it, so you can tell before
downloading. These are the scripts that derive a published number; the rest of
`scripts/` is the measurement code that produced the tables.

**Recomputes from the shipped tables. `pandas` only, no key, no network.**

| | |
|---|---|
| `v3_jointmiss_audit_score.py` | the joint-miss floor and the human audit. Refuses to report unless the paper's eight baseline figures reproduce first |
| `v3_orgeom_verify.py` | the two-geometry independence table. Refuses to report unless the published cells reproduce exactly |
| `v3_gate_analyze.py` | the contiguity gate, $\theta_b$ and the full threshold sweep |
| `v2_label_robustness.py` | the defense ordering under the multiply-caught restrictions |
| `v2_phase5_audit_score.py` | the 450-item label audit, except Cohen's kappa — see the gaps below |
| `v2_final_recompute.py` | the cross-judge table, and the superseded-width record of sections 3, 3b and 5 |
| `v3_malarm_analyze.py` | the released 530-pattern ruleset and the no-window reader, judge side, malicious arm: 10,410 cells over nine judges |
| `v3_artifact_integrity.py` | the prefilter columns of every published cell, on one stated convention each. Run this first if you intend to trust anything derived |
| `v3_power_asymmetry.py` | the structural effect with exact intervals, its minimum detectable effect, and the power asymmetry between the two geometries |
| `v3_missets.py` | the two readers' miss sets at `gap_il_4x2600`, the 45 the regex reader catches and the partition passes |
| `v3_caughtset_correction.py` | the caught set's two error-rate estimates, the correction run at each, and the 18.3x insulation ratio. Its benign block reads the aggregate counts here, and says so |
| `v3_frontier_analyze.py` | the frontier full-read grid: 4,620 cells, four frontier judges, seven attacks, with exact intervals, BOTH refusal conventions and the two-route bridge. Offline; refuses to print unless every published cell reproduces |
| `v3_granularity.py` | the fragment-granularity sweep at fixed filler volume: 3,300 cells, five granularities, four readers, with the exact intervals, the sign flip and the pinned-geometry check |
| `v3_window_density.py` | the per-window payload density at both geometries, on all three of the statistics that have been compared, so the comparison that inverts cannot be repeated by accident |
| `v3_reader_disagreement.py` | the direction behind the 0.827 agreement figure: which of the two readers catches what the other passes. Refuses to print unless the published cell reproduces |
| `v2_orgeom_indep.py` | the superseded-width record only, not the published table — see the gaps below |
| `make_figures.py` | the three figures. Create `reports/` first; it does not |

**Needs the two corpora, which are fetched rather than redistributed.** Run
`scripts/acquire_data.py` (adds `huggingface_hub` and `pyarrow`, and network). No API key
and no cost. Without it these seven stop on a missing `.parquet`, which was checked by
running each one in a built tree with no corpus present: `v2_layering.py`,
`v2_skillgate.py`, `v2_phase3_cross.py`, `v3_span_read_frac.py`,
`v3_jointmiss_audit_pack.py`, `v3_real_ruleset.py` and `v3_window_density.py`. The last two
reach the corpus through `v2_skillgate.py` and `v3_span_read_frac.py` rather than reading it
themselves, which is why they were missing from this list until the run that produced it.

**Needs API keys and money to regenerate.** Every judging run — `v3_gate_score.py`,
`v3_newreaders.py`, `v3_frontier_fullfile.py`, `v2_haiku_full.py`, `validate_pipeline.py`
and the `pilot_*` family. Their outputs are what this artifact ships, so nothing above has
to call a model. `v3_frontier_fullfile.py` is the one that ran the frontier grid, at \$8.24
over 4,620 cells; `v3_frontier_analyze.py` derives every figure the appendix prints from the
two shards it left behind, so the grid is checkable without rerunning it. Those shards keep
1,666 `ERR` rows that the driver superseded on resume — it re-runs anything without a
decided verdict — and the analysis script drops them and then asserts 165 decided cells in
every one of the 28 judge-attack pairs, which is what proves the re-runs all landed.

**Blocked by the benign-arm withholding.** Two scripts stop where they reach the withheld
per-item rows:

- `v3_benarm_analyze.py`, the benign arm of the 530-pattern and no-window readers, stops on
  its own assertion, `0 benign cells, expected 2983`.
- `v2_number_audit.py` passes its layering block (10 checks) and then stops in the benign
  `tab:cost` block on a zero denominator; its section 4, the regex reader's two benign
  draws, is unreachable for the same reason.

The rates themselves survive in `_benign_aggregate/`, which is grouped counts rather than
rows, and summing it reproduces the published figures exactly:

- the regex reader's false positives, $0.1187$ over $n = 2983$ at the original window width
  and $0.1012$ over the same 2983 at the corrected one;
- all twenty values of the released-ruleset benign table — five judges $\times$ two readers
  $\times$ strict and blocked — over the 29,830 cells, counting `ERR` as no verdict.
  `python -I scripts/v3_benign_aggregate_check.py <this directory>` checks exactly that and
  exits non-zero if any of the twenty moves.

Alongside the verdict counts, `_benign_aggregate/*.prefilter.csv` carries the arm's
**prefilter** statistics as sums per judge, reader and attack: the artifact count, how many
fired, and totals of selected prompt length, hit count and payload coverage. Those are what
make the published benign firing rates ($0.644$, $0.530$, $1.000$) and mean selected lengths
recomputable here; a total over 2983 artifacts identifies no artifact, which is why it ships
where the rows do not. `v3_artifact_integrity.py` reads it when the rows are absent and says
so in a note.

What the counts cannot give back is anything that depends on row identity or row order: the
split of those 2983 into the two 1{,}500-skill draws the paper quotes separately at $0.108$
and $0.129$, any per-skill pairing, and any statistic over individual benign items.

**Blocked for an unrelated reason.** `v2_dispute_by_judge_model.py` reads
`final/results/llm_audit_trail.csv`, which is not in this tree — see
[What is withheld](#what-is-withheld).

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
| The released 530-pattern ruleset and the no-window reader, judge side, malicious arm: 10,410 cells over nine judges | `scripts/v3_malarm_analyze.py` | `followup_results/v3_newreaders_cells*.csv` |
| The same two readers' benign arm, 29,830 cells — **rates only**, from the aggregate, because the script needs the withheld per-item rows | (none; see below) | `followup_results/_benign_aggregate/v3_newreaders_cells_pubben*.csv` |
| The frontier judges reading the whole file, on all seven attacks: no attack exceeds the unattacked baseline, and the ranking of the four rows reverses between the two refusal conventions | `scripts/v3_frontier_analyze.py` | `followup_results/v3_frontier_fullfile*.csv`, and `v3_newreaders_cells*.csv` for the route bridge |
| Fragment granularity at fixed filler volume, and the 15 points of attack success that move with the reader geometry pinned | `scripts/v3_granularity.py` | `followup_results/exp4_il_granularity.csv` |
| Per-window payload density at both geometries, and the three statistics that have been confused for one another | `scripts/v3_window_density.py` | the corpus and the harness seed; no judged cells needed |
| Which reader catches what the other passes, behind the 0.827 agreement figure | `scripts/v3_reader_disagreement.py` | `research_notes/v2_main/v2_phase*_items.csv`, `v2_skillgate_items.csv` |
| Figures | `scripts/make_figures.py` | `research_notes/v2_main/verified_numbers.md` |

---

## Layout

```
.
|-- scripts/                     measurement + analysis; the analysis scripts read only the CSVs here
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

One more file is absent without having been a disclosure decision: the per-call audit trail
`final/results/llm_audit_trail.csv`, which is what `scripts/v2_dispute_by_judge_model.py`
reads to split the caught-set dispute rate by judge model version ($0.020$, 3 of 151, under
the predecessor against $0.083$, 11 of 132, under the current model). That script therefore
cannot run here. The split it computes is reported in the paper and nowhere else in this
tree; no other number depends on it.

Two further categories are withheld, and both are recurrences of the rule above in channels
the first implementation of it did not reach. They are recorded here because the earlier
release of this artifact shipped them.

- **The unpack pilot's benign control arm.** In the source table the arm is marked by
  `source_id`, `structural_family_id` and `carrier` rather than by an `arm` column, and
  `build_artifact.py` shipped whole any table that had no `arm` column. So 430 rows judging
  230 named third-party benign skills reached the tree — 22 of those rows returning
  `MALICIOUS` over 12 distinct skills — keyed by an unsalted md5 of the skill body, and all
  230 inverted against the public benign corpus to a repository and a path. The build now
  infers the arm from those three markers and routes the rows through the ordinary split, so
  they ship as counts in `_benign_aggregate/pilot_unpack2_items.csv`. The per-item file
  `research_notes/pilot/pilot_unpack2_items.csv` therefore carries 736 malicious-arm rows
  and **does** have an `arm` column, which the build adds: the column is absent upstream and
  present in what ships. No number in the paper depends on the withheld rows.
- **The two audit keys' benign control hashes.** `audit/key/key.csv` carried 30 stratum-D
  and `audit_jointmiss/key/key.csv` 15 stratum-N control items whose `skill_hash` is an md5
  of a named third-party body. Both now carry surrogates for those rows; the malicious-arm
  hashes are unchanged, so every grouping in the packets is preserved.

`build_artifact.py` ends in a **release gate** that fails the build if any shipped row pairs
a benign-arm marker with a 32-hex identifier, in any file and any column. It needs neither
corpus nor a model call, and it runs over the tree about to be published rather than over
the code that produced it, which is what the two fixes above should have been checked
against the first time.

One thing this does **not** withhold, and which a reader should know: 488 skills appear in
both public corpora, so a malicious-arm `skill_hash` can sometimes be inverted against the
benign corpus as well. The verdict on such a row is a verdict on a skill the malicious
benchmark labels malicious, which is this paper's subject, and the overlap is a property of
the two upstream releases rather than a disclosure by us.

Otherwise nothing is held back. The malicious items ship with their text, the audit sheets
with their verdicts and evidence quotes, and the human audit with its filled sheet, its
blank template and its unblinding key.

---

## Why this is releasable

The artifact ships working attack transforms and the malicious artifact text they are built
from. We judge that publishing the measurement helps defenders more than attackers, because
the vulnerable parameter is a window cap, and a window cap is invisible to a deployer who
has not tested for it: an operator cannot find this in their own stack without the
construction, while an attacker can rediscover it by reading one scanner's source. The
truncation case has already been demonstrated publicly against a deployed scanner by
others, and the payloads here are items from a public benchmark, not new malware -- nothing
in `audit/items` or `audit_jointmiss/items` was written by us.

What the release deliberately does not contain is a working end-to-end exploit against any
named production service. The readers are reconstructions measured on a public corpus. The
skill text is inert data: nothing in this tree executes it, the third-party pattern files
are parsed with `ast` and never imported, and every analysis script is safe to run with
`python -I` on a machine that has never seen the corpus.

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
  older scripts are left in place, and left at that reader, because they are the only
  reproduction of the pre-correction column the paper quotes: on `qwen3:8b` the two
  geometries tie there at exactly $0.242$ against $0.242$, which is the paper's "at the
  mistaken half width the two had tied exactly", and the cross-judge split is 70 and 50
  where the corrected width gives 70 and 45. Repointing them at `regex_real` would erase
  that and duplicate `v3_orgeom_verify.py`. Both now say so in their own text and label
  their printed output, so the numbers cannot be mistaken for the published table.
- **One figure cannot be recomputed here, because of the benign-arm withholding, and it is
  not an error in the paper.** The reliability subsample behind Cohen's kappa is 100 items
  stratified across the four strata, 25 of them stratum B; with B withheld,
  `scripts/v2_phase5_audit_score.py` computes kappa over the 75 that remain and prints
  $0.903$ and $0.899$ where the paper reports $0.942$ and $0.940$ over all 100. The stratum-A
  disputed share, 14 of 283 at $0.049$ $[0.030, 0.081]$, does reproduce exactly.
- **The contiguity gate used to be a second such figure, and is no longer.**
  `scripts/v3_gate_analyze.py` keeps only cells whose every window is present. It took the
  expected window count by joining against the published verdicts in `v2_phase1_items.csv`,
  whose benign rows are withheld and whose benign ids the window cache replaces with
  surrogates, so every benign cell dropped, $\theta_b$ — a percentile over the benign arm —
  came back undefined, and the script died on it mid-report. It now takes the count from
  `v3_gate_windows.jsonl` itself, which records `n_windows` on every window. The two counts
  agree on all 3182 cells, so no number moved: the published verdicts are still joined where
  they ship, and the script reports how many cells it could join. $\theta_b$ is again the
  99th percentile of the 11,651 benign window scores, $0.9975$, and the published threshold
  sweep recomputes offline: on the 919 fragmentation cells and the 1768 benign cells,
  fragmentation attack success $0.365 / 0.470 / 0.592 / 1.000$ against the disjunction's
  $0.373$, at benign false-positive rates $0.097 / 0.084 / 0.053 / 0.000$.
- **The per-window gate scores ship with the benign arm's skill identities replaced.** Each
  record keeps its score, window index, length and label; a benign record's `skill_hash`
  *and* the hash component of its composite `key` are both replaced by one surrogate,
  assigned in order of first appearance, because the real hash together with the per-window
  label is the benign arm's per-skill verdict. Malicious records are verbatim.
  `scripts/build_artifact.py` does this in `copy_gate_windows`, and then asserts per record
  that no 32-hex token and no occurrence of the real hash survives in any field. That
  assertion exists because an earlier release of this artifact replaced `skill_hash` and
  left the hash inside `key`, which defeated the substitution for all 11,651 benign records
  and made 300 third-party skills recoverable, 56 of them carrying a `MALICIOUS` window
  verdict. The build's identity scan could not catch it: that scan looks for the authors'
  own identifying tokens, and a third party's content hash is not one.
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
| `data/skillgate_patterns/*.py` | MIT, from `github.com/awsm-research/skillgate` at commit `c1641c5d5664634296977ff7491f4cff469acfb7`, redistributed under those terms with the notice in `data/skillgate_patterns/LICENSE`. `PROVENANCE.txt` beside them carries the sha256 of each file, and `build_artifact.py` re-derives both and refuses to build if either has changed. They are parsed with `ast`, never imported. |

The copyright line in `LICENSE` reads `The Authors` for the duration of anonymous review and
is replaced with the named authors in the archival release.

> **Skill text in this artifact is inert data.** Nothing here executes it, and neither should
> you.
