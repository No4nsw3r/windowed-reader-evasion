# Phase 5 - label audit

Annotators with filled rows: adjudicated, annot1, annot2


## Inter-annotator agreement (n=75 items both scored)

- raw agreement: 0.96
- Cohen's kappa, 3 levels: 0.903
- Cohen's kappa, malicious vs not: 0.899
- disagreements: 3 (S0012, S0060, S0061)

Adjudicate every disagreement before quoting the numbers below: both annotators re-read those items together and record one verdict per item in audit/sheets/sheet_adjudicated.csv, which this script then picks up as a third annotator.


Adjudicated verdicts applied: 3 items.


## Agreement with the upstream label, by stratum

| stratum | n scored | upstream | called malicious | called benign | unclear | disputed share [95% CI] |
|---|---|---|---|---|---|---|
| A | 283 | malicious | 263 | 14 | 6 | 0.049 [0.03, 0.081] |
| C | 60 | malicious | 29 | 29 | 2 | 0.483 [0.362, 0.607] |
| D | 30 | benign | 0 | 30 | 0 | 0.0 [0, 0.114] |

Stratum key: A = caught set, which every ASR in the paper rests on; B = benign-corpus skills a judge flagged, the FPR numerator; C = low-recall provenance no judge flagged; D = unflagged benign control, which measures the annotators rather than the corpus.


## Disputed malicious labels by provenance

| provenance | n | called benign | share |
|---|---|---|---|
| backdoored | 12 | 7 | 0.583 |
| injected | 112 | 23 | 0.205 |
| mixed_unresolved | 174 | 10 | 0.057 |
| synthetic | 21 | 1 | 0.048 |
| test_fixture | 9 | 1 | 0.111 |
| wild | 15 | 1 | 0.067 |

## Effect on the paper's numbers

Excluded from the malicious arm: 43 items. Excluded from the benign arm: 0 items.


### ASR cells that move by at least 0.02 (7 of 238)

|                                                                            |   k_all |   n_all |   asr_all |   lo_all |   hi_all |   k_audited |   n_audited |   asr_audited |   lo_audited |   hi_audited |   delta |
|:---------------------------------------------------------------------------|--------:|--------:|----------:|---------:|---------:|------------:|------------:|--------------:|-------------:|-------------:|--------:|
| ('v2_phase1', 'gpt-4o', 'gap_il_4x2600', 'dedup_small')                    |      23 |      58 |     0.397 |    0.281 |    0.525 |          21 |          56 |         0.375 |        0.26  |        0.506 |  -0.022 |
| ('v2_phase3', 'anthropic/claude-haiku-4.5', 'gap_il_4x2600', 'dedup_full') |      28 |      92 |     0.304 |    0.22  |    0.405 |          24 |          86 |         0.279 |        0.195 |        0.382 |  -0.025 |
| ('v2_phase3', 'anthropic/claude-haiku-4.5', 'gap_il_4x2600', 'dedup_lmax') |      28 |      92 |     0.304 |    0.22  |    0.405 |          24 |          86 |         0.279 |        0.195 |        0.382 |  -0.025 |
| ('v2_phase3', 'anthropic/claude-haiku-4.5', 'il_heavy', 'dedup_full')      |      24 |      92 |     0.261 |    0.182 |    0.359 |          20 |          86 |         0.233 |        0.156 |        0.332 |  -0.028 |
| ('v2_phase3', 'anthropic/claude-haiku-4.5', 'il_heavy', 'dedup_lmax')      |      23 |      92 |     0.25  |    0.173 |    0.347 |          19 |          86 |         0.221 |        0.146 |        0.319 |  -0.029 |
| ('v2_phase3', 'anthropic/claude-haiku-4.5', 'il_heavy', 'dedup_small')     |      24 |      92 |     0.261 |    0.182 |    0.359 |          20 |          86 |         0.233 |        0.156 |        0.332 |  -0.028 |
| ('v2_phase3', 'anthropic/claude-haiku-4.5', 'il_heavy', 'none')            |      60 |      92 |     0.652 |    0.551 |    0.742 |          54 |          86 |         0.628 |        0.522 |        0.723 |  -0.024 |


### Benign FPR, before and after

Not computable here: the benign arm's per-item rows are withheld from the
public artifact, because a per-skill false-positive label is a lasting
accusation against third-party code. The per-judge counts that reproduce
every published false-positive rate are in
`research_notes/v2_main/_benign_aggregate/`, and its README works the
calculation through. Everything above this line is unaffected.

