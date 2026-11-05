# Human audit of the unattacked joint-miss set

Rows: 150.  Judged: 150.  Blank or unreadable: 0.
Tier 1 complete: 75/75.

## 0. Baseline reproduction

| quantity | paper | recomputed |
|---|---|---|
| pool n | 1124 | 1124 |
| caught by both | 152 | 152 |
| independence predicts both | 87 | 87 |
| missed by both | 631 | 631 |
| independence predicts neither | 566 | 566 |
| OR recall | 0.439 | 0.439 |
| OR recall if independent | 0.496 | 0.496 |
| cisco catches, judge misses | 92 | 92 |
| Fisher exact p | 9e-22 | 9e-22 |

Baseline reproduces: **True**

## 1. Auditor calibration (the controls)

These measure the auditor's threshold, not the corpus. They do not enter the estimate.

| control | what it is | result |
|---|---|---|
| P (positive) | caught-set items the prior audit called malicious at confidence 3 | judged benign: 0/15 = 0.000 [0.000, 0.204] |
| N (negative) | benign-corpus skills no judge ever flagged | judged malicious: 0/15 = 0.000 [0.000, 0.204] |

UNCLEAR: P 0, N 0.

## 2. Label error rate inside the 631

Judged: 114 of 120 sampled (UNCLEAR 6, excluded from the rate).

- judged **BENIGN** (i.e. mislabeled): 78/114 = 0.684 [0.594, 0.762]
- judged MALICIOUS (label holds): 36/114 = 0.316 [0.238, 0.406]

Post-stratified on whether the upstream benchmark assigned an attack category (the axis the prior audit found the disputes concentrate on; the auditor could not see it):

| upstream category | judged benign |
|---|---|
| present | 37/66 = 0.561 [0.441, 0.674] |
| absent | 41/48 = 0.854 [0.728, 0.928] |

## 3. The corrected floor

An item judged benign is not malicious, so it leaves the malicious pool entirely rather than moving between cells. Correcting the joint-miss cell by the human rate above and the three caught cells by the prior LLM audit's disputed share (14/283 = 0.049, **LLM-derived, not human**):

| | raw | corrected | corrected low | corrected high |
|---|---|---|---|---|
| malicious pool n | 1124 | 668 | 619 | 725 |
| missed by both | 631 | 199 | 150 | 256 |
| **joint-miss floor** | **0.561** | **0.298** | **0.242** | **0.353** |
| OR recall | 0.439 | 0.702 | 0.758 | 0.647 |

(The low/high columns invert: a higher label-error rate removes more of the joint-miss cell, so it lowers the floor.)

## 4. Does the correlation survive the correction?

Corrected 2x2, rounded to whole skills: both 144, judge only 237, cisco only 87, neither 199 (n = 667).

- joint misses observed 199, independence predicts 187
- Fisher exact p = 0.0489  (raw table: 9e-22)
- OR recall 0.702 against 0.720 if the two were independent

That p is at the point estimate only. Every choice the correction makes moves it, and three individually defensible choices push it above $0.05$:

| choice | label-error rate used | p | floor |
|---|---|---|---|
| point estimate | 0.684 | 0.0489 | 0.298 |
| rate at its Wilson low | 0.594 | 0.000431 | 0.354 |
| rate at its Wilson high | 0.762 | 0.798 | 0.243 |
| the 6 UNCLEAR counted malicious | 0.650 | 0.00937 | 0.321 |
| the 6 UNCLEAR counted benign | 0.700 | 0.0987 | 0.288 |
| caught cells assumed correctly labelled | 0.684 (caught 0.000) | 0.0911 | 0.288 |

Range of p over those choices: 0.000431 to 0.798. Correlation claim robust at 0.05: **False**.

The floor's *level* and the *correlation* are separate claims and they do not fare the same way. The floor is stable across all of the above (0.243 to 0.354). The correlation is not: on the corrected table the excess of joint misses over independence is within noise, so the raw table's p = 9e-22 must not be carried over, and the paper should claim the floor and not the correlation.

## 5. Human against the prior LLM audit

11 joint-miss items were also in the prior LLM audit. 9 have a definite verdict on both sides; agreement on those is 9/9 = 1.000 [0.701, 1.000].

**2 excluded from that rate** because one side is UNCLEAR -- named here rather than silently dropped:
  - J023 (S0166): human BENIGN, prior UNCLEAR
  - J071 (S0372): human UNCLEAR, prior MALICIOUS

| item | human | prior LLM audit |
|---|---|---|
| J016 (S0214) | MALICIOUS | MALICIOUS |
| J030 (S0095) | BENIGN | BENIGN |
| J056 (S0313) | MALICIOUS | MALICIOUS |
| J084 (S0135) | BENIGN | BENIGN |
| J088 (S0075) | MALICIOUS | MALICIOUS |
| J096 (S0107) | MALICIOUS | MALICIOUS |
| J111 (S0405) | BENIGN | BENIGN |
| J119 (S0324) | BENIGN | BENIGN |
| J122 (S0363) | MALICIOUS | MALICIOUS |

This is the only direct measurement of the circularity objection: the prior audit was LLM-on-LLM, this one is not. n is small by construction (the prior audit sampled 64 of the 631), so read it as a direction, not a reliability coefficient.

## 6. For the paper

```
A human audit of a random sample of 114 of the 631 jointly-missed skills judged 78 of them benign (0.684 [0.594, 0.762]). Correcting the pool for that rate, and the caught cells for the 0.049 disputed share our label audit measured, puts the unattacked joint-miss floor at 0.298 [0.242, 0.353] rather than 0.561. The disjunction of the two detectors recalls 0.702 on the corrected table, against 0.720 if their misses were independent; that difference is no longer distinguishable from zero (Fisher exact p = 0.0489, and 0.000431 to 0.798 across the correction's free choices), so we claim the floor and withdraw the correlation.
```

Auditor calibration to report alongside it: positive control 0/15 = 0.000 [0.000, 0.204] judged benign, negative control 0/15 = 0.000 [0.000, 0.204] judged malicious.

