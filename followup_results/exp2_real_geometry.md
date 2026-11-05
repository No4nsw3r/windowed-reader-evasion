# EXP 2 part R - what the existing CSV already settles, for $0

Source: v2_skillgate_items.csv, 21558 rows, 19600 with a usable verdict. No model call and no corpus read was needed for anything below.


## R1. The 500-vs-1500 bracket the real geometry sits inside (gpt-4o-mini)

The real width is cw=1000, exactly between the two widths already measured, so the DIRECTION of every effect below is already established on this judge.

| attack | reader | n | ASR | 95% Wilson | coverage | mean prompt chars |
|---|---|---|---|---|---|---|
| clean | `skillgate` | 165 | 0.261 | [0.2, 0.332] | 0.5065 | 2074 |
| clean | `regex_wide` | 165 | 0.17 | [0.12, 0.234] | 0.7849 | 3192 |
| d_real | `skillgate` | 165 | 0.261 | [0.2, 0.332] | 0.5021 | 2113 |
| d_real | `regex_wide` | 165 | 0.194 | [0.141, 0.261] | 0.7701 | 3547 |
| uniq_pad_20k | `skillgate` | 165 | 0.255 | [0.194, 0.326] | 0.5021 | 2076 |
| uniq_pad_20k | `regex_wide` | 165 | 0.17 | [0.12, 0.234] | 0.7701 | 3251 |
| neardup_10k | `skillgate` | 165 | 0.261 | [0.2, 0.332] | 0.5021 | 2076 |
| neardup_10k | `regex_wide` | 165 | 0.158 | [0.11, 0.221] | 0.7701 | 3251 |
| topical_10k | `skillgate` | 165 | 0.261 | [0.2, 0.332] | 0.5021 | 2076 |
| topical_10k | `regex_wide` | 165 | 0.158 | [0.11, 0.221] | 0.7701 | 3251 |
| gap_il_4x2600 | `skillgate` | 165 | 0.267 | [0.205, 0.339] | 0.4217 | 2192 |
| gap_il_4x2600 | `regex_wide` | 165 | 0.309 | [0.244, 0.383] | 0.5054 | 4006 |
| il_matched | `skillgate` | 165 | 0.285 | [0.221, 0.358] | 0.3372 | 2272 |
| il_matched | `regex_wide` | 165 | 0.321 | [0.255, 0.396] | 0.4631 | 4611 |

Wider windows do NOT uniformly help: clean ASR falls 0.261 -> 0.170 but gap_il_4x2600 rises 0.267 -> 0.309 and il_matched 0.285 -> 0.321. The real geometry is wider than what was measured, so promoting it improves the position cells and DEGRADES the fragmentation cells the headline rests on.


## R2. Prefilter fire rate per judge (the gate behind the low FPR)

| judge | arm | cells | calls | fire rate | mean prompt chars when it fires |
|---|---|---|---|---|---|
| `anthropic/claude-haiku-4.5` | mal | 644 | 567 | 0.880 | 2019 |
| `google/gemini-2.5-flash-lite` | mal | 840 | 784 | 0.933 | 2185 |
| `gpt-4o` | mal | 406 | 350 | 0.862 | 2201 |
| `gpt-4o-mini` | ben | 2983 | 1920 | 0.644 | 3397 |
| `gpt-4o-mini` | mal | 1155 | 1050 | 0.909 | 2338 |
| `qwen3:8b` | mal | 840 | 791 | 0.942 | 2472 |

## R3. The cap-liveness test - the paper's most exposed sentence

paper_v2.tex:783-786 says the 20-window / 8k cap "is not a live parameter in this design". skillgate caps its prompt at 8674 chars (v2_skillgate.py:100), but A.call truncates every prompt at 8000 (pilot_audit2.py:135), so 8000 is the cut the judge sees and the one saturation is measured against.

- MALICIOUS arm: 0 of 1155 paired gpt-4o-mini cells have regex_nocap above skillgate; max skillgate prompt 6731 < 8000, so the window does not bite here. **The claim holds on this arm.**
- BENIGN arm: 210 of 1920 fired rows reach the 8000-char window the judge sees. FPR among them 0.371 [0.309, 0.439] against 0.161 [0.145, 0.18] for the rest. **The claim is already false on the arm the false-positive rate comes from.** Doubling the window width can only push more benign rows into the cap, so this sentence must be rewritten whatever the paid run says.

## R4. The benign denominator, pinned

v2_skillgate.py:240-243 runs two benign seeds: `benign` at D.SEED with all three readers and `benign2` at D.SEED+1 with skillgate only. The paper quotes 0.129 (:795), 0.128 (:881) and 0.108 (:953) against "1500 benign skills".

| denominator | n | FPR | 95% Wilson |
|---|---|---|---|
| union of both seeds | 2983 | 0.119 | [0.108, 0.131] |
| fired rows only | 1920 | 0.184 | [0.168, 0.202] |

Pick ONE and state it. The union is the honest denominator because the unfired rows are real clean verdicts the deployed gate produces for free.


## R5. Empty cells - do not build a table on these

| judge | reader | attacks present |
|---|---|---|
| `gpt-4o` | `trunc10k` | missing d_real, gap_il_4x2600, il_matched |
| `gpt-4o` | `trunc12k` | missing d_real, gap_il_4x2600, il_matched |

## R6. Pure text fixes, zero credits

- Name the artifacts: the malicious benchmark (paper_v2.tex:201), the 138,133 SKILL.md corpus (:205-206) and the static scanner (:676, :682, :684) are all unnamed. Naming the scanner turns an anonymous baseline into a named vendor reported at 0.418 recall - a disclosure decision for the author, not a mechanical edit.
- Fix the attribution of the capped partition. paper_v2.tex:402-404 calls the 2500/stride-1500/cap-6 reader "The published defense" with no citation; the geometry is the authors' own (v2_phase1_kill.py:70, :82) and the only published thing is Saha et al.'s unevaluated "full-file or chunked review" recommendation (paper_v2.tex:91-92).
- Add a judge-generation limitation sentence. No sentence anywhere acknowledges that all five judges are cheap-tier and two are 2024-era (paper_v2.tex:221-223).
- Delete or correct HANDOFF.md:604, which claims the 530-pattern prefilter and the real window were implemented. HANDOFF.md:158 already contradicts it.

