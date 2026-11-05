# VERIFIED NUMBERS — single source of truth for the detection paper

Team-lead independently recomputed every number below from the cited per-item CSV (offline, no API), 2026-10-25. The writing agents MUST cite ONLY numbers from this sheet. If a number is not here, it is not verified — do not use it. 95% Wilson CIs where given; family-clustered where noted. 0 ERR / 0 malformed in every cited CSV unless stated. ASR = fraction of a CAUGHT malicious skill that flips to SAFE (lower = better defense).

## A. EXP-UNPACK — format-hiding carrier recovery  [src: pilot_unpack2_items.csv, VERIFIED]
Caught set n=60 (gpt-4o subset n=30). Raw wrapper SKILL.md = SAFE 100% in every carrier (hiding works). Recovery = normalized bundle flips to MALICIOUS given raw SAFE.
- gpt-4o-mini recovery: archive .docx-zip 51/60=0.850; bytecode .pyc 51/60=0.850; referenced-file 57/60=0.950; window-overflow 60/60=1.000.
- gpt-4o recovery: archive 20/30=0.667; bytecode 18/30=0.600; referenced 23/30=0.767; window 24/30=0.800.
- Benign unpack FPR: body 10/200=0.050 (raw==norm, so normalization does NOT add false positives); benign carriers 2/30=0.067.
- Trail-of-Bits 4 skills: context-loader, csv-summarizer, simple-formatter all SAFE to MALICIOUS on both models; dev-env-setup stays SAFE (persuasion/social-eng attack, content never hidden, so M1/M2 out of scope; clean negative control for the module boundary).
- Mechanism note: archive/referenced recovery is design-trivial (payload preserved as plaintext member/inline); bytecode (dis disassembly) / window (padding-collapse) are non-trivial static transforms. Nothing executed (.pyc via marshal+dis, archives via zipfile).

## B. EXP-REALISM — provenance-stratified baseline recall  [src: pilot_realism_items.csv, VERIFIED full-pool]
gpt-4o-mini baseline recall by provenance (label=1): backdoored 0/80=0.000; injected 27/232=0.116; test_fixture 22/94=0.234; mixed_unresolved 30/80=0.375; wild 71/154=0.461; synthetic 109/114=0.956.
- Overall recall: simple mean 259/754=0.344; population-weighted 0.299 (state which in text).
- Benign FPR: 14/303=0.046.
- Length confound (mini, malicious): len<=3000 161/323=0.498 vs len>8000 23/178=0.129.
- gpt-4o confirmation tracks mini and does not rescue the low strata. STORY: low baseline recall is CONCENTRATED in specific strata (backdoored/injected/test_fixture), not uniform; the human/runtime-verified "wild" stratum sits ~0.46.

## C. EXP-DIL — dilution attack + the dense small-window defense  [src: pilot_dil2_items.csv, VERIFIED; 0 ERR]
Defenses: none; big_chunk (6000-char windows, cap4); small_chunk (2500/overlap1000, cap6, no collapse); dedup_small (collapse-repetition THEN 2500/1000/cap6). One skill per structural family (no pseudoreplication); 95% Wilson + family-clustered bootstrap (B=3000) are nearly identical.

### C1. gpt-4o-mini (weak model), caught set n=165, baseline recall (sample) 165/460=0.359
- rejudge (recovery floor, exact caught text): none 0/165=0.000; dedup_small 15/165=0.091 (chunking alone loses ~9%); big_chunk 0.000.
- d_real (CONTIGUOUS clean dilution, +4500 benign filler, full payload length): none 122/165=0.739 (Wilson .668–.800); dedup_small 38/165=0.230 (.173–.300); big_chunk 115/165=0.697; small_chunk 35/165=0.212.
- pa_real (payload exposed at FRONT + 9500 filler): none 72/165=0.436; dedup_small 39/165=0.236; big_chunk 77/165=0.467. (Dilution-by-ratio flips 44% even with payload in-window under a single judge.)
- f_only (filler-only control, NO payload): MAL-FPR none 3/165=0.018; dedup_small 4/165=0.024; big_chunk 3/165=0.018 (filler alone almost never triggers, so the effect is dilution not added signal).
- il_matched (INTERLEAVED, SAME 4500 filler, 8 fragments — pure placement contrast vs d_real): none 88/165=0.533; dedup_small 38/165=0.230; big_chunk 71/165=0.430; small_chunk 37/165=0.224.
- il_heavy (adversarial: 16 fragments, filler-dominant): none 130/165=0.788; dedup_small 57/165=0.345; big_chunk 90/165=0.545; small_chunk 57/165=0.345.
- **KEYSTONE RESULT (placement-robustness): dedup_small ASR is 0.230 under BOTH contiguous (d_real) AND interleaved (il_matched) at equal filler volume — delta = 0.000. Interleaving does NOT break the dense small-window defense. Adversarial stress (il_heavy) raises it only to 0.345.**
- dose-response (ASR SAFE/n, n=100/cell) none / dedup_small / big_chunk / small_chunk:
  - dose 0: 0.00 / 0.13 / 0.00 / 0.03
  - dose 1000: 0.38 / 0.22 / 0.38 / 0.20
  - dose 2000: 0.61 / 0.20 / 0.61 / 0.23
  - dose 4000: 0.73 / 0.18 / 0.75 / 0.18
  - dose 8000: 0.83 / 0.25 / 0.45 / 0.23
  - (Undefended climbs 0 to 0.83 with dose; dedup_small stays flat ~0.18–0.25 = robust to contiguous dilution; big_chunk tracks none then drops at 8000 = window artifact.)
- end-to-end recall = baseline_recall x (1 − ASR) for d_real: none 0.359x0.261=0.094; big_chunk 0.109; dedup_small 0.359x0.770=0.276.

### C2. gpt-4o (strong model), caught set n=58, baseline recall (sample) 58/250=0.232
- rejudge floor: none 0.000; dedup_small 5/58=0.086.
- d_real: none 11/58=0.190; dedup_small 2/58=0.034; big_chunk 12/58=0.207; small_chunk 4/58=0.069.
- pa_real: ~2/58=0.034 across none/dedup_small/big_chunk.
- f_only FPR: 0.000 across all defenses.
- il_matched: none 14/58=0.241; dedup_small 5/58=0.086; big_chunk 9/58=0.155; small_chunk 8/58=0.138.
- il_heavy: none 25/58=0.431; dedup_small 16/58=0.276; big_chunk 16/58=0.276; small_chunk 13/58=0.224.
- dose-response: NOT AVAILABLE — the gpt-4o dose sweep returned all-ERR (OpenAI credits exhausted mid-run); correctly excluded (never fake SAFE). STATE AS A LIMITATION. The mini dose curve + gpt-4o headline/interleave already carry the mechanism + robustness story.
- STORY: strong model is natively more robust to dilution (none 0.190 vs mini 0.739), dedup_small near-eliminates it (0.034), interleaving adds a little (0.086), worst-case stress 0.276.

## D. EXP-STATS — corroborating truncation + dilution  [src: pilot_stats_items.csv, VERIFIED; 0 ERR]
(Earlier pilot, len<=3000, smaller n; use for TRUNCATION — dil2 does not cover it — and as corroboration of dilution.)
- gpt-4o-mini: baseline recall 133/300=0.443. truncation_pad_before none 90/90=1.000 to dedup_small 17/90=0.189. dilution none 71/90=0.789 to big_chunk 70/90=0.778 to dedup_small 24/90=0.267. rejudge floor dedup_small 13/90=0.144.
- gpt-4o: baseline 43/130=0.331. truncation none 38/38=1.000 to dedup_small 1/38=0.026. dilution none 9/38=0.237 to big_chunk 8/38=0.211 to dedup_small 3/38=0.079. rejudge floor 1/38=0.026.
- NOTE: dil2 (Section C) is the AUTHORITATIVE dilution result (larger n, one-per-family, with interleave). pilot_stats dilution (0.789 to 0.267, floor 0.144) is an earlier, smaller, non-family-clustered sample; cite dil2 as primary, pilot_stats as corroborating. Truncation (1.000 to 0.189 mini / 0.026 gpt-4o) is from pilot_stats and is verified.

## E. PRIOR-PILOT NUMBERS — NOT independently recomputed this session (no per-item CSV available)
Cite these as prior in-environment pilots with appropriate hedging; do NOT present as freshly re-verified.
- E-FPR (pilot_fpr_results.md): at scale (mini, mal 400 / benign 1500) none TPR 0.30 / FPR 0.043; dedup_small TPR 0.40 / FPR 0.109. gpt-4o none TPR 0.23 / FPR ~0; dedup_small TPR 0.29 / FPR 0.042. Precision at realistic 0.1% prevalence = 0.4–0.7% for every config, so the detector is a TRIAGE/ranking/evidence layer, NEVER an autonomous blocker. dedup_small raises robustness but roughly triples benign FPR (0.043 to 0.109): the value is robustness, not absolute precision.
- E-ADAPT (pilot_adapt_results.md): fixed overlapping-window dedup_small already resists geometry attacks (boundary_split 0.128 ~ floor); multi-offset/multi-size ENSEMBLE restores (boundary_split 0.128 to 0.026; all_combined to 0.051) at ~2.9 calls/skill. Worst-case residual = naive COMBINATION: trunc_dilute 0.359, trunc_persuade 0.538 (to 0.256 under provenance-strip).
- PERSUASION ASR (prior pilots, no items CSV): ~0.237 (mini) / ~0.056 (gpt-4o). NOT recomputed; and per guardrails persuasion-is-weak is PRIOR ART (do not claim as new). Prefer to treat persuasion via the dev-env-setup ToB case + M4 provenance-separation, not a headline bar.

## F. PRIOR-ART GUARDRAILS — claims the paper must NOT make (see memory detection-paper-design, verify-citations-primary-source)
1. Do NOT say "19% of skills are adversarial" (BIV's 18.9% = share of classified deviations; skill-level rate 8.8%).
2. "~1.3% precision at 0.1% prevalence" is OUR derivation from BIV recall 0.978 / FPR 7.2% — label as our calculation, not BIV's reported number.
3. Do NOT call declared-vs-observed matching a "known-weak" detector unqualified (BIV F1 0.946); the defensible claim is that the signal is NON-SPECIFIC (mismatch common in benign skills), so M5 is a cited baseline, not a module.
4. Do NOT present our truncation result or "persuasion is weakest" as NEW — "Under the Hood of SKILL.md" (2605.11418) already reports both. LEAD with the measured DEFENSE (dilution recovery incl. interleave), EvasionBench, and payload-preservation/confound-correction methodology.
5. "RARE" (2607.12507) is not a real paper name — drop it.

Citations: 25 primary-source-verified + 7 new (BIV 2605.11770, SkillConsist 2608.07639, SKILLSCOPE 2605.12875, Beyond Maliciousness 2610.19264, Under the Hood of SKILL.md 2605.11418, SkillVetBench 2606.15899, Cross-Layer Misalignment 2607.10534); CASHEWS 2609.18862 + SkillsMetric already in the 25. Full list: research_notes/v2_main/new_citations_verified.md. Author-year-word bibitem keys (e.g. wu2026biv).
