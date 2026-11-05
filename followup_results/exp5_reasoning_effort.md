# exp5b: does more reasoning budget fix a frontier scanner? (gpt-5.1 low vs high)

**Motivation.** The first gpt-5.1 arm ran at `reasoning_effort=low` and missed 0.52 even on
`clean` — undiluted, unfragmented, payload fully inside the window. A miss rate that high on
clean says the judge was not detecting at all, which is a confound we introduced, and it is the
one number a reviewer could use to dismiss the whole frontier panel ("you crippled it"). So we
re-ran the same items at `reasoning_effort=high`.

**Setup.** Identical to exp5: reference gpt-4o-mini caught set (165 items), `regex_real`
geometry, same `SCAN_SYS` prompt, same verdict parser, same OR-over-windows cell logic. Only
`reasoning_effort` and `max_completion_tokens` differ (512 -> 4000; one cell needed 16000).
Judge label `gpt-5.1-high` so both effort levels coexist in `exp2_cells.csv`. Attacks limited
to `clean` and `il_matched` (the baseline and the worst attack). Cost $2.37 total.

## Result: high reasoning effort made detection WORSE, not better

ASRblock = SAFE/n (miss rate; higher = worse detection). n=165 per cell, 0 ERR.

| judge | clean | il_matched |
|---|---|---|
| `gpt-5.1` (effort=low) | 0.521 [0.445, 0.596] | 0.539 [0.463, 0.614] |
| `gpt-5.1-high` (effort=high) | **0.576** [0.499, 0.649] | **0.636** [0.561, 0.706] |

Unpaired CIs overlap, so the paired test on the same items is the one that decides it.
Exact two-sided McNemar on discordant pairs:

| attack | low SAFE -> high CAUGHT | low CAUGHT -> high SAFE | p | verdict |
|---|---|---|---|---|
| clean | 2 | 11 | **0.0225** | high effort significantly worse |
| il_matched | 1 | 17 | **0.00014** | high effort significantly worse |

More deliberation flipped 28 items from caught to missed and only 3 the other way. The one cell
that truncated at 4000 output tokens, re-run with 16000, also resolved to SAFE: it deliberated
longer and still concluded the malicious skill was safe.

## Fragmentation separates only once the judge deliberates

il_matched vs clean, paired, within each effort level:

| judge | clean-caught -> il-MISSED | clean-missed -> il-caught | p |
|---|---|---|---|
| `gpt-5.1` (low) | 12 | 9 | 0.664 (ns) |
| `gpt-5.1-high` | 15 | 5 | **0.0414** |

At low effort the attack is not separable on this judge — it misses roughly half of everything,
so there is no headroom for an attack effect to show. At high effort the fragmentation attack
becomes statistically significant. This matters for how finding #1 is stated: il_matched has the
highest ASR *numerically* for all 9 judges, but the per-judge significance comes from the judges
that actually detect (gpt-4o-mini clean 0.17 -> il_matched 0.345), not from gpt-5.1.

## What this closes, and what it opens

**Closes the "you crippled the frontier model" objection.** We tested both ends of the reasoning
dial. High effort does not rescue gpt-5.1; it degrades it. Either way gpt-5.1 misses 0.52-0.64,
versus 0.17 for gpt-4o-mini and 0.24 for claude-haiku-5-5 at the same geometry. The claim
"frontier reasoning models do not straightforwardly beat small current-generation scanners"
survives, and is now robust to the obvious rebuttal.

**Opens a new, unreplicated observation.** "More reasoning budget degrades malicious-content
detection" is a surprising result and currently rests on ONE model and n=165. Stated as a
general property it would be overreach. Two honest options:
1. Report it as an observation about gpt-5.1 specifically (no further experiment needed).
2. Replicate on a second family before generalizing — the matched control is Claude with vs
   without extended thinking on the same 165 x {clean, il_matched}. Runnable on the Batch promo
   credit, which expires 2026-11-07.

We have NOT run option 2. The paper's argument does not require it; only the general claim does.

## Harness fixes made here (carry forward)

- `exp5_gpt5_judge.py` wrote CSV rows only after ALL calls finished, so a kill mid-run discarded
  every paid call. This actually happened on a ~50 min run. Added a per-call JSONL verdict cache
  (`_exp5_cache_<label>_<arm>.jsonl`) that is appended and flushed after each call and reloaded
  on restart. A kill now loses only the in-flight call.
- `max_completion_tokens=512` is wrong for any non-low reasoning effort: reasoning consumes the
  budget and the answer returns empty with `finish_reason="length"`, which would have scored as
  ERR. Added an explicit `TRUNC` outcome so truncation is visible instead of silently polluting
  the denominator, plus `--maxtok` to raise it.
- New flags: `--effort`, `--label` (so a re-run at different settings does not collide with the
  existing judge's rows), `--attacks`, `--maxtok`.
