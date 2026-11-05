# EXP2 all judges - real geometry (regex_real, cw=1000)

ASR(block) = SAFE/n (a REFUSAL counts as a block, i.e. detected). refusal% = REFUSAL/n.

## Malicious arm

| judge | n/attack | refusal% (all mal) | ASRblock clean | ASRblock il_matched | MAL verdicts |
|---|---|---|---|---|---|
| `anthropic/claude-haiku-4.5` | 92 | 0.000 | 0.391 [0.298,0.493] | 0.543 [0.442,0.641] | 362 |
| `claude-haiku-5-5` | 165 | 0.042 | 0.242 [0.183,0.313] | 0.303 [0.238,0.377] | 804 |
| `claude-opus-5-5` | 165 | 0.765 | 0.206 [0.151,0.274] | 0.309 [0.244,0.383] | 1 |
| `claude-sonnet-5-5` | 165 | 0.559 | 0.224 [0.167,0.294] | 0.333 [0.266,0.408] | 212 |
| `google/gemini-2.5-flash-lite` | 120 | 0.000 | 0.275 [0.203,0.361] | 0.35 [0.271,0.439] | 596 |
| `gpt-4o` | 58 | 0.000 | 0.241 [0.15,0.365] | 0.293 [0.192,0.42] | 303 |
| `gpt-4o-mini` | 165 | 0.000 | 0.17 [0.12,0.234] | 0.345 [0.277,0.421] | 911 |
| `gpt-5.1` | 165 | 0.000 | 0.521 [0.445,0.596] | 0.539 [0.463,0.614] | 552 |
| `gpt-5.1-high` | 165 | 0.000 | 0.576 [0.499,0.649] | 0.636 [0.561,0.706] | 130 |
| `qwen3:8b` | 120 | 0.000 | 0.2 [0.138,0.28] | 0.425 [0.34,0.514] | 621 |

## Benign arm (false positives)

| judge | n | FPR (MAL/n) | 95% Wilson | refusal% | SAFE% |
|---|---|---|---|---|---|
| `claude-haiku-5-5` | 2983 | 0.002 | [0.001, 0.005] | 0.002 | 0.996 |
| `claude-opus-5-5` | 2983 | 0.0 | [0, 0.001] | 0.004 | 0.996 |
| `claude-sonnet-5-5` | 2983 | 0.001 | [0.0, 0.002] | 0.002 | 0.997 |
| `gpt-4o-mini` | 2983 | 0.101 | [0.091, 0.113] | 0.000 | 0.899 |
| `gpt-5.1` | 2983 | 0.012 | [0.009, 0.017] | 0.000 | 0.988 |

## Key reads

- il_matched is the worst attack for every judge (highest ASRblock) -> the fragmentation evasion is model-agnostic, not a cheap-judge artifact.
- Claude frontier refusal scales with capability (haiku-5-5 ~low, sonnet-5-5 ~56%, opus-5-5 ~79% on malicious) while benign refusal stays ~0% -> refusal is a content-driven detection signal, and frontier FPR is ~0.
- gpt-5.1 (reasoning_effort=low) classifies without refusing but misses ~0.52 (near-flat across attacks; low-reasoning caveat). Frontier models do NOT straightforwardly beat the small current-gen scanners (gpt-4o-mini, haiku-5-5).

