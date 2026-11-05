## Cell accounting (expected vs on disk)

| judge | reader | arm | expected | rows | usable |
|---|---|---|---|---|---|
| `gpt-4o-mini` | `regex_real` | mal | 1155 | 1155 | 1155 |
| `gpt-4o-mini` | `regex_real` | ben | 2983 | 2983 | 2983 |
| `gpt-4o` | `regex_real` | mal | 406 | 406 | 406 |
| `gpt-4o` | `regex_real` | ben | 0 | 0 | 0 |
| `google/gemini-2.5-flash-lite` | `regex_real` | mal | 840 | 840 | 840 |
| `google/gemini-2.5-flash-lite` | `regex_real` | ben | 0 | 0 | 0 |
| `anthropic/claude-haiku-4.5` | `regex_real` | mal | 644 | 644 | 644 |
| `anthropic/claude-haiku-4.5` | `regex_real` | ben | 0 | 0 | 0 |
| `qwen3:8b` | `regex_real` | mal | 840 | 840 | 840 |
| `qwen3:8b` | `regex_real` | ben | 0 | 0 | 0 |

All requested cells are present and usable.


## EXP 2 part V - verdicts at the real geometry

| judge | reader | attack | n | ASR | 95% Wilson | mean calls | coverage | saturated |
|---|---|---|---|---|---|---|---|---|
| `anthropic/claude-haiku-4.5` | `regex_real` | clean | 92 | 0.391 | [0.298, 0.493] | 0.88 | 0.5978 | 0.000 |
| `anthropic/claude-haiku-4.5` | `regex_real` | d_real | 92 | 0.391 | [0.298, 0.493] | 0.88 | 0.5815 | 0.000 |
| `anthropic/claude-haiku-4.5` | `regex_real` | gap_il_4x2600 | 92 | 0.511 | [0.41, 0.611] | 0.88 | 0.4304 | 0.000 |
| `anthropic/claude-haiku-4.5` | `regex_real` | il_matched | 92 | 0.543 | [0.442, 0.641] | 0.88 | 0.2769 | 0.011 |
| `anthropic/claude-haiku-4.5` | `regex_real` | neardup_10k | 92 | 0.413 | [0.318, 0.515] | 0.88 | 0.5815 | 0.000 |
| `anthropic/claude-haiku-4.5` | `regex_real` | topical_10k | 92 | 0.413 | [0.318, 0.515] | 0.88 | 0.5815 | 0.000 |
| `anthropic/claude-haiku-4.5` | `regex_real` | uniq_pad_20k | 92 | 0.402 | [0.308, 0.504] | 0.88 | 0.5815 | 0.000 |
| `google/gemini-2.5-flash-lite` | `regex_real` | clean | 120 | 0.275 | [0.203, 0.361] | 0.93 | 0.7121 | 0.000 |
| `google/gemini-2.5-flash-lite` | `regex_real` | d_real | 120 | 0.292 | [0.218, 0.378] | 0.93 | 0.7015 | 0.000 |
| `google/gemini-2.5-flash-lite` | `regex_real` | gap_il_4x2600 | 120 | 0.317 | [0.24, 0.404] | 0.93 | 0.5002 | 0.008 |
| `google/gemini-2.5-flash-lite` | `regex_real` | il_matched | 120 | 0.35 | [0.271, 0.439] | 0.93 | 0.3458 | 0.008 |
| `google/gemini-2.5-flash-lite` | `regex_real` | neardup_10k | 120 | 0.267 | [0.196, 0.352] | 0.93 | 0.7015 | 0.000 |
| `google/gemini-2.5-flash-lite` | `regex_real` | topical_10k | 120 | 0.267 | [0.196, 0.352] | 0.93 | 0.7015 | 0.000 |
| `google/gemini-2.5-flash-lite` | `regex_real` | uniq_pad_20k | 120 | 0.267 | [0.196, 0.352] | 0.93 | 0.7015 | 0.000 |
| `gpt-4o` | `regex_real` | clean | 58 | 0.241 | [0.15, 0.365] | 0.86 | 0.6368 | 0.000 |
| `gpt-4o` | `regex_real` | d_real | 58 | 0.224 | [0.136, 0.347] | 0.86 | 0.6263 | 0.000 |
| `gpt-4o` | `regex_real` | gap_il_4x2600 | 58 | 0.241 | [0.15, 0.365] | 0.86 | 0.4606 | 0.000 |
| `gpt-4o` | `regex_real` | il_matched | 58 | 0.293 | [0.192, 0.42] | 0.86 | 0.3270 | 0.017 |
| `gpt-4o` | `regex_real` | neardup_10k | 58 | 0.276 | [0.178, 0.402] | 0.86 | 0.6263 | 0.000 |
| `gpt-4o` | `regex_real` | topical_10k | 58 | 0.259 | [0.163, 0.384] | 0.86 | 0.6263 | 0.000 |
| `gpt-4o` | `regex_real` | uniq_pad_20k | 58 | 0.241 | [0.15, 0.365] | 0.86 | 0.6263 | 0.000 |
| `gpt-4o-mini` | `regex_real` | clean | 165 | 0.17 | [0.12, 0.234] | 0.91 | 0.6922 | 0.000 |
| `gpt-4o-mini` | `regex_real` | d_real | 165 | 0.2 | [0.146, 0.268] | 0.91 | 0.6831 | 0.000 |
| `gpt-4o-mini` | `regex_real` | gap_il_4x2600 | 165 | 0.242 | [0.183, 0.313] | 0.91 | 0.4971 | 0.000 |
| `gpt-4o-mini` | `regex_real` | il_matched | 165 | 0.345 | [0.277, 0.421] | 0.91 | 0.3468 | 0.006 |
| `gpt-4o-mini` | `regex_real` | neardup_10k | 165 | 0.176 | [0.125, 0.241] | 0.91 | 0.6831 | 0.000 |
| `gpt-4o-mini` | `regex_real` | topical_10k | 165 | 0.17 | [0.12, 0.234] | 0.91 | 0.6831 | 0.000 |
| `gpt-4o-mini` | `regex_real` | uniq_pad_20k | 165 | 0.176 | [0.125, 0.241] | 0.91 | 0.6831 | 0.000 |
| `qwen3:8b` | `regex_real` | clean | 120 | 0.2 | [0.138, 0.28] | 0.94 | 0.7576 | 0.017 |
| `qwen3:8b` | `regex_real` | d_real | 120 | 0.25 | [0.181, 0.334] | 0.94 | 0.7526 | 0.017 |
| `qwen3:8b` | `regex_real` | gap_il_4x2600 | 120 | 0.325 | [0.248, 0.413] | 0.94 | 0.5577 | 0.025 |
| `qwen3:8b` | `regex_real` | il_matched | 120 | 0.425 | [0.34, 0.514] | 0.94 | 0.3890 | 0.033 |
| `qwen3:8b` | `regex_real` | neardup_10k | 120 | 0.208 | [0.145, 0.289] | 0.94 | 0.7526 | 0.017 |
| `qwen3:8b` | `regex_real` | topical_10k | 120 | 0.208 | [0.145, 0.289] | 0.94 | 0.7526 | 0.017 |
| `qwen3:8b` | `regex_real` | uniq_pad_20k | 120 | 0.208 | [0.145, 0.289] | 0.94 | 0.7526 | 0.017 |

### False positives at the real geometry (denominator pinned to the union of both benign seeds)

| judge | reader | n | FPR | 95% Wilson | fire rate | saturated |
|---|---|---|---|---|---|---|
| `gpt-4o-mini` | `regex_real` | 2983 | 0.101 | [0.091, 0.113] | 0.644 | 0.124 |

Compare against the recorded cw=500 FPR of 0.119 [0.108, 0.131] on the same 2,983 denominator. A wider window that raises FPR is the cost of the coverage the real geometry buys.



