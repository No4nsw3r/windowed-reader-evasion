# EXP 1 - matched budget with k distinct looks (`gpt-4o-mini`)

One call = one whole document in every row below. The OR rule is the one at v2_phase2_ops.py:211. Draw 0 of rep/look/shuf is byte-identical to the published artifact at v2_phase2_ops.py:173.


## OR over k, by condition

| condition | k | n | ASR | 95% Wilson | cluster 95% |
|---|---|---|---|---|---|
| rep | 1 | 165 | 0.764 | [0.693, 0.822] | [0.697, 0.83] |
| rep | 2 | 165 | 0.752 | [0.68, 0.811] | [0.685, 0.818] |
| rep | 3 | 165 | 0.745 | [0.674, 0.806] | [0.679, 0.812] |
| rep | 4 | 165 | 0.745 | [0.674, 0.806] | [0.679, 0.812] |
| rep | 5 | 165 | 0.745 | [0.674, 0.806] | [0.679, 0.812] |
| rep | 6 | 165 | 0.745 | [0.674, 0.806] | [0.679, 0.812] |
| rep | 7 | 165 | 0.745 | [0.674, 0.806] | [0.679, 0.812] |
| rep | 8 | 165 | 0.745 | [0.674, 0.806] | [0.679, 0.812] |
| rep | 9 | 165 | 0.745 | [0.674, 0.806] | [0.679, 0.812] |
| rep | 10 | 165 | 0.745 | [0.674, 0.806] | [0.679, 0.812] |
| rep | 11 | 165 | 0.745 | [0.674, 0.806] | [0.679, 0.812] |
| look | 1 | 165 | 0.77 | [0.7, 0.827] | [0.703, 0.836] |
| look | 2 | 165 | 0.661 | [0.585, 0.728] | [0.588, 0.733] |
| look | 3 | 165 | 0.618 | [0.542, 0.689] | [0.545, 0.691] |
| look | 4 | 165 | 0.582 | [0.506, 0.654] | [0.509, 0.661] |
| look | 5 | 165 | 0.545 | [0.469, 0.62] | [0.473, 0.618] |
| look | 6 | 165 | 0.509 | [0.433, 0.584] | [0.436, 0.588] |
| look | 7 | 165 | 0.503 | [0.428, 0.578] | [0.424, 0.576] |
| look | 8 | 165 | 0.479 | [0.404, 0.555] | [0.406, 0.558] |
| look | 9 | 165 | 0.467 | [0.392, 0.543] | [0.394, 0.545] |
| look | 10 | 165 | 0.455 | [0.38, 0.531] | [0.376, 0.533] |
| look | 11 | 165 | 0.448 | [0.375, 0.525] | [0.376, 0.527] |
| shuf | 1 | 165 | 0.758 | [0.687, 0.817] | [0.691, 0.824] |
| shuf | 2 | 165 | 0.648 | [0.573, 0.717] | [0.576, 0.721] |
| shuf | 3 | 165 | 0.594 | [0.518, 0.666] | [0.521, 0.667] |
| shuf | 4 | 165 | 0.57 | [0.493, 0.643] | [0.491, 0.648] |
| shuf | 5 | 165 | 0.558 | [0.481, 0.631] | [0.485, 0.63] |
| shuf | 6 | 165 | 0.545 | [0.469, 0.62] | [0.473, 0.624] |
| shuf | 7 | 165 | 0.533 | [0.457, 0.608] | [0.461, 0.612] |
| shuf | 8 | 165 | 0.515 | [0.439, 0.59] | [0.442, 0.594] |
| shuf | 9 | 165 | 0.515 | [0.439, 0.59] | [0.442, 0.594] |
| shuf | 10 | 165 | 0.515 | [0.439, 0.59] | [0.442, 0.594] |
| shuf | 11 | 165 | 0.515 | [0.439, 0.59] | [0.442, 0.594] |
| colr | 1 | 165 | 0.636 | [0.561, 0.706] | [0.564, 0.715] |
| colr | 2 | 165 | 0.63 | [0.554, 0.7] | [0.558, 0.709] |
| colr | 3 | 165 | 0.63 | [0.554, 0.7] | [0.558, 0.709] |
| colr | 4 | 165 | 0.624 | [0.548, 0.695] | [0.552, 0.703] |
| colr | 5 | 165 | 0.624 | [0.548, 0.695] | [0.552, 0.703] |
| colr | 6 | 165 | 0.624 | [0.548, 0.695] | [0.552, 0.703] |
| colr | 7 | 165 | 0.624 | [0.548, 0.695] | [0.552, 0.703] |
| colr | 8 | 165 | 0.624 | [0.548, 0.695] | [0.552, 0.703] |
| colr | 9 | 165 | 0.618 | [0.542, 0.689] | [0.545, 0.697] |
| colr | 10 | 165 | 0.618 | [0.542, 0.689] | [0.545, 0.697] |
| colr | 11 | 165 | 0.612 | [0.536, 0.683] | [0.539, 0.691] |
| coll | 1 | 165 | 0.612 | [0.536, 0.683] | [0.539, 0.691] |
| coll | 2 | 165 | 0.533 | [0.457, 0.608] | [0.461, 0.612] |
| coll | 3 | 165 | 0.497 | [0.422, 0.572] | [0.424, 0.576] |
| coll | 4 | 165 | 0.436 | [0.363, 0.513] | [0.364, 0.515] |
| coll | 5 | 165 | 0.418 | [0.346, 0.494] | [0.345, 0.497] |
| coll | 6 | 165 | 0.382 | [0.311, 0.458] | [0.309, 0.461] |
| coll | 7 | 165 | 0.376 | [0.305, 0.452] | [0.303, 0.455] |
| coll | 8 | 165 | 0.352 | [0.283, 0.427] | [0.279, 0.424] |
| coll | 9 | 165 | 0.333 | [0.266, 0.408] | [0.261, 0.406] |
| coll | 10 | 165 | 0.327 | [0.26, 0.402] | [0.255, 0.4] |
| coll | 11 | 165 | 0.327 | [0.26, 0.402] | [0.255, 0.4] |

## Same-input instability on THESE artifacts

The paper's 0.017 floor was measured on the v2_layering pool (paper_v2.tex:209-211), not on these 165 d_real artifacts. This is the floor on the artifacts actually in question.

| condition | items with all draws complete | not unanimous | rate |
|---|---|---|---|
| rep | 165 | 6 | 0.036 [0.017, 0.077] |
| colr | 165 | 9 | 0.055 [0.029, 0.1] |

## Pre-registered decision

- ASR_window at 0.1091 (1000-char windows, the call count matched to k=11)
- G  = 0.6545   whole effect attributed to window size
- F  = 0.0182   same-input noise on these artifacts
- Dl = 0.3212   distinct looks alone
- Dl - F = 0.3030 against a refute threshold of 0.3273
- Wilson-lo(ASR_look(11)) = 0.375
- common finished set: rep n=165, look n=165

**AMBIGUOUS: soften the claim and report Dl - F with its interval.**


## Free rebuttals, no calls needed

- The payload-offset half of objection 1 is false. The d_real artifact is byte-identical at all five window sizes and the payload offset is fixed at 2200-2202 per item by construction (v2_phase2_ops.py:160-168), the same at every window size.
- The window arm's call count is already in the CSV (10.96 at 1000 chars down to 2.10 at 6000) and must be printed beside every window-size point.
- Decoding to disclose: temperature 0, max_tokens 50, no top_p, no seed (pilot_audit2.py:155, :158). The 'temperature 0.7' in the docstring at v2_phase2_ops.py:13 is false and describes behaviour the code does not have.

