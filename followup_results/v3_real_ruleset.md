# The released SkillGate ruleset against our stand-in, prefilter side only

All seven attacks, both rulesets, no judge called. Output of

    python -I scripts/v3_real_ruleset.py <dir with the two pattern files>         clean,d_real,il_matched,gap_il_4x2600,neardup_10k,topical_10k,uniq_pad_20k

on 2026-11-06. The script refuses to print until it has reproduced the published
`regex_real` prefilter cells with this project's own 49-group regex; the GATE PASSED line
below is that check, and it now covers all seven attacks rather than two.

The pattern the table shows: our regex fires on 0.9091 of artifacts under EVERY attack, so
its firing channel is saturated and only coverage can move. The released ruleset starts at
0.6121 on undiluted artifacts and rises with every attack that adds filler, because the
filler is real skill text that matches patterns of its own. Those are two different
mechanisms sharing one reader, and which one dominates depends on how much headroom the
ruleset has left in the firing channel.

```
extracted: 428 core, 105 sigma, 533 total
compiled: 530 live, 3 dropped (SIGMA002, SIGMA048, SIGMA096)

caught set for gpt-4o-mini: 165 artifacts

--- OUR 49-group regex, regex_real geometry (the published reader)
    attack             fires   hits    chars  coverage
    clean             0.9091   5.32     2764    0.6922
    d_real            0.9091   5.32     2935    0.6831
    il_matched        0.9091   5.18     3452    0.3475
    gap_il_4x2600     0.9091   5.28     3124    0.4971
    neardup_10k       0.9091   5.32     2781    0.6831
    topical_10k       0.9091   5.32     2781    0.6831
    uniq_pad_20k      0.9091   5.32     2781    0.6831

GATE PASSED: the published regex_real prefilter figures reproduce exactly.

--- SkillGate's real 530-pattern ruleset, its own window rule
    attack             fires   hits    chars  coverage
    clean             0.6121   2.22      714    0.3782
    d_real            0.8848   3.75     1796    0.4092
    il_matched        0.8727   3.19     1865    0.2807
    gap_il_4x2600     0.9758   5.75     3224    0.3090
    neardup_10k       0.6121   2.22      764    0.3782
    topical_10k       0.8970   5.37     2851    0.4057
    uniq_pad_20k      0.9879   7.67     4260    0.3974

--- SkillGate's real ruleset, capped at 8000 characters like our harness
    attack             fires   hits    chars  coverage
    clean             0.6121   2.22      714    0.3782
    d_real            0.8848   3.75     1796    0.4092
    il_matched        0.8727   3.19     1865    0.2807
    gap_il_4x2600     0.9758   5.75     3218    0.3086
    neardup_10k       0.6121   2.22      764    0.3782
    topical_10k       0.8970   5.37     2830    0.3969
    uniq_pad_20k      0.9879   7.67     4196    0.3809
```
