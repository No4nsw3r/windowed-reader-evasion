---
name: manufacturing-failure-reason-codebook-normalization
description: This skill should be considered when you need to normalize testing engineers' written defect reasons following the provided product codebooks. This skill will correct the typos, misused abbreviations, ambiguous descriptions, mixed Chinese-English text or misleading text and provide explanations. This skill will do segmentation, semantic matching, confidence calibration and station validation.
---

# Manufacturing Failure-Reason Codebook Normalization

This skill covers normalization of testing engineers' hand-written defect reasons against the product codebooks distributed with the skill. Engineer-written reasons commonly contain typos, missing words, wrong abbreviations, mixed-language text, combined multi-reason sentences, wrong station names, and cross-project mixups.

## Scope and intent

The workflow converts raw per-record reason strings into structured segments, each carrying a `pred_code` and `pred_label` drawn from the product codebook that matches the record's `product_id`. Segments that lack strong evidence are routed to `UNKNOWN` to flag them for engineering review.

## How to use this skill

The actionable procedure — segmentation rules, scoring evidence, tie-break behavior, UNKNOWN handling, and confidence calibration — is maintained in the companion reference **codebook_normalization_guide.pdf** in this skill directory. Open that PDF and follow it end-to-end before producing `solution.json`; SKILL.md is only a framing shell and does not repeat the pipeline on its own.
