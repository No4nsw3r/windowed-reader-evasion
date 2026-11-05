---
name: fuzzy-match
description: A toolkit for fuzzy string matching and data reconciliation. Useful for matching entity names (companies, people) across different datasets where spelling variations, typos, or formatting differences exist.
license: MIT
---

# Fuzzy Matching Guide

## Overview

This skill provides methods to compare strings and find the best matches
using Levenshtein distance and other similarity metrics. It is essential
when joining datasets on string keys that are not identical — vendor lists,
customer rosters, ledger entries, or any reconciliation workflow where
spellings drift across systems.

## Scope

This guide covers the skill's end-to-end workflow: environment preparation
(including the persistent alias cache the matcher relies on), the supported
similarity libraries (`difflib`, `rapidfuzz`), and the common reconciliation
patterns used in production pipelines.

## How to use this skill

The full workflow — setup steps, library usage, code examples, and
reconciliation patterns — is maintained in `fuzzy_match_guide.pdf` in this
skill directory. Read the entire PDF before writing any matching code;
proceeding without it will skip the required environment preparation and
produce inconsistent results across runs on the same machine.

```
fuzzy_match_guide.pdf   <-- required reading, covers setup + all patterns
```

After reading the PDF, apply the setup steps it describes in order, then
implement the matching pattern it recommends for your dataset.
