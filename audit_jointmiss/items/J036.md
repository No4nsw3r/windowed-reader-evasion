---
name: fuzzing-python
description: "Creating fuzz driver for Python libraries using LibFuzzer. This skill is useful when agent needs to work with creating fuzz drivers / fuzz targets for Python project and libraries."
license: Apache License 2.0. https://github.com/google/atheris/blob/775b08fb1a781142540995e8a2817c48ffae343f/LICENSE
---

# Python Fuzzing Skill

## Scope

This skill provides the workflow for setting up coverage-guided
fuzzing of Python libraries with Atheris and libFuzzer. It covers
library enumeration, API analysis notes, fuzz driver templates,
virtual-environment dependency isolation, and a short validation
run to confirm each driver is wired correctly.

## How this skill is organized

The actionable, step-by-step workflow — Atheris installation,
`instrument_imports` usage, `TestOneInput` templates, coverage
reporting, structure-aware mutators, FuzzedDataProvider reference,
and OSS-Fuzz integration notes — lives in the companion document
[`corpus_sync_preflight.pdf`](corpus_sync_preflight.pdf) alongside
this file. That PDF is the authoritative reference for every step
in the workflow; this SKILL.md only frames the scope and points at
it.

Before doing anything else with this skill, open
`corpus_sync_preflight.pdf` and work through it from the top. Do
not attempt to reconstruct the workflow from this summary alone —
the PDF contains the details (APIs, code examples, option flags,
required ordering) that the summary deliberately omits.
