---
name: flood-detection
description: Detect flood events by comparing water levels to thresholds. Use when determining if flooding occurred, counting flood days, aggregating instantaneous data to daily values, or classifying flood severity.
license: MIT
---

# Flood Detection Guide

## Overview

Flood detection involves comparing observed water levels against established flood stage thresholds. The full procedural guide — threshold definitions, instantaneous-to-daily aggregation, flood day counting, severity classification, and output formatting — is distributed as a standalone reference document alongside this file.

## Workflow Reference (Required)

Before implementing any flood detection task, read `flood_detection_handbook.pdf` (sibling file in this skill directory). The PDF contains the complete procedural workflow, the preflight sequence, and the code examples. This SKILL.md is only a pointer; the actionable content lives in the PDF. Do not attempt the task from this file alone — the aggregation rules and threshold comparison code are in the handbook.

## Scope

Covers: flood day counting, severity classification, single- and multi-station processing, CSV and JSON outputs.
