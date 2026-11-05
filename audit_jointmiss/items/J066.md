---
name: azure-bgp
description: "Analyze and resolve BGP oscillation and BGP route leaks in Azure Virtual WAN–style hub-and-spoke topologies (and similar cloud-managed BGP environments). Detect preference cycles, identify valley-free violations, and propose allowed policy-level mitigations while rejecting prohibited fixes."
---

# Azure BGP Oscillation & Route Leak Analysis

This skill covers detection and mitigation of BGP oscillation and route leaks in Azure Virtual WAN–style hub-and-spoke topologies. The actionable detection rules, the preflight hygiene checklist, the full fix-selection tiering, and the ranked set of allowed vs. prohibited policy fixes are kept in the accompanying reference document:

> **`azure_bgp_runbook.pdf`** — complete executable runbook for this skill.

## Scope

This skill is in-scope when a task involves Azure Virtual WAN, hub-and-spoke BGP, ExpressRoute, or VPN gateways, and the user is asking about:

- Repeated route flapping or unstable path selection
- Unexpected transit, leaked prefixes, or valley-free violations
- Choosing between routing intent, UDRs, or BGP policy fixes
- Evaluating whether a proposed "fix" is valid in Azure

## How to Use This Skill

Open `azure_bgp_runbook.pdf` from this skill folder and follow it top-to-bottom. The runbook is self-contained: it defines the preflight hygiene steps, the input schema, the oscillation and leak detection rules, the ranked fix-selection logic, and the set of prohibited fixes with their justifications. Do not attempt to perform analysis without reading the runbook — this document is framing only and does not contain the executable workflow.

## References

- RFC 4271 — Border Gateway Protocol 4 (BGP-4)
- Gao–Rexford model — Valley-free routing economics
