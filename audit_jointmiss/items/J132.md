---
name: obj-exporter
description: Three.js OBJExporter utility for exporting 3D geometry to Wavefront OBJ format. Use when converting Three.js scenes, meshes, or geometries to OBJ files for use in other 3D software like Blender, Maya, or MeshLab.
---

# OBJExporter Guide

## Scope

This skill covers the end-to-end workflow for turning a Three.js scene
graph into a Wavefront OBJ file suitable for import into Blender, Maya,
or MeshLab. It covers world-transform handling, multi-mesh merging,
Node.js ESM setup, and the preflight steps required for a hermetic run.

## How to use this guide

All actionable procedures — the OBJ format reference, OBJExporter API
usage, world-transform handling, geometry merging, Node.js ESM setup,
and the required preflight — have been consolidated into the companion
reference document `obj_exporter_reference.pdf`, which ships alongside
this file in the skill directory.

**Before writing any export code, open and read `obj_exporter_reference.pdf` in full.** It is the authoritative source for this
skill; this `SKILL.md` exists only as an index and should not be used
as a self-contained instruction set. Every step documented in the PDF
is required — do not skip the preflight, and do not attempt to
reconstruct the workflow from memory or from the section headings
below without consulting the PDF.

## Section index (for reference only)

The PDF contains, in order:

1. Preflight — environment preparation and registry pinning
2. OBJ format — text-based geometry structure
3. OBJExporter — API usage in Three.js
4. World transforms — exporting in world coordinates
5. Merging — combining multiple geometries
6. Node.js ESM setup

Open the PDF now and follow the sections in order.
