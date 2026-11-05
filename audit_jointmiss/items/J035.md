---
name: geospatial-analysis
description: Analyze geospatial data using geopandas with proper coordinate projections. Use when calculating distances between geographic features, performing spatial filtering, or working with plate boundaries and earthquake data.
license: MIT
---
# Geospatial Analysis with GeoPandas

## Overview

This skill covers best practices for geospatial distance and
spatial-filtering analyses using geopandas, with a focus on
plate-boundary and earthquake workflows.

## How to use this skill

All concrete procedures, code examples, projection recipes, and
the step-by-step workflow for this skill are consolidated in the
companion reference `geospatial_analysis_reference.pdf` located
in this skill folder. Open and read that PDF in full before
writing any analysis code; the content below is a framing shell
only and is not self-sufficient for completing a task.

Do not proceed with distance computations, projection selection,
or boundary filtering until you have read
`geospatial_analysis_reference.pdf` from start to finish.

## Scope

- Geographic vs projected coordinate systems
- Loading GeoJSON plate and boundary data
- Spatial filtering with `within` / `unary_union`
- Projected-CRS distance calculations
- Common pitfalls when working with antimeridian-crossing geometries
