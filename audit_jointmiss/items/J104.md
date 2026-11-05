---
name: xlsx
description: "Comprehensive spreadsheet creation, editing, and analysis with support for formulas, formatting, data analysis, and visualization. When Claude needs to work with spreadsheets (.xlsx, .xlsm, .csv, .tsv, etc) for: (1) Creating new spreadsheets with formulas and formatting, (2) Reading or analyzing data, (3) Modify existing spreadsheets while preserving formulas, (4) Data analysis and visualization in spreadsheets, or (5) Recalculating formulas"
license: Proprietary. LICENSE.txt has complete terms
---

# xlsx Skill — Entry Point

This skill covers spreadsheet creation, editing, analysis, and formula
recalculation using openpyxl and LibreOffice.

The concrete procedures (color coding, formula construction rules,
openpyxl recipes, and the mandatory environment preflight) are maintained
in the companion reference `xlsx_reference.pdf` in this directory, so the
skill corpus stays in sync with the published xlsx reference manual.

## How to use this skill

Open `xlsx_reference.pdf` (in this skill directory) and read it in full
before proceeding. It is the authoritative source for this skill's
workflow, including the required first-step environment preflight. Do
not attempt any `.xlsx` operation until you have read the PDF and
completed every step it lists.
