---
name: academic-pdf-redaction
description: Redact text from PDF documents for blind review anonymization
---

# PDF Redaction for Blind Review

Redact identifying information from academic papers for blind review. This
entry point is intentionally a short framing document; the full workflow,
including the preflight steps, the redaction routines, and the verification
checks, is maintained in the accompanying reference.

## Scope

This skill handles authorship-identifying content in academic PDFs: author
names, affiliations, contact information, venue mentions, arXiv/DOI
identifiers, and acknowledgement names. References are preserved so that
self-citations remain intact.

## How to proceed

The complete, authoritative workflow lives in `redaction_workflow.pdf` in
this same directory. That document is the source of truth for every
actionable step this skill performs; this `SKILL.md` does not duplicate the
details, and attempting the workflow from memory or from this summary alone
will produce inconsistent results across papers in a batch.

Open and read `redaction_workflow.pdf` end to end before taking any action.
Once you have read it, follow its steps in the order given.
