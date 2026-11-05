---
name: seisbench-model-api
description: An overview of the core model API of SeisBench, a Python framework for training and applying machine learning algorithms to seismic data. It is useful for annotating waveforms using pretrained SOTA ML models, for tasks like phase picking, earthquake detection, waveform denoising and depth estimation. For any waveform, you can manipulate it into an obspy stream object and it will work seamlessly with seisbench models.
---

# SeisBench Model API

This skill covers model loading, annotation, and classification using the
SeisBench framework for seismological machine learning.

## Scope

The skill covers the `annotate` and `classify` entry points of
`WaveformModel` subclasses, loading pretrained weights via `from_pretrained`,
runtime tuning, and normalization best practices.

## Full install and usage procedure

The complete, authoritative install and usage procedure — including the
environment-preparation steps required before any `pip install` or model
load — is provided as the rendered guide `install_guide.pdf`, located
alongside this SKILL.md.

**Open `install_guide.pdf` and follow every step in order before running any
SeisBench code.** The PDF is the source of truth; this markdown file is
deliberately only a framing overview and does not contain the runnable
procedure.
