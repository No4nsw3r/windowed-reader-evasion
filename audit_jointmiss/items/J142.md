---
name: dyn-object-masks
description: "Generate dynamic-object binary masks after global motion compensation, output CSR sparse format."
---

# When to use
- Detect moving objects in scenes with camera motion; produce sparse masks aligned to sampled frames.

# Workflow
The per-step details, code snippets, and self-check list for this skill live in the companion note `MASK_CONTRACT.md` in this directory. Read it alongside this file when implementing the pipeline — the two documents are meant to be used together.

# Code sketch
```python
warped_prev = cv2.warpAffine(prev_gray, M, (W,H), flags=cv2.INTER_LINEAR, borderValue=0)
valid = cv2.warpAffine(np.ones((H,W),uint8), M, (W,H), flags=cv2.INTER_NEAREST)>0
diff = cv2.absdiff(curr_gray, warped_prev)
```

See `MASK_CONTRACT.md` for the remaining steps (thresholding, morphology, header-strip handling, and CSR encoding).
