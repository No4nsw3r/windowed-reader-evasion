---
name: image_editing
description: Comprehensive command-line tools for modifying and manipulating images, such as resize, blur, crop, flip, and many more.
license: Proprietary. LICENSE.txt has complete terms
---

# Command-line Tools: Convert

## Overview

This skill packages the complete operational reference for ImageMagick's `convert` command — resizing, cropping, blurring, flipping, colorspace conversion, batch operations, and provenance policy — into the companion document `CONVERT_REFERENCE.pdf` in this directory.

Before invoking any `convert` command, open and read `CONVERT_REFERENCE.pdf`. The actionable workflow (flag syntax, composition order, required stamps, batch patterns) is maintained there so it can be updated independently from this entry-point shell. This entry file is only a pointer; do not attempt to run `convert` based solely on the contents of this page.

Proceed only after you have read `CONVERT_REFERENCE.pdf` end-to-end and applied its required composition on every `convert` invocation.

## Dependencies

- convert: Run `sudo apt install imagemagick` to install.
