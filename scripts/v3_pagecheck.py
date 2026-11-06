r"""Measure the USENIX body page count from the PDF, which is the file that gets submitted.

Why this exists. The converter emits \label{usenix:endofbody} as the last thing after the
Conclusion, and reading its page out of the .aux was supposed to be the reliable method.
On 2026-11-06 it was not: reports/usenix/_build_v3/paper_v3_usenix.aux still said

    \newlabel{usenix:endofbody}{{9}{13}}

with an mtime of 2026-11-05 15:02, while the paper_v3_usenix.pdf beside it, mtime
2026-11-06 01:17, ended its Conclusion on page 14. The .aux had not been rewritten by the
later run, so a page count read from it was a page count for an older draft -- and it was
reported as "body 13/13" when the body was 14. An .aux is an intermediate; the PDF is the
deliverable. Measure the deliverable, and treat any disagreement as the .aux being wrong.

The body ends on the last page that still carries body text before the Ethics heading.
Ethics and Open Science, the references and the appendices are all excluded from the limit,
and Ethics is the first thing after the Conclusion, so: find the page holding the "Ethical
Considerations" heading. If body text precedes it on that page, that page is the body's
last. If the heading opens the page, the body ended on the page before.

usage:  python -I scripts/v3_pagecheck.py
exit:   0 within the limit, 1 over it or unmeasurable
"""
import os
import re
import sys

sys.stdout.reconfigure(encoding="utf-8", errors="replace")

LIMIT = 13
ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
USENIX = os.path.join(ROOT, "reports", "usenix")
PDF = os.path.join(USENIX, "paper_v3_usenix.pdf")
AUX = os.path.join(USENIX, "paper_v3_usenix.aux")
HEADING = "Ethical Considerations"
# A heading this far into a page's reading order has body text above it.
MARGIN = 50


def body_pages(path):
    try:
        from pypdf import PdfReader
    except ImportError:
        try:
            from PyPDF2 import PdfReader
        except ImportError:
            print("FAIL: need pypdf to read the PDF (pip install pypdf)")
            return None, None
    r = PdfReader(path)
    for i, page in enumerate(r.pages):
        text = page.extract_text()
        at = text.find(HEADING)
        if at < 0:
            continue
        if at > MARGIN:
            return i + 1, len(r.pages)        # body text precedes the heading here
        return i, len(r.pages)                # heading opens the page
    print(f"FAIL: never found {HEADING!r} in the PDF")
    return None, len(r.pages)


def aux_pages(path):
    if not os.path.exists(path):
        return None
    m = re.search(r"newlabel\{usenix:endofbody\}\{\{[^}]*\}\{(\d+)\}",
                  open(path, encoding="utf-8", errors="replace").read())
    return int(m.group(1)) if m else None


def main():
    if not os.path.exists(PDF):
        print(f"FAIL: no PDF at {PDF}")
        return 1

    body, total = body_pages(PDF)
    if body is None:
        return 1
    print(f"body:  {body} pages   (limit {LIMIT})")
    print(f"total: {total} pages  including references and appendices")

    claimed = aux_pages(AUX)
    if claimed is None:
        print("aux:   no endofbody label found -- PDF is authoritative anyway")
    elif claimed != body:
        older = os.path.getmtime(AUX) < os.path.getmtime(PDF)
        print(f"aux:   says {claimed}, DISAGREES with the PDF"
              + ("  (and is older than it -- stale)" if older else ""))
        print("       Trust the PDF. This is the exact trap that produced a false "
              "'13/13' on 2026-11-06.")
    else:
        print(f"aux:   {claimed}, agrees")

    if body > LIMIT:
        print(f"\nOVER by {body - LIMIT} page(s). Relocate body material to an appendix; "
              "appendices and references cost nothing against the limit.")
        return 1
    print("\nWithin the limit.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
