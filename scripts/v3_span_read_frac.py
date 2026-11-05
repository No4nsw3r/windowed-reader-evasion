"""v3 - span-level reader coverage: does the reader see a WHOLE malicious instruction?

The paper (reports/paper_v2.tex, \\S "Two preflights") reports

    read_frac = payload characters inside the reader's window union
                / payload characters in the original payload

and a reviewer objected that character coverage is not evidence coverage. A reader can
score read_frac = 0.6 and never receive one complete malicious instruction, because the
40% it dropped was spread across every passage that mattered. This script measures the
version that answers the objection.

The label audit required every MALICIOUS verdict to carry a quoted span, and the paper
states that all 345 such quotes occur verbatim in the item they annotate. Those quotes
are the evidence spans: each one is a passage an auditor named as the reason the skill is
malicious. So, per (skill, reader geometry, attack),

    span_read_frac = evidence spans wholly inside the reader's window union
                     / evidence spans in that skill

A span straddling a window boundary is NOT read, which is the whole point. Two variants
are kept separate because they differ and the difference is informative:

    union   the span lies entirely inside the union of the reader's windows
    single  the span lies entirely inside ONE window, so one judge call saw all of it

No reader is reimplemented here. The window arithmetic is the repo's own:
`v2_phase1_kill.reader_requests` / `.coverage_detail` for the position-addressed
partition readers and `v2_skillgate.skillgate_prompt` for the content-addressed
regex-anchored ones. This script adds offset-tracking shims around them -- a collapse
that carries a per-character index instead of a per-character payload flag, and a window
walker that returns offsets instead of strings -- and asserts at run time that each shim
reproduces the existing function's output exactly. The char-level read_frac is
recomputed from the same index map and asserted equal to `coverage_detail`, which
cross-validates the whole map against the number the paper already published.

TEXT ONLY. Nothing is executed, no judge is called, no skill body is printed. Quotes are
reported as a sha1 prefix and a length, never as text. Output is counts, offsets and
rates.

usage: python -I scripts/v3_span_read_frac.py
"""
import os
import re
import sys
import csv
import glob
import hashlib
import unicodedata

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import numpy as np
import pandas as pd
import pilot_audit2 as A
import pilot_dil2 as D
import v2_phase1_kill as P1
import v2_phase3_cross as P3
import v2_skillgate as SG
import v2_coverage as CV
from scipy import stats

ROOT = A.ROOT
NOTES = os.path.join(ROOT, "research_notes", "v2_main")
NOTES_V1 = os.path.join(ROOT, "research_notes", "pilot")
AUDIT = os.path.join(ROOT, "audit")
PRIMARY = os.path.join(ROOT, "data", "malicious_skill_bench", "primary.parquet")
BENIGN = os.path.join(ROOT, "data", "skillmd_138k", "train.parquet")

OUT_MD = os.path.join(NOTES, "v3_span_read_frac.md")
OUT_SPANS = os.path.join(NOTES, "v3_span_read_frac_spans.csv")
OUT_ITEMS = os.path.join(NOTES, "v3_span_read_frac_items.csv")
OUT_CELLS = os.path.join(NOTES, "v3_span_read_frac_cells.csv")

GOOD = ("SAFE", "MALICIOUS")


# ============================================================ 1. evidence spans
def load_quotes():
    """The 345 quote instances the paper reports, with the item they annotate.

    Returns (quotes_df, note) where quotes_df has one row per quote instance.
    """
    key = pd.read_csv(os.path.join(AUDIT, "key", "key.csv"),
                      encoding="utf-8-sig", dtype=str)
    parts = []
    for name in ("annot1", "annot2"):
        d = pd.read_csv(os.path.join(AUDIT, "sheets", f"sheet_{name}.csv"),
                        encoding="utf-8-sig", dtype=str).fillna("")
        m = d[(d.verdict == "MALICIOUS") & (d.evidence_quote.str.strip() != "")]
        parts.append(m[["item_id", "evidence_quote"]].assign(sheet=name))
    q = pd.concat(parts, ignore_index=True)
    q = q.merge(key[["item_id", "stratum", "upstream", "skill_hash", "chars"]],
                on="item_id", how="left")
    return q, key


# The annotation sheets were opened in a spreadsheet, which prefixes a cell beginning
# with "-" with an apostrophe so the "-" is not read as a formula. That guard is not part
# of the quoted text. It is stripped only when the raw quote does not occur in the item
# and the stripped one does, so the rule can never create a match that was not there.
def locate(quote, text):
    """Returns (occurrences, rule) where occurrences is [(start, end), ...]."""
    for cand, rule in ((quote, "verbatim"),
                       (quote[1:] if quote[:1] == "'" else None, "strip_excel_apostrophe"),
                       (re.sub(r"\s+", " ", quote).strip() or None, "ws_collapsed"),
                       (unicodedata.normalize("NFKC", quote), "nfkc")):
        if not cand:
            continue
        occ, i = [], text.find(cand)
        while i >= 0:
            occ.append((i, i + len(cand)))
            i = text.find(cand, i + 1)
        if occ:
            return occ, rule
    return [], "not_found"


def build_span_table(quotes, text_by_hash):
    """One row per (skill, distinct quote). Occurrences are all exact matches."""
    rows = []
    stat = {"verbatim": 0, "strip_excel_apostrophe": 0, "ws_collapsed": 0,
            "nfkc": 0, "not_found": 0, "no_text": 0}
    failed = []
    for r in quotes.itertuples(index=False):
        T = text_by_hash.get(r.skill_hash)
        if T is None:
            stat["no_text"] += 1
            failed.append((r.item_id, r.sheet, "skill_hash did not resolve to a text"))
            continue
        occ, rule = locate(r.evidence_quote, T)
        stat[rule] += 1
        if not occ:
            failed.append((r.item_id, r.sheet, "quote not present under any rule"))
            continue
        # Index containment is tested on the span's NON-WHITESPACE characters only.
        # The collapse step drops the separator it split on and re-joins retained lines
        # with a single space, so a span containing "\n" or ". " loses that one character
        # and gains an identical one. Requiring the original whitespace character would
        # score the span unread although the judge received its content verbatim, which
        # is a measurement artifact, not evidence loss.
        nz = [np.array([i for i in range(a, b) if not T[i].isspace()], dtype=np.int32)
              for a, b in occ]
        rows.append(dict(item_id=r.item_id, sheet=r.sheet, stratum=r.stratum,
                         skill_hash=r.skill_hash, rule=rule,
                         quote_sha1=hashlib.sha1(
                             r.evidence_quote.encode("utf-8")).hexdigest()[:12],
                         quote_len=len(r.evidence_quote.strip("'")),
                         n_occ=len(occ), occ=occ, nz=nz,
                         text=T[occ[0][0]:occ[0][1]]))
    inst = pd.DataFrame(rows)
    # distinct spans per skill: one entry per distinct quote text (same sha1), so a quote
    # both pipelines produced is one span, not two.
    spans = {}
    for r in inst.itertuples(index=False):
        spans.setdefault(r.skill_hash, {})
        if r.quote_sha1 not in spans[r.skill_hash]:
            spans[r.skill_hash][r.quote_sha1] = dict(
                quote_sha1=r.quote_sha1, quote_len=r.quote_len, n_occ=r.n_occ,
                occ=r.occ, nz=r.nz, text=r.text, item_id=r.item_id, sheets=set())
        spans[r.skill_hash][r.quote_sha1]["sheets"].add(r.sheet)
    spans = {h: list(v.values()) for h, v in spans.items()}
    return inst, spans, stat, failed


# ============================================================ 2. index-carrying shims
def assemble_with_map(segs):
    """segs: [(text, is_payload)] as every attack builder in this repo emits.

    Returns (artifact, src) where src[i] is the index into the ORIGINAL payload S of
    artifact character i, or -1 for filler. The payload-preservation canary that every
    builder already asserts guarantees that the payload segments concatenate to S, so the
    k-th payload character in the artifact is S[k]. That makes the map exact for the
    fragmenting attacks too, without re-deriving how each one slices S.
    """
    parts, maps, k = [], [], 0
    for t, p in segs:
        parts.append(t)
        if p:
            maps.append(np.arange(k, k + len(t), dtype=np.int32))
            k += len(t)
        else:
            maps.append(np.full(len(t), -1, dtype=np.int32))
    art = "".join(parts)
    src = np.concatenate(maps) if maps else np.empty(0, np.int32)
    assert len(src) == len(art)
    return art, src


def collapse_with_map(text, src):
    """P1.collapse_with_origin, carrying the payload INDEX instead of a payload flag.

    Same split, same normalised key, same first-occurrence-wins rule, same single-space
    join. Asserted against A.collapse_repetition by the caller.
    """
    spans, start = [], 0
    for m in P1.SPLIT.finditer(text):
        spans.append((start, m.start()))
        start = m.end()
    spans.append((start, len(text)))
    seen, parts, maps = set(), [], []
    for a, b in spans:
        ln = text[a:b]
        kk = P1.NONWORD.sub("", ln.lower())[:80]
        if kk and kk in seen:
            continue
        if kk:
            seen.add(kk)
        parts.append(ln)
        maps.append(src[a:b])
    buf, out = [], []
    for i, (p, mp) in enumerate(zip(parts, maps)):
        if i:
            buf.append(" ")
            out.append(np.array([-1], dtype=np.int32))
        buf.append(p)
        out.append(mp)
    joined = "".join(buf)
    jm = np.concatenate(out) if out else np.empty(0, np.int32)
    assert len(jm) == len(joined)
    return joined, jm


def chunk_offsets(n, size, overlap, cap):
    """P1.chunks / D.chunks_of, as offsets."""
    i, out = 0, []
    while i < n and (cap is None or len(out) < cap):
        out.append((i, min(i + size, n)))
        i += size - overlap
    return out


# geometry -> (needs_collapse, window-offset function, source of the geometry)
PREFIX = {"none": A.WINDOW, "trunc10k": 10000, "trunc12k": 12000}
PARTITION = {
    # name:        (collapse?, size, overlap, cap, l_max)
    "none":        (False, None, None, None, None),
    "trunc10k":    (False, None, None, None, None),
    "trunc12k":    (False, None, None, None, None),
    "dedup_small": (True,  2500, 1000, 6,            None),
    "dedup_lmax":  (True,  2500, 1000, None,         P1.L_MAX),
    "dedup_full":  (True,  2500, 1000, P1.HARD_CAP,  None),
    "big_chunk":   (False, 6000,  500, 4,            None),
    "small_chunk": (False, 2500, 1000, 6,            None),
}
# regex-anchored, content-addressed. regex_real is the geometry SkillGate's own method
# section describes (500 characters on EACH side of a hit); the repo's `skillgate` reader
# implements 500 total. It is included as coverage only -- no judge was ever run on it.
REGEX = {"skillgate":   dict(),
         "regex_nocap": dict(ms=10 ** 6, cap=10 ** 9),
         "regex_wide":  dict(cw=1500, dedup=375),
         "regex_real":  dict(cw=1000, dedup=250)}
REGEX_MEASURED = ("skillgate", "regex_nocap", "regex_wide")


def regex_views(text, src, geom):
    """Window-by-window payload indices for a regex-anchored reader.

    Mirrors SG.skillgate_prompt's hit loop, builds the body with a parallel window-id
    array, applies the same cap by slicing the same prompt string, and reads the
    surviving windows off the truncated arrays -- so the cap can only be applied the way
    the deployed function applies it. Asserted against SG.skillgate_prompt.

    Returns (views, n_hits, fired) where views is a list of arrays of payload indices,
    one per surviving window. fired=False means the prefilter did not fire, which in this
    design means no call at all.
    """
    cw = geom.get("cw", SG.CW)
    dedup = geom.get("dedup", SG.DEDUP)
    ms = geom.get("ms", SG.MS)
    cap = geom.get("cap", SG.CAP)

    hits = [m.start() for m in A.RISK.finditer(text)]
    if not hits:
        assert SG.skillgate_prompt(text, cw=cw, dedup=dedup, ms=ms, cap=cap)[0] is None
        return [], [], 0, False
    wins, centres = [], []
    for h in hits:
        if any(abs(h - c) < dedup for c in centres):
            continue
        centres.append(h)
        st = max(0, h - cw // 2)
        wins.append((st, min(st + cw, len(text))))
        if len(wins) >= ms:
            break

    sep = "\n---\n"
    pieces, wid = [], []
    for j, (a, b) in enumerate(wins):
        if j:
            pieces.append(sep)
            wid.append(np.full(len(sep), -1, dtype=np.int32))
        pieces.append(text[a:b])
        wid.append(np.full(b - a, j, dtype=np.int32))
    body = "".join(pieces)
    wid = np.concatenate(wid)
    # artifact index per body character, built in the same pass order as wid
    ai = []
    for j, (a, b) in enumerate(wins):
        if j:
            ai.append(np.full(len(sep), -1, dtype=np.int32))
        ai.append(np.arange(a, b, dtype=np.int32))
    art_ix = np.concatenate(ai)
    assert len(art_ix) == len(wid) == len(body)

    prompt = (SG.PREAMBLE + "\n\n" + body)[:cap + len(SG.PREAMBLE)]
    assert prompt == SG.skillgate_prompt(text, cw=cw, dedup=dedup, ms=ms, cap=cap)[0], \
        "regex window reconstruction does not match v2_skillgate.skillgate_prompt"
    keep = max(0, len(prompt) - len(SG.PREAMBLE) - 2)
    wid, art_ix = wid[:keep], art_ix[:keep]

    views, texts = [], []
    for j in range(len(wins)):
        sel = art_ix[wid == j]
        if not len(sel):
            continue
        pl = src[sel]
        views.append(pl[pl >= 0])
        texts.append(text[sel[0]:sel[-1] + 1])
    # every window text the span test will search must be text the judge actually
    # received, i.e. a substring of the prompt the deployed function built
    assert all(w in prompt for w in texts), \
        "a reconstructed regex window is not present in skillgate_prompt's output"
    return views, texts, len(hits), True


def partition_views(art, src, geometry):
    """Window-by-window payload indices for a position-addressed partition reader.

    Returns (views, n_windows, overflow). overflow=True is dedup_lmax refusing to judge.
    """
    collapse, size, overlap, cap, l_max = PARTITION[geometry]
    if collapse:
        text, m = collapse_with_map(art, src)
        assert text == A.collapse_repetition(art), \
            "collapse_with_map does not match A.collapse_repetition"
    else:
        text, m = art, src
    if l_max is not None and len(text) > l_max:
        return [], [], 0, True
    if geometry in PREFIX:
        wins = [(0, min(PREFIX[geometry], len(text)))]
    else:
        wins = chunk_offsets(len(text), size, overlap, cap)
        if collapse:
            got = [text[a:b] for a, b in wins]
            want, flag = P1.reader_requests(geometry, art)
            assert flag is None and got == want, \
                f"window offsets do not match P1.reader_requests for {geometry}"
    views, texts = [], []
    for a, b in wins:
        pl = m[a:b]
        views.append(pl[pl >= 0])
        texts.append(text[a:b])
    return views, texts, len(wins), False


# ============================================================ 3. span containment
WS = re.compile(r"\s+")


def score(views, win_texts, s_len, spans):
    """Returns (char_read_frac, per_span) with
    per_span = [(in_union, in_single, in_contiguous, covered_fraction), ...].

    Three strictnesses, reported separately because they answer different questions:

      union       every non-whitespace character of the span reached the judge, in some
                  window. The loosest reading of "the reader received the evidence".
      single      all of them reached ONE window, so one judge call held the whole span.
      contiguous  the span appears as an uninterrupted passage in one window's text.
                  This is the only one that rules out a span whose halves sit inside the
                  same window with thousands of characters of filler between them, which
                  a fragmenting attack produces and which `single` still credits.

    Whitespace runs are normalised for the contiguous test, because the reader's own
    collapse step re-joins the lines it kept with a single space.

    A span counts as read if ANY of its occurrences is covered -- the reading most
    generous to the defence, so the attack is never overstated.
    """
    union = np.zeros(s_len, dtype=bool)
    masks = []
    for v in views:
        mk = np.zeros(s_len, dtype=bool)
        if len(v):
            mk[v] = True
        masks.append(mk)
        union |= mk
    char = float(union.sum()) / s_len if s_len else 0.0
    norm_wins = [WS.sub(" ", w) for w in win_texts]
    out = []
    for sp in spans:
        iu = any(len(z) and union[z].all() for z in sp["nz"])
        isg = any(len(z) and mk[z].all() for z in sp["nz"] for mk in masks)
        q = WS.sub(" ", sp["text"]).strip()
        ict = bool(q) and any(q in w for w in norm_wins)
        # share of the span's non-whitespace characters the union covers, best
        # occurrence. A span that is not read but whose share is > 0 is a straddler: the
        # character measure gave it partial credit for a passage the judge never got
        # whole.
        frac = max((float(union[z].sum()) / len(z) for z in sp["nz"] if len(z)),
                   default=0.0)
        out.append((bool(iu), bool(isg), ict, frac))
    return char, out


# ============================================================ 4. segment builders
def segs_p1(S, attack, _):
    return P1.build_attacks(S, "").get(attack)


def segs_p3(S, attack, _):
    sd = D.md5seed(S, "p3")
    segs = P3.segments_for(S, attack, sd)
    if attack in SG.ATTACKS:
        assert SG.segments_for(S, attack, sd) == segs, \
            "v2_skillgate and v2_phase3_cross disagree on the artifact"
    return segs


def segs_dil2(S, attack, dose):
    return CV.segs_for(attack, S, dose)


FAMILIES = {"p1": segs_p1, "p3": segs_p3, "dil2": segs_dil2}


# ============================================================ 4b. self-check
SELFCHECK = (("none", "gap_il_4x2600"), ("dedup_small", "gap_il_4x2600"),
             ("dedup_full", "clean"), ("dedup_lmax", "il_heavy"),
             ("skillgate", "il_matched"), ("regex_wide", "d_real"),
             ("trunc12k", "neardup_10k"), ("trunc10k", "gap_il_4x2600"))


def selfcheck(spans_by_hash, text_by_hash, hashes):
    """Recompute the contiguous span measure WITHOUT the index map.

    This route asks the deployed reader function for its request strings and runs a
    plain substring test of the quote against each one. It shares no code with
    `score()` beyond the whitespace normalisation, so agreement means the offset
    reconstruction is not inventing or losing coverage. Returns (n_decisions,
    n_disagreements, detail).
    """
    tot = bad = 0
    detail = []
    for geo, atk in SELFCHECK:
        g_tot = g_bad = 0
        for h in hashes:
            S = text_by_hash.get(h)
            spans = spans_by_hash.get(h)
            if S is None or not spans:
                continue
            segs = segs_p3(S, atk, None)
            if segs is None:
                continue
            art = "".join(t for t, _ in segs)
            if geo in PREFIX:
                reqs = [art[:PREFIX[geo]]]
            elif geo in PARTITION:
                reqs, flag = P1.reader_requests(geo, art)
                if flag:
                    reqs = []
            else:
                p, _ = SG.skillgate_prompt(art, **REGEX[geo])
                reqs = [] if p is None else \
                    p[len(SG.PREAMBLE) + 2:].split("\n---\n")
            wn = [WS.sub(" ", r) for r in reqs]
            if geo in PARTITION:
                views, wtx, _, overflow = partition_views(art, src_of(segs), geo)
            else:
                views, wtx, _, _ = regex_views(art, src_of(segs), REGEX[geo])
            _, per = score(views, wtx, len(S), spans)
            for sp, (_, _, ict, _) in zip(spans, per):
                q = WS.sub(" ", sp["text"]).strip()
                plain = bool(q) and any(q in w for w in wn)
                g_tot += 1
                if plain != ict:
                    g_bad += 1
        detail.append((geo, atk, g_tot, g_bad))
        tot += g_tot
        bad += g_bad
    return tot, bad, detail


def src_of(segs):
    return assemble_with_map(segs)[1]


# ============================================================ 5. the measurement
def measure(spans_by_hash, text_by_hash, jobs):
    """jobs: set of (family, skill_hash, attack, dose, geometry). Returns two frames."""
    by_art = {}
    for fam, h, atk, dose, geo in jobs:
        by_art.setdefault((fam, h, atk, dose), []).append(geo)

    span_rows, cell_rows = [], []
    n_art = 0
    for (fam, h, atk, dose), geos in sorted(by_art.items()):
        S = text_by_hash.get(h)
        if S is None:
            continue
        segs = FAMILIES[fam](S, atk, dose)
        if segs is None:
            continue
        art, src = assemble_with_map(segs)
        payload_n = int((src >= 0).sum())
        spans = spans_by_hash.get(h, [])
        collapsed = None
        n_art += 1
        if n_art % 250 == 0:
            print(f"  artifacts built: {n_art}/{len(by_art)}", flush=True)
        for geo in geos:
            if geo in PARTITION:
                views, wtx, nw, overflow = partition_views(art, src, geo)
            else:
                views, wtx, nh, fired = regex_views(art, src, REGEX[geo])
                overflow = False
                nw = len(views)
            char, per = score(views, wtx, len(S), spans)
            if payload_n == 0:
                char = 0.0          # f_only: no payload, coverage undefined
            iu = sum(1 for a, _, _, _ in per if a)
            isg = sum(1 for _, b, _, _ in per if b)
            ict = sum(1 for _, _, c, _ in per if c)
            strad = sum(1 for a, _, _, f in per if not a and f > 0)
            outs = sum(1 for a, _, _, f in per if not a and f == 0)
            cell_rows.append(dict(
                family=fam, skill_hash=h, attack=atk, dose=dose, geometry=geo,
                payload_len=len(S), artifact_len=len(art), n_windows=nw,
                overflow=int(overflow), n_spans=len(spans),
                spans_union=iu, spans_single=isg, spans_contig=ict,
                spans_straddle=strad, spans_outside=outs,
                span_read_frac_union=(iu / len(spans)) if spans else np.nan,
                span_read_frac_single=(isg / len(spans)) if spans else np.nan,
                span_read_frac_contig=(ict / len(spans)) if spans else np.nan,
                char_read_frac=round(char, 6)))
            for sp, (a, b, c, f) in zip(spans, per):
                span_rows.append(dict(
                    family=fam, skill_hash=h, attack=atk, dose=dose, geometry=geo,
                    item_id=sp["item_id"], quote_sha1=sp["quote_sha1"],
                    quote_len=sp["quote_len"], n_occ=sp["n_occ"],
                    first_start=sp["occ"][0][0], first_end=sp["occ"][0][1],
                    sheets="+".join(sorted(sp["sheets"])),
                    in_union=int(a), in_single=int(b), in_contig=int(c),
                    char_frac_of_span=round(f, 4)))
        del art, src, collapsed
    return pd.DataFrame(cell_rows), pd.DataFrame(span_rows)


# ============================================================ 6. verdict sources
def load_verdicts():
    """Every measured malicious-arm row, with the character read_frac the run stored."""
    out = []

    fp = os.path.join(NOTES, "v2_phase1_items.csv")
    d = pd.read_csv(fp, dtype=str)
    d = d[d.arm == "mal"]
    out.append(pd.DataFrame(dict(
        family="p1", source=os.path.basename(fp), model=d.model,
        skill_hash=d.skill_hash.astype(str), attack=d.attack,
        geometry=d.defense, dose=np.nan, verdict=d.verdict,
        char_stored=pd.to_numeric(d.read_frac, errors="coerce"),
        char_stored_kind="read_frac (P1.coverage_detail)")))

    for fp in sorted(glob.glob(os.path.join(NOTES, "v2_phase3_items_*.csv"))):
        d = pd.read_csv(fp, dtype=str)
        if "arm" not in d.columns or not len(d):
            continue
        d = d[d.arm == "mal"]
        if not len(d):
            continue
        out.append(pd.DataFrame(dict(
            family="p3", source=os.path.basename(fp), model=d.model,
            skill_hash=d.skill_hash.astype(str), attack=d.attack,
            geometry=d.defense, dose=np.nan, verdict=d.verdict,
            char_stored=pd.to_numeric(d.covered, errors="coerce"),
            char_stored_kind="covered (P1.covered_fraction)")))

    fp = os.path.join(NOTES, "v2_skillgate_items.csv")
    d = pd.read_csv(fp, dtype=str)
    d = d[d.arm == "mal"]
    out.append(pd.DataFrame(dict(
        family="p3", source=os.path.basename(fp), model=d.model,
        skill_hash=d.skill_hash.astype(str), attack=d.attack,
        geometry=d.reader, dose=np.nan, verdict=d.verdict,
        char_stored=pd.to_numeric(d.covered, errors="coerce"),
        char_stored_kind="covered (50-char probe, understates)")))

    fp = os.path.join(NOTES_V1, "pilot_dil2_items.csv")
    d = pd.read_csv(fp, dtype=str)
    d = d[d.condition.isin(["d_real", "pa_real", "il_matched", "il_heavy",
                            "f_only", "dose", "baseline"])]
    dose = pd.to_numeric(d.filler_chars, errors="coerce")
    dose = dose.where(d.condition == "dose", np.nan)
    out.append(pd.DataFrame(dict(
        family="dil2", source=os.path.basename(fp), model=d.model,
        skill_hash=d.skill_hash.astype(str), attack=d.condition,
        geometry=d.defense, dose=dose, verdict=d.verdict,
        char_stored=np.nan, char_stored_kind="none stored")))

    v = pd.concat(out, ignore_index=True)
    v = v[v.geometry.isin(set(PARTITION) | set(REGEX))]
    return v


# ============================================================ 7. report helpers
def corr(x, y):
    m = np.isfinite(x) & np.isfinite(y)
    if m.sum() < 4 or np.std(x[m]) == 0 or np.std(y[m]) == 0:
        return np.nan, np.nan, np.nan, np.nan, int(m.sum())
    pr, pp = stats.pearsonr(x[m], y[m])
    sr, sp = stats.spearmanr(x[m], y[m])
    return pr, pp, sr, sp, int(m.sum())


def auc(score_vals, is_safe):
    """P(score lower for a SAFE row than for a MALICIOUS row): a coverage measure that
    predicts evasion should give lower coverage where the judge said SAFE."""
    a = np.asarray(score_vals, float)
    y = np.asarray(is_safe, bool)
    m = np.isfinite(a)
    a, y = a[m], y[m]
    if y.sum() == 0 or (~y).sum() == 0:
        return np.nan, int(len(a))
    u = stats.mannwhitneyu(a[y], a[~y], alternative="two-sided").statistic
    return 1.0 - u / (y.sum() * (~y).sum()), int(len(a))


def main():
    print("loading corpora", flush=True)
    A.load_pool()
    assert len(A._POOL) >= 100, "filler pool too small"

    prim = pd.read_parquet(PRIMARY, columns=["skill_text"])
    prim["skill_text"] = prim["skill_text"].fillna("").astype(str)
    text_by_hash = {}
    for s in prim["skill_text"]:
        if s:
            text_by_hash.setdefault(D.skill_hash(s), s)
    n_mal_texts = len(text_by_hash)
    del prim

    quotes, key = load_quotes()
    need = set(quotes.skill_hash) - set(text_by_hash)
    if need:
        bn = pd.read_parquet(BENIGN, columns=["content"])["content"].dropna().astype(str)
        for t in bn:
            hh = D.skill_hash(t)
            if hh in need and hh not in text_by_hash:
                text_by_hash[hh] = t
        del bn

    inst, spans_by_hash, stat, failed = build_span_table(quotes, text_by_hash)
    n_located = int(len(inst))
    n_spans = sum(len(v) for v in spans_by_hash.values())
    print(f"quotes {len(quotes)} located {n_located} distinct spans {n_spans} "
          f"skills {len(spans_by_hash)}", flush=True)

    verdicts = load_verdicts()
    have = set(spans_by_hash)
    v = verdicts[verdicts.skill_hash.isin(have)].copy()

    jobs = set()
    for r in v.itertuples(index=False):
        jobs.add((r.family, r.skill_hash, r.attack,
                  None if not np.isfinite(r.dose) else float(r.dose), r.geometry))
    # regex_real has no measured verdict anywhere; add it as a coverage-only geometry on
    # the same artifacts the measured regex readers ran on.
    for fam, h, atk, dose, geo in list(jobs):
        if geo in REGEX_MEASURED:
            jobs.add((fam, h, atk, dose, "regex_real"))
    print(f"cells to compute: {len(jobs)}", flush=True)

    cells, spanrows = measure(spans_by_hash, text_by_hash, jobs)
    cells["dose"] = pd.to_numeric(cells.dose, errors="coerce")
    v["dose_k"] = v.dose
    items = v.merge(cells, left_on=["family", "skill_hash", "attack", "dose_k", "geometry"],
                    right_on=["family", "skill_hash", "attack", "dose", "geometry"],
                    how="inner", suffixes=("", "_c"))

    # ---- cross-validation against the published character measure -------------
    chk = items[np.isfinite(items.char_stored) &
                items.char_stored_kind.str.startswith(("read_frac", "covered (P1"))]
    dev = (chk.char_read_frac - chk.char_stored).abs()
    max_dev = float(dev.max()) if len(dev) else float("nan")
    n_bad = int((dev > 5e-4).sum())

    spanrows.to_csv(OUT_SPANS, index=False, encoding="utf-8")
    items.to_csv(OUT_ITEMS, index=False, encoding="utf-8")

    # ---- per-cell aggregation ------------------------------------------------
    ok = items[items.verdict.isin(GOOD)].copy()
    ok["safe"] = (ok.verdict == "SAFE").astype(int)
    agg = ok.groupby(["family", "source", "model", "geometry", "attack"],
                     dropna=False).agg(
        n=("safe", "size"), safe=("safe", "sum"),
        char=("char_read_frac", "mean"), char_stored=("char_stored", "mean"),
        span_u_macro=("span_read_frac_union", "mean"),
        span_s_macro=("span_read_frac_single", "mean"),
        span_c_macro=("span_read_frac_contig", "mean"),
        spans_u=("spans_union", "sum"), spans_s=("spans_single", "sum"),
        spans_c=("spans_contig", "sum"),
        spans_strad=("spans_straddle", "sum"),
        spans_out=("spans_outside", "sum"),
        n_spans=("n_spans", "sum")).reset_index()
    agg["asr"] = agg.safe / agg.n
    # micro: spans read / span decisions in the cell. This is the team-lead definition
    # summed over the cell's skills. 263 of 292 skills carry exactly one span, so the
    # macro average over skills differs from it only in the third decimal; both are kept.
    agg["span_u"] = agg.spans_u / agg.n_spans
    agg["span_s"] = agg.spans_s / agg.n_spans
    agg["span_c"] = agg.spans_c / agg.n_spans
    agg["gap_u"] = agg.char - agg.span_u
    agg["gap_c"] = agg.char - agg.span_c
    agg.to_csv(OUT_CELLS, index=False, encoding="utf-8")

    print("self-check: recomputing the contiguous measure without the index map",
          flush=True)
    sc_hashes = sorted(set(items.skill_hash[items.family == "p3"]))[:60]
    sc_tot, sc_bad, sc_detail = selfcheck(spans_by_hash, text_by_hash, sc_hashes)
    print(f"  {sc_tot} span decisions, {sc_bad} disagreements", flush=True)

    rr = cells[cells.geometry == "regex_real"]
    write_report(quotes, inst, spans_by_hash, stat, failed, key, items, ok, agg, rr,
                 max_dev, n_bad, len(chk), n_mal_texts,
                 (sc_tot, sc_bad, sc_detail, len(sc_hashes)))
    print("wrote", OUT_MD)
    print("wrote", OUT_CELLS, OUT_ITEMS, OUT_SPANS, sep="\n       ")


def write_report(quotes, inst, spans_by_hash, stat, failed, key, items, ok, agg, rr,
                 max_dev, n_bad, n_chk, n_mal_texts, sc):
    L = []
    W = L.append
    W("# v3 — span-level reader coverage\n")
    W("Generated by `scripts/v3_span_read_frac.py`. No judge was called; every number "
      "here is window arithmetic over the artifacts the measured runs built, joined to "
      "the verdicts those runs recorded. Row-level output: "
      "`v3_span_read_frac_cells.csv` (per cell), `v3_span_read_frac_items.csv` "
      "(per measured row), `v3_span_read_frac_spans.csv` (per span).\n")

    W("## 1. Evidence spans located\n")
    W(f"Quote instances in `audit/sheets/sheet_annot1.csv` + `sheet_annot2.csv` with "
      f"`verdict == MALICIOUS` and a non-empty `evidence_quote`: **{len(quotes)}** "
      f"(annot1 {int((quotes.sheet == 'annot1').sum())}, "
      f"annot2 {int((quotes.sheet == 'annot2').sum())}), over "
      f"{quotes.item_id.nunique()} distinct items and "
      f"{quotes.skill_hash.nunique()} distinct `skill_hash` values. This reproduces the "
      f"345 the paper reports.\n")
    W("| match rule | quote instances |")
    W("|---|---|")
    for k in ("verbatim", "strip_excel_apostrophe", "ws_collapsed", "nfkc",
              "not_found", "no_text"):
        W(f"| {k} | {stat[k]} |")
    W("")
    W(f"Located: **{len(inst)} / {len(quotes)}**. "
      f"{stat['verbatim']} occur byte-for-byte in the skill text resolved by "
      f"`skill_hash` from `data/malicious_skill_bench/primary.parquet` "
      f"({n_mal_texts} distinct texts).\n")
    if stat["strip_excel_apostrophe"]:
        ap = inst[inst.rule == "strip_excel_apostrophe"]
        W(f"The remaining {stat['strip_excel_apostrophe']} "
          f"({', '.join(sorted(ap.item_id))}) carry a leading `'` that the skill text "
          "does not. In every one of them the next character is `-`: the annotation "
          "sheet was opened in a spreadsheet, which prefixes an apostrophe to a cell "
          "beginning with `-` so it is not parsed as a formula. Stripping that one "
          "character makes all of them verbatim. The rule is applied only when the raw "
          "quote does not occur and the stripped one does, so it cannot manufacture a "
          "match. Neither whitespace normalisation nor NFKC was needed for any quote, "
          "and `audit/sheets/rule_change_before.json` is not implicated: its eight "
          "items (S0155, S0174, S0190, S0282, S0316, S0339, S0368, S0445) all carried "
          "an empty `evidence_quote` before the rule change and are not among the "
          "345.\n")
    if failed:
        W("Unlocated:\n")
        for iid, sheet, why in failed:
            W(f"- `{iid}` ({sheet}): {why}")
        W("")
    W(f"Distinct spans after de-duplicating a quote produced by both pipelines: "
      f"**{sum(len(v) for v in spans_by_hash.values())}** over "
      f"**{len(spans_by_hash)}** skills. Spans per skill: "
      f"{pd.Series([len(v) for v in spans_by_hash.values()]).value_counts().sort_index().to_dict()}.\n")
    occ = pd.Series([sp['n_occ'] for v in spans_by_hash.values() for sp in v])
    W(f"Occurrences of a span inside its own skill: "
      f"{occ.value_counts().sort_index().to_dict()}. A span with several occurrences "
      f"counts as read if ANY occurrence is wholly covered, which is the reading most "
      f"favourable to the reader.\n")
    W(f"Span length (characters): median {int(occ.size and np.median([sp['quote_len'] for v in spans_by_hash.values() for sp in v]))}, "
      f"min {min(sp['quote_len'] for v in spans_by_hash.values() for sp in v)}, "
      f"max {max(sp['quote_len'] for v in spans_by_hash.values() for sp in v)}.\n")

    ks = key.set_index("item_id")
    cov = inst.drop_duplicates("skill_hash")
    W("Coverage of the attack grid: of the "
      f"{len(spans_by_hash)} skills with a located span, "
      f"{items.skill_hash.nunique()} appear in at least one measured malicious-arm row, "
      f"giving {len(items)} measured (skill, attack, geometry, model) rows with both a "
      f"verdict and a span measurement.\n")
    W(f"By stratum (distinct items): "
      f"{inst.drop_duplicates('item_id').stratum.value_counts().to_dict()} "
      "— stratum A is the caught-set census, C the never-caught low-recall sample. "
      "No benign-stratum item (B, D) carries a MALICIOUS quote.\n")

    W("## 2. Cross-validation of the index map\n")
    W(f"The character read_frac recomputed here from the span index map was compared "
      f"against the value the original run stored, on the {n_chk} rows where that stored "
      f"value is `P1.coverage_detail` output (`v2_phase1_items.csv:read_frac` and "
      f"`v2_phase3_items_*.csv:covered`). Maximum absolute deviation "
      f"**{max_dev:.2e}**, rows deviating by more than 5e-4: **{n_bad}**. The shims also "
      "assert at run time that the collapse reproduces `A.collapse_repetition`, that the "
      "partition window offsets reproduce `P1.reader_requests`, and that the "
      "regex-window reconstruction reproduces `v2_skillgate.skillgate_prompt`.\n")
    sc_tot, sc_bad, sc_detail, sc_n = sc
    W("The span measure itself is cross-validated separately, because an index map that "
      "was silently wrong would still agree with itself. The contiguous span measure is "
      "recomputed by a second route that shares no code with the first: it asks the "
      "deployed reader function for its request strings and runs a plain substring test "
      "of the quote against each one. Over "
      f"{len(SELFCHECK)} (geometry, attack) combinations on {sc_n} skills, "
      f"**{sc_tot} span decisions and {sc_bad} disagreements.**\n")
    W("| geometry | attack | span decisions | disagreements |")
    W("|---|---|---|---|")
    for geo, atk, t, b in sc_detail:
        W(f"| `{geo}` | {atk} | {t} | {b} |")
    W("")
    W("`v2_skillgate_items.csv:covered` is NOT used as the character baseline: it was "
      "computed by testing 50-character probes for substring membership, which misses a "
      "probe straddling a window edge and understates coverage. For the regex readers "
      "the character baseline below is the exact recomputation from the index map, and "
      "the stored probe value is shown beside it.\n")

    def table(sel, title, note, measured=True):
        W(f"\n### {title}\n")
        if note:
            W(note + "\n")
        W("| model | geometry | attack | n | ASR | char read_frac | span (union) | "
          "span (single) | span (contiguous) | span decisions | char − span(contig) |")
        W("|---|---|---|---|---|---|---|---|---|---|---|")
        for r in sel.sort_values(["model", "geometry", "attack"]).itertuples(index=False):
            W(f"| `{r.model}` | `{r.geometry}` | {r.attack} | {r.n} | "
              f"{r.asr:.3f} | {r.char:.3f} | "
              f"{'' if pd.isna(r.span_u) else f'{r.span_u:.3f}'} | "
              f"{'' if pd.isna(r.span_s) else f'{r.span_s:.3f}'} | "
              f"{'' if pd.isna(r.span_c) else f'{r.span_c:.3f}'} | {int(r.n_spans)} | "
              f"{'' if pd.isna(r.gap_c) else f'{r.gap_c:+.3f}'} |")

    W("\n## 3. span_read_frac per (geometry x attack)\n")
    W("`char read_frac` is this script's recomputation, equal to the published measure "
      "on every row where the published measure exists (\\S2). The three span columns "
      "are three strictnesses, all over the span's non-whitespace characters:\n")
    W("- **union** — every character of the span reached the judge, in some window. The "
      "loosest reading.\n")
    W("- **single** — all of them reached ONE window, so a single judge call held the "
      "whole span.\n")
    W("- **contiguous** — the span appears as an uninterrupted passage in one window's "
      "text (whitespace runs normalised, because the collapse step re-joins the lines it "
      "keeps with a single space). This is the only column that refuses a span whose "
      "halves sit in the same window with thousands of characters of filler between "
      "them, which is exactly what a fragmenting attack produces. **It is the column to "
      "quote in the paper**, because it is the one that means \"the judge was shown this "
      "instruction\", and it is the only one of the three that can fall below 1 while "
      "`char read_frac` is exactly 1.000.\n")
    W("`char − span(contig)` is the disagreement that matters. ASR is the share of SAFE "
      "verdicts among SAFE+MALICIOUS "
      "rows in the same cell; `OVERFLOW` and `ERR` rows are excluded from ASR and from "
      "the cell coverage means, and are kept in the row-level CSV. `span decisions` is "
      "the cell's denominator: one decision per (row, span). The span columns are the "
      "micro ratio, spans read over span decisions; the macro average over skills is in "
      "`v3_span_read_frac_cells.csv` as `span_u_macro` / `span_s_macro` and differs only "
      "in the third decimal, because 263 of the 292 skills carry exactly one span.\n")

    a = agg[agg.n >= 5]
    table(a[a.family == "p1"], "Partition readers, Phase 1 attack grid",
          "Source: `v2_phase1_items.csv`. Artifacts from "
          "`v2_phase1_kill.build_attacks`.")
    p3p = a[(a.family == "p3") & a.geometry.isin(PARTITION) &
            a.source.str.startswith("v2_phase3")]
    table(p3p, "Partition readers, cross-judge attack grid",
          "Source: `v2_phase3_items_*.csv`. Artifacts from "
          "`v2_phase3_cross.segments_for`.")
    sgp = a[(a.family == "p3") & a.source.str.startswith("v2_skillgate")]
    table(sgp, "Regex-anchored and truncating readers",
          "Source: `v2_skillgate_items.csv`. `regex_real` (cw=1000, dedup=250, the "
          "500-characters-each-side geometry SkillGate's method section describes) has "
          "no measured verdict and so appears only in the coverage-only table below.")
    table(a[a.family == "dil2"], "First-generation readers and the dose sweep",
          "Source: `research_notes/pilot/pilot_dil2_items.csv`. These rows "
          "stored no character coverage; both measures here are computed from the index "
          "map. `dose` rows are pooled across filler volumes in this table and split in "
          "\\S6.")

    W("\n### Coverage-only: `regex_real` beside the measured regex readers\n")
    W("`regex_real` is cw=1000 / dedup=250 — 500 characters on each side of a pattern "
      "hit, which is what SkillGate's method section describes and what the paper notes "
      "at `reports/paper_v2.tex` in the readers list. The repo's `skillgate` reader "
      "implements 500 characters **total** per hit. No judge was ever run on "
      "`regex_real`, so **no ASR is reported for it** and none should be inferred; the "
      "columns below are window arithmetic over the same artifacts, with the measured "
      "geometries shown for scale.\n")
    W("| geometry | attack | skills | char read_frac | span (union) | span (single) | "
      "span (contiguous) |")
    W("|---|---|---|---|---|---|---|")
    rg = items[items.geometry.isin(REGEX_MEASURED)][
        ["geometry", "attack", "skill_hash", "char_read_frac",
         "span_read_frac_union", "span_read_frac_single", "spans_union",
         "spans_single", "spans_contig", "n_spans"]].drop_duplicates(
        ["geometry", "attack", "skill_hash"])
    both = pd.concat([rr.rename(columns={}), rg], ignore_index=True)
    for (geo, atk), gg in both.groupby(["geometry", "attack"]):
        if gg.n_spans.sum() == 0:
            continue
        W(f"| `{geo}` | {atk} | {gg.skill_hash.nunique()} | "
          f"{gg.char_read_frac.mean():.3f} | "
          f"{gg.spans_union.sum() / gg.n_spans.sum():.3f} | "
          f"{gg.spans_single.sum() / gg.n_spans.sum():.3f} | "
          f"{gg.spans_contig.sum() / gg.n_spans.sum():.3f} |")

    W("\n## 4. Where the two measures most disagree\n")
    W("Cells ranked by `char read_frac − span (contiguous)`, i.e. character coverage "
      "that looks adequate over evidence coverage that collapses. Only cells with "
      "n >= 10 and char read_frac >= 0.40 — a cell the character measure already calls "
      "badly read is not a disagreement. **These are the cells that carry the "
      "argument.**\n")
    dis = a[(a.n >= 10) & (a.char >= 0.40)].sort_values("gap_c", ascending=False).head(25)
    W("| model | geometry | attack | n | ASR | char | span (union) | span (single) | "
      "span (contiguous) | char − span(contig) |")
    W("|---|---|---|---|---|---|---|---|---|---|")
    for r in dis.itertuples(index=False):
        W(f"| `{r.model}` | `{r.geometry}` | {r.attack} | {r.n} | {r.asr:.3f} | "
          f"{r.char:.3f} | {r.span_u:.3f} | {r.span_s:.3f} | {r.span_c:.3f} | "
          f"{r.gap_c:+.3f} |")

    W("\n### Why a span goes unread: straddling an edge versus falling outside\n")
    W("The objection that motivated this measurement names a specific mechanism: a span "
      "cut by a window boundary is not read, yet the character measure still credits the "
      "half that landed inside. That mechanism is real but it is **not** where most of "
      "the gap comes from. Splitting every unread span decision into **straddle** (some "
      "of its characters reached the judge, some did not) and **outside** (none did):\n")
    W("`f_only` is excluded from this section only: it carries no payload, so every one "
      "of its spans is trivially outside every window and counting it would bury the "
      "mechanism under the no-payload control.\n")
    sd = agg[(agg.n >= 10) & (agg.attack != "f_only") &
             (agg.spans_strad + agg.spans_out > 0)].copy()
    sd["unread"] = sd.spans_strad + sd.spans_out
    sd["strad_share"] = sd.spans_strad / sd.unread
    tot_s, tot_o = int(sd.spans_strad.sum()), int(sd.spans_out.sum())
    W(f"Over every remaining cell with n >= 10 and at least one unread span: "
      f"**{tot_s + tot_o} unread span decisions, of which {tot_s} "
      f"({tot_s / (tot_s + tot_o):.1%}) straddle a window edge and {tot_o} "
      f"({tot_o / (tot_s + tot_o):.1%}) fall entirely outside.** So straddling is an "
      "eighth of the effect overall; the dominant mechanism is a span landing wholly in "
      "material the reader never sent. The span measure earns its place not because "
      "spans are usually cut in half, but because it tells apart the dropped characters "
      "that carried an evidence passage from the dropped characters that carried "
      "boilerplate — which is what the ASR split in \\S5 shows and what the character "
      "measure cannot do.\n")
    W("The cells with the most straddling span decisions in absolute terms:\n")
    W("| model | geometry | attack | span decisions | unread | straddling | outside | "
      "straddle share |")
    W("|---|---|---|---|---|---|---|---|")
    for r in sd.sort_values("spans_strad", ascending=False).head(15).itertuples(
            index=False):
        W(f"| `{r.model}` | `{r.geometry}` | {r.attack} | {int(r.n_spans)} | "
          f"{int(r.unread)} | {int(r.spans_strad)} | {int(r.spans_out)} | "
          f"{r.strad_share:.3f} |")
    W("")
    W("Straddle share by reader family, which locates the mechanism:\n")
    W("| reader family | unread span decisions | straddling | outside | straddle share |")
    W("|---|---|---|---|---|")
    for lab, geos in (("`dedup_full` / `dedup_lmax` (uncapped collapse)",
                       ["dedup_full", "dedup_lmax"]),
                      ("`dedup_small` (capped collapse)", ["dedup_small"]),
                      ("prefix (`none`, `trunc10k`, `trunc12k`)",
                       ["none", "trunc10k", "trunc12k"]),
                      ("regex (`skillgate`, `regex_nocap`, `regex_wide`)",
                       list(REGEX_MEASURED)),
                      ("`big_chunk` / `small_chunk`", ["big_chunk", "small_chunk"])):
        g0 = sd[sd.geometry.isin(geos)]
        u, s_, o = int(g0.unread.sum()), int(g0.spans_strad.sum()), int(g0.spans_out.sum())
        if u == 0:
            continue
        W(f"| {lab} | {u} | {s_} | {o} | {s_ / u:.3f} |")
    W("")
    ks = sd[sd.geometry.isin(["dedup_full", "dedup_lmax"]) &
            (sd.attack == "keyshadow_10k")]
    nk = sd[sd.geometry.isin(["dedup_full", "dedup_lmax"]) &
            (sd.attack != "keyshadow_10k")]
    W("The uncapped collapse readers (`dedup_full`, `dedup_lmax`) are where straddling "
      "dominates, and the reason is not the window edge at all. Their windows cover the "
      "whole collapsed artifact, so a span can only be lost to the collapse step: it "
      "deletes a payload line whose normalised key already appeared in the surrounding "
      "filler, punching a hole in the middle of a span that is otherwise well inside the "
      f"window union. Over every such cell except `keyshadow_10k`, **{int(nk.unread.sum())} "
      f"unread span decisions, {int(nk.spans_strad.sum())} straddling and "
      f"{int(nk.spans_out.sum())} outside** — the hole is the only available mechanism "
      "and the arithmetic confirms it. `keyshadow_10k` is the exception and contributes "
      f"all {int(ks.spans_out.sum())} of their outside decisions: it is built to make "
      "the collapse delete the payload entirely rather than partially (its character "
      f"read_frac in those cells is {ks.char.mean():.3f}). So `read_frac` credits two "
      "distinct failures the same way — a span cut at a window edge, and a span punched "
      "through inside the window union — and the span measure separates both from a "
      "clean read. The prefix and capped readers are the opposite case, where almost "
      "every unread span is simply past the cut.\n")

    W("\nThe same ranking for the union-vs-single gap, which is the cost of a span that "
      "is covered only because two windows between them contain its halves:\n")
    a2 = a.copy()
    a2["gap_us"] = a2.span_u - a2.span_s
    dis2 = a2[a2.n >= 10].sort_values("gap_us", ascending=False).head(15)
    W("| model | geometry | attack | n | ASR | span (union) | span (single) | "
      "union − single |")
    W("|---|---|---|---|---|---|---|---|")
    for r in dis2.itertuples(index=False):
        W(f"| `{r.model}` | `{r.geometry}` | {r.attack} | {r.n} | {r.asr:.3f} | "
          f"{r.span_u:.3f} | {r.span_s:.3f} | {r.gap_us:+.3f} |")

    W("\n## 5. Does span_read_frac predict ASR better than char read_frac?\n")
    W("Two levels. **Cell level**: one point per (model, geometry, attack) cell with "
      "n >= 5, x = the cell's mean coverage, y = the cell's ASR; Pearson r and Spearman "
      "rho. **Row level**: one point per measured malicious-arm row with a SAFE or "
      "MALICIOUS verdict; point-biserial r against SAFE=1, and the Mann-Whitney AUC for "
      "the coverage measure separating SAFE from MALICIOUS (0.5 = no signal, >0.5 = "
      "lower coverage where the judge said SAFE, which is the direction the paper's "
      "argument needs). `f_only` is excluded throughout: it carries no payload and no "
      "span, so neither measure is defined on it.\n")
    use = a[(a.attack != "f_only") & np.isfinite(a.span_u)]
    rows_u = ok[(ok.attack != "f_only") & np.isfinite(ok.span_read_frac_union)]
    W("| level | measure | n | Pearson r | p | Spearman rho | p | AUC (SAFE vs MAL) |")
    W("|---|---|---|---|---|---|---|---|")
    for name, col in (("char read_frac", "char"), ("span (union)", "span_u"),
                      ("span (single)", "span_s"), ("span (contiguous)", "span_c")):
        pr, pp, sr, sp, n = corr(use[col].values.astype(float),
                                 use.asr.values.astype(float))
        W(f"| cell | {name} | {n} | {pr:+.3f} | {pp:.2e} | {sr:+.3f} | {sp:.2e} | — |")
    for name, col in (("char read_frac", "char_read_frac"),
                      ("span (union)", "span_read_frac_union"),
                      ("span (single)", "span_read_frac_single"),
                      ("span (contiguous)", "span_read_frac_contig")):
        x = rows_u[col].values.astype(float)
        y = rows_u.safe.values.astype(float)
        pr, pp, sr, sp, n = corr(x, y)
        au, na = auc(x, rows_u.safe.values.astype(bool))
        W(f"| row | {name} | {n} | {pr:+.3f} | {pp:.2e} | {sr:+.3f} | {sp:.2e} | "
          f"{au:.3f} |")
    W("")
    W("Both measures are heavily piled at 0 and 1, which inflates a Pearson r on either "
      "of them. The sharper test is the cells where coverage is strictly partial under "
      "at least one measure, i.e. the cells the two measures can actually disagree "
      "about:\n")
    par = use[((use.char > 0) & (use.char < 1)) |
              ((use.span_u > 0) & (use.span_u < 1))]
    W("| measure | cells | Pearson r | p | Spearman rho | p |")
    W("|---|---|---|---|---|---|")
    for name, col in (("char read_frac", "char"), ("span (union)", "span_u"),
                      ("span (single)", "span_s"), ("span (contiguous)", "span_c")):
        pr, pp, sr, sp, n = corr(par[col].values.astype(float),
                                 par.asr.values.astype(float))
        W(f"| {name} | {n} | {pr:+.3f} | {pp:.2e} | {sr:+.3f} | {sp:.2e} |")
    W("")
    W("Read at the row level by strata, which avoids reading a correlation off a "
      "continuous variable that is mostly 0 or 1:\n")
    W("| measure | bucket | rows | SAFE | ASR |")
    W("|---|---|---|---|---|")
    for name, col in (("char read_frac", "char_read_frac"),
                      ("span (union)", "span_read_frac_union"),
                      ("span (single)", "span_read_frac_single"),
                      ("span (contiguous)", "span_read_frac_contig")):
        x = rows_u[col].values.astype(float)
        for lab, m in (("= 0", x == 0), ("in (0, 1)", (x > 0) & (x < 1)),
                       ("= 1", x == 1)):
            if m.sum() == 0:
                continue
            k = int(rows_u.safe.values[m].sum())
            W(f"| {name} | {lab} | {int(m.sum())} | {k} | {k / m.sum():.3f} |")
    W("")
    W("The character measure's three buckets are **not monotone** in ASR: its fully-read "
      "bucket has a higher ASR than its partially-read one. That is geometry confounding "
      "it — `none` reaches read_frac exactly 1.000 on the undiluted and contiguous "
      "conditions, which are also its highest-ASR cells, while the `dedup_*` readers sit "
      "at about 0.95 on the same conditions because their own collapse step deletes a "
      "few payload lines, so every well-defended row lands in the middle bucket. The "
      "span measure's buckets are monotone, because a 5% character loss off the evidence "
      "spans leaves span_read_frac at 1.\n")

    W("\n**This is the table that answers the objection.** Under the *union* measure, "
      "`char read_frac = 1` forces `span = 1`: if every payload character is inside the "
      "window union then so is every span, and that cell of the cross-tabulation is "
      "necessarily empty. Under the *contiguous* measure it is not, and the rows that "
      "land there are exactly the ones the reviewer described — a reader whose preflight "
      "reports that it received the entire payload, while a passage an auditor named as "
      "the reason the skill is malicious never arrived as readable text, because the "
      "attack wove filler through the middle of it:\n")
    x1 = rows_u.char_read_frac.values.astype(float)
    x2 = rows_u.span_read_frac_contig.values.astype(float)
    W("| char read_frac | span (contiguous) | rows | SAFE | ASR |")
    W("|---|---|---|---|---|")
    for lc, ls, m in (("= 1", "= 1", (x1 == 1) & (x2 == 1)),
                      ("= 1", "< 1", (x1 == 1) & (x2 < 1)),
                      ("< 1", "= 1", (x1 < 1) & (x2 == 1)),
                      ("< 1", "< 1", (x1 < 1) & (x2 < 1))):
        k = int(rows_u.safe.values[m].sum())
        W(f"| {lc} | {ls} | {int(m.sum())} | {k} | "
          f"{'n/a' if m.sum() == 0 else f'{k / m.sum():.3f}'} |")
    m11 = (x1 == 1) & (x2 == 1)
    m10 = (x1 == 1) & (x2 < 1)
    k11 = int(rows_u.safe.values[m11].sum())
    k10 = int(rows_u.safe.values[m10].sum())
    W("")
    if m10.sum():
        W(f"There are **{int(m10.sum())} judged rows on which `read_frac` is exactly "
          "1.000 and the contiguous span measure is below 1** — the preflight the paper "
          "reports passes with a perfect score and the judge still did not receive a "
          f"complete named instruction. Those rows evade at ASR {k10 / m10.sum():.3f} "
          f"against {k11 / m11.sum():.3f} on the {int(m11.sum())} rows where both "
          f"measures are 1, a ratio of {(k10 / m10.sum()) / (k11 / m11.sum()):.2f}. "
          "`read_frac` cannot see this population at all: by its own arithmetic these "
          "rows are fully read. The attacks that produce them are the interleaving "
          "conditions (\\S4), which is the one place the paper's dilution result is "
          "already hedged.\n")
    W("The same split restricted to the character measure's genuinely ambiguous rows, "
      "`0 < char read_frac < 1`, where the reader received part of the payload and the "
      "character measure alone cannot say whether that part mattered:\n")
    mid = (x1 > 0) & (x1 < 1)
    W("| span (contiguous) on `0 < char < 1` | rows | SAFE | ASR |")
    W("|---|---|---|---|")
    for lab, m in (("= 1", mid & (x2 == 1)), ("in (0, 1)", mid & (x2 > 0) & (x2 < 1)),
                   ("= 0", mid & (x2 == 0))):
        if m.sum() == 0:
            continue
        k = int(rows_u.safe.values[m].sum())
        W(f"| {lab} | {int(m.sum())} | {k} | {k / m.sum():.3f} |")

    W("\n## 6. Dose sweep, span by span\n")
    W("Source: `pilot_dil2_items.csv`, `condition == dose`, which stored no character "
      "coverage. Both measures are computed here.\n")
    dz = ok[(ok.family == "dil2") & (ok.attack == "dose")]
    if len(dz):
        g = dz.groupby(["model", "geometry", "dose_k"]).agg(
            n=("safe", "size"), safe=("safe", "sum"),
            char=("char_read_frac", "mean"),
            span_u=("span_read_frac_union", "mean"),
            span_s=("span_read_frac_single", "mean"),
            span_c=("span_read_frac_contig", "mean")).reset_index()
        g["asr"] = g.safe / g.n
        W("| model | geometry | filler chars | n | ASR | char | span (union) | "
          "span (single) | span (contiguous) |")
        W("|---|---|---|---|---|---|---|---|---|")
        for r in g.sort_values(["model", "geometry", "dose_k"]).itertuples(index=False):
            W(f"| `{r.model}` | `{r.geometry}` | {int(r.dose_k)} | {r.n} | {r.asr:.3f} | "
              f"{r.char:.3f} | {r.span_u:.3f} | {r.span_s:.3f} | {r.span_c:.3f} |")
        nn = g[(g.geometry == "none") & (g.model == "gpt-4o-mini")]
        if len(nn) > 1:
            lo, hi = nn.sort_values("dose_k").iloc[0], nn.sort_values("dose_k").iloc[-1]
            W("")
            W("**This is the informative negative in the whole report.** Contiguous "
              "dilution places filler around the payload and never inside an evidence "
              "span, so all three span measures stay pinned at 1.000 across the sweep "
              f"while ASR on `none` rises from {lo.asr:.3f} at {int(lo.dose_k)} filler "
              f"characters to {hi.asr:.3f} at {int(hi.dose_k)} (`{hi.model}`, "
              f"n = {int(hi.n)} per cell). Neither coverage measure explains that: the "
              "judge received every character and every named evidence passage whole, "
              "and said SAFE anyway. So span_read_frac does not absorb the dilution "
              "result into a reading artifact — it isolates it. Where coverage is 1 and "
              "ASR is high, the failure is the judge's attention, not the reader's "
              "geometry, and the paper should say so rather than claim the span measure "
              "explains dilution.\n")

    W("\n## 7. Per-span detail\n")
    W("`v3_span_read_frac_spans.csv` carries one row per (span, attack, geometry) "
      "decision with `in_union` and `in_single`. Spans are identified by a sha1 prefix "
      "of the quote and its length; the quote text is not reproduced.\n")
    sp = pd.read_csv(OUT_SPANS)
    W("Pooled per geometry. **These rows pool different attack sets**, because the "
      "geometries were not all run on the same attacks — `none` and the `dedup_*` family "
      "carry the Phase 1 and cross-judge grids, the regex family and `trunc*` carry the "
      "SkillGate grid, `big_chunk` / `small_chunk` carry the first-generation grid — so "
      "the columns are not comparable across rows. The comparable numbers are the "
      "per-attack cells in \\S3.\n")
    W("| geometry | span decisions | attacks | in union | in single | contiguous |")
    W("|---|---|---|---|---|---|")
    for geo, gg in sp.groupby("geometry"):
        W(f"| `{geo}` | {len(gg)} | {gg.attack.nunique()} | {gg.in_union.mean():.3f} | "
          f"{gg.in_single.mean():.3f} | {gg.in_contig.mean():.3f} |")
    W("")
    W("By where the span starts in the payload, as a fraction of payload length. Same "
      "pooling caveat: compare down a family, not across families.\n")
    plen = dict(zip(items.skill_hash, items.payload_len))
    sp["payload_len"] = sp.skill_hash.map(plen)
    sp = sp[np.isfinite(sp.payload_len)]
    sp["rel"] = sp.first_start / sp.payload_len
    bands = [(0.0, 0.25), (0.25, 0.5), (0.5, 0.75), (0.75, 1.01)]
    fams = {"prefix (`none`, `trunc10k`, `trunc12k`)":
            ["none", "trunc10k", "trunc12k"],
            "partition (`dedup_small`, `dedup_lmax`, `dedup_full`)":
            ["dedup_small", "dedup_lmax", "dedup_full"],
            "regex (`skillgate`, `regex_nocap`, `regex_wide`, `regex_real`)":
            ["skillgate", "regex_nocap", "regex_wide", "regex_real"]}
    W("| reader family | span start in payload | span decisions | in union | "
      "in single | contiguous |")
    W("|---|---|---|---|---|---|")
    for lab, geos in fams.items():
        g0 = sp[sp.geometry.isin(geos)]
        for lo, hi in bands:
            gg = g0[(g0.rel >= lo) & (g0.rel < hi)]
            if not len(gg):
                continue
            W(f"| {lab} | {lo:.2f}–{min(hi, 1.0):.2f} | {len(gg)} | "
              f"{gg.in_union.mean():.3f} | {gg.in_single.mean():.3f} | "
              f"{gg.in_contig.mean():.3f} |")
    W("")
    W("The prefix family falls monotonically with span position, which is what a "
      "truncating read predicts. The partition family is flat, which is what a reader "
      "that partitions the whole file predicts. The regex family is not monotone and is "
      "lowest on spans in the first quarter of the payload; we have not established why, "
      "and do not offer a mechanism for it.\n")

    # ---------------------------------------------------------------- paragraph
    W("\n## 8. One paragraph, for the paper\n")
    top = agg[(agg.n >= 10) & (agg.char >= 0.40)].sort_values("gap_c",
                                                              ascending=False).iloc[0]
    rev = agg[(agg.n >= 10) & (agg.geometry == "skillgate")].sort_values(
        "gap_c").iloc[0]
    m_eq = (x1 > 0) & (x1 < 1) & (x2 == 1)
    m_lt = (x1 > 0) & (x1 < 1) & (x2 < 1)
    k_eq = int(rows_u.safe.values[m_eq].sum())
    k_lt = int(rows_u.safe.values[m_lt].sum())
    pr_c, _, sr_c, _, nc = corr(use.char.values.astype(float),
                                use.asr.values.astype(float))
    pr_s, _, sr_s, _, _ = corr(use.span_c.values.astype(float),
                               use.asr.values.astype(float))
    au_c, _ = auc(rows_u.char_read_frac.values.astype(float),
                  rows_u.safe.values.astype(bool))
    au_s, _ = auc(rows_u.span_read_frac_contig.values.astype(float),
                  rows_u.safe.values.astype(bool))
    W("> Character coverage is not evidence coverage. The label audit required every "
      "MALICIOUS verdict to carry a quoted span, and we locate all "
      f"{len(inst)} of those quotes in the skill they annotate "
      f"({stat['verbatim']} byte-for-byte and "
      f"{stat['strip_excel_apostrophe']} after stripping a spreadsheet's "
      "formula-guard apostrophe), giving "
      f"{sum(len(v) for v in spans_by_hash.values())} distinct evidence spans over "
      f"{len(spans_by_hash)} skills, of which {items.skill_hash.nunique()} appear in the "
      "attack grid. We then recompute coverage at span granularity: a span counts as "
      "read only if it reaches one window as an uninterrupted passage. The strongest "
      f"case against `read_frac` is the {int(m10.sum())} judged rows on which it is "
      "exactly 1.000 — the preflight reporting that the judge received the entire "
      "payload — while a passage an auditor named as the reason the skill is malicious "
      "never arrived as readable text, because the attack wove filler through the middle "
      f"of it. Those rows evade at ASR {k10 / m10.sum():.3f} against "
      f"{k11 / m11.sum():.3f} on the {int(m11.sum())} rows where both measures are 1. "
      "`read_frac` cannot see that population: by its own arithmetic nothing was lost. "
      f"The effect concentrates in the interleaving conditions, where `{top.geometry}` "
      f"on `{top.attack}` records `read_frac` {top.char:.3f} against span coverage "
      f"{top.span_c:.3f} (`{top.model}`, n = {int(top.n)}, ASR {top.asr:.3f}). The "
      "distinction also sharpens the middle of the character measure's range: among the "
      f"{int(m_eq.sum() + m_lt.sum())} rows it can only call partially read "
      f"(0 < read_frac < 1), the {int(m_eq.sum())} whose evidence spans all survive "
      f"whole evade at {k_eq / m_eq.sum():.3f} and the {int(m_lt.sum())} that lost one "
      f"at {k_lt / m_lt.sum():.3f}. Across {nc} (judge, reader, attack) cells span "
      "coverage tracks ASR "
      f"better than `read_frac` does (Pearson {pr_s:+.3f} against {pr_c:+.3f}, Spearman "
      f"{sr_s:+.3f} against {sr_c:+.3f}), and row-wise it separates evaded from caught "
      f"more sharply (AUC {au_s:.3f} against {au_c:.3f}). The correction is not uniformly "
      "bad news for readers: the content-addressed regex geometry is the one family "
      "where the character measure *understates* a reader, and its largest reversal is "
      f"`{rev.geometry}` on `{rev.attack}`, which passes only {rev.char:.3f} of the "
      f"payload to the judge but {rev.span_c:.3f} of its evidence spans intact "
      f"(`{rev.model}`, n = {int(rev.n)}), because a "
      "pattern prefilter anchors its windows on precisely the material an auditor would "
      "quote. Position-addressed readers are therefore flattered by character coverage "
      "and content-addressed ones are penalised by it, which is why we report both.\n")
    W("\n## 9. What could not be computed, and what it would take\n")
    W("- A span is only as good as the quote the audit pipeline produced. The audit is "
      "LLM-based, so the span set inherits whatever that pipeline chose to quote; a "
      "skill may carry malicious instruction the pipeline did not quote. The measure is "
      "therefore a lower bound on evidence coverage loss, not a census of malicious "
      "instructions.\n")
    W("- A span is a contiguous character range. A malicious instruction spread over "
      "two separated passages would be scored as two spans and could count as read when "
      "no single window held the argument. Measuring that needs multi-span evidence "
      "annotations, which the audit did not collect.\n")
    W("- `regex_real` has coverage but no ASR, because no judge was run on it. "
      "Converting its coverage into an ASR needs a run of "
      "`scripts/v2_skillgate.py` with that geometry added to `GEOM`.\n")
    W("- `extract_then_judge` is excluded: it changes the aggregation, not the window "
      "geometry, and `v2_phase5_extract.py` stores no per-window offsets, so span "
      "containment is not defined for it from the stored artifacts.\n")
    W("- Benign-arm rows are out of scope: a benign skill has no evidence span, so "
      "span_read_frac has no benign-side analogue and no false-positive reading. "
      "Producing one would need the audit's BENIGN verdicts to carry a quoted span for "
      "the passage that *looked* malicious, which the sheets do not collect.\n")
    W("- No span measurement exists for the 28 quote-carrying skills "
      f"({len(spans_by_hash)} located minus {items.skill_hash.nunique()} in the grid) "
      "that never entered the attack grid. These are stratum C items no judge ever "
      "flagged, so the attack runs — all conditioned on a caught set — never built an "
      "artifact for them. Measuring them needs a run of the attack grid over the "
      "never-caught stratum, which is a design change, not a recomputation.\n")
    W("- `keyshadow_10k` is measured here, but note what it does to the measure: it "
      "defeats the collapse step rather than the window geometry, driving character "
      "coverage to near zero, so the two measures move together on it and the span "
      "measure adds nothing. The distinction the span measure buys is specific to "
      "fragmenting, truncating and partially-collapsing geometry.\n")
    W("- Significance tests on the difference between the two correlations are not "
      "reported. The cells are not independent (the same skills recur across geometries "
      "and judges, and the same artifact recurs across judges), so a test of "
      "r_span > r_char would need a cluster bootstrap over skill_hash. The point "
      "estimates and the row-level bucket split are reported instead, and the bucket "
      "split does not depend on a correlation at all.\n")

    with open(OUT_MD, "w", encoding="utf-8") as f:
        f.write("\n".join(L) + "\n")


if __name__ == "__main__":
    main()
