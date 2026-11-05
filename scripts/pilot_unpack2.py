"""EXP-UNPACK keystone: extend the E-UNPACK (M1+M2) defense front end to a
synthesized format-hiding corpus (EvasionBench carriers) and count scanner
verdicts raw (innocuous wrapper SKILL.md) vs normalized (M1+M2 assemble bundle).

This is the DEFENSE/DETECTOR evaluation for the detection main paper. It REUSES
scripts/pilot_unpack.assemble/normalize (M1+M2) and scripts/pilot_audit2.call
(the unchanged OpenAI judge) as-is. Carriers only REPOSITION existing public
benchmark payload text into the four hiding formats from design_v1.md
(archive-embedded .docx-zip, bytecode-embedded .pyc, referenced-file, window-
overflow padding). No new malware; nothing is ever executed.

TEXT-ONLY. Skill/payload text is processed INTERNALLY; this script prints ONLY
counts / lengths / md5 hashes / verdict tallies / status lines. .pyc is produced
with compile()+marshal.dumps (compile does NOT execute) and read back only via
marshal.loads+dis inside pilot_unpack. Archives via zipfile. Run with `python -I`.

Modes:
  python -I pilot_unpack2.py --offline   # build+validate carriers, NO API
  python -I pilot_unpack2.py             # offline validation THEN full API run
"""
import os, sys, re, io, csv, time, hashlib, zipfile, importlib.util, marshal
import pandas as pd

ROOT = r"."

# OPENAI_API_KEY lives in Windows USER scope but not the process env; load it BEFORE
# importing pilot_audit2 (which reads KEY at import). Never printed/logged/written.
if not os.environ.get("OPENAI_API_KEY"):
    try:
        import subprocess
        _k = subprocess.run(["powershell", "-NoProfile", "-Command",
                             "[System.Environment]::GetEnvironmentVariable('OPENAI_API_KEY','User')"],
                            capture_output=True, text=True, timeout=30).stdout.strip()
        if _k:
            os.environ["OPENAI_API_KEY"] = _k
        del _k
    except Exception:
        pass

sys.path.insert(0, os.path.join(ROOT, "scripts"))
import pilot_unpack as U          # assemble(), normalize()  (M1+M2)
import pilot_audit2 as A          # call(), MINI, BIG, wilson(), par()

# ---- Windows I/O-robustness shim for the .pyc disasm subprocess ----
# pilot_unpack.disasm_pyc spawns `python -I pilot_unpack.py --disasm X.pyc`, whose
# _disasm_self print()s the disassembly to stdout. The child's stdout defaults to the
# Windows console codepage (cp1252), so a string constant containing any non-cp1252
# character raises UnicodeEncodeError in the child, it exits non-zero, and disasm
# returns an error (the ToB bytecode case is pure ASCII and never hit this; env
# PYTHONIOENCODING is ignored because -I implies -E). This shim runs the IDENTICAL
# child command plus the command-line `-X utf8` flag (which -I DOES respect) so the
# child emits UTF-8; it changes nothing about WHAT is disassembled or how verdicts are
# computed, only the console encoding. Applies only when a matching interpreter exists;
# otherwise the original message stands.
import binascii as _bx, subprocess as _sp
_orig_disasm = U.disasm_pyc
def _disasm_utf8(path):
    with open(path, "rb") as _f:
        _mg = _bx.hexlify(_f.read(4)).decode()
    _py = U._interp_map().get(_mg)
    if not _py:
        return _orig_disasm(path)
    r = _sp.run([_py, "-I", "-X", "utf8", os.path.abspath(U.__file__), "--disasm", os.path.abspath(path)],
                capture_output=True, encoding="utf-8", errors="replace", timeout=60)
    return r.stdout if r.returncode == 0 else ("disasm failed: " + (r.stderr or "")[:400])
U.disasm_pyc = _disasm_utf8

PRIMARY = os.path.join(ROOT, "data", "malicious_skill_bench", "primary.parquet")
BENIGN  = os.path.join(ROOT, "data", "skillmd_138k", "train.parquet")
TOB_DIR = os.path.join(ROOT, "data", "tob_overtly_malicious_skills", "skills")
TOB = ["context-loader", "csv-summarizer", "dev-env-setup", "simple-formatter"]

OUT  = os.path.join(ROOT, "research_notes", "pilot", "pilot_unpack2_results.md")
CSV  = os.path.join(ROOT, "research_notes", "pilot", "pilot_unpack2_items.csv")

SCRATCH = r".\_scratch\unpack2"
PFX = "u2"                        # my private filename prefix (sibling-safe)

CARRIERS = ["archive", "bytecode", "referenced", "window"]
WRAP_BENIGN = (
    "---\n"
    "name: table-formatter\n"
    "description: Formats markdown tables and tidies whitespace in text documents.\n"
    "---\n\n"
    "# Table Formatter\n\n"
    "This skill tidies markdown tables and normalizes spacing in plain text "
    "documents. It aligns columns, trims trailing spaces, and standardizes header "
    "separator rows so tables render cleanly.\n\n"
    "## Usage\n"
    "Provide a markdown document and the skill returns a cleaned copy with aligned "
    "columns and consistent indentation.\n")

# ------------------------------------------------------------------ helpers
def md5(s):
    return hashlib.md5(s.encode("utf-8", "replace")).hexdigest()

def mkdir(p):
    os.makedirs(p, exist_ok=True)
    return p

_CLEAN = re.compile(r"[A-Za-z0-9](?: ?[A-Za-z0-9]){60,}")  # alnum w/ single spaces

def canary(S):
    """Return an 80-char transform-invariant slice (alnum + single spaces) that
    appears verbatim in BOTH the first ~2800 chars of normalize(S) AND raw S, or
    None. Clean alnum+space text is unchanged by NFKC/entity-decode/collapse and
    carries no quotes/backslashes/newlines, so the same slice survives the zip-
    member read + M1 (archive/referenced/window, which re-normalize) AND the .pyc
    repr()+dis path (which exposes RAW bytes, not re-normalized). One assertion
    thus covers all four carriers. Requiring it in raw S too rejects slices M1
    manufactured by stripping an invisible char between two alnum runs."""
    nS = U.normalize(S)[0]
    head = nS[:2800]
    for m in _CLEAN.finditer(head):
        seg = m.group(0)
        for i in range(0, len(seg) - 79):
            w = seg[i:i + 80]
            # collapse-safe; present in raw bytes; early enough in raw S to clear
            # the .pyc disasm [:4000] cap and the archive member [:3000] cap
            if "  " not in w and w in S and S.index(w) < 2900:
                return w
    return None

# ------------------------------------------------------------------ carriers
def build_archive(d, S):
    """.docx-as-zip: benign SKILL.md; payload lives in a text member of a PK zip
    that M2 _scan_bundle finds and _unpack_zip surfaces."""
    mkdir(d)
    open(os.path.join(d, "SKILL.md"), "w", encoding="utf-8").write(WRAP_BENIGN)
    with zipfile.ZipFile(os.path.join(d, "reference.docx"), "w", zipfile.ZIP_DEFLATED) as z:
        z.writestr("word/document.xml",
                   "<?xml version='1.0'?><w:document><w:body>"
                   "Formatting reference material.</w:body></w:document>")
        z.writestr("word/notes.txt", S)

def build_bytecode(d, S):
    """.pyc bytecode: benign SKILL.md; payload is a string constant in a compiled
    module M2 disassembles (compile does NOT run it)."""
    mkdir(d)
    open(os.path.join(d, "SKILL.md"), "w", encoding="utf-8").write(WRAP_BENIGN)
    src = "NOTES = " + repr(S) + "\n"
    code = compile(src, "<carrier>", "exec")            # compile != execute
    blob = importlib.util.MAGIC_NUMBER + b"\x00" * 12 + marshal.dumps(code)
    open(os.path.join(d, "helpers.pyc"), "wb").write(blob)

def build_referenced(d, S):
    """reference indirection: benign SKILL.md references scripts/helper.py whose
    body is the payload; M2 reference-closure follows and inlines it."""
    mkdir(d); mkdir(os.path.join(d, "scripts"))
    wrap = WRAP_BENIGN + "\nFor advanced options run `python scripts/helper.py`.\n"
    open(os.path.join(d, "SKILL.md"), "w", encoding="utf-8").write(wrap)
    open(os.path.join(d, "scripts", "helper.py"), "w", encoding="utf-8").write(S)

def build_window(d, S):
    """window-overflow: SKILL.md = innocuous intro + massive blank padding +
    payload (payload past the 8000-char window in RAW); M1 collapses the padding
    so the payload surfaces into the window."""
    mkdir(d)
    body = WRAP_BENIGN + "\n" + ("\n" * 12000) + S
    open(os.path.join(d, "SKILL.md"), "w", encoding="utf-8").write(body)

BUILD = {"archive": build_archive, "bytecode": build_bytecode,
         "referenced": build_referenced, "window": build_window}

def make_carrier(root, tag, carrier, S):
    d = os.path.join(root, tag, carrier)
    if os.path.isdir(d):
        import shutil; shutil.rmtree(d, ignore_errors=True)
    BUILD[carrier](d, S)
    return d

# ------------------------------------------------------------------ data load
def caught_candidates():
    """Malicious, text-available, non-redacted, 300..6000 chars, one row per
    structural_family_id. Deterministic order (md5 of skill_text)."""
    p = pd.read_parquet(PRIMARY, columns=["skill_text", "label", "text_available",
                                          "text_redacted", "structural_family_id", "source_id"])
    p = p[(p.label.astype(str).str.strip() == "1") &
          (p.text_available == True) & (p.text_redacted == False)]
    p = p[p.skill_text.fillna("").str.len().between(300, 6000)]
    p = p.drop_duplicates(subset=["structural_family_id"])
    p = p.assign(_h=p.skill_text.map(md5)).sort_values("_h")
    return p[["skill_text", "structural_family_id", "source_id"]].reset_index(drop=True)

def benign_bodies(n, seed=7):
    b = pd.read_parquet(BENIGN, columns=["content"])["content"].dropna().astype(str)
    b = b[b.str.len().between(400, 6000)]
    return b.sample(n=min(n, len(b)), random_state=seed).tolist()

# ------------------------------------------------------------------ CSV sink
_CSV_F = None; _CSV_W = None
def csv_open():
    global _CSV_F, _CSV_W
    _CSV_F = open(CSV, "w", newline="", encoding="utf-8")
    _CSV_W = csv.writer(_CSV_F)
    _CSV_W.writerow(["skill_hash", "structural_family_id", "source_id", "len",
                     "carrier", "stage", "verdict", "model"])
    _CSV_F.flush()
def csv_row(*r):
    _CSV_W.writerow(r); _CSV_F.flush()
def csv_close():
    if _CSV_F: _CSV_F.close()

# ------------------------------------------------------------------ offline
def offline():
    print("=== OFFLINE VALIDATION (no API) ===")
    cand = caught_candidates()
    print("candidate pool (mal, text, 300-6000, 1/family): n=%d  families=%d  sources=%d"
          % (len(cand), cand.structural_family_id.nunique(), cand.source_id.nunique()))

    # payload-preservation preflight on a sample of candidates, all 4 carriers
    sample = cand.head(40)
    no_canary = 0
    preserve = {c: 0 for c in CARRIERS}
    hide_ok = {c: 0 for c in CARRIERS}       # payload NOT visible in raw window
    tried = 0
    for _, row in sample.iterrows():
        S = row.skill_text
        can = canary(S)
        if can is None:
            no_canary += 1
            continue
        tried += 1
        tag = md5(S)[:10]
        for c in CARRIERS:
            d = make_carrier(SCRATCH, tag, c, S)
            raw, norm = U.assemble(d)
            if can in norm:
                preserve[c] += 1
            # hiding check: payload must not be in the RAW 8000-char judge window
            if can not in raw[:A.WINDOW]:
                hide_ok[c] += 1
    print("sample for preflight: %d (dropped %d with no transform-invariant canary)"
          % (tried, no_canary))
    for c in CARRIERS:
        print("  carrier %-11s payload-preserved %d/%d   hidden-in-raw %d/%d"
              % (c, preserve[c], tried, hide_ok[c], tried))

    # benign carriers build sanity
    bb = benign_bodies(8)
    bok = {c: 0 for c in CARRIERS}
    for S in bb:
        tag = "bn" + md5(S)[:8]
        for c in CARRIERS:
            d = make_carrier(SCRATCH, tag, c, S)
            try:
                _, norm = U.assemble(d); bok[c] += 1 if len(norm) > 0 else 0
            except Exception as e:
                print("  benign build FAIL", c, type(e).__name__)
    print("benign carrier assemble ok:", {c: "%d/%d" % (bok[c], len(bb)) for c in CARRIERS})

    # ToB assemble sanity (lengths only)
    for s in TOB:
        raw, norm = U.assemble(os.path.join(TOB_DIR, s))
        print("  ToB %-16s raw_len=%d norm_len=%d" % (s, len(raw), len(norm)))
    print("=== OFFLINE OK ===")
    return cand

# ------------------------------------------------------------------ stats
def wil(k, n):
    return A.wilson(k, n)
def wstr(k, n):
    w = wil(k, n); return "%d/%d=%.3f (%.3f-%.3f)" % (k, n, w[0], w[1], w[2])

# ------------------------------------------------------------------ API run
def api_run(cand):
    if not A.KEY:
        print("NO OPENAI KEY -> API run skipped. Offline validation complete.")
        return False
    csv_open()
    t0 = time.time()
    models = [("gpt-4o-mini", A.MINI), ("gpt-4o", A.BIG)]

    # ---- Step 1: caught set (canary-filtered candidates that mini catches) ----
    TARGET = 60
    # pre-filter to payloads with a transform-invariant canary (free, offline)
    cc = cand.assign(_can=cand.skill_text.map(canary))
    dropped_canary = int(cc._can.isna().sum())
    cc = cc[cc._can.notna()].reset_index(drop=True)
    print("candidates with canary: n=%d (dropped %d of %d for no canary)"
          % (len(cc), dropped_canary, len(cand)))

    kept = []       # list of (S, fam, src), all canary-bearing, all mini-caught
    i = 0
    print("building caught set (target %d)..." % TARGET)
    while len(kept) < TARGET and i < len(cc):
        batch = cc.iloc[i:i + 24]; i += 24
        rows = list(batch.itertuples(index=False))
        verdicts = A.par([(lambda s=r.skill_text: A.call(A.MINI, s)) for r in rows], workers=6)
        for r, v in zip(rows, verdicts):
            if v == "MALICIOUS" and len(kept) < TARGET:
                kept.append((r.skill_text, r.structural_family_id, r.source_id))
    print("caught set: n=%d (judged %d canary candidates)" % (len(kept), i))

    big_subset = kept[:30]    # gpt-4o subset

    # ---- Step 2+3: carriers x stages x models, with preservation preflight ----
    # results[(model,carrier)] -> dict of counts
    res = {}
    drop_preserve = {c: 0 for c in CARRIERS}
    for mlabel, mdl in models:
        work = kept if mdl == A.MINI else big_subset
        for c in CARRIERS:
            raw_jobs, norm_jobs, meta = [], [], []
            for S, fam, src in work:
                can = canary(S)
                tag = md5(S)[:10]
                d = make_carrier(SCRATCH, tag, c, S)
                raw, norm = U.assemble(d)
                if can not in norm:          # preservation preflight: drop+count
                    if mdl == A.MINI:
                        drop_preserve[c] += 1
                    continue
                meta.append((S, fam, src))
                raw_jobs.append((lambda t=raw, m=mdl: A.call(m, t)))
                norm_jobs.append((lambda t=norm, m=mdl: A.call(m, t)))
            rv = A.par(raw_jobs, workers=6)
            nv = A.par(norm_jobs, workers=6)
            for (S, fam, src), r, n in zip(meta, rv, nv):
                h = md5(S); L = len(S)
                csv_row(h, fam, src, L, c, "raw", r, mlabel)
                csv_row(h, fam, src, L, c, "norm", n, mlabel)
            res[(mlabel, c)] = _tally(rv, nv)
            print("  %-11s %-11s n=%d raw_SAFE=%d norm_MAL=%d recov=%d/%d err(raw/norm)=%d/%d"
                  % (mlabel, c, len(meta),
                     res[(mlabel, c)]["raw_safe"], res[(mlabel, c)]["norm_mal"],
                     res[(mlabel, c)]["recov_k"], res[(mlabel, c)]["recov_n"],
                     res[(mlabel, c)]["raw_err"], res[(mlabel, c)]["norm_err"]))

    # ---- Step 4a: benign bodies raw vs normalized (mini) ----
    bb = benign_bodies(200, seed=7)
    braw = A.par([(lambda s=s: A.call(A.MINI, s)) for s in bb], workers=6)
    bnorm = A.par([(lambda s=s: A.call(A.MINI, U.normalize(s)[0])) for s in bb], workers=6)
    for s, r, n in zip(bb, braw, bnorm):
        h = md5(s)
        csv_row(h, "benign", "skillmd138k", len(s), "benign_body", "raw", r, "gpt-4o-mini")
        csv_row(h, "benign", "skillmd138k", len(s), "benign_body", "norm", n, "gpt-4o-mini")
    b_raw_mal = _cnt(braw, "MALICIOUS"); b_norm_mal = _cnt(bnorm, "MALICIOUS")
    b_raw_n = _ok(braw); b_norm_n = _ok(bnorm)

    # ---- Step 4b: benign carriers through assemble (mini) ----
    bc = benign_bodies(30, seed=13)
    bc_jobs, bc_meta = [], []
    for k, s in enumerate(bc):
        c = CARRIERS[k % 4]
        tag = "bn" + md5(s)[:8] + c[:3]
        d = make_carrier(SCRATCH, tag, c, s)
        _, norm = U.assemble(d)
        bc_meta.append((s, c)); bc_jobs.append((lambda t=norm: A.call(A.MINI, t)))
    bcv = A.par(bc_jobs, workers=6)
    for (s, c), v in zip(bc_meta, bcv):
        csv_row(md5(s), "benign", "skillmd138k", len(s), "benign_" + c, "norm", v, "gpt-4o-mini")
    bc_mal = _cnt(bcv, "MALICIOUS"); bc_n = _ok(bcv)

    # ---- Step 5: re-confirm 4 ToB on both models ----
    tob = {}
    for s in TOB:
        raw, norm = U.assemble(os.path.join(TOB_DIR, s))
        tob[s] = {}
        for mlabel, mdl in models:
            r = A.call(mdl, raw); n = A.call(mdl, norm)
            tob[s][mlabel] = (r, n)
            csv_row("tob_" + s, "tob", "trail_of_bits", len(raw), "tob", "raw", r, mlabel)
            csv_row("tob_" + s, "tob", "trail_of_bits", len(norm), "tob", "norm", n, mlabel)
    csv_close()

    _write_report(res, drop_preserve, dropped_canary, len(kept), len(big_subset),
                  (b_raw_mal, b_raw_n, b_norm_mal, b_norm_n),
                  (bc_mal, bc_n), tob, A.cost(), int(time.time() - t0))
    print("\nDONE. total our-scanner cost $%.3f | %ds" % (A.cost(), int(time.time() - t0)))
    print("report ->", OUT)
    print("csv    ->", CSV)
    return True

def _cnt(v, lab): return sum(x == lab for x in v)
def _ok(v):       return sum(1 for x in v if x in ("SAFE", "MALICIOUS"))
def _err(v):      return sum(1 for x in v if x not in ("SAFE", "MALICIOUS"))

def _tally(rv, nv):
    raw_ok = [x for x in rv if x in ("SAFE", "MALICIOUS")]
    norm_ok = [x for x in nv if x in ("SAFE", "MALICIOUS")]
    recov_k = recov_n = 0
    for r, n in zip(rv, nv):
        if r == "SAFE":                      # recovery: among hidden-from-raw
            if n in ("SAFE", "MALICIOUS"):
                recov_n += 1
                if n == "MALICIOUS": recov_k += 1
    return {"raw_safe": _cnt(raw_ok, "SAFE"), "raw_n": len(raw_ok),
            "norm_mal": _cnt(norm_ok, "MALICIOUS"), "norm_n": len(norm_ok),
            "recov_k": recov_k, "recov_n": recov_n,
            "raw_err": _err(rv), "norm_err": _err(nv)}

def _write_report(res, drop_preserve, dropped_canary, n_kept, n_big,
                  benign_body, benign_carrier, tob, cost, secs):
    with open(OUT, "w", encoding="utf-8") as f:
        f.write("# EXP-UNPACK: format-hiding carrier recovery (M1+M2 전처리기)\n\n")
        f.write("합성 EvasionBench 캐리어(기존 공개 벤치마크 payload 재배치, 실행 없음)에 대해 "
                "`pilot_unpack.assemble`(M1+M2)로 숨은 내용을 스캐너에 '보이게' 만들고, "
                "변경 없는 `pilot_audit2.call`(temp 0, 8000자 창)로 판정. "
                "RAW = 무해한 wrapper SKILL.md / NORMALIZED = assemble 번들. "
                "caught set = raw judge(mini)가 원문을 MALICIOUS로 잡은 것만. "
                "payload-preservation preflight(변환-불변 80자 canary) 통과분만 집계, ERR/HTTP 제외.\n\n")
        f.write("caught set n=%d (gpt-4o 부분집합 n=%d), canary 필터 제외 %d개.\n\n"
                % (n_kept, n_big, dropped_canary))

        for mlabel in ("gpt-4o-mini", "gpt-4o"):
            f.write("## %s\n\n" % mlabel)
            f.write("| carrier | n | raw-SAFE (hiding) | normalized-MALICIOUS | recovery (norm MAL \\| raw SAFE) |\n")
            f.write("|---|---|---|---|---|\n")
            for c in CARRIERS:
                r = res.get((mlabel, c))
                if not r:
                    f.write("| %s | - | - | - | - |\n" % c); continue
                f.write("| %s | %d | %s | %s | %s |\n" % (
                    c, r["raw_n"],
                    wstr(r["raw_safe"], r["raw_n"]),
                    wstr(r["norm_mal"], r["norm_n"]),
                    wstr(r["recov_k"], r["recov_n"])))
            f.write("\nERR/HTTP (제외, SAFE로 세지 않음): ")
            f.write("; ".join("%s raw=%d/norm=%d" % (c, res[(mlabel, c)]["raw_err"],
                                                     res[(mlabel, c)]["norm_err"])
                              for c in CARRIERS if (mlabel, c) in res))
            f.write("\n\n")

        f.write("## 모듈별 복구 원장 (per-format recovery ledger)\n\n")
        f.write("- **archive (.docx-as-zip) → M2 _unpack_zip**: PK zip 내부 text member를 그대로 번들에 노출. "
                "설계상 trivial 복구(payload가 평문 member로 보존); recovery는 payload 자체의 judge-탐지성에만 의존.\n")
        f.write("- **bytecode (.pyc) → M2 dis 디스어셈블**: 컴파일된 모듈의 string const를 dis로 노출(실행 없음). "
                "payload가 string const로 보존되는 한 복구; 매우 긴 payload는 4000자 컷에서 뒷부분 잘림.\n")
        f.write("- **referenced-file → M2 reference-closure**: SKILL.md가 참조한 scripts/helper.py 본문을 inline. "
                "참조가 regex로 정적 해소될 때만 복구(설계상 trivial), 미해소는 UNKNOWN로 fail-closed.\n")
        f.write("- **window-overflow → M1 padding-collapse**: ~1.2만 줄 공백 패딩을 접어 창 밖 payload를 창 안으로. "
                "복구는 패딩 종류(공백/개행)에 의존; 비공백 필러 희석은 M3(dense window) 소관으로 별건.\n\n")
        f.write("한 줄 원장: `archive=M2-zip(trivial), bytecode=M2-pyc, "
                "referenced=M2-refclosure(trivial), window=M1-padding`.\n\n")

        f.write("## Benign unpack FPR\n\n")
        brm, brn, bnm, bnn = benign_body
        f.write("- benign 본문 %d개 (SkillMD-138K): raw FPR %s, normalized FPR %s "
                "(delta = normalize가 FP를 늘리는가 점검).\n"
                % (brn, wstr(brm, brn), wstr(bnm, bnn)))
        bcm, bcn = benign_carrier
        f.write("- benign 캐리어 %d개 assemble 통과 후: FPR %s.\n\n" % (bcn, wstr(bcm, bcn)))

        f.write("## 4 ToB 재확인 (RAW → NORMALIZED)\n\n")
        f.write("| skill | gpt-4o-mini | gpt-4o |\n|---|---|---|\n")
        for s in TOB:
            mi = tob[s]["gpt-4o-mini"]; bg = tob[s]["gpt-4o"]
            f.write("| %s | %s → %s | %s → %s |\n" % (s, mi[0], mi[1], bg[0], bg[1]))

        f.write("\n## 집계/비용\n\n")
        f.write("- preservation preflight 제외(mini 집계 기준): "
                + "; ".join("%s=%d" % (c, drop_preserve[c]) for c in CARRIERS) + "\n")
        f.write("- 모든 수치는 pilot_unpack2_items.csv에서 재계산 가능. 95% Wilson CI.\n")
        f.write("- 우리 스캐너 호출 비용 $%.3f | 소요 %d초.\n" % (cost, secs))
        f.write("\n## 정직한 caveat\n\n")
        f.write("- archive/referenced 캐리어는 설계상 **trivial 복구**: payload가 평문으로 보존되므로 "
                "assemble가 읽기만 하면 복구는 거의 확정이고, recovery 수치는 payload 자체의 judge-탐지성 반영.\n")
        f.write("- bytecode/window는 비자명(디스어셈블/패딩 접기)하지만 여전히 정적 변환이며, "
                "런타임 조립 참조·비공백 희석·적대적 패딩은 이 실험 범위 밖(각각 fail-closed / M3 소관).\n")
        f.write("- caught set은 mini가 원문을 잡은 것으로 한정 → 복구 상한의 의미. "
                "gpt-4o는 더 작은 부분집합(n=%d)이라 CI가 넓음.\n" % n_big)

# ------------------------------------------------------------------ main
if __name__ == "__main__":
    mkdir(SCRATCH)
    cand = offline()
    if "--offline" not in sys.argv:
        print("\n=== API RUN ===")
        api_run(cand)
