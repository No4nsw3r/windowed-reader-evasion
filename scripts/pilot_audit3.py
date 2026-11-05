"""Decisive dilution test (rigor-reviewer top risk): does the small-window defense (dedup_small)
still reduce dilution when the filler is INTERLEAVED into the payload (not just appended around a
contiguous block), and across the FULL payload-length distribution? The earlier clean result
(0.757 -> 0.143) used contiguous filler on <=3000-char payloads, which lets a 2500-char window land
almost tautologically on the whole payload. Interleaving the payload with real benign SKILL.md text
is the adaptive attacker's move: every window then sees payload fragments buried in benign text.
Payload is PRESERVED exactly (filler inserted between slices; ''.join(pieces)==S). Text only, nothing
executed. Reuses pilot_audit2's filler pool, scanner, and defenses. usage: rehearse | run"""
import os, sys, math, re, io, time
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import pilot_audit2 as A  # reuse: call, DEF, load_mal, load_pool, filler_real, f_only, d_real, par, wilson, cnt

OUT = os.path.join(A.ROOT, "research_notes", "pilot", "pilot_audit3_results.md")
MINI, BIG = A.MINI, A.BIG

def cut_positions(S, n_cuts):
    L = len(S); targets = [int(L * (i + 1) / (n_cuts + 1)) for i in range(n_cuts)]
    pos = []
    for t in targets:
        j = t
        while j < L and not S[j].isspace():
            j += 1
        if 0 < j < L:
            pos.append(j)
    return sorted(set(pos))
def interleave(S, filler_total, n_cuts, seed):
    """Split S into n_cuts+1 slices (exact partition) and weave real benign filler between them."""
    cuts = cut_positions(S, n_cuts)
    pieces, prev = [], 0
    for c in cuts:
        pieces.append(S[prev:c]); prev = c
    pieces.append(S[prev:])
    assert "".join(pieces) == S, "payload not preserved"
    gaps = max(1, len(pieces) - 1); per = max(200, filler_total // gaps)
    out = pieces[0]
    for i in range(1, len(pieces)):
        out += "\n\n" + A.filler_real(per, seed + i * 7) + "\n\n" + pieces[i]
    return out
def seedof(S): return hash(S) & 0xffff
def d_contig(S):      return A.d_real(S)                               # prior contiguous (filler + S + filler)
def d_inter6(S):      return interleave(S, 4500, 6, seedof(S))         # ~same filler volume, woven into 7 pieces
def d_inter12(S):     return interleave(S, 4500, 12, seedof(S))        # finer: 13 pieces, payload fragments ~1/13 each
def d_inter_heavy(S): return interleave(S, 9000, 10, seedof(S))       # heavier filler, longer total (>window for none)

def cnt(v, lab): return sum(x == lab for x in v)
def fmt(k, n): w = A.wilson(k, n); return f"{k}/{n} = {w[0]} ({w[1]}~{w[2]})"

def caught(model, pool, cap):
    base = A.par([lambda s=s: A.call(model, s) for s in pool])
    cm = [s for s, v in zip(pool, base) if v == "MALICIOUS"][:cap]
    return cm, A.wilson(cnt(base, "MALICIOUS"), len(pool))

def rehearse():
    print("=== VALIDATE audit3 ===")
    A.load_pool()
    x = next((t for t in A.load_mal(6, 11, 3000) if A.call(MINI, t) == "MALICIOUS"), A.load_mal(1, 11, 3000)[0])
    for nm, fn in [("contig", d_contig), ("inter6", d_inter6), ("inter12", d_inter12)]:
        t = fn(x)
        print(f"{nm}: total={len(t)} payload_preserved={all(p in t for p in [x[:40], x[-40:]])} "
              f"| none={A.DEF['none'](MINI, t)} | dedup_small={A.DEF['dedup_small'](MINI, t)}")
    print("filler pool", len(A._POOL), "| validate cost ${:.4f}".format(A.cost()))

def run():
    A.load_pool()
    with io.open(OUT, "w", encoding="utf-8") as f:
        W = lambda *a: print(*a, file=f) or f.flush()
        W("# 결정 실험: interleaved 필러 + 전체 길이에서 작은 창 방어가 희석을 막는가")
        W("ASR=잡힌 악성이 SAFE로 뒤집힌 비율(낮을수록 방어 좋음). 필러=실제 정상 SKILL.md 본문. temp 0.")
        W("contig=필러+S+필러(기존). inter6/12=S를 7/13조각으로 쪼개 사이에 필러(적응형). 모두 payload 전량 보존.\n")
        # Pool 1: short payloads so 'none' is not truncation-confounded; direct contiguous-vs-interleaved
        pool = A.load_mal(240, 11, 3000)
        cm, rec = caught(MINI, pool, 75)
        W(f"## gpt-4o-mini, 3000자 이하 (기본재현율 {rec[0]} CI {rec[1]}~{rec[2]}, 잡힌 {len(cm)})")
        W("| 공격 | none | big_chunk | dedup_small |")
        W("|---|---|---|---|")
        for nm, fn in [("rejudge(바닥)", lambda s: s), ("contig", d_contig),
                       ("inter6", d_inter6), ("inter12", d_inter12)]:
            cells = []
            for d in ["none", "big_chunk", "dedup_small"]:
                v = A.par([lambda s=s, fn=fn, d=d: A.DEF[d](MINI, fn(s)) for s in cm], workers=4)
                cells.append(fmt(cnt(v, "SAFE"), len(cm)))
            W(f"| {nm} | " + " | ".join(cells) + " |")
        # filler-only false positives for the interleave construction
        fo = A.par([lambda s=s: A.DEF["dedup_small"](MINI, A.f_only(s)) for s in cm], workers=4)
        W(f"\nfiller_only 오탐(dedup_small): {fmt(cnt(fo,'MALICIOUS'), len(cm))}")
        # Pool 2: FULL length distribution, interleaved, stratified
        pool2 = A.load_mal(240, 23)
        cm2, rec2 = caught(MINI, pool2, 80)
        sh = [s for s in cm2 if len(s) <= 3000]; lo = [s for s in cm2 if len(s) > 3000]
        W(f"\n## gpt-4o-mini, 전체 길이 (기본재현율 {rec2[0]}, 잡힌 {len(cm2)}: <=3000 {len(sh)}개 / >3000 {len(lo)}개)")
        W("inter6 기준, 길이 구간별 ASR\n")
        W("| 구간 | none | dedup_small |")
        W("|---|---|---|")
        for nm, grp in [("전체", cm2), ("<=3000", sh), (">3000", lo)]:
            if not grp: continue
            a = A.par([lambda s=s: A.DEF["none"](MINI, d_inter6(s)) for s in grp], workers=4)
            b = A.par([lambda s=s: A.DEF["dedup_small"](MINI, d_inter6(s)) for s in grp], workers=4)
            W(f"| {nm} ({len(grp)}) | {fmt(cnt(a,'SAFE'),len(grp))} | {fmt(cnt(b,'SAFE'),len(grp))} |")
        # gpt-4o confirm on the decisive cells
        cg, rg = caught(BIG, A.load_mal(90, 11, 3000), 28)
        W(f"\n## gpt-4o 확인, 3000자 이하 (기본재현율 {rg[0]}, 잡힌 {len(cg)})")
        W("| 공격 | none | dedup_small |")
        W("|---|---|---|")
        for nm, fn in [("contig", d_contig), ("inter6", d_inter6)]:
            a = A.par([lambda s=s, fn=fn: A.DEF["none"](BIG, fn(s)) for s in cg], workers=4)
            b = A.par([lambda s=s, fn=fn: A.DEF["dedup_small"](BIG, fn(s)) for s in cg], workers=4)
            W(f"| {nm} | {fmt(cnt(a,'SAFE'),len(cg))} | {fmt(cnt(b,'SAFE'),len(cg))} |")
        W(f"\n---\n**대략 비용 ${A.cost():.3f}**")
    print(f"done -> {OUT} | cost ${A.cost():.3f}")

if __name__ == "__main__":
    if not A.KEY:
        print("NO KEY"); sys.exit(1)
    (rehearse if (len(sys.argv) > 1 and sys.argv[1] == "rehearse") else run)()
