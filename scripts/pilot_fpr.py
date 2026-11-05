"""E-FPR: the honest operating point. The dense-window defense trades benign false positives
for recall; the paper must report precision at REALISTIC prevalence, not benchmark prevalence.
Measure, at large n, the benign false-positive rate and the malicious recall (TPR) under the stock
single-window judge vs the dedup_small defense, then compute precision at 0.01/0.1/1% prevalence via
Bayes. Benign = real SkillMD-138K bodies; malicious = MaliciousSkillBench. Text only.
Reuses pilot_audit2 (call, DEF, load_benign, load_mal, par, wilson). usage: rehearse | run"""
import os, sys, io
import pandas as pd
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import pilot_audit2 as A

OUT = os.path.join(A.ROOT, "research_notes", "pilot", "pilot_fpr_results.md")
MINI, BIG = A.MINI, A.BIG

def load_benign(n, seed=41):
    s = pd.read_parquet(A.BENIGN_FP, columns=["content"])["content"].dropna().astype(str)
    s = s[s.str.len() > 200]
    return s.sample(n=min(n, len(s)), random_state=seed).tolist()
A.load_benign = load_benign  # patch for convenience
def cnt(v, lab): return sum(x == lab for x in v)
def fmt(k, n): w = A.wilson(k, n); return f"{k}/{n} = {w[0]} ({w[1]}~{w[2]})"
def prec(tpr, fpr, pi):
    d = pi*tpr + (1-pi)*fpr
    return (pi*tpr/d) if d > 0 else 0.0

def measure(model, mal, ben, defense):
    r = A.par([lambda s=s: A.DEF[defense](model, s) for s in mal], workers=5)
    f = A.par([lambda s=s: A.DEF[defense](model, s) for s in ben], workers=5)
    tpr = cnt(r, "MALICIOUS")/len(mal); fpr = cnt(f, "MALICIOUS")/len(ben)
    return tpr, fpr, r, f

def rehearse():
    print("=== VALIDATE E-FPR ===")
    mal = A.load_mal(4, 31); ben = A.load_benign(4)
    for d in ["none", "dedup_small"]:
        rm = [A.DEF[d](MINI, s) for s in mal]; rb = [A.DEF[d](MINI, s) for s in ben]
        print(f"{d}: mal flags {cnt(rm,'MALICIOUS')}/4  benign flags {cnt(rb,'MALICIOUS')}/4")
    print(f"validate cost ${A.cost():.4f}")

def run():
    with io.open(OUT, "w", encoding="utf-8") as fp:
        W = lambda *a: print(*a, file=fp) or fp.flush()
        W("# E-FPR: 대규모 정상 오탐율 + 유병률 보정 정밀도")
        W("TPR=악성 재현율, FPR=정상 오탐율. 정밀도@π = π·TPR / (π·TPR + (1-π)·FPR). temp 0.\n")
        for model, nmal, nben in [(MINI, 400, 1500), (BIG, 100, 120)]:
            mal = A.load_mal(nmal, 31); ben = A.load_benign(nben)
            W(f"## {model} (악성 {len(mal)}, 정상 {len(ben)})")
            W("| 방어 | TPR(재현율) | FPR(오탐) | 정밀도@1% | @0.1% | @0.01% |")
            W("|---|---|---|---|---|---|")
            for d in ["none", "dedup_small"]:
                tpr, fpr, rv, fv = measure(model, mal, ben, d)
                W(f"| {d} | {fmt(cnt(rv,'MALICIOUS'),len(mal))} | {fmt(cnt(fv,'MALICIOUS'),len(ben))} | "
                  f"{prec(tpr,fpr,0.01):.3f} | {prec(tpr,fpr,0.001):.3f} | {prec(tpr,fpr,0.0001):.4f} |")
            fp.flush()
        W("\n비교: 학습형 TF-IDF 탐지기는 유병률 0.1%에서 정밀도 ~1%(0.011). 위 수치를 그 옆에 둘 것.")
        W(f"\n---\n**대략 비용 ${A.cost():.3f}**")
    print(f"done -> {OUT} | cost ${A.cost():.3f}")

if __name__ == "__main__":
    if not A.KEY: print("NO KEY"); sys.exit(1)
    (rehearse if (len(sys.argv) > 1 and sys.argv[1] == "rehearse") else run)()
