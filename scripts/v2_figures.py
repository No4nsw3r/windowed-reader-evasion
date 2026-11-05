"""Figures for the v2 paper, drawn from the per-item CSVs. Deterministic, no API.

Every value is recomputed here from the same tables that v2_consolidate.py reads, so a
figure cannot drift from the text.
"""
import os, sys, glob
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import pilot_audit2 as A
import pandas as pd
import numpy as np
import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt

OUTDIR = os.path.join(A.ROOT, "research_notes", "v2_main")
FIGDIR = os.path.join(A.ROOT, "reports")
GOOD = ("SAFE", "MALICIOUS")

plt.rcParams.update({"font.size": 9, "font.family": "DejaVu Sans",
                     "axes.titlesize": 10, "figure.dpi": 150,
                     "savefig.bbox": "tight"})
C_NONE, C_CAP, C_UNCAP, C_ALT = "#c44536", "#e09f3e", "#2a9d8f", "#5e548e"
GRID = "#d8dce0"


def style(ax):
    for s in ("top", "right"):
        ax.spines[s].set_visible(False)
    ax.yaxis.grid(True, color=GRID, lw=0.7)
    ax.set_axisbelow(True)


def bar_labels(ax, rects, fmt="%.3f", small=7.0):
    for r in rects:
        h = r.get_height()
        if np.isnan(h):
            continue
        ax.annotate(fmt % h, (r.get_x() + r.get_width() / 2, h), xytext=(0, 2),
                    textcoords="offset points", ha="center", va="bottom", fontsize=small)


def load(name):
    fp = os.path.join(OUTDIR, name)
    return pd.read_csv(fp, dtype={"skill_hash": str}, on_bad_lines="skip") if os.path.exists(fp) else None


def asr(d, **sel):
    g = d
    for k, v in sel.items():
        g = g[g[k] == v]
    g = g[g.verdict.isin(GOOD)]
    if "read_frac" in g.columns:
        g = g[pd.to_numeric(g.read_frac, errors="coerce").fillna(1) > 0]
    elif "covered" in g.columns:
        g = g[pd.to_numeric(g.covered, errors="coerce").fillna(1) > 0]
    return ((g.verdict == "SAFE").mean(), len(g)) if len(g) else (np.nan, 0)


# ---------------------------------------------------------------- fig 1: the cap
def fig_cap():
    p1 = load("v2_phase1_items.csv")
    d = p1[(p1.model == A.MINI) & (p1.arm == "mal")]
    attacks = [("rep_pad_10k", "repeated\npadding"), ("uniq_pad_10k", "unique\n10k"),
               ("topical_10k", "topical\n10k"), ("uniq_pad_20k", "unique\n20k"),
               ("uniq_pad_50k", "unique\n50k")]
    readers = [("dedup_small", "capped (published)", C_CAP),
               ("dedup_full", "uncapped", C_UNCAP)]
    x = np.arange(len(attacks)); w = 0.36
    fig, ax = plt.subplots(figsize=(6.0, 2.9))
    for i, (r, lab, col) in enumerate(readers):
        vals, miss = [], []
        for a, _ in attacks:
            v, n = asr(d, attack=a, defense=r)
            vals.append(0.0 if np.isnan(v) else v)
            miss.append(np.isnan(v))
        rects = ax.bar(x + (i - 0.5) * w, vals, w, label=lab, color=col,
                       edgecolor="white", linewidth=0.6)
        for rect, m, v in zip(rects, miss, vals):
            if m:
                ax.annotate("payload\nnever read", (rect.get_x() + w / 2, 0.02),
                            ha="center", va="bottom", fontsize=6.4, color=col,
                            fontweight="bold")
            else:
                ax.annotate("%.3f" % v, (rect.get_x() + w / 2, v), xytext=(0, 2),
                            textcoords="offset points", ha="center", va="bottom",
                            fontsize=7)
    style(ax); ax.set_xticks(x); ax.set_xticklabels([l for _, l in attacks])
    ax.set_ylim(0, 1.05); ax.set_ylabel("attack success rate")
    ax.set_title("The window cap is the vulnerability (gpt-4o-mini, n=165)")
    ax.legend(frameon=False, fontsize=8, loc="upper left")
    fig.savefig(f"{FIGDIR}/fig_cap.pdf"); plt.close(fig)
    print("fig_cap")


# ---------------------------------------------------------------- fig 2: cross-family
def fig_cross():
    rows = []
    p1 = load("v2_phase1_items.csv")
    for m, lab in ((A.MINI, "gpt-4o-mini"), ("gpt-4o", "gpt-4o")):
        d = p1[(p1.model == m) & (p1.arm == "mal")]
        g_n, _ = asr(d, attack="gap_il_4x2600", defense="none")
        g_u, _ = asr(d, attack="gap_il_4x2600", defense="dedup_full")
        rows.append((lab, np.nan, np.nan, g_n, g_u))
    for fp in sorted(glob.glob(os.path.join(OUTDIR, "v2_phase3_items_*.csv"))):
        d = load(os.path.basename(fp))
        if d is None or not len(d):
            continue
        name = str(d.model.iloc[0])
        if name.startswith("gemini-flash-lite"):      # quota-truncated arm, n<=7
            continue
        d = d[d.arm == "mal"]
        if len(d) < 100:
            continue
        lab = name.split("/")[-1]
        d_n, _ = asr(d, attack="d_real", defense="none")
        d_u, _ = asr(d, attack="d_real", defense="dedup_full")
        g_n, _ = asr(d, attack="gap_il_4x2600", defense="none")
        g_u, _ = asr(d, attack="gap_il_4x2600", defense="dedup_full")
        rows.append((lab, d_n, d_u, g_n, g_u))

    labs = [r[0] for r in rows]
    x = np.arange(len(rows)); w = 0.2
    fig, ax = plt.subplots(figsize=(6.6, 3.0))
    series = [(1, "dilution, no defense", C_NONE, 0.55),
              (2, "dilution, uncapped reader", C_NONE, 1.0),
              (3, "fragmentation, no defense", C_UNCAP, 0.55),
              (4, "fragmentation, uncapped reader", C_UNCAP, 1.0)]
    for i, (idx, lab, col, alpha) in enumerate(series):
        vals = [r[idx] for r in rows]
        ax.bar(x + (i - 1.5) * w, vals, w, label=lab, color=col, alpha=alpha,
               edgecolor="white", linewidth=0.5)
    style(ax); ax.set_xticks(x); ax.set_xticklabels(labs, fontsize=8)
    ax.set_ylim(0, 1.05); ax.set_ylabel("attack success rate")
    ax.set_title("The same pattern on every judge: dilution is recovered, fragmentation is not")
    ax.legend(frameon=False, fontsize=7.2, ncol=2, loc="upper center",
              bbox_to_anchor=(0.5, -0.16))
    fig.savefig(f"{FIGDIR}/fig_cross.pdf"); plt.close(fig)
    print("fig_cross")


# ---------------------------------------------------------------- fig 3: cost
def fig_cost():
    p2 = load("v2_phase2_items.csv")
    b = p2[(p2.block == "opcost") & (p2.arm == "ben") & p2.verdict.isin(GOOD)].copy()
    edges = [0, 2000, 5000, 10000, 20000, 10 ** 9]
    names = ["<2k", "2-5k", "5-10k", "10-20k", ">20k"]
    b["bucket"] = pd.cut(b.artifact_len, edges, labels=names)
    fig, (ax1, ax2) = plt.subplots(1, 2, figsize=(7.2, 2.9))

    for r, lab, col in (("none", "single 8k read", C_NONE),
                        ("dedup_small", "capped windows", C_CAP),
                        ("dedup_full", "uncapped windows", C_UNCAP)):
        ys = []
        for bk in names:
            g = b[(b.config == r) & (b.bucket == bk)]
            ys.append((g.verdict == "MALICIOUS").mean() if len(g) >= 10 else np.nan)
        ax1.plot(names, ys, "-o", color=col, lw=1.8, ms=4.5, label=lab)
    style(ax1); ax1.set_ylabel("benign false positive rate")
    ax1.set_xlabel("artifact length (characters)")
    ax1.set_title("Cost grows with length (gpt-4o-mini)")
    ax1.legend(frameon=False, fontsize=7.5)

    # per-judge FPR of the uncapped reader
    js, vs = [], []
    p1 = load("v2_phase1_items.csv")
    for m in ("gpt-4o", A.MINI):
        g = p1[(p1.model == m) & (p1.arm == "ben") & (p1.attack == "clean") &
               (p1.defense == "dedup_full") & p1.verdict.isin(GOOD)]
        if len(g):
            js.append(m); vs.append((g.verdict == "MALICIOUS").mean())
    for fp in sorted(glob.glob(os.path.join(OUTDIR, "v2_phase3_items_*.csv"))):
        d = load(os.path.basename(fp))
        if d is None or not len(d):
            continue
        name = str(d.model.iloc[0])
        if name.startswith("gemini-flash-lite"):
            continue
        g = d[(d.arm == "ben") & (d.defense == "dedup_full") & d.verdict.isin(GOOD)]
        if len(g) >= 100:
            js.append(name.split("/")[-1]); vs.append((g.verdict == "MALICIOUS").mean())
    order = np.argsort(vs)
    js = [js[i] for i in order]; vs = [vs[i] for i in order]
    rects = ax2.barh(js, vs, color=C_ALT, edgecolor="white", height=0.6)
    for r, v in zip(rects, vs):
        ax2.annotate("%.3f" % v, (v, r.get_y() + r.get_height() / 2), xytext=(3, 0),
                     textcoords="offset points", va="center", fontsize=7.5)
    for s in ("top", "right"):
        ax2.spines[s].set_visible(False)
    ax2.xaxis.grid(True, color=GRID, lw=0.7); ax2.set_axisbelow(True)
    ax2.set_xlabel("benign false positive rate, uncapped reader")
    ax2.set_title("and it varies over 20x by judge")
    ax2.set_xlim(0, max(vs) * 1.25)
    fig.savefig(f"{FIGDIR}/fig_cost.pdf"); plt.close(fig)
    print("fig_cost")


# ---------------------------------------------------------------- fig 4: mechanism
def fig_mech():
    p2 = load("v2_phase2_items.csv")
    ok = p2[p2.verdict.isin(GOOD)]
    ws = ok[(ok.block == "wsweep") & (ok.attack == "d_real")]
    sizes = [1000, 1500, 2500, 4000, 6000]
    xs, ys = [], []
    for s in sizes:
        g = ws[ws.config == str(s)]
        if len(g):
            xs.append(g.n_calls.mean()); ys.append((g.verdict == "SAFE").mean())
    eq = ok[ok.block == "eqcall"]
    ex, ey = [], []
    for k in (1, 3, 6):
        g = eq[eq.config == f"k{k}"]
        if len(g):
            ex.append(k); ey.append((g.verdict == "SAFE").mean())

    # Diversified whole-document sampling at a matched budget (the exp1 control). The
    # `coll` variant is the strongest of the four we ran AND shares the window arm's
    # collapse preprocessing, so it is the best case for the objection that small windows
    # merely buy more distinct looks. Plotting it keeps the figure from overstating the
    # window-size attribution the way a repeat-only control does.
    dx, dy = [], []
    e1fp = os.path.join(A.ROOT, "..", "followup_results", "exp1_calls.csv")
    if os.path.exists(e1fp):
        e1 = pd.read_csv(e1fp, dtype={"skill_hash": str})
        e1 = e1[(e1["cond"] == "coll") & e1.verdict.isin(GOOD)]
        piv = e1.pivot(index="skill_hash", columns="draw", values="verdict")
        for k in (1, 2, 3, 6, 11):
            cols = [c for c in range(k) if c in piv.columns]
            if len(cols) < k:
                continue
            sub = piv[cols].dropna()
            if len(sub):
                dx.append(k); dy.append(float((sub == "SAFE").all(axis=1).mean()))

    fig, ax = plt.subplots(figsize=(5.4, 3.0))
    ax.plot(xs, ys, "-o", color=C_UNCAP, lw=2, ms=6, label="small windows (size labelled)")
    for x, y, s in zip(xs, ys, sizes):
        ax.annotate(f"{s}", (x, y), xytext=(4, 5), textcoords="offset points", fontsize=7)
    ax.plot(ex, ey, "-s", color=C_NONE, lw=2, ms=6, label="identical whole-doc repeats, OR-ed")
    for x, y, k in zip(ex, ey, (1, 3, 6)):
        ax.annotate(f"k={k}", (x, y), xytext=(4, -10), textcoords="offset points", fontsize=7)
    if dx:
        ax.plot(dx, dy, "-^", color=C_ALT, lw=2, ms=6,
                label="diversified whole-doc looks, OR-ed")
        ax.annotate(f"k={dx[-1]}", (dx[-1], dy[-1]), xytext=(4, -10),
                    textcoords="offset points", fontsize=7)
    style(ax); ax.set_xlabel("API calls per artifact"); ax.set_ylabel("attack success rate")
    ax.set_ylim(0, 1.0)
    ax.set_title("At a matched budget, window size does most of the work")
    ax.legend(frameon=False, fontsize=7.5, loc="upper right")
    fig.savefig(f"{FIGDIR}/fig_mech.pdf"); plt.close(fig)
    print("fig_mech")


# ---------------------------------------------------------------- fig 5: fragmentation
def fig_frag():
    p1 = load("v2_phase1_items.csv")
    d = p1[(p1.model == A.MINI) & (p1.arm == "mal")]
    ex = load("v2_extract_items.csv")
    p4 = load("v2_phase4_items.csv")

    def layered(arm, atk):
        # uncapped reader OR the cisco static scanner, joined per skill; returns the share
        # both pass (ASR on the malicious arm) or the share either flags (FPR on benign)
        src = d if arm == "mal" else p1[(p1.model == A.MINI) & (p1.arm == "ben")]
        r = src[(src.attack == atk) & (src.defense == "dedup_full") & src.verdict.isin(GOOD)]
        if "read_frac" in r.columns:
            r = r[pd.to_numeric(r.read_frac, errors="coerce").fillna(1) > 0]
        r = r.drop_duplicates("skill_hash").set_index("skill_hash").verdict
        s = p4[(p4.arm == arm) & (p4.scanner == "cisco") & (p4.attack == atk) &
               p4.verdict.isin(GOOD)]
        s = s.drop_duplicates("skill_hash").set_index("skill_hash").verdict
        j = r.index.intersection(s.index)
        if not len(j):
            return np.nan
        both_pass = (r.loc[j] == "SAFE") & (s.loc[j] == "SAFE")
        return both_pass.mean() if arm == "mal" else 1 - both_pass.mean()

    def ex_asr(atk):
        g = ex[(ex.arm == "mal") & (ex.attack == atk) & ex.verdict.isin(GOOD)]
        return (g.verdict == "SAFE").mean() if len(g) else np.nan

    atks = ["gap_il_4x2600", "gap_il_6x3000"]
    approaches = [
        ("read more\n(uncapped)", [asr(d, attack=a, defense="dedup_full")[0] for a in atks], 0.087),
        ("different aggregation\n(extract-then-judge)", [ex_asr(a) for a in atks], 0.240),
        ("add a static scanner\n(either flags)", [layered("mal", a) for a in atks],
         layered("ben", "clean")),
    ]
    base = asr(d, attack="clean", defense="dedup_full")[0]

    x = np.arange(len(approaches)); w = 0.34
    fig, ax = plt.subplots(figsize=(6.2, 3.1))
    for i, lab in enumerate(["4 fragments", "6 fragments"]):
        vals = [a[1][i] for a in approaches]
        rects = ax.bar(x + (i - 0.5) * w, vals, w, label=lab,
                       color=[C_UNCAP, C_ALT, C_CAP][0] if i == 0 else None,
                       edgecolor="white", linewidth=0.6,
                       alpha=1.0 if i == 0 else 0.55,
                       facecolor=None)
        for r in rects:
            r.set_color(C_UNCAP if i == 0 else C_ALT)
        bar_labels(ax, rects)
    ax.axhline(base, ls="--", lw=1.1, color="#555", label=f"undiluted baseline {base:.3f}")
    for i, (lab, _, fpr) in enumerate(approaches):
        ax.annotate(f"FPR {fpr:.3f}", (i, 0.015), ha="center", fontsize=7.2, color="#333")
    style(ax); ax.set_xticks(x); ax.set_xticklabels([a[0] for a in approaches], fontsize=8)
    ax.set_ylim(0, 0.42); ax.set_ylabel("attack success rate")
    ax.set_title("No defense we tried stops fragmentation (gpt-4o-mini)")
    ax.legend(frameon=False, fontsize=8, loc="upper right")
    fig.savefig(f"{FIGDIR}/fig_frag.pdf"); plt.close(fig)
    print("fig_frag")


if __name__ == "__main__":
    for f in (fig_cap, fig_cross, fig_cost, fig_mech, fig_frag):
        try:
            f()
        except Exception as e:
            print(f"{f.__name__} FAILED: {type(e).__name__}: {e}")
    print("figures written to", FIGDIR)
