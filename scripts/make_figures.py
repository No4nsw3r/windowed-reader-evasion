"""Regenerate paper figures from VERIFIED numbers (research_notes/v2_main/verified_numbers.md).
All values are team-lead-recomputed from per-item CSVs. No API, deterministic.
  fig_attacks : attack success rate by channel x model (dilution=EXP-DIL, truncation=EXP-STATS, neutral=filler-only control)
  fig_defense : dense small-window defense (dedup_small) recovers dilution AND truncation; rejudge recall-loss floor marked
  fig_dose    : dose-response (mini) - undefended climbs with filler, dedup_small stays flat
"""
import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt
import numpy as np

OUT = r".\reports"
plt.rcParams.update({"font.size": 9.5, "font.family": "DejaVu Sans", "axes.titlesize": 10.5,
                     "figure.dpi": 120, "savefig.bbox": "tight"})
C_NEUTRAL, C_DIL, C_TRUNC = "#8a8f98", "#d1495b", "#3a7ca5"
C_NONE, C_DEDUP = "#d1495b", "#2a9d8f"
GRID = "#d8dce0"

def style(ax):
    for s in ("top", "right"):
        ax.spines[s].set_visible(False)
    ax.yaxis.grid(True, color=GRID, lw=0.8); ax.set_axisbelow(True)

def labels(ax, rects, fmt="%.2f"):
    for r in rects:
        h = r.get_height()
        ax.annotate(fmt % h, (r.get_x() + r.get_width()/2, h), xytext=(0, 2),
                    textcoords="offset points", ha="center", va="bottom", fontsize=7.5)

# ---------------- fig_attacks: ASR by channel x model ----------------
# verified: neutral(f_only/none) mini 0.018 gpt-4o 0.000 ; dilution(d_real/none) mini 0.739 gpt-4o 0.190 ;
#           truncation(none) mini 1.000 gpt-4o 1.000
models = ["gpt-4o-mini", "gpt-4o"]
series = [("Neutral (filler-only control)", [0.018, 0.000], C_NEUTRAL),
          ("Dilution (contiguous)",         [0.739, 0.190], C_DIL),
          ("Truncation",                    [1.000, 1.000], C_TRUNC)]
x = np.arange(len(models)); w = 0.26
fig, ax = plt.subplots(figsize=(5.4, 3.0))
for i, (name, vals, col) in enumerate(series):
    r = ax.bar(x + (i - 1) * w, vals, w, label=name, color=col, edgecolor="white", linewidth=0.6)
    labels(ax, r)
style(ax); ax.set_xticks(x); ax.set_xticklabels(models); ax.set_ylim(0, 1.12)
ax.set_ylabel("Attack success rate (ASR)")
ax.set_title("Evasion attacks defeat the single-pass judge")
ax.legend(frameon=False, ncol=1, fontsize=7.6, loc="upper center", bbox_to_anchor=(0.5, -0.12))
fig.savefig(f"{OUT}/fig_attacks.pdf"); fig.savefig(f"{OUT}/fig_attacks.png", dpi=200); plt.close(fig)

# ---------------- fig_defense: dedup_small recovers both attacks (mini) ----------------
# verified (mini): dilution none 0.739 -> dedup_small 0.230 ; truncation none 1.000 -> dedup_small 0.189 ;
#                  rejudge recall-loss floor (dedup_small) 0.091
attacks = ["Dilution", "Truncation"]
none_v = [0.739, 1.000]; dedup_v = [0.230, 0.189]; floor = 0.091
x = np.arange(len(attacks)); w = 0.34
fig, ax = plt.subplots(figsize=(5.0, 3.0))
r1 = ax.bar(x - w/2, none_v, w, label="No defense (single pass)", color=C_NONE, edgecolor="white", linewidth=0.6)
r2 = ax.bar(x + w/2, dedup_v, w, label="Dense small-window (dedup_small)", color=C_DEDUP, edgecolor="white", linewidth=0.6)
labels(ax, r1); labels(ax, r2)
ax.axhline(floor, ls="--", lw=1.1, color="#555")
ax.annotate(f"rejudge recall-loss floor {floor:.3f}", (len(attacks)-1, floor), xytext=(0, 4),
            textcoords="offset points", ha="right", va="bottom", fontsize=7.3, color="#555")
style(ax); ax.set_xticks(x); ax.set_xticklabels(attacks); ax.set_ylim(0, 1.12)
ax.set_ylabel("Attack success rate (ASR)")
ax.set_title("One perception-control defense recovers both attacks (gpt-4o-mini)")
ax.legend(frameon=False, ncol=1, fontsize=7.6, loc="upper center", bbox_to_anchor=(0.5, -0.12))
fig.savefig(f"{OUT}/fig_defense.pdf"); fig.savefig(f"{OUT}/fig_defense.png", dpi=200); plt.close(fig)

# ---------------- fig_dose: dose-response (mini) ----------------
doses = [0, 1000, 2000, 4000, 8000]
none_d  = [0.00, 0.38, 0.61, 0.73, 0.83]
big_d   = [0.00, 0.38, 0.61, 0.75, 0.45]
small_d = [0.03, 0.20, 0.23, 0.18, 0.23]
dedup_d = [0.13, 0.22, 0.20, 0.18, 0.25]
fig, ax = plt.subplots(figsize=(5.2, 3.0))
ax.plot(doses, none_d,  "-o", color=C_NONE,  lw=2, ms=5, label="No defense")
ax.plot(doses, big_d,   "-s", color="#b08968", lw=1.6, ms=4, label="big_chunk (6000)")
ax.plot(doses, small_d, "-^", color="#5e81ac", lw=1.6, ms=4, label="small_chunk (2500)")
ax.plot(doses, dedup_d, "-D", color=C_DEDUP, lw=2, ms=5, label="dedup_small")
style(ax); ax.set_ylim(0, 0.95)
ax.set_xlabel("Benign filler added (characters)"); ax.set_ylabel("Attack success rate (ASR)")
ax.set_title("Dose-response: dedup_small stays flat as dilution grows (gpt-4o-mini)")
ax.legend(frameon=False, fontsize=7.6, loc="upper left")
fig.savefig(f"{OUT}/fig_dose.pdf"); fig.savefig(f"{OUT}/fig_dose.png", dpi=200); plt.close(fig)

print("wrote fig_attacks, fig_defense, fig_dose (.pdf/.png) from verified numbers")
