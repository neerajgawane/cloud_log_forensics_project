"""Turn results/*.json into the paper's figures (figures/*.png) and tables (results/tables.md)."""
import json
import os
import sys

import numpy as np
import pandas as pd
import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt  # noqa: E402

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
RES, FIG = os.path.join(ROOT, "results"), os.path.join(ROOT, "figures")
os.makedirs(FIG, exist_ok=True)

ACCENT = "#2563eb"
GREY = "#9aa3ad"
DARK = "#374151"
GOOD, BAD = "#16a34a", "#dc2626"
plt.rcParams.update({"font.family": "DejaVu Sans", "font.size": 10.5, "axes.spines.top": False,
                     "axes.spines.right": False, "axes.edgecolor": "#c4c9cf", "axes.labelcolor": DARK,
                     "xtick.color": DARK, "ytick.color": DARK, "axes.titleweight": "bold",
                     "axes.titlesize": 12, "axes.titlelocation": "left", "figure.dpi": 150,
                     "savefig.bbox": "tight", "legend.frameon": False})


def load(n):
    p = os.path.join(RES, n + ".json")
    return json.load(open(p)) if os.path.exists(p) else None


def save(fig, name):
    fig.savefig(os.path.join(FIG, name + ".png"), dpi=200)
    plt.close(fig)
    print("fig", name)


def fig_integrity(e1):
    schemes = ["plain", "hmac", "chain", "sealed"]
    names = {"plain": "SHA-256 per record", "hmac": "HMAC per record", "chain": "HMAC hash chain",
             "sealed": "Chain + sealed WORM\ncheckpoints (ours)"}
    attacks = ["modify", "insert", "delete", "reorder", "truncate"]
    M = np.array([[e1["detection"][s][a] for a in attacks] for s in schemes])
    fig, ax = plt.subplots(figsize=(7.2, 3.1))
    from matplotlib.colors import LinearSegmentedColormap
    cmap = LinearSegmentedColormap.from_list("g", ["#f3f4f6", ACCENT])
    ax.imshow(M, cmap=cmap, vmin=0, vmax=1, aspect="auto")
    for i in range(len(schemes)):
        for j in range(len(attacks)):
            ax.text(j, i, f"{M[i, j]*100:.0f}%", ha="center", va="center",
                    color="white" if M[i, j] > 0.5 else DARK, fontsize=10.5, fontweight="bold")
    ax.set_xticks(range(len(attacks)), [a.capitalize() for a in attacks])
    ax.set_yticks(range(len(schemes)), [names[s] for s in schemes])
    ax.tick_params(length=0)
    for s in ax.spines.values():
        s.set_visible(False)
    ax.set_title("Only the sealed hash chain detects all five insider tampering attacks")
    ax.set_xlabel(f"Tampering action ({e1['trials']} random trials each, attacker lacks the key)")
    save(fig, "fig2_integrity")

    fig, ax = plt.subplots(figsize=(6.4, 3.2))
    shades = {"10": 1.0, "100": 0.65, "1000": 0.35}
    for every, rows in e1["truncation"].items():
        ks = [r["k"] for r in rows]
        ax.plot(ks, [r["detect"] * 100 for r in rows], marker="o", color=ACCENT, alpha=shades[every],
                label=f"checkpoint every {every} records", lw=2)
    ax.set_xscale("log")
    ax.set_xlabel("Records truncated from the tail (log scale)")
    ax.set_ylabel("Truncations detected (%)")
    ax.set_ylim(-3, 105)
    ax.set_title("Tail truncation is caught once it crosses a checkpoint")
    ax.legend(loc="lower right")
    save(fig, "fig3_truncation")


def fig_sync(e2):
    df = pd.DataFrame(e2["offset_sweep"])
    g = df.groupby(["max_offset", "method"]).agg(["mean", "std"]).reset_index()
    labels = {"none": "No synchronization", "offset": "Offset only", "drift": "Offset + drift (ours)"}
    styles = {"none": (GREY, 1.0), "offset": (ACCENT, 0.45), "drift": (ACCENT, 1.0)}
    fig, axs = plt.subplots(1, 2, figsize=(9.6, 3.4))
    for m in ("none", "offset", "drift"):
        s = g[g.method == m]
        c, a = styles[m]
        axs[0].errorbar(s.max_offset, s[("mae_s", "mean")], yerr=s[("mae_s", "std")], marker="o", color=c,
                        alpha=a, label=labels[m], lw=2, capsize=2)
        axs[1].errorbar(s.max_offset, s[("pair_order_acc", "mean")] * 100,
                        yerr=s[("pair_order_acc", "std")] * 100, marker="o", color=c, alpha=a, lw=2, capsize=2)
    for ax in axs:
        ax.set_xscale("log")
        ax.set_xlabel("Maximum clock offset per source (s, log scale)")
    axs[0].set_yscale("log")
    axs[0].set_ylabel("Mean |timestamp error| (s, log)")
    axs[0].set_title("Timestamp error")
    axs[1].set_ylabel("Cross-source attack pairs in order (%)")
    axs[1].set_title("Timeline ordering")
    axs[0].legend(loc="upper left", fontsize=9)
    fig.suptitle("Anchor-based synchronization keeps timestamp error near 0.1 s, whatever the skew",
                 x=0.06, ha="left", fontweight="bold", fontsize=12, y=1.04)
    save(fig, "fig4_sync")

    dd = pd.DataFrame(e2["drift_sweep"])
    g2 = dd.groupby(["max_drift_ppm", "method"]).mean(numeric_only=True).reset_index()
    fig, ax = plt.subplots(figsize=(6.4, 3.2))
    for m in ("none", "offset", "drift"):
        s = g2[g2.method == m]
        c, a = styles[m]
        ax.plot(s.max_drift_ppm.astype(str), s.mae_s, marker="o", color=c, alpha=a, lw=2, label=labels[m])
    ax.set_yscale("log")
    ax.set_xlabel("Maximum clock drift per source (ppm), offset ±2 s")
    ax.set_ylabel("Mean |timestamp error| (s, log)")
    ax.set_title("Modelling drift matters once clocks drift > 50 ppm")
    ax.legend(fontsize=9)
    save(fig, "fig5_drift")


def fig_visibility(e3):
    df = pd.DataFrame(e3)
    sub = df[(df.min_score == 2) & ~df.subset.str.startswith("ablation")]
    g = sub.groupby("subset")[["recall_all", "stage_coverage", "precision", "visible_attack_events"]].mean()
    g = g.sort_values(["recall_all", "stage_coverage"])
    fig, ax = plt.subplots(figsize=(8.2, 4.2))
    y = np.arange(len(g))
    ax.barh(y - 0.2, g.recall_all * 100, height=0.38, color=[ACCENT if i == "all six" else GREY for i in g.index],
            label="Attack records recovered (recall)")
    ax.barh(y + 0.2, g.stage_coverage * 100, height=0.38,
            color=[ACCENT if i == "all six" else GREY for i in g.index], alpha=0.45,
            label="Attack stages covered")
    for i, (r, sc) in enumerate(zip(g.recall_all, g.stage_coverage)):
        ax.text(r * 100 + 1, i - 0.2, f"{r*100:.0f}%", va="center", fontsize=8.5, color=DARK)
        ax.text(sc * 100 + 1, i + 0.2, f"{sc*100:.0f}%", va="center", fontsize=8.5, color=DARK)
    ax.set_yticks(y, g.index)
    ax.invert_yaxis()
    ax.set_xlim(0, 112)
    ax.set_xlabel("% (mean of 10 seeds, threshold k = 2)")
    ax.set_title("No single log category reconstructs the intrusion; all six recover 100%")
    ax.legend(loc="upper right", fontsize=9)
    save(fig, "fig6_visibility")


def fig_retention(e4):
    df = pd.DataFrame(e4)
    fig, axs = plt.subplots(1, 2, figsize=(9.6, 3.4))
    d2 = df[df.delay_h == 2]
    circ = d2[d2.strategy == "local_circular"].groupby("capacity")[["recall_all", "stage_coverage"]].mean()
    axs[0].plot(circ.index, circ.recall_all * 100, marker="o", color=GREY, lw=2, label="Local circular buffer")
    for strat, c, ls in (("central_sealed", ACCENT, "-"), ("local_linear", DARK, "--")):
        v = d2[d2.strategy == strat].recall_all.mean() * 100
        axs[0].axhline(v, color=c, ls=ls, lw=1.6,
                       label="Central sealed store (ours)" if strat == "central_sealed" else "Local linear log")
    axs[0].set_xscale("log")
    axs[0].set_xlabel("Circular buffer capacity per source (records)")
    axs[0].set_ylabel("Attack records recovered (%)")
    axs[0].set_title("Investigation starts 2 h after the attack")
    axs[0].legend(fontsize=8.5, loc="center right")
    for cap, alpha in ((5000, 0.35), (20000, 0.65)):
        s = df[(df.strategy == "local_circular") & (df.capacity == cap)].groupby("delay_h").recall_all.mean()
        axs[1].plot(s.index, s * 100, marker="o", color=GREY, alpha=0.4 + alpha / 2, lw=2,
                    label=f"Circular, {cap:,} records")
    s = df[df.strategy == "central_sealed"].groupby("delay_h").recall_all.mean()
    axs[1].plot(s.index, s * 100, marker="o", color=ACCENT, lw=2, label="Central sealed store (ours)")
    axs[1].set_xlabel("Investigation delay after attack ends (h)")
    axs[1].set_title("Evidence decays with delay in circular logs")
    axs[1].legend(fontsize=8.5)
    for ax in axs:
        ax.set_ylim(-3, 105)
    fig.suptitle("Circular logging loses evidence; anti-forensic wipes defeat host-local logs",
                 x=0.06, ha="left", fontweight="bold", fontsize=12, y=1.04)
    save(fig, "fig7_retention")


def fig_scale(e6):
    df = pd.DataFrame(e6)
    stages = ["preserve", "collect_normalize", "synchronize", "detect", "correlate"]
    names = ["Preserve (HMAC chain)", "Collect + normalize", "Synchronize", "Detect", "Correlate"]
    fig, ax = plt.subplots(figsize=(7.0, 3.4))
    bottom = np.zeros(len(df))
    x = np.arange(len(df))
    shades = [0.95, 0.75, 0.55, 0.38, 0.22]
    for st, nm, a in zip(stages, names, shades):
        ax.bar(x, df[st], bottom=bottom, color=ACCENT, alpha=a, width=0.6, label=nm, edgecolor="white")
        bottom += df[st].to_numpy()
    for i, (tot, n) in enumerate(zip(bottom, df.events)):
        ax.text(i, tot + bottom.max() * 0.02, f"{tot:.1f} s\n{n/tot/1000:.0f}k rec/s", ha="center", fontsize=8.5)
    ax.set_xticks(x, [f"{n/1000:.0f}k" for n in df.events])
    ax.set_xlabel("Records in case (4-hour window)")
    ax.set_ylabel("Wall-clock time (s)")
    ax.set_ylim(0, bottom.max() * 1.25)
    ax.set_title("Processing time grows linearly with log volume")
    ax.legend(fontsize=8.5, loc="upper left")
    save(fig, "fig8_scale")


if __name__ == "__main__":
    e1, e2, e3, e4, e6 = (load(n) for n in ("e1_integrity", "e2_sync", "e3_visibility", "e4_retention", "e6_scale"))
    if e1: fig_integrity(e1)
    if e2: fig_sync(e2)
    if e3: fig_visibility(e3)
    if e4: fig_retention(e4)
    if e6: fig_scale(e6)
