#!/usr/bin/env python3
"""RaceProof figures, regenerated from results/*.csv.

    python3 analysis/plots.py                 # run 1: results/{uncontrolled,overhead,controlled}.csv
    python3 analysis/plots.py --run run2      # results/run2_{uncontrolled,overhead,controlled}.csv
    python3 analysis/plots.py --run run2 --overhead results/run2b_overhead.csv   # per-file override
    python3 analysis/plots.py --run run2 --overhead results/run2b_overhead.csv --overhead-fast results/run3b_openssl_overhead.csv
    python3 analysis/plots.py --results results --out report/figures

Each figure carries a footer naming the CSV files it was drawn from.

Figure 1  mismatch rate vs check-to-launch gap, one line per policy, panel per attack (uncontrolled)
Figure 2  launch time vs executable size, median with a whisker to p99, one line per policy (overhead);
          a second row of panels when a fast-hash overhead file is given (--overhead-fast)
Figure 3  sealed-copy policy under free timing: torn, rejected and mismatched launches vs size,
          panel per load, tail-rewrite attack (uncontrolled), with the barrier-controlled mid-tear
          rate as the reference line
Table     full outcome breakdown per policy and attack under free timing with CPU stress

Colors follow the policy, never its rank: path blue, fd orange, sealed aqua. Rates carry
Wilson 95% intervals as whiskers. Memory cost is bytes copied, not RSS.
"""
import argparse
import csv
import math
import statistics
from collections import defaultdict
from pathlib import Path

import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt  # noqa: E402

POLICY_COLOR = {"path": "#2a78d6", "fd": "#eb6834", "sealed": "#1baf7a"}
POLICY_LABEL = {"path": "pathname", "fd": "open descriptor", "sealed": "sealed copy"}
OUTCOME_COLOR = {"torn": "#6250d6", "REJECT": "#eda100", "MISMATCH": "#e34948"}
SIZES = ["64k", "1m", "8m", "32m"]
SIZE_BYTES = {"64k": 65536, "1m": 2**20, "8m": 2**23, "32m": 2**25}
GAP_ORDER = ["none", "short", "long"]
INK, MUTED, GRID = "#0b0b0b", "#898781", "#e1e0d9"

plt.rcParams.update({
    "font.size": 10, "axes.edgecolor": "#c3c2b7", "axes.labelcolor": INK, "xtick.color": MUTED,
    "ytick.color": MUTED, "axes.grid": True, "grid.color": GRID, "grid.linewidth": 0.6,
    "axes.spines.top": False, "axes.spines.right": False, "legend.frameon": False,
    "figure.facecolor": "white", "axes.facecolor": "white",
})


def p99(sorted_vals):
    """Nearest-rank 99th percentile: the ceil(0.99 n)-th smallest value."""
    if not sorted_vals:
        return float("nan")
    return sorted_vals[min(len(sorted_vals) - 1, max(0, math.ceil(0.99 * len(sorted_vals)) - 1))]


def wilson(k, n, z=1.96):
    if n == 0:
        return 0.0, 0.0
    p = k / n
    d = 1 + z * z / n
    c = (p + z * z / (2 * n)) / d
    h = z * math.sqrt(p * (1 - p) / n + z * z / (4 * n * n)) / d
    return max(0.0, c - h), min(1.0, c + h)


def load(path: Path):
    return list(csv.DictReader(open(path, newline=""))) if path.exists() else []


def group(rows, keys):
    g = defaultdict(list)
    for r in rows:
        g[tuple(r[k] for k in keys)].append(r)
    return g


def rate_series(rows, predicate, xs, keyfn):
    """For each x: (rate, lo, hi, n) of rows where keyfn(row)==x."""
    out = []
    for x in xs:
        g = [r for r in rows if keyfn(r) == x]
        n = len(g)
        k = sum(1 for r in g if predicate(r))
        lo, hi = wilson(k, n)
        out.append((k / n if n else float("nan"), lo, hi, n))
    return out


def end_labels(ax, items, min_gap, log=False):
    """Direct labels at the right end of each line, pushed apart so they never overlap.
    items: [(x, y, label)]; min_gap in data units (or as a ratio when log=True)."""
    items = sorted((i for i in items if not math.isnan(i[1])), key=lambda i: i[1])
    placed = []
    for x, y, label in items:
        yy = y
        if placed:
            prev = placed[-1][1]
            if log:
                yy = max(yy, prev * min_gap)
            else:
                yy = max(yy, prev + min_gap)
        placed.append((x, yy, label))
    for x, yy, label in placed:
        ax.annotate(label, (x, yy), xytext=(6, 0), textcoords="offset points", color=INK, fontsize=9, va="center")


def plot_rate_lines(ax, series, xs, xlabels, title):
    """series: list of (label, color, [(rate, lo, hi, n), ...])"""
    xpos = list(range(len(xs)))
    ends = []
    for label, color, pts in series:
        ys = [p[0] for p in pts]
        yerr = [[max(0, p[0] - p[1]) for p in pts], [max(0, p[2] - p[0]) for p in pts]]
        ax.errorbar(xpos, ys, yerr=yerr, color=color, linewidth=2, marker="o", markersize=6,
                    capsize=3, elinewidth=1, label=label)
        if pts:
            ends.append((xpos[-1], pts[-1][0], label))
    end_labels(ax, ends, 0.06)
    ax.set_xticks(xpos, xlabels)
    ax.set_ylim(-0.03, 1.08)
    ax.set_yticks([0, 0.25, 0.5, 0.75, 1.0], ["0%", "25%", "50%", "75%", "100%"])
    ax.set_title(title, loc="left", fontsize=11, color=INK)


def footer(fig, files):
    fig.text(0.99, 0.005, "data: " + ", ".join(f.name for f in files), ha="right", va="bottom",
             fontsize=7, color=MUTED)


def figure1(unc, out, src=()):
    attacks = [("replace", "", "Atomic replacement (rename)"), ("rewrite", "text", "In-place rewrite of .text"),
               ("rewrite", "tail", "In-place rewrite of the tail")]
    attacks = [a for a in attacks if any(r["change"] == a[0] and r["region"] == a[1] for r in unc)]
    if not attacks:
        return
    fig, axes = plt.subplots(1, len(attacks), figsize=(4.6 * len(attacks), 4), sharey=True)
    axes = [axes] if len(attacks) == 1 else list(axes)
    for ax, (change, region, title) in zip(axes, attacks):
        rows = [r for r in unc if r["change"] == change and r["region"] == region and r["load"] == "idle"]
        series = []
        for pol in ("path", "fd", "sealed"):
            pr = [r for r in rows if r["policy"] == pol]
            if pr:
                series.append((POLICY_LABEL[pol], POLICY_COLOR[pol],
                               rate_series(pr, lambda r: r["outcome"] == "MISMATCH", GAP_ORDER, lambda r: r["gap"])))
        plot_rate_lines(ax, series, GAP_ORDER, ["0", "200 µs", "5 ms"], title)
        ax.set_xlabel("inserted check-to-launch gap")
    axes[0].set_ylabel("launches that ran unapproved bytes")
    axes[0].legend(loc="upper left", fontsize=9)
    n = len([r for r in unc if r["load"] == "idle"])
    fig.suptitle(f"Mismatch rate by launch policy under free-timing attack, all sizes pooled, idle, n={n} launches",
                 x=0.01, ha="left", fontsize=12, color=INK)
    fig.tight_layout(rect=(0, 0.02, 1, 0.95))
    footer(fig, src)
    fig.savefig(out / "fig1_mismatch_vs_gap.png", dpi=160)
    plt.close(fig)


def hash_label(rows):
    impl = {r.get("hash_impl", "") for r in rows} - {""}
    if impl == {"openssl-evp"}:
        return "OpenSSL SHA-256 (SHA-NI)"
    if impl == {"vendored-c"} or not impl:
        return "plain-C SHA-256"
    return "/".join(sorted(impl))


def figure2(ovh, out, src=(), fast=None):
    if not ovh:
        return
    datasets = [(hash_label(ovh), ovh)] + ([(hash_label(fast), fast)] if fast else [])
    fig, grid = plt.subplots(len(datasets), 2, figsize=(10, 4.4 * len(datasets)), squeeze=False, sharey=True)
    for (hlabel, rows), axes in zip(datasets, grid):
      for ax, load in zip(axes, ("idle", "stress")):
        ovh = rows
        ends = []
        for pol in ("path", "fd", "sealed"):
            med, tail = [], []
            for s in SIZES:
                t = sorted(int(r["t_total_us"]) for r in ovh if r["policy"] == pol and r["size"] == s
                           and r["load"] == load and r["t_total_us"] not in ("", "-1"))
                if not t:
                    med.append(float("nan")); tail.append(float("nan")); continue
                med.append(statistics.median(t) / 1000)
                tail.append(p99(t) / 1000)
            xs = [SIZE_BYTES[s] for s in SIZES]
            ax.errorbar(xs, med, yerr=[[0] * len(xs), [max(0, b - a) for a, b in zip(med, tail)]],
                        color=POLICY_COLOR[pol], linewidth=2, marker="o", markersize=6, capsize=3,
                        elinewidth=1, label=POLICY_LABEL[pol])
            ends.append((xs[-1], med[-1], POLICY_LABEL[pol]))
        ax.set_xscale("log", base=2)
        ax.set_yscale("log")
        end_labels(ax, ends, 1.25, log=True)
        ax.set_xticks([SIZE_BYTES[s] for s in SIZES], ["64 KiB", "1 MiB", "8 MiB", "32 MiB"])
        ax.set_xlabel("executable size")
        ax.set_title(f"CPU {load}, {hlabel}", loc="left", fontsize=11, color=INK)
      axes[0].set_ylabel("launch time, ms (median, whisker to p99)")
    grid[0][0].legend(loc="upper left", fontsize=9)
    fig.suptitle("Launch time by policy and executable size, no attacker (request to first output byte)",
                 x=0.01, ha="left", fontsize=12, color=INK)
    fig.tight_layout(rect=(0, 0.02, 1, 0.96 if len(datasets) == 1 else 0.975))
    footer(fig, src)
    fig.savefig(out / "fig2_overhead_vs_size.png", dpi=160)
    plt.close(fig)


def figure3(unc, ctl, out, src=()):
    rows = [r for r in unc if r["policy"] == "sealed" and r["change"] == "rewrite" and r["region"] == "tail"]
    if not rows:
        return
    loads = [l for l in ("idle", "stress") if any(r["load"] == l for r in rows)]
    fig, axes = plt.subplots(1, len(loads), figsize=(5 * len(loads), 4.2), sharey=True)
    axes = [axes] if len(loads) == 1 else list(axes)
    for ax, load in zip(axes, loads):
        lr = [r for r in rows if r["load"] == load]
        series = [
            ("torn copies", OUTCOME_COLOR["torn"], rate_series(lr, lambda r: r["torn"] == "1", SIZES, lambda r: r["size"])),
            ("rejected", OUTCOME_COLOR["REJECT"], rate_series(lr, lambda r: r["outcome"] == "REJECT", SIZES, lambda r: r["size"])),
            ("ran unapproved bytes", OUTCOME_COLOR["MISMATCH"], rate_series(lr, lambda r: r["outcome"] == "MISMATCH", SIZES, lambda r: r["size"])),
        ]
        plot_rate_lines(ax, series, SIZES, ["64 KiB", "1 MiB", "8 MiB", "32 MiB"], f"CPU {load}, n={len(lr)}")
        # reference: barrier-controlled tear inside the tail region
        cref = [r for r in ctl if r["policy"] == "sealed" and r["stage"] == "mid_copy" and r["region"] == "tail"
                and r["tear"] == "mid" and r["load"] == load]
        if cref:
            k = sum(1 for r in cref if r["torn"] == "1")
            ax.axhline(k / len(cref), color=MUTED, linestyle="--", linewidth=1)
            ax.annotate(f"controlled mid-tail tear: {k}/{len(cref)} torn, all rejected", (0, k / len(cref)),
                        xytext=(4, 4), textcoords="offset points", color=MUTED, fontsize=8)
        ax.set_xlabel("executable size")
    axes[0].set_ylabel("share of launches")
    axes[0].legend(loc="upper center", bbox_to_anchor=(0.5, -0.18), ncol=3, fontsize=9)
    fig.suptitle("Sealed-copy policy under a free-timing tail rewrite: what happens to the copy",
                 x=0.01, ha="left", fontsize=12, color=INK)
    fig.tight_layout(rect=(0, 0.07, 1, 0.95))
    footer(fig, src)
    fig.savefig(out / "fig3_sealed_torn_vs_size.png", dpi=160)
    plt.close(fig)


def outcome_table(unc, out, src=None):
    rows = [r for r in unc if r["load"] == "stress"] or unc
    if not rows:
        return
    lines = ["| Policy | Attack | n | CORRECT | MISMATCH | REJECT | EXEC_ERROR | HARNESS_ERROR | torn | mismatch rate (95% CI) |",
             "| --- | --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: | --- |"]
    for pol in ("path", "fd", "sealed"):
        for change, region in (("replace", ""), ("rewrite", "text"), ("rewrite", "tail")):
            g = [r for r in rows if r["policy"] == pol and r["change"] == change and r["region"] == region]
            if not g:
                continue
            n = len(g)
            c = {o: sum(1 for r in g if r["outcome"] == o) for o in ("CORRECT", "MISMATCH", "REJECT", "EXEC_ERROR", "HARNESS_ERROR")}
            torn = sum(1 for r in g if r["torn"] == "1")
            lo, hi = wilson(c["MISMATCH"], n)
            attack = "replace" if change == "replace" else f"rewrite {region}"
            lines.append(f"| {POLICY_LABEL[pol]} | {attack} | {n} | {c['CORRECT']} | {c['MISMATCH']} | {c['REJECT']} | "
                         f"{c['EXEC_ERROR']} | {c['HARNESS_ERROR']} | {torn} | {100*c['MISMATCH']/n:.2f}% ({100*lo:.2f}-{100*hi:.2f}) |")
    load = "CPU stress" if any(r["load"] == "stress" for r in rows) else "idle"
    srcline = f" Data: `{src.name}`." if src else ""
    (out / "table_outcomes.md").write_text(
        f"Outcomes per policy and attack under free timing, {load}, all sizes and gaps pooled.{srcline}\n\n" + "\n".join(lines) + "\n")


def overhead_table(ovh, out, src=None, fast=None, fast_src=None):
    if not ovh:
        return
    lines = ["| Hash | Policy | Size | Load | n | hash median ms | copy median ms | total median ms | total p99 ms | copy share | bytes copied |",
             "| --- | --- | --- | --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: |"]
    datasets = [ovh] + ([fast] if fast else [])
    for rows in datasets:
        hl = hash_label(rows)
        for load in ("idle", "stress"):
            for s in SIZES:
                for pol in ("path", "fd", "sealed"):
                    g = [r for r in rows if r["policy"] == pol and r["size"] == s and r["load"] == load]
                    if not g:
                        continue
                    t = sorted(int(r["t_total_us"]) for r in g if r["t_total_us"] not in ("", "-1"))
                    chk = statistics.median(int(r["t_check_us"]) for r in g)
                    cp = statistics.median(int(r["t_copy_us"]) for r in g)
                    bc = max(int(r["bytes_copied"]) for r in g)
                    med = statistics.median(t)
                    share = f"{100*cp/med:.0f}%" if pol == "sealed" and med else "-"
                    lines.append(f"| {hl} | {POLICY_LABEL[pol]} | {s} | {load} | {len(g)} | {chk/1000:.2f} | {cp/1000:.2f} | "
                                 f"{med/1000:.2f} | {p99(t)/1000:.2f} | {share} | {bc} |")
    srcs = [f.name for f in (src, fast_src) if f]
    srcline = (" Data: " + ", ".join("`" + n + "`" for n in srcs) + ".") if srcs else ""
    (out / "table_overhead.md").write_text(f"Launch cost by policy, size and load, no attacker.{srcline}\n\n" + "\n".join(lines) + "\n")


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--results", default="results")
    ap.add_argument("--out", default="report/figures")
    ap.add_argument("--run", default="", help="file prefix: 'run2' reads results/run2_<matrix>.csv; "
                                               "empty reads results/<matrix>.csv (run 1)")
    ap.add_argument("--uncontrolled", help="override the uncontrolled CSV path")
    ap.add_argument("--overhead", help="override the overhead CSV path")
    ap.add_argument("--controlled", help="override the controlled CSV path")
    ap.add_argument("--overhead-fast", help="a second overhead CSV from the OpenSSL (SHA-NI) broker build; "
                                            "adds a row of panels to figure 2 and rows to the overhead table")
    args = ap.parse_args()
    res, out = Path(args.results), Path(args.out)
    out.mkdir(parents=True, exist_ok=True)
    pre = f"{args.run}_" if args.run else ""
    f_unc = Path(args.uncontrolled) if args.uncontrolled else res / f"{pre}uncontrolled.csv"
    f_ovh = Path(args.overhead) if args.overhead else res / f"{pre}overhead.csv"
    f_ctl = Path(args.controlled) if args.controlled else res / f"{pre}controlled.csv"
    for f in (f_unc, f_ovh, f_ctl):
        if not f.exists():
            print("missing", f)
    f_fast = Path(args.overhead_fast) if args.overhead_fast else None
    if f_fast and not f_fast.exists():
        print("missing", f_fast); f_fast = None
    unc, ovh, ctl = load(f_unc), load(f_ovh), load(f_ctl)
    fast = load(f_fast) if f_fast else None
    figure1(unc, out, (f_unc,)); figure2(ovh, out, (f_ovh,) + ((f_fast,) if f_fast else ()), fast)
    figure3(unc, ctl, out, (f_unc, f_ctl))
    outcome_table(unc, out, f_unc); overhead_table(ovh, out, f_ovh, fast, f_fast)
    print("wrote", sorted(p.name for p in out.iterdir()))


if __name__ == "__main__":
    main()
