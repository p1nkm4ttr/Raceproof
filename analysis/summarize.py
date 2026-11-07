#!/usr/bin/env python3
"""Per-configuration outcome counts and rates with Wilson 95% intervals.

    python3 analysis/summarize.py results/controlled.csv
    python3 analysis/summarize.py results/uncontrolled.csv --by policy,change,gap,size,load
    python3 analysis/summarize.py results/overhead.csv --timing

Never prints a rate without its n.
"""
import argparse
import csv
import math
import statistics
from collections import Counter, defaultdict

OUTCOMES = ["CORRECT", "MISMATCH", "REJECT", "EXEC_ERROR"]
DEFAULT_KEYS = {
    "controlled": ["policy", "change", "stage", "region", "tear", "size", "load"],
    "uncontrolled": ["policy", "change", "gap", "size", "load"],
    "overhead": ["policy", "size", "load"],
}


def wilson(k: int, n: int, z: float = 1.96) -> tuple[float, float]:
    if n == 0:
        return 0.0, 0.0
    p = k / n
    d = 1 + z * z / n
    c = (p + z * z / (2 * n)) / d
    h = z * math.sqrt(p * (1 - p) / n + z * z / (4 * n * n)) / d
    return max(0.0, c - h), min(1.0, c + h)


def fmt_rate(k, n):
    lo, hi = wilson(k, n)
    return f"{k}/{n} ({100*k/n:5.1f}%, CI {100*lo:4.0f}-{100*hi:3.0f})" if n else "0/0"


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("csv")
    ap.add_argument("--by", help="comma list of grouping columns")
    ap.add_argument("--timing", action="store_true", help="median and p99 of t_total_us, t_check_us, t_copy_us")
    args = ap.parse_args()

    rows = list(csv.DictReader(open(args.csv, newline="")))
    if not rows:
        print("no rows")
        return
    matrix = rows[0]["matrix"]
    keys = args.by.split(",") if args.by else DEFAULT_KEYS.get(matrix, ["policy", "size"])

    groups = defaultdict(list)
    for r in rows:
        groups[tuple(r[k] for k in keys)].append(r)

    print(f"{args.csv}: {len(rows)} rows, {len(groups)} configurations, grouped by {','.join(keys)}\n")
    head = " | ".join(f"{k:>9}" for k in keys)
    if args.timing:
        print(f"{head} |    n | total med/p99 us | check med us | copy med us | bytes_copied")
    else:
        print(f"{head} |    n | MISMATCH | REJECT | CORRECT | EXEC_ERR | torn | etxtbsy")
    for key in sorted(groups):
        g = groups[key]
        n = len(g)
        label = " | ".join(f"{(v or '-'):>9}" for v in key)
        if args.timing:
            tot = [int(r["t_total_us"]) for r in g if r["t_total_us"] not in ("", "-1")]
            chk = [int(r["t_check_us"]) for r in g if r["t_check_us"]]
            cp = [int(r["t_copy_us"]) for r in g if r["t_copy_us"]]
            bc = [int(r["bytes_copied"]) for r in g if r["bytes_copied"]]
            p99 = sorted(tot)[max(0, int(0.99 * len(tot)) - 1)] if tot else 0
            print(f"{label} | {n:4} | {statistics.median(tot) if tot else 0:8.0f}/{p99:8.0f} | {statistics.median(chk) if chk else 0:12.0f} | {statistics.median(cp) if cp else 0:11.0f} | {max(bc) if bc else 0}")
        else:
            c = Counter(r["outcome"] for r in g)
            torn = sum(int(r["torn"] or 0) for r in g)
            etx = sum(int(r["etxtbsy"] or 0) for r in g)
            print(f"{label} | {n:4} | {c['MISMATCH']:8} | {c['REJECT']:6} | {c['CORRECT']:7} | {c['EXEC_ERROR']:8} | {torn:4} | {etx:7}")

    if not args.timing:
        print("\nHeadline rates (Wilson 95% CI):")
        by_policy = defaultdict(list)
        for r in rows:
            by_policy[r["policy"]].append(r)
        for pol, g in sorted(by_policy.items()):
            n = len(g)
            mis = sum(r["outcome"] == "MISMATCH" for r in g)
            torn = sum(int(r["torn"] or 0) for r in g)
            print(f"  {pol:6} mismatch {fmt_rate(mis, n)}   torn {fmt_rate(torn, n)}")


if __name__ == "__main__":
    main()
