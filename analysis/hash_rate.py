#!/usr/bin/env python3
"""Hash throughput per cell, as a check on whether a run's timings can be trusted.

    python3 analysis/hash_rate.py results/run4_*.csv

The hash code does not change between launches, so bytes hashed per second measures the
machine, not the policy. All three policies hash the same file in the same cell, so their
rates should agree; when something else was using the CPU for part of a cell they do not.
For every file this prints the median rate in MB/s per size and load for each policy, and
marks an idle cell UNEVEN when the fastest policy's median is more than 1.5 times the
slowest's. An UNEVEN idle cell in an overhead file means: do not use that file's launch
times, rerun the overhead matrix with nothing else running. Stress cells are printed but
not marked, because twelve CPU hogs make them uneven by design.

Security outcomes do not depend on this check; latency numbers do.
"""
import csv
import statistics
import sys
from collections import defaultdict
from pathlib import Path

SIZES = ["64k", "1m", "8m", "32m"]
POLICIES = ["path", "fd", "sealed"]
UNEVEN = 1.5


def rates(path):
    """{(matrix, hash_impl, load, size): {policy: [MB/s, ...]}} for rows that hashed something."""
    cells = defaultdict(lambda: defaultdict(list))
    with open(path, newline="") as f:
        for r in csv.DictReader(f):
            try:
                us, n = int(r["t_check_us"]), int(r["bytes_hashed"])
            except (KeyError, ValueError):
                continue
            if us <= 0 or n <= 0 or r.get("outcome") == "HARNESS_ERROR":
                continue
            key = (r.get("matrix", ""), r.get("hash_impl") or "vendored-c", r["load"], r["size"])
            cells[key][r["policy"]].append(n / us)        # bytes per microsecond is MB/s
    return cells


def report(path):
    cells = rates(path)
    if not cells:
        print(f"{path.name}: no rows with a hash time")
        return 0
    flagged = 0
    print(path.name)
    print(f"  {'matrix':12} {'hash':12} {'load':6} {'size':4} " + " ".join(f"{p:>8}" for p in POLICIES) + "   max/min")
    order = sorted(cells, key=lambda k: (k[0], k[1], k[2], SIZES.index(k[3]) if k[3] in SIZES else 99))
    for key in order:
        med = {p: statistics.median(v) for p, v in cells[key].items() if v}
        spread = max(med.values()) / min(med.values()) if len(med) > 1 else 1.0
        mark = ""
        if key[2] == "idle" and spread > UNEVEN:
            mark = "  UNEVEN"
            flagged += 1
        cols = " ".join(f"{med[p]:8.0f}" if p in med else f"{'-':>8}" for p in POLICIES)
        print(f"  {key[0]:12} {key[1]:12} {key[2]:6} {key[3]:4} {cols}   {spread:6.2f}{mark}")
    return flagged


def main():
    files = [Path(a) for a in sys.argv[1:]]
    if not files:
        sys.exit(__doc__.strip().splitlines()[2].strip())
    missing = [str(f) for f in files if not f.exists()]
    if missing:
        sys.exit("missing: " + ", ".join(missing))
    flagged = {f.name: report(f) for f in files}
    print()
    bad = {name: n for name, n in flagged.items() if n}
    if bad:
        for name, n in bad.items():
            print(f"CHECK {name}: {n} idle cell(s) UNEVEN. If this is an overhead file, its launch times are not usable.")
    else:
        print("hash rates agree across policies in every idle cell")


if __name__ == "__main__":
    main()
