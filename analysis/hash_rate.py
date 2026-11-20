#!/usr/bin/env python3
"""Hash throughput per cell, as a check on whether a run's timings can be trusted.

    python3 analysis/hash_rate.py results/run4_*.csv

The hash code does not change between launches, so bytes hashed per second measures the
machine, not the policy. All three policies hash the same file in the same cell, so their
rates should be close; when something else was using the CPU for part of a cell they are
not. For every file this prints the median rate in MB/s per size and load for each policy,
and judges each CPU-idle cell:

  UNEVEN      the fastest policy's median is more than 1.5 times the slowest's
  INCOMPLETE  a policy has no hash timings in the cell, so there is nothing to compare
  FEW         fewer than 10 launches for some policy: printed, not judged

Stress cells are printed but not judged, because twelve CPU hogs make them uneven by design.

Every file is judged on its own and the exit status is the worst verdict of any file, so a
good file can never stand in for one that failed or was not checked:

  0  every idle cell of every file was judged and none is UNEVEN in an overhead matrix
  1  an idle cell of an overhead matrix is UNEVEN: do not use that file's launch times,
     rerun the overhead matrix with nothing else running
  2  a comparison could not be made: a file with no hash timings, or an INCOMPLETE cell
  3  too few launches to judge: an overhead matrix has a FEW idle cell, or a file has no
     idle cell that could be judged at all (expected for a reduced rehearsal run)

It never reports agreement for a comparison it did not make. Security outcomes do not
depend on this check; latency numbers do.
"""
import csv
import statistics
import sys
from collections import defaultdict
from pathlib import Path

SIZES = ["64k", "1m", "8m", "32m"]
POLICIES = ["path", "fd", "sealed"]
UNEVEN = 1.5
MIN_N = 10
EVEN, UNEVEN_OVERHEAD, NOT_COMPARABLE, TOO_FEW = 0, 1, 2, 3


def rates(path):
    """{(matrix, hash_impl, load, size): {policy: [MB/s, ...]}} for rows that hashed something."""
    cells = defaultdict(lambda: defaultdict(list))
    with open(path, newline="") as f:
        for r in csv.DictReader(f):
            try:
                us, n = int(r["t_check_us"]), int(r["bytes_hashed"])
            except (KeyError, ValueError, TypeError):
                continue
            if us <= 0 or n <= 0 or r.get("outcome") == "HARNESS_ERROR" or r.get("policy") not in POLICIES:
                continue
            key = (r.get("matrix", ""), r.get("hash_impl") or "vendored-c", r.get("load", ""), r.get("size", ""))
            cells[key][r["policy"]].append(n / us)        # bytes per microsecond is MB/s
    return cells


def report(path):
    """Print one file's table and return its counts of judged, uneven, incomplete and few idle cells."""
    count = dict(judged=0, uneven_overhead=0, uneven_other=0, incomplete=0, few=0, few_overhead=0, no_data=0)
    cells = rates(path)
    print(path)
    if not cells:
        print("  no rows with a hash time, nothing to compare")
        count["no_data"] = 1
        return count
    print(f"  {'matrix':12} {'hash':12} {'load':6} {'size':4} " + " ".join(f"{p:>8}" for p in POLICIES) + "   max/min")
    order = sorted(cells, key=lambda k: (k[0], k[1], k[2], SIZES.index(k[3]) if k[3] in SIZES else 99))
    for key in order:
        med = {p: statistics.median(v) for p, v in cells[key].items() if v}
        spread = max(med.values()) / min(med.values()) if len(med) > 1 else None
        mark = ""
        if key[2] == "idle":
            missing = [p for p in POLICIES if p not in med]
            if missing:
                mark = "  INCOMPLETE (no timings for " + ", ".join(missing) + ")"
                count["incomplete"] += 1
            elif min(len(cells[key][p]) for p in POLICIES) < MIN_N:
                mark = f"  FEW (under {MIN_N} launches for a policy, not judged)"
                count["few"] += 1
                count["few_overhead"] += key[0] == "overhead"
            else:
                count["judged"] += 1
                if spread > UNEVEN:
                    mark = "  UNEVEN"
                    count["uneven_overhead" if key[0] == "overhead" else "uneven_other"] += 1
        cols = " ".join(f"{med[p]:8.0f}" if p in med else f"{'-':>8}" for p in POLICIES)
        shown = f"{spread:6.2f}" if spread is not None else f"{'-':>6}"
        print(f"  {key[0]:12} {key[1]:12} {key[2]:6} {key[3]:4} {cols}   {shown}{mark}")
    return count


def verdict(c):
    """One file's verdict from its counts."""
    if c["uneven_overhead"]:
        return UNEVEN_OVERHEAD
    if c["no_data"] or c["incomplete"]:
        return NOT_COMPARABLE
    if c["few_overhead"] or c["judged"] == 0:
        return TOO_FEW
    return EVEN


def check(files):
    """Print the report for every file, then one line per file, and return the worst verdict."""
    results = [(f, report(f)) for f in files]       # a list, so two files with the same name stay separate
    print()
    verdicts = []
    for f, c in results:
        v = verdict(c)
        verdicts.append(v)
        if v == UNEVEN_OVERHEAD:
            print(f"CHECK {f}: {c['uneven_overhead']} idle overhead cell(s) UNEVEN. Its launch times are not usable; rerun the overhead matrix.")
        elif v == NOT_COMPARABLE:
            print(f"NOT CHECKED {f}: no hash timings, or a policy is missing from {c['incomplete']} idle cell(s).")
        elif v == TOO_FEW:
            print(f"NOT JUDGED {f}: {c['few']} idle cell(s) have fewer than {MIN_N} launches per policy; {c['judged']} judged.")
        else:
            extra = f"; {c['few']} more not judged (fewer than {MIN_N} launches)" if c["few"] else ""
            print(f"ok {f}: {c['judged']} idle cell(s) judged, policies within a factor of {UNEVEN}{extra}")
        if c["uneven_other"]:
            print(f"note {f}: {c['uneven_other']} idle cell(s) UNEVEN outside the overhead matrix; outcomes are unaffected, the machine was disturbed.")
    for worst in (UNEVEN_OVERHEAD, NOT_COMPARABLE, TOO_FEW):
        if worst in verdicts:
            return worst
    unjudged = sum(c["few"] for _, c in results)
    if not any(c["uneven_other"] for _, c in results):
        if unjudged:
            print(f"hash rates are within a factor of {UNEVEN} across policies in every idle cell judged; "
                  f"{unjudged} cell(s) outside the overhead matrix were not judged")
        else:
            print(f"hash rates are within a factor of {UNEVEN} across policies in every idle cell of every file")
    return EVEN


def main():
    files = [Path(a) for a in sys.argv[1:]]
    if not files:
        sys.exit("usage: python3 analysis/hash_rate.py results/<run>_*.csv")
    missing = [str(f) for f in files if not f.exists()]
    if missing:
        sys.exit("missing: " + ", ".join(missing))
    sys.exit(check(files))


if __name__ == "__main__":
    main()
