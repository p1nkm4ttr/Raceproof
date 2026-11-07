#!/usr/bin/env python3
"""RaceProof matrix runner.

Runs the controlled, uncontrolled and overhead matrices from config.json against
the broker and updater, classifies every trial, and appends rows to a CSV.

    python3 harness/run_trials.py --matrix controlled --out results/controlled.csv
    python3 harness/run_trials.py --all
    python3 harness/run_trials.py --matrix controlled --quick    # 64k, idle, 2 reps

Every trial runs in a scratch directory on a native Linux filesystem
($RP_SCRATCH, default ~/raceproof-scratch); the runner refuses anything else
because rename and ETXTBSY semantics on the Windows bridge are not Linux's.
"""
import argparse
import csv
import itertools
import json
import os
import shutil
import subprocess
import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent))
from classify import classify  # noqa: E402

ROOT = Path(__file__).resolve().parent.parent
BROKER = ROOT / "broker" / "broker"
UPDATER = ROOT / "updater" / "updater"
FIXTURES = ROOT / "fixtures" / "bin"
LAYOUT = ROOT / "fixtures" / "layout.txt"
ALLOWLIST = ROOT / "fixtures" / "allowlist.txt"
CONFIG = json.loads((Path(__file__).parent / "config.json").read_text())

COLUMNS = ["matrix", "policy", "change", "stage", "region", "tear", "gap", "gap_us", "size", "load", "rep",
           "outcome", "launched_id", "launched_pad", "torn", "etxtbsy", "unsupported",
           "decision", "exec_errno", "exit_status", "signal", "timed_out",
           "t_check_us", "t_copy_us", "t_total_us", "t_wait_us", "bytes_hashed", "bytes_copied",
           "seal_ok", "torn_first", "torn_last", "updater_errno", "updater_t_us",
           "updater_writes", "updater_etxtbsy", "timestamp"]


# ---------------------------------------------------------------- environment

def scratch_dir() -> Path:
    s = Path(os.environ.get("RP_SCRATCH", Path.home() / "raceproof-scratch"))
    s.mkdir(parents=True, exist_ok=True)
    fstype = subprocess.run(["stat", "-f", "-c", "%T", str(s)], capture_output=True, text=True).stdout.strip()
    if fstype not in ("ext2/ext3", "ext4", "xfs", "btrfs"):
        sys.exit(f"scratch {s} is on {fstype!r}; it must be a native Linux filesystem (set RP_SCRATCH)")
    return s


def read_layout() -> dict:
    """name -> {size, text_off, text_size, pad}"""
    out = {}
    for line in LAYOUT.read_text().splitlines():
        parts = line.split()
        if not parts:
            continue
        name = Path(parts[0]).name
        kv = dict(p.split("=", 1) for p in parts[1:])
        out[name] = {"size": int(kv["size"]), "text_off": int(kv["text_off"]),
                     "text_size": int(kv["text_size"]), "pad": kv["pad"]}
    return out


def region_span(region: str, lay: dict) -> tuple[int, int]:
    if region == "header":
        return 0, 64
    if region == "text":
        return lay["text_off"], lay["text_size"]
    if region == "tail":
        n = min(65536, lay["size"])
        return lay["size"] - n, n
    raise ValueError(region)


def check_built():
    for p in (BROKER, UPDATER):
        if not p.exists():
            sys.exit(f"{p} not built; run make")
    if not LAYOUT.exists() or not ALLOWLIST.exists():
        sys.exit("fixtures not built; run make fixtures")


# ---------------------------------------------------------------- one trial

class Trial:
    """Scratch state for one configuration: target file, references, FIFOs."""

    def __init__(self, scratch: Path, size: str, layout: dict, change: str | None, region: str | None):
        self.dir = scratch / "trial"
        if self.dir.exists():
            shutil.rmtree(self.dir)
        self.dir.mkdir()
        self.a = FIXTURES / f"prog_a_{size}"
        self.b = FIXTURES / f"prog_b_{size}"
        self.lay = layout[f"prog_a_{size}"]
        self.target = self.dir / "target"
        self.ref_a = self.dir / "ref_a"
        self.ref_after = self.dir / "ref_after"
        shutil.copy(self.a, self.ref_a)
        # Expected post-attack image: B for replace, A with one region from B for rewrite.
        if change == "replace":
            shutil.copy(self.b, self.ref_after)
        elif change == "rewrite":
            data = bytearray(self.a.read_bytes())
            bdata = self.b.read_bytes()
            off, n = region_span(region, self.lay)
            data[off:off + n] = bdata[off:off + n]
            self.ref_after.write_bytes(data)
        else:
            shutil.copy(self.a, self.ref_after)
        self.fifo = self.dir / "fifo"
        self.fifo.mkdir()
        self.reset_target()

    def reset_target(self):
        shutil.copy(self.a, self.target)
        os.chmod(self.target, 0o755)

    def env(self, **extra) -> dict:
        e = dict(os.environ)
        e.update({"RP_REF_A": str(self.ref_a), "RP_REF_B": str(self.ref_after)})
        e.update({k: str(v) for k, v in extra.items() if v is not None})
        return e


def parse_updater(text: str) -> dict:
    writes, etxtbsy, last = 0, 0, {}
    for line in text.splitlines():
        try:
            r = json.loads(line)
        except json.JSONDecodeError:
            continue
        writes += 1
        if r.get("errno") == 26:
            etxtbsy += 1
        last = r
    return {"updater_writes": writes, "updater_etxtbsy": etxtbsy,
            "updater_errno": last.get("errno", ""), "updater_t_us": last.get("t_us", "")}


def run_broker(policy: str, env: dict, requests: list[str], timeout: float) -> list[dict]:
    p = subprocess.run([str(BROKER), "--policy", policy, "--allowlist", str(ALLOWLIST), "--timeout-ms", "5000"],
                       input="".join(f"RUN {r}\n" for r in requests), capture_output=True, text=True,
                       env=env, timeout=timeout, cwd=ROOT)
    recs = []
    for line in p.stdout.splitlines():
        try:
            recs.append(json.loads(line))
        except json.JSONDecodeError:
            pass
    if p.stderr.strip():
        print("broker stderr:", p.stderr.strip()[:300], file=sys.stderr)
    return recs


def row_from(rec: dict, outcome, base: dict, upd: dict) -> dict:
    row = dict(base)
    row.update(outcome.as_row())
    for k in ("decision", "exec_errno", "exit_status", "signal", "timed_out", "t_check_us", "t_copy_us",
              "t_total_us", "t_wait_us", "bytes_hashed", "bytes_copied", "seal_ok", "torn_first", "torn_last"):
        row[k] = rec.get(k, "")
    row["torn"] = int(bool(rec.get("torn", 0)))
    row.update(upd)
    row["timestamp"] = time.strftime("%Y-%m-%dT%H:%M:%S")
    return row


# ---------------------------------------------------------------- matrices

def controlled_configs(cfg, sizes, loads, regions):
    m = cfg["matrices"]["controlled"]
    for load, size, (policy, pc) in itertools.product(loads, sizes, m["policies"].items()):
        for stage in pc["stages"]:
            for change in m["changes"]:
                if change == "replace":
                    tear = m["tear_for_mid_copy_replace"] if stage == "mid_copy" else ""
                    yield dict(policy=policy, change=change, stage=stage, region="", tear=tear, size=size, load=load)
                else:
                    tears = m["tears_for_mid_copy_rewrite"] if stage == "mid_copy" else [""]
                    for region, tear in itertools.product(regions, tears):
                        yield dict(policy=policy, change=change, stage=stage, region=region, tear=tear, size=size, load=load)


def tear_bytes(tear: str, region: str, lay: dict) -> int | None:
    """Where the mid_copy stage fires, in bytes copied.

    before: at the region's start, so the whole region is copied after the write lands;
            the copy equals the post-attack image (no tear, the attack simply won the copy).
    after:  at the region's end, so the region was copied before the write; the copy
            equals the pre-attack image (the attack lost the copy).
    mid:    inside the region, so the copy holds the first half from before the write and
            the second half from after it: a genuine torn copy, matching neither image.
    """
    if tear == "half" or tear == "":
        return None                                   # broker default: half the file
    off, n = region_span(region, lay)
    return {"before": off, "mid": off + n // 2, "after": off + n}[tear]


def controlled_trial(t: "Trial", c: dict, tear: int | None):
    """One barrier-controlled launch. Returns (broker record or None, updater info)."""
    t.reset_target()
    # The harness owns the FIFOs so neither process can open them before they exist.
    for f in t.fifo.iterdir():
        f.unlink()
    os.mkfifo(t.fifo / "to_updater")
    os.mkfifo(t.fifo / "from_updater")
    upd_cmd = [str(UPDATER), "--mode", c["change"], "--at", c["stage"], "--target", str(t.target),
               "--payload", str(t.b), "--layout", str(LAYOUT), "--once"]
    if c["change"] == "rewrite":
        upd_cmd += ["--region", c["region"]]
    env = t.env(RP_BARRIER_DIR=str(t.fifo), RP_TEAR_AT=tear)
    upd = subprocess.Popen(upd_cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, env=env, cwd=ROOT)
    try:
        recs = run_broker(c["policy"], env, [str(t.target)], timeout=30)
    except subprocess.TimeoutExpired:
        recs = []
    try:
        uout, uerr = upd.communicate(timeout=10)
    except subprocess.TimeoutExpired:
        upd.kill()
        uout, uerr = upd.communicate()
    if uerr.strip():
        print("updater stderr:", uerr.strip()[:200], file=sys.stderr)
    return (recs[0] if recs else None), parse_updater(uout)


def run_controlled(cfg, scratch, layout, writer, sizes, loads, regions, reps, quick):
    for c in controlled_configs(cfg, sizes, loads, regions):
        t = Trial(scratch, c["size"], layout, c["change"], c["region"] or None)
        tear = tear_bytes(c["tear"], c["region"], t.lay) if c["stage"] == "mid_copy" else None
        base = dict(matrix="controlled", gap="none", gap_us=0, **c)
        for rep in range(reps):
            for attempt in range(3):
                rec, upd_info = controlled_trial(t, c, tear)
                if rec is not None and rec.get("decision") in ("APPROVE", "REJECT"):
                    break
                print(f"retry {attempt + 1}: no usable broker record for {c} rep {rep}: "
                      f"{rec and {k: rec.get(k) for k in ('decision', 'exit_status', 'signal', 'timed_out')}}", file=sys.stderr)
            else:
                print(f"giving up on {c} rep {rep}", file=sys.stderr)
                continue
            out = classify(rec, approved_pad=t.lay["pad"], etxtbsy=upd_info["updater_etxtbsy"] > 0)
            writer.writerow(row_from(rec, out, dict(base, rep=rep), upd_info))
        print(f"controlled {c['policy']:6} {c['change']:7} {c['stage']:9} {c['region'] or '-':6} {c['tear'] or '-':6} {c['size']:3} {c['load']:6} done", flush=True)


def run_uncontrolled(cfg, scratch, layout, writer, sizes, loads, reps, quick):
    m = cfg["matrices"]["uncontrolled"]
    gaps = cfg["gaps_us"]
    for load, size, policy, change, gap in itertools.product(loads, sizes, m["policies"], m["changes"], m["gaps"]):
        region = m["rewrite_region"] if change == "rewrite" else ""
        t = Trial(scratch, size, layout, change, region or None)
        upd_cmd = [str(UPDATER), "--mode", change, "--at", "free", "--target", str(t.target), "--payload", str(t.b),
                   "--alt", str(t.a), "--layout", str(LAYOUT), "--interval-us", m["interval_us"]]
        if change == "rewrite":
            upd_cmd += ["--region", region]
        env = t.env(RP_GAP_US=gaps[gap])
        upd = subprocess.Popen(upd_cmd, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, text=True, env=env, cwd=ROOT)
        time.sleep(0.05)
        try:
            recs = run_broker(policy, env, [str(t.target)] * reps, timeout=600)
        finally:
            upd.terminate()
            uout, _ = upd.communicate()
        upd_info = parse_updater(uout)
        base = dict(matrix="uncontrolled", policy=policy, change=change, stage="free", region=region, tear="",
                    gap=gap, gap_us=gaps[gap], size=size, load=load)
        for rep, rec in enumerate(recs):
            out = classify(rec, approved_pad=t.lay["pad"])
            writer.writerow(row_from(rec, out, dict(base, rep=rep), upd_info))
        print(f"uncontrolled {policy:6} {change:7} gap={gap:5} {size:3} {load:6} n={len(recs)} done", flush=True)


def run_overhead(cfg, scratch, layout, writer, sizes, loads, reps, quick):
    m = cfg["matrices"]["overhead"]
    for load, size, policy in itertools.product(loads, sizes, m["policies"]):
        t = Trial(scratch, size, layout, None, None)
        env = dict(os.environ)                          # no RP_REF_*: no torn analysis, clean timing
        env.pop("RP_REF_A", None); env.pop("RP_REF_B", None)
        recs = run_broker(policy, env, [str(t.target)] * reps, timeout=600)
        base = dict(matrix="overhead", policy=policy, change="", stage="", region="", tear="", gap="none",
                    gap_us=0, size=size, load=load)
        for rep, rec in enumerate(recs):
            out = classify(rec, approved_pad=t.lay["pad"])
            writer.writerow(row_from(rec, out, dict(base, rep=rep), parse_updater("")))
        print(f"overhead {policy:6} {size:3} {load:6} n={len(recs)} done", flush=True)


# ---------------------------------------------------------------- main

class Stress:
    def __init__(self):
        self.p = None

    def start(self):
        if shutil.which("stress-ng") is None:
            sys.exit("stress-ng not installed")
        self.p = subprocess.Popen(["stress-ng", "--cpu", "0", "--quiet"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        time.sleep(1.0)

    def stop(self):
        if self.p:
            self.p.terminate()
            self.p.wait()
            self.p = None


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--matrix", choices=["controlled", "uncontrolled", "overhead"])
    ap.add_argument("--all", action="store_true")
    ap.add_argument("--out", help="CSV path (default results/<matrix>.csv)")
    ap.add_argument("--reps", type=int)
    ap.add_argument("--sizes", help="comma list, e.g. 64k,1m")
    ap.add_argument("--loads", help="comma list: idle,stress")
    ap.add_argument("--quick", action="store_true", help="64k, idle, 2 reps")
    args = ap.parse_args()
    if not args.matrix and not args.all:
        ap.error("--matrix or --all")

    check_built()
    scratch = scratch_dir()
    layout = read_layout()
    matrices = ["controlled", "uncontrolled", "overhead"] if args.all else [args.matrix]
    sizes = args.sizes.split(",") if args.sizes else (["64k"] if args.quick else CONFIG["sizes"])
    loads = args.loads.split(",") if args.loads else (["idle"] if args.quick else CONFIG["loads"])
    regions = CONFIG["regions"]

    for name in matrices:
        reps = args.reps or (2 if args.quick else CONFIG["matrices"][name]["reps"])
        out = Path(args.out) if (args.out and len(matrices) == 1) else ROOT / "results" / f"{name}.csv"
        out.parent.mkdir(exist_ok=True)
        new = not out.exists()
        with out.open("a", newline="") as f:
            w = csv.DictWriter(f, fieldnames=COLUMNS)
            if new:
                w.writeheader()
            stress = Stress()
            for load in loads:
                if load == "stress":
                    stress.start()
                try:
                    if name == "controlled":
                        run_controlled(CONFIG, scratch, layout, w, sizes, [load], regions, reps, args.quick)
                    elif name == "uncontrolled":
                        run_uncontrolled(CONFIG, scratch, layout, w, sizes, [load], reps, args.quick)
                    else:
                        run_overhead(CONFIG, scratch, layout, w, sizes, [load], reps, args.quick)
                finally:
                    stress.stop()
        print(f"wrote {out}")


if __name__ == "__main__":
    main()
