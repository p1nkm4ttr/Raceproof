#!/usr/bin/env python3
"""RaceProof matrix runner.

Runs the controlled, uncontrolled and overhead matrices from config.json against
the broker and updater, classifies every trial, and appends rows to a CSV.

    python3 harness/run_trials.py --matrix controlled --run-id run2 --out results/run2_controlled.csv
    python3 harness/run_trials.py --all --run-id run3      # results/run3_<matrix>.csv
    python3 harness/run_trials.py --matrix controlled --quick    # 64k, idle, 2 reps

Guarantees this runner makes about its output:
  * every row carries run_id and git_rev, so runs are distinguishable;
  * it refuses to append to a CSV whose header differs from its own columns;
  * a trial that produced no usable broker record is written as a row with
    outcome HARNESS_ERROR, never silently retried away; retries are numbered in
    the attempt column and the successful attempt is written too;
  * it fails loudly if the broker returns a different number of records than
    requested, prints unparsable output, or if the updater or stress-ng died;
  * no RP_* variable from the calling shell reaches the broker or updater;
  * policies are interleaved within each cell, not run in blocks, so order
    effects do not line up with policy.

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
import signal
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
CONFIG_PATH = Path(__file__).parent / "config.json"
CONFIG = json.loads(CONFIG_PATH.read_text())

HARNESS_ERROR = "HARNESS_ERROR"
BROKER_TIMEOUT_MS = 30000          # per launch, inside the broker
PER_LAUNCH_BUDGET_S = 45           # harness-side budget per launch, must exceed the broker's
INTERLEAVE_BLOCK = 10              # launches per policy before rotating to the next policy

COLUMNS = ["run_id", "git_rev", "hash_impl", "matrix", "policy", "change", "stage", "region", "tear", "gap", "gap_us",
           "size", "load", "rep", "attempt",
           "outcome", "launched_id", "launched_pad", "torn", "etxtbsy", "unsupported", "broker_error",
           "decision", "observed_hash", "exec_errno", "exit_status", "signal", "timed_out",
           "t_check_us", "t_copy_us", "t_total_us", "t_wait_us", "bytes_hashed", "bytes_copied",
           "seal_ok", "torn_checked", "torn_first", "torn_last",
           "attack_landed", "updater_errno", "updater_t_us",
           "batch_launches", "batch_updater_writes", "batch_updater_etxtbsy",
           "harness_note", "timestamp"]


class HarnessError(RuntimeError):
    pass


# ---------------------------------------------------------------- environment

def scratch_dir() -> Path:
    s = Path(os.environ.get("RP_SCRATCH", Path.home() / "raceproof-scratch"))
    s.mkdir(parents=True, exist_ok=True)
    fstype = subprocess.run(["stat", "-f", "-c", "%T", str(s)], capture_output=True, text=True).stdout.strip()
    if fstype not in ("ext2/ext3", "ext4", "xfs", "btrfs"):
        sys.exit(f"scratch {s} is on {fstype!r}; it must be a native Linux filesystem (set RP_SCRATCH)")
    return s


def clean_env() -> dict:
    """The calling shell's environment with every experiment control removed."""
    return {k: v for k, v in os.environ.items() if not k.startswith("RP_")}


def git_rev() -> str:
    try:
        rev = subprocess.run(["git", "rev-parse", "--short", "HEAD"], capture_output=True, text=True, cwd=ROOT).stdout.strip()
        dirty = subprocess.run(["git", "status", "--porcelain", "--untracked-files=no"], capture_output=True, text=True, cwd=ROOT).stdout.strip()
        return (rev or "unknown") + ("-dirty" if dirty else "")
    except OSError:
        return "unknown"


def read_layout() -> dict:
    out = {}
    for line in LAYOUT.read_text().splitlines():
        parts = line.split()
        if not parts:
            continue
        kv = dict(p.split("=", 1) for p in parts[1:])
        out[Path(parts[0]).name] = {"size": int(kv["size"]), "text_off": int(kv["text_off"]),
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


# ---------------------------------------------------------------- processes

def run_broker(policy: str, env: dict, requests: list[str]) -> list[dict]:
    """Run one broker over the requests. Raises HarnessError on anything unexpected."""
    budget = PER_LAUNCH_BUDGET_S * len(requests) + 15
    p = subprocess.Popen([str(BROKER), "--policy", policy, "--allowlist", str(ALLOWLIST),
                          "--timeout-ms", str(BROKER_TIMEOUT_MS)],
                         stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True,
                         env=env, cwd=ROOT, start_new_session=True)
    try:
        out, err = p.communicate("".join(f"RUN {r}\n" for r in requests), timeout=budget)
    except subprocess.TimeoutExpired:
        os.killpg(p.pid, signal.SIGKILL)            # the broker and any child it is waiting on
        out, err = p.communicate()
        raise HarnessError(f"broker exceeded {budget}s for {len(requests)} launches; killed its process group")
    recs, bad = [], 0
    for line in out.splitlines():
        try:
            recs.append(json.loads(line))
        except json.JSONDecodeError:
            bad += 1
    if bad:
        raise HarnessError(f"broker printed {bad} unparsable line(s); stderr: {err.strip()[:300]}")
    if len(recs) != len(requests):
        raise HarnessError(f"broker returned {len(recs)} records for {len(requests)} requests; stderr: {err.strip()[:300]}")
    if p.returncode != 0:
        raise HarnessError(f"broker exited {p.returncode}; stderr: {err.strip()[:300]}")
    return recs


def parse_updater(text: str) -> dict:
    """Controlled: one JSON line per write (one write with --once). Free mode: one summary line."""
    writes, etxtbsy, errors, last, summary = 0, 0, 0, {}, None
    for line in text.splitlines():
        try:
            r = json.loads(line)
        except json.JSONDecodeError:
            continue
        if r.get("summary"):
            summary = r
            continue
        writes += 1
        if r.get("errno") == 26:
            etxtbsy += 1
        elif r.get("errno"):
            errors += 1
        last = r
    if summary:
        return {"writes": summary["writes"], "etxtbsy": summary["etxtbsy"], "errors": summary.get("errors", 0),
                "last_errno": "", "last_t_us": summary.get("run_us", "")}
    return {"writes": writes, "etxtbsy": etxtbsy, "errors": errors,
            "last_errno": last.get("errno", ""), "last_t_us": last.get("t_us", "")}


class Stress:
    def __init__(self):
        self.p = None

    def start(self):
        if shutil.which("stress-ng") is None:
            sys.exit("stress-ng not installed")
        self.p = subprocess.Popen(["stress-ng", "--cpu", "0", "--quiet"], stdout=subprocess.DEVNULL,
                                  stderr=subprocess.DEVNULL, env=clean_env())
        time.sleep(1.0)

    def check(self):
        if self.p is not None and self.p.poll() is not None:
            raise HarnessError(f"stress-ng died (exit {self.p.returncode}) during a stress cell")

    def stop(self):
        if self.p:
            self.p.terminate()
            self.p.wait()
            self.p = None


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

    def env(self, refs=True, **extra) -> dict:
        e = clean_env()
        if refs:
            e.update({"RP_REF_A": str(self.ref_a), "RP_REF_B": str(self.ref_after)})
        e.update({k: str(v) for k, v in extra.items() if v is not None})
        return e


class Writer:
    def __init__(self, path: Path, run_id: str, rev: str):
        self.path, self.run_id, self.rev = path, run_id, rev
        path.parent.mkdir(exist_ok=True)
        if path.exists() and path.stat().st_size > 0:
            header = path.open(newline="").readline().strip().split(",")
            if header != COLUMNS:
                sys.exit(f"{path} has a different header ({len(header)} columns vs {len(COLUMNS)} expected). "
                         f"Rename or move it; this runner never appends to a mismatched file.")
            self.f = path.open("a", newline="")
            self.w = csv.DictWriter(self.f, fieldnames=COLUMNS)
        else:
            self.f = path.open("w", newline="")
            self.w = csv.DictWriter(self.f, fieldnames=COLUMNS)
            self.w.writeheader()

    def row(self, base: dict, rec: dict | None, outcome=None, upd: dict | None = None, batch: dict | None = None,
            note: str = ""):
        row = {c: "" for c in COLUMNS}
        row.update({"run_id": self.run_id, "git_rev": self.rev, "timestamp": time.strftime("%Y-%m-%dT%H:%M:%S")})
        row.update(base)
        if outcome is not None:
            row.update(outcome.as_row())
        else:
            row["outcome"] = HARNESS_ERROR
        if rec:
            row["hash_impl"] = rec.get("hash_impl", "vendored-c")
            for k in ("decision", "observed_hash", "exec_errno", "exit_status", "signal", "timed_out", "t_check_us",
                      "t_copy_us", "t_total_us", "t_wait_us", "bytes_hashed", "bytes_copied", "seal_ok",
                      "torn_checked", "torn_first", "torn_last"):
                row[k] = rec.get(k, "")
            row["torn"] = int(bool(rec.get("torn", 0)))
        if upd is not None:
            row["attack_landed"] = int(upd["writes"] > 0 and upd["errors"] == 0 and upd["etxtbsy"] == 0)
            row["updater_errno"] = upd["last_errno"]
            row["updater_t_us"] = upd["last_t_us"]
        if batch is not None:
            row.update(batch)
        row["harness_note"] = note
        self.w.writerow(row)
        self.f.flush()

    def close(self):
        self.f.close()


# ---------------------------------------------------------------- matrices

def controlled_configs(cfg, sizes, loads, regions):
    m = cfg["matrices"]["controlled"]
    for load, size in itertools.product(loads, sizes):
        for policy, pc in m["policies"].items():
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
    before: at the region's start (copy equals the post-attack image, no tear);
    after:  at the region's end (copy equals the pre-attack image);
    mid:    inside the region (a genuine torn copy, matching neither image)."""
    if tear in ("half", ""):
        return None
    off, n = region_span(region, lay)
    return {"before": off, "mid": off + n // 2, "after": off + n}[tear]


def controlled_trial(t: Trial, c: dict, tear: int | None):
    """One barrier-controlled launch. Returns (broker record or None, updater info, note)."""
    t.reset_target()
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
    note, rec = "", None
    try:
        rec = run_broker(c["policy"], env, [str(t.target)])[0]
    except HarnessError as e:
        note = str(e)
    try:
        uout, uerr = upd.communicate(timeout=PER_LAUNCH_BUDGET_S)
    except subprocess.TimeoutExpired:
        upd.kill()
        uout, uerr = upd.communicate()
        note = (note + "; " if note else "") + "updater did not exit; killed"
    if upd.returncode != 0:
        note = (note + "; " if note else "") + f"updater exited {upd.returncode}: {uerr.strip()[:120]}"
    return rec, parse_updater(uout), note


def run_controlled(cfg, scratch, layout, writer, sizes, loads, regions, reps, stress):
    for c in controlled_configs(cfg, sizes, loads, regions):
        t = Trial(scratch, c["size"], layout, c["change"], c["region"] or None)
        tear = tear_bytes(c["tear"], c["region"], t.lay) if c["stage"] == "mid_copy" else None
        base = dict(matrix="controlled", gap="none", gap_us=0, **c)
        for rep in range(reps):
            for attempt in range(1, 4):
                if c["load"] == "stress":
                    stress.check()
                rec, upd, note = controlled_trial(t, c, tear)
                usable = rec is not None and rec.get("decision") in ("APPROVE", "REJECT", "ERROR") and not note
                if usable and c["policy"] == "sealed" and not rec.get("torn_checked", 0) and rec.get("decision") != "ERROR":
                    raise HarnessError(f"sealed broker did not run the torn analysis for {c}; references missing?")
                if usable:
                    out = classify(rec, approved_pad=t.lay["pad"], etxtbsy=upd["etxtbsy"] > 0)
                    writer.row(dict(base, rep=rep, attempt=attempt), rec, out, upd)
                    break
                writer.row(dict(base, rep=rep, attempt=attempt), rec, None, upd,
                           note=note or f"unusable record: decision={rec and rec.get('decision')}")
                print(f"attempt {attempt} failed: {c} rep {rep}: {note or rec}", file=sys.stderr)
        print(f"controlled {c['policy']:6} {c['change']:7} {c['stage']:9} {c['region'] or '-':6} {c['tear'] or '-':6} "
              f"{c['size']:3} {c['load']:6} done", flush=True)


def interleaved(policies, reps):
    """Yield (policy, count) blocks so that policies alternate every INTERLEAVE_BLOCK launches."""
    done = {p: 0 for p in policies}
    i = 0
    while any(done[p] < reps for p in policies):
        order = policies[i % len(policies):] + policies[:i % len(policies)]
        for p in order:
            n = min(INTERLEAVE_BLOCK, reps - done[p])
            if n > 0:
                yield p, n
                done[p] += n
        i += 1


def run_uncontrolled(cfg, scratch, layout, writer, sizes, loads, reps, stress, regions_filter=None):
    m = cfg["matrices"]["uncontrolled"]
    gaps = cfg["gaps_us"]
    policies = list(m["policies"])
    variants = [("replace", "")] + [("rewrite", r) for r in m["rewrite_regions"]]
    if regions_filter:
        variants = [(c, r) for c, r in variants if (r or c) in regions_filter]
    for load, size, (change, region), gap in itertools.product(loads, sizes, variants, m["gaps"]):
        t = Trial(scratch, size, layout, change, region or None)
        upd_cmd = [str(UPDATER), "--mode", change, "--at", "free", "--target", str(t.target), "--payload", str(t.b),
                   "--alt", str(t.a), "--layout", str(LAYOUT), "--interval-us", m["interval_us"], "--quiet"]
        if change == "rewrite":
            upd_cmd += ["--region", region]
        env = t.env(RP_GAP_US=gaps[gap])
        upd = subprocess.Popen(upd_cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, env=env, cwd=ROOT)
        time.sleep(0.05)
        per_policy = {p: [] for p in policies}
        try:
            for policy, n in interleaved(policies, reps):
                if load == "stress":
                    stress.check()
                if upd.poll() is not None:
                    raise HarnessError(f"updater died (exit {upd.returncode}) mid-cell")
                per_policy[policy].extend(run_broker(policy, env, [str(t.target)] * n))
        finally:
            upd.terminate()
            uout, uerr = upd.communicate(timeout=10)
        info = parse_updater(uout)
        if not uout.strip() or upd.returncode not in (0, -15):
            raise HarnessError(f"updater ended badly (exit {upd.returncode}): {uerr.strip()[:200]}")
        total = sum(len(v) for v in per_policy.values())
        batch = {"batch_launches": total, "batch_updater_writes": info["writes"], "batch_updater_etxtbsy": info["etxtbsy"]}
        for policy, recs in per_policy.items():
            base = dict(matrix="uncontrolled", policy=policy, change=change, stage="free", region=region, tear="",
                        gap=gap, gap_us=gaps[gap], size=size, load=load, attempt=1)
            for rep, rec in enumerate(recs):
                out = classify(rec, approved_pad=t.lay["pad"])
                writer.row(dict(base, rep=rep), rec, out, None, batch)
        print(f"uncontrolled {change:7} {region or '-':5} gap={gap:5} {size:3} {load:6} n={total} "
              f"writes={info['writes']} done", flush=True)


def run_overhead(cfg, scratch, layout, writer, sizes, loads, reps, stress):
    m = cfg["matrices"]["overhead"]
    policies = list(m["policies"])
    for load, size in itertools.product(loads, sizes):
        t = Trial(scratch, size, layout, None, None)
        env = t.env(refs=False)                      # no RP_REF_*: no torn analysis, clean timing
        per_policy = {p: [] for p in policies}
        for policy, n in interleaved(policies, reps):
            if load == "stress":
                stress.check()
            per_policy[policy].extend(run_broker(policy, env, [str(t.target)] * n))
        for policy, recs in per_policy.items():
            base = dict(matrix="overhead", policy=policy, change="", stage="", region="", tear="", gap="none",
                        gap_us=0, size=size, load=load, attempt=1)
            for rep, rec in enumerate(recs):
                out = classify(rec, approved_pad=t.lay["pad"])
                writer.row(dict(base, rep=rep), rec, out, None, {"batch_launches": len(recs)})
        print(f"overhead {size:3} {load:6} n={sum(len(v) for v in per_policy.values())} done", flush=True)


# ---------------------------------------------------------------- main

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--matrix", choices=["controlled", "uncontrolled", "overhead"])
    ap.add_argument("--all", action="store_true")
    ap.add_argument("--out", help="CSV path (default results/<run_id>_<matrix>.csv)")
    ap.add_argument("--reps", type=int)
    ap.add_argument("--sizes", help="comma list, e.g. 64k,1m")
    ap.add_argument("--loads", help="comma list: idle,stress")
    ap.add_argument("--regions", help="uncontrolled only: comma list of variants, e.g. tail or replace,text")
    ap.add_argument("--quick", action="store_true", help="64k, idle, 2 reps")
    ap.add_argument("--run-id", help="label for this run (default: timestamp)")
    args = ap.parse_args()
    if not args.matrix and not args.all:
        ap.error("--matrix or --all")

    check_built()
    scratch = scratch_dir()
    layout = read_layout()
    run_id = args.run_id or time.strftime("%Y%m%dT%H%M%S")
    rev = git_rev()
    matrices = ["controlled", "uncontrolled", "overhead"] if args.all else [args.matrix]
    sizes = args.sizes.split(",") if args.sizes else (["64k"] if args.quick else CONFIG["sizes"])
    loads = args.loads.split(",") if args.loads else (["idle"] if args.quick else CONFIG["loads"])
    regions = CONFIG["regions"]
    print(f"run_id={run_id} git_rev={rev} sizes={sizes} loads={loads}")

    for name in matrices:
        reps = args.reps or (2 if args.quick else CONFIG["matrices"][name]["reps"])
        # Default file name carries the run id so a new run never collides with a committed one
        # (the writer refuses to append to a file whose header differs from its own).
        out = Path(args.out) if (args.out and len(matrices) == 1) else ROOT / "results" / f"{run_id}_{name}.csv"
        writer = Writer(out, run_id, rev)
        stress = Stress()
        try:
            for load in loads:
                if load == "stress":
                    stress.start()
                try:
                    if name == "controlled":
                        run_controlled(CONFIG, scratch, layout, writer, sizes, [load], regions, reps, stress)
                    elif name == "uncontrolled":
                        run_uncontrolled(CONFIG, scratch, layout, writer, sizes, [load], reps, stress,
                                         args.regions.split(",") if args.regions else None)
                    else:
                        run_overhead(CONFIG, scratch, layout, writer, sizes, [load], reps, stress)
                finally:
                    stress.stop()
        except HarnessError as e:
            writer.close()
            sys.exit(f"HARNESS ERROR in {name}: {e}")
        writer.close()
        print(f"wrote {out}")


if __name__ == "__main__":
    main()
