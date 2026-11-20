# RaceProof

**Does an AI tool launcher execute the bytes it approved?** A controlled measurement of check-to-execution ([TOCTOU](https://cwe.mitre.org/data/definitions/367.html)) mismatches across three launch policies on Linux: pathname, open descriptor, and sealed memfd copy.

CS/CE 232/324 Operating Systems, final project. Ahmed Mujtaba (am09620), Hamna Munib (hm09929), Myrah Hussain (mh10074).

## Contents

- [What it measures](#what-it-measures)
- [Headline result](#headline-result)
- [Requirements](#requirements)
- [Quick start](#quick-start)
- [Components](#components)
- [Layout](#layout)
- [Result files](#result-files)
- [Limitations](#limitations)
- [References](#references)

## What it measures

A trusted broker approves a program by hashing it against an allowlist, then launches it. A competing updater changes the file in the window between the check and the launch, either by **atomic replacement** (write, then rename) or by **rewriting bytes in place**. Three launch policies are compared:

| Policy | Check and launch sequence | Expected to resist |
| --- | --- | --- |
| `path` | hash the file at a path, close it, `execve` the path | nothing (the baseline) |
| `fd` | open once, hash through the descriptor, `execveat` that descriptor | pathname replacement, not in-place rewrites |
| `sealed` | copy into a memfd, seal it against write/shrink/grow, hash the sealed bytes, `execveat` the memfd | both; the remaining window is the copy itself |

Every launch is classified from **what actually ran**, never from what the broker believed: the fixture programs print their identity, and the harness compares it with the approved program.

The sealed policy is not a new technique. It is the copy, seal, execute sequence that [runc adopted in 2019](https://github.com/opencontainers/runc/commit/0a8e4117e7f715d5fbeef398405813ce8e88558b); this project measures it against the two simpler policies.

## Headline result

Share of free-timing launches that ran unapproved bytes, out of 7,200 per policy per run:

| Policy | Run 4 | Run 2 | Run 1 |
| --- | ---: | ---: | ---: |
| pathname | 20.2% | 19.3% | 19.5% |
| open descriptor | 11.4% | 12.3% | 11.9% |
| sealed copy | **0** | **0** | **0** |

- **Torn copies.** The sealed copy was torn 418 times under free timing across the three runs and 240 more times on purpose in the controlled matrix. Every one was rejected by the hash.
- **Cost.** With the CPU idle, a sealed launch is 10 to 25% slower than a pathname launch with a plain-C hash and 39 to 58% slower with a SHA-NI hash (run 4).

Details, and what did not repeat between runs, are under [Result files](#result-files).

## Requirements

- **Kernel.** Linux x86-64, **3.19 or later**: [`memfd_create`](https://man7.org/linux/man-pages/man2/memfd_create.2.html) and file seals arrived in 3.17, [`execveat`](https://man7.org/linux/man-pages/man2/execveat.2.html) in 3.19. [`vm.memfd_noexec`](https://docs.kernel.org/userspace-api/mfd_noexec.html) must not be 2.
- **Developed and measured on** WSL2 Ubuntu 26.04, kernel 6.6 (gcc 15.2, Python 3.14, matplotlib 3.10.7).
- **Also followed from an empty install of** Ubuntu 24.04 (gcc 13.3, Python 3.12, matplotlib 3.6.3, OpenSSL 3.0.13): the build, the environment check, the tests, a reduced experiment under both loads and the plots all work there.

```bash
sudo apt update      # a new install has empty package lists; without this the next line fails
sudo apt install -y git build-essential binutils python3 stress-ng python3-matplotlib python3-numpy python3-pytest
sudo apt install -y libssl-dev    # only for the optional OpenSSL (SHA-NI) broker build
```

## Quick start

1. **Get the code.**

   ```bash
   git clone https://github.com/p1nkm4ttr/Raceproof.git && cd Raceproof
   ```

2. **Check the environment.** It must print `SUPPORTED`, `experiments: ready` and `plots: ready`. It writes `results/env.txt`, a local file that is not tracked.

   ```bash
   make check-env
   ```

3. **Build the fixtures.** This builds `fixtures/bin/prog_{a,b}_{64k,1m,8m,32m}`, `allowlist.txt` and `layout.txt`, and takes one to four minutes.

   ```bash
   make fixtures
   ```

4. **Build the broker and the updater.** The default broker hashes with a plain-C SHA-256.

   ```bash
   make
   ```

   Optionally build the same broker hashing with OpenSSL EVP, which uses SHA-NI on this CPU. Rows record which hash ran in `hash_impl`. The next `make`, `make quick` or `make experiment` puts the default broker back.

   ```bash
   make broker HASH=openssl
   ```

5. **Run the smoke test.** About ten seconds: the controlled matrix at 64 KiB with 2 repetitions, then a summary.

   ```bash
   make quick
   ```

6. **Run the experiment.** All three matrices into `results/<run>_<matrix>.csv`, about 75 minutes. Add `RUN=name` to label it.

   ```bash
   make experiment
   ```

7. **Draw the figures.** Figures and tables go into `report/figures/`, report versions into `report/figures/paper/`.

   ```bash
   make plots
   ```

**Where measurements run.** The repository may live on the Windows filesystem (`/mnt/c/...`); building there is fine. Measurements never run there: the harness copies fixtures into a scratch directory on a native Linux filesystem (`$HOME/raceproof-scratch`, which is ext4 under WSL; override with `RP_SCRATCH`, no spaces in the path) before every trial and refuses anything that is not ext4, XFS or Btrfs, because `rename` and `ETXTBSY` semantics on the Windows bridge are not Linux's.

## Components

### Fixtures

`fixtures/prog.c` is a freestanding x86-64 program (no libc) built as `prog_a` and `prog_b` at four sizes.

- **What it prints.** Two lines: `RACEPROOF_ID=<A|B> PID=<pid>` and `RACEPROOF_PAD=<64-bit checksum of its padding>`.
- **The checksum** is the FNV-1a loop (xor a byte, multiply by 1099511628211) started from 1469598103934665603, which is **not** the standard FNV offset basis (14695981039346656037). Expected values are derived from the fixtures themselves at build time, so every comparison is self-consistent, but an independent FNV-1a implementation will not reproduce the printed values.
- **The padding** is filled with the program's own ID byte, so A and B differ at every padding byte.
- **What the two lines attest.** The two regions the attacks target, the ID-printing code and the padding. They do not attest the ELF header or any other byte.
- **The allowlist** holds only the four `prog_a` hashes.
- **Build outputs are not tracked.** `fixtures/allowlist.txt` and `fixtures/layout.txt` depend on the compiler: another compiler produces different bytes and therefore different hashes (gcc 13.3 and gcc 15.2 do). The fixtures a published run measured are recorded in `results/<run>_fixtures.txt`.

### Broker

```bash
echo "RUN fixtures/bin/prog_a_1m" | ./broker/broker --policy sealed    # or: --policy path, --policy fd
# optional: --allowlist FILE (default fixtures/allowlist.txt), --timeout-ms N (default 5000)
```

It prints **one JSON line per request**: the decision, the observed hash, what actually ran (`child_output`), timings, byte counts and errors. An example, wrapped here for reading; the PID and the timings vary, and the hash depends on the compiler that built the fixture:

```json
{"policy": "sealed", "hash_impl": "vendored-c", "path": "fixtures/bin/prog_a_1m",
 "observed_hash": "d7b4ae48e836b72f007732fb1a4c7d13532adb6dfdb3f8871755806c725f1ade",
 "allowlisted": true, "decision": "APPROVE", "exec_errno": 0, "exec_errstr": "",
 "exit_status": 0, "signal": 0, "timed_out": 0,
 "child_output": "RACEPROOF_ID=A PID=795\nRACEPROOF_PAD=19fa3825ce6d0383",
 "t_check_us": 3173, "t_copy_us": 722, "t_total_us": 4481, "t_wait_us": 5519,
 "bytes_hashed": 1057464, "bytes_copied": 1057464, "peak_rss_kb": 1024,
 "seal_ok": 1, "torn_checked": 0, "torn": 0, "torn_first": -1, "torn_last": -1, "gap_us": 0}
```

Decisions:

- `APPROVE`: the hash is on the allowlist and exec was attempted.
- `REJECT`: the content failed validation, either not an ELF or its hash is not on the allowlist.
- `ERROR`: the broker itself failed before launching (open, read, memfd, seal). An `ERROR` is **never counted as a prevention**.

Environment variables:

| Variable | Effect |
| --- | --- |
| `RP_GAP_US` | inserts a sleep between hash and exec |
| `RP_BARRIER_DIR` | names a directory holding the `to_updater` and `from_updater` FIFOs for controlled interleavings (`broker/barrier.h`); stages are `pre_hash`, `post_hash` (path, fd), `mid_copy` and `post_seal` (sealed) |
| `RP_TEAR_AT` | sealed only: the byte count after which `mid_copy` fires (default half the file) |
| `RP_REF_A`, `RP_REF_B` | sealed only: the expected pre- and post-attack images. When both are readable the broker reports `torn_checked=1` and whether the sealed copy matches neither (`torn=1`), with the differing byte range |

The reference comparison runs before exec, so `t_total_us` includes it whenever the references are set. Launch-cost numbers come from the overhead matrix, which sets none.

### Updater

```bash
# controlled: swap the file at the post_hash stage of the next broker launch
RP_BARRIER_DIR=/path/to/fifos ./updater/updater --mode replace --at post_hash \
    --target /scratch/target --payload fixtures/bin/prog_b_64k --once
# free timing: rewrite .text with B's bytes, then restore A's, every 100-400 us, until SIGTERM
./updater/updater --mode rewrite --region text --at free --target /scratch/target \
    --payload fixtures/bin/prog_b_64k --alt fixtures/bin/prog_a_64k --interval-us 100:400 --quiet
```

`--region` picks what an in-place rewrite touches:

| Region | Bytes | Difference between A and B |
| --- | --- | --- |
| `header` | 64 bytes at offset 0 | none: a control |
| `text` | the `.text` section from `fixtures/layout.txt` | one byte, the ID |
| `tail` | the last 64 KiB | every byte: the region where a copy-time tear is detectable |

In free mode always pass `--quiet`: the updater counts its writes and `ETXTBSY` refusals internally and prints one summary line on SIGTERM.

### Harness and analysis

Run a matrix, or all of them:

```bash
python3 harness/run_trials.py --matrix controlled --run-id mytest     # or: --matrix uncontrolled, --matrix overhead, --all
#   optional: --sizes 64k,1m  --loads idle,stress  --reps N  --out file.csv  --require-clean
```

Make a complete, publishable run: every matrix with both hashes, from a committed tree only, 50 to 80 minutes. Use a run id not yet in `results/` (`run4` is the published run).

```bash
bash tools/full_run.sh run5
```

Check whether a run's timings are usable. Each file is judged on its own: exit 0 even, 1 an overhead idle cell differs by more than 1.5 times, 2 nothing to compare, 3 too few launches.

```bash
python3 analysis/hash_rate.py results/run4_*.csv
```

Summarise and plot:

```bash
python3 analysis/summarize.py results/controlled.csv
python3 analysis/summarize.py results/overhead.csv --timing
python3 analysis/plots.py --run run4 --overhead-fast results/run4_openssl_overhead.csv --paper   # what make plots runs
python3 analysis/plots.py                                                   # run 1 files
```

Or read a result file directly:

```python
import csv
from collections import Counter

rows = list(csv.DictReader(open("results/run4_uncontrolled.csv", newline="")))
print(Counter((r["policy"], r["outcome"]) for r in rows))
```

The matrices are defined in `harness/config.json`. Each CSV row is one launch with its configuration (policy, change mode, barrier stage, region, tear position, gap, size, load), the outcome, flags, every number the broker reported, and `run_id` and `git_rev` so runs are distinguishable.

What the runner guarantees about its output:

- It **refuses to append** to a CSV whose header differs from its own.
- It writes a **`HARNESS_ERROR` row** for any trial that produced no usable record.
- It **strips every `RP_*` variable** from the inherited environment.
- It **stops** on a record-count mismatch or a dead updater or stress-ng.
- It **interleaves policies** within each cell so timing cannot line up with run order.

Outcomes, decided in this order by `harness/classify.py`:

| Outcome | Meaning |
| --- | --- |
| `REJECT` | the broker refused to launch (hash not on the allowlist, or not an ELF) |
| `EXEC_ERROR` | the broker reported `ERROR`, or exec failed (for example `ETXTBSY` because the file was open for writing), or the child died, or no ID line came back |
| `MISMATCH` | a program ran and its ID or pad hash is not the approved program's: unapproved bytes executed |
| `CORRECT` | the approved program ran, ID and pad hash both matching |
| `HARNESS_ERROR` | the harness could not obtain a usable record for this attempt |

Flags: `torn` (sealed copy matched neither reference), `etxtbsy` (this launch's exec was refused, or a controlled updater write was refused), `unsupported` (executable memfds not permitted), `broker_error`.

Analysis notes:

- `summarize.py` prints counts per configuration with **Wilson 95% intervals** and never a rate without its n.
- **p99 is nearest-rank**, so with the overhead matrix's 50 launches per cell it is the slowest launch.
- `plots.py` exits non-zero when an input is missing or a figure had no rows, and reports only the files it wrote.
- **Memory cost** is reported as bytes copied into the memfd. It is the size of the private copy, not a measure of total system memory.

`plots.py` writes three figures and two tables to `report/figures/`:

1. Mismatch rate against the inserted gap, per policy and attack.
2. Launch time against executable size per policy (median, whisker to p99, from the overhead matrix only).
3. The sealed policy's torn, rejected and mismatched shares against size under a free-timing tail rewrite.

With `--paper` (which `make plots` passes) the same data is also drawn for the report into `report/figures/paper/` as PDF and PNG, one text column wide, greyscale and untitled:

1. Unapproved launches per attack and policy, with sizes, gaps and loads pooled.
2. Which bytes ran when the barrier-controlled attack landed after the policy's last read of the file (after the hash for pathname and open descriptor; after the seal and before the hash for the sealed copy), one tile per attack and policy.
3. The sealed policy's torn-copy rate against size, idle and stress.
4. Launch time against size with the CPU idle, one panel per hash implementation.

## Layout

| Path | What |
| --- | --- |
| `tools/full_run.sh` | one complete run of every matrix with both hashes; refuses to start with uncommitted changes to tracked files, with untracked files in the source directories, onto existing result files, or with options that would change its run id, matrices or output files; rebuilds every binary from scratch and logs its SHA-256; keeps a per-run environment record and log |
| `tools/check_env.sh` | kernel version, memfd policy, filesystem types, and a live probe that creates, seals and executes a memfd with the same flags the broker uses |
| `fixtures/` | `prog.c`, `build.sh`; build outputs, not tracked: `fixtures/bin/`, `allowlist.txt`, `layout.txt` |
| `broker/` | `broker.c` (request loop, fork, JSON record, deadline), `policy_path.c`, `policy_fd.c`, `policy_sealed.c`, `barrier.c`, `sha256.c` (vendored, verified against the FIPS vectors) |
| `updater/` | `updater.c` |
| `harness/` | `run_trials.py`, `classify.py` and its tests, `config.json` |
| `analysis/` | `summarize.py`, `plots.py`, `hash_rate.py` (hash throughput per cell, the check for a run disturbed by other programs) |
| `results/` | committed CSVs, and for runs made by `tools/full_run.sh` an environment record and a log; see [Result files](#result-files) |
| `report/`, `slides/` | final report and presentation |

## Result files

Three runs of the two security matrices are committed (run 1's controlled matrix is one trial short). The overhead matrix was measured with the plain-C hash in each run and with the OpenSSL hash twice, on November 9 and November 20. `make plots` draws run 4, and every figure and table names the files it was drawn from. A new run writes `results/<run_id>_<matrix>.csv` and never touches these files.

| Run | Files | Made | Source | Notes |
| --- | --- | --- | --- | --- |
| 4 (published) | `run4_controlled.csv`, `run4_uncontrolled.csv`, `run4_overhead.csv`, `run4_openssl_overhead.csv`, `run4_env.txt`, `run4_log.txt`, `run4_fixtures.txt` | November 20, by `tools/full_run.sh run4` | commit `ca725dd`, no uncommitted changes | 2,720 + 21,600 + 1,200 + 1,200 launches, no harness errors, no retries, policies' median hash rates within a factor of 1.17 in every idle cell (the check allows 1.5). The run script of that commit checked tracked files only and reused existing binaries; nothing untracked was present and no source had changed since they were built, and the script has since been tightened to enforce both |
| 2 | `run2_controlled.csv`, `run2_uncontrolled.csv`, `run2b_overhead.csv`, `run3b_openssl_overhead.csv` | November 7; the OpenSSL overhead on November 9 | `a3537df-dirty`: an uncommitted tree, so the revision string does not pin the source; `82da746` is the first commit containing all of it | first run on the current harness |
| 1 | `controlled.csv`, `uncontrolled.csv`, `overhead.csv` | November 7 | first harness, 36-column header, no `run_id` or `git_rev` | policies run in a fixed order; controlled has 2,719 rows, one trial having exceeded that harness's 5 s limit |
| kept, not plotted | `run2_overhead.csv`, `run3_openssl_overhead.csv`, `prelim_controlled_64k_nov7.csv` | | | the first was disturbed by other programs on the host (`analysis/hash_rate.py` marks it); the second paid OpenSSL's start-up in every forked child before the broker initialised it once in the parent; the third is the 64 KiB preliminary pass |

Policies are interleaved in blocks of ten in the free-timing and overhead matrices of runs 2 and 4. Controlled configurations run one after another in every run; their outcomes are fixed by the barrier, not by timing. Runs 1 and 2 were made on the same day; run 4 thirteen days later. Runs 1 and 2 predate the per-run environment record and have none.

### What all three runs agree on

- **Sealed copy.** It ran unapproved bytes in 0 of 7,200 free-timing launches in each run (95% upper bound 0.05% per run). Its copy was torn 137, 158 and 123 times under free timing, always under the in-place tail rewrite, and every torn copy was rejected. The controlled matrix forces 80 more tears per run; all 240 were rejected.
- **Open descriptor.** It ran unapproved bytes in 0 of 2,400 launches under replacement in each run, and in 11.9%, 12.3% and 11.4% of all launches, every one an in-place rewrite.
- **Pathname.** It ran unapproved bytes in 19.5%, 19.3% and 20.2% of launches.
- **Controlled matrix.** All 272 configurations gave the same outcome in runs 2 and 4, and in run 1 apart from its one missing trial.
- **The gap under tail rewrite.** Under the in-place tail rewrite, the 200 µs inserted gap was the most dangerous of the three for both vulnerable policies, at both loads, in every run.
  - Pathname mismatches of 800 at gaps of 0, 200 µs and 5 ms: 66, 114, 86 in run 1; 60, 119, 93 in run 2; 38, 103, 69 in run 4.
  - Pooling both vulnerable policies, of the approved launches that ran (an approval followed by an `ETXTBSY` exec refusal is not counted) about 30% ran the rewritten tail with no gap, about 60% at 200 µs and about 47% at 5 ms, in each run (per policy: pathname 28 to 31%, 58 to 64%, 46 to 52%; open descriptor 30 to 33%, 56 to 64%, 42 to 49%).
  - The updater rewrites every 100 to 400 µs, so a gap of about one write interval is when a file that was good at the check has most likely been changed exactly once. This is a reading of the pattern, not something the experiment isolates.
  - The colour figure `fig1_mismatch_vs_gap.png` shows it in its right-hand panel.

### What did not repeat

These are therefore **not claimed**:

- **Per-attack rates** move by several points between days (pathname under replacement: 21.5%, 22.4%, 26.4%).
- **The gap in general.** Mismatch rates did not rise steadily with the inserted gap, and outside the tail rewrite no gap pattern repeated.
- **Executable size.** No trend with executable size appeared in more than one run.
- **CPU stress.** It roughly doubled the 64 KiB tear count in both November 7 runs (15 to 33, 15 to 34 of 300) but not on November 20 (26 idle, 19 under stress).

### Launch cost

- **Absolute times differ between runs.** Comparing CPU-idle medians: with the plain-C hash, 64 KiB and 1 MiB launches took 29 to 43% less time in run 4 than in run 2b and 32 MiB launches 6 to 17% less; with OpenSSL the two measurements are within 15%. Under CPU stress the medians moved more, by up to 47% with the plain-C hash and 31% with OpenSSL. The runs also came from different source states, so the difference is not attributed to the machine alone, and times are quoted as this machine, this run.
- **The ratios are stable for a given hash.**
  - With the plain-C SHA-256 (230 to 340 MB/s across runs) the copy is 8 to 10% of a sealed launch at every size, and hashing is about half of a 64 KiB launch and 90 to 100% above 1 MiB.
  - With OpenSSL's SHA-NI SHA-256 (1.56 to 1.76 GB/s at 1 MiB and above) pathname and descriptor launches are 3 to 5 times faster at 1 MiB and above, and the copy, which runs at about 3 GB/s either way, is 11% of a sealed launch at 64 KiB, about a quarter at 1 MiB and a third at 8 and 32 MiB.
- **The copy's share is not the price of the policy.** A sealed launch is 10 to 25% slower than a pathname launch with the plain-C hash in run 4 (6 to 34% in run 2b) and 39 to 58% slower with SHA-NI (42 to 68% in the November 9 measurement). In run 4 that slowdown equals the copy time to within 0.6 ms at 1 MiB and above.
- **One cell that did not recur.** In run 2b's 32 MiB cell the sealed policy's hash step ran 12 ms slower than the others'; that did not recur and its cause is unknown.

### Keeping the tree clean

- `make check-env`, `make fixtures`, `make` and `make quick` do not modify any tracked file (their outputs are local), so `tools/full_run.sh` can be started after them from the same checkout.
- `make plots` reproduces the committed figures **byte for byte only with the matplotlib version they were drawn with** (3.10.7). With another version the tables come out identical and the images look the same but differ in bytes (checked with 3.6.3), which leaves tracked files modified. This puts the committed ones back:

  ```bash
  git checkout -- report/figures
  ```

## Limitations

- **Fixtures.** Static ELF fixtures only.
- **Attacker.** A same-host attacker on the approval window.
- **Kernel.** The WSL2 build of the 6.6 kernel rather than a distribution kernel.
- **Runs.** Three runs on two days on one laptop, of which only the last was measured from a committed tree.
- **Hash speed.** The default broker hashes with a plain-C SHA-256 (230 to 340 MB/s across runs), which makes hashing a larger share of launch time than a hardware-accelerated hash would. The OpenSSL SHA-NI build bounds that from the other side, and both are reported.
- **Ground truth.** It covers the ID and the padding, the two regions the attacks target, and nothing else.
- **Scope.** None of this is a malware detector. It tests whether approved executable bytes are the bytes that run.

## References

- Linux man-pages, [`memfd_create(2)`](https://man7.org/linux/man-pages/man2/memfd_create.2.html), file sealing section.
- Linux man-pages, [`execveat(2)`](https://man7.org/linux/man-pages/man2/execveat.2.html).
- Linux man-pages, [`fexecve(3)`](https://man7.org/linux/man-pages/man3/fexecve.3.html), NOTES section.
- Linux kernel documentation, [Executable and non-executable memfds](https://docs.kernel.org/userspace-api/mfd_noexec.html).
- A. Sarai and C. Brauner, [nsenter: clone /proc/self/exe to avoid exposing host binary to container](https://github.com/opencontainers/runc/commit/0a8e4117e7f715d5fbeef398405813ce8e88558b), runc commit 0a8e4117, 2019.
- MITRE, [CWE-367: Time-of-check Time-of-use (TOCTOU) Race Condition](https://cwe.mitre.org/data/definitions/367.html).
- D. Dean and A. J. Hu, [Fixing Races for Fun and Profit: How to Use access(2)](https://www.usenix.org/conference/13th-usenix-security-symposium/fixing-races-fun-and-profit-how-use-access2), USENIX Security Symposium, 2004.
