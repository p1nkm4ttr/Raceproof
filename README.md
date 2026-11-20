# RaceProof

Does an AI tool launcher execute the bytes it approved? A controlled measurement of check-to-execution (TOCTOU) mismatches across three launch policies on Linux: pathname, open descriptor, and sealed memfd copy.

CS/CE 232/324 Operating Systems, final project. Ahmed Mujtaba (am09620), Hamna Munib (hm09929), Myrah Hussain (mh10074).

## What it measures

A trusted broker approves a program by hashing it against an allowlist, then launches it. A competing updater changes the file in the window between the check and the launch, either by atomic replacement (write, then rename) or by rewriting bytes in place. Three launch policies are compared:

| Policy | Check and launch sequence | Expected to resist |
| --- | --- | --- |
| `path` | hash the file at a path, close it, `execve` the path | nothing (the baseline) |
| `fd` | open once, hash through the descriptor, `execveat` that descriptor | pathname replacement, not in-place rewrites |
| `sealed` | copy into a memfd, seal it against write/shrink/grow, hash the sealed bytes, `execveat` the memfd | both; the remaining window is the copy itself |

Every launch is classified from what actually ran, never from what the broker believed: the fixture programs print their identity, and the harness compares it with the approved program.

## Requirements

Linux x86-64 with `memfd_create`, file seals and `execveat` (kernel 3.17 or later, `vm.memfd_noexec` not 2). Developed and measured on WSL2 Ubuntu 26.04, kernel 6.6.

```bash
sudo apt install -y build-essential binutils python3 stress-ng python3-matplotlib python3-numpy python3-pytest
sudo apt install -y libssl-dev    # only for the optional OpenSSL (SHA-NI) broker build
```

## Quick start

```bash
make check-env    # must print SUPPORTED, "experiments: ready" and "plots: ready"; writes results/env.txt (local, not tracked)
make fixtures     # builds fixtures/bin/prog_{a,b}_{64k,1m,8m,32m}, allowlist.txt, layout.txt
make              # builds broker/broker and updater/updater (plain-C SHA-256)
make broker HASH=openssl   # same broker hashing with OpenSSL EVP, SHA-NI on this CPU; rows carry hash_impl
make quick        # 10-second smoke test: controlled matrix at 64 KiB, 2 reps, then a summary
make experiment   # all three matrices into results/<run>_<matrix>.csv (about 75 minutes; RUN=name to label it)
make plots        # figures and tables into report/figures/, report versions into report/figures/paper/
```

The repository may live on the Windows filesystem (`/mnt/c/...`); building there is fine. Measurements never run there: the harness copies fixtures into a scratch directory on a native Linux filesystem (`$HOME/raceproof-scratch`, which is ext4 under WSL; override with `RP_SCRATCH`, no spaces in the path) before every trial and refuses anything that is not ext4, XFS or Btrfs, because `rename` and `ETXTBSY` semantics on the Windows bridge are not Linux's.

## Components

### Fixtures

`fixtures/prog.c` is a freestanding x86-64 program (no libc) built as `prog_a` and `prog_b` at four sizes. It prints two lines: `RACEPROOF_ID=<A|B> PID=<pid>` and `RACEPROOF_PAD=<64-bit checksum of its padding>`. The checksum is the FNV-1a loop (xor a byte, multiply by 1099511628211) started from 1469598103934665603, which is not the standard FNV offset basis (14695981039346656037). Expected values are derived from the fixtures themselves at build time, so every comparison is self-consistent, but an independent FNV-1a implementation will not reproduce the printed values. The padding is filled with the program's own ID byte, so A and B differ at every padding byte. The two lines attest the two regions the attacks target, the ID-printing code and the padding; they do not attest the ELF header or any other byte. Only the four `prog_a` hashes are on the allowlist.

### Broker

```bash
echo "RUN fixtures/bin/prog_a_1m" | ./broker/broker --policy sealed    # or: --policy path, --policy fd
# optional: --allowlist FILE (default fixtures/allowlist.txt), --timeout-ms N (default 5000)
```

One JSON line per request: the decision, the observed hash, what actually ran (`child_output`), timings, byte counts and errors. Decisions: `APPROVE` (hash on the allowlist, exec attempted), `REJECT` (content failed validation: not an ELF, or hash not on the allowlist), `ERROR` (the broker itself failed before launching: open, read, memfd, seal). An `ERROR` is never counted as a prevention.

Environment: `RP_GAP_US` inserts a sleep between hash and exec. `RP_BARRIER_DIR` names a directory holding the `to_updater` and `from_updater` FIFOs for controlled interleavings (`broker/barrier.h`); stages are `pre_hash`, `post_hash` (path, fd), `mid_copy` and `post_seal` (sealed). Sealed only: `RP_TEAR_AT` is the byte count after which `mid_copy` fires (default half the file); `RP_REF_A` and `RP_REF_B` name the expected pre- and post-attack images, and when both are readable the broker reports `torn_checked=1` and whether the sealed copy matches neither (`torn=1`) with the differing byte range. That comparison runs before exec, so `t_total_us` includes it whenever the references are set; launch-cost numbers come from the overhead matrix, which sets none.

### Updater

```bash
# controlled: swap the file at the post_hash stage of the next broker launch
RP_BARRIER_DIR=/path/to/fifos ./updater/updater --mode replace --at post_hash \
    --target /scratch/target --payload fixtures/bin/prog_b_64k --once
# free timing: rewrite .text with B's bytes, then restore A's, every 100-400 us, until SIGTERM
./updater/updater --mode rewrite --region text --at free --target /scratch/target \
    --payload fixtures/bin/prog_b_64k --alt fixtures/bin/prog_a_64k --interval-us 100:400 --quiet
```

`--region header|text|tail` picks 64 bytes at offset 0, the `.text` section from `fixtures/layout.txt`, or the last 64 KiB. Header bytes are identical between A and B (a control); text differs in one byte (the ID); the tail differs at every byte (the region where a copy-time tear is detectable). In free mode always pass `--quiet`: the updater counts its writes and ETXTBSY refusals internally and prints one summary line on SIGTERM.

### Harness and analysis

```bash
python3 harness/run_trials.py --matrix controlled --run-id mytest     # or: --matrix uncontrolled, --matrix overhead, --all
#   optional: --sizes 64k,1m  --loads idle,stress  --reps N  --out file.csv  --require-clean
bash tools/full_run.sh run5                 # every matrix with both hashes, from a committed tree only, 50 to 80 minutes; use a run id not yet in results/ (run4 is the published run)
python3 analysis/hash_rate.py results/run4_*.csv   # timing check, each file judged on its own: exit 0 even, 1 an overhead idle cell differs by more than 1.5 times, 2 nothing to compare, 3 too few launches
python3 analysis/summarize.py results/controlled.csv
python3 analysis/summarize.py results/overhead.csv --timing
python3 analysis/plots.py --run run4 --overhead-fast results/run4_openssl_overhead.csv --paper   # what make plots runs
python3 analysis/plots.py                                                   # run 1 files
```

The matrices are defined in `harness/config.json`. Each CSV row is one launch with its configuration (policy, change mode, barrier stage, region, tear position, gap, size, load), the outcome, flags, every number the broker reported, and `run_id` and `git_rev` so runs are distinguishable. The runner refuses to append to a CSV whose header differs from its own, writes a `HARNESS_ERROR` row for any trial that produced no usable record, strips every `RP_*` variable from the inherited environment, stops on a record-count mismatch or a dead updater or stress-ng, and interleaves policies within each cell so timing cannot line up with run order.

Outcomes, decided in this order by `harness/classify.py`:

| Outcome | Meaning |
| --- | --- |
| `REJECT` | the broker refused to launch (hash not on the allowlist, or not an ELF) |
| `EXEC_ERROR` | the broker reported `ERROR`, or exec failed (for example `ETXTBSY` because the file was open for writing), or the child died, or no ID line came back |
| `MISMATCH` | a program ran and its ID or pad hash is not the approved program's: unapproved bytes executed |
| `CORRECT` | the approved program ran, ID and pad hash both matching |
| `HARNESS_ERROR` | the harness could not obtain a usable record for this attempt |

Flags: `torn` (sealed copy matched neither reference), `etxtbsy` (this launch's exec was refused, or a controlled updater write was refused), `unsupported` (executable memfds not permitted), `broker_error`.

`summarize.py` prints counts per configuration with Wilson 95% intervals and never a rate without its n. p99 is nearest-rank, so with the overhead matrix's 50 launches per cell it is the slowest launch. `plots.py` exits non-zero when an input is missing or a figure had no rows, and reports only the files it wrote. It writes three figures and two tables to `report/figures/`: mismatch rate against the inserted gap per policy and attack; launch time against executable size per policy (median, whisker to p99, from the overhead matrix only); and the sealed policy's torn, rejected and mismatched shares against size under a free-timing tail rewrite. Memory cost is reported as bytes copied into the memfd; it is the size of the private copy, not a measure of total system memory. With `--paper` (which `make plots` passes) the same data is also drawn for the report into `report/figures/paper/` as PDF and PNG, one text column wide, greyscale and untitled: unapproved launches per attack and policy with sizes, gaps and loads pooled; which bytes ran when the barrier-controlled attack landed after the policy's last read of the file (after the hash for pathname and open descriptor; after the seal and before the hash for the sealed copy), one tile per attack and policy; the sealed policy's torn-copy rate against size, idle and stress; and launch time against size with the CPU idle, one panel per hash implementation.

## Layout

| Path | What |
| --- | --- |
| `tools/full_run.sh` | one complete run of every matrix with both hashes; refuses to start with uncommitted changes to tracked files, with untracked files in the source directories, onto existing result files, or with options that would change its run id, matrices or output files; rebuilds every binary from scratch and logs its SHA-256; keeps a per-run environment record and log |
| `tools/check_env.sh` | kernel version, memfd policy, filesystem types, and a live probe that creates, seals and executes a memfd with the same flags the broker uses |
| `fixtures/` | `prog.c`, `build.sh`, outputs in `fixtures/bin/`, `allowlist.txt`, `layout.txt` |
| `broker/` | `broker.c` (request loop, fork, JSON record, deadline), `policy_path.c`, `policy_fd.c`, `policy_sealed.c`, `barrier.c`, `sha256.c` (vendored, verified against the FIPS vectors) |
| `updater/` | `updater.c` |
| `harness/` | `run_trials.py`, `classify.py` and its tests, `config.json` |
| `analysis/` | `summarize.py`, `plots.py`, `hash_rate.py` (hash throughput per cell, the check for a run disturbed by other programs) |
| `results/` | committed CSVs, and for runs made by `tools/full_run.sh` an environment record and a log; see Result files |
| `report/`, `slides/` | final report and presentation |

## Result files

Three runs of the two security matrices are committed (run 1's controlled matrix is one trial short). The overhead matrix was measured with the plain-C hash in each run and with the OpenSSL hash twice, on November 9 and November 20. `make plots` draws run 4, and every figure and table names the files it was drawn from. A new run writes `results/<run_id>_<matrix>.csv` and never touches these files. `make check-env`, `make quick` and `make plots` do not modify any tracked file (`results/env.txt` and `results/quick.csv` are local, and regenerating the figures from unchanged data reproduces them byte for byte), so `tools/full_run.sh` can be started after them from the same checkout. Runs 1 and 2 predate the per-run environment record and have none.

| Run | Files | Made | Source | Notes |
| --- | --- | --- | --- | --- |
| 4 (published) | `run4_controlled.csv`, `run4_uncontrolled.csv`, `run4_overhead.csv`, `run4_openssl_overhead.csv`, `run4_env.txt`, `run4_log.txt` | November 20, by `tools/full_run.sh run4` | commit `ca725dd`, no uncommitted changes | 2,720 + 21,600 + 1,200 + 1,200 launches, no harness errors, no retries, policies' median hash rates within a factor of 1.17 in every idle cell (the check allows 1.5). The run script of that commit checked tracked files only and reused existing binaries; nothing untracked was present and no source had changed since they were built, and the script has since been tightened to enforce both |
| 2 | `run2_controlled.csv`, `run2_uncontrolled.csv`, `run2b_overhead.csv`, `run3b_openssl_overhead.csv` | November 7; the OpenSSL overhead on November 9 | `a3537df-dirty`: an uncommitted tree, so the revision string does not pin the source; `82da746` is the first commit containing all of it | first run on the current harness |
| 1 | `controlled.csv`, `uncontrolled.csv`, `overhead.csv` | November 7 | first harness, 36-column header, no `run_id` or `git_rev` | policies run in a fixed order; controlled has 2,719 rows, one trial having exceeded that harness's 5 s limit |
| kept, not plotted | `run2_overhead.csv`, `run3_openssl_overhead.csv`, `prelim_controlled_64k_nov7.csv` | | | the first was disturbed by other programs on the host (`analysis/hash_rate.py` marks it); the second paid OpenSSL's start-up in every forked child before the broker initialised it once in the parent; the third is the 64 KiB preliminary pass |

Policies are interleaved in blocks of ten in the free-timing and overhead matrices of runs 2 and 4. Controlled configurations run one after another in every run; their outcomes are fixed by the barrier, not by timing. Runs 1 and 2 were made on the same day; run 4 thirteen days later.

What all three runs agree on:

- The sealed copy ran unapproved bytes in 0 of 7,200 free-timing launches in each run (95% upper bound 0.05% per run). Its copy was torn 137, 158 and 123 times under free timing, always under the in-place tail rewrite, and every torn copy was rejected. The controlled matrix forces 80 more tears per run; all 240 were rejected.
- The open descriptor ran unapproved bytes in 0 of 2,400 launches under replacement in each run, and in 11.9%, 12.3% and 11.4% of all launches, every one an in-place rewrite.
- The pathname policy ran unapproved bytes in 19.5%, 19.3% and 20.2% of launches.
- All 272 controlled configurations gave the same outcome in runs 2 and 4, and in run 1 apart from its one missing trial.
- Under the in-place tail rewrite, the 200 µs inserted gap was the most dangerous of the three for both vulnerable policies, at both loads, in every run. Pathname mismatches of 800 at gaps of 0, 200 µs and 5 ms: 66, 114, 86 in run 1; 60, 119, 93 in run 2; 38, 103, 69 in run 4. Pooling both vulnerable policies, of the approved launches that ran (an approval followed by an `ETXTBSY` exec refusal is not counted) about 30% ran the rewritten tail with no gap, about 60% at 200 µs and about 47% at 5 ms, in each run (per policy: pathname 28 to 31%, 58 to 64%, 46 to 52%; open descriptor 30 to 33%, 56 to 64%, 42 to 49%). The updater rewrites every 100 to 400 µs, so a gap of about one write interval is when a file that was good at the check has most likely been changed exactly once; this is a reading of the pattern, not something the experiment isolates. The colour figure `fig1_mismatch_vs_gap.png` shows it in its right-hand panel.

What did not repeat, and is therefore not claimed: per-attack rates move by several points between days (pathname under replacement: 21.5%, 22.4%, 26.4%); mismatch rates did not rise steadily with the inserted gap, and outside the tail rewrite no gap pattern repeated; no trend with executable size appeared in more than one run; and CPU stress roughly doubled the 64 KiB tear count in both November 7 runs (15 to 33, 15 to 34 of 300) but not on November 20 (26 idle, 19 under stress).

Absolute launch times differ between runs. Comparing CPU-idle medians: with the plain-C hash, 64 KiB and 1 MiB launches took 29 to 43% less time in run 4 than in run 2b and 32 MiB launches 6 to 17% less; with OpenSSL the two measurements are within 15%. Under CPU stress the medians moved more, by up to 47% with the plain-C hash and 31% with OpenSSL. The runs also came from different source states, so the difference is not attributed to the machine alone, and times are quoted as this machine, this run. The ratios are stable for a given hash. With the plain-C SHA-256 (230 to 340 MB/s across runs) the copy is 8 to 10% of a sealed launch at every size, and hashing is about half of a 64 KiB launch and 90 to 100% above 1 MiB. With OpenSSL's SHA-NI SHA-256 (1.56 to 1.76 GB/s at 1 MiB and above) pathname and descriptor launches are 3 to 5 times faster at 1 MiB and above, and the copy, which runs at about 3 GB/s either way, is 11% of a sealed launch at 64 KiB, about a quarter at 1 MiB and a third at 8 and 32 MiB. The copy's share is not the price of the policy: a sealed launch is 10 to 25% slower than a pathname launch with the plain-C hash in run 4 (6 to 34% in run 2b) and 39 to 58% slower with SHA-NI (42 to 68% in the November 9 measurement). In run 2b's 32 MiB cell the sealed policy's hash step ran 12 ms slower than the others'; that did not recur and its cause is unknown. In run 4 that slowdown equals the copy time to within 0.6 ms at 1 MiB and above.

## Limitations

Static ELF fixtures only; a same-host attacker on the approval window; the WSL2 build of the 6.6 kernel rather than a distribution kernel; three runs on two days on one laptop, of which only the last was measured from a committed tree; the default broker hashes with a plain-C SHA-256 (230 to 300 MB/s), which makes hashing a larger share of launch time than a hardware-accelerated hash would; the OpenSSL SHA-NI build bounds that from the other side, and both are reported. The ground truth covers the ID and the padding, the two regions the attacks target, and nothing else. None of this is a malware detector; it tests whether approved executable bytes are the bytes that run.
