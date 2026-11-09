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
make check-env    # must print SUPPORTED; writes results/env.txt
make fixtures     # builds fixtures/bin/prog_{a,b}_{64k,1m,8m,32m}, allowlist.txt, layout.txt
make              # builds broker/broker and updater/updater (plain-C SHA-256)
make broker HASH=openssl   # same broker hashing with OpenSSL EVP, SHA-NI on this CPU; rows carry hash_impl
make quick        # 10-second smoke test: controlled matrix at 64 KiB, 2 reps, then a summary
make experiment   # all three matrices into results/<run>_<matrix>.csv (about 75 minutes; RUN=name to label it)
make plots        # figures and tables into report/figures/ from the run 2 CSVs
```

The repository may live on the Windows filesystem (`/mnt/c/...`); building there is fine. Measurements never run there: the harness copies fixtures into a scratch directory on WSL's ext4 (`$HOME/raceproof-scratch`, override with `RP_SCRATCH`, no spaces in the path) before every trial and refuses any other filesystem, because `rename` and `ETXTBSY` semantics on the Windows bridge are not Linux's.

## Components

### Fixtures

`fixtures/prog.c` is a freestanding x86-64 program (no libc) built as `prog_a` and `prog_b` at four sizes. It prints two lines: `RACEPROOF_ID=<A|B> PID=<pid>` and `RACEPROOF_PAD=<FNV-1a 64 of its padding>`. The padding is filled with the program's own ID byte, so A and B differ at every padding byte. The two lines attest the two regions the attacks target, the ID-printing code and the padding; they do not attest the ELF header or any other byte. Only the four `prog_a` hashes are on the allowlist.

### Broker

```bash
echo "RUN fixtures/bin/prog_a_1m" | ./broker/broker --policy path|fd|sealed [--allowlist file] [--timeout-ms N]
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
python3 harness/run_trials.py --matrix controlled|uncontrolled|overhead [--sizes 64k,1m] [--loads idle,stress] [--reps N] [--run-id label] [--out file.csv]
python3 analysis/summarize.py results/controlled.csv
python3 analysis/summarize.py results/overhead.csv --timing
python3 analysis/plots.py --run run2 --overhead results/run2b_overhead.csv   # what make plots runs
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

`summarize.py` prints counts per configuration with Wilson 95% intervals and never a rate without its n. p99 is nearest-rank. `plots.py` writes three figures and two tables to `report/figures/`: mismatch rate against the inserted gap per policy and attack; launch time against executable size per policy (median, whisker to p99, from the overhead matrix only); and the sealed policy's torn, rejected and mismatched shares against size under a free-timing tail rewrite. Memory cost is reported as bytes copied into the memfd; it is the size of the private copy, not a measure of total system memory.

## Layout

| Path | What |
| --- | --- |
| `tools/check_env.sh` | kernel version, memfd policy, filesystem types, and a live probe that creates, seals and executes a memfd with the same flags the broker uses |
| `fixtures/` | `prog.c`, `build.sh`, outputs in `fixtures/bin/`, `allowlist.txt`, `layout.txt` |
| `broker/` | `broker.c` (request loop, fork, JSON record, deadline), `policy_path.c`, `policy_fd.c`, `policy_sealed.c`, `barrier.c`, `sha256.c` (vendored, verified against the FIPS vectors) |
| `updater/` | `updater.c` |
| `harness/` | `run_trials.py`, `classify.py` and its tests, `config.json` |
| `analysis/` | `summarize.py`, `plots.py` |
| `results/` | committed CSVs and `env.txt`; see Result files |
| `report/`, `slides/` | final report and presentation |

## Result files

Two complete runs of every matrix are committed. Run 1 (`controlled.csv`, `overhead.csv`, `uncontrolled.csv`) was produced by the first harness, with a 36-column header and policies run in order. Run 2 (`run2_controlled.csv`, `run2_overhead.csv`, `run2_uncontrolled.csv`) is the replication on the current harness, with `run_id` and `git_rev` on every row and policies interleaved. `run2_overhead.csv` is kept as data but not plotted: its launch times were inflated by other programs running on the host at the time, which shows as hash throughput far below the controlled matrix's and uneven across policies inside one cell. `run2b_overhead.csv` is the overhead matrix rerun on an otherwise idle machine and is what the figures use. Every figure and table names the files it was drawn from. `run3b_openssl_overhead.csv` is the overhead matrix from the OpenSSL (SHA-NI) broker build (`make broker HASH=openssl`), every row tagged `hash_impl=openssl-evp`; it is the second row of figure 2. `run3_openssl_overhead.csv` is the first attempt at that run and is kept but not plotted: the broker then initialised OpenSSL lazily in each forked child, which added about half a millisecond of library start-up to every launch (the fix initialises once in the parent). `prelim_controlled_64k_nov7.csv` is the 64 KiB preliminary pass. A new run writes `results/<run_id>_<matrix>.csv` and never touches these files; plot it with `python3 analysis/plots.py --run <run_id>`.

Absolute launch times differ between runs by 25 to 40% with no code change, so quote them as this machine, this run. The ratios are stable for a given hash: with the plain-C SHA-256 (230 to 300 MB/s) the copy is 8 to 10% of a sealed launch at every size and hashing is about half of a 64 KiB launch and 90 to 99% above 1 MiB; with OpenSSL's SHA-NI SHA-256 (1.6 to 1.75 GB/s on this CPU) path and fd launches are 3 to 5× faster, the copy, which runs at about 3 GB/s either way, becomes 11% of a sealed launch at 64 KiB, 25% at 1 MiB and a third at 8 and 32 MiB, and the sealed policy's premium over the pathname policy rises from 1.06 to 1.35× to 1.4 to 1.7×.

## Limitations

Static ELF fixtures only; a same-host attacker on the approval window; the WSL2 build of the 6.6 kernel rather than a distribution kernel; the default broker hashes with a plain-C SHA-256 (230 to 300 MB/s), which makes hashing a larger share of launch time than a hardware-accelerated hash would; the OpenSSL SHA-NI build bounds that from the other side, and both are reported. The ground truth covers the ID and the padding, the two regions the attacks target, and nothing else. None of this is a malware detector; it tests whether approved executable bytes are the bytes that run.
