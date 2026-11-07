# RaceProof

Does an AI tool launcher execute the bytes it approved? A controlled measurement of check-to-execution (TOCTOU) mismatches across three launch policies on Linux: pathname, open descriptor, and sealed memfd copy.

CS/CE 232/324 Operating Systems, final project. Ahmed Mujtaba (am09620), Hamna Munib (hm09929), Myrah Hussain (mh10074).

Status: all three policies, the barrier, the updater, the fixtures and the outcome classifier work. The pathname race, the in-place-rewrite race against the descriptor policy, and a copy-time torn copy caught by the sealed policy's post-seal hash are all reproduced. The matrix harness and plots are next.

## Broker usage

```bash
make broker
echo "RUN fixtures/bin/prog_a_1m" | ./broker/broker --policy path    # or fd, sealed
```

One JSON line per request: the decision, the observed hash, what actually ran (`child_output`), timings and errors. Environment: `RP_GAP_US` inserts a sleep between hash and exec; `RP_BARRIER_DIR` points at a directory holding the `to_updater` and `from_updater` FIFOs for controlled interleavings (see `broker/barrier.h`). Sealed policy only: `RP_TEAR_AT` is the byte count after which the `mid_copy` stage fires (default half the file); `RP_REF_A` and `RP_REF_B` name the expected pre- and post-attack images, and when set the broker reports whether the sealed copy is torn (matches neither) and the differing byte range.

## Updater usage

```bash
make updater
# controlled: swap the file at the post_hash stage of the next broker launch
RP_BARRIER_DIR=/path/to/fifos ./updater/updater --mode replace --at post_hash \
    --target /scratch/target --payload fixtures/bin/prog_b_64k --once
# free timing: rewrite .text with B's bytes, then restore A's, every 100-400 us, until killed
./updater/updater --mode rewrite --region text --at free --target /scratch/target \
    --payload fixtures/bin/prog_b_64k --alt fixtures/bin/prog_a_64k --interval-us 100:400
```

The fixtures print two lines, `RACEPROOF_ID=<A|B>` and `RACEPROOF_PAD=<hash of the padding>`. The classifier (`harness/classify.py`) calls a launch CORRECT only if both match the approved program, so a rewrite anywhere in the file is detected even when the ID still prints as A.

## Requirements

- Linux x86-64 with `memfd_create`, file seals and `execveat` (kernel 3.17+; executable memfd policy `vm.memfd_noexec` must not be 2). Developed and measured on WSL2 Ubuntu 26.04, kernel 6.6.
- `gcc`, `make`, `python3`, `binutils` (for `readelf`), `stress-ng`, `python3-matplotlib`, `python3-numpy`, `python3-pytest`.

```bash
sudo apt install -y build-essential binutils python3 stress-ng python3-matplotlib python3-numpy python3-pytest
```

## Quick start (inside WSL)

```bash
make check-env    # must print SUPPORTED; writes results/env.txt
make fixtures     # builds fixtures/bin/prog_{a,b}_{64k,1m,8m,32m}, allowlist.txt, layout.txt
make              # builds broker and updater once their sources exist
make experiment   # runs every matrix in harness/config.yaml (long)
make plots        # regenerates figures from results/*.csv
```

If this clone is on the Windows filesystem (`/mnt/c/...`), that is fine for building. The harness copies fixtures into a scratch directory on WSL's ext4 (default `$HOME/raceproof-scratch`, override with `RP_SCRATCH`) before every trial and refuses to run on anything else, because `rename` and `ETXTBSY` semantics on the Windows bridge are not native Linux.

## Layout

| Path | What |
| --- | --- |
| `tools/check_env.sh` | kernel version, memfd policy, and a live probe that seals a memfd and executes it |
| `fixtures/` | `prog.c` (freestanding, prints its ID), `build.sh`, outputs in `fixtures/bin/` |
| `broker/` | the trusted broker and its three policies |
| `updater/` | the competing updater (replace, rewrite; barrier-controlled or free timing) |
| `harness/` | matrix runner, outcome classifier, `config.yaml` |
| `analysis/` | summary tables and the three plots |
| `results/` | committed CSVs and `env.txt` from the final runs |
| `report/`, `slides/` | final report and presentation |
