# RaceProof

Does an AI tool launcher execute the bytes it approved? A controlled measurement of check-to-execution (TOCTOU) mismatches across three launch policies on Linux: pathname, open descriptor, and sealed memfd copy.

CS/CE 232/324 Operating Systems, final project. Ahmed Mujtaba (am09620), Hamna Munib (hm09929), Myrah Hussain (mh10074).

Status: skeleton. See `docs/PLAN.md` for the full plan and `docs/NOTES.md` for the running log.

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
| `docs/` | proposal (LaTeX and PDF), plan, sources, running log |
| `report/`, `slides/` | final report and presentation |
