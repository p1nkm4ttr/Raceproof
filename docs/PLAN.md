# RaceProof: complete project plan

Written November 1, 2026. Team: Ahmed Mujtaba (am09620), Hamna Munib (hm09929), Myrah Hussain (mh10074). Course: CS/CE 232/324 Operating Systems. Proposal due November 2; final submission November 26, 11:59 PM.

The proposal (RaceProof_Proposal.tex) says what and why. This file says how and by when. All work happens together on this laptop, in work sessions with everyone present; one person types (the driver) and rotates each session. Everyone has to be able to explain every part for the individual viva, and working in one room on one machine is how that happens.

---

## 1. The machine (checked November 1, 2026)

| Item | Status |
| --- | --- |
| Host | Windows 11 Home, 12 logical CPUs, 24 GB RAM |
| Linux | WSL2, Ubuntu 26.04 LTS, kernel 6.6.114.1-microsoft-standard-WSL2, 12 CPUs and 11 GB visible inside WSL |
| `vm.memfd_noexec` | 0 (executable memfds allowed by default) |
| Sealed-memfd `execveat` probe | **Passed.** A static binary copied into a memfd, sealed with SHRINK, GROW, WRITE and SEAL, then executed with `execveat(AT_EMPTY_PATH)`, ran. This is the feasibility test the options document asked for in week 0. |
| Installed | gcc, make, python3, pip3, readelf, git |
| Missing | stress-ng, matplotlib |

Setup once, inside WSL:

```bash
sudo apt update && sudo apt install -y stress-ng python3-matplotlib python3-numpy python3-pytest
```

Two rules that follow from working in WSL:

1. **The repository is cloned on Windows** at `C:\Users\HP VICTUS\Documents\OS Project Final\Raceproof` (remote: https://github.com/p1nkm4ttr/Raceproof) and committed through GitHub Desktop under Ahmed's account. WSL sees it at `/mnt/c/Users/HP VICTUS/Documents/OS Project Final/Raceproof`, which is fine for editing and building. **Measurements never run there.** The Windows filesystem bridge (v9fs) does not give native `rename`, `ETXTBSY` or timing behaviour, so the harness copies fixtures into a scratch directory on WSL's ext4 (`$HOME/raceproof-scratch`, override with `RP_SCRATCH`) before every trial and refuses any other filesystem. `check_env.sh` prints both filesystem types.
2. **Line endings.** `.gitattributes` forces LF and the clone has `core.autocrlf=false`. A bash script with CRLF fails inside WSL with "syntax error" or "command not found". If that ever happens, `tr -d '\r'` is the diagnosis.
3. **Commit and push at the end of every session.** This laptop is the only machine; the remote is the backup.

The kernel is Microsoft's WSL2 build of 6.6, not a distribution kernel. `results/env.txt` records that, and the report says it in the limitations section. The mechanisms under test (memfd, seals, execveat, rename) are mainline kernel code, so this does not weaken the result.

---

## 2. Definition of done

On November 26 the following exist and work on a fresh WSL distro by following the README alone:

1. A GitHub repository with the broker, updater, fixtures, harness, analysis scripts and README.
2. `make` builds everything; `make check-env` reports kernel support; `make experiment` runs the full matrix; `make plots` regenerates all figures from the CSVs.
3. Three plots: mismatch rate vs check-to-launch gap per policy; launch overhead vs executable size per policy; torn-copy rate and rejection rate for the sealed-copy policy vs size and load.
4. A report in the Part 4 sample format, leading with those plots.
5. A 20-minute presentation with a live demo (10 minutes of Q&A follow).
6. Each member can explain every component for the individual viva.

Grading: presentation 5, viva 10, code 7, report 8. Code that does not run or is poorly documented scores zero, so the fresh-distro README test in week 4 is not optional.

---

## 3. Repository layout

```
raceproof/
  README.md               how to build, check the kernel, run, plot; file map
  Makefile                targets: all, check-env, fixtures, experiment, plots, clean
  tools/
    check_env.sh          kernel version, vm.memfd_noexec, memfd exec probe (the one that passed today)
  fixtures/
    prog.c                one source; -DPROG_ID='A' or 'B' and -DPAD_BYTES=N at build time
    build.sh              builds prog_a and prog_b at 4 sizes each, statically linked
  broker/
    broker.c              request loop, fork/exec, JSON record, timing
    policy_path.c         pathname policy
    policy_fd.c           open-descriptor policy
    policy_sealed.c       sealed-copy policy with mid-copy stage and torn-copy check
    sha256.c / sha256.h   hashing (OpenSSL EVP wrapper, or a vendored single-file SHA-256)
    barrier.c / barrier.h FIFO stage barrier shared with the updater
  updater/
    updater.c             replace mode, rewrite mode, controlled (barrier) and free timing
  harness/
    run_trials.py         builds the matrix, launches broker + updater + stress, classifies, writes CSV
    classify.py           outcome taxonomy (section 5), unit-tested
    config.yaml           the matrices in section 6
  analysis/
    plots.py              the three figures plus the outcome breakdown table
    summarize.py          per-configuration rates with trial counts and 95% Wilson intervals
  results/
    controlled.csv, uncontrolled.csv, overhead.csv, env.txt (committed after the final run)
  report/
    report.tex            Part 4 sample format
    figures/
  slides/
```

Git: `main` only, small commits with clear messages through GitHub Desktop, pushed after every session. No branches are needed when one machine does all the work; a tag `v1.0` marks the submission. The proposal, plan, sources and running log live in `docs/` so the whole team has them.

---

## 4. Component specifications

### 4.1 Fixtures

- `prog.c`: prints `RACEPROOF_ID=<A|B> PID=<pid>` to stdout, flushes, exits 0.
- `PAD_BYTES` embeds a `const` array in `.rodata` so file size can be set without changing behaviour. Sizes: 64 KiB, 1 MiB, 8 MiB, 32 MiB.
- Build: `gcc -O2 -static -DPROG_ID='A' -DPAD_BYTES=... -o prog_a_1m prog.c`. Record the SHA-256 of each `prog_a_*` in `fixtures/allowlist.txt`. No `prog_b` hash is ever on the allowlist.
- `readelf -S` on each fixture gives the `.text` offset; `build.sh` writes it to `fixtures/layout.txt` so the updater can target the code segment.

### 4.2 Broker

One binary, policy chosen by `--policy path|fd|sealed`. Reads tool requests from stdin, one per line: `RUN <path> [args]`. For each request:

1. Record `t_req` with `clock_gettime(CLOCK_MONOTONIC)`.
2. Fork. Child applies the policy and execs; parent waits and reads the child's stdout through a pipe.
3. Parent writes one JSON line per request:
   `{"policy","path","approved_hash","observed_hash","decision","exec_errno","exit_status","signal","child_output","t_check_us","t_copy_us","t_total_us","bytes_copied","peak_rss_kb","seal_ok","torn":{...}}`.

Policies, in the child:

- **path**: `open(path)`, hash by `read` loop, `close`, compare with allowlist, then `execve(path, ...)`. Barrier stages: `pre_hash`, `post_hash`.
- **fd**: `fd = open(path, O_RDONLY|O_CLOEXEC)`, hash through `fd` with `pread`, compare, then `execveat(fd, "", argv, envp, AT_EMPTY_PATH)`. Stages: `pre_hash`, `post_hash`. The fd is never closed and reopened.
- **sealed**: `src = open(path, O_RDONLY)`; `mfd = memfd_create("raceproof", MFD_CLOEXEC|MFD_ALLOW_SEALING)`; copy with a `read`/`write` loop in 64 KiB chunks; after `RP_TEAR_AT` bytes have been copied, fire the `mid_copy` stage; after the copy, `fcntl(mfd, F_ADD_SEALS, F_SEAL_SHRINK|F_SEAL_GROW|F_SEAL_WRITE|F_SEAL_SEAL)`; fire `post_seal`; hash the memfd with `pread`; compare; `execveat(mfd, "", argv, envp, AT_EMPTY_PATH)`. Stages: `pre_hash`, `mid_copy`, `post_seal`. This is exactly the sequence the November 1 probe ran, plus the hash check.
- Validation before exec in every policy: ELF magic plus allowlist hash. A hash mismatch is a **rejection** (decision `REJECT`, no exec). An exec that returns is an **exec error** with errno.
- Torn-copy detection (sealed only): after sealing, compare the memfd bytes with `prog_a` and `prog_b` region by region (header, `.text`, tail) and record which regions match A and which match B. A copy that is neither all-A nor all-B is torn; record the first and last differing offsets.
- Timing: `t_check_us` is hash time; `t_copy_us` is copy plus seal time (sealed only); `t_total_us` is from `t_req` to the child's first byte of output. Peak RSS from `getrusage(RUSAGE_CHILDREN)` after wait.
- `RP_GAP_US`: an inserted `usleep` between hash and exec (0, 200, 5000), used only by the uncontrolled matrix to make the race winnable at a known rate.

### 4.3 Barrier protocol

Two FIFOs under `RP_BARRIER_DIR`. The broker child writes the stage name (`pre_hash\n`, `post_hash\n`, `mid_copy\n`, `post_seal\n`) to `to_updater` and blocks reading `from_updater` until it gets `go\n`. The updater waits for the stage it was told to attack, performs its write, then sends `go`; for other stages it echoes `go` at once. With no `RP_BARRIER_DIR`, the hooks are no-ops, so the measured broker is the production broker apart from a null check.

### 4.4 Updater

`updater --mode replace|rewrite --at <stage>|free --target <path> --payload prog_b_<size> [--region header|text|tail | --offset N --len M] [--interval-us lo:hi]`

- **replace**: write `prog_b` to `<path>.tmp` in the same directory, `fsync`, `rename(tmp, path)`. Atomic; the inode changes.
- **rewrite**: `open(path, O_WRONLY)`, `pwrite` bytes `[offset, offset+len)` of `prog_b` into the same inode. Presets: `header` (offset 0, 64 bytes), `text` (from `layout.txt`), `tail` (last 64 KiB). Record `ETXTBSY` if the kernel refuses because the file is being executed; that is a result, not a bug.
- **controlled**: participate in the barrier at the named stage.
- **free**: loop forever alternating `prog_a` and `prog_b` contents with a random sleep in `[lo, hi]` µs between writes; killed by the harness after the run.

### 4.5 Harness

`run_trials.py --matrix controlled|uncontrolled|overhead --reps N --out results/<name>.csv`

For each configuration: make a scratch directory under `~/raceproof/scratch` (ext4, never `/mnt/c`) with a fresh copy of `prog_a_<size>`, start `stress-ng --cpu 12` if load is `stress`, start the updater, start the broker, send one `RUN` request (controlled) or `N` requests (uncontrolled), collect the JSON lines, kill the updater and stress, classify, append rows. Every row carries: policy, change mode, stage or `free`, gap, size, load, rep, and every broker field.

### 4.6 Analysis

- `summarize.py`: per configuration, the count of each outcome, the rate, and a Wilson 95% interval. Never a rate without its n.
- `plots.py`:
  1. Mismatch rate vs gap, one line per policy, panels for replace and rewrite (uncontrolled matrix).
  2. `t_total_us` median and p99 vs size, one line per policy, plus `bytes_copied` and `peak_rss_kb` (overhead matrix, no updater).
  3. Sealed-copy policy: torn-copy rate and rejection rate vs size, panels per load, controlled `mid_copy` and free timing side by side. The headline figure.
  Plus one table: full outcome breakdown per policy under free timing with stress.

---

## 5. Outcome taxonomy (fixed before any data is collected)

Exactly one primary outcome per trial, decided in this order:

| Outcome | Definition |
| --- | --- |
| `REJECT` | Broker computed a hash not on the allowlist and did not exec. |
| `EXEC_ERROR` | Broker approved, called exec, and exec returned an error, or the child died by signal before printing an ID. The errno or signal is recorded. |
| `MISMATCH` | A program ran and printed an ID that is not the approved program's (`B` ran). The security failure. |
| `CORRECT` | The approved program ran and printed `A`. |

Secondary flags: `torn` (sealed copy neither all-A nor all-B), `etxtbsy` (updater's write refused), `unsupported` (environment refused executable memfd).

A `REJECT` of a torn copy is the sealed-copy policy working as designed. A `MISMATCH` under the sealed policy would mean the hash check or sealing failed; treat it as a bug until proven otherwise, then as a finding.

---

## 6. Experiment matrices and budget

| Matrix | Factors | Configs | Reps | Trials | Est. time on this laptop |
| --- | --- | --- | --- | --- | --- |
| Controlled | 3 policies × 2 change modes × applicable stages (path, fd: 2; sealed: 3, with 3 regions for rewrite at `mid_copy`) × 4 sizes × 2 loads (idle, stress) | about 200 | 10 | about 2,000 | under 30 min |
| Uncontrolled | 3 policies × 2 change modes × 3 gaps × 4 sizes × 2 loads (idle, stress) | 144 | 100 | 14,400 | about 1.5 h, the 32 MiB fixture dominating |
| Overhead | 3 policies × 4 sizes × 2 loads, no updater | 24 | 50 | 1,200 | under 15 min |

Run each matrix twice on different days with nothing else running on the laptop (close the browser, Docker Desktop stopped) and report both. Commit `env.txt` with every CSV. The "LLM inference" load from the proposal is only run if the stretch goal is built; otherwise the report says it was dropped.

Expected shape of results, written down now so surprise can be told from confirmation:

- `path`: `MISMATCH` under both modes at any stage after hash; rate under free timing rises with gap.
- `fd`: `CORRECT` under replace at every stage; `MISMATCH` under rewrite at `post_hash` (same inode changed), unless `ETXTBSY` blocks the write, which is itself a finding.
- `sealed`: never `MISMATCH`. At `mid_copy` with rewrite: `torn=1` and `REJECT` whenever the written region is past the copy cursor; `CORRECT` when it is before. Torn rate under free timing rises with size. Overhead grows linearly with size.

---

## 7. Schedule: work sessions on this laptop

Today is Sunday November 1. Plan on three sessions a week of about three hours, everyone present, driver rotating (Ahmed, Hamna, Myrah, repeat). Each session ends with a commit, a push, and one line in `NOTES.md` saying what works and what is next. The dates below are the targets; the Sunday checkpoints are the only hard gates.

### Week 0: November 1 to 2. Proposal, environment, fixtures

| Session | Work | Done when |
| --- | --- | --- |
| S0, Nov 1 | **Done.** Feasibility probe passed. Repo created and cloned. Layout, Makefile, `.gitattributes`, `.gitignore`, README, `tools/check_env.sh`, `fixtures/prog.c` and `build.sh` written; `make check-env` prints SUPPORTED and `make fixtures` builds all 8 fixtures, which run and print the right ID. stress-ng, matplotlib, numpy and pytest installed. Still to do: first commit and push from GitHub Desktop. | First commit pushed. |
| S1, Nov 2 | Check the shared class Google Doc for any TOCTOU or agent-launch question, then enter our question and three names. Submit the proposal PDF. Then start S2 early. | Class doc entry made; proposal submitted. |

### Week 1: November 3 to 9. Baseline race reproduced

| Session | Work | Done when |
| --- | --- | --- |
| S2, Nov 3 or 4 | `harness/classify.py` with the section 5 taxonomy and its tests (small, do it first so everyone agrees on the outcomes). `broker.c` request loop, fork/exec, JSON output, timing. `policy_path.c`. | `echo "RUN fixtures/prog_a_64k" \| broker --policy path` prints a CORRECT JSON line; `pytest` passes. |
| S3, Nov 5 or 6 | `policy_fd.c`. `barrier.c`. `updater.c` replace mode with controlled and free timing. | Updater at `post_hash` with replace makes `path` print MISMATCH every time and `fd` print CORRECT every time, by hand. |
| S4, Nov 7 or 8 | `run_trials.py` v0: one configuration end to end into CSV; `summarize.py` v0. Run the `path` and `fd` rows of the controlled matrix at 64 KiB. | A table of rates with n=10 reproduces the pathname race from the CSV. |
| Nov 9 | **Checkpoint: pathname race reproduced and recorded in `results/`.** Push. | |

### Week 2: November 10 to 16. Three policies and the copy-time race

| Session | Work | Done when |
| --- | --- | --- |
| S5, Nov 10 or 11 | `policy_sealed.c` with `mid_copy`, `post_seal`, `RP_TEAR_AT`, torn-copy region check, `peak_rss`. `RP_GAP_US`. | Sealed policy prints CORRECT with no updater; with the updater at `mid_copy` rewriting the tail it prints REJECT with `torn=1`. |
| S6, Nov 12 or 13 | Updater rewrite mode with `header`, `text`, `tail` presets and `ETXTBSY` reporting. stress-ng integration in the harness. Full `config.yaml`. | Controlled matrix runs for all three policies, both modes, every stage, at 64 KiB and 1 MiB. |
| S7, Nov 14 or 15 | `plots.py` v0 for plots 1 and 2. README first draft (build, check-env, one-command run). Run the full controlled matrix at all sizes, idle. | Plots 1 and 2 render from the controlled CSV. |
| Nov 16 | **Checkpoint: all three policies compared; copy-time interleaving working.** Push. | |

### Week 3: November 17 to 22. Sweeps, repetition, README

| Session | Work | Done when |
| --- | --- | --- |
| S8, Nov 17 or 18 | Fix whatever week 2 exposed. Start the uncontrolled matrix running (about 1.5 h; let it run while writing plot 3). Plot 3, outcome table, Wilson intervals. | Plot 3 renders from the first uncontrolled run. |
| S9, Nov 19 or 20 | Overhead matrix. Second run of every matrix. Controlled matrix under stress. Decide the stretch goal: only if everything above is green, a 50-line Python loop that calls a local model and routes tool calls through `broker --policy sealed`; otherwise drop it and write that down. | `results/` holds every CSV from two runs plus `env.txt`. |
| S10, Nov 21 | **Fresh-distro README test.** Install a second WSL distro (`wsl --install -d Ubuntu-24.04` or import a copy), clone the repo there, and follow the README with no help from whoever wrote it. Every problem becomes a README fix. `make plots` from a clean clone. | A clean clone builds, checks, and regenerates every figure. |
| Nov 22 | **Checkpoint: repetitions done, figures final, README passes.** Push. | |

### Week 4: November 23 to 26. Report, slides, demo, viva

| Session | Work | Done when |
| --- | --- | --- |
| S11, Nov 23 | Report in the Part 4 sample format: abstract, question, background (the 8 proposal references, more from SOURCES.md if the sample wants related work), design, experiments, results with the three plots, limitations (static ELF only, same-host attacker, WSL2 kernel, mechanism is runc's), conclusion. Everyone writes; split by section in the room. | Full draft by end of session. |
| S12, Nov 24 | Slides (section 8). Demo script with exact commands, rehearsed to under 5 minutes. Record the demo as a video fallback. | Slides done; video in `slides/`. |
| S13, Nov 25 | Rehearsal: full 20-minute run, then every member answers every question in section 9 aloud. Final `make clean && make && make check-env && make plots` on the clean clone. Code comments pass. | Everyone can answer every viva question. |
| Nov 26 | Final read of the report. Tag `v1.0`. **Submit by 21:00**, not 23:50. | Submitted. |

---

## 8. Presentation outline (20 minutes plus 10 Q&A)

1. The gap in one slide: hash a file, exec the path, another process swaps it (1 min).
2. Why an agent launcher cares; the fexecve manual says the descriptor does not stop content changes (2 min).
3. The three policies as one diagram; copy, seal, validate, execute (2 min).
4. The harness: barriers make races deterministic, then free timing (2 min).
5. **Live demo** on this laptop in WSL (5 min): approve A, swap, show B under `path`, A under `fd`; rewrite in place, show mismatch under `fd`; rewrite mid-copy, show REJECT with `torn=1` under `sealed`.
6. Results: plot 1, plot 2, plot 3 with trial counts (5 min).
7. Limitations and what we did not claim: static ELF only, same-host attacker, WSL2 kernel, mechanism is runc's (2 min).
8. Conclusion: what a sealed copy buys, what it costs, where it is still not atomic (1 min).

---

## 9. Viva question bank (every member answers every one)

- Why does an open file descriptor survive `rename` but not an in-place write? (inode vs directory entry)
- What does `F_SEAL_WRITE` do to existing shared writable mappings, and why does the broker not have any?
- Why hash after sealing and not before copying?
- What does `vm.memfd_noexec=2` do, and what is it on our machine?
- What is `AT_EMPTY_PATH` in `execveat`?
- Why statically linked fixtures?
- What is `ETXTBSY` and when did we see it?
- What is a torn copy, and can one ever be a valid ELF that runs?
- Why report rejections separately from exec errors?
- Why is the result a measurement and not a proof?
- How does our contribution differ from runc's fix for CVE-2019-5736?
- Why did results have to come from the WSL ext4 filesystem and not `/mnt/c`?
- How many trials, and what is the confidence interval on the headline rate?

---

## 10. Risks and fallbacks

| Risk | Signal | Fallback |
| --- | --- | --- |
| Laptop fails or Windows update breaks WSL | | Repo pushed after every session; a fresh `wsl --install` plus the README restores everything in under an hour. |
| Results taken on `/mnt/c` by mistake | odd `rename` or `ETXTBSY` behaviour, slow runs | Harness refuses to run unless `scratch/` is on ext4 (`stat -f -c %T` returns `ext2/ext3`). |
| `fd` policy never mismatches under rewrite because `ETXTBSY` blocks the updater | `etxtbsy=1` in every rewrite row | A real finding: the kernel protects a running image, not a checked one. The `post_hash` barrier fires before exec, so the write should land; report whichever happens. |
| Free-timing races never land | mismatch rate 0 at every gap | Increase the `long` gap; report controlled results as primary, free timing as supporting. |
| Uncontrolled matrix too slow | over 3 h | 50 reps at 32 MiB, 100 elsewhere; say so. |
| A session is missed | Sunday checkpoint slips | The next session takes the smallest unfinished item first; Nov 9 and Nov 16 are the only hard gates. |
| Stretch LLM integration eats week 3 | not green by Nov 19 | Drop it; the proposal says it is optional. |
| Demo fails live | | Play the Nov 24 video. |

---

## 11. Checklist for November 26

- [ ] Class Google Doc entry made (Nov 2)
- [ ] `results/env.txt` committed from `make check-env`
- [ ] All CSVs from two runs committed
- [ ] `make plots` regenerates all three figures on a clean clone
- [ ] README passed the fresh-distro test by someone who did not write it
- [ ] Report in Part 4 format, figures embedded, references complete
- [ ] Slides and demo video
- [ ] Release tagged `v1.0`
- [ ] Submitted before 21:00
