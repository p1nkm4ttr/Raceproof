# RaceProof project log

Running record of everything significant: decisions, trip-ups, findings, surprising results, workarounds. Newest entry at the bottom. Add to this at the end of every session and whenever something breaks or surprises us. This is the raw material for the report's limitations section and for viva answers.

Format per entry: date, tag, what happened, what we did about it.
Tags: DECISION, ISSUE, FINDING, RESULT, WORKAROUND, DEADLINE.

---

## 2026-10-28

- **DECISION.** Professor chose RaceProof from the five options. Team: Ahmed Mujtaba, Hamna Munib, Myrah Hussain. Three members, not four.
- **DECISION.** Proposal is written in LaTeX (RaceProof_Proposal.tex), compiled with the MiKTeX already on this laptop. The first draft document is superseded; the .tex is the master copy.
- **ISSUE.** A literature check came back claiming RaceProof's novelty was "no longer defensible" because runc and three public agent tool runners already do copy-seal-execute. All five cited items were verified real (Sandlock, VirusTotal MCP control.md, WORKSPACE-GUARD, control-stack PR 23, .CMPCT PR 379).
- **DECISION.** Keep the project. The options document already framed it as an applied measurement study with a narrow claim. Reframed the proposal to say so explicitly: a controlled measurement of an established mechanism, not a new technique.
- **DECISION.** Sharpened the experiment around the copy-time race. The .CMPCT PR states in writing that a sealed clone is not an atomic snapshot while the original is being copied; nobody has measured how often a mid-copy write produces a torn copy or whether hash-after-seal catches every one. That is now the headline result (plot 3).
- **FINDING.** The fexecve(3) NOTES section predicts two of our three results outright: executing through a descriptor avoids the pathname race but does not stop the file's contents changing. Only the sealed-copy case is genuinely open. Cite it; do not present the path and fd results as discoveries.
- **WORKAROUND.** The proposal's bibliography had grown to 23 entries. Cut to 8 in the proposal; the full annotated list lives in SOURCES.md for the report and viva.

## 2026-11-01

- **DECISION.** All work happens on this laptop, together, in sessions with a rotating driver. No separate VM, no parallel per-person tracks. PLAN.md rewritten accordingly.
- **RESULT. Feasibility probe passed.** WSL2 Ubuntu 26.04, kernel 6.6.114.1-microsoft-standard-WSL2, `vm.memfd_noexec = 0`. A static binary copied into a memfd, sealed with SHRINK|GROW|WRITE|SEAL, then run with `execveat(mfd, "", argv, envp, AT_EMPTY_PATH)` executed correctly. The core mechanism works on this machine with no sysctl changes. Probe source will become `tools/check_env.sh`.
- **ISSUE.** stress-ng and matplotlib are not installed in WSL. Install: `sudo apt install -y stress-ng python3-matplotlib python3-numpy python3-pytest`.
- **ISSUE / WORKAROUND.** Passing a multi-line bash script with heredocs and parentheses through `wsl -- bash -c "..."` from PowerShell broke on quoting. Workaround: write the script to a file and run `wsl -d Ubuntu -- bash -c "tr -d '\r' < '/mnt/c/.../script.sh' | bash"`. The `tr -d '\r'` matters because files written from Windows may carry CRLF line endings, which make bash fail with "syntax error" or "command not found" on otherwise correct scripts.
- **DECISION.** Repository lives at `~/raceproof` on WSL's ext4, never under `/mnt/c`. Reason: the Windows filesystem bridge (drvfs/9p) does not give native Linux semantics for `rename`, `ETXTBSY` or timing, and would invalidate the measurements. The harness will refuse to run on a non-ext4 scratch directory.
- **DECISION.** Note in env.txt and the report that the kernel is Microsoft's WSL2 build of 6.6, not a distro kernel. The mechanisms under test are mainline code, so this is a limitation to state, not a threat to the result.
- **DEADLINE.** November 2: enter the research question and three names in the class Google Doc after checking for overlap; submit the proposal PDF. November 26, 11:59 PM: final submission. Internal target: submit by 21:00.
- **DECISION.** Repo is https://github.com/p1nkm4ttr/Raceproof, cloned on Windows under the project folder, committed via GitHub Desktop under Ahmed's account. Earlier plan to keep the clone on WSL ext4 is replaced: build on `/mnt/c` is fine, only the race scratch directory must be ext4 (`$HOME/raceproof-scratch`). `check_env.sh` reports the repo as `v9fs` and the scratch as `ext2/ext3`, which is the intended split. Proposal, plan, sources and this log moved into `docs/`.
- **RESULT.** `tools/check_env.sh` on the clone: SUPPORTED. seals=0xf after `F_ADD_SEALS`, execveat on the sealed memfd OK. `results/env.txt` written.
- **RESULT.** Fixtures build freestanding (no libc, raw syscalls, `-nostdlib -nostartfiles`): sizes 74,392 / 1,057,432 / 8,397,464 / 33,563,288 bytes for the 64k/1m/8m/32m variants, A and B identical in size. `.text` is 322 bytes at offset 4096 in every one. All eight run and print their ID.
- **ISSUE / WORKAROUND.** `fixtures/build.sh` failed silently under `set -e`. Two causes: `readelf -S` prints `[ 1]` with a space for section indices under 10, which shifts awk's field numbers; and Ubuntu's default awk is mawk, which has no `strtonum`. Fix: normalise the bracket with sed, convert hex in bash with `$((16#...))`.
- **ISSUE / WORKAROUND.** The probe's `printf` of the seal value vanished because `execveat` replaces the process before stdio flushes. Added `fflush(stdout)` before the exec. The broker must do the same before every exec, or use `write(2)` directly.
- **FINDING (design).** With a zero-filled pad, prog_a and prog_b differed in only two bytes (the ID in `.text` and the first pad byte). A mid-copy rewrite of B's tail into A would then be byte-identical to A, so tearing in the tail would be invisible and harmless by construction, which would make plot 3 meaningless for tail regions. Fixed by filling the entire pad with the program's ID (`[0 ... N-1] = PROG_ID`), so A and B differ at every pad byte and a torn copy is detectable at any offset. Allowlist hashes changed as a result; rebuild before use.
- **ISSUE / WORKAROUND.** Multi-line commands passed to `wsl -- bash -c "..."` from PowerShell keep breaking on quoting. Standard practice now: write the script to a file, run `tr -d '\r' < file | bash`.
- **RESULT.** Dependencies installed in WSL as root (`wsl -u root`, no sudo password needed): stress-ng, python3-matplotlib 3.10.7, numpy 2.3.5, pytest 9.0.2. `make check-env` should now show no MISSING tools. Week 0 environment work is complete.

---

## Open questions to answer with data (move to RESULT when answered)

- Does `ETXTBSY` block the updater's in-place rewrite under the fd policy at the `post_hash` stage, or does the write land because exec has not started yet? Either answer is a finding.
- Can a torn copy ever be a valid ELF that passes the magic check and runs? If yes, the hash check is the only line of defence; record every such case.
- How does torn-copy rate scale with fixture size under free timing: linear with copy time, or something else?
- Does stress-ng CPU load widen or narrow the copy window on this 12-CPU machine?
