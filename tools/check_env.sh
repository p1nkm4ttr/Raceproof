#!/bin/bash
# RaceProof environment check. Run inside WSL/Linux: bash tools/check_env.sh
# Prints SUPPORTED or UNSUPPORTED with reasons and writes results/env.txt, or the file named
# as the first argument (tools/full_run.sh keeps one environment record per run that way).
# SUPPORTED is about the kernel, filesystem and compiler: the sealed policy can run here.
# The "experiments" and "plots" lines say whether the rest of the toolchain is present.
# Never changes any sysctl.

set -u
cd "$(dirname "$0")/.." || exit 1
mkdir -p results
OUT="${1:-results/env.txt}"
ok=1
: > "$OUT"

log() { echo "$*" | tee -a "$OUT"; }

log "date: $(date -Iseconds)"
log "kernel: $(uname -r)"
log "arch: $(uname -m)"
. /etc/os-release 2>/dev/null && log "distro: ${PRETTY_NAME:-unknown}"
log "nproc: $(nproc)"
log "mem_total_kb: $(awk '/MemTotal/{print $2}' /proc/meminfo)"
if grep -qi microsoft /proc/version; then log "wsl: yes"; else log "wsl: no"; fi
log "cpu: $(awk -F': ' '/model name/{print $2; exit}' /proc/cpuinfo)"
if grep -qw sha_ni /proc/cpuinfo; then log "cpu_sha_ni: yes"; else log "cpu_sha_ni: no"; fi
log "openssl: $(openssl version 2>/dev/null || echo absent)"
if [ -r /usr/include/openssl/evp.h ]; then log "libssl-dev: present (make broker HASH=openssl available)"; else log "libssl-dev: absent (default plain-C hash only)"; fi

if [ -r /proc/sys/vm/memfd_noexec ]; then
  noexec=$(cat /proc/sys/vm/memfd_noexec)
  log "vm.memfd_noexec: $noexec"
  if [ "$noexec" = "2" ]; then log "FAIL: vm.memfd_noexec=2 forbids executable memfds"; ok=0; fi
else
  log "vm.memfd_noexec: (absent; kernel older than 6.3, memfds executable by default)"
fi

for t in gcc make python3 readelf stress-ng; do
  if command -v "$t" >/dev/null 2>&1; then log "tool $t: $(command -v "$t")"; else log "tool $t: MISSING"; [ "$t" = stress-ng ] || ok=0; fi
done
python3 -c "import matplotlib, numpy" 2>/dev/null && log "python: matplotlib+numpy ok" || log "python: matplotlib/numpy MISSING (needed for plots only)"

fstype=$(stat -f -c %T "$PWD" 2>/dev/null || echo unknown)
log "repo_fstype: $fstype"
scratch="${RP_SCRATCH:-$HOME/raceproof-scratch}"
mkdir -p "$scratch" 2>/dev/null
sfs=$(stat -f -c %T "$scratch" 2>/dev/null || echo unknown)
log "scratch: $scratch ($sfs)"
case "$sfs" in ext2/ext3|ext4|xfs|btrfs) ;; *) log "FAIL: scratch dir must be on a native Linux filesystem, got $sfs"; ok=0;; esac

# Live probe: copy a static binary into a memfd, seal it, execveat it.
probe_src=$(mktemp /tmp/rp_probe_XXXX.c)
probe_bin="${probe_src%.c}"
cat > "$probe_src" <<'EOF'
#define _GNU_SOURCE
#include <sys/mman.h>
#include <sys/syscall.h>
#include <fcntl.h>
#include <unistd.h>
#include <stdio.h>
#include <errno.h>
#include <string.h>
extern char **environ;
int main(int argc, char **argv) {
  const char *target = argc > 1 ? argv[1] : "/bin/true";
  int src = open(target, O_RDONLY);
  if (src < 0) { printf("probe: open %s failed: %s\n", target, strerror(errno)); return 2; }
  /* Same creation path as broker/policy_sealed.c: ask for MFD_EXEC, fall back on kernels that do not know it. */
#ifndef MFD_EXEC
#define MFD_EXEC 0x0010U
#endif
  int m = syscall(SYS_memfd_create, "rp_probe", MFD_CLOEXEC | MFD_ALLOW_SEALING | MFD_EXEC);
  if (m < 0 && errno == EINVAL) { printf("probe: MFD_EXEC unknown to this kernel, retrying without it\n");
    m = syscall(SYS_memfd_create, "rp_probe", MFD_CLOEXEC | MFD_ALLOW_SEALING); }
  if (m < 0) { printf("probe: memfd_create failed: %s\n", strerror(errno)); return 2; }
  char b[65536]; ssize_t n;
  while ((n = read(src, b, sizeof b)) > 0) if (write(m, b, n) != n) { printf("probe: write failed\n"); return 2; }
  if (fcntl(m, F_ADD_SEALS, F_SEAL_SHRINK | F_SEAL_GROW | F_SEAL_WRITE | F_SEAL_SEAL) < 0) {
    printf("probe: F_ADD_SEALS failed: %s\n", strerror(errno)); return 2; }
  printf("probe: seals=0x%x\n", fcntl(m, F_GET_SEALS));
  fflush(stdout); /* execveat replaces the process; unflushed stdio output is lost */
  char *av[] = { "true", 0 };
  syscall(SYS_execveat, m, "", av, environ, AT_EMPTY_PATH);
  printf("probe: execveat failed: %s\n", strerror(errno));
  return 2;
}
EOF
if gcc -O2 -o "$probe_bin" "$probe_src" 2>>"$OUT"; then
  if "$probe_bin" | tee -a "$OUT"; then :; fi
  "$probe_bin" >/dev/null 2>&1; rc=$?
  if [ $rc -eq 0 ]; then log "probe: execveat on sealed memfd OK"; else log "FAIL: sealed memfd did not execute (rc=$rc)"; ok=0; fi
else
  log "FAIL: probe did not compile"; ok=0
fi
rm -f "$probe_src" "$probe_bin"

if command -v stress-ng >/dev/null 2>&1; then log "experiments: ready"
else log "experiments: NOT READY (stress-ng missing; the CPU-stress half of every matrix cannot run)"; fi
if python3 -c "import matplotlib" 2>/dev/null; then log "plots: ready"
else log "plots: NOT READY (python3-matplotlib missing)"; fi

if [ $ok -eq 1 ]; then log "RESULT: SUPPORTED"; exit 0; else log "RESULT: UNSUPPORTED"; exit 1; fi
