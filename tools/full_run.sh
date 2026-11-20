#!/bin/bash
# One complete run for publication, from a tree with no uncommitted changes, so that the
# git_rev on every row names the source that produced it. To make that hold it refuses to
# start when a tracked file is modified or when an untracked file sits where the build or
# the harness would pick it up, and it rebuilds every binary from scratch and logs their
# SHA-256. It cannot vouch for the compiler and libraries; results/<run>_env.txt names them.
#
#     bash tools/full_run.sh run5                  # a run id that has not been used; run4 is the published run
#     bash tools/full_run.sh rehearsal --quick     # same sequence in about two minutes: 64k, idle, 2 reps
#
# Only --quick, --reps N, --sizes LIST, --loads LIST and --regions LIST may follow the run id;
# they are passed to harness/run_trials.py and make the run a reduced rehearsal. The script
# sets the run id, the matrices and the output files itself and refuses options that would
# change them (--out, --run-id, --matrix, --all).
#
# Runs, in order: the environment check, a full build with the default hash, the controlled,
# free-timing and overhead matrices, then the overhead matrix again with the OpenSSL hash
# (skipped when libssl-dev is absent). About 80 minutes on the reference laptop. Nothing else
# should be running: other programs on the host change launch times, see the README.
#
# Writes results/<run>_controlled.csv, results/<run>_uncontrolled.csv,
# results/<run>_overhead.csv, results/<run>_openssl_overhead.csv, results/<run>_env.txt and
# results/<run>_log.txt, and finishes with the hash-rate check that shows whether the
# overhead timings can be trusted. It never overwrites or appends to an existing file.

set -u -o pipefail
cd "$(dirname "$0")/.." || exit 1

RUN="${1:-}"
if [ -z "$RUN" ]; then echo "usage: bash tools/full_run.sh <run_id> [run_trials.py options]    for example: run5"; exit 2; fi
case "$RUN" in
  *[!A-Za-z0-9._-]*) echo "run id '$RUN' is not usable: letters, digits, dot, underscore and hyphen only (it becomes part of file names)"; exit 2;;
esac
shift
EXTRA=("$@")
i=0
while [ $i -lt ${#EXTRA[@]} ]; do
  case "${EXTRA[$i]}" in
    --quick|--reps=*|--sizes=*|--loads=*|--regions=*) ;;
    --reps|--sizes|--loads|--regions)
      i=$((i + 1))
      if [ $i -ge ${#EXTRA[@]} ]; then echo "option ${EXTRA[$((i - 1))]} needs a value"; exit 2; fi ;;
    *)
      echo "option '${EXTRA[$i]}' is not accepted: this script sets the run id, the matrices and the output files itself."
      echo "allowed after the run id: --quick, --reps N, --sizes LIST, --loads LIST, --regions LIST"
      exit 2 ;;
  esac
  i=$((i + 1))
done
REHEARSAL=0
if [ ${#EXTRA[@]} -gt 0 ]; then REHEARSAL=1; fi

clean_or_stop() {
  local dirty
  dirty=$(git status --porcelain --untracked-files=no)
  if [ -n "$dirty" ]; then
    echo "STOP ($1): tracked files have uncommitted changes, so git_rev would not identify the source:"
    echo "$dirty"
    exit 1
  fi
}

stray=$(git status --porcelain -- broker updater fixtures harness tools analysis Makefile | grep '^??' || true)
if [ -n "$stray" ]; then
  echo "STOP: untracked files where the build or the harness would use them; commit or remove them:"
  echo "$stray"
  exit 1
fi
clean_or_stop "before the build"
outputs=("results/${RUN}_controlled.csv" "results/${RUN}_uncontrolled.csv" "results/${RUN}_overhead.csv"
         "results/${RUN}_openssl_overhead.csv" "results/${RUN}_env.txt" "results/${RUN}_log.txt")
for f in "${outputs[@]}"; do
  if [ -e "$f" ]; then echo "STOP: $f already exists; pick a run id that has not been used"; exit 1; fi
done

main() {
  local t0 rev rc check_rc ssl_ran=0 fast=""
  t0=$(date +%s)
  rev=$(git rev-parse --short HEAD)
  echo "run $RUN from commit $rev, started $(date -Iseconds)"
  if [ $REHEARSAL -eq 1 ]; then echo "REHEARSAL with reduced options (${EXTRA[*]}): not a publishable run"; fi

  echo "== environment check =="
  bash tools/check_env.sh "results/${RUN}_env.txt" | grep -E "kernel|cpu:|openssl|experiments|plots|RESULT|FAIL"
  grep -q "^RESULT: SUPPORTED" "results/${RUN}_env.txt" || { echo "STOP: environment check failed"; return 1; }
  grep -q "^experiments: ready" "results/${RUN}_env.txt" || { echo "STOP: stress-ng is missing"; return 1; }

  echo "== build from scratch (default hash) =="
  # HASH is given explicitly so that a HASH variable exported in the calling shell cannot
  # turn the default-hash matrices into OpenSSL ones.
  make clean > /dev/null && make all HASH=vendored > /dev/null || { echo "STOP: build failed"; return 1; }
  sha256sum broker/broker updater/updater | sed 's/^/  /'
  clean_or_stop "after the build: the rebuilt fixtures differ from the committed allowlist or layout"

  echo "== matrices: controlled, free timing, overhead =="
  python3 harness/run_trials.py --all --run-id "$RUN" --require-clean ${EXTRA[@]+"${EXTRA[@]}"} | grep -vE " done$" || return 1

  if [ -r /usr/include/openssl/evp.h ]; then
    echo "== overhead matrix with the OpenSSL hash =="
    make broker HASH=openssl > /dev/null || { echo "STOP: OpenSSL broker build failed"; return 1; }
    sha256sum broker/broker | sed 's/^/  /'
    python3 harness/run_trials.py --matrix overhead --run-id "${RUN}_openssl" --require-clean ${EXTRA[@]+"${EXTRA[@]}"} | grep -vE " done$"
    rc=$?
    # Always put the default broker back, and say so loudly if that fails: the tree would be
    # left with the OpenSSL broker under the default name.
    make broker HASH=vendored > /dev/null || { echo "STOP: could not rebuild the default broker; broker/broker is still the OpenSSL build"; return 1; }
    [ $rc -eq 0 ] || { echo "STOP: the OpenSSL overhead matrix failed"; return 1; }
    ssl_ran=1
  else
    echo "== libssl-dev absent: OpenSSL overhead matrix skipped =="
  fi

  echo "== finished $(date -Iseconds), $(( ($(date +%s) - t0) / 60 )) minutes =="
  echo
  python3 analysis/hash_rate.py results/"${RUN}"_*.csv
  check_rc=$?
  echo
  echo "Next: read the hash-rate check above, then"
  echo "  python3 analysis/summarize.py results/${RUN}_uncontrolled.csv --by policy,change,region"
  if [ $ssl_ran -eq 1 ]; then fast=" --overhead-fast results/${RUN}_openssl_overhead.csv"; fi
  echo "  python3 analysis/plots.py --run ${RUN}${fast} --paper --out report/figures_${RUN}"
  if [ $check_rc -eq 1 ]; then
    echo "STOP: uneven hash rates in an overhead file. Do not use this run's launch times; rerun the overhead matrix with nothing else running. Security outcomes are unaffected."
    return 1
  fi
  if [ $check_rc -eq 3 ] && [ $REHEARSAL -eq 1 ]; then
    echo "NOTE: too few launches per cell to judge the timings, as expected in a rehearsal. The sequence completed; the timings are unchecked."
    return 0
  fi
  if [ $check_rc -ne 0 ]; then echo "STOP: the hash-rate check could not judge the timings (exit $check_rc); they are unchecked"; return 1; fi
}

main 2>&1 | tee "results/${RUN}_log.txt"
