#!/bin/bash
# One complete run for publication, from a tree with no uncommitted changes, so that the
# git_rev on every row names the exact source that produced it.
#
#     bash tools/full_run.sh run4
#     bash tools/full_run.sh rehearsal --quick     # same sequence in about two minutes: 64k, idle, 2 reps
#
# Anything after the run id is passed to harness/run_trials.py.
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
if [ -z "$RUN" ]; then echo "usage: bash tools/full_run.sh <run_id> [run_trials.py options]    for example: run4"; exit 2; fi
shift
EXTRA=("$@")

clean_or_stop() {
  local dirty
  dirty=$(git status --porcelain --untracked-files=no)
  if [ -n "$dirty" ]; then
    echo "STOP ($1): tracked files have uncommitted changes, so git_rev would not identify the source:"
    echo "$dirty"
    exit 1
  fi
}

clean_or_stop "before the build"
outputs="results/${RUN}_controlled.csv results/${RUN}_uncontrolled.csv results/${RUN}_overhead.csv
results/${RUN}_openssl_overhead.csv results/${RUN}_env.txt results/${RUN}_log.txt"
for f in $outputs; do
  if [ -e "$f" ]; then echo "STOP: $f already exists; pick a run id that has not been used"; exit 1; fi
done

main() {
  local t0 rev rc
  t0=$(date +%s)
  rev=$(git rev-parse --short HEAD)
  echo "run $RUN from commit $rev, started $(date -Iseconds)"

  echo "== environment check =="
  bash tools/check_env.sh "results/${RUN}_env.txt" | grep -E "kernel|cpu:|openssl|experiments|plots|RESULT|FAIL"
  grep -q "^RESULT: SUPPORTED" "results/${RUN}_env.txt" || { echo "STOP: environment check failed"; return 1; }
  grep -q "^experiments: ready" "results/${RUN}_env.txt" || { echo "STOP: stress-ng is missing"; return 1; }

  echo "== build (default hash) =="
  make all > /dev/null || { echo "STOP: build failed"; return 1; }
  clean_or_stop "after the build: the rebuilt fixtures differ from the committed allowlist or layout"

  echo "== matrices: controlled, free timing, overhead =="
  python3 harness/run_trials.py --all --run-id "$RUN" --require-clean ${EXTRA[@]+"${EXTRA[@]}"} | grep -vE " done$" || return 1

  if [ -r /usr/include/openssl/evp.h ]; then
    echo "== overhead matrix with the OpenSSL hash =="
    make broker HASH=openssl > /dev/null || { echo "STOP: OpenSSL broker build failed"; return 1; }
    python3 harness/run_trials.py --matrix overhead --run-id "${RUN}_openssl" --require-clean ${EXTRA[@]+"${EXTRA[@]}"} | grep -vE " done$"
    rc=$?
    make broker > /dev/null          # always put the default broker back
    [ $rc -eq 0 ] || return 1
  else
    echo "== libssl-dev absent: OpenSSL overhead matrix skipped =="
  fi

  echo "== finished $(date -Iseconds), $(( ($(date +%s) - t0) / 60 )) minutes =="
  echo
  python3 analysis/hash_rate.py results/"${RUN}"_*.csv
  echo
  echo "Next: read the hash-rate check above, then"
  echo "  python3 analysis/summarize.py results/${RUN}_uncontrolled.csv --by policy,change,region"
  echo "  python3 analysis/plots.py --run ${RUN} --overhead-fast results/${RUN}_openssl_overhead.csv --paper --out report/figures_${RUN}"
}

main 2>&1 | tee "results/${RUN}_log.txt"
