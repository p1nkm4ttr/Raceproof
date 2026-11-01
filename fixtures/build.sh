#!/bin/bash
# Builds the RaceProof fixtures: prog_a and prog_b at four sizes, statically linked,
# freestanding. Writes fixtures/bin/, fixtures/allowlist.txt (SHA-256 of every prog_a only)
# and fixtures/layout.txt (.text offset and size per fixture, for the updater's --region text).
set -eu
cd "$(dirname "$0")"
mkdir -p bin
CFLAGS="-O2 -static -nostdlib -nostartfiles -fno-stack-protector -fno-builtin -fno-pie -no-pie -Wl,--build-id=none"

# name:pad_bytes  (file size is pad plus a few KiB of ELF headers and code)
SIZES="64k:65536 1m:1048576 8m:8388608 32m:33554432"

: > allowlist.txt
: > layout.txt
for entry in $SIZES; do
  name=${entry%%:*}; pad=${entry##*:}
  for id in A B; do
    lc=$(echo "$id" | tr 'A-Z' 'a-z')
    out="bin/prog_${lc}_${name}"
    gcc $CFLAGS -DPROG_ID="'$id'" -DPAD_BYTES="$pad" -o "$out" prog.c
    strip --strip-all "$out" 2>/dev/null || true
    size=$(stat -c %s "$out")
    # .text offset and size from the section header table. readelf prints "[ 1]" with a
    # space for indices under 10, which shifts awk's fields; normalise it first. Hex to
    # decimal is done in bash because Ubuntu's default awk (mawk) has no strtonum.
    line=$(readelf -S -W "$out" | sed 's/\[ *\([0-9]*\)\]/[\1]/' | awk '$2==".text"{print $5, $6}')
    toff=$((16#${line%% *})); tsize=$((16#${line##* }))
    # expected pad hash: what this fixture prints when its bytes are intact
    padhash=$("$out" | sed -n 's/^RACEPROOF_PAD=//p')
    echo "$out size=$size text_off=$toff text_size=$tsize pad=$padhash" >> layout.txt
    if [ "$id" = A ]; then sha256sum "$out" | awk '{print $1"  "$2}' >> allowlist.txt; fi
  done
done

echo "built:"; ls -l bin/ | awk 'NR>1{print "  "$NF, $5" bytes"}'
echo "allowlist.txt: $(wc -l < allowlist.txt) entries (prog_a only)"
# sanity: every fixture runs and prints its own ID
for f in bin/prog_*; do
  want=$(basename "$f" | cut -d_ -f2 | tr 'a-z' 'A-Z')
  got=$("$f" | sed -n 's/^RACEPROOF_ID=\(.\).*/\1/p')
  [ "$got" = "$want" ] || { echo "FAIL: $f printed '$got', expected '$want'"; exit 1; }
done
# A and B of the same size must have different pad hashes, or tearing is invisible
for s in 64k 1m 8m 32m; do
  pa=$(grep "prog_a_$s " layout.txt | sed 's/.*pad=//'); pb=$(grep "prog_b_$s " layout.txt | sed 's/.*pad=//')
  [ "$pa" != "$pb" ] || { echo "FAIL: prog_a_$s and prog_b_$s have the same pad hash"; exit 1; }
done
echo "all fixtures run, print the right ID, and A/B pad hashes differ at every size"
