#!/bin/sh
# Does an observed timing difference depend on the data-independent-timing
# mode of the processor (AArch64, FEAT_DIT)?
#
#   scripts/dit-experiment.sh <output directory> [rounds] [repeats]
#
# Runs `anu fo-oracle` alternately without and with `--dit` (default: 100000
# rounds, 4 repeats of each) and stores the reports and JSON results in
# <output directory>/plain and <output directory>/dit. Summarise each of the
# two folders with scripts/summarize.py; it pools the runs per input class.
#
# Build first:  cargo build --release --all-targets --locked
set -u
if [ "$#" -lt 1 ]; then
    echo "usage: scripts/dit-experiment.sh <output directory> [rounds] [repeats]" >&2
    exit 64
fi
out="$1"
rounds="${2:-100000}"
repeats="${3:-4}"
anu="${ANU:-./target/release/anu}"
if [ ! -x "$anu" ]; then
    echo "not found: $anu  (build first: cargo build --release --all-targets --locked)" >&2
    exit 64
fi
if [ -e "$out/log.txt" ]; then
    echo "$out already contains results (log.txt); choose another directory" >&2
    exit 64
fi
mkdir -p "$out/plain" "$out/dit"
: > "$out/log.txt"
"$anu" info > "$out/plain/info.txt" 2>&1
"$anu" --dit info > "$out/dit/info.txt" 2>&1 || {
    echo "the data-independent-timing mode is not available on this machine:" >&2
    cat "$out/dit/info.txt" >&2
    echo "dit not available" >> "$out/log.txt"
    exit 1
}
i=1
while [ "$i" -le "$repeats" ]; do
    printf '[%d/%d] without DIT ... ' "$i" "$repeats"
    "$anu" fo-oracle --samples "$rounds" -o "$out/plain/fo-oracle-$i.json" > "$out/plain/fo-oracle-$i.txt" 2>&1
    code=$?; echo "plain fo-oracle-$i exit $code" >> "$out/log.txt"; printf 'exit %d, with DIT ... ' "$code"
    "$anu" --dit fo-oracle --samples "$rounds" -o "$out/dit/fo-oracle-$i.json" > "$out/dit/fo-oracle-$i.txt" 2>&1
    code=$?; echo "dit fo-oracle-$i exit $code" >> "$out/log.txt"; echo "exit $code"
    i=$((i + 1))
done
echo "experiment complete" | tee -a "$out/log.txt"
