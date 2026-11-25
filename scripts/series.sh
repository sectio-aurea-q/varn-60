#!/bin/sh
# Measurement series behind the numbers quoted in the README.
#
#   scripts/series.sh <output directory> [rounds]
#
# Runs, with the same number of rounds (default 20000):
#   5 × anu control, 12 × anu multi-lib, 3 × anu fo-oracle, 1 × anu ci,
#   and the key_dependence example.
# For every run the printed report (.txt) and the JSON result are stored;
# log.txt records the exit code of every run.
#
# Exit status: 0 if every run ended with exit code 0, otherwise 1. A run that
# ends with another code is not necessarily broken (anu ci exits with 1 for a
# confirmed difference, anu control with 1 for a failed control); the series
# is always run to the end, and the runs concerned are listed.
#
# Build first:  cargo build --release --all-targets --locked
set -u
if [ "$#" -lt 1 ]; then
    echo "usage: scripts/series.sh <output directory> [rounds]" >&2
    exit 64
fi
out="$1"
rounds="${2:-20000}"
anu="${ANU:-./target/release/anu}"
example="${KEY_DEPENDENCE:-./target/release/examples/key_dependence}"
for bin in "$anu" "$example"; do
    if [ ! -x "$bin" ]; then
        echo "not found: $bin  (build first: cargo build --release --all-targets --locked)" >&2
        exit 64
    fi
done
if [ -e "$out/log.txt" ]; then
    echo "$out already contains a series (log.txt); choose another directory" >&2
    exit 64
fi
total=22
step=0
nonzero=""
mkdir -p "$out"
: > "$out/log.txt"

run() { # name, command...
    name="$1"; shift
    step=$((step + 1))
    printf '[%2d/%d] %s ... ' "$step" "$total" "$name"
    "$@" > "$out/$name.txt" 2>&1
    code=$?
    echo "$name exit $code" >> "$out/log.txt"
    echo "exit $code"
    if [ "$code" -ne 0 ]; then
        nonzero="$nonzero $name($code)"
    fi
}

echo "series: $rounds rounds per run, output in $out"
"$anu" info > "$out/info.txt" 2>&1
i=1; while [ "$i" -le 5 ]; do
    run "control-$i" "$anu" control --samples "$rounds" -o "$out/control-$i.json"
    i=$((i + 1))
done
i=1; while [ "$i" -le 12 ]; do
    run "multi-lib-$i" "$anu" multi-lib --samples "$rounds" -o "$out/multi-lib-$i.json"
    i=$((i + 1))
done
i=1; while [ "$i" -le 3 ]; do
    run "fo-oracle-$i" "$anu" fo-oracle --samples "$rounds" -o "$out/fo-oracle-$i.json"
    i=$((i + 1))
done
run "ci-1" "$anu" ci --samples "$rounds" -o "$out/ci-1.json"
run "key-dependence" "$example" "$rounds"
if [ -z "$nonzero" ]; then
    echo "series complete: all $total runs ended with exit code 0" | tee -a "$out/log.txt"
    exit 0
fi
echo "series complete: runs with a non-zero exit code:$nonzero" | tee -a "$out/log.txt"
exit 1
