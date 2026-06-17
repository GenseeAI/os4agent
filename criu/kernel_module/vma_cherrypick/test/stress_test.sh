#!/bin/bash

ITERATIONS=${1:-100}
PARALLEL=${2:-4}
LOG_DIR="/tmp/vma_cherrypick_stress_$$"
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
FAIL_COUNT=0
PASS_COUNT=0

if [ "$EUID" -ne 0 ]; then
    echo "Must run as root."
    exit 1
fi

mkdir -p "$LOG_DIR"

echo "=================================================="
echo " vma_cherrypick stress test"
echo " Iterations: $ITERATIONS  Parallel: $PARALLEL"
echo " Logs: $LOG_DIR"
echo "=================================================="
echo "[*] Compiling test binary..."
make -C "$SCRIPT_DIR" clean > /dev/null 2>&1
make -C "$SCRIPT_DIR" > /dev/null 2>&1
export SKIP_COMPILE=1

run_one() {
    local i=$1
    local log="$LOG_DIR/run_${i}.log"

    "$SCRIPT_DIR/run_test.sh" > "$log" 2>&1
}

i=1
while [ $i -le $ITERATIONS ]; do
    pids=()
    batch_end=$((i + PARALLEL - 1))
    if [ $batch_end -gt $ITERATIONS ]; then
        batch_end=$ITERATIONS
    fi

    for j in $(seq $i $batch_end); do
        run_one $j &
        pids+=($!)
    done

    for pid in "${pids[@]}"; do
        wait $pid
        rc=$?
        if [ $rc -ne 0 ]; then
            FAIL_COUNT=$((FAIL_COUNT + 1))
        else
            PASS_COUNT=$((PASS_COUNT + 1))
        fi
    done

    printf "\r  Progress: %d/%d (pass=%d fail=%d)" \
        "$batch_end" "$ITERATIONS" "$PASS_COUNT" "$FAIL_COUNT"

    i=$((batch_end + 1))
done

echo ""
echo ""

FAIL_LOGS=$(grep -l "FAIL\|FAILED" "$LOG_DIR"/run_*.log 2>/dev/null)

echo "=================================================="
echo " Results: $PASS_COUNT passed, $FAIL_COUNT failed"
echo "=================================================="

if [ -n "$FAIL_LOGS" ]; then
    echo ""
    echo "Logs with failures:"
    for f in $FAIL_LOGS; do
        echo "  $f"
    done
    echo ""
    echo "First failure:"
    head -30 "$(echo "$FAIL_LOGS" | head -1)"
    exit 1
else
    echo "All $ITERATIONS runs passed. No FAIL found in logs."
    rm -rf "$LOG_DIR"
    exit 0
fi
