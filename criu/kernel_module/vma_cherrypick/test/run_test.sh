#!/bin/bash

set -e

TEST_BIN="./test_vma_cherrypick"
MODULE_NAME="vma_cherrypick"

echo "=================================================="
echo " vma_cherrypick Userspace Test"
echo "=================================================="

if [ "$EUID" -ne 0 ]; then
    echo "[-] Error: Must run as root."
    exit 1
fi

if ! lsmod | grep -q "$MODULE_NAME"; then
    echo "[-] Error: $MODULE_NAME module not loaded!"
    echo "[-] Run: sudo insmod ../$MODULE_NAME.ko"
    exit 1
fi

if [ "${SKIP_COMPILE:-0}" != "1" ]; then
    echo "[*] Compiling test..."
    make clean > /dev/null 2>&1
    make > /dev/null 2>&1
fi

if [ ! -f "$TEST_BIN" ]; then
    echo "[-] Test binary not found. Compile first."
    exit 1
fi

FAIL=0

run_test_pair() {
    local target_mode="$1"
    local test_mode="$2"

    echo ""
    echo ">>> TEST MODE: $test_mode (target: $target_mode) <<<"
    echo "--------------------------------------------------"

    echo "[*] Launching target process..."
    setarch x86_64 -R "$TEST_BIN" "$target_mode" &
    TARGET_PID=$!
    sleep 1

    if ! kill -0 $TARGET_PID 2>/dev/null; then
        echo "[-] Target failed to start."
        FAIL=1
        return
    fi

    echo "[*] Target PID: $TARGET_PID"
    echo "[*] Running test..."

    if setarch x86_64 -R "$TEST_BIN" "$test_mode" "$TARGET_PID"; then
        echo "[+] $test_mode: PASSED"
    else
        echo "[-] $test_mode: FAILED"
        FAIL=1
    fi

    echo "[*] Cleaning up target..."
    kill -9 $TARGET_PID 2>/dev/null || true
    wait $TARGET_PID 2>/dev/null || true
    echo "--------------------------------------------------"
}

run_test_pair "target" "test-vpid"
run_test_pair "target" "test-pidfd"

run_test_pair "target-dontfork" "test-dontfork-vpid"
run_test_pair "target-dontfork" "test-dontfork-pidfd"

echo ""
if [ $FAIL -eq 0 ]; then
    echo "[+] All tests PASSED!"
else
    echo "[-] Some tests FAILED!"
fi
echo "=================================================="

exit $FAIL
