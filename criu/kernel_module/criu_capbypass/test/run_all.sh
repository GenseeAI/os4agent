#!/bin/bash

set -u

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
MOD_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"
MOD_KO="$MOD_DIR/criu_capbypass.ko"

TESTS=(
	test_capbypass
	test_non_clone_denied
	test_narrow_syscall_mask
	test_fd_close_revoke
)

if [ ! -f "$MOD_KO" ]; then
	( cd "$MOD_DIR" && make ) || exit 1
fi
( cd "$SCRIPT_DIR" && make ) || exit 1

loaded=0
if lsmod | grep -q '^criu_capbypass\b'; then
	loaded=1
else
	echo "Loading module..."
	sudo insmod "$MOD_KO" || exit 1
fi

fail=0
for t in "${TESTS[@]}"; do
	echo "===== $t ====="
	sudo "$SCRIPT_DIR/$t"
	rc=$?
	if [ $rc -ne 0 ]; then
		echo "FAIL: $t exited $rc"
		fail=$((fail + 1))
	fi
	echo
done

if [ "$loaded" = "0" ]; then
	sudo rmmod criu_capbypass 2>/dev/null
fi

if [ $fail -ne 0 ]; then
	echo "$fail test(s) failed."
	exit 1
fi
echo "All tests passed."
