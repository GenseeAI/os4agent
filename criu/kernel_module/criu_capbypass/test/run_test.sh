#!/bin/bash

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
MOD_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"
MOD_KO="$MOD_DIR/criu_capbypass.ko"

if [ ! -f "$MOD_KO" ]; then
	echo "Module not built: $MOD_KO" >&2
	echo "Run 'make' in $MOD_DIR first." >&2
	exit 1
fi

if [ ! -x "$SCRIPT_DIR/test_capbypass" ]; then
	( cd "$SCRIPT_DIR" && make ) || exit 1
fi

loaded=0
if lsmod | grep -q '^criu_capbypass\b'; then
	loaded=1
	echo "Module already loaded; skipping insmod."
else
	echo "Loading module..."
	sudo insmod "$MOD_KO"
fi

echo "Running test..."
sudo "$SCRIPT_DIR/test_capbypass"
rc=$?

if [ "$loaded" = "0" ]; then
	echo "Unloading module..."
	sudo rmmod criu_capbypass
fi

exit $rc
