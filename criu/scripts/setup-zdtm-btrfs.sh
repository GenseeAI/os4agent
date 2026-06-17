#!/bin/bash

set -euo pipefail

if [[ -z "${BTRFS_ROOT:-}" ]]; then
    BTRFS_ROOT=$(findmnt -t btrfs -no TARGET 2>/dev/null | head -1 || true)
    if [[ -z "$BTRFS_ROOT" ]]; then
        echo "no btrfs mountpoint found; set BTRFS_ROOT=/path/to/btrfs-mount" >&2
        exit 1
    fi
fi
SUBVOL_NAME=${SUBVOL_NAME:-zdtm-test}
SUBVOL_PATH=$BTRFS_ROOT/$SUBVOL_NAME

SCRIPT_DIR=$(cd "$(dirname "$0")" && pwd)
REPO_ROOT=$(git -C "$SCRIPT_DIR" rev-parse --show-toplevel 2>/dev/null \
            || dirname "$SCRIPT_DIR")
TEST_DIR=${1:-$REPO_ROOT/test}

if [[ $EUID -ne 0 ]]; then
    echo "must run as root (btrfs/mount)"
    exit 1
fi

if mountpoint -q "$TEST_DIR" \
        && findmnt -no SOURCE "$TEST_DIR" 2>/dev/null \
                | grep -qE "\[/$SUBVOL_NAME\]"; then
    echo "zdtm-btrfs already mounted at $TEST_DIR"
    exit 0
fi

fstype=$(stat -f -c %T "$BTRFS_ROOT" 2>/dev/null || true)
if [[ $fstype != "btrfs" ]]; then
    echo "$BTRFS_ROOT is not on btrfs (got '$fstype')" >&2
    exit 1
fi

if ! btrfs subvolume show "$SUBVOL_PATH" >/dev/null 2>&1; then
    btrfs subvolume create "$SUBVOL_PATH"
fi

if [[ -z $(ls -A "$SUBVOL_PATH" 2>/dev/null) ]]; then
    echo "staging $TEST_DIR -> $SUBVOL_PATH"
    rsync -aHAX "$TEST_DIR/" "$SUBVOL_PATH/"
fi

mount --bind "$SUBVOL_PATH" "$TEST_DIR"
echo "bind-mounted $SUBVOL_PATH at $TEST_DIR"
