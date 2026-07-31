#!/bin/bash
# SPDX-License-Identifier: GPL-2.0

set -euo pipefail

readonly KSFT_SKIP=4
readonly STATS=/proc/filecow_stats
readonly LOOPS="${FILECOW_TEST_LOOPS:-100}"
readonly TEST_ROOT="${FILECOW_TEST_ROOT:-}"

skip()
{
	echo "1..0 # SKIP $*"
	exit "$KSFT_SKIP"
}

fail()
{
	echo "not ok 1 - filecow layer lifetime"
	echo "# $*"
	exit 1
}

stat_value()
{
	awk -v key="$1" '$1 == key { print $2; found = 1 }
		END { if (!found) exit 1 }' "$STATS"
}

[[ $EUID -eq 0 ]] || skip "must be run as root"
[[ -n "$TEST_ROOT" ]] ||
	skip "set FILECOW_TEST_ROOT to an existing btrfs directory"
[[ "$LOOPS" =~ ^[1-9][0-9]*$ ]] || skip "FILECOW_TEST_LOOPS must be positive"
[[ -r "$STATS" ]] || skip "$STATS is unavailable"
command -v btrfs >/dev/null || skip "btrfs-progs is unavailable"
[[ "$(findmnt -n -o FSTYPE -T "$TEST_ROOT")" == btrfs ]] ||
	skip "$TEST_ROOT is not on btrfs"

for key in layers_allocated layers_active fork_no_layer fork_reused_layer; do
	stat_value "$key" >/dev/null ||
		skip "running kernel does not expose the $key counter"
done

workdir="$(mktemp -d "${TEST_ROOT%/}/filecow-layer-lifetime.XXXXXX")"
source_subvol="$workdir/source"
child_subvol="$workdir/child"

cleanup()
{
	exec 8<&- 9<&-
	if btrfs subvolume show "$child_subvol" >/dev/null 2>&1; then
		btrfs subvolume delete "$child_subvol" >/dev/null
	fi
	if btrfs subvolume show "$source_subvol" >/dev/null 2>&1; then
		btrfs subvolume delete "$source_subvol" >/dev/null
	fi
	rmdir "$workdir" 2>/dev/null || true
}
trap cleanup EXIT

btrfs subvolume create "$source_subvol" >/dev/null
printf 'filecow-layer-lifetime\n' >"$source_subvol/cached"
: >"$source_subvol/empty"
sync -f "$source_subvol/cached"

# Populate one source folio.  The first snapshot needs a layer for it; later
# unchanged snapshots must share that layer rather than extend the chain.
cat "$source_subvol/cached" >/dev/null
exec 8<"$source_subvol/cached"
exec 9<"$source_subvol/empty"

allocated_before="$(stat_value layers_allocated)"
active_before="$(stat_value layers_active)"
no_layer_before="$(stat_value fork_no_layer)"
reused_before="$(stat_value fork_reused_layer)"

for ((i = 0; i < LOOPS; i++)); do
	btrfs subvolume snapshot "$source_subvol" "$child_subvol" >/dev/null
	[[ "$(cat "$child_subvol/cached")" == filecow-layer-lifetime ]] ||
		fail "snapshot data mismatch in iteration $i"
	stat "$child_subvol/empty" >/dev/null
	btrfs subvolume delete "$child_subvol" >/dev/null
done

allocated_after="$(stat_value layers_allocated)"
active_after="$(stat_value layers_active)"
no_layer_after="$(stat_value fork_no_layer)"
reused_after="$(stat_value fork_reused_layer)"

allocated_delta=$((allocated_after - allocated_before))
active_delta=$((active_after - active_before))
no_layer_delta=$((no_layer_after - no_layer_before))
reused_delta=$((reused_after - reused_before))

((allocated_delta <= 1)) ||
	fail "unchanged forks allocated $allocated_delta layers; expected at most 1"
((active_delta <= 1)) ||
	fail "unchanged forks retained $active_delta layers; expected at most 1"
((no_layer_delta >= LOOPS)) ||
	fail "empty inode skipped only $no_layer_delta layers; expected at least $LOOPS"
((reused_delta >= LOOPS - 1)) ||
	fail "cached inode reused only $reused_delta layers; expected at least $((LOOPS - 1))"

echo "ok 1 - filecow layer lifetime"
echo "# loops=$LOOPS allocated_delta=$allocated_delta active_delta=$active_delta"
echo "# fork_no_layer_delta=$no_layer_delta fork_reused_layer_delta=$reused_delta"
echo "1..1"
