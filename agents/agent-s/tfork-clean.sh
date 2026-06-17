#!/usr/bin/env bash

set -u
REPO="${REPO:-$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)}"
MNT="${MNT:-/mnt/btrfs}"

inventory() {
  printf "  containers:                %s\n" \
    "$(sudo "$REPO/podman-tfork.sh" ps -aq 2>/dev/null | wc -l)"
  printf "  tfork-bundle subvolumes:   %s\n" \
    "$(sudo btrfs subvolume list "$MNT" 2>/dev/null | awk '{print $NF}' \
       | grep -c '^podman/storage/tfork-bundles/' || true)"
  printf "  tfork-bundles dir entries: %s\n" \
    "$(sudo ls "$MNT/podman/storage/tfork-bundles/" 2>/dev/null | wc -l)"
}

echo "=== before ==="
inventory

ids=$(sudo "$REPO/podman-tfork.sh" ps -aq 2>/dev/null)
if [ -n "$ids" ]; then
  n=$(echo "$ids" | wc -l)
  echo "--- removing $n container(s) ---"
  sudo "$REPO/podman-tfork.sh" rm -f $ids >/dev/null
fi

echo "--- deleting tfork-bundle subvolumes ---"
sudo btrfs subvolume list "$MNT" 2>/dev/null \
  | awk '{print $NF}' \
  | grep '^podman/storage/tfork-bundles/' \
  | while read sv; do
      sudo btrfs subvolume delete "$MNT/$sv" >/dev/null 2>&1
    done

echo "--- removing leftover bundle dirs ---"
for d in "$MNT/podman/storage/tfork-bundles/"*; do
  [ -e "$d" ] && sudo rm -rf "$d"
done

if [ -x "$REPO/tfork-cgroup-cleanup.sh" ]; then
  echo "--- cgroup cleanup ---"
  sudo "$REPO/tfork-cgroup-cleanup.sh" 2>&1 | tail -5
fi

echo "=== after ==="
inventory
