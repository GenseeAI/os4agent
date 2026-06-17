#!/usr/bin/env bash

set -euo pipefail

DRY=0
VERBOSE=1
for a in "$@"; do
    case "$a" in
        --dry-run|-n) DRY=1 ;;
        --quiet|-q)   VERBOSE=0 ;;
        -h|--help)
            sed -n '2,30p' "$0"
            exit 0
            ;;
        *) echo "unknown arg: $a" >&2; exit 2 ;;
    esac
done

if [[ $EUID -ne 0 ]]; then
    echo "tfork-cgroup-cleanup: must run as root (uses mount/rmdir on cgroupfs)" >&2
    exit 1
fi

log() { [[ $VERBOSE -eq 1 ]] && echo "$@"; }
do_or_show() { if [[ $DRY -eq 1 ]]; then echo "[dry-run] $*"; else eval "$@"; fi; }

drain_cgroup_tree() {
    local root="$1" name_pat="$2" max_passes=30
    local pass before after
    for pass in $(seq 1 "$max_passes"); do
        before=$(find "$root" -name "$name_pat" -type d 2>/dev/null | wc -l)
        if [[ "$before" -eq 0 ]]; then
            return
        fi
        if [[ $DRY -eq 1 ]]; then
            echo "[dry-run] would rmdir $before dirs matching '$name_pat' under $root"
            return
        fi
        find "$root" -name "$name_pat" -type d 2>/dev/null \
            | awk -F/ '{print NF, $0}' | sort -rn | cut -d' ' -f2- \
            | xargs -I{} rmdir {} 2>/dev/null || true
        after=$(find "$root" -name "$name_pat" -type d 2>/dev/null | wc -l)
        if [[ "$after" -eq "$before" ]]; then
            return
        fi
    done
}

log "--- Phase 1: cgroup2 unified ---"
v2_libpod_before=$(find /sys/fs/cgroup -name "libpod-*" -type d 2>/dev/null | wc -l)
v2_parent_before=$(find /sys/fs/cgroup -name "libpod_parent" -type d 2>/dev/null | wc -l)
log "  libpod-* dirs before: $v2_libpod_before"
log "  libpod_parent dirs before: $v2_parent_before"

drain_cgroup_tree /sys/fs/cgroup "libpod-*"
drain_cgroup_tree /sys/fs/cgroup "libpod_parent"

v2_libpod_after=$(find /sys/fs/cgroup -name "libpod-*" -type d 2>/dev/null | wc -l)
v2_parent_after=$(find /sys/fs/cgroup -name "libpod_parent" -type d 2>/dev/null | wc -l)
log "  libpod-* dirs after:  $v2_libpod_after"
log "  libpod_parent dirs after: $v2_parent_after"

log
log "--- Phase 2: cgroup v1 named hierarchies ---"

mapfile -t named_hier < <(awk -F: '/:name=/ { sub(/^name=/, "", $2); print $2 }' /proc/1/cgroup | sort -u)
if [[ ${#named_hier[@]} -eq 0 ]]; then
    log "  no named v1 hierarchies present — skipping"
else
    for name in "${named_hier[@]}"; do
        log "  named hierarchy: $name"
        tmp_mnt="$(mktemp -d "/tmp/tfork-cgcleanup-$name.XXXXXX")"
        if ! mount -t cgroup -o "name=$name" none "$tmp_mnt" 2>/dev/null; then
            log "    mount failed; skipping"
            rmdir "$tmp_mnt" 2>/dev/null || true
            continue
        fi
        before=$(find "$tmp_mnt" -mindepth 1 -type d 2>/dev/null | wc -l)
        log "    empty cgroups before: $before"


        if [[ $DRY -eq 1 ]]; then
            echo "[dry-run] would drain $before dirs under $tmp_mnt (name=$name)"
        else
            for pass in $(seq 1 30); do
                count=$(find "$tmp_mnt" -mindepth 1 -type d 2>/dev/null | wc -l)
                [[ "$count" -eq 0 ]] && break
                find "$tmp_mnt" -mindepth 1 -type d 2>/dev/null \
                    | awk -F/ '{print NF, $0}' | sort -rn | cut -d' ' -f2- \
                    | xargs -I{} rmdir {} 2>/dev/null || true
                new=$(find "$tmp_mnt" -mindepth 1 -type d 2>/dev/null | wc -l)
                [[ "$new" -eq "$count" ]] && break
            done
        fi
        after=$(find "$tmp_mnt" -mindepth 1 -type d 2>/dev/null | wc -l)
        log "    empty cgroups after:  $after  (reaped $((before - after)))"
        umount "$tmp_mnt" 2>/dev/null || umount -l "$tmp_mnt" 2>/dev/null || true
        rmdir "$tmp_mnt" 2>/dev/null || true
    done
fi

log
log "--- Phase 3: orphan .criu.cgyard mounts ---"
cgyard_paths=$(mount | awk '/\.criu\.cgyard\..*\/unified/ {print $3}' || true)
n_cgyard=$(printf "%s\n" "$cgyard_paths" | grep -c . || true)
log "  active .criu.cgyard mounts: $n_cgyard"
if [[ -n "$cgyard_paths" ]]; then
    while IFS= read -r p; do
        [[ -z "$p" ]] && continue
        if [[ $DRY -eq 1 ]]; then
            echo "[dry-run] would umount -l $p"
        else
            umount -l "$p" 2>/dev/null && log "    umount $p" || log "    umount FAILED $p"
        fi
    done <<<"$cgyard_paths"
fi

echo
echo "tfork-cgroup-cleanup: done."
echo "  cgroup2 libpod-*:        $v2_libpod_before -> $(find /sys/fs/cgroup -name 'libpod-*' -type d 2>/dev/null | wc -l)"
echo "  cgroup2 libpod_parent:   $v2_parent_before -> $(find /sys/fs/cgroup -name 'libpod_parent' -type d 2>/dev/null | wc -l)"
echo "  named-v1 hierarchies:    ${#named_hier[@]} drained"
echo "  .criu.cgyard mounts:     $n_cgyard released"
