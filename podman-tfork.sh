#!/usr/bin/env bash

set -euo pipefail

REPO="$(readlink -f "$(dirname "${BASH_SOURCE[0]}")")"

if [[ "${1:-}" == "--tfork-help" ]]; then
    cat <<'EOF'
podman-tfork.sh — wrapper for the in-tree podman + tfork stack.

Wrapper-only flags (consumed here; not forwarded to podman):
  --tfork-help                 print this reference and exit.

All other arguments are passed through to the in-tree podman.

Live-clone flags (on `podman container clone --live`):
  --live                       engage the tfork path; required to clone.
  --copies N                   fan out to N parallel clones (default 1).
  --shared-usr                 cross-clone /usr ext-mount; saves ~3 GiB
                               per clone for image-heavy stacks (webtop).
  --persistent[=async|sync]    persist source memory to clone's image
                               dir. Bare --persistent → async (default
                               when used). --persistent=sync flushes
                               before clone returns.
  --with-previous              chain incremental memdump off most-recent
                               `done` clone (requires --persistent).
  --tfork-overlay-btrfs        per-clone rootfs as overlay(lower=shared
                               snap-ro btrfs subvol, upper=plain dir).
                               Sibling clones share the lower inode →
                               ONE page cache refcounted N ways.
                               Default OFF = legacy `btrfs subvolume
                               snapshot` per clone (own super_block /
                               address_space; page cache duplicated).
  --tfork-ghost-limit BYTES    raise CRIU's per-dump ghost-file cap
                               above its 1 MiB default. Default 256 MiB
                               (GUI apps need >1 MiB). 0 = CRIU default.
  --tfork-tcp-close[=BOOL]     dump ESTABLISHED TCP sockets as closed.
                               Default true (chromium / electron / any
                               long-poll workload reconnects cleanly).
                               Pass --tfork-tcp-close=false to fall
                               back to CRIU's refuse-on-established.

Environment variables read by the in-tree podman:
  PODMAN_TFORK_NO_REAP=1       keep failed-clone bundles on disk for
                               post-mortem (skips the error-path
                               tforkBestEffortBundleReap).
  PODMAN_TFORK_BTRFS_ROOT=DIR  override the auto-detected btrfs root
                               mountpoint used to translate a source
                               container's volume mountinfo paths to
                               host paths. Auto-detected by scanning
                               /proc/self/mountinfo for a btrfs entry
                               with root=/ matching the volume's
                               device major:minor.
  PODMAN_TFORK_SKIP_SYSCTL=1   skip the wrapper's read-only sysctl
                               preflight (use when sysctls are managed
                               by orchestration outside this wrapper).

System sysctls verified by the wrapper's preflight (set them once
per boot; the wrapper does NOT change them, only reads + reports):
  kernel.io_uring_disabled       must equal 2
  fs.nr_open                     must be >= 1048576
  fs.inotify.max_user_instances  must be >= 524288

Apply / persist:
  sudo sysctl -w kernel.io_uring_disabled=2
  sudo sysctl -w fs.nr_open=1048576
  sudo sysctl -w fs.inotify.max_user_instances=524288
  # persist:
  /etc/sysctl.d/90-tfork.conf  with the same three key=value lines

Internal (do NOT set manually):
  CRIU_VMA_CHERRYPICK_FD, CRIU_CAPBYPASS_FD, CRIU_PKEY_STATE_FD —
  service-fd inheritance plumbing populated by crun.

Examples:
  sudo $0 ps
  sudo $0 run -d --name src --log-driver=k8s-file \
      docker.io/library/alpine:3.19 sleep 1000
  sudo $0 container clone --live --name g1 src
  sudo $0 container clone --live --copies=4 --persistent=async \
      --tfork-overlay-btrfs --name fan src

Further reading:
  README.md                    setup, build, smoke test.
EOF
    exit 0
fi

if [[ "${PODMAN_TFORK_SKIP_SYSCTL:-0}" != "1" ]]; then
    sysctl_fails=()

    check_sysctl() {
        local key="$1" op="$2" want="$3"
        local path="/proc/sys/${key//./\/}"
        if [[ ! -r "$path" ]]; then
            sysctl_fails+=("$key: $path not readable")
            return
        fi
        local cur
        cur=$(awk '{print $1; exit}' "$path")
        case "$op" in
            eq) [[ "$cur" == "$want" ]] || sysctl_fails+=("$key: have $cur, need $want") ;;
            ge) [[ "$cur" -ge "$want" ]] 2>/dev/null \
                || sysctl_fails+=("$key: have $cur, need >= $want") ;;
        esac
    }
    check_sysctl kernel.io_uring_disabled        eq 2
    check_sysctl fs.nr_open                      ge 1048576
    check_sysctl fs.inotify.max_user_instances   ge 524288
    if (( ${#sysctl_fails[@]} > 0 )); then
        {
            echo "podman-tfork: required sysctls not set:"
            for f in "${sysctl_fails[@]}"; do echo "  - $f"; done
            echo
            echo "Apply with:"
            echo "  sudo sysctl -w kernel.io_uring_disabled=2"
            echo "  sudo sysctl -w fs.nr_open=1048576"
            echo "  sudo sysctl -w fs.inotify.max_user_instances=524288"
            echo
            echo "Persist by appending to /etc/sysctl.d/90-tfork.conf."
            echo "Set PODMAN_TFORK_SKIP_SYSCTL=1 to bypass this check."
        } >&2
        exit 1
    fi
    unset -f check_sysctl
    unset sysctl_fails
fi

if [[ -z "${CONTAINERS_CONF:-}" ]]; then
    CONTAINERS_CONF="${REPO}/.os4agent-containers.conf"
    cat > "$CONTAINERS_CONF" <<EOF
[containers]
log_driver = "k8s-file"

[engine]
conmon_path = ["${REPO}/conmon/bin/conmon"]
runtime = "crun"
cgroup_manager = "cgroupfs"

[engine.runtimes]
crun = ["${REPO}/crun/crun"]
EOF
fi

exec env \
    CONTAINERS_CONF="$CONTAINERS_CONF" \
    LD_LIBRARY_PATH="${REPO}/criu/lib/c" \
    PATH="${REPO}/criu/criu:${PATH}" \
    OS4AGENT_CRUN="${REPO}/crun/crun" \
    OS4AGENT_CONMON="${REPO}/conmon/bin/conmon" \
    "${REPO}/podman/bin/podman" "$@"
