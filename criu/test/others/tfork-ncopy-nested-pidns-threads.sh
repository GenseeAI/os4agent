#!/usr/bin/env bash
set -euo pipefail

PODMAN=${PODMAN:-podman}
PODMAN_GLOBAL_ARGS=${PODMAN_GLOBAL_ARGS:-}
OS4AGENT_CRUN=${OS4AGENT_CRUN:-crun}
CC=${CC:-cc}
IMAGE=${IMAGE:-docker.io/library/alpine:3.19}
COPIES=${COPIES:-4}
ITERATIONS=${ITERATIONS:-3}
SIBLINGS=${SIBLINGS:-40}
THREADS=${THREADS:-8}
PARALLEL_WORKERS=${PARALLEL_WORKERS:-4}
PREFIX=${PREFIX:-tfork-ncopy-pidns-$RANDOM}
TFORK_CLONE_ARGS=${TFORK_CLONE_ARGS:---tfork-overlay-btrfs}

read -r -a podman_global_args <<<"$PODMAN_GLOBAL_ARGS"
read -r -a tfork_clone_args <<<"$TFORK_CLONE_ARGS"
script_dir=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
workload_src=$script_dir/tfork-ncopy-nested-pidns-threads.c
work_dir=$(mktemp -d /tmp/tfork-ncopy-pidns.XXXXXX)
workload=$work_dir/tfork-ncopy-workload
source_name=${PREFIX}-source

podman_cmd() {
	"$PODMAN" "${podman_global_args[@]}" "$@"
}

cleanup_containers() {
	podman_cmd ps -a --format '{{.Names}}' |
		awk -v prefix="$PREFIX" 'index($0, prefix) == 1' |
		while read -r name; do
			podman_cmd rm -f -t 0 "$name" >/dev/null 2>&1 || true
		done
}

cleanup() {
	cleanup_containers
	rm -rf "$work_dir"
}
trap cleanup EXIT

check_nested_init() {
	local name=$1
	podman_cmd exec \
		-e TFORK_EXPECT_THREADS="$((THREADS + 1))" \
		"$name" sh -eu -c '
found=0
for status in /proc/[0-9]*/status; do
    name_value=
    nspid=
    threads=
    while IFS=: read -r key value; do
        case "$key" in
            Name) set -- $value; name_value=$1 ;;
            NSpid) nspid=$value ;;
            Threads) set -- $value; threads=$1 ;;
        esac
    done <"$status"
    [ "$name_value" = tfork-ns-init ] || continue
    set -- $nspid
    [ "$#" -ge 2 ]
    for last do :; done
    [ "$last" -eq 1 ]
    [ "$threads" -eq "$TFORK_EXPECT_THREADS" ]
    found=$((found + 1))
    echo "nested-init nspid=$nspid threads=$threads"
done
[ "$found" -eq 1 ]
'
}

cleanup_containers
test -f "$workload_src"
"$CC" -O2 -Wall -Wextra -pthread -static "$workload_src" -o "$workload"
podman_cmd run -d --name "$source_name" \
	--log-driver k8s-file \
	--cap-add SYS_ADMIN \
	--security-opt seccomp=unconfined \
	--security-opt apparmor=unconfined \
	-v "$workload:/tfork-ncopy-workload:ro" \
	"$IMAGE" /tfork-ncopy-workload "$SIBLINGS" "$THREADS" >/dev/null

for ((attempt = 0; attempt < 200; attempt++)); do
	if podman_cmd exec "$source_name" \
		test -f /tmp/tfork-ncopy-nested-pidns-ready; then
		break
	fi
	sleep 0.05
done
podman_cmd exec "$source_name" test -f /tmp/tfork-ncopy-nested-pidns-ready
check_nested_init "$source_name"

for ((iteration = 1; iteration <= ITERATIONS; iteration++)); do
	clone_base=${PREFIX}-clone-${iteration}
	env \
		CRIU_TFORK_PARALLEL_SIBLINGS="$PARALLEL_WORKERS" \
		OS4AGENT_CRUN="$OS4AGENT_CRUN" \
		"$PODMAN" "${podman_global_args[@]}" container clone \
		--live --copies "$COPIES" "${tfork_clone_args[@]}" \
		"$source_name" "$clone_base" >/dev/null

	for ((copy = 0; copy < COPIES; copy++)); do
		name=${clone_base}-${copy}
		check_nested_init "$name"
	done

	rootfs=$(podman_cmd inspect --format '{{.Rootfs}}' "${clone_base}-0")
	bundle=$(dirname "$rootfs")
	grep -Eq 'tfork: creating [0-9]+ .*siblings with [0-9]+ temporary helpers' \
		"$bundle/img/tfork-restore.log.copy0"

	for ((copy = 0; copy < COPIES; copy++)); do
		podman_cmd rm -f -t 0 "${clone_base}-${copy}" >/dev/null
	done
	printf 'iteration %d: %d concurrent copies passed\n' "$iteration" "$COPIES"
done

podman_cmd rm -f -t 0 "$source_name" >/dev/null
trap - EXIT
