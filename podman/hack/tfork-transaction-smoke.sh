#!/usr/bin/env bash
set -euo pipefail

PODMAN=${PODMAN:-podman}
PODMAN_GLOBAL_ARGS=${PODMAN_GLOBAL_ARGS:-}
IMAGE=${IMAGE:-docker.io/library/alpine:3.19}
PREFIX=${PREFIX:-tfork-txn-$RANDOM}
TFORK_RUNTIME_ROOT=${TFORK_RUNTIME_ROOT:-/run/libpod/tfork}

source_name=${PREFIX}-source
clone_name=${PREFIX}-clone
read -r -a podman_global_args <<<"$PODMAN_GLOBAL_ARGS"

podman_cmd() {
	"$PODMAN" "${podman_global_args[@]}" "$@"
}

count_dirs() {
	local path=$1
	if [[ ! -d $path ]]; then
		echo 0
		return
	fi
	find "$path" -mindepth 1 -maxdepth 1 -type d -print | wc -l
}

cleanup() {
	podman_cmd kill -s KILL "$clone_name" >/dev/null 2>&1 || true
	podman_cmd rm -f -t 0 "$clone_name" >/dev/null 2>&1 || true
	podman_cmd kill -s KILL "$source_name" >/dev/null 2>&1 || true
	podman_cmd rm -f -t 0 "$source_name" >/dev/null 2>&1 || true
}
trap cleanup EXIT

runtime_before=$(count_dirs "$TFORK_RUNTIME_ROOT")
bundle_root=$(podman_cmd info --format '{{.Store.GraphRoot}}')/tfork-bundles
bundles_before=$(count_dirs "$bundle_root")

podman_cmd run -d --name "$source_name" \
	--log-driver k8s-file \
	--security-opt seccomp=unconfined \
	--security-opt apparmor=unconfined \
	"$IMAGE" sh -c 'echo source-before-fork >/tmp/sentinel; exec tail -f /dev/null' >/dev/null
cgroups_before=$(find /sys/fs/cgroup -type d -name 'libpod-*' -print 2>/dev/null | wc -l)

for stage in \
	before_freeze \
	after_freeze \
	after_filesystem \
	before_restore \
	after_restore \
	after_thaw \
	after_register_0 \
	before_commit
do
	if env PODMAN_TFORK_FAULT_INJECT="$stage" \
		"$PODMAN" "${podman_global_args[@]}" container clone --live --tfork-overlay-btrfs \
		"$source_name" "$clone_name" >/tmp/tfork-fault.stdout 2>/tmp/tfork-fault.stderr
	then
		echo "fault stage $stage unexpectedly succeeded" >&2
		exit 1
	fi
	if ! grep -Fq "injected tfork fault at $stage" /tmp/tfork-fault.stderr; then
		echo "fault stage $stage was not reached; clone failed for another reason" >&2
		sed -n '1,120p' /tmp/tfork-fault.stderr >&2
		exit 1
	fi
	podman_cmd exec "$source_name" sh -c \
		'test "$(cat /tmp/sentinel)" = source-before-fork'
	if podman_cmd container exists "$clone_name"; then
		echo "fault stage $stage published clone $clone_name" >&2
		exit 1
	fi
	if [[ $(count_dirs "$bundle_root") != "$bundles_before" ]]; then
		echo "fault stage $stage leaked a graphroot bundle" >&2
		exit 1
	fi
	if [[ $(count_dirs "$TFORK_RUNTIME_ROOT") != "$runtime_before" ]]; then
		echo "fault stage $stage leaked a runtime publication" >&2
		exit 1
	fi
	if [[ $(find /sys/fs/cgroup -type d -name 'libpod-*' -print 2>/dev/null | wc -l) != "$cgroups_before" ]]; then
		echo "fault stage $stage leaked a cgroup" >&2
		exit 1
	fi
	echo "PASS fault=$stage"
done

podman_cmd container clone --live --tfork-overlay-btrfs \
	"$source_name" "$clone_name" >/dev/null
[[ $(podman_cmd exec "$clone_name" cat /tmp/sentinel) == source-before-fork ]]
podman_cmd exec "$clone_name" sh -c 'echo child-only >/tmp/sentinel'
[[ $(podman_cmd exec "$source_name" cat /tmp/sentinel) == source-before-fork ]]

podman_cmd kill -s KILL "$clone_name" >/dev/null
podman_cmd rm -f -t 0 "$clone_name" >/dev/null
if [[ $(count_dirs "$TFORK_RUNTIME_ROOT") != "$runtime_before" ]]; then
	echo "successful clone cleanup leaked a runtime publication" >&2
	exit 1
fi

echo "PASS normal-fork"
