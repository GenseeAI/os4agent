#!/usr/bin/env bash
set -euo pipefail

PODMAN=${PODMAN:-podman}
PODMAN_GLOBAL_ARGS=${PODMAN_GLOBAL_ARGS:-}
OS4AGENT_CRUN=${OS4AGENT_CRUN:-crun}
IMAGE=${IMAGE:-docker.io/library/python:3.12-slim}
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
workload=$script_dir/tfork-ncopy-nested-pidns-threads.py
source_name=${PREFIX}-source

podman_cmd() {
	"$PODMAN" "${podman_global_args[@]}" "$@"
}

cleanup() {
	podman_cmd ps -a --format '{{.Names}}' |
		awk -v prefix="$PREFIX" 'index($0, prefix) == 1' |
		while read -r name; do
			podman_cmd rm -f -t 0 "$name" >/dev/null 2>&1 || true
		done
}
trap cleanup EXIT

check_nested_init() {
	local name=$1
	podman_cmd exec \
		-e TFORK_EXPECT_THREADS="$((THREADS + 1))" \
		"$name" python3 -c '
import os

expected = int(os.environ["TFORK_EXPECT_THREADS"])
matches = []
for entry in os.listdir("/proc"):
    if not entry.isdigit():
        continue
    try:
        fields = {}
        with open(f"/proc/{entry}/status", encoding="utf-8") as status:
            for line in status:
                key, _, value = line.partition(":")
                fields[key] = value.strip()
    except (FileNotFoundError, PermissionError, ProcessLookupError):
        continue
    if fields.get("Name") != "tfork-ns-init":
        continue
    nspid = [int(pid) for pid in fields.get("NSpid", "").split()]
    threads = int(fields.get("Threads", "0"))
    matches.append((entry, nspid, threads))

assert len(matches) == 1, f"expected one nested init, got {matches}"
_, nspid, threads = matches[0]
assert len(nspid) >= 2 and nspid[-1] == 1, f"bad nested init NSpid: {nspid}"
assert threads == expected, f"expected {expected} threads, got {threads}"
print(f"nested-init nspid={nspid} threads={threads}")
'
}

cleanup
test -f "$workload"
podman_cmd run -d --name "$source_name" \
	--cap-add SYS_ADMIN \
	--security-opt seccomp=unconfined \
	--security-opt apparmor=unconfined \
	-e TFORK_TEST_SIBLINGS="$SIBLINGS" \
	-e TFORK_TEST_THREADS="$THREADS" \
	-v "$workload:/tfork-ncopy-workload.py:ro" \
	"$IMAGE" python3 /tfork-ncopy-workload.py >/dev/null

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
