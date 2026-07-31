#!/usr/bin/env bash
set -euo pipefail

PODMAN=${PODMAN:-podman}
PODMAN_GLOBAL_ARGS=${PODMAN_GLOBAL_ARGS:-}
CRIU_ROOT=${CRIU_ROOT:?set CRIU_ROOT}
OS4AGENT_CRUN=${OS4AGENT_CRUN:-crun}
IMAGE=${IMAGE:-docker.io/library/alpine:3.19}
PREFIX=${PREFIX:-tfork-network-smoke-$RANDOM}

read -r -a podman_global_args <<<"$PODMAN_GLOBAL_ARGS"
source_name=${PREFIX}-source
clone_name=${PREFIX}-clone

podman_cmd() {
	"$PODMAN" "${podman_global_args[@]}" "$@"
}

cleanup() {
	podman_cmd rm -f -t 0 "$clone_name" >/dev/null 2>&1 || true
	podman_cmd rm -f -t 0 "$source_name" >/dev/null 2>&1 || true
}
trap cleanup EXIT

assert_no_criu_table() {
	local name=$1
	local pid

	pid=$(podman_cmd inspect --format '{{.State.Pid}}' "$name")
	if nsenter -t "$pid" -n nft list tables 2>/dev/null |
		grep -qi criu; then
		printf 'stale CRIU nftables table in %s\n' "$name" >&2
		return 1
	fi
}

cleanup
podman_cmd run -d --name "$source_name" \
	--log-driver k8s-file \
	--security-opt seccomp=unconfined \
	--security-opt apparmor=unconfined \
	"$IMAGE" sh -c \
	'echo source-before-fork >/tmp/sentinel
	while :; do
		printf "HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok" |
			nc -l -p 18080
	done' >/dev/null

for ((attempt = 0; attempt < 100; attempt++)); do
	if [[ $(podman_cmd exec "$source_name" \
		wget -qO- http://127.0.0.1:18080 2>/dev/null || true) == ok ]]; then
		break
	fi
	sleep 0.05
done
if ((attempt == 100)); then
	printf 'source listener did not become ready\n' >&2
	exit 1
fi
assert_no_criu_table "$source_name"

env \
	PATH="$CRIU_ROOT/criu:$PATH" \
	LD_LIBRARY_PATH="$CRIU_ROOT/lib/c${LD_LIBRARY_PATH:+:$LD_LIBRARY_PATH}" \
	OS4AGENT_CRUN="$OS4AGENT_CRUN" \
	"$PODMAN" "${podman_global_args[@]}" container clone \
	--live --tfork-overlay-btrfs \
	--tfork-network-lock=nftables \
	"$source_name" "$clone_name" >/dev/null

[[ $(podman_cmd exec "$clone_name" cat /tmp/sentinel) == source-before-fork ]]
[[ $(podman_cmd exec "$source_name" \
	wget -qO- http://127.0.0.1:18080) == ok ]]
[[ $(podman_cmd exec "$clone_name" \
	wget -qO- http://127.0.0.1:18080) == ok ]]
assert_no_criu_table "$source_name"
assert_no_criu_table "$clone_name"

podman_cmd exec "$clone_name" sh -c 'echo clone-only >/tmp/divergence'
test "$(podman_cmd exec "$clone_name" cat /tmp/divergence)" = clone-only
if podman_cmd exec "$source_name" test -e /tmp/divergence; then
	printf 'clone filesystem write leaked into source\n' >&2
	exit 1
fi

cleanup
trap - EXIT
printf 'tfork nftables network-lock smoke: PASS\n'
