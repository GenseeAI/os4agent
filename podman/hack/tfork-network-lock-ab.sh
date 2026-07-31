#!/usr/bin/env bash
set -euo pipefail

PODMAN=${PODMAN:-podman}
PODMAN_GLOBAL_ARGS=${PODMAN_GLOBAL_ARGS:-}
CRIU_ROOT=${CRIU_ROOT:?set CRIU_ROOT}
OS4AGENT_CRUN=${OS4AGENT_CRUN:-crun}
SAMPLES=${SAMPLES:-10}
WORKLOAD_PROCESSES=${WORKLOAD_PROCESSES:-100}
IMAGE=${IMAGE:-docker.io/library/alpine:3.19}
PREFIX=${PREFIX:-tfork-network-lock-$RANDOM}
OUTPUT=${OUTPUT:-/tmp/tfork-network-lock-ab.tsv}
LOG_DIR=${LOG_DIR:-}

read -r -a podman_global_args <<<"$PODMAN_GLOBAL_ARGS"
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

run_clone() {
	local backend=$1
	local index=$2
	local name=${PREFIX}-${backend}-${index}
	local started ended elapsed rootfs bundle

	started=$(date +%s%N)
	env \
		PATH="$CRIU_ROOT/criu:$PATH" \
		LD_LIBRARY_PATH="$CRIU_ROOT/lib/c${LD_LIBRARY_PATH:+:$LD_LIBRARY_PATH}" \
		OS4AGENT_CRUN="$OS4AGENT_CRUN" \
		"$PODMAN" "${podman_global_args[@]}" container clone \
		--live --tfork-overlay-btrfs \
		--tfork-network-lock="$backend" \
		"$source_name" "$name" >/dev/null
	ended=$(date +%s%N)
	elapsed=$(( (ended - started) / 1000000 ))

	[[ $(podman_cmd exec "$name" cat /tmp/sentinel) == source-before-fork ]]
	if [[ -n $LOG_DIR ]]; then
		rootfs=$(podman_cmd inspect --format '{{.Rootfs}}' "$name")
		bundle=$(dirname "$rootfs")
		test -f "$bundle/img/tfork.log"
		cp "$bundle/img/tfork.log" \
			"$LOG_DIR/${backend}-${index}.tfork.log"
	fi
	podman_cmd kill -s KILL "$name" >/dev/null
	podman_cmd rm -f -t 0 "$name" >/dev/null
	printf '%s\t%d\t%d\n' "$backend" "$index" "$elapsed" |
		tee -a "$OUTPUT"
}

cleanup
: >"$OUTPUT"
if [[ -n $LOG_DIR ]]; then
	mkdir -p "$LOG_DIR"
fi
podman_cmd run -d --name "$source_name" \
	--log-driver k8s-file \
	--security-opt seccomp=unconfined \
	--security-opt apparmor=unconfined \
	"$IMAGE" sh -c \
	'count=$1
	i=1
	while [ "$i" -lt "$count" ]; do
		sleep 86400 &
		i=$((i + 1))
	done
	echo source-before-fork >/tmp/sentinel
	exec tail -f /dev/null' sh "$WORKLOAD_PROCESSES" >/dev/null

for ((attempt = 0; attempt < 100; attempt++)); do
	actual_processes=$(podman_cmd top "$source_name" pid |
		awk 'NR > 1 { count++ } END { print count + 0 }')
	if ((actual_processes == WORKLOAD_PROCESSES)); then
		break
	fi
	sleep 0.05
done
if ((actual_processes != WORKLOAD_PROCESSES)); then
	printf 'expected %d source processes, found %d\n' \
		"$WORKLOAD_PROCESSES" "$actual_processes" >&2
	exit 1
fi

for ((i = 1; i <= SAMPLES; i++)); do
	if ((i % 2)); then
		run_clone iptables "$i"
		run_clone nftables "$i"
	else
		run_clone nftables "$i"
		run_clone iptables "$i"
	fi
done

podman_cmd rm -f -t 0 "$source_name" >/dev/null
trap - EXIT
