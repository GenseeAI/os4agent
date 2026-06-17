#!/usr/bin/env bash


set -euo pipefail

SCRIPT_PATH="$(readlink -f "${BASH_SOURCE[0]}")"
SCRIPT_DIR="$(dirname "${SCRIPT_PATH}")"
cd "${SCRIPT_DIR}"

if [ ! -f Makefile ] || [ ! -d src ] || [ ! -f src/runtime_args.c ]; then
    echo "build.sh: ${SCRIPT_DIR} doesn't look like the conmon source root." >&2
    echo "  expected Makefile + src/runtime_args.c here." >&2
    exit 1
fi

if [ "${EUID:-$(id -u)}" -ne 0 ]; then
    echo "build.sh must be run as root (apt install needs it)." >&2
    echo "Re-run with: sudo $0" >&2
    exit 1
fi

echo "[1/3] Installing build dependencies"
DEBIAN_FRONTEND=noninteractive apt-get update
DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends \
    gcc \
    make \
    pkg-config \
    git \
    libc6-dev \
    libglib2.0-dev \
    libseccomp-dev

CORES_TOTAL="$(nproc)"
if [ "${CORES_TOTAL}" -gt 2 ]; then
    JOBS=$((CORES_TOTAL - 2))
else
    JOBS=1
fi


echo "[2/3] Building conmon (make -j${JOBS}, ${CORES_TOTAL} cores total, journald disabled)"
make clean >/dev/null 2>&1 || true
DISABLE_SYSTEMD=1 make -j"${JOBS}"

if [ ! -x bin/conmon ]; then
    echo "build.sh: bin/conmon not present after build" >&2
    exit 1
fi

echo "[3/3] Verifying --tfork flag is present"
if ! bin/conmon --help 2>&1 | grep -q -- "--tfork"; then
    echo "build.sh: bin/conmon lacks --tfork; did you build the right tree?" >&2
    exit 1
fi
echo "  -- bin/conmon supports --tfork"

echo
echo "Done. Built ${SCRIPT_DIR}/bin/conmon"
echo
echo "To make podman use this conmon, point /etc/containers/containers.conf at it:"
echo
echo "  [engine]"
echo "  conmon_path = [\"${SCRIPT_DIR}/bin/conmon\"]"
echo
echo "Or run 'sudo make podman' to install at \$PREFIX/libexec/podman/conmon"
echo "(default \$PREFIX is /usr/local; podman picks that up automatically when"
echo "no explicit conmon_path is set)."
