#!/usr/bin/env bash

set -euo pipefail

SCRIPT_PATH="$(readlink -f "${BASH_SOURCE[0]}")"
SCRIPT_DIR="$(dirname "${SCRIPT_PATH}")"
CRIU_DIR="$(readlink -f "${SCRIPT_DIR}/../criu")"
cd "${SCRIPT_DIR}"

if [ ! -f Makefile.am ] || [ ! -d src/libcrun ] || [ ! -f src/tfork.c ]; then
    echo "build.sh: ${SCRIPT_DIR} doesn't look like the crun source root." >&2
    echo "  expected Makefile.am + src/tfork.c here." >&2
    exit 1
fi

if [ "${EUID:-$(id -u)}" -ne 0 ]; then
    echo "build.sh must be run as root (apt install needs it)." >&2
    echo "Re-run with: sudo $0" >&2
    exit 1
fi

if [ ! -f "${CRIU_DIR}/lib/c/libcriu.so" ] \
        || [ ! -f "${CRIU_DIR}/lib/c/pc/criu.pc" ] \
        || [ ! -e "${CRIU_DIR}/lib/c/criu/criu.h" ]; then
    echo "build.sh: in-tree libcriu not ready at ${CRIU_DIR}/lib/c/" >&2
    echo "  expected libcriu.so + pc/criu.pc + criu/criu.h symlink." >&2
    echo "  Build the criu submodule first: sudo ${CRIU_DIR}/build.sh" >&2
    exit 1
fi

echo "[1/3] Installing build dependencies"
DEBIAN_FRONTEND=noninteractive apt-get update
DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends \
    gcc \
    make \
    git \
    build-essential \
    autoconf \
    automake \
    libtool \
    pkgconf \
    python3 \
    libcap-dev \
    libseccomp-dev \
    libprotobuf-c-dev \
    libsystemd-dev \
    libbpf-dev

CORES_TOTAL="$(nproc)"
if [ "${CORES_TOTAL}" -gt 2 ]; then
    JOBS=$((CORES_TOTAL - 2))
else
    JOBS=1
fi

echo "[2/3] Running autogen.sh + configure (linking against ${CRIU_DIR}/lib/c)"
./autogen.sh

CPPFLAGS="-I${CRIU_DIR}/lib/c" \
PKG_CONFIG_PATH="${CRIU_DIR}/lib/c/pc" \
    ./configure \
        --enable-embedded-yajl

echo "[3/3] Building crun (make -j${JOBS}, ${CORES_TOTAL} cores total)"
make -j"${JOBS}"

if [ ! -x crun ]; then
    echo "build.sh: ${SCRIPT_DIR}/crun not present after build" >&2
    exit 1
fi

if ! LD_LIBRARY_PATH="${CRIU_DIR}/lib/c" ./crun tfork --help 2>&1 | grep -q -- "--tfork-snap-root"; then
    echo "build.sh: ./crun lacks the tfork verb; did you build the right tree?" >&2
    exit 1
fi
echo "  -- ./crun has the tfork verb (dlopens libcriu from ${CRIU_DIR}/lib/c)"

echo
echo "Done. Built ${SCRIPT_DIR}/crun"
echo
echo "To make podman use this crun, point /etc/containers/containers.conf at it:"
echo
echo "  [engine.runtimes]"
echo "  crun = [\"${SCRIPT_DIR}/crun\"]"
echo
echo "Crun dlopens libcriu at runtime; podman must be able to find it. Either:"
echo "  - export LD_LIBRARY_PATH=${CRIU_DIR}/lib/c, OR"
echo "  - drop a /etc/ld.so.conf.d/criu-tfork.conf with that line + ldconfig."
