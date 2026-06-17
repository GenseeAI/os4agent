#!/usr/bin/env bash


set -euo pipefail

ACTIVE_MODULES=(vma_cherrypick criu_capbypass pkey_state reparent_task)

SCRIPT_PATH="$(readlink -f "${BASH_SOURCE[0]}")"
SCRIPT_DIR="$(dirname "${SCRIPT_PATH}")"
cd "${SCRIPT_DIR}"

if [ ! -f Makefile.versions ] || [ ! -d kernel_module ]; then
    echo "build.sh: ${SCRIPT_DIR} doesn't look like the criu source root." >&2
    echo "  expected Makefile.versions + kernel_module/ here." >&2
    exit 1
fi

if [ "${EUID:-$(id -u)}" -ne 0 ]; then
    echo "build.sh must be run as root (apt install + insmod need it)." >&2
    echo "Re-run with: sudo $0" >&2
    exit 1
fi

echo "[1/5] Installing apt dependencies (contrib/dependencies/apt-packages.sh)"
DEBIAN_FRONTEND=noninteractive apt-get update
sh contrib/dependencies/apt-packages.sh

CORES_TOTAL="$(nproc)"
if [ "${CORES_TOTAL}" -gt 2 ]; then
    JOBS=$((CORES_TOTAL - 2))
else
    JOBS=1
fi

echo "[2/5] Building criu (make -j${JOBS}, ${CORES_TOTAL} cores total)"
make -j"${JOBS}"

echo "[3/5] Building libcriu.so + podman/crun integration shim"
make -j"${JOBS}" lib

SO_MAJOR="$(awk '/^CRIU_SO_VERSION_MAJOR/{print $3}' Makefile.versions)"
if [ -n "${SO_MAJOR}" ] && [ ! -e "lib/c/libcriu.so.${SO_MAJOR}" ]; then
    ln -sfn libcriu.so "lib/c/libcriu.so.${SO_MAJOR}"
fi

[ -e lib/c/criu ]         || ln -sfn . lib/c/criu
[ -e lib/c/version.h ]    || ln -sfn "${SCRIPT_DIR}/criu/include/version.h" lib/c/version.h
[ -e lib/c/rpc.pb-c.h ]   || ln -sfn "${SCRIPT_DIR}/images/rpc.pb-c.h"     lib/c/rpc.pb-c.h

mkdir -p lib/c/pc
cat > lib/c/pc/criu.pc <<EOF
libdir=${SCRIPT_DIR}/lib/c
includedir=${SCRIPT_DIR}/lib/c

Name: CRIU
Description: RPC library for userspace checkpoint and restore
Version: $(awk '/^CRIU_VERSION_MAJOR/{maj=$3} /^CRIU_VERSION_MINOR/{min=$3} END{print maj"."min}' Makefile.versions)
Libs: -L\${libdir} -lcriu
Cflags: -I\${includedir}
EOF

echo "[4/5] Installing kernel-module build dependencies"
KERNEL_RELEASE="$(uname -r)"
HEADERS_BUILD_DIR="/lib/modules/${KERNEL_RELEASE}/build"
INSTALL_LINUX_HEADERS=1
if [ -d "${HEADERS_BUILD_DIR}" ] && [ "${PODMAN_TFORK_FORCE_LINUX_HEADERS:-0}" != "1" ]; then
    echo "  -- ${HEADERS_BUILD_DIR} present; treating ${KERNEL_RELEASE} as a custom kernel and skipping linux-headers apt install"
    INSTALL_LINUX_HEADERS=0
fi
APT_PKGS=(bc bison flex libssl-dev dwarves)
if [ "${INSTALL_LINUX_HEADERS}" -eq 1 ]; then
    APT_PKGS=("linux-headers-${KERNEL_RELEASE}" "${APT_PKGS[@]}")
fi
DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends \
    "${APT_PKGS[@]}"

echo "[5/5] Building and loading kernel modules: ${ACTIVE_MODULES[*]}"
for mod in "${ACTIVE_MODULES[@]}"; do
    mod_dir="kernel_module/${mod}"
    ko_path="${mod_dir}/${mod}.ko"

    if [ ! -d "${mod_dir}" ]; then
        echo "  skip ${mod}: directory ${mod_dir} not found" >&2
        continue
    fi

    echo "  -- ${mod}: build"
    ( cd "${mod_dir}" && make )

    if [ ! -f "${ko_path}" ]; then
        echo "  skip ${mod}: ${ko_path} not present after build" >&2
        continue
    fi

    if lsmod | awk '{print $1}' | grep -qx "${mod}"; then
        echo "  -- ${mod}: already loaded, rmmod then insmod"
        rmmod "${mod}" 2>/dev/null || true
    else
        echo "  -- ${mod}: insmod"
    fi
    insmod "${ko_path}"
done

echo "  -- verify all modules loaded"
for mod in "${ACTIVE_MODULES[@]}"; do
    if ! lsmod | awk '{print $1}' | grep -qx "${mod}"; then
        echo "build.sh: kernel module ${mod} is not loaded; aborting" >&2
        exit 1
    fi
done
echo "  -- ${#ACTIVE_MODULES[@]} modules loaded"

echo
echo "Done. Built criu, libcriu.so, and loaded: ${ACTIVE_MODULES[*]}"
echo "Try: sudo ${SCRIPT_DIR}/criu/criu --version"
echo
echo "For podman/crun integration:"
echo "  CPPFLAGS=-I${SCRIPT_DIR}/lib/c \\"
echo "  PKG_CONFIG_PATH=${SCRIPT_DIR}/lib/c/pc \\"
echo "  LD_LIBRARY_PATH=${SCRIPT_DIR}/lib/c \\"
echo "    ./configure ... && make"
