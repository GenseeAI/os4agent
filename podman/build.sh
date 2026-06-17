#!/usr/bin/env bash

set -euo pipefail

GO_VERSION="1.24.2"
GO_TARBALL="go${GO_VERSION}.linux-amd64.tar.gz"
GO_URL="https://go.dev/dl/${GO_TARBALL}"

SCRIPT_PATH="$(readlink -f "${BASH_SOURCE[0]}")"
SCRIPT_DIR="$(dirname "${SCRIPT_PATH}")"
cd "${SCRIPT_DIR}"

if [ ! -f Makefile ] || [ ! -d cmd/podman ] || [ ! -f pkg/domain/infra/abi/container_tfork.go ]; then
    echo "build.sh: ${SCRIPT_DIR} doesn't look like the podman source root." >&2
    echo "  expected Makefile + cmd/podman + container_tfork.go here." >&2
    exit 1
fi

if [ "${EUID:-$(id -u)}" -ne 0 ]; then
    echo "build.sh must be run as root (apt install needs it)." >&2
    echo "Re-run with: sudo $0" >&2
    exit 1
fi

echo "[1/4] Installing build dependencies"
DEBIAN_FRONTEND=noninteractive apt-get update
DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends \
    make \
    gcc \
    pkg-config \
    git \
    curl \
    ca-certificates \
    libsystemd-dev \
    libseccomp-dev \
    libgpgme-dev \
    libdevmapper-dev \
    libbtrfs-dev \
    libassuan-dev \
    libsubid-dev \
    libapparmor-dev \
    libsqlite3-dev \
    libselinux1-dev \
    btrfs-progs \
    go-md2man

need_install_go=1
go_ver_required="$(awk '/^go /{print $2; exit}' go.mod)"
for cand in /usr/local/go/bin/go "$(command -v go 2>/dev/null || true)"; do
    [ -x "${cand}" ] || continue
    have="$("${cand}" version 2>/dev/null | awk '{print $3}' | sed 's/^go//')"
    [ -n "${have}" ] || continue

    if [ "$(printf '%s\n%s\n' "${go_ver_required}" "${have}" | sort -V | head -1)" = "${go_ver_required}" ]; then
        echo "[2/4] Found go ${have} at ${cand} (>= ${go_ver_required})"
        export PATH="$(dirname "${cand}"):${PATH}"
        need_install_go=0
        break
    fi
done

if [ "${need_install_go}" = 1 ]; then
    echo "[2/4] Installing Go ${GO_VERSION} from upstream tarball"
    tmp_tar="$(mktemp -d)/${GO_TARBALL}"
    curl -fsSL "${GO_URL}" -o "${tmp_tar}"
    rm -rf /usr/local/go
    tar -C /usr/local -xzf "${tmp_tar}"
    rm -rf "$(dirname "${tmp_tar}")"
    export PATH="/usr/local/go/bin:${PATH}"
    /usr/local/go/bin/go version
fi

CORES_TOTAL="$(nproc)"
if [ "${CORES_TOTAL}" -gt 2 ]; then
    JOBS=$((CORES_TOTAL - 2))
else
    JOBS=1
fi

echo "[3/4] Building bin/podman (-p ${JOBS}, ${CORES_TOTAL} cores total)"
make GOFLAGS="-p=${JOBS}" podman

if [ ! -x bin/podman ]; then
    echo "build.sh: bin/podman not present after build" >&2
    exit 1
fi

echo "[4/4] Verifying --live tfork path is wired"
if ! ./bin/podman container clone --help 2>&1 | grep -q -- "--live"; then
    echo "build.sh: bin/podman container clone lacks --live; did you build the right tree?" >&2
    exit 1
fi
echo "  -- bin/podman has 'container clone --live'"

CRIU_DIR="$(readlink -f "${SCRIPT_DIR}/../criu" 2>/dev/null || echo "../criu")"
CRUN_DIR="$(readlink -f "${SCRIPT_DIR}/../crun" 2>/dev/null || echo "../crun")"
CONMON_DIR="$(readlink -f "${SCRIPT_DIR}/../conmon" 2>/dev/null || echo "../conmon")"

echo
echo "Done. Built ${SCRIPT_DIR}/bin/podman ($(./bin/podman --version | awk '{print $3}'))"
echo
echo "To run with the in-tree tfork stack, point /etc/containers/containers.conf"
echo "at the matching criu / crun / conmon (build those first via their build.sh):"
echo
cat <<EOF
  [engine]
  conmon_path = ["${CONMON_DIR}/bin/conmon"]
  runtime = "crun"

  [engine.runtimes]
  crun = ["${CRUN_DIR}/crun"]
EOF
echo
echo "crun dlopens libcriu; export LD_LIBRARY_PATH=${CRIU_DIR}/lib/c in podman's"
echo "environment, or drop /etc/ld.so.conf.d/criu-tfork.conf with that line + ldconfig."
echo
echo "Then try: sudo ${SCRIPT_DIR}/bin/podman container clone --live <src-id>"
