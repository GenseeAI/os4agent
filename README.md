# Tclone Runtime for Gensee Crate

This repository is Gensee's fork of tclone. It provides the patched Linux
kernel, CRIU, crun, conmon, and Podman components used by
[`gensee-crate`](https://github.com/GenseeAI/gensee-crate) for fast, live
container forks.

Gensee owns the container lifecycle. After this host is prepared, use
`gensee run --runtime tclone` to launch an agent. Do not manually start a
webtop source container or run `podman container clone`; Gensee creates,
forks, compares, merges, promotes, and discards the containers on behalf of
the agent after the required user approvals.

## Components

| Directory | Role |
|---|---|
| [`linux-pagecache-cow/`](linux-pagecache-cow/) | Linux kernel with the page-cache CoW support used by tclone |
| [`criu/`](criu/) | `criu tfork`, libcriu, and the tclone kernel modules |
| [`crun/`](crun/) | `crun tfork` OCI runtime implementation |
| [`conmon/`](conmon/) | tclone-aware conmon with the `--tfork` flag |
| [`podman/`](podman/) | Podman with `container clone --live` |
| [`podman-tfork.sh`](podman-tfork.sh) | Wrapper that selects the in-tree Podman, conmon, crun, and libcriu |
| [`ubuntu-img/`](ubuntu-img/) | Source for the tmux-capable container image used by Gensee |

## Requirements

- Ubuntu on x86_64 with root access.
- A dedicated btrfs filesystem for rootful Podman's graphroot.
- Enough free space for the kernel build, container image, and fork overlays.
- A host installation of the agent CLI you will launch, such as Codex.
- `tmux` on the host and inside the container image for automatic source/fork
  pane management.

Tclone is currently rootful, btrfs-only, and amd64-only.

## 1. Clone this repository

The repository's default branch contains the Gensee integration and the merged
tclone stability fixes.

```bash
git clone --recurse-submodules https://github.com/GenseeAI/os4agent.git
cd os4agent
git submodule update --init --recursive
```

Run all remaining tclone commands from this repository root unless a step says
otherwise.

## 2. Configure the required sysctls

Apply the settings immediately:

```bash
sudo sysctl -w kernel.io_uring_disabled=2
sudo sysctl -w fs.nr_open=1048576
sudo sysctl -w fs.inotify.max_user_instances=524288
sudo sysctl -w kernel.apparmor_restrict_unprivileged_unconfined=0
```

Persist them across reboots:

```bash
sudo tee /etc/sysctl.d/90-tfork.conf >/dev/null <<'EOF'
kernel.io_uring_disabled=2
fs.nr_open=1048576
fs.inotify.max_user_instances=524288
kernel.apparmor_restrict_unprivileged_unconfined=0
EOF

sudo sysctl --system
```

## 3. Configure rootful Podman storage on btrfs

Install Podman and the btrfs tools first:

```bash
sudo apt update
sudo apt install -y btrfs-progs podman
```

On a new machine, configure storage before the first rootful Podman command.
Mount a dedicated btrfs filesystem and point rootful Podman at a directory on
it. For example, after mounting btrfs at `/mnt/btrfs`:

```toml
# /etc/containers/storage.conf
[storage]
driver = "btrfs"
runroot = "/run/containers/storage"
graphroot = "/mnt/btrfs/podman"
```

Do not change an existing Podman graphroot without first accounting for its
containers and images. Formatting and mounting the btrfs device is intentionally
left to the host administrator.

If rootful Podman was already initialized, inspect its current store before
changing anything:

```bash
sudo podman info --format '{{.Store.GraphRoot}} {{.Store.GraphDriverName}}'
GRAPHROOT="$(sudo podman info --format '{{.Store.GraphRoot}}')"
findmnt -T "$GRAPHROOT"
```

The reported driver and filesystem must both be `btrfs`. An `overlay` driver
stored on a btrfs filesystem is still overlay storage, and tclone snapshots fail
against it with errors such as `Not a Btrfs filesystem`.

If you cannot change the host-wide rootful store, create a dedicated storage
configuration and pass it to every tclone Podman and Gensee command:

```bash
export GENSEE_HOME="${GENSEE_HOME:-$HOME/.gensee}"
export CONTAINERS_STORAGE_CONF="$GENSEE_HOME/tclone-btrfs-storage.conf"
mkdir -p "$GENSEE_HOME" /mnt/btrfs/tclone-root /mnt/btrfs/tclone-run

cat >"$CONTAINERS_STORAGE_CONF" <<'EOF'
[storage]
driver = "btrfs"
runroot = "/mnt/btrfs/tclone-run"
graphroot = "/mnt/btrfs/tclone-root"
EOF

sudo env "CONTAINERS_STORAGE_CONF=$CONTAINERS_STORAGE_CONF" \
  podman info --format '{{.Store.GraphRoot}} {{.Store.GraphDriverName}}'
```

Images are scoped to the selected store. If `CONTAINERS_STORAGE_CONF` is set
when Gensee runs, use the same value when pulling or building the image. Step 6
verifies the same store through the newly built tclone wrapper.

## 4. Build and boot the tclone kernel

Install common Ubuntu kernel-build dependencies:

```bash
sudo apt update
sudo apt install -y \
  build-essential bc bison flex cpio dwarves fakeroot \
  libelf-dev libncurses-dev libssl-dev rsync
```

Build and install the page-cache CoW kernel:

```bash
cd linux-pagecache-cow
cp config .config
./build_kernel.sh build
sudo ./build_kernel.sh install
sudo reboot
```

After reconnecting, return to the repository and verify that the new kernel is
running:

```bash
cd ~/os4agent
uname -r
cat /proc/filecow_stats
```

`uname -r` should end in `-pgcachecow`, and `/proc/filecow_stats` must exist.
Build the userspace stack only after booting this kernel so the tclone kernel
modules are compiled against the running kernel.

## 5. Build the tclone userspace stack

Build the components in this order:

```bash
cd ~/os4agent

sudo ./criu/build.sh
sudo ./crun/build.sh
sudo ./conmon/build.sh
sudo ./podman/build.sh
```

`criu/build.sh` builds libcriu and loads these modules:

- `vma_cherrypick`
- `criu_capbypass`
- `pkey_state`
- `reparent_task`

Stop existing tclone containers before rebuilding CRIU. The build fails closed
if an old module is still in use and cannot be unloaded.

If `insmod` reports `Invalid module format`, the modules were built for a
different kernel than the one currently running. Reboot into the
`-pgcachecow` kernel, verify `uname -r`, then rerun `sudo ./criu/build.sh`.
You can inspect the expected kernel release with:

```bash
modinfo criu/kernel_module/vma_cherrypick/vma_cherrypick.ko | grep vermagic
uname -r
```

Always invoke Podman through [`podman-tfork.sh`](podman-tfork.sh). The wrapper
selects the matching in-tree binaries, sets `LD_LIBRARY_PATH`, uses
`cgroup_manager = "cgroupfs"`, and preserves the rootful Podman store expected
by Gensee.

## 6. Verify the tclone stack

Check the runtime wiring:

```bash
sudo env "CONTAINERS_STORAGE_CONF=$CONTAINERS_STORAGE_CONF" \
  ./podman-tfork.sh info |
  grep -A2 -E 'conmon:|ociRuntime:|cgroupManager:|graphStatus:|graphRoot:|kernel:|logDriver:'
```

The output should show:

- the in-tree `conmon/bin/conmon`;
- the in-tree `crun/crun`;
- `cgroupManager: cgroupfs`;
- `logDriver: k8s-file`;
- a btrfs graphroot; and
- the `-pgcachecow` kernel.

Verify the individual tfork pieces:

```bash
lsmod | grep -E 'vma_cherrypick|criu_capbypass|pkey_state|reparent_task'
ls -l /dev/vma_cherrypick /dev/criu_capbypass /dev/reparent /dev/pkey_state

LD_LIBRARY_PATH="$PWD/criu/lib/c" \
  ./crun/crun --help | grep tfork

./conmon/bin/conmon --help 2>&1 | grep -- --tfork
sudo env "CONTAINERS_STORAGE_CONF=$CONTAINERS_STORAGE_CONF" \
  ./podman-tfork.sh container clone --help | grep -- --live
cat /proc/filecow_stats
```

Do not continue to Gensee until these checks pass.

## 7. Prepare the Gensee container image

Pull the default image through the rootful tclone wrapper. Pulling it with
ordinary rootless Podman puts it in a different image store and Gensee will not
find it.

```bash
sudo env "CONTAINERS_STORAGE_CONF=$CONTAINERS_STORAGE_CONF" \
  ./podman-tfork.sh pull ghcr.io/wuklab/webtop:ubuntu-kde
sudo env "CONTAINERS_STORAGE_CONF=$CONTAINERS_STORAGE_CONF" \
  ./podman-tfork.sh image inspect \
  ghcr.io/wuklab/webtop:ubuntu-kde >/dev/null
```

To build the image locally instead:

```bash
sudo env "CONTAINERS_STORAGE_CONF=$CONTAINERS_STORAGE_CONF" \
  ./podman-tfork.sh build \
  -t gensee-tclone-webtop:tmux \
  ./ubuntu-img
```

If you build locally, set `GENSEE_TCLONE_IMAGE` to
`gensee-tclone-webtop:tmux`. Otherwise, use the fully qualified GHCR name to
avoid Podman's short-name resolution error.

Gensee creates and live-clones the source container itself. There is no manual
source-container or Podman clone step.

## 8. Install Gensee Crate

Install the Linux prerequisites and Rust:

```bash
sudo apt update
sudo apt install -y \
  build-essential curl git jq libssl-dev nftables pkg-config tmux

curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs |
  sh -s -- -y
source "$HOME/.cargo/env"
```

Build and install Gensee:

```bash
cd ~
git clone https://github.com/GenseeAI/gensee-crate.git
cd gensee-crate
cargo install --path crate/gensee-crate-cli --force
```

Configure Gensee's Codex hooks:

```bash
export GENSEE_HOME="${GENSEE_HOME:-$HOME/.gensee}"
gensee setup codex --yes --gensee-home "$GENSEE_HOME"
```

Open `/hooks` in Codex once and trust the installed Gensee hook command.

## 9. Configure the tclone runtime

Add these exports to the host shell profile:

```bash
export GENSEE_HOME="${GENSEE_HOME:-$HOME/.gensee}"
export GENSEE_TCLONE_PODMAN="$HOME/os4agent/podman-tfork.sh"
export GENSEE_TCLONE_IMAGE="ghcr.io/wuklab/webtop:ubuntu-kde"
export GENSEE_TCLONE_READY_TIMEOUT_SECS=120
export GENSEE_TMP_ROOT="${GENSEE_TMP_ROOT:-/tmp}"
export TMPDIR="$GENSEE_TMP_ROOT"
# Include this only if you created the dedicated storage config in step 3.
# export CONTAINERS_STORAGE_CONF="$GENSEE_HOME/tclone-btrfs-storage.conf"
```

If Node and the agent CLI come from NVM, also export:

```bash
export GENSEE_TCLONE_NODE_ROOT="$HOME/.nvm"
export GENSEE_TCLONE_NODE_BIN="$(dirname "$(command -v node)")"
```

Keep `GENSEE_TMP_ROOT` outside the workspace you will run agents in. If Gensee
stages inside the workspace, later launches can recursively copy the
`gensee-agent-guard` staging tree and fail with `File name too long`.

Use the same sudo-preserving wrapper for every Gensee tclone command:

```bash
alias gensee-tclone='sudo env "PATH=$PATH" "HOME=$HOME" "TERM=$TERM" "TMUX=$TMUX" "TMPDIR=$TMPDIR" "GENSEE_TMP_ROOT=$GENSEE_TMP_ROOT" "CONTAINERS_STORAGE_CONF=$CONTAINERS_STORAGE_CONF" "GENSEE_HOME=$GENSEE_HOME" "GENSEE_TCLONE_PODMAN=$GENSEE_TCLONE_PODMAN" "GENSEE_TCLONE_IMAGE=$GENSEE_TCLONE_IMAGE" "GENSEE_TCLONE_READY_TIMEOUT_SECS=$GENSEE_TCLONE_READY_TIMEOUT_SECS" gensee'
```

Gensee copies or mounts the detected host agent configuration into the source
container. The image must contain `tmux`; the default image does. If you rebuild
or reinstall Gensee, stop the old source and launch a fresh source so the
host-control process uses the new binary.

## 10. Launch Codex through Gensee

Start a host tmux session so Gensee can automatically open and close source and
fork panes:

```bash
tmux new -s gensee
```

Inside tmux, enter the project you want Codex to edit and launch it:

```bash
cd /path/to/your/project

GENSEE_BIN="$(command -v gensee)"

sudo env \
  "PATH=$PATH" \
  "HOME=$HOME" \
  "TERM=$TERM" \
  "TMUX=$TMUX" \
  "TMPDIR=$TMPDIR" \
  "GENSEE_TMP_ROOT=$GENSEE_TMP_ROOT" \
  "CONTAINERS_STORAGE_CONF=$CONTAINERS_STORAGE_CONF" \
  "GENSEE_HOME=$GENSEE_HOME" \
  "GENSEE_TCLONE_PODMAN=$GENSEE_TCLONE_PODMAN" \
  "GENSEE_TCLONE_IMAGE=$GENSEE_TCLONE_IMAGE" \
  "GENSEE_TCLONE_READY_TIMEOUT_SECS=$GENSEE_TCLONE_READY_TIMEOUT_SECS" \
  "$GENSEE_BIN" run --runtime tclone -- codex
```

If you use the optional NVM variables, include them in the `sudo env` command:

```bash
"GENSEE_TCLONE_NODE_ROOT=$GENSEE_TCLONE_NODE_ROOT" \
"GENSEE_TCLONE_NODE_BIN=$GENSEE_TCLONE_NODE_BIN" \
```

The launcher prints the source run ID and starts Codex in a tmux-backed source
container. Normal Gensee/Codex operation is chat-driven: Codex asks before
creating a fork, Gensee opens the fork pane, the work continues in the fork,
and Codex summarizes the result before offering merge, promote, or discard.
Users should not type Gensee lifecycle commands manually.

You can use the wrapper form instead:

```bash
cd /path/to/your/project
gensee-tclone run --runtime tclone -- codex
```

## 11. Smoke-test the mediated fork workflow

In the source Codex chat, submit a deliberately small fork-worthy request:

```text
Make a tiny test strategy smoke test: create fork-smoke-1.txt containing
"first fork". Run only git diff --check.
```

Expected behavior:

1. Codex asks permission to create a fork.
2. After approval, Gensee creates and opens the fork pane.
3. The cloned Codex session continues the original request in the fork.
4. The fork reports its changed files and test result.
5. Codex asks whether to merge, promote, or discard.
6. After explicit approval, Gensee performs the selected action and returns
   focus to the source.

For parallel-fork testing, ask Codex to try two materially different approaches.
Gensee keeps the source pane on the left, stacks fork panes on the right, and
returns the comparison and group-level lifecycle choice to the source Codex.

## Troubleshooting

### Image not found or short-name resolution failed

Pull through the same rootful wrapper Gensee uses and use the fully qualified
image name:

```bash
sudo env "CONTAINERS_STORAGE_CONF=$CONTAINERS_STORAGE_CONF" \
  "$GENSEE_TCLONE_PODMAN" pull \
  ghcr.io/wuklab/webtop:ubuntu-kde
export GENSEE_TCLONE_IMAGE=ghcr.io/wuklab/webtop:ubuntu-kde
```

### Gensee reports that a container is missing

Use the same `sudo`, `GENSEE_HOME`, and `GENSEE_TCLONE_PODMAN` values for every
Gensee tclone invocation. Rootless Podman, rootful Podman without
`CONTAINERS_STORAGE_CONF`, and rootful Podman with `CONTAINERS_STORAGE_CONF`
can all use different stores.

### Fork appears in `gensee run list` but no tmux pane opens

The attach pane re-enters `gensee run attach`, so it needs the same
`GENSEE_HOME`, `GENSEE_TMP_ROOT`, `TMPDIR`, `CONTAINERS_STORAGE_CONF`, and
`GENSEE_TCLONE_PODMAN` environment as the original launch. Use the
`gensee-tclone` alias above for `run`, `list`, `fork`, `attach`, `send`,
`exec`, `merge`, `switch`, and cleanup.

If this happens after rebuilding Gensee, launch a fresh source. Already-running
sources keep their old host-control process in memory.

### `File name too long` during launch

Set `GENSEE_TMP_ROOT` and `TMPDIR` to a directory outside the workspace, then
launch again. If a previous failed launch left a staging tree inside the
workspace, remove that generated `gensee-agent-guard` directory before retrying.

### Kernel modules fail with `Invalid module format`

The `.ko` files were built for a different kernel release than the booted
kernel. Reboot into the `-pgcachecow` kernel, run `uname -r`, rebuild with
`sudo ./criu/build.sh`, and verify that `/dev/vma_cherrypick`,
`/dev/criu_capbypass`, `/dev/reparent`, and `/dev/pkey_state` exist.

### Clone readiness times out

Increase the host-side timeout before launching Gensee:

```bash
export GENSEE_TCLONE_READY_TIMEOUT_SECS=120
export PODMAN_TFORK_CLONE_READY_TIMEOUT_SECS=120
```

If a clone hangs while CRIU walks the source cgroups and reports a timeout
waiting for `tfork.pid*` files, remove stopped tclone containers and then run:

```bash
cd ~/os4agent
sudo ./tfork-cgroup-cleanup.sh
```

### No space left on device

Ask Gensee to delete tracked tclone runs before removing Podman storage:

```bash
GENSEE_BIN="$(command -v gensee)"

sudo env \
  "PATH=$PATH" \
  "HOME=$HOME" \
  "GENSEE_HOME=$GENSEE_HOME" \
  "GENSEE_TCLONE_PODMAN=$GENSEE_TCLONE_PODMAN" \
  "GENSEE_TCLONE_IMAGE=$GENSEE_TCLONE_IMAGE" \
  "$GENSEE_BIN" run delete --all

sudo "$GENSEE_TCLONE_PODMAN" system df
```

Do not delete the graphroot manually while containers or tclone processes are
running.

### Rebuilding after changing CRIU or the kernel modules

Stop active tclone containers first, then rerun `sudo ./criu/build.sh`. The
script intentionally refuses to continue if a loaded module cannot be removed.

## Security and limitations

- The tclone runtime is not currently a confinement boundary. Gensee source
  containers run with unconfined seccomp and AppArmor settings required by the
  live-clone implementation.
- Agent configuration and credentials copied into the source are inherited by
  its forks.
- Tclone currently requires rootful Podman, btrfs, amd64, and the custom
  page-cache CoW kernel.
- The page-cache CoW kernel currently has a known memory leak.

See
[`gensee-crate/docs/tclone.md`](https://github.com/GenseeAI/gensee-crate/blob/main/docs/tclone.md)
for Gensee's fork, comparison, merge, promotion, and discard behavior.

## License

This repository contains multiple components under their respective licenses
(GPL-2.0, LGPL-2.1, Apache-2.0, and GPL-3.0). The license of a given file is the
one in that component's `LICENSE` or `COPYING` file.
