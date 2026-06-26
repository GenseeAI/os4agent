# Tclone

Tclone is a workspace-versioning substrate built for computer-use agents. Tclone provides a versioned personal workspace that can be quickly forked, snapshotted, and rolledback.
It forks a live, running container in milliseconds: clones share
memory and file-cache pages copy-on-write, so a branch is runnable
instantly while its durable checkpoint streams to disk in the background —
letting computer-use agents explore many action paths in parallel.

Please find more details in our [paper](https://arxiv.org/abs/2605.17320) and
[blog post](https://mlsys.wuklab.io/posts/tclone/).

<img width="1672" height="941" alt="image" src="https://mlsys.wuklab.io/images/tclone/overview.png" />

## Components

| Directory | Role |
|---|---|
| [`criu/`](criu/) | `criu tfork` + `vma_cherrypick` / `capbypass` kernel modules + libcriu |
| [`crun/`](crun/) | `crun tfork` OCI runtime verb |
| [`conmon/`](conmon/) | `--tfork` flag |
| [`podman/`](podman/) | `container clone --live` |
| [`linux-pagecache-cow/`](linux-pagecache-cow/) | Linux kernel with a CoW page-cache (`filecow`) layer |
| [`ubuntu-img/`](ubuntu-img/) | sample webtop image (optional) |
| [`agents/`](agents/) | OSWorld evaluation harness |

## Prerequisites

- Ubuntu x86_64, root access.
- btrfs filesystem at podman's graphroot
  (`findmnt -no FSTYPE /var/lib/containers/storage` → `btrfs`).

## Required sysctls

```bash
sudo sysctl -w kernel.io_uring_disabled=2
sudo sysctl -w fs.nr_open=1048576
sudo sysctl -w fs.inotify.max_user_instances=524288
sudo sysctl -w kernel.apparmor_restrict_unprivileged_unconfined=0
```

Persist by appending to `/etc/sysctl.d/90-tfork.conf`.

## Fetch submodules

```bash
git submodule update --init --recursive
```

## Build (in this order, all as root)

```bash
sudo apt install podman     # podman has some other components we won't modify
                            # this makes installing components much simpler
sudo ./criu/build.sh        # libcriu + kernel modules
sudo ./crun/build.sh        # links against in-tree libcriu
sudo ./conmon/build.sh      # --tfork flag
sudo ./podman/build.sh      # container clone --live
```

## Custom kernel (page-cache CoW)

[`linux-pagecache-cow/`](linux-pagecache-cow/) is a modified Linux that
adds a copy-on-write page-cache (`filecow`) layer shared across
`address_space`s when one btrfs subvol is a snapshot of another. With this
kernel running, the default `btrfs subvolume snapshot` rootfs path of
`--live` clones shares its file pages with the source through the kernel
CoW path.

```sh
# install your distro's kernel build dependencies (gcc, make, bison, flex,
# libelf-dev, libssl-dev, bc, etc.)
cd linux-pagecache-cow
cp config .config
./build_kernel.sh build
sudo ./build_kernel.sh install   # then reboot into the pgcachecow kernel
```

Verify after reboot:

```sh
uname -r
cat /proc/filecow_stats   # ra_unbounded_calls / ra_order_calls grow on fan-out
```

## Run podman

Run podman through [`./podman-tfork.sh`](./podman-tfork.sh) — a wrapper that
points the in-tree podman at the in-tree conmon, crun, and libcriu without
touching any system files. It writes a `CONTAINERS_CONF` (in-tree conmon +
crun, `cgroup_manager = "cgroupfs"`, `log_driver = "k8s-file"`), sets
`LD_LIBRARY_PATH` for libcriu, and exports `OS4AGENT_CRUN` / `OS4AGENT_CONMON`.
All other arguments pass through to podman.

## Verify

Wiring:

```bash
sudo ./podman-tfork.sh info | grep -A2 -E "conmon:|ociRuntime:|cgroupManager:|graphStatus:|graphRoot:|kernel:|logDriver:"
```

`conmon` and `ociRuntime` should point at the in-tree binaries (the
`ociRuntime` version reads `criu_tfork_*`); `cgroupManager` = `cgroupfs`,
`logDriver` = `k8s-file`, `graphRoot` on a btrfs mount, `kernel` the
page-cache-CoW build.

The tfork pieces are live:

```bash
# all 4 criu kernel modules loaded (criu/build.sh insmods these):
lsmod | grep -E 'vma_cherrypick|criu_capbypass|pkey_state|reparent_task'

# tfork verbs/flags present in the in-tree binaries:
LD_LIBRARY_PATH=$(pwd)/criu/lib/c ./crun/crun --help | grep tfork   # crun tfork verb
./conmon/bin/conmon --help 2>&1 | grep -- --tfork                  # conmon --tfork
sudo ./podman-tfork.sh container clone --help | grep -- --live     # podman --live

# page-cache-CoW kernel running:
cat /proc/filecow_stats
```

## Start os-world container
```bash
sudo ./podman-tfork.sh run -d \
      --name webtop-src \
      --log-driver=k8s-file \
      --security-opt seccomp=unconfined \
      --security-opt apparmor=unconfined \
      --shm-size=2g \
      --tmpfs /config:size=512m \
      --tmpfs /tmp:size=1g \
      --tmpfs /run:size=256m \
      -e PUID=1000 -e PGID=1000 -e TZ=Etc/UTC \
      -e CUSTOM_USER=admin -e PASSWORD=changeme \
      -p 3101:3001 \
      ghcr.io/wuklab/webtop:ubuntu-kde
```

## Clone 4
```bash
sudo ./podman-tfork.sh container clone --live --copies=4 \
      --persistent=async \
      --tfork-tcp-close --tfork-ghost-limit=$((64 << 20)) \
      --name webtop-fan webtop-src
```

## Live-clone flags & environment

Flags below attach to `podman container clone --live`. Run
`./podman-tfork.sh --tfork-help` for the same reference at the shell.

| Flag | Default | Effect |
|---|---|---|
| `--live` | off | engage the tfork path; required to clone live. |
| `--copies N` | 1 | fan out to N parallel clones from one source freeze. |
| `--persistent[=async\|sync]` | off | persist source memory to clone's image-dir (`pages-*.img`). Bare `--persistent` → async; `=sync` flushes before clone returns. |
| `--tfork-ghost-limit BYTES` | 256 MiB | raise CRIU's per-dump ghost-file cap above its 1 MiB default. GUI apps (chromium, firefox, KDE) keep multi-MiB unlinked tmp files mmap'd. `0` falls back to CRIU's default. |
| `--tfork-tcp-close[=BOOL]` | true | dump ESTABLISHED TCP sockets as closed (clones with fresh netns reconnect cleanly). `=false` reverts to CRIU's refuse-on-established. |

## Clean up

If `podman container clone --live` hangs in Phase A (CRIU's cgroup walk)
and eventually fails with `timeout waiting for N tfork.pid* files`, the
cgroup tree has likely accumulated empty zombie cgroups from prior crashed
clones. CRIU enumerates every cgroup the source process belongs to, and a
few hundred thousand empty entries push past the 60s podman timeout.

```bash
sudo ./tfork-cgroup-cleanup.sh
```

## Usage with Agent-S3

check [agent-s README](agents/agent-s/README.md)

## Limitations

- btrfs only
- rootful only
- amd64 only
- linux page-cache CoW currently has a memory leak that will be fixed

## License

This repository contains multiple components under their respective
licenses (GPL-2.0, LGPL-2.1, Apache-2.0, GPL-3.0). The license of a given
file is the one of the directory it lives in; see the `LICENSE`/`COPYING`
file there.
