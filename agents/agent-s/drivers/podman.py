"""Podman snapshot driver — handles both CKPT and TFORK modes.

  CKPT  : N back-to-back  podman container clone --copies=1 --persistent=sync
  TFORK : single          podman container clone --copies=N --persistent=async

The mode comparison is "N serial single-copy clones" (CKPT) vs "1 parallel
N-copy clone" (TFORK). CKPT uses --persistent=sync (pages flush before the
clone returns) so each round's dump is fully on-disk before the next freeze
fires; this matches the traditional checkpoint/restore shape we want to
benchmark against TFORK. TFORK stays on --persistent=async because the
on-disk dump runs in parallel with the live CoW clones — the live path is
what we're timing.

Mode-bound at construction; same source-launch + teardown for both, only
``clone()`` branches.
"""

from __future__ import annotations

import logging
import os
import re
import shlex
import shutil
import subprocess
import threading
import time
from pathlib import Path
from typing import TYPE_CHECKING, Any, Optional
if TYPE_CHECKING:
    from bench import BenchConfig, ExpMode
from . import SCREENSHOT_PY as _SCREENSHOT_PY

logger = logging.getLogger(__name__)

_CLONE_ID_RE = re.compile(r"^[0-9a-f]{64}$")
def _parse_clone_ids(stdout: str, expected: int) -> list[str]:
    ids = [ln.strip() for ln in (stdout or "").splitlines()
           if _CLONE_ID_RE.match(ln.strip())]
    if len(ids) != expected:
        raise RuntimeError(
            f"podman clone returned {len(ids)} container ID(s), expected "
            f"{expected}; stdout was: {stdout!r}")
    return ids

_TFORK_BUNDLES = Path("/mnt/btrfs/podman/graphroot/tfork-bundles")

class _LogScraper:
    """Polls /mnt/btrfs/podman/graphroot/tfork-bundles/*/crun-tfork.log every
    50 ms and copies anything new to ``<results_dir>/crun-logs/``. Catches
    crun-tfork.log files in the small window before podman's failure
    cleanup deletes them. Uses ``sudo -n cat`` so it works against
    rootful podman bundle dirs from a non-root test process."""

    POLL_INTERVAL = 0.05
    BUNDLES_ROOT = _TFORK_BUNDLES

    def __init__(self, *, round_idx: int, results_dir):
        self.round_idx = round_idx
        self.dest = (Path(results_dir) / "crun-logs"
                     if results_dir else Path("/tmp/os4agent-crun-logs"))
        self._stop = threading.Event()
        self._thread: threading.Thread | None = None
        self._seen: set[Path] = set()
        self._captured: dict[Path, str] = {}

    def start(self) -> None:
        if not self.BUNDLES_ROOT.exists():
            return
        if os.environ.get("OS4AGENT_NO_CRUN_LOGS"):
            return
        self.dest.mkdir(parents=True, exist_ok=True)
        self._thread = threading.Thread(target=self._poll, daemon=True,
                                         name=f"tfork-log-scraper-r{self.round_idx}")
        self._thread.start()

    def stop(self) -> None:
        self._stop.set()
        if self._thread:
            self._thread.join(timeout=1.0)

    def report(self, stderr: str) -> None:
        """If stderr names a specific log path, dump that one's contents to
        the logger so it shows up next to the failure in the log output."""
        m = re.search(r"see\s+(\S+\.log)\b", stderr)
        if not m:
            return
        target = Path(m.group(1))
        bundle = target.parent.name
        candidates = [
            target,
            self.dest / f"r{self.round_idx}-{bundle}.tfork.log",
            self.dest / f"r{self.round_idx}-{bundle}.crun.log",
        ]
        for cand in candidates:
            content = self._captured.get(cand) or self._read(cand)
            if not content:
                continue

            import re as _re
            err_re = _re.compile(r"\)\s+Error\s+\(")
            lines = content.splitlines()
            err_idx = [i for i, ln in enumerate(lines) if err_re.search(ln)]
            if err_idx:
                snippet_idx: set[int] = set()
                for i in err_idx[:30]:
                    snippet_idx.update(range(max(0, i - 2),
                                             min(len(lines), i + 2)))
                snippet = "\n".join(lines[i] for i in sorted(snippet_idx))
            else:
                snippet = "\n".join(lines[-80:])
            logger.warning("crun-tfork log (%s):\n%s", cand, snippet)
            return

    def _poll(self) -> None:
        sizes: dict[Path, int] = {}
        while not self._stop.is_set():
            try:
                for bundle in self.BUNDLES_ROOT.iterdir():
                    targets: list[tuple[Path, str]] = [
                        (bundle / "crun-tfork.log", "crun"),
                        (bundle / "img" / "tfork.log", "tfork"),
                    ]
                    img = bundle / "img"
                    try:
                        for p in img.glob("*.log"):
                            if p.name == "tfork.log":
                                continue
                            targets.append((p, p.stem))
                    except (FileNotFoundError, PermissionError, OSError):
                        pass
                    for log, suffix in targets:
                        cur_size = self._size(log)
                        if cur_size is None:
                            continue
                        if sizes.get(log) == cur_size:
                            continue
                        content = self._read(log)
                        if content is None:
                            continue
                        sizes[log] = cur_size
                        out = (self.dest
                               / f"r{self.round_idx}-{bundle.name}.{suffix}.log")
                        try:
                            out.write_text(content)
                            self._captured[out] = content
                            logger.debug("scraped %s (%d bytes) → %s",
                                         log, len(content), out)
                        except OSError as e:
                            logger.warning("could not write %s: %s", out, e)
            except FileNotFoundError:
                pass
            except OSError as e:
                logger.debug("scraper iter: %s", e)
            self._stop.wait(self.POLL_INTERVAL)

    @staticmethod
    def _size(path: Path) -> int | None:
        try:
            return path.stat().st_size
        except FileNotFoundError:
            return None
        except PermissionError:
            try:
                r = subprocess.run(["sudo", "-n", "stat", "-c%s", str(path)],
                                   capture_output=True, text=True, timeout=2)
                return int(r.stdout.strip()) if r.returncode == 0 else None
            except (OSError, ValueError, subprocess.TimeoutExpired):
                return None
        except OSError:
            return None

    @staticmethod
    def _read(path: Path) -> str | None:
        """Read ``path``; fall back to ``sudo -n cat`` if EACCES."""
        try:
            return path.read_text(errors="replace")
        except FileNotFoundError:
            return None
        except PermissionError:
            try:
                r = subprocess.run(["sudo", "-n", "cat", str(path)],
                                   capture_output=True, text=True, timeout=2)
                return r.stdout if r.returncode == 0 else None
            except (OSError, subprocess.TimeoutExpired):
                return None
        except OSError:
            return None


class PodmanDriver:
    desktop_user = "abc"
    display = ":1"
    xauthority = "/config/.Xauthority"
    home_dir = "/config"
    current_user = "root"
    path_rewrites = [("/home/user/", "/config/"), ("/root/", "/config/")]

    def __init__(self, mode: "ExpMode", config: "BenchConfig") -> None:
        if mode.name not in ("CKPT", "TFORK"):
            raise ValueError(f"PodmanDriver does not support mode {mode!r}")
        self.mode = mode
        self.config = config

    @property
    def guest_env(self) -> dict[str, str]:
        env = {"DISPLAY": self.display}
        if self.xauthority:
            env["XAUTHORITY"] = self.xauthority
        return env

    def exec_python(self, target: str, code: str, *,
                    env: Optional[dict] = None, timeout: int = 15
                    ) -> subprocess.CompletedProcess:
        """`podman exec -e <env> <target> python3 -c <code>`. Bypasses
        bash -lc so /etc/profile.d/ can't clobber DISPLAY before pyautogui
        sees it. Caller-supplied ``env`` overrides driver defaults."""
        full_env = dict(self.guest_env)
        if env:
            full_env.update(env)
        argv = [self.config.podman, "exec"]
        for k, v in full_env.items():
            argv += ["-e", f"{k}={v}"]
        argv += [target, "python3", "-c", code]
        return subprocess.run(argv, capture_output=True, text=True,
                              timeout=timeout)


    def launch_source(self, *, round_idx: int,
                      pre_ready_hook: Optional[Any] = None) -> str:
        """Boot a source container, wait until ready, run any post-launch
        step. Readiness + post-launch are workload-defined (see
        ``Workload.source_ready_probe`` / ``source_post_launch``); a
        workload that only needs ``tini sleep infinity`` sets neither
        and the driver waits for ``bash -c true`` to succeed.

        ``pre_ready_hook`` is an optional callable invoked with the
        container name immediately after ``podman run -d`` returns,
        *before* the readiness probe loop starts (e.g. to run setup
        against the container before the readiness gate)."""
        name = f"perf-src-r{round_idx}"
        port = 4500 + round_idx
        wl = getattr(self.config, "workload", None)
        common = [
            "--security-opt", "seccomp=unconfined",
            "--security-opt", "label=disable",
            "--cgroupns=host",
            "--shm-size=2g",
        ]
        webtop_args = [
            "--tmpfs", "/config:size=512m",
            "--tmpfs", "/tmp:size=1g",
            "--tmpfs", "/run:size=256m",
            "-e", "PUID=1000", "-e", "PGID=1000", "-e", "TZ=Etc/UTC",
            "-e", "CUSTOM_USER=admin", "-e", "PASSWORD=changeme",
            "-e", "PIXELFLUX_WAYLAND=false",
            "-e", "SELKIES_ENCODER=jpeg",
            "-e", "SELKIES_FRAMERATE=30",
            "-e", "SELKIES_MANUAL_WIDTH=1920",
            "-e", "SELKIES_MANUAL_HEIGHT=1080",
            "-e", "SELKIES_JPEG_QUALITY=40",
            "-p", f"{port}:3001",
        ]
        extra = list(wl.source_run_args) if (wl and wl.source_run_args is not None) else webtop_args
        self._podman("rm", "-f", name, check=False)
        self._podman(
            "run", "-d", "--name", name,
            *common,
            *extra,
            self.config.image,
            check=True,
        )
        if pre_ready_hook is not None:
            try:
                pre_ready_hook(name)
            except Exception as e:
                logger.warning("pre_ready_hook failed: %s", e)
        probe = (wl.source_ready_probe if wl and wl.source_ready_probe
                 else "true")
        deadline = time.monotonic() + 120
        while time.monotonic() < deadline:
            if self.exec(name, probe, timeout=5).returncode == 0:
                break
            time.sleep(0.1)
        else:
            raise RuntimeError(f"source {name} never came ready (probe: {probe!r})")
        if wl and wl.source_post_launch:
            self.exec(name, wl.source_post_launch, timeout=10)

        if (getattr(self.config, "task_setup_enabled", False)
                and wl and wl.task_setup
                and getattr(self.config, "task_config", None)):
            try:
                wl.task_setup(self, name, self.config.task_config)
            except Exception as e:
                logger.warning("task_setup raised: %s", e)

        settle = float(getattr(wl, "source_ready_settle_s", 0.0) or 0.0)
        if settle > 0:
            logger.info("source %s settling for %.1fs", name, settle)
            time.sleep(settle)
        return name

    def cp_into(self, target: str, host_path: str, dest_path: str,
                *, timeout: int = 120) -> None:
        """Write ``host_path`` to ``target:dest_path`` via piped exec.
        Used by the OSWorld task_setup runner for `download` items.

        We DON'T use `podman cp` here even though it's simpler:
        `podman cp` writes through the container's storage driver
        (overlayfs) without going through the container's mount
        namespace, so inotify watches inside the container don't fire.
        Net effect on webtop: file lands at /config/Desktop/foo.mp4
        but KDE Plasma's Folder View never re-renders, and the agent's
        screenshot misses the icon. Piping through `bash -c 'cat > ...'`
        triggers a write event the inotify watch sees."""
        with open(host_path, "rb") as f:
            argv = [self.config.podman, "exec", "-i", target,
                    "bash", "-c", f"cat > {shlex.quote(dest_path)}"]
            subprocess.run(argv, stdin=f, check=True, timeout=timeout,
                           capture_output=True)

    def clone(self, *, src: str, n: int, round_idx: int) -> list[str]:
        """Returns the N container IDs printed by ``podman container
        clone`` on stdout (one 64-char hex per line). ``--name`` is a
        naming HINT, not deterministic — the daemon may pick any unique
        suffix or fall back to a generated name when the hint collides
        with stale state, so we parse the IDs instead of guessing."""
        rp = f"perf-r{round_idx}"
        results_dir = getattr(self.config, "results_dir", None)
        scraper = _LogScraper(round_idx=round_idx, results_dir=results_dir)
        scraper.start()
        try:
            ghost_limit = 64 << 20
            extra_args: list[str] = []
            if os.environ.get("OS4AGENT_TFORK_FULL_MEMCOPY"):
                extra_args.append("--tfork-full-memcopy")
            if self.mode.name == "TFORK":
                base = f"{rp}-tfork"
                self._rm_with_prefix(base)
                persistent = os.environ.get(
                    "OS4AGENT_TFORK_PERSISTENT", "async")
                r = self._podman(
                    "container", "clone", "--live",
                    f"--copies={n}", f"--persistent={persistent}",

                    "--tfork-tcp-close",
                    f"--tfork-ghost-limit={ghost_limit}",
                    *extra_args,
                    "--name", base, src, check=True,
                )
                clones = _parse_clone_ids(r.stdout, n)
            else:
                base = f"{rp}-ckpt"
                self._rm_with_prefix(base)
                clones = []
                parallel = bool(os.environ.get("OS4AGENT_CKPT_PARALLEL"))
                names = [f"{base}-{i}" for i in range(n)]
                ckpt_args = [
                    "container", "clone", "--live",
                    "--copies=1", "--persistent=sync",
                    "--tfork-tcp-close",
                    f"--tfork-ghost-limit={ghost_limit}",
                    *extra_args,
                ]
                if not parallel:
                    for nm in names:
                        r = self._podman(*ckpt_args, "--name", nm, src,
                                         check=True)
                        clones.extend(_parse_clone_ids(r.stdout, 1))
                else:
                    procs = []
                    for nm in names:
                        cmd = [self.config.podman, *ckpt_args,
                               "--name", nm, src]
                        logger.debug("podman (parallel CKPT): %s",
                                     " ".join(cmd))
                        procs.append((nm, subprocess.Popen(
                            cmd, stdout=subprocess.PIPE,
                            stderr=subprocess.PIPE, text=True)))
                    failures: list[str] = []
                    for nm, p in procs:
                        out, err = p.communicate()
                        if p.returncode != 0:
                            self._capture_clone_log(
                                err or "", round_idx, results_dir)
                            scraper.report(err or "")
                            failures.append(
                                f"{nm}: rc={p.returncode}\n"
                                f"stderr={(err or '')[-2000:]}")
                        else:
                            clones.extend(_parse_clone_ids(out, 1))
                    if failures:
                        raise RuntimeError(
                            "parallel CKPT clone failures:\n"
                            + "\n---\n".join(failures))
        except subprocess.CalledProcessError as e:
            stderr = e.stderr or ""
            stdout = e.stdout or ""
            self._capture_clone_log(stderr, round_idx, results_dir)
            scraper.report(stderr)
            if stderr.strip():
                logger.warning("podman stderr (last 2KB):\n%s",
                               stderr[-2000:])
            if stdout.strip():
                logger.warning("podman stdout (last 2KB):\n%s",
                               stdout[-2000:])
            raise
        finally:
            scraper.stop()
        wl = getattr(self.config, "workload", None)
        if wl and wl.source_post_launch:
            for c in clones:
                self.exec(c, wl.source_post_launch, timeout=10)
        return clones

    def teardown(self, *, src: Optional[str], clones: list[str],
                 round_idx: int) -> None:
        """Batched ``podman rm -f`` of every clone, plus ``src`` iff
        non-None. Pass ``src=None`` when the source is being reused."""
        targets = list(clones)
        if src:
            targets.append(src)
        if not targets:
            return
        for target in targets:

            self._podman("rm", "-f", target, check=False)

    def screenshot(self, target: str) -> Optional[bytes]:
        """PIL.ImageGrab over ``podman exec``. Returns PNG bytes, or
        None on failure with the guest's stderr logged so the caller
        can see WHY (missing pyautogui, X11 socket not connectable,
        XAUTHORITY mismatch, etc.)."""
        argv = [self.config.podman, "exec"]
        for k, v in self.guest_env.items():
            argv += ["-e", f"{k}={v}"]
        argv += [target, "python3", "-c", _SCREENSHOT_PY]
        try:
            proc = subprocess.run(argv, capture_output=True, timeout=10)
        except Exception as e:
            logger.warning("screenshot exec for %s raised: %s", target, e)
            return None
        if proc.returncode == 0 and proc.stdout:
            return proc.stdout
        logger.warning(
            "screenshot from %s failed (rc=%d): %s",
            target, proc.returncode,
            (proc.stderr or b"").decode("utf-8", "replace")[:500] or "(no stderr)",
        )
        return None

    def exec(self, target: str, cmd: str, *, timeout: int = 30,
             env: Optional[dict[str, str]] = None) -> subprocess.CompletedProcess:
        """Run ``cmd`` inside ``target`` via ``podman exec``."""
        argv = [self.config.podman, "exec"]
        if env:
            for k, v in env.items():
                argv += ["-e", f"{k}={v}"]
        argv += [target, "bash", "-lc", cmd]

        return subprocess.run(argv, capture_output=True, text=True, timeout=timeout)

    def working_set_bytes(self, target: str) -> Optional[int]:
        """Bytes the snapshot mechanism must dump to clone ``target``.

        TFORK: sum ``/proc/<pid>/statm`` field 2 (resident pages) across
        the container's ``cgroup.procs``, multiplied by page size.
        Why not cgroup memory.current: kernel charges pages to the
        cgroup they were first allocated in, so every CRIU-restored
        source in the chain (round 2+) reads 0. statm is read from
        per-process /proc and reflects what's actually mapped, so all
        rounds use the same lens. Caveat: over-counts pages shared
        between processes in the same cgroup (e.g. libQt5Core.so across
        KDE procs). ~10 us/proc; sub-ms for typical container.

        CKPT and other modes: cgroup v2 memory.current with VmRSS
        fall-back (kept as-is from the prior fix).
        """
        try:
            r = self._podman("inspect", "--format", "{{.State.CgroupPath}}",
                             target, check=False)
        except (OSError, subprocess.SubprocessError):
            return None
        cgroup = (r.stdout or "").strip()
        if not cgroup:
            return None

        if self.mode.name == "TFORK":
            procs_file = Path(f"/sys/fs/cgroup{cgroup}/cgroup.procs")
            try:
                pids = procs_file.read_text().split()
            except OSError:
                return None
            page = os.sysconf("SC_PAGE_SIZE")
            total_pages = 0
            for pid in pids:
                try:
                    total_pages += int(
                        Path(f"/proc/{pid}/statm").read_text().split()[1])
                except (OSError, ValueError, IndexError):
                    continue
            return total_pages * page if total_pages > 0 else None

        v2 = Path(f"/sys/fs/cgroup{cgroup}/memory.current")
        try:
            n = int(v2.read_text().strip())
            if n > 0:
                return n
        except (OSError, ValueError):
            pass

        procs_file = Path(f"/sys/fs/cgroup{cgroup}/cgroup.procs")
        try:
            pids = procs_file.read_text().split()
        except OSError:
            pids = []
        total_kb = 0
        for pid in pids:
            try:
                for line in Path(f"/proc/{pid}/status").read_text().splitlines():
                    if line.startswith("VmRSS:"):
                        total_kb += int(line.split()[1])
                        break
            except (OSError, ValueError):
                continue
        if total_kb > 0:
            return total_kb * 1024

        v1 = Path(f"/sys/fs/cgroup/memory/memory.usage_in_bytes{cgroup}")
        try:
            return int(v1.read_text().strip())
        except (OSError, ValueError):
            return None

    def _capture_clone_log(self, stderr: str, round_idx: int,
                           results_dir) -> None:
        """When podman clone fails it prints ``see <path>/crun-tfork.log``
        in stderr. That log is wiped during the daemon's failure cleanup,
        so read it now and stash a copy under ``<results_dir>/clone-fail-r<N>.log``.

        Rootful podman writes logs as root, so plain read fails with
        EACCES from a non-root test process — fall back to ``sudo -n
        cat``. Best-effort: silent on read errors."""
        m = re.search(r"see\s+(\S+\.log)\b", stderr)
        if not m:
            return
        log_path = m.group(1)
        from pathlib import Path
        try:
            content = Path(log_path).read_text(errors="replace")
        except PermissionError:
            try:
                r = subprocess.run(["sudo", "-n", "cat", log_path],
                                   capture_output=True, text=True, timeout=5)
                if r.returncode == 0:
                    content = r.stdout
                else:
                    logger.warning(
                        "sudo -n cat %s failed (rc=%d): %s. Add a NOPASSWD "
                        "rule for cat, or run under sudo.",
                        log_path, r.returncode, r.stderr.strip())
                    return
            except (OSError, subprocess.TimeoutExpired) as e:
                logger.warning("sudo cat %s failed: %s", log_path, e)
                return
        except OSError as e:
            logger.warning("could not read crun log %s: %s", log_path, e)
            return

        logger.warning("crun-tfork log (%s):\n%s", log_path, content[-4000:])

        if results_dir is not None:
            try:
                from pathlib import Path
                dest = Path(results_dir) / f"clone-fail-r{round_idx}.log"
                dest.parent.mkdir(parents=True, exist_ok=True)
                dest.write_text(content)
                logger.warning("saved crun log to %s", dest)
            except OSError:
                pass

    def _rm_with_prefix(self, prefix: str) -> None:
        """Best-effort ``podman rm -f`` of every container whose name
        begins with ``prefix``. Catches stale entries from a prior
        aborted run that would otherwise collide on the next clone.
        Uses ``--filter name=^<prefix>`` (anchored) so a more general
        prefix doesn't sweep unrelated containers."""
        r = self._podman("ps", "-a", "--filter", f"name=^{prefix}",
                         "--format", "{{.Names}}", check=False)
        names = [n.strip() for n in (r.stdout or "").splitlines() if n.strip()]
        if names:
            self._podman("rm", "-f", *names, check=False)

    def _podman(self, *args: str, check: bool = True) -> subprocess.CompletedProcess:
        argv = [self.config.podman, *args]
        logger.debug("podman: %s", " ".join(argv))
        return subprocess.run(argv, capture_output=True, text=True, check=check)
