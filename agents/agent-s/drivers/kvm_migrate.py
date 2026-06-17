"""KVM migrate driver — QMP migrate-out + N -incoming children.

Source ends each round in ``postmigrate`` (paused); the bench currently
re-launches a fresh source per round rather than ``cont``'ing the old one.
See CLAUDE.md for freeze-window vs other drivers.
"""

from __future__ import annotations

import json
import logging
import os
import shlex
import shutil
import socket
import subprocess
import threading
import time
from pathlib import Path
from typing import TYPE_CHECKING, Optional

from . import SCREENSHOT_PY as _SCREENSHOT_PY

if TYPE_CHECKING:
    from bench import BenchConfig

logger = logging.getLogger(__name__)


class KvmMigrateDriver:
    desktop_user = "user"
    display = ":0"
    xauthority = "/home/user/.Xauthority"
    home_dir = "/home/user"
    current_user = "user"
    path_rewrites: list[tuple[str, str]] = []

    def __init__(self, config: "BenchConfig") -> None:
        self.config = config

        self._meta: dict[str, dict[str, int]] = {}

    @property
    def guest_env(self) -> dict[str, str]:
        env = {"DISPLAY": self.display}
        if self.xauthority:
            env["XAUTHORITY"] = self.xauthority
        return env

    def exec_python(self, target: str, code: str, *,
                    env: Optional[dict] = None,
                    timeout: int = 15) -> subprocess.CompletedProcess:
        """ssh + `env K=V python3 -c <code>`. Bypasses bash -lc so
        /etc/profile.d/ can't override DISPLAY before pyautogui sees
        it. Same shape as PodmanDriver.exec_python so
        osworld_run_branch's action step is driver-agnostic."""
        port = self._meta.get(target, {}).get("ssh_port")
        if port is None:
            raise RuntimeError(f"unknown target {target!r}")
        full_env = dict(self.guest_env)
        if env:
            full_env.update(env)
        env_str = " ".join(f"{k}={shlex.quote(v)}"
                           for k, v in full_env.items())
        cmd = f"{env_str} python3 -c {shlex.quote(code)}"
        return subprocess.run([
            "ssh", "-i", str(self.config.ssh_key),
            "-p", str(port),
            "-o", "StrictHostKeyChecking=no", "-o", "BatchMode=yes",
            "user@127.0.0.1", cmd,
        ], capture_output=True, text=True, timeout=timeout)

    def cp_into(self, target: str, host_path: str, dest_path: str,
                *, timeout: int = 120) -> None:
        """scp host_path into target's filesystem at dest_path. Used by
        osworld_task_setup's `download` dispatcher with --setup."""
        port = self._meta.get(target, {}).get("ssh_port")
        if port is None:
            raise RuntimeError(f"unknown target {target!r}")

        parent = os.path.dirname(dest_path) or "."
        self.exec(target, f"mkdir -p {shlex.quote(parent)}", timeout=20)
        subprocess.run([
            "scp", "-i", str(self.config.ssh_key),
            "-P", str(port),
            "-o", "StrictHostKeyChecking=no", "-o", "BatchMode=yes",
            host_path, f"user@127.0.0.1:{dest_path}",
        ], check=True, timeout=timeout)

    def launch_source(self, *, round_idx: int) -> str:
        name = f"kvm-src-r{round_idx}"
        run_dir = self.config.kvm_run_base / name


        self._reset_run_base()
        self._reset_run_dir(run_dir, name=name)
        run_dir.mkdir(parents=True, exist_ok=True)

        ovmf_vars = run_dir / "OVMF_VARS.fd"
        if not ovmf_vars.exists():
            shutil.copy("/usr/share/OVMF/OVMF_VARS_4M.fd", ovmf_vars)

        src_disk = run_dir / "disk.qcow2"
        argv = ["qemu-img", "create", "-f", "qcow2",
                "-b", str(self.config.base_disk), "-F", "qcow2",
                str(src_disk)]
        r = subprocess.run(argv, capture_output=True, text=True)
        if r.returncode != 0:
            raise RuntimeError(
                f"qemu-img create failed (rc={r.returncode}): "
                f"{r.stderr.strip() or '(no stderr)'}\n"
                f"  cmd: {' '.join(argv)}"
            )

        ssh_port = 8060 + round_idx
        vnc_disp = 30 + round_idx
        self._qemu_launch(name=name, run_dir=run_dir, disk=src_disk,
                          ssh_port=ssh_port, vnc_disp=vnc_disp)
        if not self._wait_ssh(ssh_port):
            raise RuntimeError(f"KVM source {name}: sshd on :{ssh_port} never came up")


        if not self._wait_desktop(ssh_port):
            raise RuntimeError(
                f"KVM source {name}: desktop never came ready on :{ssh_port}"
            )
        self._meta[name] = {"ssh_port": ssh_port, "vnc_disp": vnc_disp}
        return name

    def clone(self, *, src: str, n: int, round_idx: int) -> list[str]:
        src_dir = self.config.kvm_run_base / src
        state = src_dir / "state.bin"
        self._qmp_human(src_dir / "qmp.sock",
                        f'migrate "exec:cat > {state}"')
        self._wait_migrate_completed(src_dir / "qmp.sock")
        os.sync()
        self._kill_source_after_migrate(src)

        clones: list[str] = []
        threads: list[threading.Thread] = []

        def _start_child(i: int) -> None:
            nm = f"perf-r{round_idx}-kvm-{i}"
            cdir = self.config.kvm_run_base / nm
            cdir.mkdir(parents=True, exist_ok=True)
            shutil.copy("/usr/share/OVMF/OVMF_VARS_4M.fd", cdir / "OVMF_VARS.fd")
            cdisk = cdir / "disk.qcow2"
            cargv = ["qemu-img", "create", "-f", "qcow2",
                     "-b", str(src_dir / "disk.qcow2"), "-F", "qcow2",
                     str(cdisk)]
            r = subprocess.run(cargv, capture_output=True, text=True)
            if r.returncode != 0:
                raise RuntimeError(
                    f"qemu-img create (clone {nm}) failed "
                    f"(rc={r.returncode}): {r.stderr.strip() or '(no stderr)'}"
                )
            ssh_port = 8061 + round_idx * 10 + i
            vnc_disp = 40 + round_idx * 10 + i
            self._qemu_launch(
                name=nm, run_dir=cdir, disk=cdisk,
                ssh_port=ssh_port, vnc_disp=vnc_disp,
                incoming=f"exec:cat {state}",
            )
            self._meta[nm] = {"ssh_port": ssh_port, "vnc_disp": vnc_disp}
            clones.append(nm)

        for i in range(n):
            th = threading.Thread(target=_start_child, args=(i,), daemon=True)
            th.start()
            threads.append(th)
        for th in threads:
            th.join()

        for nm in clones:
            if not self._wait_ssh(self._meta[nm]["ssh_port"]):
                logger.warning("KVM child %s sshd not ready", nm)
        return sorted(clones, key=lambda c: int(c.rsplit("-", 1)[-1]))

    def teardown(self, *, src: Optional[str], clones: list[str],
                 round_idx: int) -> None:
        """Tear down ONLY the explicitly named src + clones. Mid-beam
        calls pass src=None and clones=[losers], so the winner stays
        alive to be cloned again in round R+1. End-of-beam calls pass
        src=<chain entry>, clones=[] for each historical chain member.

        Previously had a `glob(f'perf-r{round_idx}-*')` sweep here
        that "garbage-collected" any leftover dirs from this round —
        but that included the winner, breaking round 2's clone()
        which looks up <winner>/qmp.sock. The explicit list is
        sufficient; the chain teardown at end of beam_search picks
        up everything that got promoted forward."""
        targets = list(clones) + ([src] if src else [])
        for nm in targets:
            d = self.config.kvm_run_base / nm
            pid_file = d / "qemu.pid"
            if pid_file.exists():
                try:
                    os.kill(int(pid_file.read_text().strip()), 9)
                except (OSError, ValueError):
                    pass
            shutil.rmtree(d, ignore_errors=True)
            self._meta.pop(nm, None)

    def screenshot(self, target: str) -> Optional[bytes]:
        port = self._meta.get(target, {}).get("ssh_port")
        if port is None:
            return None
        argv = [
            "ssh", "-i", str(self.config.ssh_key),
            "-p", str(port),
            "-o", "StrictHostKeyChecking=no", "-o", "BatchMode=yes",
            "-o", "ConnectTimeout=4",
            "user@127.0.0.1",
            "DISPLAY=:0 XAUTHORITY=/home/user/.Xauthority python3",
        ]
        try:
            proc = subprocess.run(argv, input=_SCREENSHOT_PY.encode(),
                                  capture_output=True, text=False, timeout=15)
            if proc.returncode != 0:
                logger.warning("ssh screenshot from %s rc=%d: %s",
                               target, proc.returncode,
                               (proc.stderr or b"").decode("utf-8", "replace")
                               .strip()[:240])
                return None
            return proc.stdout if proc.stdout else None
        except Exception as e:
            logger.warning("ssh screenshot from %s failed: %s", target, e)
            return None

    def exec(self, target: str, cmd: str, *, timeout: int = 30
             ) -> subprocess.CompletedProcess:
        port = self._meta.get(target, {}).get("ssh_port")
        if port is None:
            raise RuntimeError(f"unknown target {target!r}")
        return subprocess.run([
            "ssh", "-i", str(self.config.ssh_key),
            "-p", str(port),
            "-o", "StrictHostKeyChecking=no", "-o", "BatchMode=yes",
            "user@127.0.0.1", f"bash -lc {shlex.quote(cmd)}",
        ], capture_output=True, text=True, timeout=timeout)

    def working_set_bytes(self, target: str) -> Optional[int]:
        """qemu's RSS = VM RAM + small host-side overhead. One read
        of /proc/<qemu-pid>/status."""
        d = self.config.kvm_run_base / target
        try:
            pid = int((d / "qemu.pid").read_text().strip())
            for line in Path(f"/proc/{pid}/status").read_text().splitlines():
                if line.startswith("VmRSS:"):
                    return int(line.split()[1]) * 1024
        except (OSError, ValueError):
            return None
        return None

    def _kill_source_after_migrate(self, src: str) -> None:
        """SIGKILL the source qemu and remove it from _meta. Called
        right after _wait_migrate_completed: the source is paused and
        its anon-RSS is dead weight while N children spawn. state.bin
        on disk is unaffected (regular file)."""
        src_dir = self.config.kvm_run_base / src
        pid_file = src_dir / "qemu.pid"
        if not pid_file.exists():
            return
        try:
            pid = int(pid_file.read_text().strip())
            os.kill(pid, 9)
            logger.info("freed source %s (pid %d) after migrate", src, pid)
        except (OSError, ValueError):
            pass


        for f in ("qmp.sock", "qemu.pid"):
            try:
                (src_dir / f).unlink()
            except FileNotFoundError:
                pass
        self._meta.pop(src, None)

    def _reset_run_base(self) -> None:
        """Kill every qemu-system whose argv references this driver's
        kvm_run_base, then rmtree every per-target dir under it.
        Run once at launch_source start so subsequent bench invocations
        don't trip over stale clones from a prior failed run binding
        ssh-forward ports we want to reuse.

        Doesn't error if kvm_run_base doesn't exist yet (first run on
        a fresh host)."""
        run_base = self.config.kvm_run_base
        if not run_base.exists():
            return

        try:
            r = subprocess.run(
                ["pgrep", "-f", f"qemu-system-x86_64.*{run_base}"],
                capture_output=True, text=True, timeout=5,
            )
            for pid_str in (r.stdout or "").split():
                try:
                    os.kill(int(pid_str), 9)
                    logger.info("reset: killed leftover qemu pid %s "
                                "in %s", pid_str, run_base)
                except (OSError, ValueError):
                    pass
        except (OSError, subprocess.SubprocessError):
            pass

        time.sleep(0.5)

        for entry in run_base.iterdir():
            if entry.is_dir():
                shutil.rmtree(entry, ignore_errors=True)


        self._meta.clear()

    def _reset_run_dir(self, run_dir: Path, *, name: str) -> None:
        """Kill any qemu still alive from a prior failed run + wipe the
        run_dir. Safe to call when run_dir doesn't exist (no-op)."""
        if not run_dir.exists():
            return
        pid_file = run_dir / "qemu.pid"
        if pid_file.exists():
            try:
                pid = int(pid_file.read_text().strip())
                logger.info("reset: killing stale qemu pid %d for %s",
                            pid, name)
                os.kill(pid, 9)
            except (OSError, ValueError):
                pass

        try:
            r = subprocess.run(
                ["pgrep", "-f", f"qemu-system-x86_64.*{run_dir}"],
                capture_output=True, text=True, timeout=5,
            )
            for pid_str in (r.stdout or "").split():
                try:
                    os.kill(int(pid_str), 9)
                    logger.info("reset: killed qemu pid %s matching %s",
                                pid_str, run_dir)
                except (OSError, ValueError):
                    pass
        except (OSError, subprocess.SubprocessError):
            pass

        time.sleep(0.5)
        shutil.rmtree(run_dir, ignore_errors=True)

    def _qemu_launch(self, *, name: str, run_dir: Path, disk: Path,
                     ssh_port: int, vnc_disp: int,
                     incoming: Optional[str] = None) -> None:
        logger.info("qemu launch %s: disk=%s ssh=:%d vnc=:%d incoming=%s",
                    name, disk, ssh_port, vnc_disp, incoming or "none")
        args = [
            "qemu-system-x86_64",
            "-name", name,
            "-machine", "q35,smm=on,accel=kvm",
            "-enable-kvm",
            "-cpu", "host,kvm=on,l3-cache=on,+hypervisor,-invtsc",
            "-smp", "4",
            "-m", os.environ.get("KVM_VM_MEM", "2048M"),
            "-global", "ICH9-LPC.disable_s3=1",
            "-global", "kvm-pit.lost_tick_policy=discard",
            "-drive", "if=pflash,format=raw,readonly=on,file=/usr/share/OVMF/OVMF_CODE_4M.fd",
            "-drive", f"if=pflash,format=raw,file={run_dir}/OVMF_VARS.fd,snapshot=on",
            "-drive", f"file={disk},format=qcow2,if=none,id=disk0,discard=unmap,cache=writeback,aio=threads",
            "-device", "virtio-blk-pci,drive=disk0,bootindex=1",
            "-netdev", f"user,id=n0,hostfwd=tcp::{ssh_port}-:22",
            "-device", "virtio-net-pci,netdev=n0",
            "-object", "rng-random,id=rng0,filename=/dev/urandom",
            "-device", "virtio-rng-pci,rng=rng0",
            "-vga", "virtio",
            "-vnc", f"127.0.0.1:{vnc_disp}",
            "-qmp", f"unix:{run_dir}/qmp.sock,server=on,wait=off",
            "-serial", f"file:{run_dir}/serial.log",
            "-pidfile", f"{run_dir}/qemu.pid",
            "-display", "none", "-daemonize",
        ]
        if incoming:
            args += ["-incoming", incoming]
        proc = subprocess.run(args, capture_output=True, text=True)
        if proc.returncode != 0:
            raise RuntimeError(
                f"qemu launch {name!r} failed rc={proc.returncode}: "
                f"{proc.stderr.strip()}"
            )

    def _qmp_query(self, sock: Path, command: str) -> dict:
        """Send a structured QMP query and return its `return` body.
        Used by the migrate poller below; doesn't share state with
        _qmp_human (each call opens its own socket since QMP doesn't
        multiplex)."""
        s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        s.connect(str(sock))
        s.settimeout(15)
        try:
            self._qmp_recv_json(s)
            s.sendall(b'{"execute":"qmp_capabilities"}\r\n')
            self._qmp_recv_json(s)
            s.sendall(json.dumps({"execute": command}).encode() + b"\r\n")
            reply = self._qmp_recv_json(s, want=("return", "error"))
        finally:
            s.close()
        if "error" in reply:
            raise RuntimeError(f"QMP {command!r} failed: {reply['error']}")
        return reply.get("return", {})

    def _wait_migrate_completed(self, sock: Path, *,
                                timeout_s: int = 600) -> None:
        """Poll query-migrate until status=='completed'. Raises on
        'failed' or 'cancelled'. Logs progress every ~5s so a slow
        host (spinning btrfs at 38 MB/s = 105s for 4 GB) doesn't look
        frozen."""
        deadline = time.monotonic() + timeout_s
        last_log_at = 0.0
        while time.monotonic() < deadline:
            r = self._qmp_query(sock, "query-migrate")
            status = r.get("status", "unknown")
            if status == "completed":
                ram = r.get("ram", {})
                logger.info(
                    "migrate completed: total=%dB transferred=%dB "
                    "duration=%dms",
                    ram.get("total", 0),
                    ram.get("transferred", 0),
                    r.get("total-time", 0),
                )
                return
            if status in ("failed", "cancelled"):
                raise RuntimeError(
                    f"migrate failed: status={status} "
                    f"error={r.get('error-desc', '(none)')}"
                )
            now = time.monotonic()
            if now - last_log_at > 5.0:
                ram = r.get("ram", {})
                pct = (100 * ram.get("transferred", 0)
                       / max(ram.get("total", 1), 1))
                logger.info("migrate %s: %.0f%% transferred (%d MB/s)",
                            status, pct,
                            int(ram.get("mbps", 0)))
                last_log_at = now
            time.sleep(0.5)
        raise TimeoutError(
            f"migrate did not complete within {timeout_s}s "
            f"(last status: {status})"
        )

    def _qmp_human(self, sock: Path, cmd: str) -> str:
        s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        s.connect(str(sock))
        s.settimeout(15)
        try:
            self._qmp_recv_json(s)
            s.sendall(b'{"execute":"qmp_capabilities"}\r\n')
            self._qmp_recv_json(s)
            s.sendall(json.dumps({
                "execute": "human-monitor-command",
                "arguments": {"command-line": cmd},
            }).encode() + b"\r\n")
            reply = self._qmp_recv_json(s, want=("return", "error"))
        finally:
            s.close()
        if "error" in reply:
            raise RuntimeError(f"QMP {cmd!r} failed: {reply['error']}")
        return json.dumps(reply)

    @staticmethod
    def _qmp_recv_json(s: socket.socket,
                       want: tuple[str, ...] = ()) -> dict:
        """Drain newline-delimited JSON until a frame containing any of
        ``want`` (or any frame if ``want`` is empty) arrives."""
        buf = bytearray()
        while True:
            chunk = s.recv(4096)
            if not chunk:
                raise RuntimeError("QMP socket closed mid-reply")
            buf += chunk
            while b"\n" in buf:
                line, _, buf = buf.partition(b"\n")
                line = line.strip()
                if not line:
                    continue
                try:
                    obj = json.loads(line)
                except json.JSONDecodeError:
                    continue
                if not want or any(k in obj for k in want):
                    return obj

    def _wait_desktop(self, port: int, *, timeout_s: int = 90,
                      settle_s: float = 5.0) -> bool:
        """Wait for GNOME-Shell to actually be drawing the desktop, not
        just sshd + Xorg up. Three signals via a single ssh:
          1. xdpyinfo — X server up
          2. pgrep -x gnome-shell — shell process running
          3. xprop -root _NET_SUPPORTING_WM_CHECK — WM has registered
             with X (the canonical EWMH "WM is alive" probe)
        Plus settle_s extra seconds for first-frame paint.

        Logs progress every ~5s so a hang is diagnosable. Without this
        probe, bench.py --modes KVM hands the agent a black screenshot
        on round 1 and burns a round on a wake-the-display action."""
        deadline = time.monotonic() + timeout_s
        last_log_at = 0.0
        last_state = "starting"
        ssh_argv = [
            "ssh", "-i", str(self.config.ssh_key),
            "-p", str(port),
            "-o", "StrictHostKeyChecking=no",
            "-o", "BatchMode=yes", "-o", "ConnectTimeout=4",
            "user@127.0.0.1",
        ]

        def _probe(cmd: str) -> int:
            try:
                r = subprocess.run([*ssh_argv, cmd], capture_output=True,
                                   timeout=8)
                return r.returncode
            except subprocess.TimeoutExpired:
                return 124

        while time.monotonic() < deadline:
            if _probe("DISPLAY=:0 xdpyinfo >/dev/null 2>&1") != 0:
                last_state = "X server not ready"
            elif _probe("pgrep -x gnome-shell >/dev/null") != 0:
                last_state = "gnome-shell not started"
            elif _probe(
                "DISPLAY=:0 xprop -root _NET_SUPPORTING_WM_CHECK 2>/dev/null "
                "| grep -q 'window id'"
            ) != 0:
                last_state = "WM not registered yet"
            else:
                logger.info("desktop ready on :%d; settling %.1fs for "
                            "first-frame paint", port, settle_s)
                time.sleep(settle_s)
                return True
            now = time.monotonic()
            if now - last_log_at > 5.0:
                elapsed = timeout_s - (deadline - now)
                logger.info("waiting for desktop on :%d (%.0fs/%ds): %s",
                            port, elapsed, timeout_s, last_state)
                last_log_at = now
            time.sleep(1.0)
        logger.warning("desktop never came ready on :%d (%s)",
                       port, last_state)
        return False

    def _wait_ssh(self, port: int, *, timeout_s: int = 240) -> bool:
        deadline = time.monotonic() + timeout_s
        last_log_at = 0.0
        last_stderr = ""
        attempts = 0
        while time.monotonic() < deadline:
            try:
                proc = subprocess.run([
                    "ssh", "-i", str(self.config.ssh_key),
                    "-p", str(port),
                    "-o", "StrictHostKeyChecking=no",
                    "-o", "BatchMode=yes", "-o", "ConnectTimeout=2",
                    "user@127.0.0.1", "true",
                ], capture_output=True, timeout=4)
                if proc.returncode == 0:
                    elapsed = timeout_s - (deadline - time.monotonic())
                    logger.info("sshd on :%d came up after %.1fs (%d probes)",
                                port, elapsed, attempts)
                    return True
                last_stderr = (proc.stderr or b"").decode("utf-8", "replace").strip()
            except subprocess.TimeoutExpired:
                last_stderr = "ssh probe timed out"
            attempts += 1
            now = time.monotonic()


            if now - last_log_at > 10.0:
                elapsed = timeout_s - (deadline - now)
                logger.info(
                    "waiting for sshd on :%d (%.0fs/%ds, %d probes); "
                    "last error: %s", port, elapsed, timeout_s, attempts,
                    last_stderr[:120] or "(none)")
                last_log_at = now
            time.sleep(0.25)
        return False
