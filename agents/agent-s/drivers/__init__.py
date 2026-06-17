"""Snapshot drivers — one per fan-out mechanism. Same five-method
protocol so RunExp can dispatch by ExpMode without an ``if mode is …``
chain."""

from __future__ import annotations

import subprocess
from pathlib import Path
from typing import Optional, Protocol, runtime_checkable


SCREENSHOT_PY = (
    "import sys, io;\n"
    "from PIL import ImageGrab;\n"
    "im = ImageGrab.grab();\n"
    "b = io.BytesIO(); im.save(b, 'PNG');\n"
    "sys.stdout.buffer.write(b.getvalue())\n"
)


@runtime_checkable
class SnapshotDriver(Protocol):
    """Five methods every snapshot mechanism implements. ``RunExp.driver``
    constructs the right one per ``ExpMode``; targets are opaque ids
    (container name, libvirt domain, …) the driver decodes itself.

    Drivers also expose a few read-only conventions that workloads
    consult to do the right thing per-image:

      desktop_user: str   — uid/login that owns the X session inside
                            the guest (``abc`` on linuxserver/webtop,
                            ``user`` on the OSWorld Ubuntu VM)
      display: str        — DISPLAY value pyautogui targets (``:1`` on
                            webtop's Xvfb, ``:0`` on the OSWorld VM)
      xauthority: Optional[str] — XAUTHORITY path inside the guest, or
                            None when X has no auth (KVM/Wayland)
      home_dir: str       — desktop_user's HOME inside the guest
      path_rewrites: list[(old_prefix, new_prefix)]
                          — workloads that consume OSWorld specs (which
                            assume /home/user/) rewrite paths through
                            this list before downloads / opens. Empty
                            for drivers whose guest already matches the
                            spec layout."""

    desktop_user: str
    display: str
    xauthority: Optional[str]
    home_dir: str
    path_rewrites: list[tuple[str, str]]

    def launch_source(self, *, round_idx: int) -> str: ...
    def clone(self, *, src: str, n: int, round_idx: int) -> list[str]: ...
    def teardown(self, *, src: Optional[str], clones: list[str],
                 round_idx: int) -> None:
        """Free clones (always) and the source (if ``src`` is not None).
        Pass ``src=None`` to keep the source alive for another round of
        clones."""
        ...
    def screenshot(self, target: str) -> Optional[bytes]: ...
    def exec(self, target: str, cmd: str, *, timeout: int = 30
             ) -> subprocess.CompletedProcess: ...
    def exec_python(self, target: str, code: str, *,
                    env: Optional[dict] = None, timeout: int = 15
                    ) -> subprocess.CompletedProcess:
        """Run ``code`` as ``python3 -c`` inside ``target`` with
        ``env`` injected. Bypasses login-shell processing so the
        guest's /etc/profile.d/ doesn't override DISPLAY/XAUTHORITY
        between us and the python interpreter."""
        ...

    def working_set_bytes(self, target: str) -> Optional[int]:
        """Bytes the snapshot mechanism must dump to clone ``target``.

        Container drivers: cgroup memory.current of the source.
        VM drivers: qemu's RSS (≈ VM RAM + small overhead).

        Sampled once per round in RunExp.run_round and attached to the
        per-round timing record. Default implementation returns None
        for drivers that don't implement it. Sub-ms read; safe to call
        on the hot path."""
        return None
