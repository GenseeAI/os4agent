"""Per-workload presets. ``--workload <name>`` overrides BenchConfig
defaults at construction. Add a workload by dropping a file alongside
``osworld.py`` and listing its instance in ``WORKLOADS``.
"""

from __future__ import annotations

import dataclasses as dc
import os
from pathlib import Path
from typing import Any, Callable, Optional


def _env_default(key: str, fallback: str) -> str:
    raw = os.environ.get(key)
    if raw is None:
        from storage import parse_dotenv
        env = parse_dotenv(Path(__file__).resolve().parent.parent / ".env")
        raw = env.get(key, fallback)


    if raw.startswith("~/") or raw == "~":
        raw = _user_home() + raw[1:]
    return raw


def _user_home() -> str:
    """Real user's home dir even under sudo. Defined inline above
    _env_default so the latter can call it. Forward-defined for
    DEFAULT_SSH_KEY etc. that reference it through _env_default."""
    sudo_user = os.environ.get("SUDO_USER")
    if sudo_user:
        try:
            import pwd
            return pwd.getpwnam(sudo_user).pw_dir
        except (KeyError, ImportError):
            pass
    return str(Path.home())


DEFAULT_MODEL = _env_default("DEFAULT_MODEL", "gpt-5.4-mini")
DEFAULT_OSWORLD_IMAGE = _env_default("OSWORLD_IMAGE", "localhost/ubuntu-webtop:test")


_FIXTURES_DEFAULT = str(Path(__file__).resolve().parent.parent / "_fixtures")
DEFAULT_RESULTS_DIR = _env_default("RESULTS_DIR", "/tmp/os4agent-bench")
DEFAULT_FIXTURES_ROOT = _env_default("FIXTURES_ROOT", _FIXTURES_DEFAULT)
DEFAULT_OSWORLD_ROOT = _env_default(
    "OSWORLD_ROOT", str(Path(DEFAULT_FIXTURES_ROOT) / "osworld" / "evaluation_examples"))
DEFAULT_BASE_DISK = _env_default("BASE_DISK", "")


DEFAULT_OSWORLD_BASE_DISK = _env_default("OSWORLD_BASE_DISK", "") or DEFAULT_BASE_DISK
DEFAULT_KVM_RUN_BASE = _env_default("KVM_RUN_BASE", "/tmp/os4agent-kvm")
def _default_podman_bin() -> str:


    wrapper = Path(__file__).resolve().parents[3] / "podman-tfork.sh"
    if wrapper.is_file():
        return str(wrapper)
    return "podman"


DEFAULT_PODMAN_BIN = _env_default("PODMAN_BIN", _default_podman_bin())
DEFAULT_SSH_KEY = _env_default("SSH_KEY", str(Path(_user_home()) / ".ssh" / "id_ed25519"))


@dc.dataclass
class Workload:
    name: str


    image: Optional[str] = None
    model: Optional[str] = None
    screen_w: Optional[int] = None
    screen_h: Optional[int] = None
    max_trajectory_length: Optional[int] = None
    enable_reflection: Optional[bool] = None
    judge_enabled: Optional[bool] = None


    base_disk: Optional[str] = None


    task_loader: Optional[Callable[[str, Any], dict[str, Any]]] = None


    list_tasks: Optional[Callable[[Any], list[str]]] = None


    prompt_overrides: dict[str, str] = dc.field(default_factory=dict)


    run_branch: Optional[Callable[..., Any]] = None


    judge: Optional[Callable[..., dict[str, Any]]] = None


    judge_prompt_template: Optional[str] = None


    source_run_args: Optional[list[str]] = None


    source_ready_probe: Optional[str] = None


    source_post_launch: Optional[str] = None


    task_setup: Optional[Callable[..., None]] = None


    source_ready_settle_s: float = 0.0

    def apply(self, cfg) -> None:
        for fname in ("image", "model", "screen_w", "screen_h",
                      "max_trajectory_length", "enable_reflection",
                      "judge_enabled"):
            v = getattr(self, fname)
            if v is not None:
                setattr(cfg, fname, v)


        if self.base_disk:
            cfg.base_disk = Path(self.base_disk)


from .osworld import OSWORLD


WORKLOADS: dict[str, Workload] = {
    OSWORLD.name: OSWORLD,
}


def get_workload(name: str) -> Workload:
    if name not in WORKLOADS:
        raise KeyError(f"unknown workload {name!r}; available: {sorted(WORKLOADS)}")
    return WORKLOADS[name]
