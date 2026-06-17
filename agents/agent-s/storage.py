"""On-disk storage primitives — screenshots and the LLM replay cache."""

from __future__ import annotations

import json
import re
import threading
import time
from pathlib import Path
from typing import Any, Optional


def load_osworld_task(spec: str, *, examples_root: Path) -> dict[str, Any]:
    """Load an OSWorld task spec JSON. ``spec`` is ``"<domain>/<id>"`` or
    an absolute path to a .json file. Relative paths are NOT cwd-resolved
    (they're treated as ``<domain>/<id>``)."""
    sp = Path(spec)
    p = sp if (sp.is_absolute() and sp.suffix == ".json") \
        else examples_root / "examples" / f"{spec}.json"
    if not p.exists():
        raise FileNotFoundError(f"OSWorld task not found: {p}")
    return json.loads(p.read_text())


def parse_dotenv(path: Path) -> dict[str, str]:
    """KEY=VALUE per line, ``#`` comments, no quoting."""
    out: dict[str, str] = {}
    if not path.exists():
        return out
    for raw in path.read_text().splitlines():
        line = raw.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        k, v = line.split("=", 1)
        out[k.strip()] = v.strip()
    return out


class ScreenshotStore:
    """``<root>/round-NN/<mode>/branch-i/step-MM-<phase>.png``."""

    def __init__(self, root: Path) -> None:
        self.root = root
        self.root.mkdir(parents=True, exist_ok=True)
        self._lock = threading.Lock()

    def save(self, png: bytes, *, round_idx: int, mode: str,
             branch: int, step: int, phase: str = "pre") -> Path:
        d = self.root / f"round-{round_idx:02d}" / mode.lower() / f"branch-{branch}"
        d.mkdir(parents=True, exist_ok=True)
        path = d / f"step-{step:02d}-{phase}.png"
        with self._lock:
            path.write_bytes(png)
        return path

    def index(self) -> list[Path]:
        return sorted(self.root.rglob("step-*.png"))


class DiskLLMCache:
    """File-per-entry replay cache for ``llm_call`` results, keyed by
    ``(round, branch, task_id)``. Each entry is one JSON file under
    ``<root>/round-NN/branch-i/<task_id>.json``. Caller is responsible
    for picking ``task_id`` values that uniquely identify a call —
    the cache does not verify that arguments match."""

    def __init__(self, disk_cache_name: str = "",
                 *, workload: Optional[str] = None,
                 root: Optional[Path] = None) -> None:


        base = root or Path("/tmp/os4agent-llm-cache")
        if workload:
            base = base / workload
        self.root = base / disk_cache_name if disk_cache_name else base
        self.root.mkdir(parents=True, exist_ok=True)
        self._lock = threading.Lock()

    def _path(self, round_idx: int, branch: int, task_id: str) -> Path:
        safe = re.sub(r"[^A-Za-z0-9_.-]+", "_", task_id)[:120]
        return (self.root / f"round-{round_idx:02d}"
                / f"branch-{branch}" / f"{safe}.json")

    def get(self, round_idx: int, branch: int,
            task_id: str) -> Optional[tuple[dict[str, Any], dict[str, Any]]]:
        """Return ``(result, timing)`` if cached, else ``None``."""
        p = self._path(round_idx, branch, task_id)
        if not p.exists():
            return None
        try:
            d = json.loads(p.read_text())
        except json.JSONDecodeError:
            return None
        return d.get("result", {}), d.get("timing", {})

    def put(self, round_idx: int, branch: int, task_id: str,
            result: dict[str, Any], timing: dict[str, Any],
            *, latency_ms: Optional[float] = None,
            args: Optional[dict[str, Any]] = None) -> Path:
        """Persist a result + timing. ``latency_ms`` (if given) is folded
        into ``timing`` for convenience; ``args`` is recorded alongside
        for human-readable inspection (model, prompt, image-len etc.)."""
        p = self._path(round_idx, branch, task_id)
        p.parent.mkdir(parents=True, exist_ok=True)
        timing = dict(timing)
        if latency_ms is not None and "latency_ms" not in timing:
            timing["latency_ms"] = latency_ms
        payload = {
            "round": round_idx,
            "branch": branch,
            "task_id": task_id,
            "args": args or {},
            "result": result,
            "timing": timing,
            "saved_at": time.strftime("%FT%TZ", time.gmtime()),
        }
        with self._lock:
            p.write_text(json.dumps(payload, indent=2, default=str))
        return p
