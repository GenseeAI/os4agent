"""Live progress monitor.

Watches ``<results_dir>/<task>/timings.jsonl`` files written by the bench
and prints a simple full-screen status. No deps beyond stdlib.

Usage:
    python3 monitor.py                          # default ${RESULTS_DIR}
    python3 monitor.py --results /path/to/dir   # explicit
    python3 monitor.py --interval 2             # refresh every 2 s
"""

from __future__ import annotations

import argparse
import json
import os
import sys
import time
from collections import defaultdict
from pathlib import Path
from typing import Any

try:
    from workloads import DEFAULT_RESULTS_DIR
except ImportError:
    DEFAULT_RESULTS_DIR = "/tmp/os4agent-bench"


def _read_timings(path: Path) -> list[dict[str, Any]]:
    out = []
    try:
        for line in path.read_text().splitlines():
            line = line.strip()
            if line:
                out.append(json.loads(line))
    except (OSError, json.JSONDecodeError):
        pass
    return out


def _scan(root: Path) -> dict[str, dict[str, Any]]:
    """{task_dir_name: {timings, last_mtime, finished}}"""
    out: dict[str, dict[str, Any]] = {}
    if not root.exists():
        return out
    has_subdirs = any(p.is_dir() for p in root.iterdir())
    candidates = [p for p in root.iterdir() if p.is_dir()] if has_subdirs else [root]
    for d in candidates:
        tj = d / "timings.jsonl"
        if not tj.exists():
            continue
        timings = _read_timings(tj)
        finished = bool(list(d.glob("round-*.done")))
        out[d.name] = {
            "timings": timings,
            "mtime": tj.stat().st_mtime,
            "finished": finished,
            "path": d,
        }
    return out


def _fmt_dur(secs: float) -> str:
    if secs < 1:
        return f"{secs*1000:.0f}ms"
    if secs < 60:
        return f"{secs:.1f}s"
    m, s = divmod(int(secs), 60)
    return f"{m}m{s:02d}s"


def _bar(frac: float, width: int = 30) -> str:
    n = int(round(frac * width))
    return "[" + "█" * n + "·" * (width - n) + "]"


def _per_mode_stats(by_task: dict[str, dict[str, Any]]) -> list[dict[str, Any]]:
    """For each mode, mean of {clone_op, agent, judge, round} elapsed."""
    sums: dict[str, dict[str, list[float]]] = defaultdict(lambda: defaultdict(list))
    counts_by_mode: dict[str, set[str]] = defaultdict(set)
    for tname, info in by_task.items():
        for ev in info["timings"]:
            mode = (ev.get("mode") or "").upper()
            label = ev.get("label", "")
            if not mode or label not in ("clone_op", "agent", "judge", "round"):
                continue
            sums[mode][label].append(float(ev.get("elapsed_ms", 0)) / 1000)
            counts_by_mode[mode].add(tname)
    rows = []
    for mode in sorted(sums):
        rows.append({
            "mode": mode,
            "n": len(counts_by_mode[mode]),
            "clone": _mean(sums[mode]["clone_op"]),
            "agent": _mean(sums[mode]["agent"]),
            "judge": _mean(sums[mode]["judge"]),
            "round": _mean(sums[mode]["round"]),
        })
    return rows


def _mean(xs: list[float]) -> float:
    return sum(xs) / len(xs) if xs else 0.0


def _current_task(by_task: dict[str, dict[str, Any]]) -> dict[str, Any] | None:
    """Most recently active unfinished task; reports its latest event."""
    candidates = [(name, info) for name, info in by_task.items()
                  if not info["finished"] and info["timings"]]
    if not candidates:
        return None
    name, info = max(candidates, key=lambda kv: kv[1]["mtime"])
    last = info["timings"][-1]
    return {
        "task": name,
        "round": last.get("round"),
        "mode": (last.get("mode") or "").upper(),
        "branch": last.get("branch"),
        "step": last.get("step"),
        "label": last.get("label"),
    }


def _per_workload(by_task: dict[str, dict[str, Any]]) -> dict[str, tuple[int, int]]:
    """Return {workload_name: (done, total)}. Workload is read from the
    cache args we wrote, falling back to the timings 'extra' if any. If
    we can't tell, group everything under 'unknown'."""
    out: dict[str, list[int]] = defaultdict(lambda: [0, 0])
    for name, info in by_task.items():
        wl = "unknown"


        if "/" in name or name.startswith(("os_", "chrome_", "vlc_", "gimp_",
                                           "libreoffice_", "vs_code_",
                                           "thunderbird_", "multi_apps_")):
            wl = "osworld"
        out[wl][1] += 1
        if info["finished"]:
            out[wl][0] += 1
    return {k: tuple(v) for k, v in out.items()}


def render(root: Path, started_at: float) -> str:
    by_task = _scan(root)
    total = len(by_task)
    done = sum(1 for v in by_task.values() if v["finished"])
    elapsed = time.monotonic() - started_at
    rate = done / elapsed if (elapsed > 0 and done > 0) else 0
    eta = ((total - done) / rate) if rate > 0 else None
    frac = (done / total) if total else 0.0

    lines = []
    lines.append(f"=== bench monitor ===  results: {root}")
    lines.append(f"elapsed {_fmt_dur(elapsed)}"
                 + (f"   ETA {_fmt_dur(eta)}" if eta else ""))
    lines.append(f"{_bar(frac)}  {done}/{total} ({frac*100:.1f}%)")
    lines.append("")

    wl = _per_workload(by_task)
    if wl:
        lines.append("by workload:")
        for k in sorted(wl):
            d, t = wl[k]
            lines.append(f"  {k:<10} {d}/{t}")
        lines.append("")

    cur = _current_task(by_task)
    if cur:
        parts = [f"task={cur['task']}"]
        if cur["mode"]:
            parts.append(f"mode={cur['mode']}")
        if cur["round"] is not None:
            parts.append(f"round={cur['round']}")
        if cur["branch"] is not None:
            parts.append(f"branch={cur['branch']}")
        if cur["label"]:
            parts.append(f"phase={cur['label']}")
        lines.append("active: " + "  ".join(parts))
        lines.append("")

    rows = _per_mode_stats(by_task)
    if rows:
        lines.append(f"{'mode':<10}{'n':>4}  {'clone':>8}{'agent':>9}"
                     f"{'judge':>8}{'round':>8}")
        for r in rows:
            lines.append(f"{r['mode']:<10}{r['n']:>4}  "
                         f"{_fmt_dur(r['clone']):>8}"
                         f"{_fmt_dur(r['agent']):>9}"
                         f"{_fmt_dur(r['judge']):>8}"
                         f"{_fmt_dur(r['round']):>8}")
        lines.append("")

    recent = sorted(by_task.items(), key=lambda kv: kv[1]["mtime"], reverse=True)[:8]
    if recent:
        lines.append("recent:")
        for name, info in recent:
            wall_evs = [e for e in info["timings"] if e.get("label") == "round"]
            wall = sum(float(e.get("elapsed_ms", 0)) for e in wall_evs) / 1000
            mark = "✓" if info["finished"] else "·"
            lines.append(f"  {mark} {name:<40} wall={_fmt_dur(wall):>7}")

    lines.append("")
    lines.append("ctrl-C to quit")
    return "\n".join(lines)


def main(argv=None) -> int:
    p = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    p.add_argument("--results", type=Path, default=Path(DEFAULT_RESULTS_DIR),
                   help=f"default ${{RESULTS_DIR}} or {DEFAULT_RESULTS_DIR}")
    p.add_argument("--interval", type=float, default=2.0,
                   help="refresh interval (seconds)")
    args = p.parse_args(argv)

    started = time.monotonic()
    try:
        while True:
            sys.stdout.write("\033[2J\033[H")
            sys.stdout.write(render(args.results, started))
            sys.stdout.write("\n")
            sys.stdout.flush()
            time.sleep(args.interval)
    except KeyboardInterrupt:
        return 0


if __name__ == "__main__":
    sys.exit(main())
