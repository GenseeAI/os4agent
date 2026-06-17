"""Render a static HTML index of the bench's saved screenshots and a
per-round / per-mode timing summary parsed from `timings.jsonl`. Open
the resulting `index.html` in a browser to browse what each branch saw.

    python3 view.py --results /tmp/os4agent-bench [--open]
"""

from __future__ import annotations

import argparse
import collections
import dataclasses as dc
import html
import json
import statistics
import sys
import webbrowser
from pathlib import Path
from typing import Any


def _ms(x: float) -> str:
    if x is None:
        return "—"
    if x < 1000:
        return f"{x:.0f} ms"
    return f"{x/1000:.2f} s"


def _load_timings(path: Path) -> list[dict[str, Any]]:
    out: list[dict[str, Any]] = []
    if not path.exists():
        return out
    for raw in path.read_text().splitlines():
        if raw.strip():
            out.append(json.loads(raw))
    return out


_SUMMARY_LABEL_TO_KEY = {
    "round": "round_ms",
    "clone_op": "clone_ms",
    "cleanup": "cleanup_ms",
    "src_launch": "src_launch_ms",
}


def _summary_table(timings: list[dict[str, Any]]) -> str:
    by_mode_round: dict[tuple[str, int], dict[str, float]] = collections.defaultdict(dict)
    for t in timings:
        if not (t.get("mode") and t.get("round")):
            continue
        key = _SUMMARY_LABEL_TO_KEY.get(t["label"])
        if key is not None:
            by_mode_round[(t["mode"], t["round"])][key] = t["elapsed_ms"]

    rows: list[str] = []
    for (mode, rnd), v in sorted(by_mode_round.items()):
        rows.append(
            f"<tr><td>{html.escape(mode)}</td><td>{rnd}</td>"
            f"<td>{_ms(v.get('round_ms'))}</td>"
            f"<td>{_ms(v.get('clone_ms'))}</td>"
            f"<td>{_ms(v.get('src_launch_ms'))}</td>"
            f"<td>{_ms(v.get('cleanup_ms'))}</td></tr>"
        )

    means: dict[str, dict[str, list[float]]] = collections.defaultdict(lambda: collections.defaultdict(list))
    for (mode, _r), v in by_mode_round.items():
        for k, x in v.items():
            means[mode][k].append(x)
    mean_rows: list[str] = []
    for mode, kvs in sorted(means.items()):
        def cell(k: str) -> str:
            return _ms(statistics.mean(kvs[k])) if k in kvs else "—"
        mean_rows.append(
            f"<tr class=mean><td>{html.escape(mode)}</td><td>(mean)</td>"
            f"<td>{cell('round_ms')}</td>"
            f"<td>{cell('clone_ms')}</td>"
            f"<td>{cell('src_launch_ms')}</td>"
            f"<td>{cell('cleanup_ms')}</td></tr>"
        )

    return (
        "<table class=summary>"
        "<thead><tr><th>mode</th><th>round</th><th>round wall</th>"
        "<th>clone</th><th>src-launch</th><th>cleanup</th></tr></thead>"
        "<tbody>"
        + "".join(rows)
        + "</tbody><tfoot>"
        + "".join(mean_rows)
        + "</tfoot></table>"
    )


def _per_branch_table(timings: list[dict[str, Any]]) -> str:
    """Per-step phase timings: screenshot/predict/exec/total per branch."""
    rows = []
    seen: set[tuple] = set()
    for t in timings:
        if t.get("step") is None:
            continue
        phase = (t.get("extra") or {}).get("phase", "")
        if phase not in ("screenshot", "predict", "exec", "total"):
            continue
        key = (t["round"], t["mode"], t["branch"], t["step"])
        seen.add(key)
    by_key: dict[tuple, dict[str, float]] = collections.defaultdict(dict)
    for t in timings:
        if t.get("step") is None:
            continue
        phase = (t.get("extra") or {}).get("phase", "")
        if phase not in ("screenshot", "predict", "exec", "total"):
            continue
        by_key[(t["round"], t["mode"], t["branch"], t["step"])][phase] = t["elapsed_ms"]
    for key in sorted(by_key):
        r, m, b, s = key
        v = by_key[key]
        rows.append(
            f"<tr><td>{r}</td><td>{html.escape(m)}</td><td>{b}</td><td>{s}</td>"
            f"<td>{_ms(v.get('screenshot'))}</td>"
            f"<td>{_ms(v.get('predict'))}</td>"
            f"<td>{_ms(v.get('exec'))}</td>"
            f"<td>{_ms(v.get('total'))}</td></tr>"
        )
    return (
        "<table class=steps>"
        "<thead><tr><th>r</th><th>mode</th><th>br</th><th>step</th>"
        "<th>screenshot</th><th>predict</th><th>exec</th><th>total</th></tr></thead>"
        "<tbody>" + "".join(rows) + "</tbody></table>"
    )


def _shots_section(root: Path) -> str:
    """Group shots by round/mode/branch and emit a thumbnails grid."""
    shots = sorted((root / "screenshots").rglob("step-*.png"))
    if not shots:
        return "<p>No screenshots saved.</p>"
    grouped: dict[tuple[str, str, str], list[Path]] = collections.defaultdict(list)
    for p in shots:

        try:
            rel = p.relative_to(root)
            r, mode, branch = rel.parts[1:4]
        except (ValueError, IndexError):
            continue
        grouped[(r, mode, branch)].append(p)
    parts = ["<div class=shots>"]
    for (r, mode, branch), plist in sorted(grouped.items()):
        parts.append(f"<div class=group><h3>{html.escape(r)} / {html.escape(mode)} / {html.escape(branch)}</h3><div class=row>")
        for p in plist:
            rel_url = p.relative_to(root).as_posix()
            label = p.stem
            parts.append(
                f'<figure><a href="{html.escape(rel_url)}" target=_blank>'
                f'<img src="{html.escape(rel_url)}" loading=lazy></a>'
                f'<figcaption>{html.escape(label)}</figcaption></figure>'
            )
        parts.append("</div></div>")
    parts.append("</div>")
    return "".join(parts)


CSS = """
body { font: 14px/1.4 system-ui, sans-serif; background:#0d1117; color:#e6edf3; padding:20px; }
h1, h2, h3 { color:#58a6ff; }
table { border-collapse: collapse; margin: 12px 0; }
th, td { border: 1px solid #30363d; padding: 6px 10px; text-align: left; }
thead th { background:#161b22; }
tfoot tr.mean td { background:#1f2630; color:#fadd6f; font-weight: 600; }
.shots { display: flex; flex-direction: column; gap: 18px; }
.group { background:#161b22; border:1px solid #30363d; border-radius:6px; padding:12px; }
.row { display: grid; grid-template-columns: repeat(auto-fill, minmax(220px,1fr)); gap: 8px; }
figure { margin: 0; }
figure img { width: 100%; border:1px solid #30363d; border-radius: 4px; }
figcaption { font-size: 11px; color:#8b949e; padding: 4px 0; }
"""


def render(results_dir: Path) -> Path:
    timings = _load_timings(results_dir / "timings.jsonl")
    summary = _summary_table(timings)
    steps = _per_branch_table(timings)
    shots = _shots_section(results_dir)
    out = results_dir / "index.html"
    out.write_text(
        f"<!doctype html><meta charset=utf-8><title>os4agent bench</title>"
        f"<style>{CSS}</style>"
        f"<h1>os4agent × Agent-S bench</h1>"
        f"<p>results dir: <code>{html.escape(str(results_dir))}</code> · "
        f"timings rows: {len(timings)}</p>"
        f"<h2>Per-mode summary</h2>{summary}"
        f"<h2>Per-step phases</h2>{steps}"
        f"<h2>Screenshots</h2>{shots}"
    )
    return out


def main() -> int:
    p = argparse.ArgumentParser()
    p.add_argument("--results", type=Path, default=Path("/tmp/os4agent-bench"))
    p.add_argument("--open", action="store_true")
    a = p.parse_args()
    if not a.results.exists():
        print(f"no results dir at {a.results}", file=sys.stderr)
        return 1
    out = render(a.results)
    print(f"wrote {out}")
    if a.open:
        webbrowser.open(out.as_uri())
    return 0


if __name__ == "__main__":
    sys.exit(main())
