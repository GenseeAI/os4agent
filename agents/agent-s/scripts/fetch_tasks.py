"""Download OSWorld task fixtures into a local dir.

Layout produced:
    <dest>/osworld/evaluation_examples/examples/<domain>/<id>.json
    <dest>/osworld/evaluation_examples/test_small.json

Usage:
    python3 agents/agent-s/scripts/fetch_tasks.py [--dest <root>] \\
        [--osworld] [--all]

Defaults to ``--all``. Existing files are skipped (idempotent). Point the
bench at the result with ``--osworld-root`` or set ``OSWORLD_ROOT`` in
``.env``.
"""

from __future__ import annotations

import argparse
import json
import sys
import urllib.error
import urllib.request
from pathlib import Path


OSWORLD_REPO = "xlang-ai/OSWorld"
OSWORLD_BRANCH = "main"
OSWORLD_RAW = f"https://raw.githubusercontent.com/{OSWORLD_REPO}/{OSWORLD_BRANCH}"
OSWORLD_TREE_API = (f"https://api.github.com/repos/{OSWORLD_REPO}/git/trees/"
                     f"{OSWORLD_BRANCH}?recursive=1")
OSWORLD_INDEX_FILES = ["evaluation_examples/test_all.json",
                        "evaluation_examples/test_small.json"]


def _download(url: str, dest: Path, *, timeout: int = 60) -> bool:
    if dest.exists() and dest.stat().st_size > 0:
        return False
    dest.parent.mkdir(parents=True, exist_ok=True)
    try:
        with urllib.request.urlopen(url, timeout=timeout) as r:
            dest.write_bytes(r.read())
        return True
    except (urllib.error.HTTPError, urllib.error.URLError, TimeoutError) as e:
        print(f"  FAIL {url}: {e}", file=sys.stderr)
        return False


def _list_osworld_examples(*, timeout: int = 30) -> list[str]:
    """Enumerate every ``evaluation_examples/examples/<dom>/<id>.json`` via
    GitHub's recursive-tree API. Returns repo-relative paths."""
    print(f"[osworld] listing examples via {OSWORLD_TREE_API}")
    req = urllib.request.Request(
        OSWORLD_TREE_API, headers={"Accept": "application/vnd.github+json"})
    with urllib.request.urlopen(req, timeout=timeout) as r:
        tree = json.load(r).get("tree", [])
    prefix = "evaluation_examples/examples/"
    paths = sorted(
        node["path"] for node in tree
        if node.get("type") == "blob"
        and isinstance(node.get("path"), str)
        and node["path"].startswith(prefix)
        and node["path"].endswith(".json")
    )
    print(f"  {len(paths)} task JSONs found")
    return paths


def fetch_osworld(dest_root: Path) -> int:
    out_root = dest_root / "osworld"
    print(f"[osworld] {OSWORLD_RAW} → {out_root}/")
    n_new = 0

    try:
        rel_paths = _list_osworld_examples()
    except (urllib.error.HTTPError, urllib.error.URLError, TimeoutError) as e:
        print(f"  FAIL listing tree (rate-limited?): {e}", file=sys.stderr)
        return 0

    for rel in OSWORLD_INDEX_FILES + rel_paths:
        url = f"{OSWORLD_RAW}/{rel}"
        dest = out_root / rel
        if _download(url, dest):
            n_new += 1
        if n_new and n_new % 25 == 0:
            print(f"  ... {n_new} new")
    print(f"  done ({n_new} new, {len(rel_paths) + len(OSWORLD_INDEX_FILES) - n_new} already present)")
    return n_new


def main() -> int:
    p = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    p.add_argument("--dest", type=Path,
                   default=Path(__file__).resolve().parent.parent / "_fixtures",
                   help="destination root (default: agents/agent-s/_fixtures)")
    p.add_argument("--osworld", action="store_true",
                   help="fetch ALL OSWorld tasks via GitHub trees API")
    p.add_argument("--all", action="store_true", help="(default) fetch OSWorld")
    args = p.parse_args()
    if not (args.osworld or args.all):
        args.all = True
    args.dest.mkdir(parents=True, exist_ok=True)
    print(f"fixtures root: {args.dest}")

    n = 0
    if args.osworld or args.all:
        n += fetch_osworld(args.dest)

    print(f"\nDone. {n} new file(s) fetched.")
    print("Point the bench at these fixtures via .env:")
    print(f"  OSWORLD_ROOT={args.dest}/osworld/evaluation_examples")
    return 0


if __name__ == "__main__":
    sys.exit(main())
