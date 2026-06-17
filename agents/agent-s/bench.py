"""os4agent perf bench — orchestrator.

ExpMode picks a snapshot driver (``drivers/``); Workload picks the
per-branch ``run_branch`` + ``judge`` (``workloads/``). RunExp owns the
data model and the round/beam loop; everything else delegates."""

from __future__ import annotations

import argparse
import base64
import dataclasses as dc
import enum
import json
import logging
import os
import re
import subprocess
import sys
import threading
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path
from typing import Any, Iterable, Optional, Union

from openai import OpenAI

from drivers import SnapshotDriver
from storage import (
    DiskLLMCache,
    ScreenshotStore,
    load_osworld_task,
    parse_dotenv,
)
from workloads import (
    DEFAULT_BASE_DISK,
    DEFAULT_KVM_RUN_BASE, DEFAULT_MODEL, DEFAULT_OSWORLD_IMAGE,
    DEFAULT_OSWORLD_ROOT, DEFAULT_PODMAN_BIN, DEFAULT_RESULTS_DIR,
    DEFAULT_SSH_KEY, Workload, get_workload,
)

logger = logging.getLogger("os4agent.bench")


class ExpMode(enum.Enum):
    """See module docstring for what each mode runs."""
    KVM = enum.auto()
    KVM_VIRSH = enum.auto()
    CKPT = enum.auto()
    TFORK = enum.auto()


@dc.dataclass
class TimingInfo:
    """One phase's timing record. Append-only after creation.

    ``label`` is a short verb (``clone_op``, ``agent``, ``judge``,
    ``step.predict``, …); structured context (round/mode/branch/step)
    lives on the dedicated fields, not in the label string."""
    label: str
    started_ms: float
    elapsed_ms: float
    round: int = 0
    mode: str = ""
    branch: Optional[int] = None
    step: Optional[int] = None
    extra: dict[str, Any] = dc.field(default_factory=dict)


@dc.dataclass
class BranchResult:
    """Per-branch outcome of one round; ``effective_score`` drives winner pick."""
    branch: int
    container: str
    agent_ms: float
    judge_ms: float = 0.0
    n_steps: int = 0
    finished: bool = False
    score: Optional[float] = None
    success: Optional[bool] = None
    judge_reason: str = ""
    error: Optional[str] = None


    state: Optional[Any] = None


    stage_ms: dict[str, float] = dc.field(default_factory=dict)

    @property
    def effective_score(self) -> float:
        if self.score is not None:
            return float(self.score)
        return 1.0 if self.finished else 0.0


@dc.dataclass
class RoundResult:
    round_idx: int
    mode: ExpMode
    src: str
    clones: list[str]
    branches: list[BranchResult]
    winner: Optional[BranchResult]
    elapsed_ms: float
    clone_ms: float
    cleanup_ms: float = 0.0


@dc.dataclass
class BenchConfig:
    results_dir: Path = dc.field(default_factory=lambda: Path(DEFAULT_RESULTS_DIR))
    image: str = DEFAULT_OSWORLD_IMAGE
    base_disk: Optional[Path] = dc.field(
        default_factory=lambda: Path(DEFAULT_BASE_DISK) if DEFAULT_BASE_DISK else None)
    podman: str = DEFAULT_PODMAN_BIN
    ssh_key: Path = dc.field(default_factory=lambda: Path(DEFAULT_SSH_KEY))
    kvm_run_base: Path = dc.field(default_factory=lambda: Path(DEFAULT_KVM_RUN_BASE))
    model: str = DEFAULT_MODEL
    task: str = "Right-click on the desktop background to open the context menu."
    screen_w: int = 1024
    screen_h: int = 768
    n: int = 4
    capture_screenshots: bool = True
    max_trajectory_length: int = 12
    enable_reflection: bool = True
    judge_enabled: bool = False
    llm_cache_name: str = ""
    task_id: Optional[str] = None


    task_config: Optional[list[dict[str, Any]]] = None
    task_setup_enabled: bool = False
    osworld_examples_root: Path = dc.field(
        default_factory=lambda: Path(DEFAULT_OSWORLD_ROOT))
    virsh_source_xml: Optional[Path] = None
    virsh_source_domain: str = "agent-s-source"
    virsh_libvirt_uri: str = "qemu:///system"
    workload: Optional[Workload] = None


def _now_ms() -> float:
    return time.monotonic() * 1000


def _tail_text(messages: list[dict[str, Any]]) -> str:
    if not messages:
        return ""
    last = messages[-1].get("content")
    if isinstance(last, str):
        return last[:300]
    if isinstance(last, list):
        for c in reversed(last):
            if isinstance(c, dict) and c.get("type") == "text":
                return (c.get("text") or "")[:300]
    return ""


class RunExp:
    """One bench session.

    Owns timings + screenshots + a per-mode driver dict; persists on
    ``save()``. Drivers are constructed lazily so a run that uses only
    podman doesn't import libvirt machinery.
    """

    def __init__(self, config: Optional[BenchConfig] = None) -> None:
        self.config = config or BenchConfig()


        if self.config.workload is not None:
            self.config.workload.apply(self.config)
        self.config.results_dir.mkdir(parents=True, exist_ok=True)
        self.timings: list[TimingInfo] = []


        from datetime import datetime, timezone
        self.session_start_iso = datetime.now(timezone.utc).isoformat()
        self.session_start_monotonic_ms = _now_ms()


        self.rounds: list[RoundResult] = []
        self.screenshots = ScreenshotStore(self.config.results_dir / "screenshots")
        self.llm_cache: Optional[DiskLLMCache] = (
            DiskLLMCache(
                self.config.llm_cache_name,
                workload=(self.config.workload.name
                          if self.config.workload else None),
            )
            if self.config.llm_cache_name else None
        )
        self._lock = threading.Lock()
        self._env = parse_dotenv(Path(__file__).resolve().parent / ".env")
        self._client: Optional[OpenAI] = None
        self._drivers: dict[ExpMode, SnapshotDriver] = {}
        self._cleanup_threads: list[threading.Thread] = []


    def save(self) -> Path:
        """Write timings.jsonl AND rounds.json. Returns timings.jsonl path."""
        path = self.config.results_dir / "timings.jsonl"
        with self._lock:
            with path.open("w") as f:
                for ti in self.timings:
                    f.write(json.dumps(dc.asdict(ti), default=str) + "\n")
            self._save_rounds_json()
        return path

    def _save_rounds_json(self) -> None:
        """Structured per-round summary for fast plotting. One file at
        <results_dir>/rounds.json, rewritten on every save(). Joins
        RoundResult metadata with per-(round, branch) events from
        self.timings — so a plot script reads ONE JSON, no grouping."""
        out_path = self.config.results_dir / "rounds.json"
        rounds_json = []
        for rr in self.rounds:
            winner_id = rr.winner.container if rr.winner else None
            branches: dict[str, dict[str, Any]] = {}
            for b in rr.branches:
                if b.error:
                    status = "errored"
                elif rr.winner and b.container == winner_id:
                    status = "winner"
                else:
                    status = "loser"

                events = [
                    {"label": t.label,
                     "started_ms": t.started_ms,
                     "elapsed_ms": t.elapsed_ms,
                     "extra": t.extra}
                    for t in self.timings
                    if t.round == rr.round_idx
                    and (t.branch == b.branch
                         or (t.branch is None and t.label in
                             ("clone_op", "src_launch", "round")))
                ]
                branches[str(b.branch)] = {
                    "status": status,
                    "container": b.container,
                    "agent_ms": b.agent_ms,
                    "judge_ms": b.judge_ms,
                    "n_steps": b.n_steps,
                    "finished": b.finished,
                    "score": b.score,
                    "success": b.success,
                    "judge_reason": b.judge_reason,
                    "error": b.error,
                    "stage_ms": dict(b.stage_ms),
                    "events": events,
                }


            round_evt = next(
                (t for t in reversed(self.timings)
                 if t.label == "round" and t.round == rr.round_idx
                 and t.mode == rr.mode.name), None)
            extra = round_evt.extra if round_evt else {}
            rounds_json.append({
                "round": rr.round_idx,
                "mode": rr.mode.name,
                "src": rr.src,
                "wall_ms": rr.elapsed_ms,
                "clone_ms": rr.clone_ms,
                "cleanup_ms": rr.cleanup_ms,
                "winner_branch": (rr.winner.branch if rr.winner else None),
                "working_set_bytes": extra.get("working_set_bytes"),
                "agent_ms_max": extra.get("agent_ms"),
                "judge_ms_max": extra.get("judge_ms"),
                "n_branches": len(rr.branches),
                "branches": branches,
            })
        with out_path.open("w") as f:
            json.dump({


                "session_start_iso": self.session_start_iso,
                "session_start_monotonic_ms": self.session_start_monotonic_ms,
                "rounds": rounds_json,
            }, f, indent=2, default=str)

    def round_done(self, round_idx: int) -> bool:
        return (self.config.results_dir / f"round-{round_idx:02d}.done").exists()

    def mark_round_done(self, round_idx: int) -> None:
        (self.config.results_dir / f"round-{round_idx:02d}.done").touch()


    def driver(self, mode: ExpMode) -> SnapshotDriver:
        """Lazy-construct the driver for ``mode`` and cache it.
        Lock-guarded so concurrent run_branch() workers don't double-construct."""
        with self._lock:
            d = self._drivers.get(mode)
            if d is not None:
                return d
            if mode in (ExpMode.CKPT, ExpMode.TFORK):
                from drivers.podman import PodmanDriver
                d = PodmanDriver(mode=mode, config=self.config)
            elif mode is ExpMode.KVM:
                from drivers.kvm_migrate import KvmMigrateDriver
                d = KvmMigrateDriver(config=self.config)
            elif mode is ExpMode.KVM_VIRSH:
                from drivers.kvm_virsh import KvmVirshDriver
                d = KvmVirshDriver(
                    work_dir=self.config.kvm_run_base / "virsh",
                    source_xml=self.config.virsh_source_xml,
                    source_domain=self.config.virsh_source_domain,
                    base_disk=self.config.base_disk,
                    libvirt_uri=self.config.virsh_libvirt_uri,
                )
            else:
                raise ValueError(f"unknown mode {mode!r}")
            self._drivers[mode] = d
            return d


    def exec_in_container(self, container: str, cmd: str, *,
                          mode: ExpMode = ExpMode.TFORK,
                          timeout: int = 30,
                          ) -> subprocess.CompletedProcess:
        """Run ``cmd`` inside ``container`` via the matching driver."""
        return self.driver(mode).exec(container, cmd, timeout=timeout)

    def clone(self, mode: ExpMode, *, src: str, n: Optional[int] = None,
              round_idx: int = 0) -> list[str]:
        n = n or self.config.n
        t0 = _now_ms()
        clones = self.driver(mode).clone(src=src, n=n, round_idx=round_idx)
        self._record("clone_op", t0, _now_ms() - t0,
                     round=round_idx, mode=mode.name, extra={"n": n})
        return clones


    _DEFAULT_JUDGE_PROMPT = (
        "You are evaluating whether an agent successfully completed a task.\n"
        "TASK: {task}\n"
        "Reply ONLY with a JSON object:\n"
        '{{"success": <true|false>, "score": <0..10>, "reason": "<one sentence>"}}\n'
    )

    def llm_judge(self, *, image: bytes, task: Optional[str] = None,
                  model: Optional[str] = None,
                  round_idx: int = 0, mode: Optional[ExpMode] = None,
                  branch: Optional[int] = None) -> dict[str, Any]:
        """Post-trajectory success check. Workload-specific prompt template
        if ``BenchConfig.workload`` is set, else a generic fallback."""
        task = task or self.config.task
        wl = self.config.workload
        template = (wl.judge_prompt_template if wl and wl.judge_prompt_template
                    else self._DEFAULT_JUDGE_PROMPT)
        prompt = template.format(task=task)
        rsp = self.llm_call(model=model, image=image, prompt=prompt,
                            round_idx=round_idx, branch=branch or 0,
                            task_id="judge", stage="judge")
        m = re.search(r"\{.*\}", (rsp.get("text") or "").strip(), re.S)
        verdict: dict[str, Any] = {"raw": rsp.get("text", ""),
                                   "success": None, "score": None, "reason": ""}
        if m:
            try:
                verdict.update(json.loads(m.group(0)))
            except json.JSONDecodeError:
                pass
        self._record(
            "judge", _now_ms(), rsp["latency_ms"],
            round=round_idx, mode=(mode or ExpMode.TFORK).name, branch=branch,
            extra={"verdict": verdict, "tokens_in": rsp["tokens_in"],
                   "tokens_out": rsp["tokens_out"]},
        )
        return verdict

    def llm_call(self, *, model: Optional[str] = None,
                 messages: Optional[list[dict[str, Any]]] = None,
                 image: Optional[bytes] = None,
                 prompt: str = "describe this screen",
                 round_idx: int = 0, branch: int = 0,
                 task_id: Optional[str] = None,
                 stage: str = "ad-hoc") -> dict[str, Any]:
        """Pass ``messages=`` for role-tagged multi-turn history, or
        ``prompt=`` (+ optional ``image=``) for a one-shot call."""
        model = model or self.config.model

        if self.llm_cache is not None and task_id:
            hit = self.llm_cache.get(round_idx, branch, task_id)
            if hit is not None:
                result, timing = hit
                latency = timing.get("latency_ms", 0.0)
                self._record("llm_call", _now_ms(), latency,
                             round=round_idx, branch=branch,
                             extra={"model": model, "task_id": task_id,
                                    "stage": stage, "cached": True})
                return {**result, "latency_ms": latency, "cached": True}

        if messages is None:
            content: list[dict[str, Any]] = [{"type": "text", "text": prompt}]
            if image is not None:
                content.append({
                    "type": "image_url",
                    "image_url": {"url": "data:image/png;base64," + base64.b64encode(image).decode()},
                })
            messages = [{"role": "user", "content": content}]

        client = self._openai()
        t0 = _now_ms()
        rsp = client.chat.completions.create(model=model, messages=messages)
        latency = _now_ms() - t0

        text = rsp.choices[0].message.content or ""
        usage = getattr(rsp, "usage", None)
        tin = getattr(usage, "prompt_tokens", 0) if usage else 0
        tout = getattr(usage, "completion_tokens", 0) if usage else 0
        result = {"text": text, "tokens_in": tin, "tokens_out": tout}


        extra: dict[str, Any] = {
            "model": model, "tokens_in": tin, "tokens_out": tout,
            "n_messages": len(messages),
            "task_id": task_id, "stage": stage, "cached": False,
        }
        if stage != "grounder":
            extra["text"] = text
        self._record("llm_call", t0, latency,
                     round=round_idx, branch=branch,
                     extra=extra)
        if self.llm_cache is not None and task_id:
            self.llm_cache.put(
                round_idx, branch, task_id,
                result=result, timing={"latency_ms": latency},
                args={"model": model, "n_messages": len(messages),
                      "tail_text": (prompt[:300] if messages is None
                                    else _tail_text(messages))},
            )
        return {**result, "latency_ms": latency, "cached": False}


    def run_branch(self, *, container: str, branch_idx: int,
                   round_idx: int, mode: ExpMode,
                   parent_state: Any = None) -> BranchResult:
        """Drive one branch: ``workload.run_branch`` then ``workload.judge``.
        ``parent_state`` is the prior-round winner's ``BranchResult.state``;
        the workload threads it through to make multi-turn agents work."""
        wl = self.config.workload
        if wl is None or wl.run_branch is None:
            raise RuntimeError(
                "no workload.run_branch set; use --workload <name> or "
                "construct a BenchConfig with workload=… and a run_branch."
            )
        t0 = _now_ms()
        try:
            result = wl.run_branch(
                target=container, branch_idx=branch_idx,
                round_idx=round_idx, mode=mode,
                task=self.config.task, driver=self.driver(mode), runner=self,
                state=parent_state,
            )
        except Exception as e:
            logger.exception("workload.run_branch failed: %s", e)
            result = BranchResult(branch=branch_idx, container=container,
                                  agent_ms=_now_ms() - t0, error=str(e))
        self._record("agent", t0, _now_ms() - t0,
                     round=round_idx, mode=mode.name, branch=branch_idx,
                     extra={"n_steps": result.n_steps,
                            "finished": result.finished,
                            "error": result.error,


                            "stage_ms": dict(result.stage_ms)})
        self._maybe_judge(result, container=container, round_idx=round_idx,
                          mode=mode)
        return result

    def _maybe_judge(self, result: BranchResult, *, container: str,
                     round_idx: int, mode: ExpMode) -> None:
        """Call ``workload.judge`` if set + ``judge_enabled``. Workloads
        own their evidence gathering (screenshot, workspace audit, …)
        — bench does not provide a generic fallback."""
        if not self.config.judge_enabled:
            return
        wl = self.config.workload
        if wl is None or wl.judge is None:
            return
        t_j = _now_ms()
        try:
            verdict = wl.judge(branch=result, target=container,
                               task=self.config.task, round_idx=round_idx,
                               mode=mode, driver=self.driver(mode), runner=self)
        except Exception as e:
            logger.warning("judge for branch %d: %s", result.branch, e)
            return
        result.judge_ms = _now_ms() - t_j
        result.score = verdict.get("score")
        result.success = verdict.get("success")
        result.judge_reason = verdict.get("reason", "")

    @staticmethod
    def pick_winner(branches: list[BranchResult]) -> Optional[BranchResult]:
        """Highest ``effective_score``; ties broken by fewer steps then
        less wall. Returns None if every branch errored."""
        ok = [b for b in branches if b.error is None]
        if not ok:
            return None
        return max(ok, key=lambda b: (b.effective_score, -b.n_steps, -b.agent_ms))


    def run_round(self, *, mode: ExpMode, round_idx: int, src: str,
                  n: Optional[int] = None,
                  parent_state: Any = None) -> RoundResult:
        """One beam round: clone, run agents in parallel, judge, pick winner.
        Winner's container is preserved; src + losers tear down asynchronously.
        Each branch starts from ``parent_state`` (prior round's winner state)."""
        n = n or self.config.n
        t_round = _now_ms()


        try:
            ws_bytes = self.driver(mode).working_set_bytes(src)
        except Exception as e:
            logger.debug("working_set_bytes(%s) failed: %s", src, e)
            ws_bytes = None

        t_clone = _now_ms()
        clones = self.clone(mode, src=src, n=n, round_idx=round_idx)
        clone_ms = _now_ms() - t_clone

        branches: list[BranchResult] = []
        with ThreadPoolExecutor(max_workers=n) as ex:
            futs = {
                ex.submit(self.run_branch, container=c, branch_idx=i,
                          round_idx=round_idx, mode=mode,
                          parent_state=parent_state): (i, c)
                for i, c in enumerate(clones)
            }
            for fut in as_completed(futs):
                i, c = futs[fut]
                try:
                    branches.append(fut.result())
                except Exception as e:
                    logger.exception("branch %d failed: %s", i, e)
                    branches.append(BranchResult(
                        branch=i, container=c, agent_ms=0.0, error=str(e)))
        branches.sort(key=lambda b: b.branch)


        for b in branches:
            if b.error:
                logger.error("round %d branch %d error: %s",
                             round_idx, b.branch, b.error)

        winner = self.pick_winner(branches)
        losers = [b.container for b in branches
                  if not winner or b.container != winner.container]


        self._teardown_async(mode=mode, round_idx=round_idx, src=None,
                             clones=losers)

        elapsed = _now_ms() - t_round


        agent_wall = max((b.agent_ms for b in branches), default=0.0)
        judge_wall = max((b.judge_ms for b in branches), default=0.0)
        round_extra = {"n": n,
                       "winner_branch": winner.branch if winner else None,
                       "winner_score": winner.effective_score if winner else None,

                       "working_set_bytes": ws_bytes,
                       "clone_ms": clone_ms,
                       "agent_ms": agent_wall,
                       "judge_ms": judge_wall}
        self._record("round", t_round, elapsed, round=round_idx, mode=mode.name,
                     extra=round_extra)
        rr = RoundResult(
            round_idx=round_idx, mode=mode, src=src, clones=clones,
            branches=branches, winner=winner,
            elapsed_ms=elapsed, clone_ms=clone_ms,
        )
        self.rounds.append(rr)
        self.save()
        return rr

    def _print_winner_round(self, rr: "RoundResult") -> None:
        """Stream the winning branch's plan + action + judge verdict +
        stage timings for one round. Same shape as solo's _print_round.
        OSWorld actions are pyautogui code blobs (rc + code + stderr)."""
        win = rr.winner
        if win is None:
            return
        bar = "─" * 76
        print(f"  {bar}")
        print(f"  [round {rr.round_idx:>2}] container={win.container[:12]} "
              f"branch={win.branch} steps={win.n_steps} "
              f"finished={win.finished} err={(win.error or '')[:80]!r}")
        print(f"  {bar}")


        evs = sorted(
            (t for t in self.timings
             if t.round == rr.round_idx and t.branch == win.branch),
            key=lambda t: t.started_ms,
        )

        plans = [t for t in evs if t.label == "llm_call"
                 and t.extra.get("stage") == "planner"]
        if plans:
            last_plan = plans[-1]
            print(f"    planner: {last_plan.elapsed_ms:.0f}ms "
                  f"in={last_plan.extra.get('tokens_in')} "
                  f"out={last_plan.extra.get('tokens_out')} "
                  f"cached={last_plan.extra.get('cached')}")


            text = last_plan.extra.get("text") or ""
            if not text and self.llm_cache is not None:
                tid = last_plan.extra.get("task_id")
                cand = (self.llm_cache.root / f"round-{rr.round_idx:02d}"
                        / f"branch-{last_plan.branch}" / f"{tid}.json")
                if cand.exists():
                    try:
                        payload = json.loads(cand.read_text())
                        text = payload.get("result", {}).get("text", "")
                    except (json.JSONDecodeError, OSError):
                        pass
            if text:
                print("    plan:")
                for line in text.splitlines()[:30]:
                    print(f"      | {line}")

        for a in (t for t in evs if t.label == "action"):
            ex = a.extra


            rc = ex.get("rc")
            code = (ex.get("code") or "").strip()
            stderr = (ex.get("stderr") or "").strip()
            print(f"    action: {a.elapsed_ms:.0f}ms rc={rc}")
            for line in code.splitlines():
                print(f"      > {line}")
            if stderr:
                print(f"      stderr: {stderr[:240]!r}")


        if win.judge_ms or win.score is not None or win.judge_reason:
            print(f"    judge: success={win.success!r} "
                  f"score={win.score!r} "
                  f"reason={(win.judge_reason or '')[:200]!r}")

        sm = win.stage_ms or {}
        if sm:
            breakdown = " ".join(f"{k}={v:.0f}ms" for k, v in sm.items())
            print(f"    stages: {breakdown}")

    def beam_search(self, *, mode: ExpMode, n: Optional[int] = None,
                    depth: int = 1, round_offset: int = 0) -> list[RoundResult]:
        """Multi-round beam: round R+1 clones from round R's winner.
        ``depth=1`` collapses to a single fan-out + judge."""
        n = n or self.config.n


        tid = self.config.task_id or "<no-id>"
        task_txt = (self.config.task or "").strip().splitlines()
        print(f"  task[{tid}]: {(task_txt[0] if task_txt else '')[:300]}",
              flush=True)
        rounds: list[RoundResult] = []
        d = self.driver(mode)
        t_src = _now_ms()
        src = d.launch_source(round_idx=round_offset + 1)
        self._record("src_launch", t_src, _now_ms() - t_src,
                     round=round_offset + 1, mode=mode.name)


        chain: list[str] = [src]
        parent_state: Any = None
        depth = 30 if depth > 30 else depth
        try:
            for k in range(1, depth + 1):
                rr = self.run_round(mode=mode, round_idx=round_offset + k,
                                    src=src, n=n, parent_state=parent_state)
                rounds.append(rr)


                win = rr.winner
                wb = f"branch{win.branch}" if win else "branch?"
                wscore = win.effective_score if win else 0.0
                wfin = win.finished if win else False
                wsteps = win.n_steps if win else 0
                print(
                    f"  r{rr.round_idx}/{round_offset + depth} "
                    f"{rr.mode.name} clone={rr.clone_ms/1000:.2f}s "
                    f"wall={rr.elapsed_ms/1000:.2f}s "
                    f"winner={wb} score={wscore:.2f} "
                    f"steps={wsteps} finished={wfin}",
                    flush=True,
                )


                wl = self.config.workload
                if wl is not None:
                    try:
                        self._print_winner_round(rr)
                    except Exception as e:
                        logger.debug("verbose round print failed: %s", e)
                if not rr.winner:
                    logger.warning("round %d had no winner; stopping beam",
                                   rr.round_idx)
                    break
                src = rr.winner.container
                chain.append(src)
                parent_state = rr.winner.state


        finally:


            for s in reversed(chain):
                self._teardown_async(mode=mode,
                                     round_idx=round_offset + depth,
                                     src=s, clones=[])
        return rounds


    def _teardown_async(self, *, mode: ExpMode, round_idx: int, src: str,
                        clones: Iterable[str]) -> threading.Thread:
        """Fire driver.teardown() in a background thread so the next round
        can start immediately. Cleanup wall is recorded inside the thread."""
        clones_l = list(clones)
        d = self.driver(mode)

        def _run() -> None:
            t0 = _now_ms()
            try:
                d.teardown(src=src, clones=clones_l, round_idx=round_idx)
            except Exception as e:
                logger.warning("teardown failed: %s", e)
            self._record("cleanup", t0, _now_ms() - t0,
                         round=round_idx, mode=mode.name,
                         extra={"n_targets": 1 + len(clones_l)})

        th = threading.Thread(target=_run, daemon=True,
                              name=f"cleanup-r{round_idx}-{mode.name}")
        th.start()
        with self._lock:
            self._cleanup_threads.append(th)
        return th

    def await_pending_cleanup(self, *, timeout: float = 60.0) -> None:
        with self._lock:
            ts = list(self._cleanup_threads)
            self._cleanup_threads.clear()
        for th in ts:
            th.join(timeout=timeout)


    def _openai(self) -> OpenAI:
        if self._client is None:


            api_key = (self._env.get("OPENAI_API_KEY")
                       or os.environ.get("OPENAI_API_KEY"))
            if not api_key:
                raise RuntimeError(
                    "OPENAI_API_KEY not set. Add it to agents/agent-s/.env "
                    "or export it before running. Live LLM calls (cache "
                    "miss in replay, or any --e2e-record run) require a "
                    "real key — failing here instead of letting OpenAI's "
                    "client return a confusing 401 deep in the call."
                )
            self._client = OpenAI(api_key=api_key)
        return self._client

    def _record(self, label: str, started_ms: float, elapsed_ms: float,
                **kw) -> None:
        extra = kw.pop("extra", {}) or {}
        ti_fields = {f.name for f in dc.fields(TimingInfo)}
        for k in list(kw):
            if k not in ti_fields:
                extra[k] = kw.pop(k)
        ti = TimingInfo(label=label, started_ms=started_ms, elapsed_ms=elapsed_ms,
                        extra=extra, **kw)
        with self._lock:
            self.timings.append(ti)


def main(argv: Optional[Iterable[str]] = None) -> int:
    p = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    p.add_argument("--rounds", type=int, default=1,
                   help="independent re-runs of the bench (statistical replicates)")
    p.add_argument("--depth", type=int, default=1,
                   help="beam-search depth: round R+1 uses round R's winner as src")
    p.add_argument("--n", type=int, default=4, help="branches per beam round")
    p.add_argument("--modes", default="CKPT,TFORK",
                   help="comma list: any of {KVM, KVM_VIRSH, CKPT, TFORK}")
    p.add_argument("--results-dir", type=Path,
                   default=Path(DEFAULT_RESULTS_DIR),
                   help=f"default ${{RESULTS_DIR}} or {DEFAULT_RESULTS_DIR}")
    p.add_argument("--model", default=DEFAULT_MODEL)

    task = p.add_mutually_exclusive_group()
    task.add_argument("--task", help="task instruction string")
    task.add_argument("--osworld-task",
                      help='OSWorld task spec, "<domain>/<id>" or path to .json')
    p.add_argument("--osworld-root", type=Path,
                   default=Path(DEFAULT_OSWORLD_ROOT),
                   help=f"default ${{OSWORLD_ROOT}} or {DEFAULT_OSWORLD_ROOT}")
    p.add_argument("--workload", default=None,
                   help='preset bundle (e.g. "osworld")')
    p.add_argument("--task-spec", default=None,
                   help='single workload task id (alias for --task-specs of length 1)')
    p.add_argument("--task-specs", default=None,
                   help='comma list of workload task ids, "ALL", or @path-to-file '
                        '(one id per line, # comments). Each task runs in its own '
                        'subdirectory under --results-dir.')

    p.add_argument("--judge", action="store_true",
                   help="post-trajectory LLM success judge per branch")
    p.add_argument("--setup", action="store_true",
                   help="apply the task spec's config[] (downloads, "
                        "launches, opens) inside the source container "
                        "after launch_source. Off by default — most "
                        "config[] items pull HF artifacts and only apply "
                        "to OSWorld-style tasks.")
    p.add_argument("--llm-cache-name", default="",
                   help="if set, llm_call replays from a per-(round,branch,task_id) cache")
    p.add_argument("--virsh-source-xml", type=Path, default=None)
    p.add_argument("--virsh-source-domain", default="agent-s-source")
    p.add_argument("--virsh-libvirt-uri", default="qemu:///system")
    p.add_argument("--resume", action="store_true",
                   help="skip rounds whose round-NN.done marker exists")
    p.add_argument("--verbose", "-v", action="count", default=0)
    args = p.parse_args(argv)

    logging.basicConfig(
        level=logging.WARNING - 10 * args.verbose,
        format="%(asctime)s %(name)s %(levelname)s %(message)s",
    )

    workload = get_workload(args.workload) if args.workload else None

    cfg_kwargs: dict[str, Any] = {"osworld_examples_root": args.osworld_root}

    specs = _resolve_task_specs(args, workload, BenchConfig(**cfg_kwargs))
    modes = [ExpMode[m.strip().upper()] for m in args.modes.split(",")]

    if specs is not None:
        if not specs:
            print("no task specs resolved; nothing to do", file=sys.stderr)
            return 1
        print(f"[multi] {len(specs)} task(s): {', '.join(specs[:5])}"
              f"{' ...' if len(specs) > 5 else ''}")
        return _run_many(specs, args=args, workload=workload,
                         cfg_kwargs=cfg_kwargs, modes=modes)

    task_text, task_id, task_config = _resolve_single_task(
        args, workload, cfg_kwargs)
    cfg = _build_cfg(args, workload, task_text, task_id, cfg_kwargs,
                     task_config=task_config)
    runner = RunExp(cfg)
    run_sweep(runner, modes=modes, rounds=args.rounds, depth=args.depth,
              n=args.n, resume=args.resume)
    return 0


def _resolve_task_specs(args, workload: Optional[Workload],
                        probe_cfg: "BenchConfig") -> Optional[list[str]]:
    """Return a list of task specs from --task-specs (comma list, "ALL", or
    @file), or None if the user didn't pass --task-specs."""
    raw = args.task_specs
    if raw is None:
        return None
    if raw.strip().upper() == "ALL":
        if workload is None or workload.list_tasks is None:
            raise SystemExit("--task-specs ALL requires --workload with a "
                             "list_tasks helper (osworld)")
        return list(workload.list_tasks(probe_cfg))
    if raw.startswith("@"):
        path = Path(raw[1:]).expanduser()
        items = []
        for line in path.read_text().splitlines():
            line = line.split("#", 1)[0].strip()
            if line:
                items.append(line)
        return items
    return [s.strip() for s in raw.split(",") if s.strip()]


def _resolve_single_task(args, workload: Optional[Workload],
                         cfg_kwargs: dict[str, Any],
                         ) -> tuple[str, Optional[str], Optional[list]]:
    """Returns (instruction, task_id, task_config). task_config is the
    raw spec config[] when available (workload task_loader or
    --osworld-task); None when the task came from --task as a free string."""
    if workload is not None and args.task_spec and workload.task_loader is not None:
        loaded = workload.task_loader(args.task_spec, BenchConfig(**cfg_kwargs))
        return loaded["instruction"], loaded["task_id"], loaded.get("config")
    if args.osworld_task:
        spec = load_osworld_task(args.osworld_task, examples_root=args.osworld_root)
        return (spec["instruction"], spec.get("id", args.osworld_task),
                spec.get("config"))
    return (args.task or "Right-click on the desktop background to open the context menu.",
            None, None)


def _build_cfg(args, workload: Optional[Workload], task_text: str,
               task_id: Optional[str], cfg_kwargs: dict[str, Any],
               task_config: Optional[list] = None) -> "BenchConfig":
    return BenchConfig(
        results_dir=args.results_dir, model=args.model,
        task=task_text, task_id=task_id,
        workload=workload,
        osworld_examples_root=args.osworld_root,
        n=args.n,
        judge_enabled=args.judge, llm_cache_name=args.llm_cache_name,
        virsh_source_xml=args.virsh_source_xml,
        virsh_source_domain=args.virsh_source_domain,
        virsh_libvirt_uri=args.virsh_libvirt_uri,
        task_config=task_config,
        task_setup_enabled=getattr(args, "setup", False),
    )


def _safe_dir_segment(spec: str) -> str:
    return re.sub(r"[^A-Za-z0-9._-]+", "_", spec).strip("_") or "task"


def _run_tfork_clean(modes: list["ExpMode"]) -> None:
    """Invoke tfork-clean.sh to drop orphan containers + btrfs subvols
    left behind by the just-finished task. No-op when only non-podman
    modes ran (KVM*). Best-effort: failures log and move on.

    The bench is launched under sudo, so the child process is already
    root; the script's internal sudo calls become no-ops in that case.
    """
    if not any(m.name in ("CKPT", "TFORK") for m in modes):
        return
    script = Path(__file__).resolve().parent / "tfork-clean.sh"
    if not script.is_file():
        logger.warning("tfork-clean: script missing at %s", script)
        return
    try:
        r = subprocess.run([str(script)], capture_output=True, text=True,
                           timeout=120)
        if r.returncode != 0:
            logger.warning("tfork-clean exit=%d stderr=%s",
                           r.returncode, (r.stderr or "")[-500:])
        else:

            for line in (r.stdout or "").splitlines():
                if line.startswith(("===", "  containers:",
                                    "  tfork-bundle", "  tfork-bundles")):
                    print(f"  [tfork-clean] {line.strip()}")
    except (OSError, subprocess.SubprocessError) as e:
        logger.warning("tfork-clean: %s", e)


def _run_many(specs: list[str], *, args, workload: Workload,
              cfg_kwargs: dict[str, Any], modes: list["ExpMode"]) -> int:
    """One BenchConfig + RunExp per task. Each task gets its own
    ``<results_dir>/<task-segment>/`` directory and ``<llm-cache>/<task>``
    cache so they never share state."""
    if workload is None or workload.task_loader is None:
        raise SystemExit("--task-specs requires --workload with a task_loader")
    base_results = args.results_dir
    base_cache = args.llm_cache_name
    failures = 0
    for i, spec in enumerate(specs):
        seg = _safe_dir_segment(spec)
        print(f"\n[task {i + 1}/{len(specs)}] {spec}")
        try:
            loaded = workload.task_loader(spec, BenchConfig(**cfg_kwargs))
        except Exception as e:
            print(f"  skip — task_loader failed: {e}", file=sys.stderr)
            failures += 1
            continue
        ns = argparse.Namespace(**vars(args))
        ns.results_dir = base_results / seg
        ns.llm_cache_name = f"{base_cache}/{seg}" if base_cache else ""
        cfg = _build_cfg(ns, workload, loaded["instruction"], loaded["task_id"],
                         cfg_kwargs, task_config=loaded.get("config"))
        try:
            runner = RunExp(cfg)
            run_sweep(runner, modes=modes, rounds=args.rounds, depth=args.depth,
                      n=args.n, resume=args.resume)
        except Exception as e:
            logger.exception("task %s failed: %s", spec, e)
            failures += 1
        finally:
            _run_tfork_clean(modes)
    print(f"\n[multi] done. {len(specs) - failures}/{len(specs)} succeeded.")
    return 0 if failures == 0 else 2


def run_sweep(runner: "RunExp", *, modes: list["ExpMode"], rounds: int,
              depth: int, n: int, resume: bool = False) -> None:
    """Drive the outer rounds × modes loop and print per-round summaries.

    Each ``round`` is a statistical replicate; within a round, every
    mode runs a depth-deep beam search. The marker file
    ``round-NN.done`` lets ``--resume`` pick up where a crashed sweep
    left off.
    """
    for r in range(1, rounds + 1):
        if resume and runner.round_done(r):
            print(f"[round {r}] skipped (resume marker)")
            continue
        for mode in modes:
            offset = (r - 1) * depth
            print(f"[round {r}/{rounds}] mode={mode.name} depth={depth}")
            try:
                runner.beam_search(
                    mode=mode, n=n, depth=depth, round_offset=offset)
            except Exception as e:
                logger.exception("round %d %s failed: %s", r, mode.name, e)
        runner.mark_round_done(r)
        runner.save()

    runner.await_pending_cleanup()
    print(f"\nDone. timings @ {runner.save()}")
    print(f"     screenshots @ {runner.screenshots.root}")
    if runner.llm_cache is not None:
        print(f"     llm cache  @ {runner.llm_cache.root}")


if __name__ == "__main__":
    sys.exit(main())
