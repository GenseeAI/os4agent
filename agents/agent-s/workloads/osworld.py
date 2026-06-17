"""OSWorld workload — Agent-S style GUI agent, ported inline.

Per turn: screenshot → reflector (turn ≥ 2) → planner → parse plan →
grounder per click → driver.exec. Multi-turn role-tagged chat history
on ``OsworldState`` propagates across beam rounds via
``BranchResult.state``.
"""

from __future__ import annotations

import base64
import dataclasses as dc
import logging
import os
import re
import textwrap
from pathlib import Path
from typing import TYPE_CHECKING, Any, Optional

logger = logging.getLogger("os4agent.workloads.osworld")

from . import (
    DEFAULT_OSWORLD_BASE_DISK, DEFAULT_OSWORLD_IMAGE, DEFAULT_OSWORLD_ROOT,
    Workload,
)
from .prompts import AGENT_S_DEFAULT_PROMPTS

if TYPE_CHECKING:
    from bench import BranchResult, ExpMode, RunExp
    from drivers import SnapshotDriver


@dc.dataclass
class OsworldState:
    """Role-tagged worker + reflection chat history; append-only."""
    worker_messages: list[dict[str, Any]] = dc.field(default_factory=list)
    reflection_messages: list[dict[str, Any]] = dc.field(default_factory=list)
    last_plan: str = ""
    turn_count: int = 0


_WORKER_SYSTEM = textwrap.dedent("""\
    You are an expert in graphical user interfaces and Python code. You
    are responsible for executing the task: `{task}`.
    You are working in {os_name}.

    Never assume a task is done based on appearances — always ensure
    the specific requested action has been performed and is visible
    on screen. If you haven't executed any actions, the task is not
    complete.

    You are provided with:
    1. A screenshot of the current time step.
    2. The history of your previous interactions with the UI.
    3. Access to the following class and methods to interact with the UI:

    class Agent:

        def click(element_description: str, num_clicks: int = 1,
                  button_type: str = "left") -> None:
            '''Click on the described element. ``element_description`` is a
            natural-language description of the target — a separate vision
            model resolves it to pixel coordinates. Be specific (e.g. "the
            three-dot menu in Chromium's top-right toolbar", not "the
            menu").'''

        def double_click(element_description: str) -> None: ...
        def right_click(element_description: str) -> None: ...
        def triple_click(element_description: str) -> None:
            '''Useful for selecting an entire line of text.'''
        def middle_click(element_description: str) -> None: ...

        def scroll(element_description: str, count: int = 3,
                   direction: str = "down") -> None: ...

        def drag(source_description: str, target_description: str) -> None: ...

        def write(text: str, enter: bool = False) -> None:
            '''Type literal text into the focused field. ``enter=True``
            presses Enter after typing.'''

        def hotkey(keys: list[str]) -> None:
            '''Press the listed keys as a CHORD (held simultaneously).
            For Ctrl+S, Alt+Tab, etc. Do NOT use for repeated or
            sequential keys — use ``press`` for those.'''

        def press(key, presses: int = 1, interval: float = 0.05) -> None:
            '''Press a single key, optionally repeated ``presses`` times,
            OR press a list of keys in sequence.
            Examples:
              agent.press("down", presses=14)
              agent.press(keys=["down", "down", "enter"])'''

        def key_down(key: str) -> None:
            '''Hold ``key`` down. Pair with ``key_up``.'''
        def key_up(key: str) -> None: ...

        def wait(seconds: float = 1.0) -> None: ...

        def shell(cmd: str) -> None:
            '''Run a bash command inside the container. Useful for
            inspecting state, reading files, or applying gsettings
            without traversing GUI menus.'''

        def done() -> None:
            '''The task is fully complete and visibly verified.'''
        def fail() -> None:
            '''Task is impossible to complete after exhausting reasonable attempts.'''

    Your response should be formatted like this:
    (Previous action verification)
    Carefully analyze based on the screenshot if the previous action was
    successful. If the previous action was not successful, provide a
    reason for the failure.

    (Screenshot Analysis)
    Closely examine and describe the current state of the desktop along
    with the currently open applications.

    (Next Action)
    Based on the current screenshot and the history of your previous
    interaction with the UI, decide on the next action in natural
    language to accomplish the given task.

    (Grounded Action)
    Translate the next action into code using the provided API methods.
    Format the code like this:
    ```python
    agent.click("The menu button at the top right of the window", 1, "left")
    ```

    Note for the grounded action:
    1. Only perform one action at a time.
    2. Do not put anything other than python code in the code block.
       You can only use one function call at a time. Do not put more
       than one function call in the block.
    3. You must use only the available methods provided above to
       interact with the UI; do not invent new methods.
    4. Only return one code block every time. There must be a single
       line of code in the code block.
    5. NEVER guess pixel coordinates yourself — always describe the
       target element in natural language and let the grounder
       resolve it.
    6. Whenever possible, your grounded action should use hot-keys
       (``agent.hotkey``) or application keyboard shortcuts (e.g.
       Ctrl+L for the address bar, Ctrl+, for preferences) instead
       of clicking or dragging. They're more reliable than visual
       grounding and faster.
    7. ``hotkey`` is a CHORD (held simultaneously). Use ``press`` for
       repeated or sequential keys.
    8. Generate ``agent.fail()`` as your grounded action ONLY if you
       are exhaustively stuck and believe the task is impossible.
       Never call ``fail()`` on the first turn.
    9. Generate ``agent.done()`` as your grounded action ONLY when the
       screenshot CLEARLY shows the task is complete. Do not call
       ``done()`` after merely describing a plan.
    10. If repeating the same action stops producing visible progress
        (the screenshot looks unchanged), CHANGE STRATEGY: try a
        keyboard shortcut, a different element, or ``agent.shell``
        to inspect state. Do not click the same area more than twice.
    11. Prefer hotkeys and application features over clicking on
        text elements when possible. Highlighting text is fine.
""")


_REFLECTOR_SYSTEM = textwrap.dedent("""\
    You are a reflection agent watching a GUI agent solve a task. After
    each step you receive: the screenshot AFTER the step, plus the plan
    the agent issued. Reply in 1-2 sentences: did the plan have the
    intended effect? What should the agent try next?

    TASK: {task}
""")


def _user_with_image(text: str, image_b64: str) -> dict[str, Any]:
    return {"role": "user", "content": [
        {"type": "text", "text": text},
        {"type": "image_url",
         "image_url": {"url": f"data:image/png;base64,{image_b64}"}},
    ]}


def _assistant(text: str) -> dict[str, Any]:
    return {"role": "assistant", "content": text}


def _strip_old_images(messages: list[dict[str, Any]], *, keep_last: int) -> None:
    """Drop images from all but the last ``keep_last`` user messages.
    Mutates the prefix → invalidates prefix cache up to that point."""
    img_indices = [
        i for i, m in enumerate(messages)
        if m["role"] == "user" and isinstance(m["content"], list)
        and any(isinstance(c, dict) and c.get("type") == "image_url"
                for c in m["content"])
    ]
    drop = img_indices[:-keep_last] if keep_last > 0 else img_indices
    for i in drop:
        text_parts = [c for c in messages[i]["content"]
                      if isinstance(c, dict) and c.get("type") == "text"]
        text_parts.append({"type": "text",
                           "text": "(prior screenshot omitted)"})
        messages[i] = {"role": "user", "content": text_parts}


_GROUNDER_PROMPT = (
    "Query:{ref_expr}\n"
    "Output only the coordinate of one point in your response.\n"
)


_JUDGE_PROMPT = (
    "You are a strict, impartial GUI-agent judge. Given ONE screenshot of "
    "a desktop, score how close the agent is to completing the user's "
    "request, on a 0-10 scale.\n"
    "TASK: {task}\n\n"
    "Scoring scale:\n"
    "  10: task is visibly complete; the goal state is on screen.\n"
    "  7-9: substantial progress; goal essentially done with minor "
    "cleanup pending (leftover popup, wrong window in front).\n"
    "  4-6: meaningful progress; the agent has opened the right app, "
    "surfaced the right setting, or is mid-flow through a dialog with "
    "the right inputs.\n"
    "  1-3: little progress; agent is exploring or hunting for the right "
    "UI but nothing materially closer to the goal.\n"
    "  0: visibly worse than the start (regression: wrong app open, "
    "error dialog, agent stuck on an unrelated screen).\n\n"
    "Rules:\n"
    "- Judge only what is visible. Do not assume offscreen progress.\n"
    "- An UNRELATED popup, account-setup wizard, donation page, or "
    "error dialog is a regression — penalize.\n"
    "- App-internal pickers, menus, file-open dialogs, settings panes, "
    "etc. that the agent intentionally opened to advance the task are "
    "NOT regressions; score them on whether they're advancing the goal.\n\n"
    "Reply ONLY with a JSON object:\n"
    '{{"success": <true|false>, "score": <0..10>, "reason": "<one sentence>"}}\n'
)


_CODE_BLOCK_RE = re.compile(r"```(?:python)?\s*\n(.*?)```", re.DOTALL)
_COORDS_RE = re.compile(r"\d+")


def _parse_plan_code(plan_text: str) -> str:
    m = _CODE_BLOCK_RE.search(plan_text)
    return (m.group(1) if m else plan_text).strip()


def _walk_actions(plan_code: str
                  ) -> list[tuple[str, list[Any], dict[str, Any]]]:
    """Parse ``plan_code`` as Python and yield every ``agent.<verb>(...)``
    call in textual order. Uses the AST so nested parens inside string
    args (e.g. ``"foo (bar) baz"``) are handled correctly — a regex
    parser bails at the first ``)`` it sees, even inside a quoted arg."""
    import ast
    try:
        tree = ast.parse(plan_code)
    except SyntaxError:
        return []
    actions: list[tuple[str, list[Any], dict[str, Any]]] = []
    for node in ast.walk(tree):
        if not isinstance(node, ast.Call):
            continue
        f = node.func
        if not (isinstance(f, ast.Attribute)
                and isinstance(f.value, ast.Name)
                and f.value.id == "agent"):
            continue
        positional: list[Any] = []
        for a in node.args:
            try:
                positional.append(ast.literal_eval(a))
            except (ValueError, SyntaxError):
                positional.append(None)
        kwargs: dict[str, Any] = {}
        for kw in node.keywords:
            if kw.arg is None:
                continue
            try:
                kwargs[kw.arg] = ast.literal_eval(kw.value)
            except (ValueError, SyntaxError):
                pass
        actions.append((f.attr, positional, kwargs))
    return actions


def _parse_coords(text: str) -> Optional[tuple[int, int]]:
    nums = _COORDS_RE.findall(text or "")
    return (int(nums[0]), int(nums[1])) if len(nums) >= 2 else None


def _ground(*, ref_expr: str, screenshot: bytes, runner: "RunExp",
            round_idx: int, branch: int, step_tag: str,
            ) -> Optional[tuple[int, int]]:
    rsp = runner.llm_call(
        model=runner.config.model, image=screenshot,
        prompt=_GROUNDER_PROMPT.format(ref_expr=ref_expr),
        round_idx=round_idx, branch=branch,
        task_id=f"ground-{step_tag}", stage="grounder",
    )
    coords = _parse_coords(rsp.get("text", ""))
    if coords is None:


        rsp = runner.llm_call(
            model=runner.config.model, image=screenshot,
            prompt=_GROUNDER_PROMPT.format(ref_expr=ref_expr),
            round_idx=round_idx, branch=branch,
            task_id=f"ground-{step_tag}-retry", stage="grounder",
        )
        coords = _parse_coords(rsp.get("text", ""))
    return coords


def _format_action(verb: str, positional: list[Any], kwargs: dict[str, Any],
                   *, screenshot: bytes, runner: "RunExp",
                   round_idx: int, branch: int, action_idx: int,
                   ) -> tuple[str, bool, Optional[str]]:
    tag = f"r{round_idx}-b{branch}-a{action_idx}"

    if verb == "done":
        return ("", True, None)
    if verb == "fail":
        return ("", True, "agent.fail()")
    if verb in ("next", "screenshot"):
        return ("pass", False, None)

    if verb == "wait":
        secs = positional[0] if positional else kwargs.get("seconds", 1.0)
        return (f"import time; time.sleep({float(secs)})", False, None)

    if verb in ("click", "double_click", "right_click",
                "triple_click", "middle_click"):
        if not positional:
            return ("", False, f"{verb} without target description")
        desc = positional[0]


        verb_defaults = {
            "click":         (1, "left"),
            "double_click":  (2, "left"),
            "triple_click":  (3, "left"),
            "right_click":   (1, "right"),
            "middle_click":  (1, "middle"),
        }
        d_clicks, d_button = verb_defaults[verb]
        if verb == "click":
            clicks = positional[1] if len(positional) > 1 else kwargs.get("clicks", d_clicks)
            button = positional[2] if len(positional) > 2 else kwargs.get("button", d_button)
        else:
            clicks = kwargs.get("clicks", d_clicks)
            button = kwargs.get("button", d_button)
        coords = _ground(ref_expr=desc, screenshot=screenshot, runner=runner,
                         round_idx=round_idx, branch=branch, step_tag=tag)
        if coords is None:
            return ("", False, f"grounder: no coords for {desc!r}")
        x, y = coords
        return (f"pyautogui.click({x}, {y}, clicks={int(clicks)}, "
                f"button={button!r})", False, None)

    if verb == "click_at":
        if len(positional) < 2:
            return ("", False, "click_at requires (x, y)")
        x, y = int(positional[0]), int(positional[1])
        clicks = kwargs.get("clicks", 1)
        button = kwargs.get("button", "left")
        return (f"pyautogui.click({x}, {y}, clicks={int(clicks)}, "
                f"button={button!r})", False, None)

    if verb == "move":
        if len(positional) < 2:
            return ("", False, "move requires (x, y)")
        x, y = int(positional[0]), int(positional[1])
        return (f"pyautogui.moveTo({x}, {y})", False, None)

    if verb == "write":
        text = positional[0] if positional else kwargs.get("text", "")
        enter = bool(kwargs.get("enter", False))
        line = f"pyautogui.write({text!r}, interval=0.02)"
        if enter:
            line += "; pyautogui.press('enter')"
        return (line, False, None)

    if verb == "hotkey":
        keys = positional[0] if positional else kwargs.get("keys", [])
        if isinstance(keys, str):
            keys = [keys]


        modifiers = {"ctrl", "control", "alt", "option", "shift",
                     "cmd", "command", "meta", "super", "win",
                     "winleft", "winright", "fn"}
        is_chord = any(isinstance(k, str) and k.lower() in modifiers
                       for k in keys)
        if not is_chord and len(keys) >= 2:
            return (f"pyautogui.press({list(keys)!r})", False, None)
        return (f"pyautogui.hotkey({', '.join(repr(k) for k in keys)})",
                False, None)

    if verb == "press":


        keys_kw = kwargs.get("keys")
        first = positional[0] if positional else None
        if isinstance(first, list) or isinstance(keys_kw, list):
            seq = list(keys_kw if isinstance(keys_kw, list) else first)
            if not seq:
                return ("", False, "press: empty key list")
            return (f"pyautogui.press({seq!r})", False, None)
        key = first or keys_kw
        if not isinstance(key, str):
            return ("", False, "press requires a key name or list of keys")
        presses = int(kwargs.get("presses", 1))
        interval = float(kwargs.get("interval", 0.05))
        return (f"pyautogui.press({key!r}, presses={presses}, "
                f"interval={interval})", False, None)

    if verb == "key_down":
        key = positional[0] if positional else kwargs.get("key")
        if not isinstance(key, str):
            return ("", False, "key_down requires a key name")
        return (f"pyautogui.keyDown({key!r})", False, None)

    if verb == "key_up":
        key = positional[0] if positional else kwargs.get("key")
        if not isinstance(key, str):
            return ("", False, "key_up requires a key name")
        return (f"pyautogui.keyUp({key!r})", False, None)

    if verb == "scroll":
        if not positional:
            return ("", False, "scroll without target")
        coords = _ground(ref_expr=positional[0], screenshot=screenshot,
                         runner=runner, round_idx=round_idx, branch=branch,
                         step_tag=tag)
        if coords is None:
            return ("", False, "grounder: no scroll coords")
        x, y = coords
        count = positional[1] if len(positional) > 1 else kwargs.get("count", 3)
        direction = kwargs.get("direction", "down")
        amount = int(count) * (-1 if direction == "down" else 1)
        return (f"pyautogui.moveTo({x}, {y}); pyautogui.scroll({amount})",
                False, None)

    if verb == "drag":
        if len(positional) < 2:
            return ("", False, "drag needs two descriptions")
        src = _ground(ref_expr=positional[0], screenshot=screenshot,
                      runner=runner, round_idx=round_idx, branch=branch,
                      step_tag=f"{tag}-src")
        dst = _ground(ref_expr=positional[1], screenshot=screenshot,
                      runner=runner, round_idx=round_idx, branch=branch,
                      step_tag=f"{tag}-dst")
        if src is None or dst is None:
            return ("", False, "grounder: missing src/dst for drag")
        return (f"pyautogui.moveTo({src[0]}, {src[1]}); "
                f"pyautogui.dragTo({dst[0]}, {dst[1]}, button='left')",
                False, None)

    if verb == "scroll_at":
        if len(positional) < 2:
            return ("", False, "scroll_at requires (x, y)")
        x, y = int(positional[0]), int(positional[1])
        count = positional[2] if len(positional) > 2 else kwargs.get("count", 3)
        direction = kwargs.get("direction", "down")
        amount = int(count) * (-1 if direction == "down" else 1)
        return (f"pyautogui.moveTo({x}, {y}); pyautogui.scroll({amount})",
                False, None)

    if verb == "drag_at":


        if (len(positional) >= 2
                and isinstance(positional[0], (list, tuple))
                and isinstance(positional[1], (list, tuple))):
            (x1, y1), (x2, y2) = positional[0], positional[1]
        elif len(positional) >= 4:
            x1, y1, x2, y2 = positional[:4]
        else:
            return ("", False, "drag_at requires (x1,y1,x2,y2) or two pairs")
        return (f"pyautogui.moveTo({int(x1)}, {int(y1)}); "
                f"pyautogui.dragTo({int(x2)}, {int(y2)}, button='left')",
                False, None)

    if verb == "shell":


        cmd = positional[0] if positional else kwargs.get("cmd")
        if not isinstance(cmd, str):
            return ("", False, "shell requires a command string")
        return (
            "import subprocess as _sp; "
            f"_p = _sp.run(['bash', '-lc', {cmd!r}], "
            "capture_output=True, text=True); "
            "print(_p.stdout, end=''); "
            "import sys; sys.stderr.write(_p.stderr); "
            "sys.exit(_p.returncode)",
            False, None,
        )

    return ("", False, f"unknown action agent.{verb}(...)")


def _build_pyautogui(plan_code: str, *, screenshot: bytes, runner: "RunExp",
                     round_idx: int, branch: int,
                     ) -> tuple[str, bool, Optional[str]]:
    lines = ["import pyautogui", "pyautogui.FAILSAFE = False"]
    finished = False
    err: Optional[str] = None
    actions = _walk_actions(plan_code)
    found = len(actions)
    for i, (verb, positional, kwargs) in enumerate(actions):
        code, fin, e = _format_action(
            verb, positional, kwargs,
            screenshot=screenshot, runner=runner,
            round_idx=round_idx, branch=branch, action_idx=i,
        )
        if e and err is None:
            err = e
        if fin:
            finished = True
            break
        if code:
            lines.append(code)
    if found == 0 and err is None:
        err = "planner emitted no agent.<verb>(...) call"
    return "\n".join(lines), finished, err


def _osworld_examples_root(cfg: Any) -> Path:
    return Path(getattr(cfg, "osworld_examples_root", None)
                or DEFAULT_OSWORLD_ROOT)


def osworld_task_loader(spec: str, cfg: Any) -> dict[str, Any]:
    from storage import load_osworld_task
    raw = load_osworld_task(spec, examples_root=_osworld_examples_root(cfg))
    return {
        "instruction": raw["instruction"],
        "task_id": raw.get("id", spec),


        "config": raw.get("config"),
        "extra": {"snapshot": raw.get("snapshot"),
                  "related_apps": raw.get("related_apps"),
                  "source": raw.get("source")},
    }


import shlex as _shlex
import time as _time
import urllib.request as _urlreq
from pathlib import Path as _Path

_FILE_CACHE = _Path.home() / ".cache" / "os4agent" / "osworld-files"
_TEMPLATE_VARS = {
    "{SCREEN_WIDTH}": "1920", "{SCREEN_HEIGHT}": "1080",
    "{SCREEN_WIDTH_HALF}": "960", "{SCREEN_HEIGHT_HALF}": "540",
}


def _driver_path_rewrites(driver: Any) -> list[tuple[str, str]]:
    """Driver tells us how OSWorld spec paths translate to its guest's
    real layout (webtop: /home/user/ → /config/; KVM: no rewrite).
    Falls back to [] if the driver doesn't expose `path_rewrites`."""
    return list(getattr(driver, "path_rewrites", []) or [])


def _expand(s: str, driver: Any) -> str:
    for k, v in _TEMPLATE_VARS.items():
        s = s.replace(k, v)
    for old, new in _driver_path_rewrites(driver):
        s = s.replace(old, new)
    return s


def _rewrite_path(p: str, driver: Any) -> str:
    for old, new in _driver_path_rewrites(driver):
        if p.startswith(old):
            return new + p[len(old):]
    return p


def _cache_download(url: str, task_id: str) -> _Path:
    fname = _urlreq.unquote(url.rsplit("/", 1)[-1]).split("?", 1)[0]
    out_dir = _FILE_CACHE / task_id
    out_dir.mkdir(parents=True, exist_ok=True)
    out = out_dir / fname
    if out.exists() and out.stat().st_size > 0:
        return out
    logger.info("[osworld-setup] download %s → %s", url, out)
    with _urlreq.urlopen(url, timeout=120) as r:
        out.write_bytes(r.read())
    return out


def _exec_setup(driver: Any, target: str, cmd: str,
                user: str | None = None) -> int:
    """driver.exec wrapper that injects DISPLAY/XAUTHORITY/HOME so
    xdg-open / wmctrl / pyautogui work inside the source. Runs as
    ``user`` (defaults to driver.desktop_user — `abc` on webtop,
    `user` on the OSWorld VM).

    `runuser` is only used when the driver's `current_user` differs
    from the requested user. PodmanDriver's `podman exec` runs as
    root, so `runuser -u abc` is needed to drop to the desktop user.
    `_SshSolo` ssh's in as the desktop user directly, so `runuser`
    would fail (it needs root to switch users) — skip it."""
    if user is None:
        user = getattr(driver, "desktop_user", "user")
    current = getattr(driver, "current_user", "root")
    env = dict(getattr(driver, "guest_env", {"DISPLAY": ":0"}))
    env["HOME"] = getattr(driver, "home_dir", f"/home/{user}")
    if user == current:
        full = cmd
    elif current == "root":
        full = (f"runuser -u {_shlex.quote(user)} -- bash -lc "
                f"{_shlex.quote(cmd)}")
    else:


        logger.debug("[osworld-setup] cannot become %s from %s; "
                     "running as %s", user, current, current)
        full = cmd
    r = driver.exec(target, full, timeout=60, env=env)
    if r.returncode != 0:
        logger.warning("[osworld-setup] rc=%d cmd=%s stderr=%s",
                       r.returncode, cmd[:160],
                       (r.stderr or "").strip()[:240])
    return r.returncode


def osworld_task_setup(driver: Any, target: str,
                       task_config: list[dict[str, Any]]) -> None:
    """Walk a spec's config[] inside ``target``. Best-effort — a step
    that fails prints + continues. ``driver`` must expose ``.exec(...)``;
    ``download`` items also need ``driver.cp_into(target, host, dest)``."""
    if not task_config:
        return
    has_cp = hasattr(driver, "cp_into")
    if not has_cp:
        logger.warning("[osworld-setup] driver %s has no cp_into; "
                       "download items will be skipped",
                       type(driver).__name__)
    print(f"[osworld-setup] applying {len(task_config)} item(s)")
    for i, item in enumerate(task_config):
        kind = item.get("type")
        params = item.get("parameters") or {}
        print(f"[osworld-setup] [{i + 1}/{len(task_config)}] {kind}")
        try:
            if kind == "download":
                if not has_cp:
                    continue


                user = getattr(driver, "desktop_user", "user")
                current = getattr(driver, "current_user", "root")


                want_chown = current == "root" and user != "root"
                for f in params.get("files", []):
                    url = f["url"]
                    task_ns = url.rsplit("/", 2)[-2] if "/" in url else "task"
                    host_path = _cache_download(url, task_ns)
                    dest = _rewrite_path(f["path"], driver)
                    if dest != f["path"]:
                        print(f"[osworld-setup]   path rewrite "
                              f"{f['path']} → {dest}")
                    parent = os.path.dirname(dest)
                    mkdir_cmd = f"mkdir -p {_shlex.quote(parent)}"
                    if want_chown:
                        mkdir_cmd += (f" && chown {user}:{user} "
                                      f"{_shlex.quote(parent)}")
                    _exec_setup(driver, target, mkdir_cmd,
                                user=current)
                    driver.cp_into(target, str(host_path), dest)
                    if want_chown:
                        _exec_setup(
                            driver, target,
                            f"chown {user}:{user} {_shlex.quote(dest)}",
                            user="root")
            elif kind in ("launch", "command"):
                cmd = params.get("command")
                if isinstance(cmd, list):
                    cmd = " ".join(_shlex.quote(s) for s in cmd)
                cmd = _expand(str(cmd), driver)
                _exec_setup(driver, target, f"({cmd}) >/dev/null 2>&1 &")
            elif kind == "execute":
                cmd = params.get("command")
                if isinstance(cmd, list):
                    cmd = " ".join(_shlex.quote(s) for s in cmd)
                cmd = _expand(str(cmd), driver)
                _exec_setup(driver, target, cmd)
            elif kind == "open":
                p = _rewrite_path(params["path"], driver)
                _exec_setup(driver, target,
                            f"xdg-open {_shlex.quote(p)} >/dev/null 2>&1 &")
            elif kind == "activate_window":
                name = params.get("window_name", "")
                _exec_setup(driver, target,
                            f"wmctrl -a {_shlex.quote(name)}")
            elif kind == "sleep":
                _time.sleep(float(params.get("seconds", 0)))
            else:
                print(f"[osworld-setup]   unsupported type {kind!r}; skipping")
        except Exception as e:
            print(f"[osworld-setup]   step {kind} failed: {e}; continuing")
    print("[osworld-setup] done")


def osworld_list_tasks(cfg: Any) -> list[str]:
    """All ``<domain>/<id>`` specs found under ``examples/``."""
    root = _osworld_examples_root(cfg) / "examples"
    if not root.exists():
        raise FileNotFoundError(
            f"OSWorld examples not found at {root}; run scripts/fetch_tasks.py")
    out = [f"{p.parent.name}/{p.stem}" for p in root.glob("*/*.json")]
    return sorted(out)


def osworld_judge(*, branch, target, task, round_idx, mode,
                  driver, runner) -> dict[str, Any]:
    png = driver.screenshot(target)
    if png is None:
        return {"success": None, "score": None, "reason": "no screenshot"}
    return runner.llm_judge(image=png, task=task, branch=branch.branch,
                            round_idx=round_idx, mode=mode)


def osworld_run_branch(*, target: str, branch_idx: int, round_idx: int,
                       mode: "ExpMode", task: str,
                       driver: "SnapshotDriver",
                       runner: "RunExp",
                       state: Optional[OsworldState] = None,
                       ) -> "BranchResult":
    from bench import BranchResult, _now_ms

    cfg = runner.config
    t0 = _now_ms()
    parent = state or OsworldState()
    new_state = OsworldState(
        worker_messages=[dict(m) for m in parent.worker_messages],
        reflection_messages=[dict(m) for m in parent.reflection_messages],
        last_plan=parent.last_plan,
        turn_count=parent.turn_count + 1,
    )


    stage_ms: dict[str, float] = {
        "screenshot": 0.0, "planning": 0.0, "grounding": 0.0,
        "reflection": 0.0, "action": 0.0,
    }

    t_ss = _now_ms()
    img = driver.screenshot(target)
    ss_dt = _now_ms() - t_ss
    stage_ms["screenshot"] += ss_dt
    runner._record("screenshot", t_ss, ss_dt, round=round_idx, mode=mode.name,
                   branch=branch_idx)
    if img is None:
        return BranchResult(branch=branch_idx, container=target,
                            agent_ms=_now_ms() - t0, error="no screenshot",
                            state=new_state, stage_ms=stage_ms)
    if cfg.capture_screenshots:
        runner.screenshots.save(img, round_idx=round_idx, mode=mode.name,
                                 branch=branch_idx, step=new_state.turn_count,
                                 phase="pre")
    img_b64 = base64.b64encode(img).decode()

    reflection_text = ""
    if cfg.enable_reflection and parent.last_plan:
        if not new_state.reflection_messages:
            new_state.reflection_messages.append({
                "role": "system",
                "content": _REFLECTOR_SYSTEM.format(task=task),
            })
        new_state.reflection_messages.append(_user_with_image(
            f"Previous plan:\n```python\n{parent.last_plan}\n```\n"
            "Screenshot AFTER executing it is attached. Reflect.",
            img_b64,
        ))
        rsp_r = runner.llm_call(
            model=cfg.model, messages=new_state.reflection_messages,
            round_idx=round_idx, branch=branch_idx,
            task_id=f"reflect-r{round_idx}-b{branch_idx}", stage="reflector",
        )
        stage_ms["reflection"] += float(rsp_r.get("latency_ms") or 0.0)
        reflection_text = (rsp_r.get("text") or "").strip()
        new_state.reflection_messages.append(_assistant(reflection_text))

    if not new_state.worker_messages:
        new_state.worker_messages.append({
            "role": "system",
            "content": _WORKER_SYSTEM.format(os_name="linux", task=task),
        })
        new_state.worker_messages.append(_user_with_image(
            "Initial screenshot attached. Emit your first plan.", img_b64))
    else:
        prefix = (f"Reflection: {reflection_text}\n\n" if reflection_text
                  else "")
        new_state.worker_messages.append(_user_with_image(
            prefix + "New screenshot attached. Emit the next plan.", img_b64))

    if cfg.max_trajectory_length:
        _strip_old_images(new_state.worker_messages,
                          keep_last=cfg.max_trajectory_length)

    plan = runner.llm_call(
        model=cfg.model, messages=new_state.worker_messages,
        round_idx=round_idx, branch=branch_idx,
        task_id=f"plan-r{round_idx}-b{branch_idx}", stage="planner",
    )
    stage_ms["planning"] += float(plan.get("latency_ms") or 0.0)
    plan_text = plan.get("text") or ""
    new_state.worker_messages.append(_assistant(plan_text))
    plan_code = _parse_plan_code(plan_text)
    new_state.last_plan = plan_code

    t_g = _now_ms()
    exec_code, finished, err = _build_pyautogui(
        plan_code, screenshot=img, runner=runner,
        round_idx=round_idx, branch=branch_idx,
    )


    stage_ms["grounding"] += sum(
        t.elapsed_ms for t in runner.timings
        if t.label == "llm_call" and t.round == round_idx
        and t.branch == branch_idx and t.started_ms >= t_g
        and t.extra.get("stage") == "grounder"
    )

    if exec_code.strip() and not (finished and exec_code.count("\n") <= 1):
        t_act = _now_ms()


        action_timeout = float(os.environ.get("OSWORLD_ACTION_TIMEOUT", "15"))
        proc = driver.exec_python(target, exec_code,
                                  timeout=action_timeout)


        import time as _t; _t.sleep(2.0)
        if proc.returncode != 0:
            err = (proc.stderr or "").strip()[:300]
        act_dt = _now_ms() - t_act
        stage_ms["action"] += act_dt
        runner._record("action", t_act, act_dt, round=round_idx,
                       mode=mode.name, branch=branch_idx,
                       extra={"rc": proc.returncode,
                              "stderr": (proc.stderr or "")[-500:],


                              "code": exec_code})


    is_soft = bool(err) and err.startswith("grounder:")
    if is_soft:
        new_state.last_plan = (new_state.last_plan or "") + f"\n# {err}"
    return BranchResult(
        branch=branch_idx, container=target,
        agent_ms=_now_ms() - t0, n_steps=1,
        finished=finished,
        error=None if (finished or is_soft) else err,
        state=new_state,
        stage_ms=stage_ms,
    )


OSWORLD = Workload(
    name="osworld",
    image=DEFAULT_OSWORLD_IMAGE,
    base_disk=DEFAULT_OSWORLD_BASE_DISK or None,
    model="gpt-5.4-mini",
    screen_w=1920,
    screen_h=1080,
    max_trajectory_length=8,
    enable_reflection=True,
    task_loader=osworld_task_loader,
    list_tasks=osworld_list_tasks,
    prompt_overrides=dict(AGENT_S_DEFAULT_PROMPTS),
    judge_prompt_template=_JUDGE_PROMPT,
    run_branch=osworld_run_branch,
    judge=osworld_judge,
    task_setup=osworld_task_setup,


    source_ready_probe=(
        "pgrep -x plasmashell >/dev/null && pgrep -x kwin_x11 >/dev/null "
        "&& pgrep -x Xvfb >/dev/null "
        "&& DISPLAY=:1 xdpyinfo >/dev/null 2>&1"
    ),


    source_post_launch=(
        "touch /config/.Xauthority && chown abc:abc /config/.Xauthority"
    ),


    source_ready_settle_s=1.0,
)
