"""Drop-in pyautogui shim that drives xdotool.

The OSWorld bench builds pyautogui call strings (see
workloads/osworld.py:_format_action) and execs them inside the
container. This shim covers exactly the surface the bench uses so the
generator code can stay unchanged.

xdotool sends events to the X server via the XTest extension. It
needs no special device passthrough (no /dev/uinput, no /dev/input)
and works against the existing kwin_x11 + Xvfb session that Selkies
streams.

Required at runtime: DISPLAY=:1 (and XAUTHORITY=/config/.Xauthority
if auth is enabled — the bench already sets both).
"""
import os
import subprocess
import time

FAILSAFE = False


_BUTTON = {"left": 1, "middle": 2, "right": 3,
           1: 1, 2: 2, 3: 3}


_KEY_RENAME = {
    "enter": "Return", "return": "Return",
    "esc": "Escape", "escape": "Escape",
    "del": "Delete", "delete": "Delete",
    "backspace": "BackSpace",
    "ins": "Insert", "insert": "Insert",
    "pageup": "Page_Up", "pagedown": "Page_Down",
    "up": "Up", "down": "Down", "left": "Left", "right": "Right",
    "ctrl": "ctrl", "ctrlleft": "ctrl", "ctrlright": "ctrl",
    "shift": "shift", "shiftleft": "shift", "shiftright": "shift",
    "alt": "alt", "altleft": "alt", "altright": "alt",
    "win": "super", "winleft": "super", "winright": "super",
    "super": "super", "cmd": "super", "command": "super", "meta": "super",
    "capslock": "Caps_Lock", "numlock": "Num_Lock",
    "tab": "Tab", "space": "space",
    "home": "Home", "end": "End",
    "f1": "F1", "f2": "F2", "f3": "F3", "f4": "F4", "f5": "F5",
    "f6": "F6", "f7": "F7", "f8": "F8", "f9": "F9", "f10": "F10",
    "f11": "F11", "f12": "F12",
}


def _xdo(*args, check=True):
    return subprocess.run(["xdotool", *map(str, args)],
                          capture_output=True, text=True,
                          env={**os.environ, "DISPLAY": os.environ.get("DISPLAY", ":1")},
                          check=check)


def _key_name(name):
    if isinstance(name, str):
        return _KEY_RENAME.get(name.lower(), name)
    return str(name)


def moveTo(x, y, duration=0.0, **_kw):
    _xdo("mousemove", "--sync", int(x), int(y))
    if duration:
        time.sleep(duration)


def click(x=None, y=None, clicks=1, interval=0.0, button="left", **_kw):
    if x is not None and y is not None:
        moveTo(x, y)
    btn = _BUTTON.get(button, 1)
    args = ["click", "--repeat", str(int(clicks))]
    if interval:
        args += ["--delay", str(int(interval * 1000))]
    args.append(str(btn))
    _xdo(*args)


def rightClick(x=None, y=None, **kw):
    click(x, y, button="right", **kw)


def doubleClick(x=None, y=None, **kw):
    click(x, y, clicks=2, **kw)


def mouseDown(x=None, y=None, button="left", **_kw):
    if x is not None and y is not None:
        moveTo(x, y)
    _xdo("mousedown", _BUTTON.get(button, 1))


def mouseUp(x=None, y=None, button="left", **_kw):
    if x is not None and y is not None:
        moveTo(x, y)
    _xdo("mouseup", _BUTTON.get(button, 1))


def dragTo(x, y, duration=0.0, button="left", **_kw):
    mouseDown(button=button)
    if duration:
        time.sleep(duration)
    moveTo(x, y)
    mouseUp(button=button)


def scroll(clicks, x=None, y=None, **_kw):
    if x is not None and y is not None:
        moveTo(x, y)

    btn = 4 if clicks > 0 else 5
    _xdo("click", "--repeat", str(abs(int(clicks))), str(btn))


def write(text, interval=0.0, **_kw):
    delay_ms = max(int(interval * 1000), 0)
    _xdo("type", "--delay", delay_ms, "--", str(text))


typewrite = write


def press(key, presses=1, interval=0.0, **_kw):
    if isinstance(key, (list, tuple)):
        for k in key:
            press(k, presses=presses, interval=interval)
        return
    name = _key_name(key)
    args = ["key", "--repeat", str(int(presses))]
    if interval:
        args += ["--delay", str(int(interval * 1000))]
    args.append(name)
    _xdo(*args)


def keyDown(key, **_kw):
    _xdo("keydown", _key_name(key))


def keyUp(key, **_kw):
    _xdo("keyup", _key_name(key))


def hotkey(*keys, interval=0.0, **_kw):


    combo = "+".join(_key_name(k) for k in keys)
    _xdo("key", combo)


def position():
    try:
        out = _xdo("getmouselocation").stdout

        parts = dict(p.split(":", 1) for p in out.split() if ":" in p)
        return (int(parts["x"]), int(parts["y"]))
    except Exception:
        return (0, 0)


def size():
    try:
        out = _xdo("getdisplaygeometry").stdout.strip()
        w, h = out.split()
        return (int(w), int(h))
    except Exception:
        return (1920, 1080)
