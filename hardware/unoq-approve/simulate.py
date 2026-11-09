#!/usr/bin/env python3
"""Desktop simulator for the UNO Q Approve button: the same approver.py logic, with the 8x13 LED matrix
drawn in the terminal and keys standing in for the button.

  python hardware/unoq-approve/simulate.py --demo                 # made-up requests, no box needed
  python hardware/unoq-approve/simulate.py --config approver.json # a real family box (familybox device add)
  python hardware/unoq-approve/simulate.py --demo --script "wait 2, short, wait 3, long, wait 3"

Keys: Space or Enter = press (approve)   H = hold (deny)   A = add a made-up request (demo only)   Q = quit
"""

from __future__ import annotations

import argparse
import json
import os
import select
import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent / "python"))

import approver  # noqa: E402

# Fictional household from demo/family.toml. No real person or value appears anywhere here.
DEMO_REQUESTS = [
    "Maya's ChatGPT wants Dana's passport number",
    "Sam's Claude wants Dana's Social Security number",
    "Maya's Codex wants Dana's health detail",
]


class FakeBox:
    """An in-memory stand-in for the box's device API, answering like the real one (no values, ever)."""

    def __init__(self, token: str = "fbd_0000demo_" + "x" * 43):
        self.token = token
        self.items: list[dict] = []
        self.decided: list[tuple[str, str]] = []
        self.n = 0

    def add(self, text: str | None = None) -> None:
        text = text or DEMO_REQUESTS[self.n % len(DEMO_REQUESTS)]
        self.n += 1
        self.items.append({"id": f"demo{self.n:04d}", "text": text, "created": int(time.time()) + self.n})

    def transport(self, method: str, path: str, headers: dict) -> tuple[int, bytes]:
        if headers.get("Authorization") != f"Bearer {self.token}":
            return 401, b'{"error": "device not recognized"}'
        if method == "GET" and path == f"{approver.API}/pending":
            return 200, json.dumps({"count": len(self.items), "items": self.items}).encode()
        parts = path.split("/")
        if method == "POST" and path.startswith(f"{approver.API}/items/") and len(parts) == 7:
            item_id, action = parts[5], parts[6]
            if action in ("approve", "deny") and any(i["id"] == item_id for i in self.items):
                self.items = [i for i in self.items if i["id"] != item_id]
                status = "approved" if action == "approve" else "denied"
                self.decided.append((item_id, status))
                return 200, json.dumps({"id": item_id, "status": status}).encode()
        return 404, b'{"error": "not found"}'


def draw(frame: approver.Frame, caption: str, footer: str, ansi: bool) -> str:
    on, off = ("██", "· ") if ansi else ("#", ".")
    rows = ["+" + "-" * (len(on) * approver.WIDTH) + "+"]
    rows += ["|" + "".join(on if p else off for p in row) + "|" for row in frame]
    rows.append(rows[0])
    out = "\n".join(rows) + f"\n{caption or '(nothing waiting)'}\n{footer}\n"
    return ("\x1b[H\x1b[2J" + out) if ansi else out


def parse_script(script: str) -> list[tuple[str, float]]:
    steps = []
    for part in [p.strip() for p in script.split(",") if p.strip()]:
        word, _, arg = part.partition(" ")
        if word == "wait":
            steps.append(("wait", float(arg or 1)))
        elif word in ("short", "long", "add"):
            steps.append((word, 0.0))
        else:
            raise SystemExit(f"unknown script step {part!r}; use wait N, short, long, add")
    return steps


def make_client(args) -> tuple[approver.BoxClient | None, FakeBox | None]:
    if args.demo:
        fake = FakeBox()
        for _ in range(args.requests):
            fake.add()
        return approver.BoxClient(fake.token, fake.transport), fake
    try:
        cfg = approver.load_config(Path(args.config) if args.config else None)
    except (ValueError, OSError) as e:
        print(f"not set up: {e}", file=sys.stderr)
        return None, None
    return approver.BoxClient.from_config(cfg), None


def run_script(args, state, runner, scroller, fake) -> int:
    """Non-interactive: follow the script and print a frame every --every seconds (plain characters)."""
    t_end_steps = parse_script(args.script)
    last_print = -1e9
    for step, arg in t_end_steps + [("wait", 0.0)]:
        if step in ("short", "long"):
            runner.press(step)
            print(f">>> button: {'press (approve)' if step == 'short' else 'hold (deny)'}")
        elif step == "add" and fake:
            fake.add()
            print(">>> a new made-up request arrives")
        deadline = time.monotonic() + arg
        while True:
            now = time.monotonic()
            text, waiting = state.screen()
            if now - last_print >= args.every:
                print(draw(scroller.frame(text, waiting, now), text, "", ansi=False))
                last_print = now
            if now >= deadline:
                break
            time.sleep(0.05)
    if fake:
        print(f"decisions sent to the box: {fake.decided or 'none'}")
    return 0


def run_interactive(args, state, runner, scroller, fake) -> int:
    import termios
    import tty
    fd = sys.stdin.fileno()
    old = termios.tcgetattr(fd)
    footer = "Space/Enter = press (approve)   H = hold (deny)" + ("   A = new request" if fake else "") + \
             "   Q = quit"
    note = ""
    try:
        tty.setcbreak(fd)
        sys.stdout.write("\x1b[?25l")
        while True:
            ready, _, _ = select.select([sys.stdin], [], [], 0.05)
            if ready:
                key = os.read(fd, 1).decode(errors="ignore").lower()
                if key == "q":
                    break
                if key in (" ", "\n", "\r"):
                    runner.press("short"); note = "you pressed the button"
                elif key == "h":
                    runner.press("long"); note = "you held the button"
                elif key == "a" and fake:
                    fake.add(); note = "a new made-up request arrived"
            text, waiting = state.screen()
            frame = scroller.frame(text, waiting, time.monotonic())
            sys.stdout.write(draw(frame, text, f"{footer}\n{note}", ansi=True))
            sys.stdout.flush()
    finally:
        termios.tcsetattr(fd, termios.TCSADRAIN, old)
        sys.stdout.write("\x1b[?25h\n")
    if fake:
        print(f"decisions sent to the made-up box: {fake.decided or 'none'}")
    return 0


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    src = ap.add_mutually_exclusive_group()
    src.add_argument("--demo", action="store_true", help="use made-up requests instead of a real box")
    src.add_argument("--config", help="approver.json from `familybox device add` (default: FAMILYBOX_* env)")
    ap.add_argument("--requests", type=int, default=1, help="made-up requests waiting at the start (--demo)")
    ap.add_argument("--script", help='run without a keyboard, e.g. "wait 2, short, wait 3"')
    ap.add_argument("--every", type=float, default=0.5, help="seconds between printed frames (--script)")
    ap.add_argument("--speed", type=float, default=14.0, help="scroll speed in columns per second")
    args = ap.parse_args(argv)

    client, fake = make_client(args)
    poll_s = 0.5 if fake else approver.POLL_S
    state = approver.Approver(client)
    runner = approver.Runner(state, poll_s=poll_s).start()
    scroller = approver.Scroller(cols_per_s=args.speed)
    time.sleep(0.2)   # let the first poll land
    try:
        if args.script or not sys.stdin.isatty():
            return run_script(args, state, runner, scroller, fake) if args.script else \
                (print("no keyboard: pass --script", file=sys.stderr) or 2)
        return run_interactive(args, state, runner, scroller, fake)
    finally:
        runner.stop()


if __name__ == "__main__":
    sys.exit(main())
