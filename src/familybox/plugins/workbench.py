"""Confidential analysis workbench: the enclave model may run short Python scripts over the asker's files.

The model writes a stdlib-only Python script and calls run_analysis(code). The box runs it in a
throwaway sandbox (familybox.sandbox): no network, no capabilities, strict limits, and a workspace
that holds read-only copies of ONLY this person's own files and the shared folder (plus folders the
owner granted them, if include_granted is on). The script's output goes back to the model only.
Whatever the model then says still goes through the gate like any other answer.

The tool runs in a worker thread (the box never calls tools on its event loop), and only one script
runs at a time: a second one gets a "busy" answer straight away instead of waiting.

The staging copy lives in a private 0700 folder, in RAM when $XDG_RUNTIME_DIR is available, and is
deleted after each run. Leftovers from a crash are removed the next time the box starts.

Every script, its output and any limits it hit are written to the question's event log, the audit
entry (under "plugins" -> "workbench"), and the person's own workbench log
(<runtime>/workbench/<person>.jsonl), with known protected values scrubbed.

Off by default. The box owner switches it on in family.toml:

    [workbench]
    enabled = true
    people = ["dana", "maya"]     # optional: only these people get the tool (default: everyone)
    include_granted = true        # optional: also copy folders granted with also_reads (default: off)

Anything else (enabled = "true" as text, people = "dana" as text) counts as off, and
`familybox workbench status` says what to fix.

FAMILYBOX_WORKBENCH=on or off overrides family.toml. On a computer without Linux namespaces
(macOS, or user namespaces disabled) the tool is not offered, and `familybox workbench status`
says why.
"""

from __future__ import annotations

import json
import logging
import os
import shutil
import tempfile
import time
import tomllib
from pathlib import Path, PurePosixPath

from familybox import access, sandbox
from familybox.config import Config, Person
from familybox.store import Store, extract_text

log = logging.getLogger("familybox.plugins.workbench")

TOOL_NAME = "run_analysis"
MAX_RUNS_PER_QUESTION = 3
MAX_FILE_BYTES = 20 * 1024 * 1024
MAX_TOTAL_BYTES = 64 * 1024 * 1024
MAX_FILES = 2000
MAX_TEXT_CHARS = 2_000_000
EVENT_CHARS = 4000            # code and output kept in events and the audit entry
LOG_CHARS = sandbox.Limits().output_bytes + sandbox.MAX_CODE_CHARS

LIMITS = sandbox.Limits()
LEFTOVER_AGE_S = 15 * 60      # staging folders older than this are from a crash (a run takes under 1 min)

TOOL = {"type": "function", "function": {
    "name": TOOL_NAME,
    "description": (
        "Run a short Python 3 script (standard library only) on the family box to calculate, count, compare "
        "or summarize this person's files. Use it for math over several files (totals, dates, differences). "
        "The script runs in a locked sandbox with no internet. Files are read-only copies: /data/index.json "
        "lists them (path, bytes, text), /data/text/<path>.txt holds the plain text of each file and "
        "/data/files/<path> the original, where <path> is the same path search_files returns. Print only the "
        "result you need; output over 16 KB is cut. Limits: 512 MB memory, 20 s CPU, 30 s in total. Files you "
        "write in /work or /tmp are thrown away and cannot be run. It cannot start additional processes. "
        "If another script is running the result says busy; try again once. Never print full ID or "
        "account numbers."),
    "parameters": {"type": "object", "properties": {
        "code": {"type": "string", "description": "The complete Python 3 script to run."}},
        "required": ["code"]}}}

README = """Family box analysis workspace (read-only).
index.json       list of files: path, bytes, text
text/<path>.txt  plain text of each file
files/<path>     the original file
Write scratch files in /work or /tmp. Nothing is kept after the script ends. There is no network.
"""


# ---- settings -----------------------------------------------------------------------------------

def settings(cfg: Config) -> dict:
    """{"enabled", "people", "include_granted", "problem"}. Fails closed: any setting that is not
    exactly the right type switches the workbench off, and "problem" says which one."""
    try:
        data = tomllib.loads((cfg.home / "family.toml").read_text()).get("workbench", {})
    except (OSError, tomllib.TOMLDecodeError):
        data = {}
    if not isinstance(data, dict):
        data = {"enabled": data}
    problems = []
    raw = data.get("enabled", False)
    if raw is not True and raw is not False:
        problems.append("enabled must be true or false, without quotes")
    enabled = raw is True
    env = os.environ.get("FAMILYBOX_WORKBENCH", "").strip().lower()
    if env in ("on", "1", "yes", "true"):
        enabled = True
    elif env in ("off", "0", "no", "false"):
        enabled = False
    people = data.get("people")
    if people is not None and not (isinstance(people, list) and all(isinstance(p, str) for p in people)):
        problems.append('people must be a list of names in square brackets, like ["dana", "maya"]')
        people = []
    granted = data.get("include_granted", False)
    if granted is not True and granted is not False:
        problems.append("include_granted must be true or false, without quotes")
        granted = False
    if problems:
        enabled = False
    return {"enabled": enabled, "people": people, "include_granted": granted,
            "problem": "; ".join(problems) or None}


def status(cfg: Config, person: Person | None = None) -> dict:
    """{"offered": bool, "enabled": bool, "available": bool, "reason": plain English}"""
    s = settings(cfg)
    if s["problem"]:
        return {"offered": False, "enabled": False, "available": None,
                "reason": f"The [workbench] setting in family.toml is not valid, so the workbench is off: "
                          f"{s['problem']}."}
    if not s["enabled"]:
        return {"offered": False, "enabled": False, "available": None,
                "reason": "The box owner has not switched on the analysis workbench "
                          "([workbench] enabled = true in family.toml)."}
    if person is not None and s["people"] is not None and person.id not in s["people"]:
        return {"offered": False, "enabled": True, "available": None,
                "reason": f"The analysis workbench is not switched on for {person.display}."}
    ok, why = sandbox.available()
    return {"offered": ok, "enabled": True, "available": ok, "reason": why or "Ready."}


# ---- the asker's workspace ----------------------------------------------------------------------

def in_scope(person: Person, rel: str, include_granted: bool) -> bool:
    """The person's own folder and shared/ always; folders granted by also_reads only when switched on."""
    if not access.can_read(person, rel):
        return False
    parts = PurePosixPath(rel).parts
    own = (parts[:1] == ("shared",)) or access.owner_of(rel) == person.id
    return own or include_granted


def stage_workspace(cfg: Config, store: Store, person: Person, dest: Path,
                    include_granted: bool = False) -> list[dict]:
    """Copy into dest (files/, text/, index.json) this person's own files and the shared folder, plus
    folders granted to them only when include_granted is on. Returns the index.

    Skips links (a link inside someone's folder could point at another person's file), anything
    outside files/, and files over the size limits.
    """
    root = cfg.files.resolve()
    (dest / "files").mkdir(parents=True)
    (dest / "text").mkdir()
    index: list[dict] = []
    skipped: list[dict] = []
    total = 0
    for f in store.files():
        rel = f.relative_to(cfg.files).as_posix()
        if not in_scope(person, rel, include_granted):
            continue
        real = f.resolve()
        if real != root / rel or f.is_symlink() or not real.is_file():
            skipped.append({"path": rel, "why": "link"})
            continue
        size = real.stat().st_size
        if size > MAX_FILE_BYTES or total + size > MAX_TOTAL_BYTES or len(index) >= MAX_FILES:
            skipped.append({"path": rel, "why": "too big"})
            continue
        total += size
        out = dest / "files" / rel
        out.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(real, out)
        text = extract_text(real)[:MAX_TEXT_CHARS]
        tout = dest / "text" / (rel + ".txt")
        tout.parent.mkdir(parents=True, exist_ok=True)
        tout.write_text(text)
        index.append({"path": rel, "bytes": size, "text": f"/data/text/{rel}.txt", "file": f"/data/files/{rel}"})
    (dest / "index.json").write_text(json.dumps({"person": person.display, "files": index,
                                                 "skipped": skipped}, indent=1))
    (dest / "README.txt").write_text(README)
    return index


# ---- the tool provider --------------------------------------------------------------------------

class Workbench:
    """Tool provider for run_analysis. Offered only when switched on and the sandbox works here."""

    def __init__(self, box):
        self.box = box
        self.cfg: Config = box.cfg

    def status(self, person: Person | None = None) -> dict:
        return status(self.cfg, person)

    def tools(self, person: Person) -> list[dict]:
        return [TOOL] if self.status(person)["offered"] else []

    def run(self, person: Person, name: str, args: dict, ctx) -> str | None:
        if name != TOOL_NAME:
            return None
        code = args.get("code")
        if not isinstance(code, str) or not code.strip():
            return json.dumps({"error": "run_analysis needs a non-empty code string"})
        runs = ctx.data.setdefault("workbench_runs", 0)
        if runs >= MAX_RUNS_PER_QUESTION:
            return json.dumps({"error": f"only {MAX_RUNS_PER_QUESTION} scripts per question; answer with what "
                                        "you have"})
        ctx.data["workbench_runs"] = runs + 1
        st = self.status(person)
        if not st["offered"]:   # switched off since the tools were listed
            return json.dumps({"error": st["reason"]})
        res, files = run_for(self.cfg, self.box.store, person, code)
        if res.busy:   # nothing ran: does not use up one of this question's runs
            ctx.data["workbench_runs"] -= 1
            ctx.emit("workbench_busy")
            return json.dumps(model_view(res))
        # Not counted as read (the script may have opened none of them), but the gate applies the
        # rules of every owner whose files the script could see.
        for f in files:
            if f["path"] not in ctx.files_visible:
                ctx.files_visible.append(f["path"])
        record(self.cfg, person, ctx, code, res, len(files))
        return json.dumps(model_view(res))


def scratch_dir(cfg: Config) -> Path:
    """A private 0700 folder for staging copies: in RAM ($XDG_RUNTIME_DIR, a tmpfs on Linux) when it is
    there and ours, otherwise under the box's runtime folder."""
    xdg = os.environ.get("XDG_RUNTIME_DIR")
    base = None
    if xdg and os.path.isabs(xdg):
        try:
            st = os.stat(xdg)
            if os.path.isdir(xdg) and st.st_uid == os.getuid() and os.access(xdg, os.W_OK):
                base = Path(xdg) / "familybox-workbench"
        except OSError:
            base = None
    if base is None:
        base = cfg.runtime / "workbench" / "tmp"
    base.mkdir(parents=True, exist_ok=True, mode=0o700)
    os.chmod(base, 0o700)
    return base


def clean_leftovers(cfg: Config, max_age_s: float = LEFTOVER_AGE_S) -> int:
    """Remove staging folders a crash left behind. Only old ones, so a run in progress in another
    Box in the same process is never touched."""
    removed = 0
    now = time.time()
    for base in {scratch_dir(cfg), cfg.runtime / "workbench" / "tmp"}:
        if not base.is_dir():
            continue
        for d in base.iterdir():
            if d.name.startswith(("ws-", "run-")) and d.is_dir() and not d.is_symlink():
                try:
                    if now - d.lstat().st_mtime < max_age_s:
                        continue
                except OSError:
                    continue
                shutil.rmtree(d, ignore_errors=True)
                removed += 1
    return removed


def run_for(cfg: Config, store: Store, person: Person, code: str,
            limits: sandbox.Limits = LIMITS) -> tuple[sandbox.Result, list[dict]]:
    """Take the run slot (without waiting), stage the workspace, run. Busy: nothing is staged."""
    with sandbox.slot() as got:
        if not got:
            return sandbox.Result(ok=False, error=sandbox.BUSY, busy=True), []
        scratch = scratch_dir(cfg)
        with tempfile.TemporaryDirectory(prefix="ws-", dir=scratch) as d:
            files = stage_workspace(cfg, store, person, Path(d) / "data",
                                    include_granted=settings(cfg)["include_granted"])
            res = sandbox.run(code, data_dir=Path(d) / "data", scratch=scratch, limits=limits, slot_held=True)
    return res, files


def model_view(res: sandbox.Result) -> dict:
    if res.busy:
        return {"error": res.error, "busy": True}
    if not res.ok:
        return {"error": res.error or "the sandbox could not run the script"}
    out = {"exit_code": res.exit_code, "output": res.output, "seconds": res.seconds}
    if res.signal:
        out["killed_by_signal"] = res.signal
    if res.truncated:
        out["output_truncated"] = f"output was {res.output_bytes} bytes; only the first {LIMITS.output_bytes} are shown"
    if res.limits_hit:
        out["limits_hit"] = res.limits_hit
    if res.script_reported:
        out["output_mentions_limits"] = res.script_reported
    return out


def record(cfg: Config, person: Person, ctx, code: str, res: sandbox.Result, n_files: int) -> None:
    """Log the script for its owner: event, audit entry and the person's workbench log (all scrubbed)."""
    summary = {"exit_code": res.exit_code, "signal": res.signal, "ok": res.ok, "error": res.error,
               "limits_hit": res.limits_hit, "limits_reported_by_script": res.script_reported, "seconds": res.seconds, "cpu_s": res.cpu_s,
               "max_rss_kb": res.max_rss_kb, "output_bytes": res.output_bytes, "truncated": res.truncated,
               "files_in_workspace": n_files,
               "limits": {"memory_mb": LIMITS.memory_bytes // 2**20, "cpu_s": LIMITS.cpu_s,
                          "wall_s": LIMITS.wall_s, "max_procs": LIMITS.max_procs,
                          "output_kb": LIMITS.output_bytes // 1024}}
    ctx.emit("workbench", code=code[:EVENT_CHARS], output=res.output[:EVENT_CHARS], **summary)
    scrub = ctx._scrub_value
    ctx.data.setdefault("audit", {}).setdefault("workbench", []).append(
        scrub({"code": code[:EVENT_CHARS], "output": res.output[:EVENT_CHARS], **summary}))
    path = cfg.runtime / "workbench" / f"{person.id}.jsonl"
    path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    entry = scrub({"time": int(time.time()), "qid": ctx.qid, "source": ctx.source, "code": code[:LOG_CHARS],
                   "output": res.output[:LOG_CHARS], **summary})
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_APPEND, 0o600)
    with os.fdopen(fd, "a") as f:
        f.write(json.dumps(entry) + "\n")


def limits_text(e: dict) -> str:
    """Measured limits, and separately the ones only the script's own output mentions."""
    text = "limits hit: " + (", ".join(e.get("limits_hit") or []) or "none")
    said = e.get("limits_reported_by_script") or []
    if said:
        text += "; the script's output mentions: " + ", ".join(said) + " (not measured by the box)"
    return text


def read_log(cfg: Config, person_id: str, last: int = 20) -> list[dict]:
    path = cfg.runtime / "workbench" / f"{person_id}.jsonl"
    if not path.exists():
        return []
    rows = []
    for line in path.read_text().splitlines()[-last:]:
        try:
            rows.append(json.loads(line))
        except json.JSONDecodeError:
            continue
    return rows


# ---- hooks --------------------------------------------------------------------------------------

def register(box) -> None:
    try:
        clean_leftovers(box.cfg)
    except OSError:
        log.exception("could not remove old workbench staging folders")
    if settings(box.cfg)["enabled"]:
        sandbox.available()   # the one-time probe runs here, at start-up, not on a question's event loop
    box.tool_providers.append(Workbench(box))


def cli(sub) -> None:
    w = sub.add_parser("workbench", help="the confidential analysis workbench")
    ws = w.add_subparsers(dest="wb_action", required=True)
    s = ws.add_parser("status")
    s.add_argument("--as", dest="person", default=None)
    r = ws.add_parser("run")
    r.add_argument("--as", dest="person", required=True)
    r.add_argument("script", help="a .py file, or - to read the script from standard input")
    lg = ws.add_parser("log")
    lg.add_argument("--as", dest="person", required=True)
    lg.add_argument("--last", type=int, default=10)


def run_cli(args, cfg: Config) -> int | None:
    if args.cmd != "workbench":
        return None
    import sys
    person = cfg.person(args.person) if getattr(args, "person", None) else None
    if args.wb_action == "status":
        st = status(cfg, person)
        print("Ready: the analysis workbench is on." if st["offered"] else f"Not offered. {st['reason']}")
        return 0 if st["offered"] else 1
    if args.wb_action == "log":
        for e in read_log(cfg, person.id, args.last):
            when = time.strftime("%Y-%m-%d %H:%M", time.localtime(e.get("time", 0)))
            print(f"{when}  question {e.get('qid')}  exit {e.get('exit_code')}  {limits_text(e)}")
            print("  " + e.get("code", "").replace("\n", "\n  "))
        return 0
    # run: the owner trying a script by hand. Output prints here, on the box's own screen.
    code = sys.stdin.read() if args.script == "-" else Path(args.script).read_text()
    st = status(cfg, person)
    if not st["offered"]:
        print(st["reason"])
        return 1
    from familybox.box import Box, Question
    box = Box(cfg)
    ctx = Question(box, person, "(workbench run from the command line)", "cli")
    res, files = run_for(cfg, box.store, person, code)
    record(cfg, person, ctx, code, res, len(files))
    print(json.dumps(model_view(res), indent=1))
    return 0 if res.ok and res.exit_code == 0 else 1


def web_nav() -> list[tuple[str, str]]:
    return [("Analysis", "/workbench")]


def web_routes(ctx) -> list:
    from starlette.routing import Route

    esc = ctx.esc

    async def page(request, sess):
        st = status(ctx.cfg, sess.person)
        rows = []
        for e in reversed(read_log(ctx.cfg, sess.person.id, 20)):
            when = time.strftime("%Y-%m-%d %H:%M", time.localtime(e.get("time", 0)))
            rows.append(f'<div class="card"><div><strong>{esc(when)}</strong> '
                        f'<span class="muted">{esc(limits_text(e))}, exit {esc(e.get("exit_code"))}</span></div>'
                        f'<pre>{esc(e.get("code", ""))}</pre>'
                        f'<div class="muted">What the script printed (only the model saw this):</div>'
                        f'<pre>{esc(e.get("output", ""))}</pre></div>')
        state = ("On. Assistants can ask the box to run small calculations over your files."
                 if st["offered"] else f"Off. {st['reason']}")
        body = (f'<h1>Analysis</h1><p>{esc(state)}</p>'
                '<p class="muted">When a question needs math across your files, the private model can write a '
                'small Python script. The box runs it in a sealed sandbox with no internet and only copies of your own '
                'files and the shared folder (plus folders the owner granted you, if the owner switched that on), '
                'and the answer still goes through the same privacy check. Every script is listed here. '
                'Private numbers are replaced with [protected].</p>'
                + ("".join(rows) or '<p class="muted">No scripts have run for you yet.</p>'))
        return ctx.page(sess, "Analysis", body, "/workbench")

    return [Route("/workbench", ctx.need_signin(page))]
