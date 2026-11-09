"""A throwaway sandbox for short Python analysis scripts, built from unprivileged Linux namespaces.

No root, no sudo, no bubblewrap or firejail: only `unshare` (util-linux) and the system Python.
Each run gets brand new user, mount, network, PID, IPC and UTS namespaces. Inside, the launcher
(familybox/sandbox_launcher.py) builds a fresh root from an allowlist and pivots into it:

  /usr, /bin, /lib...   the host's system folders, read-only (so python3 and the stdlib work);
                        /usr/local and Debian's dist-packages are covered by empty folders
  /data                 read-only copies of the files the caller staged (here: the asker's files)
  /code/main.py         the script, read-only
  /work, /tmp           small empty tmpfs folders (nothing in them can be run as a program);
                        everything written there is thrown away
  /dev                  null, zero, full, random, urandom only
  /proc                 empty (the host's processes and their environments are not visible)

There is no network device except a downed loopback, so every connection fails. The script runs as
python3 -I with no capabilities, under memory, CPU, thread, file size and open file limits, plus a
wall clock. A seccomp filter lets it start threads but not additional processes, so the memory limit
holds for the whole script, and refuses namespace, mount, ptrace, keyring, bpf and io_uring calls.
(The script can still replace itself with a system program such as /usr/bin/sh. That program stays in
the same sandbox, under the same limits.) Output is capped. When the run ends the namespaces and all
their tmpfs memory are gone.

Only one script runs at a time. A second one asked for meanwhile gets a "busy" result straight away
instead of waiting.

On macOS, or a Linux box where unprivileged user namespaces are switched off, available() says why
and nothing runs.
"""

from __future__ import annotations

import json
import os
import platform
import shutil
import signal
import subprocess
import sys
import tempfile
import threading
import time
from collections.abc import Iterator
from contextlib import contextmanager
from dataclasses import asdict, dataclass, field
from pathlib import Path

LAUNCHER = Path(__file__).with_name("sandbox_launcher.py")
PYTHON_CANDIDATES = ("/usr/bin/python3", "/bin/python3")
SYSTEM_PREFIXES = ("/usr/", "/bin/", "/lib/", "/sbin/")
HIDDEN_PREFIXES = ("/usr/local/",)   # covered by an empty folder inside the sandbox
KNOWN_MACHINES = {"x86_64", "aarch64", "arm64", "riscv64", "armv7l", "armv6l", "i686", "i386"}
MAX_CODE_CHARS = 20_000
MAX_DRAIN_BYTES = 4 * 1024 * 1024   # stop the run if it prints more than this in total


@dataclass(frozen=True)
class Limits:
    memory_bytes: int = 512 * 1024 * 1024
    cpu_s: int = 20
    wall_s: int = 30
    max_procs: int = 16              # threads inside the sandbox (new processes are refused outright)
    output_bytes: int = 16 * 1024
    file_bytes: int = 16 * 1024 * 1024
    work_bytes: int = 32 * 1024 * 1024
    tmp_bytes: int = 16 * 1024 * 1024


@dataclass
class Result:
    ok: bool                          # the script ran (it may still have failed or hit a limit)
    exit_code: int | None = None
    signal: int | None = None
    output: str = ""
    output_bytes: int = 0             # total bytes the script printed, before the cap
    truncated: bool = False
    limits_hit: list[str] = field(default_factory=list)       # measured by the launcher, not the script
    script_reported: list[str] = field(default_factory=list)  # limits the script's own output mentions
    seconds: float = 0.0
    cpu_s: float | None = None
    max_rss_kb: int | None = None
    error: str = ""                   # set when the sandbox itself could not run
    busy: bool = False                # another script was running; nothing ran

    def to_dict(self) -> dict:
        return asdict(self)


def find_python() -> str | None:
    override = os.environ.get("FAMILYBOX_SANDBOX_PYTHON")
    for c in ([override] if override else []) + list(PYTHON_CANDIDATES):
        if c and os.path.isfile(c) and os.access(c, os.X_OK):
            real = os.path.realpath(c)
            if real.startswith(SYSTEM_PREFIXES) and not real.startswith(HIDDEN_PREFIXES):
                return c
    return None


def _command(python: str, stage: Path, status_fd: int) -> list[str]:
    return [shutil.which("unshare") or "unshare", "--user", "--map-root-user", "--mount", "--net", "--pid",
            "--ipc", "--uts", "--fork", "--kill-child",
            python, "-I", "-S", str(LAUNCHER), str(stage), str(status_fd)]


def _static_reason() -> str | None:
    if not sys.platform.startswith("linux"):
        return (f"The analysis sandbox needs Linux namespaces, and this computer is running {platform.system()}. "
                "It works on the family box itself (the Raspberry Pi).")
    if platform.machine() not in KNOWN_MACHINES:
        return f"The analysis sandbox does not know this processor type ({platform.machine()})."
    if not shutil.which("unshare"):
        return "The analysis sandbox needs the unshare command (util-linux), and it is not installed."
    if not find_python():
        return "The analysis sandbox needs a system Python 3 in /usr/bin, and none was found."
    return None


_probe: tuple[bool, str] | None = None
_probe_lock = threading.Lock()


def available(refresh: bool = False) -> tuple[bool, str]:
    """(True, "") when sandboxed runs work here, else (False, a plain-English reason). Cached."""
    global _probe
    with _probe_lock:
        if _probe is not None and not refresh:
            return _probe
        reason = _static_reason()
        if reason:
            _probe = (False, reason)
            return _probe
        with tempfile.TemporaryDirectory(prefix="fbx-probe-") as d:
            r = run("print('sandbox-ok')", data_dir=None, scratch=Path(d),
                    limits=Limits(wall_s=10), slot_held=True, _probing=True)
        if r.ok and r.exit_code == 0 and r.output.strip() == "sandbox-ok":
            _probe = (True, "")
        else:
            why = r.error or r.output.strip()[-300:] or f"exit {r.exit_code}"
            _probe = (False, f"The analysis sandbox could not start on this box: {why}")
        return _probe


_slots = threading.BoundedSemaphore(int(os.environ.get("FAMILYBOX_SANDBOX_SLOTS", "1")))
BUSY = "another analysis is still running; try again in a moment"


@contextmanager
def slot() -> Iterator[bool]:
    """Take a run slot without waiting. Yields False when every slot is in use."""
    got = _slots.acquire(blocking=False)
    try:
        yield got
    finally:
        if got:
            _slots.release()


def _reader(stream, cap: int, sink: dict, stop) -> None:
    kept = bytearray()
    total = 0
    while True:
        chunk = stream.read1(65536) if hasattr(stream, "read1") else stream.read(65536)
        if not chunk:
            break
        total += len(chunk)
        if len(kept) <= cap:
            kept += chunk[: cap + 1 - len(kept)]
        if total > MAX_DRAIN_BYTES:
            stop()
            break
    sink["kept"], sink["total"] = bytes(kept), total


def run(code: str, *, data_dir: Path | None, scratch: Path, limits: Limits = Limits(),
        slot_held: bool = False, _probing: bool = False) -> Result:
    """Run code with python3 -I in a fresh sandbox. data_dir (copied in, read-only) appears as /data.

    scratch is a private folder on the host for the short-lived staging copy; it is removed after.
    slot_held: the caller already holds a slot from slot(). Otherwise one is taken here, without
    waiting, and a busy Result comes back when none is free.
    """
    if not _probing:
        ok, why = available()
        if not ok:
            return Result(ok=False, error=why)
    if len(code) > MAX_CODE_CHARS:
        return Result(ok=False, error=f"the script is longer than {MAX_CODE_CHARS} characters")
    if "\x00" in code:
        return Result(ok=False, error="the script contains a NUL character")
    python = find_python()
    if not python:
        return Result(ok=False, error="no system python3")
    if slot_held:
        return _run_in_stage(code, data_dir, scratch, python, limits)
    with slot() as got:
        if not got:
            return Result(ok=False, error=BUSY, busy=True)
        return _run_in_stage(code, data_dir, scratch, python, limits)


def _run_in_stage(code: str, data_dir: Path | None, scratch: Path, python: str, limits: Limits) -> Result:
    stage = Path(tempfile.mkdtemp(prefix="run-", dir=scratch))
    try:
        return _run_staged(code, data_dir, stage, python, limits)
    finally:
        shutil.rmtree(stage, ignore_errors=True)


def _dir_size(path: Path | None) -> tuple[int, int]:
    if not path or not path.exists():
        return 0, 0
    total = n = 0
    for root, dirs, files in os.walk(path):
        n += len(dirs) + len(files)
        for f in files:
            total += os.lstat(os.path.join(root, f)).st_size
    return total, n


def _run_staged(code: str, data_dir: Path | None, stage: Path, python: str, limits: Limits) -> Result:
    os.chmod(stage, 0o700)
    (stage / "root").mkdir()
    data = stage / "data"
    data.mkdir()
    (stage / "main.py").write_text(code)
    size, inodes = _dir_size(data_dir)
    spec = {"python": python, "memory_bytes": limits.memory_bytes, "cpu_s": limits.cpu_s,
            "wall_s": limits.wall_s, "max_procs": limits.max_procs, "file_bytes": limits.file_bytes,
            "work_bytes": limits.work_bytes, "tmp_bytes": limits.tmp_bytes,
            "data_bytes": size + 1024 * 1024 + inodes * 4096, "data_inodes": inodes + 64,
            "data_src": str(data_dir) if data_dir else str(data)}
    (stage / "spec.json").write_text(json.dumps(spec))

    status_r, status_w = os.pipe()
    started = time.monotonic()
    try:
        proc = subprocess.Popen(_command(python, stage, status_w), stdin=subprocess.DEVNULL,
                                stdout=subprocess.PIPE, stderr=subprocess.STDOUT, pass_fds=(status_w,),
                                env={"PATH": "/usr/bin:/bin", "LANG": "C.UTF-8"}, cwd="/",
                                start_new_session=True)
    except OSError as e:
        os.close(status_r)
        os.close(status_w)
        return Result(ok=False, error=f"could not start the sandbox: {e}")
    os.close(status_w)

    flooded = threading.Event()

    def kill_all() -> None:
        try:
            os.killpg(proc.pid, signal.SIGKILL)
        except OSError:
            pass

    def stop_flood() -> None:
        flooded.set()
        kill_all()

    sink: dict = {}
    t = threading.Thread(target=_reader, args=(proc.stdout, limits.output_bytes, sink, stop_flood), daemon=True)
    t.start()
    backstop = False
    try:
        proc.wait(timeout=limits.wall_s + 15)   # namespace setup time plus the launcher's own clock
    except subprocess.TimeoutExpired:
        backstop = True
        kill_all()
        proc.wait()
    t.join(timeout=5)
    with os.fdopen(status_r, "rb") as f:
        raw = f.read(65536).decode(errors="replace").strip().splitlines()
    try:
        status = json.loads(raw[-1]) if raw else {}
    except json.JSONDecodeError:
        status = {}

    kept, total = sink.get("kept", b""), sink.get("total", 0)
    truncated = len(kept) > limits.output_bytes
    out = kept[: limits.output_bytes].decode("utf-8", errors="replace")
    res = Result(ok=bool(status.get("ok")), exit_code=status.get("exit_code"), signal=status.get("signal"),
                 output=out, output_bytes=total, truncated=truncated,
                 seconds=round(time.monotonic() - started, 3), cpu_s=status.get("cpu_s"),
                 max_rss_kb=status.get("max_rss_kb"))
    if not status:
        res.ok = False
        res.error = "the sandbox stopped before reporting" + (" (output flood)" if flooded.is_set() else "")
        if backstop:
            res.error = "the sandbox did not finish in time and was stopped"
    elif not status.get("ok"):
        res.error = f"sandbox setup failed: {status.get('error', 'unknown')}"
    res.limits_hit = limits_hit(res, timed_out=bool(status.get("timed_out")) or backstop,
                                flooded=flooded.is_set(), limits=limits)
    res.script_reported = script_reported(res.output, res.limits_hit)
    return res


def limits_hit(res: Result, *, timed_out: bool, flooded: bool, limits: Limits) -> list[str]:
    """Limits the launcher measured. Nothing here comes from the script's own output, so a script
    cannot fake an entry (sending itself SIGXCPU without using the CPU does not count either)."""
    hit = []
    if timed_out:
        hit.append("time")
    used_cpu = res.cpu_s is not None and res.cpu_s >= limits.cpu_s - 0.5
    if res.signal in (signal.SIGXCPU, signal.SIGKILL) and used_cpu and not timed_out and not flooded:
        hit.append("cpu")
    if res.max_rss_kb is not None and res.max_rss_kb * 1024 >= 0.9 * limits.memory_bytes:
        hit.append("memory")
    if res.truncated or flooded:
        hit.append("output")
    return hit


SCRIPT_SIGNS = (("memory", ("MemoryError", "Cannot allocate memory")),
                ("processes", ("Resource temporarily unavailable", "can't start new thread")),
                ("disk", ("File too large", "No space left on device")))


def script_reported(output: str, measured: list[str]) -> list[str]:
    """Limits the script's own output mentions (a real error message, or the script just printing the
    words). Logged separately and labelled as reported by the script, never as measured."""
    return [name for name, signs in SCRIPT_SIGNS if name not in measured and any(s in output for s in signs)]
