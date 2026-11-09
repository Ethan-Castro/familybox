"""Tamper-evident audit logs: every entry is chained to the one before it.

Each person's log is <runtime>/audit/<person>.jsonl, one JSON object per line. Every entry written
through append() carries three extra fields:

  seq         0, 1, 2, ... in the order entries were written
  prev_hash   entry_hash of the previous entry (the first entry uses the person's genesis hash)
  entry_hash  sha256 over the canonical JSON of the entry without entry_hash, with a version prefix

Canonical JSON is json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False,
allow_nan=False) encoded as UTF-8, so the hash depends only on the values, not on how the line was
formatted on disk. Editing any field, deleting or reordering lines, or swapping in another person's
log breaks the chain. Cutting entries off the end cannot be seen from the log alone; that is what the
head file, local checkpoints and the NEAR anchor are for (see docs/ANCHOR.md).

Logs written before chaining existed are kept as they are. The first chained entry in such a file is a
"ledger_start" entry that records how many old lines there were and the sha256 of their exact bytes, so
those lines cannot change afterwards either.

Writers take an exclusive lock on <person>.jsonl.lock, so the CLI, the web page and the MCP servers can
append to the same log at the same time without forking the chain. verify() takes the same lock shared
while it reads the log and the head file, so it never sees one without the other.

A write cut off by a power cut leaves a piece of a line at the end of the file. The next append seals it
with a ledger_resume entry marked reason "torn_write"; verify() lists that as a warning, not a failure,
because the piece's exact bytes are pinned by the seal. Anything else unchained after a chained entry (for
example an entry with its chain fields stripped) is still a failure.
"""

from __future__ import annotations

import contextlib
import hashlib
import json
import os
import time
from dataclasses import dataclass, field
from pathlib import Path

try:  # the box runs on Linux (the Pi) and macOS; both have fcntl
    import fcntl
except ImportError:  # pragma: no cover - Windows: no cross-process lock
    fcntl = None

VERSION = "familybox-ledger-v1"
HASH_FIELDS = ("seq", "prev_hash", "entry_hash")


class LedgerError(Exception):
    pass


def canonical(obj) -> bytes:
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False,
                      allow_nan=False).encode("utf-8")


def genesis_hash(person_id: str) -> str:
    """The prev_hash of a person's first entry. Binds the chain to that person's log."""
    return hashlib.sha256(f"{VERSION}|genesis|{person_id}".encode()).hexdigest()


def entry_hash(entry: dict) -> str:
    body = {k: v for k, v in entry.items() if k != "entry_hash"}
    return hashlib.sha256(VERSION.encode() + b"\n" + canonical(body)).hexdigest()


def log_path(runtime: Path, person_id: str) -> Path:
    return runtime / "audit" / f"{person_id}.jsonl"


def head_path(runtime: Path, person_id: str) -> Path:
    return runtime / "audit" / f"{person_id}.head.json"


def _safe_id(person_id: str) -> str:
    if not person_id or "/" in person_id or "\\" in person_id or person_id in (".", "..") or "\x00" in person_id:
        raise LedgerError(f"bad person id {person_id!r}")
    return person_id


@contextlib.contextmanager
def _locked(path: Path, *, shared: bool = False):
    """The per-person lock. Writers hold it exclusively; verify() holds it shared while it reads."""
    path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    lock = path.with_name(path.name + ".lock")
    fd = os.open(lock, os.O_RDWR | os.O_CREAT, 0o600)
    try:
        if fcntl is not None:
            fcntl.flock(fd, fcntl.LOCK_SH if shared else fcntl.LOCK_EX)
        yield
    finally:
        if fcntl is not None:
            fcntl.flock(fd, fcntl.LOCK_UN)
        os.close(fd)


def _no_dupes(pairs):
    d = {}
    for k, v in pairs:
        if k in d:
            raise ValueError(f"duplicate key {k!r}")
        d[k] = v
    return d


def _parse(line: bytes):
    """A JSON object, or None if the line is not one (or has duplicate keys)."""
    try:
        obj = json.loads(line.decode("utf-8"), object_pairs_hook=_no_dupes)
    except (ValueError, UnicodeDecodeError):
        return None
    return obj if isinstance(obj, dict) else None


def _is_chained(obj) -> bool:
    return isinstance(obj, dict) and all(k in obj for k in HASH_FIELDS)


def _last_line(path: Path, chunk: int = 65536) -> bytes:
    """The last non-empty line of a file, read from the end."""
    with path.open("rb") as f:
        f.seek(0, os.SEEK_END)
        end = f.tell()
        buf = b""
        pos = end
        while pos > 0:
            step = min(chunk, pos)
            pos -= step
            f.seek(pos)
            buf = f.read(step) + buf
            stripped = buf.rstrip(b"\n")
            if b"\n" in stripped:
                return stripped.rsplit(b"\n", 1)[1]
        return buf.rstrip(b"\n")


def _write_head(runtime: Path, person_id: str, seq: int, h: str) -> None:
    path = head_path(runtime, person_id)
    tmp = path.with_name(f".{path.name}.{os.getpid()}.tmp")
    tmp.write_text(json.dumps({"count": seq + 1, "head": h, "updated": int(time.time())}))
    os.chmod(tmp, 0o600)
    os.replace(tmp, path)


def append(runtime: Path, person_id: str, entry: dict) -> dict:
    """Chain one entry onto the person's log and return it as written (with seq and hashes)."""
    _safe_id(person_id)
    if any(k in entry for k in HASH_FIELDS):
        raise LedgerError("entry already has chain fields")
    path = log_path(runtime, person_id)
    with _locked(path):
        prev, seq = genesis_hash(person_id), 0
        lines: list[dict] = []
        if path.exists() and path.stat().st_size > 0:
            last = _parse(_last_line(path))
            if _is_chained(last) and isinstance(last.get("seq"), int):
                prev, seq = last["entry_hash"], last["seq"] + 1
            else:
                # Old unchained lines, or a damaged last line. Chain from the last good entry and record
                # what came after it, so nothing already in the file can change unnoticed.
                prev, seq, start, tail = _resume_point(path, person_id)
                torn = seq > 0 and _is_torn_tail(tail)
                if tail and not tail.endswith(b"\n"):
                    tail += b"\n"   # the newline written below, before our first line
                mark = {"event": "ledger_start" if seq == 0 else "ledger_resume", "time": int(time.time()),
                        "unchained_lines": sum(1 for x in tail.splitlines() if x.strip()),
                        "unchained_from_byte": start,
                        "unchained_sha256": hashlib.sha256(tail).hexdigest()}
                if torn:
                    mark["reason"] = "torn_write"
                lines.append(mark)
        lines.append(dict(entry))
        out = b""
        for e in lines:
            e["seq"], e["prev_hash"] = seq, prev
            e["entry_hash"] = prev = entry_hash(e)
            out += json.dumps(e, allow_nan=False).encode() + b"\n"   # same look as before; the hash uses canonical()
            seq += 1
        fd = os.open(path, os.O_WRONLY | os.O_APPEND | os.O_CREAT, 0o600)
        try:
            # A file that does not end in a newline (torn write) gets one, so our line stays whole.
            if path.stat().st_size and _ends_without_newline(path):
                out = b"\n" + out
            os.write(fd, out)
            os.fsync(fd)
        finally:
            os.close(fd)
        _write_head(runtime, person_id, seq - 1, prev)
        return lines[-1]


def _is_torn_tail(tail: bytes) -> bool:
    """True when the bytes after the last chained entry look like one write that was cut off (for example
    by a power cut): a single piece of a line, at the very end of the file, with no newline, that is not
    a whole JSON object. An entry whose chain fields were stripped still parses, so it never counts."""
    if not tail or tail.endswith(b"\n"):
        return False
    parts = [x for x in tail.splitlines() if x.strip()]
    return len(parts) == 1 and _parse(parts[0].strip()) is None


def _ends_without_newline(path: Path) -> bool:
    with path.open("rb") as f:
        f.seek(-1, os.SEEK_END)
        return f.read(1) != b"\n"


def _resume_point(path: Path, person_id: str) -> tuple[str, int, int, bytes]:
    """(prev_hash, next_seq, byte offset, bytes after the last chained entry) for a file whose tail is unchained."""
    data = path.read_bytes()
    prev, seq, offset = genesis_hash(person_id), 0, 0
    pos = 0
    for raw in data.splitlines(keepends=True):
        obj = _parse(raw.strip())
        pos += len(raw)
        if _is_chained(obj) and isinstance(obj.get("seq"), int):
            prev, seq, offset = obj["entry_hash"], obj["seq"] + 1, pos
    return prev, seq, offset, data[offset:]


@dataclass
class Report:
    person: str
    ok: bool
    count: int = 0                 # chained entries
    head: str = ""                 # entry_hash of the last chained entry ("" if none)
    unchained_lines: int = 0       # old lines sealed by ledger_start
    problems: list[str] = field(default_factory=list)
    warnings: list[str] = field(default_factory=list)   # worth knowing, but the log still checks out
    checkpoints_checked: int = 0

    def to_dict(self) -> dict:
        return {"person": self.person, "ok": self.ok, "count": self.count, "head": self.head,
                "unchained_lines": self.unchained_lines, "problems": self.problems,
                "warnings": self.warnings, "checkpoints_checked": self.checkpoints_checked}


def _snapshot(runtime: Path, person_id: str) -> tuple[bytes | None, str | None]:
    """(log bytes, head file text) read together under the shared lock, so a writer in another process
    cannot slip an entry in between the two reads. None for a file that does not exist."""
    path, hp = log_path(runtime, person_id), head_path(runtime, person_id)

    def read():
        data = path.read_bytes() if path.exists() else None
        try:
            hd = hp.read_text()
        except FileNotFoundError:
            hd = None
        return data, hd

    if not path.parent.exists():
        return None, None          # nothing was ever written; do not create the folder just to look
    with _locked(path, shared=True):
        return read()


def verify(runtime: Path, person_id: str, *, checkpoints: list[dict] | None = None,
           check_head_file: bool = True) -> Report:
    """Walk the whole chain. checkpoints are {"count": n, "head": hash} pairs that must still be in it."""
    _safe_id(person_id)
    rep = Report(person_id, ok=True)
    data, head_text = _snapshot(runtime, person_id)
    if data is None:
        if head_text is not None or checkpoints:
            rep.problems.append("the log file is missing but the box has a record of it")
        rep.ok = not rep.problems
        return rep

    raw_lines = data.splitlines(keepends=True)
    prev, expect_seq = genesis_hash(person_id), 0
    heads: dict[int, str] = {}      # count -> head after that many entries
    unchained: list[tuple[int, bytes]] = []   # (line number, raw) since the last chained entry
    after_chained = 0               # byte offset just past the last chained entry
    pos = 0

    def bad(msg):
        if len(rep.problems) < 50:
            rep.problems.append(msg)

    for n, raw in enumerate(raw_lines, start=1):
        line_start = pos
        pos += len(raw)
        stripped = raw.strip()
        if not stripped:
            continue
        obj = _parse(stripped)
        if not _is_chained(obj):
            unchained.append((n, raw))
            continue
        # A chained entry: anything unchained right before it must be sealed by this entry.
        if unchained:
            sealed = obj.get("event") in ("ledger_start", "ledger_resume")
            blob = data[after_chained:line_start]
            if not sealed:
                bad(f"line {unchained[0][0]}: {len(unchained)} line(s) without chain fields in the middle of the log")
            elif (obj.get("unchained_sha256") != hashlib.sha256(blob).hexdigest()
                  or obj.get("unchained_from_byte") != after_chained
                  or obj.get("unchained_lines") != len(unchained)):
                bad(f"line {n}: the older lines before it were changed")
            elif (obj.get("event") == "ledger_resume" and obj.get("reason") == "torn_write"
                  and len(unchained) == 1 and _parse(unchained[0][1].strip()) is None):
                # One write that was cut off (a power cut or crash). Its bytes are pinned by the seal's
                # sha256, so they cannot change later; the entry it was meant to be is lost.
                rep.warnings.append(f"line {unchained[0][0]}: one entry was cut off while it was being "
                                    f"written (for example by a power cut). It is kept as it was and sealed "
                                    f"by the next entry, so it cannot be changed later.")
            elif obj.get("event") == "ledger_resume":
                # Lines without chain fields after a chained entry: a damaged write, or an entry whose
                # chain fields were stripped. Either way the log is no longer whole.
                bad(f"line {unchained[0][0]}: {len(unchained)} damaged line(s) after entry "
                    f"{expect_seq - 1} (a broken write, or an entry that was changed)")
            if expect_seq == 0:
                rep.unchained_lines += len(unchained)
            unchained = []
        elif obj.get("event") in ("ledger_start", "ledger_resume") and obj.get("unchained_lines"):
            bad(f"line {n}: older lines this entry sealed are gone")
        if obj.get("seq") != expect_seq:
            bad(f"line {n}: entry number {obj.get('seq')!r}, expected {expect_seq} (lines removed or reordered)")
        if obj.get("prev_hash") != prev:
            bad(f"line {n}: does not follow the entry before it (an entry was removed, reordered or changed)")
        try:
            h = entry_hash(obj)
        except ValueError:
            h = ""
        if obj.get("entry_hash") != h:
            bad(f"line {n}: its contents were changed after it was written")
        prev = obj.get("entry_hash", "")
        expect_seq = (obj["seq"] + 1) if isinstance(obj.get("seq"), int) else expect_seq + 1
        after_chained = pos
        rep.count += 1
        rep.head = prev
        heads[rep.count] = prev

    if unchained:
        if rep.count == 0:
            rep.unchained_lines = len(unchained)   # an old log that was never chained: nothing to check yet
        elif _is_torn_tail(data[after_chained:]):
            # A write that was cut off and not sealed yet. The head file was never moved past the last
            # whole entry, so a real cut-off write still matches it; an entry cut short on purpose does not.
            rep.warnings.append(f"line {unchained[0][0]}: the last entry was cut off while it was being "
                                f"written (for example by a power cut). The next entry will seal it.")
        else:
            bad(f"line {unchained[0][0]}: {len(unchained)} line(s) at the end without chain fields")

    if check_head_file:
        if head_text is not None:
            try:
                hd = json.loads(head_text)
                hc, hh = int(hd["count"]), str(hd["head"])
            except (ValueError, KeyError, TypeError):
                bad("the saved chain head is unreadable")
            else:
                if heads.get(hc) != hh:
                    bad(f"the box last recorded {hc} entries ending in {hh[:12]}, but the log does not match "
                        f"(entries were removed or rewritten)")
        elif rep.count:
            bad("the saved chain head is missing")

    for cp in checkpoints or []:
        try:
            c, h = int(cp["count"]), str(cp["head"])
        except (KeyError, TypeError, ValueError):
            bad("a checkpoint is unreadable")
            continue
        rep.checkpoints_checked += 1
        if heads.get(c) != h:
            where = cp.get("where", "checkpoint")
            bad(f"{where} says entry {c} ends in {h[:12]}, but the log does not match "
                f"(entries were removed or rewritten)")

    rep.ok = not rep.problems
    return rep


def head(runtime: Path, person_id: str) -> tuple[int, str]:
    """(count, head hash) from the head file, without walking the log. (0, "") if nothing was chained."""
    _safe_id(person_id)
    hp = head_path(runtime, person_id)
    try:
        d = json.loads(hp.read_text())
        return int(d["count"]), str(d["head"])
    except (OSError, ValueError, KeyError, TypeError):
        return 0, ""


# --- checkpoints: heads the box sent (or would send) to NEAR, kept so a later rewrite shows up -------

def checkpoints_path(runtime: Path, person_id: str) -> Path:
    return runtime / "ledger" / "checkpoints" / f"{_safe_id(person_id)}.jsonl"


def add_checkpoint(runtime: Path, person_id: str, count: int, head_hash: str, where: str, **extra) -> dict:
    cp = {"time": int(time.time()), "count": int(count), "head": head_hash, "where": where, **extra}
    path = checkpoints_path(runtime, person_id)
    path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    fd = os.open(path, os.O_WRONLY | os.O_APPEND | os.O_CREAT, 0o600)
    try:
        os.write(fd, (json.dumps(cp, sort_keys=True) + "\n").encode())
    finally:
        os.close(fd)
    return cp


def checkpoints(runtime: Path, person_id: str) -> list[dict]:
    path = checkpoints_path(runtime, person_id)
    if not path.exists():
        return []
    out = []
    for line in path.read_text().splitlines():
        if line.strip():
            try:
                out.append(json.loads(line))
            except ValueError:
                out.append({"where": "a damaged checkpoint line"})   # verify reports it as unreadable
    return out


def verify_all(runtime: Path, person_id: str) -> Report:
    """verify() with the saved checkpoints included: the check `familybox log verify` runs."""
    return verify(runtime, person_id, checkpoints=checkpoints(runtime, person_id))
