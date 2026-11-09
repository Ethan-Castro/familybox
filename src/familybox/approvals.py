"""Held values wait here for their owner. Approving shows the full value on the owner's own screen
(the box's local page or CLI); it is never sent back to the assistant that asked.

approvals.json has more than one writer (the answer gate, the forms plugin, the web page and the CLI, maybe
in different processes), so every read-modify-write holds a shared lock, and the file is replaced
atomically with mode 0600.

Every decision is written to the owner's tamper-evident log (familybox.ledger): what was approved or
denied, for whom, and when. Never the value itself."""

from __future__ import annotations

import contextlib
import fcntl
import json
import os
import secrets
import time
from pathlib import Path

from . import ledger
from .config import Config
from .gate import Held


def write_private(path: Path, data: bytes) -> None:
    """Write a file only the box's user can read, atomically (temp file, fsync, rename)."""
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_name(f".{path.name}.{secrets.token_hex(6)}.tmp")
    fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    try:
        with os.fdopen(fd, "wb") as f:
            f.write(data)
            f.flush()
            os.fsync(f.fileno())
        os.replace(tmp, path)
    finally:
        with contextlib.suppress(FileNotFoundError):
            tmp.unlink()


def append_private(path: Path, line: str) -> None:
    """Append one line to a log only the box's user can read (also fixes the mode of an older log)."""
    path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_APPEND, 0o600)
    try:
        os.fchmod(fd, 0o600)
        os.write(fd, (line.rstrip("\n") + "\n").encode())
    finally:
        os.close(fd)


class Approvals:
    def __init__(self, cfg: Config):
        self.runtime: Path = cfg.runtime
        self.path: Path = cfg.runtime / "approvals.json"

    @contextlib.contextmanager
    def _locked(self):
        self.path.parent.mkdir(parents=True, exist_ok=True)
        fd = os.open(self.path.with_name(".approvals.lock"), os.O_WRONLY | os.O_CREAT, 0o600)
        try:
            fcntl.flock(fd, fcntl.LOCK_EX)
            yield
        finally:
            fcntl.flock(fd, fcntl.LOCK_UN)
            os.close(fd)

    def _load(self) -> dict:
        return json.loads(self.path.read_text()) if self.path.exists() else {}

    def _save(self, data: dict) -> None:
        write_private(self.path, json.dumps(data, indent=1).encode())

    def add(self, asker: str, question: str, held: list[Held]) -> list[str]:
        with self._locked():
            data = self._load()
            for h in held:
                data[h.id] = {"asker": asker, "question": question, "kind": h.kind, "label": h.label,
                              "owner": h.owner, "path": h.path, "value": h.value, "status": "waiting",
                              "created": int(time.time())}
            self._save(data)
        return [h.id for h in held]

    def pending(self, owner: str) -> list[dict]:
        return [{"id": k} | {f: v[f] for f in ("asker", "question", "kind", "label", "path", "status")}
                for k, v in self._load().items() if v["owner"] == owner and v["status"] == "waiting"]

    def decide(self, owner: str, item_id: str, approve: bool) -> dict:
        with self._locked():
            data = self._load()
            item = data.get(item_id)
            if not item or item["owner"] != owner:
                raise KeyError("no such item for this owner")
            item["status"] = "approved" if approve else "denied"
            item["decided"] = int(time.time())
            # Log the decision first: if the log cannot be written, the value is not released.
            ledger.append(self.runtime, owner, {"time": item["decided"], "event": item["status"],
                                                "item_id": item_id, "kind": item.get("kind"),
                                                "label": item["label"], "asker": item["asker"],
                                                "source": "approvals"})
            self._save(data)
        # The value is returned to the owner's own screen only.
        return {"id": item_id, "label": item["label"], "value": item["value"] if approve else None,
                "asker": item["asker"]}
