"""Held values wait here for their owner. Approving shows the full value on the owner's own screen
(the box's local page or CLI); it is never sent back to the assistant that asked.

Several processes write this file (the answer gate, the forms plugin, the MCP server, the web page, the
CLI, the Approve button API), so every read-modify-write holds one lock file (<runtime>/.approvals.lock)
and every write is atomic (temp file, fsync, rename). A reader never sees a half-written file and no
update is lost. The file holds full values, so it is kept 0600.

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
    """Write a file atomically with mode 0600 (temp file in the same folder, fsync, rename)."""
    path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
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
        self.lock_path: Path = cfg.runtime / ".approvals.lock"

    @contextlib.contextmanager
    def locked(self):
        self.lock_path.parent.mkdir(parents=True, exist_ok=True)
        fd = os.open(self.lock_path, os.O_WRONLY | os.O_CREAT, 0o600)
        try:
            fcntl.flock(fd, fcntl.LOCK_EX)
            yield
        finally:
            fcntl.flock(fd, fcntl.LOCK_UN)
            os.close(fd)

    _locked = locked   # older name, same lock

    def _load(self) -> dict:
        return json.loads(self.path.read_text()) if self.path.exists() else {}

    def _save(self, data: dict) -> None:
        write_private(self.path, json.dumps(data, indent=1).encode())

    def add(self, asker: str, question: str, held: list[Held], *, source: str = "") -> list[str]:
        with self.locked():
            data = self._load()
            for h in held:
                # Holding the same detail again starts a fresh request: any earlier decision (and its
                # "decision" stamp, which a one-time view on the Devices page is tied to) is dropped.
                data[h.id] = {"asker": asker, "question": question, "kind": h.kind, "label": h.label,
                              "owner": h.owner, "path": h.path, "value": h.value, "status": "waiting",
                              "created": int(time.time()), "source": source}
            self._save(data)
        return [h.id for h in held]

    def pending(self, owner: str) -> list[dict]:
        return [{"id": k} | {f: v[f] for f in ("asker", "question", "kind", "label", "path", "status")}
                for k, v in self._load().items() if v["owner"] == owner and v["status"] == "waiting"]

    def _decide_locked(self, data: dict, item_id: str, approve: bool, via: str = "approvals") -> dict:
        item = data[item_id]
        item["status"] = "approved" if approve else "denied"
        item["decided"] = int(time.time())
        item["decision"] = secrets.token_hex(8)   # tells this decision apart from any later one
        # Log the decision first: if the log cannot be written, the value is not released.
        ledger.append(self.runtime, item["owner"], {"time": item["decided"], "event": item["status"],
                                                    "item_id": item_id, "kind": item.get("kind"),
                                                    "label": item["label"], "asker": item["asker"],
                                                    "source": via})
        self._save(data)
        # The value is returned to the owner's own screen only.
        return {"id": item_id, "label": item["label"], "value": item["value"] if approve else None,
                "asker": item["asker"], "decision": item["decision"]}

    def decide(self, owner: str, item_id: str, approve: bool) -> dict:
        with self.locked():
            data = self._load()
            item = data.get(item_id)
            if not item or item["owner"] != owner:
                raise KeyError("no such item for this owner")
            return self._decide_locked(data, item_id, approve)

    def decide_if_waiting(self, owner: str, item_id: str, approve: bool, *, created: int | None = None,
                          via: str = "device") -> dict:
        """Decide an item only if it is still waiting for this owner (and, when given, was held at
        `created`). KeyError otherwise. One locked step, so a press can't race a new hold or a web decision."""
        with self.locked():
            data = self._load()
            item = data.get(item_id)
            if not item or item.get("owner") != owner or item.get("status") != "waiting":
                raise KeyError("not waiting for this person")
            if created is not None and int(item.get("created", 0)) != int(created):
                raise KeyError("held again since this was shown")
            return self._decide_locked(data, item_id, approve, via)
