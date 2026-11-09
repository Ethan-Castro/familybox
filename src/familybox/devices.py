"""Approver devices: small gadgets (like the Arduino UNO Q button) that can approve or deny held items.

A device belongs to one person and has one scope, "approve". With its token it can:
  - list that person's items waiting for approval (who asked, which assistant, what kind of detail), and
  - approve or deny one of them by id.
It can never see a held value, the question text or a file path, ask questions, or open the box's web page.
Approved values are shown later only on the owner's own signed-in screen (the Devices page).

What is stored in <runtime>/devices/ (folder 0700, files 0600):
  devices.json     device id -> person, name, scope, SHA-256 of the token, created, last seen
  decisions.json   what each device approved or denied, and whether the owner has looked at the value

Tokens look like fbd_<8 hex id>_<43 random characters>. Only their SHA-256 is kept, so a copy of the
box's files does not let anyone act as a device. Tokens are 256-bit random, so a plain hash is enough.
"""

from __future__ import annotations

import contextlib
import fcntl
import hashlib
import hmac
import json
import os
import re
import secrets
import time
from pathlib import Path

from .approvals import Approvals
from .config import Config

SCOPE_APPROVE = "approve"
TOKEN_RE = re.compile(r"^fbd_([0-9a-f]{8})_([A-Za-z0-9_-]{43})$")
ITEM_ID_RE = re.compile(r"^[A-Za-z0-9_-]{1,64}$")
NAME_MAX = 40
LAST_SEEN_EVERY_S = 60          # write last_seen at most once a minute, not on every poll
REVEAL_WINDOW_S = 24 * 60 * 60  # a button-approved value can be shown on the owner's screen for a day
MAX_ITEMS = 20

ASSISTANTS = (("chatgpt", "ChatGPT"), ("openai", "ChatGPT"), ("claude", "Claude"), ("codex", "Codex"),
              ("cursor", "Cursor"), ("gemini", "Gemini"), ("copilot", "Copilot"))


class DeviceError(ValueError):
    pass


def _token_hash(token: str) -> str:
    return hashlib.sha256(token.encode()).hexdigest()


def _write_private(path: Path, data: bytes) -> None:
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


def clean_name(name: str) -> str:
    name = re.sub(r"[^\w .'-]", "", name or "", flags=re.UNICODE).strip()
    return name[:NAME_MAX] or "Approve button"


def assistant_name(source: str) -> str | None:
    """Which assistant asked, from the question's source. None when the source does not say."""
    s = (source or "").lower()
    for needle, name in ASSISTANTS:
        if needle in s:
            return name
    return None


def what_label(kind: str, label: str) -> str:
    """How the held detail is named on a display other people in the room can see.

    Health details are never named (not "diagnosis" or "medication"), only "a health detail"."""
    if kind == "ssn":
        return "Social Security number"
    if kind == "id" and label:
        return label.lower()
    if kind == "health":
        return "health detail"
    return "private detail"


def describe(cfg: Config, item: dict) -> str:
    """'Maya's ChatGPT wants Dana's passport number'."""
    def disp(pid: str) -> str:
        return cfg.people[pid].display if pid in cfg.people else str(pid)
    asker = disp(item.get("asker", ""))
    owner = disp(item.get("owner", ""))
    who = asker
    src = item.get("source", "")
    name = assistant_name(src)
    if name:
        who = f"{asker}'s {name}"
    elif src.startswith("mcp"):
        who = f"{asker}'s assistant"
    return f"{who} wants {owner}'s {what_label(item.get('kind', ''), item.get('label', ''))}"


class Devices:
    def __init__(self, cfg: Config):
        self.cfg = cfg
        self.dir = cfg.runtime / "devices"
        self.dir.mkdir(parents=True, exist_ok=True, mode=0o700)
        os.chmod(self.dir, 0o700)

    # ---- storage

    @contextlib.contextmanager
    def _lock(self):
        fd = os.open(self.dir / ".lock", os.O_WRONLY | os.O_CREAT, 0o600)
        try:
            fcntl.flock(fd, fcntl.LOCK_EX)
            yield
        finally:
            fcntl.flock(fd, fcntl.LOCK_UN)
            os.close(fd)

    def _load(self, name: str, default):
        p = self.dir / name
        if not p.exists():
            return default
        try:
            return json.loads(p.read_text())
        except ValueError:
            return default

    def _save(self, name: str, data) -> None:
        _write_private(self.dir / name, json.dumps(data, indent=1).encode())

    # ---- devices

    def add(self, person_id: str, name: str = "") -> tuple[str, str]:
        """Make a device for person_id. Returns (device id, token). The token is shown once, never stored."""
        self.cfg.person(person_id)   # KeyError for unknown people
        with self._lock():
            data = self._load("devices.json", {})
            dev_id = secrets.token_hex(4)
            while dev_id in data:
                dev_id = secrets.token_hex(4)
            token = f"fbd_{dev_id}_{secrets.token_urlsafe(32)}"
            assert TOKEN_RE.match(token)
            data[dev_id] = {"person": person_id, "name": clean_name(name), "scope": SCOPE_APPROVE,
                            "token_sha256": _token_hash(token), "created": int(time.time()), "last_seen": None}
            self._save("devices.json", data)
        return dev_id, token

    def list(self, person_id: str) -> list[dict]:
        return [{"id": k, "name": v["name"], "scope": v["scope"], "created": v["created"],
                 "last_seen": v.get("last_seen")}
                for k, v in sorted(self._load("devices.json", {}).items(), key=lambda kv: kv[1]["created"])
                if v["person"] == person_id]

    def remove(self, person_id: str, dev_id: str) -> bool:
        with self._lock():
            data = self._load("devices.json", {})
            if dev_id not in data or data[dev_id]["person"] != person_id:
                return False
            del data[dev_id]
            self._save("devices.json", data)
        return True

    def check_token(self, token: str, now: float | None = None) -> dict | None:
        """The device for this token, or None. Constant-time hash compare; unknown people are refused."""
        m = TOKEN_RE.match(token or "")
        if not m:
            return None
        dev_id = m.group(1)
        dev = self._load("devices.json", {}).get(dev_id)
        if not dev or not hmac.compare_digest(dev.get("token_sha256", ""), _token_hash(token)):
            return None
        if dev.get("scope") != SCOPE_APPROVE or dev.get("person") not in self.cfg.people:
            return None
        now = time.time() if now is None else now
        if not dev.get("last_seen") or now - dev["last_seen"] >= LAST_SEEN_EVERY_S:
            with self._lock():
                data = self._load("devices.json", {})
                if dev_id in data:
                    data[dev_id]["last_seen"] = int(now)
                    self._save("devices.json", data)
        return {"id": dev_id, "person": dev["person"], "name": dev["name"], "scope": dev["scope"]}

    # ---- what a device may see and do

    def pending_for(self, device: dict) -> list[dict]:
        """Waiting items for the device's person, oldest first. No values, questions or paths."""
        raw = Approvals(self.cfg)._load()
        out = []
        for item_id, it in raw.items():
            if it.get("owner") != device["person"] or it.get("status") != "waiting":
                continue
            out.append({"id": item_id, "text": describe(self.cfg, it),
                        "asker": self.cfg.people[it["asker"]].display if it.get("asker") in self.cfg.people
                        else str(it.get("asker", "")),
                        "assistant": assistant_name(it.get("source", "")),
                        "what": what_label(it.get("kind", ""), it.get("label", "")),
                        "created": int(it.get("created", 0))})
        out.sort(key=lambda x: (x["created"], x["id"]))
        return out[:MAX_ITEMS]

    def decide(self, device: dict, item_id: str, approve: bool) -> dict:
        """Approve or deny one waiting item. Raises KeyError when it is not waiting for this device's person.
        Returns only the id and new status, never the value."""
        if not ITEM_ID_RE.match(item_id or ""):
            raise KeyError("bad id")
        with self._lock():
            appr = Approvals(self.cfg)
            it = appr._load().get(item_id)
            if not it or it.get("owner") != device["person"] or it.get("status") != "waiting":
                raise KeyError("not waiting for this person")
            appr.decide(device["person"], item_id, approve)   # the returned value is dropped here
            decisions = self._load("decisions.json", [])
            decisions.append({"item": item_id, "device": device["id"], "person": device["person"],
                              "approved": bool(approve), "time": int(time.time()), "revealed": False})
            self._save("decisions.json", decisions[-200:])
        self._audit(device, item_id, approve)
        return {"id": item_id, "status": "approved" if approve else "denied"}

    def _audit(self, device: dict, item_id: str, approve: bool) -> None:
        path = self.cfg.runtime / "audit" / f"{device['person']}.jsonl"
        path.parent.mkdir(parents=True, exist_ok=True)
        with path.open("a") as f:
            f.write(json.dumps({"time": int(time.time()), "event": "device_decision", "device": device["id"],
                                "item": item_id, "approved": bool(approve)}) + "\n")

    # ---- the owner's own screen

    def recent_decisions(self, person_id: str, now: float | None = None) -> list[dict]:
        """Button decisions for this person, newest first, with whether the value can still be shown."""
        now = time.time() if now is None else now
        raw = Approvals(self.cfg)._load()
        names = {d["id"]: d["name"] for d in self.list(person_id)}
        out = []
        for d in reversed(self._load("decisions.json", [])):
            if d.get("person") != person_id:
                continue
            it = raw.get(d["item"]) or {}
            showable = (d["approved"] and not d.get("revealed") and it.get("status") == "approved"
                        and it.get("owner") == person_id and now - d["time"] < REVEAL_WINDOW_S)
            out.append({"item": d["item"], "device": names.get(d["device"], "a removed device"),
                        "approved": d["approved"], "time": d["time"], "showable": showable,
                        "text": describe(self.cfg, it) if it else "an item that is gone"})
        return out[:20]

    def reveal(self, person_id: str, item_id: str, now: float | None = None) -> dict:
        """Show a button-approved value once, on the owner's own signed-in screen. KeyError otherwise."""
        now = time.time() if now is None else now
        with self._lock():
            decisions = self._load("decisions.json", [])
            it = Approvals(self.cfg)._load().get(item_id)
            for d in reversed(decisions):
                if d.get("item") == item_id and d.get("person") == person_id:
                    break
            else:
                raise KeyError("no button decision for this item")
            if (not d["approved"] or d.get("revealed") or not it or it.get("owner") != person_id
                    or it.get("status") != "approved" or now - d["time"] >= REVEAL_WINDOW_S):
                raise KeyError("not showable")
            d["revealed"] = True
            self._save("decisions.json", decisions)
        return {"label": it["label"], "value": it["value"]}
