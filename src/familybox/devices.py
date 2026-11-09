"""Approver devices: small gadgets (like the Arduino UNO Q button) that can approve or deny held items.

A device belongs to one person and has one scope, "approve". With its token it can:
  - list that person's items waiting for approval (who asked, which assistant, what kind of detail), and
  - approve or deny one of them by id.
It can never see a held value, the question text or a file path, ask questions, or open the box's web page.
Approved values are shown later only on the owner's own signed-in screen (the Devices page).

The device never sees the box's own held-item ids either. Those are an unkeyed hash of path, kind and
value, so an SSN could be brute-forced back out of one. Each waiting item is given a random handle
instead, and only the handle leaves the box.

What is stored in <runtime>/devices/ (folder 0700, files 0600):
  devices.json     device id -> person, name, scope, SHA-256 of the token, created, last seen
  handles.json     random handle -> held item id (and when it was held), for items still waiting
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

from .approvals import Approvals, write_private as _write_private
from .config import Config

SCOPE_APPROVE = "approve"
TOKEN_RE = re.compile(r"^fbd_([0-9a-f]{8})_([A-Za-z0-9_-]{43})$")
ITEM_ID_RE = re.compile(r"^[A-Za-z0-9_-]{1,64}$")
NAME_MAX = 40
LAST_SEEN_EVERY_S = 60          # write last_seen at most once a minute, not on every poll
REVEAL_WINDOW_S = 24 * 60 * 60  # a button-approved value can be shown on the owner's screen for a day
MAX_ITEMS = 20
MAX_HANDLES = 500

ASSISTANTS = (("chatgpt", "ChatGPT"), ("openai", "ChatGPT"), ("claude", "Claude"), ("codex", "Codex"),
              ("cursor", "Cursor"), ("gemini", "Gemini"), ("copilot", "Copilot"))


class DeviceError(ValueError):
    pass


def _token_hash(token: str) -> str:
    return hashlib.sha256(token.encode()).hexdigest()


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
    if kind == "form":
        return "filled form"
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

    def _handles(self, raw: dict) -> tuple[dict, bool]:
        """handles.json with entries for items that are no longer waiting (or were held again) dropped."""
        handles = self._load("handles.json", {})
        keep = {h: e for h, e in handles.items()
                if isinstance(e, dict) and e.get("item") in raw and raw[e["item"]].get("status") == "waiting"
                and int(raw[e["item"]].get("created", 0)) == e.get("created")}
        if len(keep) > MAX_HANDLES:
            keep = dict(sorted(keep.items(), key=lambda kv: kv[1]["created"])[-MAX_HANDLES:])
        return keep, keep != handles

    def pending_for(self, device: dict) -> list[dict]:
        """Waiting items for the device's person, oldest first. No values, questions, paths or held ids:
        each item is named by a random handle that only this box can turn back into the item."""
        raw = Approvals(self.cfg)._load()
        waiting = [(item_id, it) for item_id, it in raw.items()
                   if it.get("owner") == device["person"] and it.get("status") == "waiting"]
        waiting.sort(key=lambda kv: (int(kv[1].get("created", 0)), kv[0]))
        waiting = waiting[:MAX_ITEMS]
        with self._lock():
            handles, changed = self._handles(raw)
            by_item = {(e["item"], e["created"]): h for h, e in handles.items()}
            out = []
            for item_id, it in waiting:
                created = int(it.get("created", 0))
                handle = by_item.get((item_id, created))
                if handle is None:
                    handle = secrets.token_urlsafe(12)
                    handles[handle] = {"item": item_id, "created": created, "person": device["person"]}
                    changed = True
                out.append({"id": handle, "text": describe(self.cfg, it),
                            "asker": self.cfg.people[it["asker"]].display if it.get("asker") in self.cfg.people
                            else str(it.get("asker", "")),
                            "assistant": assistant_name(it.get("source", "")),
                            "what": what_label(it.get("kind", ""), it.get("label", "")),
                            "created": created})
            if changed:
                self._save("handles.json", handles)
        return out

    def decide(self, device: dict, handle: str, approve: bool) -> dict:
        """Approve or deny one waiting item by its handle. Raises KeyError when it is not waiting for this
        device's person. Returns only the handle and new status, never the value."""
        if not ITEM_ID_RE.match(handle or ""):
            raise KeyError("bad id")
        with self._lock():
            entry = self._load("handles.json", {}).get(handle)
            if not isinstance(entry, dict) or entry.get("person") != device["person"]:
                raise KeyError("not waiting for this person")
            item_id = entry["item"]
            # One locked step in Approvals: still waiting, same hold, same owner. The value is dropped here.
            result = Approvals(self.cfg).decide_if_waiting(device["person"], item_id, approve,
                                                           created=entry["created"])
            handles = self._load("handles.json", {})
            handles.pop(handle, None)
            self._save("handles.json", handles)
            decisions = self._load("decisions.json", [])
            decisions.append({"item": item_id, "handle": handle, "decision": result["decision"],
                              "device": device["id"], "person": device["person"],
                              "approved": bool(approve), "time": int(time.time()), "revealed": False})
            self._save("decisions.json", decisions[-200:])
        self._audit(device, item_id, approve)
        return {"id": handle, "status": "approved" if approve else "denied"}

    def _audit(self, device: dict, item_id: str, approve: bool) -> None:
        from . import ledger   # the person's tamper-evident audit log (chained, locked, 0600)
        ledger.append(self.cfg.runtime, device["person"],
                      {"time": int(time.time()), "event": "device_decision", "device": device["id"],
                       "item": item_id, "approved": bool(approve)})

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
            out.append({"item": d.get("handle", ""), "device": names.get(d["device"], "a removed device"),
                        "approved": d["approved"], "time": d["time"],
                        "showable": bool(d.get("handle")) and self._showable(d, it, person_id, now),
                        "text": describe(self.cfg, it) if it else "an item that is gone"})
        return out[:20]

    @staticmethod
    def _showable(d: dict, it: dict, person_id: str, now: float) -> bool:
        """Approved by the button, not looked at yet, within a day, and the item still carries this very
        decision. If the detail was held again or decided somewhere else since, the stamp differs."""
        return bool(d.get("approved") and not d.get("revealed") and it
                    and it.get("owner") == person_id and it.get("status") == "approved"
                    and d.get("decision") and it.get("decision") == d.get("decision")
                    and now - d["time"] < REVEAL_WINDOW_S)

    def reveal(self, person_id: str, handle: str, now: float | None = None) -> dict:
        """Show a button-approved value once, on the owner's own signed-in screen. KeyError otherwise."""
        now = time.time() if now is None else now
        if not ITEM_ID_RE.match(handle or ""):
            raise KeyError("bad id")
        with self._lock():
            decisions = self._load("decisions.json", [])
            for d in reversed(decisions):
                if d.get("handle") == handle and d.get("person") == person_id:
                    break
            else:
                raise KeyError("no button decision for this item")
            it = Approvals(self.cfg)._load().get(d["item"])
            if not self._showable(d, it or {}, person_id, now):
                raise KeyError("not showable")
            d["revealed"] = True
            self._save("decisions.json", decisions)
        return {"label": it["label"], "value": it["value"]}
