"""The family itself: first-time setup, PINs, and adding or changing people. State only, no web pages.

What is stored:
  family.toml             people, what each may also read, words never to share (config.save)
  <runtime>/web/pins.json       scrypt hash and salt per person, never the PIN
  <runtime>/web/pin_failures.json  times of wrong PINs, per person (5 per 10 minutes locks that name)

Every change goes through config.save and then config.reload, so the running box sees it at once.
Health folders can never be granted to someone else, the same rule access.can_read keeps.
"""

from __future__ import annotations

import hashlib
import hmac
import re
import secrets
import time
import unicodedata
from dataclasses import replace

from . import config
from .config import Config, Person
from .web import LOCKOUT_MAX, LOCKOUT_WINDOW_S, PERSON_FOLDERS, WebState

SETUP_WINDOW_S = 15 * 60
STARTED = time.time()          # when this process loaded the box; the setup window counts from here

PIN_MIN, PIN_MAX = 6, 12
SCRYPT = {"n": 2 ** 14, "r": 8, "p": 1}
PINS = "pins.json"
PIN_FAILS = "pin_failures.json"

GRANTABLE = tuple(f for f in PERSON_FOLDERS if f != "health")   # health stays with its owner
NAME_MAX = 40
WORD_MAX = 100
WORDS_MAX = 50


class HouseholdError(ValueError):
    """A change that was refused. The message is plain words, safe to show on the page."""


# --- setup window ------------------------------------------------------------------------------

def setup_open(cfg: Config, now: float | None = None) -> bool:
    """Setup is allowed only while the box has no family and the box started less than 15 minutes ago."""
    now = time.time() if now is None else now
    return not cfg.people and now - STARTED < SETUP_WINDOW_S


# --- PINs --------------------------------------------------------------------------------------

def pin_problem(pin: str) -> str | None:
    """None when the PIN is acceptable, otherwise a plain reason."""
    if not isinstance(pin, str) or not pin.isascii() or not pin.isdigit():
        return "A PIN is numbers only."
    if not PIN_MIN <= len(pin) <= PIN_MAX:
        return f"A PIN is {PIN_MIN} to {PIN_MAX} numbers long."
    if len(set(pin)) == 1:
        return "Pick a PIN that isn't the same number over and over."
    return None


def _hash(pin: str, salt: bytes, params: dict) -> str:
    return hashlib.scrypt(pin.encode(), salt=salt, n=params["n"], r=params["r"], p=params["p"],
                          maxmem=64 * 1024 * 1024, dklen=32).hex()


def set_pin(state: WebState, person_id: str, pin: str) -> None:
    state.cfg.person(person_id)
    why = pin_problem(pin)
    if why:
        raise HouseholdError(why)
    salt = secrets.token_bytes(16)
    entry = {"salt": salt.hex(), "hash": _hash(pin, salt, SCRYPT), **SCRYPT}
    with state._lock():
        pins = state._load(PINS, {})
        pins[person_id] = entry
        state._save(PINS, pins)
        fails = state._load(PIN_FAILS, {})
        if fails.pop(person_id, None) is not None:
            state._save(PIN_FAILS, fails)


def has_pin(state: WebState, person_id: str) -> bool:
    return person_id in state._load(PINS, {})


def pin_locked(state: WebState, person_id: str, now: float | None = None) -> bool:
    now = time.time() if now is None else now
    fails = state._load(PIN_FAILS, {}).get(person_id, [])
    return len([t for t in fails if now - t < LOCKOUT_WINDOW_S]) >= LOCKOUT_MAX


def check_pin(state: WebState, person_id: str, pin: str) -> tuple[bool, str | None]:
    """(True, None) when the PIN is right. Otherwise (False, "wrong" or "locked"). Wrong tries count
    against that one name only, so one person's mistakes never lock anyone else out."""
    now = time.time()
    with state._lock():
        pins = state._load(PINS, {})
        all_fails = state._load(PIN_FAILS, {})
        known = person_id in state.cfg.people and person_id in pins
        key = person_id if known else "?"
        fails = [t for t in all_fails.get(key, []) if now - t < LOCKOUT_WINDOW_S]
        if len(fails) >= LOCKOUT_MAX:
            return False, "locked"
        entry = pins.get(person_id) if known else None
        if entry:
            params = {k: int(entry[k]) for k in ("n", "r", "p")}
            got = _hash(str(pin or ""), bytes.fromhex(entry["salt"]), params)
            ok = hmac.compare_digest(got, entry["hash"])
        else:
            _hash(str(pin or ""), b"\0" * 16, SCRYPT)   # same work either way, so timing tells nothing
            ok = False
        if ok:
            if key in all_fails:
                all_fails.pop(key)
                state._save(PIN_FAILS, all_fails)
            return True, None
        fails.append(now)
        all_fails[key] = fails
        state._save(PIN_FAILS, all_fails)
        return False, ("locked" if len(fails) >= LOCKOUT_MAX else "wrong")


# --- people ------------------------------------------------------------------------------------

def clean_name(display: str) -> str:
    name = " ".join("".join(ch for ch in str(display or "") if ch.isprintable()).split())
    if not name:
        raise HouseholdError("Type a name.")
    if len(name) > NAME_MAX:
        raise HouseholdError(f"Keep the name to {NAME_MAX} letters or fewer.")
    return name


def slug(display: str, taken) -> str:
    """A short id for a person, made from their name and unique in the family: "Maya Okafor" -> "maya-okafor"."""
    base = unicodedata.normalize("NFKD", display).encode("ascii", "ignore").decode().lower()
    base = re.sub(r"[^a-z0-9]+", "-", base).strip("-")[:24].strip("-") or "person"
    taken = set(taken)
    out, i = base, 2
    while out in taken:
        out = f"{base}-{i}"
        i += 1
    return out


def _taken_ids(cfg: Config) -> set[str]:
    """Ids in use now or used before: a new person must never inherit an old folder or audit log."""
    taken = set(cfg.people)
    people_dir = cfg.files / "people"
    if people_dir.is_dir():
        taken |= {d.name for d in people_dir.iterdir()}
    audit = cfg.runtime / "audit"
    if audit.is_dir():
        taken |= {f.name.split(".", 1)[0] for f in audit.iterdir()}
    return taken


def _write(cfg: Config, people: dict[str, Person], name: str | None = None) -> None:
    config.save(cfg.home, name=name, people=people)
    config.reload(cfg)


def setup_family(state: WebState, family_name: str, display: str, pin: str) -> Person:
    """First-time setup: names the box and makes the first person, who runs it. Works only while
    setup_open() is true, and only once."""
    cfg = state.cfg
    family = clean_name(family_name)
    name = clean_name(display)
    why = pin_problem(pin)
    if why:
        raise HouseholdError(why)
    with state._lock():
        config.reload(cfg)               # another tab may have finished setup a moment ago
        if not setup_open(cfg):
            raise HouseholdError("Setup is closed.")
        pid = slug(name, _taken_ids(cfg))
        person = Person(id=pid, display=name, admin=True)
        _write(cfg, {pid: person}, name=family)
    set_pin(state, pid, pin)
    return person


def add_person(state: WebState, display: str) -> Person:
    cfg = state.cfg
    name = clean_name(display)
    with state._lock():
        config.reload(cfg)
        if any(p.display.lower() == name.lower() for p in cfg.people.values()):
            raise HouseholdError("Someone in the family already has that name.")
        pid = slug(name, _taken_ids(cfg))
        person = Person(id=pid, display=name)
        _write(cfg, dict(cfg.people) | {pid: person})
    return person


def grant_choices(cfg: Config, person_id: str) -> list[tuple[str, str]]:
    """(folder path, label) for every folder this person could be allowed to also read."""
    out = []
    for other in sorted(cfg.people.values(), key=lambda p: p.display.lower()):
        if other.id == person_id:
            continue
        for f in GRANTABLE:
            out.append((f"people/{other.id}/{f}", f"{other.display}: {f}"))
    return out


def set_also_reads(state: WebState, person_id: str, grants) -> Person:
    """Replace what this person may also read. Each grant is people/<someone else>/<folder>, never health."""
    cfg = state.cfg
    with state._lock():
        config.reload(cfg)
        person = cfg.person(person_id)
        allowed = {g for g, _ in grant_choices(cfg, person_id)}
        clean = []
        for g in grants:
            g = str(g).strip().strip("/")
            if g not in allowed:
                raise HouseholdError("One of those folders can't be shared. Health folders stay private "
                                     "to their owner.")
            if g not in clean:
                clean.append(g)
        person = replace(person, also_reads=tuple(sorted(clean)))
        _write(cfg, dict(cfg.people) | {person_id: person})
    return person


def set_never_share(state: WebState, person_id: str, words) -> Person:
    cfg = state.cfg
    clean: list[str] = []
    for w in words:
        w = " ".join("".join(ch for ch in str(w) if ch.isprintable()).split())
        if not w:
            continue
        if len(w) > WORD_MAX:
            raise HouseholdError(f"Keep each word or phrase to {WORD_MAX} letters or fewer.")
        if w.lower() not in (c.lower() for c in clean):
            clean.append(w)
    if len(clean) > WORDS_MAX:
        raise HouseholdError(f"Up to {WORDS_MAX} words or phrases.")
    with state._lock():
        config.reload(cfg)
        person = replace(cfg.person(person_id), never_share=tuple(clean))
        _write(cfg, dict(cfg.people) | {person_id: person})
    return person


def remove_person(state: WebState, person_id: str, by: str) -> Person:
    """Take a person out of the family. Their files stay on the box; nobody else gains access to them.
    Their PIN, sessions, sign-in codes and grants that pointed at their folders are removed."""
    cfg = state.cfg
    with state._lock():
        config.reload(cfg)
        gone = cfg.person(person_id)
        if person_id == by:
            raise HouseholdError("You can't remove yourself.")
        rest = {pid: p for pid, p in cfg.people.items() if pid != person_id}
        if not any(p.admin for p in rest.values()):
            raise HouseholdError("The family needs at least one person who runs the box.")
        prefix = f"people/{person_id}/"
        rest = {pid: replace(p, also_reads=tuple(g for g in p.also_reads
                                                 if not (g.strip("/") + "/").startswith(prefix)))
                for pid, p in rest.items()}
        _write(cfg, rest)
        # Purge everything that could sign this id in again, so a new person with the same name
        # never inherits an old session or code.
        for name in (PINS, PIN_FAILS):
            data = state._load(name, {})
            if data.pop(person_id, None) is not None:
                state._save(name, data)
        sessions = state._load("sessions.json", {})
        state._save("sessions.json", {k: v for k, v in sessions.items() if v.get("person") != person_id})
        codes = state._load("codes.json", {})
        state._save("codes.json", {k: v for k, v in codes.items() if v.get("person") != person_id})
    return gone


def unowned_folders(cfg: Config) -> list[tuple[str, int]]:
    """(people/<id>, file count) for folders whose person is no longer in the family."""
    root = cfg.files / "people"
    if not root.is_dir():
        return []
    out = []
    for d in sorted(root.iterdir()):
        if d.is_dir() and d.name not in cfg.people:
            out.append((f"people/{d.name}", sum(1 for f in d.rglob("*") if f.is_file())))
    return out
