"""Household configuration: people, what each may read, and box settings.

family.toml lives in the box's home folder (FAMILYBOX_HOME, default ./demo).
"""

from __future__ import annotations

import os
import re
import tomllib
from dataclasses import dataclass, field
from pathlib import Path

DEFAULT_MODEL = "deepseek-ai/DeepSeek-V4.1-Flash-1017"


@dataclass(frozen=True)
class Person:
    id: str
    display: str
    admin: bool = False
    also_reads: tuple[str, ...] = ()      # extra folders, relative to files/, e.g. "people/maya/ids"
    never_share: tuple[str, ...] = ()     # words or phrases that must never leave in an answer


@dataclass(frozen=True)
class Config:
    home: Path
    name: str
    model: str
    attestation_max_age_s: int
    people: dict[str, Person] = field(default_factory=dict)

    @property
    def files(self) -> Path:
        return self.home / "files"

    @property
    def runtime(self) -> Path:
        return self.home / "runtime"

    def person(self, person_id: str) -> Person:
        if person_id not in self.people:
            raise KeyError(f"unknown person {person_id!r}; known: {', '.join(sorted(self.people))}")
        return self.people[person_id]


def home_dir() -> Path:
    return Path(os.environ.get("FAMILYBOX_HOME", Path.cwd() / "demo")).resolve()


KEY_ENV = ("NEAR_AI_CLOUD_API_KEY", "NEARAI_API_KEY")


def key_path(home: Path) -> Path:
    """Where the box keeps the NEAR AI key pasted on its page (0600)."""
    return home / "runtime" / "secrets" / "near_api_key"


def load_stored_key(home: Path) -> bool:
    """Put the stored NEAR AI key into the environment when no key variable is set. Never prints it."""
    if any(os.environ.get(k) for k in KEY_ENV):
        return False
    try:
        key = key_path(home).read_text().strip()
    except (OSError, UnicodeDecodeError):
        return False
    if not key:
        return False
    os.environ[KEY_ENV[0]] = key
    return True


def _people_of(data: dict) -> dict[str, Person]:
    return {
        pid: Person(
            id=pid,
            display=p.get("display", pid),
            admin=bool(p.get("admin", False)),
            also_reads=tuple(p.get("also_reads", [])),
            never_share=tuple(p.get("never_share", [])),
        )
        for pid, p in data.get("people", {}).items()
    }


def _read(home: Path) -> dict:
    """family.toml as a dict. A home with no family.toml yet is a box that is not set up."""
    path = home / "family.toml"
    if not path.exists():
        return {}
    return tomllib.loads(path.read_text())


def load(home: Path | None = None) -> Config:
    home = (home or home_dir()).resolve()
    data = _read(home)
    box = data.get("box", {})
    load_stored_key(home)
    return Config(
        home=home,
        name=box.get("name", "Family box"),
        model=os.environ.get("FAMILYBOX_MODEL", box.get("model", DEFAULT_MODEL)),
        attestation_max_age_s=int(box.get("attestation_max_age_s", 300)),
        people=_people_of(data),
    )


def reload(cfg: Config) -> Config:
    """Re-read family.toml into the same Config object, so the box, the store and the web page, which
    all share it, see the change without a restart."""
    new = load(cfg.home)
    cfg.people.clear()
    cfg.people.update(new.people)
    for name in ("name", "model", "attestation_max_age_s"):
        object.__setattr__(cfg, name, getattr(new, name))
    return cfg


# --- writing family.toml ------------------------------------------------------------------------

_BARE = re.compile(r"^[A-Za-z0-9_-]+$")


def _key(k: str) -> str:
    return k if _BARE.match(k) else _str(k)


def _str(s: str) -> str:
    out = []
    for ch in s:
        if ch == "\\":
            out.append("\\\\")
        elif ch == '"':
            out.append('\\"')
        elif ch == "\n":
            out.append("\\n")
        elif ch == "\t":
            out.append("\\t")
        elif ord(ch) < 0x20 or ord(ch) == 0x7F:
            out.append(f"\\u{ord(ch):04x}")
        else:
            out.append(ch)
    return '"' + "".join(out) + '"'


def _value(v) -> str:
    if isinstance(v, bool):
        return "true" if v else "false"
    if isinstance(v, (int, float)):
        return repr(v)
    if isinstance(v, str):
        return _str(v)
    if isinstance(v, (list, tuple)):
        return "[" + ", ".join(_value(x) for x in v) + "]"
    raise ValueError(f"family.toml can't hold a {type(v).__name__}")


def _table(lines: list[str], path: list[str], table: dict) -> None:
    plain = {k: v for k, v in table.items() if not isinstance(v, dict)}
    subs = {k: v for k, v in table.items() if isinstance(v, dict)}
    if path and (plain or not subs):
        lines.append("")
        lines.append("[" + ".".join(_key(p) for p in path) + "]")
    for k, v in plain.items():
        lines.append(f"{_key(k)} = {_value(v)}")
    for k, v in subs.items():
        _table(lines, path + [k], v)


def dumps(data: dict) -> str:
    lines = ["# Written by the family box. Edits made on the box's page replace this file."]
    _table(lines, [], data)
    return "\n".join(lines).strip() + "\n"


def save(home: Path, name: str | None = None, model: str | None = None,
         people: dict[str, Person] | None = None, extra: dict | None = None) -> Path:
    """Write family.toml atomically (0600). Tables this function does not know ([pins], [remote],
    [paraphrase_check] and the rest) are kept from the old file. None keeps the old value."""
    from .web import _write_private   # web imports config, so this import waits until it is needed

    home = Path(home).resolve()
    old = _read(home)
    box = dict(old.get("box", {}))
    if name is not None:
        box["name"] = name
    if model is not None:
        box["model"] = model
    data: dict = {"box": box}
    if people is None:
        data["people"] = old.get("people", {})
    else:
        data["people"] = {
            pid: {"display": p.display, "admin": p.admin, "also_reads": list(p.also_reads),
                  "never_share": list(p.never_share)}
            for pid, p in people.items()
        }
    for k, v in old.items():
        if k not in ("box", "people"):
            data[k] = v
    for k, v in (extra or {}).items():
        if k in ("box", "people"):
            raise ValueError("use name, model and people for those")
        data[k] = v
    text = dumps(data)
    tomllib.loads(text)   # never write a file the box could not read back
    path = home / "family.toml"
    _write_private(path, text.encode())
    return path
