"""Household configuration: people, what each may read, and box settings.

family.toml lives in the box's home folder (FAMILYBOX_HOME, default ./demo).
"""

from __future__ import annotations

import os
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


def load(home: Path | None = None) -> Config:
    home = (home or home_dir()).resolve()
    data = tomllib.loads((home / "family.toml").read_text())
    box = data.get("box", {})
    people = {
        pid: Person(
            id=pid,
            display=p.get("display", pid),
            admin=bool(p.get("admin", False)),
            also_reads=tuple(p.get("also_reads", [])),
            never_share=tuple(p.get("never_share", [])),
        )
        for pid, p in data.get("people", {}).items()
    }
    return Config(
        home=home,
        name=box.get("name", "Family box"),
        model=os.environ.get("FAMILYBOX_MODEL", box.get("model", DEFAULT_MODEL)),
        attestation_max_age_s=int(box.get("attestation_max_age_s", 300)),
        people=people,
    )
