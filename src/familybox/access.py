"""Who may read what. Checked before any search or read, so other people's files never reach the model.

Rules:
- people/<id>/** belongs to <id>.
- shared/** is readable by everyone in the household.
- also_reads grants extra folders (e.g. a parent reading a child's ids folder).
- A folder named "health" is only readable by its owner, even if also_reads covers its parent.
"""

from __future__ import annotations

from pathlib import PurePosixPath

from .config import Config, Person


def canonical(rel_path: str) -> str:
    """One spelling per file: "./people//dana/./health/x.txt" and "/people/dana/health/x.txt" both become
    "people/dana/health/x.txt". ".." is kept, so can_read still refuses it."""
    out = PurePosixPath(str(rel_path).strip().lstrip("/")).as_posix()
    return "" if out == "." else out


def owner_of(rel_path: str) -> str | None:
    parts = PurePosixPath(rel_path).parts
    if len(parts) >= 2 and parts[0] == "people":
        return parts[1]
    return None


def is_health(rel_path: str) -> bool:
    return "health" in PurePosixPath(rel_path).parts[:-1]


def can_read(person: Person, rel_path: str) -> bool:
    rel_path = canonical(rel_path)
    p = PurePosixPath(rel_path)
    if ".." in p.parts or p.is_absolute():
        return False
    owner = owner_of(rel_path)
    if p.parts and p.parts[0] == "shared":
        return True
    if owner == person.id:
        return True
    if is_health(rel_path):
        return False  # health folders: owner only
    return any(rel_path == g or rel_path.startswith(g.rstrip("/") + "/")
               for g in (canonical(x) for x in person.also_reads) if g)


def readable_owners(cfg: Config, person: Person) -> list[str]:
    owners = {person.id}
    for g in person.also_reads:
        o = owner_of(g + "/x")
        if o:
            owners.add(o)
    return sorted(owners)
