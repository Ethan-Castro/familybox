"""Who may read what. Checked before any search or read, so other people's files never reach the model.

Rules:
- people/<id>/** belongs to <id>.
- shared/** is readable by everyone in the household.
- also_reads grants extra folders (e.g. a parent reading a child's ids folder).
- A folder named "health" is only readable by its owner, even if also_reads covers its parent.
- Filing (can_file) follows reading, plus one drop-off case: the admin may file into the health folder
  of a person whose other folders they read, without being able to read it back.
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


def can_file(person: Person, rel_path: str) -> bool:
    """May this person put a new file at rel_path? Kept apart from can_read on purpose.

    Anything the person may read, they may also file into. One extra case: the admin may drop a paper
    into the health folder of someone whose other folders they already read through also_reads (a
    parent filing a child's vaccine record). That is drop-off only: can_read still says no, so the
    admin can't list, open or search it afterwards.
    """
    rel_path = canonical(rel_path)
    p = PurePosixPath(rel_path)
    if not p.parts or ".." in p.parts or p.is_absolute():
        return False
    if can_read(person, rel_path):
        return True
    owner = owner_of(rel_path)
    if not person.admin or not owner or owner == person.id:
        return False
    if len(p.parts) < 4 or p.parts[2] != "health":
        return False
    return owner in {owner_of(canonical(g) + "/x") for g in person.also_reads}


def readable_owners(cfg: Config, person: Person) -> list[str]:
    owners = {person.id}
    for g in person.also_reads:
        o = owner_of(g + "/x")
        if o:
            owners.add(o)
    return sorted(owners)
