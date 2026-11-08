"""The family's files: text extraction, keyword search (SQLite FTS5) and the list of sensitive values.

Sensitive values are pulled out at index time so the answer gate can recognize them later,
however the model formats them. Nothing here talks to the network.
"""

from __future__ import annotations

import json
import re
import shutil
import sqlite3
import subprocess
from dataclasses import dataclass
from pathlib import Path

from . import access
from .config import Config, Person

TEXT_SUFFIXES = {".txt", ".md", ".json", ".csv", ".pdf"}

SSN_RE = re.compile(r"\b(\d{3})[- ](\d{2})[- ](\d{4})\b")
# "Label: value" lines whose value is an identifier the gate should protect.
ID_LABEL_RE = re.compile(
    r"^\s*(?P<label>passport (?:number|no\.?)|member id|policy (?:number|no\.?)|account (?:number|no\.?)|"
    r"routing (?:number|no\.?)|group (?:number|no\.?)|driver'?s license (?:number|no\.?)|license number|"
    r"medical record number|mrn|ein)\s*:\s*(?P<value>[A-Za-z0-9-]{4,})",
    re.IGNORECASE | re.MULTILINE,
)
# Lines in health records whose content is a health detail (diagnosis, medication, notes).
HEALTH_LABEL_RE = re.compile(
    r"^\s*(?P<label>diagnosis|diagnoses|condition|conditions|assessment|medication|medications|prescription|"
    r"plan|notes?|reason for visit|result|results|impression)\s*:\s*(?P<value>.+)$",
    re.IGNORECASE | re.MULTILINE,
)
TRIPWIRE_RE = re.compile(r"\bFBX-[A-Z0-9]{4,8}\b")


@dataclass(frozen=True)
class Sensitive:
    value: str
    kind: str        # ssn | id | health | tripwire
    label: str
    path: str
    owner: str | None


def extract_text(path: Path) -> str:
    if path.suffix.lower() == ".pdf":
        if not shutil.which("pdftotext"):
            return ""
        out = subprocess.run(["pdftotext", "-layout", str(path), "-"], capture_output=True, text=True, timeout=60)
        return out.stdout
    text = path.read_text(errors="replace")
    if path.suffix.lower() == ".json":
        try:
            return fhir_to_text(json.loads(text))
        except (ValueError, TypeError):
            return text
    return text


def fhir_to_text(doc: dict) -> str:
    """Flatten a small FHIR Bundle into labeled lines the rest of the box understands."""
    if doc.get("resourceType") != "Bundle":
        return json.dumps(doc, indent=1)
    lines = []
    for entry in doc.get("entry", []):
        r = entry.get("resource", {})
        rt = r.get("resourceType")
        code = (r.get("code") or r.get("vaccineCode") or r.get("medicationCodeableConcept") or {}).get("text", "")
        when = r.get("occurrenceDateTime") or r.get("onsetDateTime") or r.get("authoredOn") or r.get("recordedDate") or ""
        if rt == "Patient":
            name = (r.get("name") or [{}])[0]
            lines.append(f"Patient: {' '.join(name.get('given', []))} {name.get('family', '')}".strip())
            if r.get("birthDate"):
                lines.append(f"Date of birth: {r['birthDate']}")
            for ident in r.get("identifier", []):
                if ident.get("type", {}).get("text") == "MRN":
                    lines.append(f"Medical record number: {ident.get('value')}")
        elif rt == "Immunization":
            lines.append(f"Immunization: {code} on {when}")
        elif rt == "Condition":
            lines.append(f"Condition: {code} (since {when})")
        elif rt in ("MedicationRequest", "MedicationStatement"):
            lines.append(f"Medication: {code} (started {when})")
        elif rt == "AllergyIntolerance":
            lines.append(f"Allergy: {code}")
        elif rt == "Encounter":
            reason = ((r.get("reasonCode") or [{}])[0]).get("text", "")
            lines.append(f"Visit on {(r.get('period') or {}).get('start', '')}: {(r.get('type') or [{}])[0].get('text', '')}")
            if reason:
                lines.append(f"Reason for visit: {reason}")
        elif rt == "Observation":
            val = r.get("valueQuantity") or {}
            lines.append(f"Result: {code} = {val.get('value', '')} {val.get('unit', '')} on {when}".strip())
    return "\n".join(lines)


def find_sensitive(text: str, rel_path: str) -> list[Sensitive]:
    owner = access.owner_of(rel_path)
    found: list[Sensitive] = []
    for m in SSN_RE.finditer(text):
        found.append(Sensitive("".join(m.groups()), "ssn", "SSN", rel_path, owner))
    for m in ID_LABEL_RE.finditer(text):
        found.append(Sensitive(m["value"], "id", m["label"].strip().title(), rel_path, owner))
    if access.is_health(rel_path):
        for m in HEALTH_LABEL_RE.finditer(text):
            value = m["value"].strip()
            # Each comma/semicolon part counts on its own, so a single drug name in an answer is caught.
            for part in [value, *re.split(r"[;,]", value)]:
                part = re.sub(r"\(.*?\)", "", part).strip(" .")
                if len(part) >= 4:
                    found.append(Sensitive(part, "health", m["label"].strip().title(), rel_path, owner))
    for m in TRIPWIRE_RE.finditer(text):
        found.append(Sensitive(m.group(0), "tripwire", "Tripwire", rel_path, owner))
    return found


class Store:
    def __init__(self, cfg: Config):
        self.cfg = cfg
        cfg.runtime.mkdir(parents=True, exist_ok=True)
        self.db = sqlite3.connect(cfg.runtime / "index.sqlite3")
        self.db.executescript(
            """
            CREATE VIRTUAL TABLE IF NOT EXISTS docs USING fts5(path UNINDEXED, owner UNINDEXED, body);
            CREATE TABLE IF NOT EXISTS sensitive(value TEXT, kind TEXT, label TEXT, path TEXT, owner TEXT);
            CREATE TABLE IF NOT EXISTS meta(path TEXT PRIMARY KEY, mtime REAL);
            """
        )

    def files(self) -> list[Path]:
        return sorted(p for p in self.cfg.files.rglob("*")
                      if p.is_file() and p.suffix.lower() in TEXT_SUFFIXES and not p.name.startswith("."))

    def reindex(self) -> int:
        self.db.execute("DELETE FROM docs")
        self.db.execute("DELETE FROM sensitive")
        self.db.execute("DELETE FROM meta")
        n = 0
        for f in self.files():
            rel = f.relative_to(self.cfg.files).as_posix()
            text = extract_text(f)
            owner = access.owner_of(rel)
            self.db.execute("INSERT INTO docs(path, owner, body) VALUES (?,?,?)", (rel, owner, f"{rel}\n{text}"))
            for s in find_sensitive(text, rel):
                self.db.execute("INSERT INTO sensitive VALUES (?,?,?,?,?)", (s.value, s.kind, s.label, s.path, s.owner))
            self.db.execute("INSERT INTO meta VALUES (?,?)", (rel, f.stat().st_mtime))
            n += 1
        self.db.commit()
        return n

    def ensure_index(self) -> None:
        indexed = dict(self.db.execute("SELECT path, mtime FROM meta"))
        current = {f.relative_to(self.cfg.files).as_posix(): f.stat().st_mtime for f in self.files()}
        if indexed != current:
            self.reindex()

    def search(self, person: Person, query: str, limit: int = 8) -> list[dict]:
        words = re.findall(r"[A-Za-z0-9]+", query)
        if not words:
            return []
        fts = " OR ".join(f'"{w}"' for w in words)
        rows = self.db.execute(
            "SELECT path, snippet(docs, 2, '', '', ' … ', 12) FROM docs WHERE docs MATCH ? ORDER BY rank LIMIT 50",
            (fts,),
        ).fetchall()
        hits = [{"path": p, "context": s.replace("\n", " ")} for p, s in rows if access.can_read(person, p)]
        return hits[:limit]

    def read(self, person: Person, rel_path: str, max_chars: int = 12000) -> str | None:
        rel_path = rel_path.strip().lstrip("/")
        if not access.can_read(person, rel_path):
            return None
        target = (self.cfg.files / rel_path).resolve()
        if self.cfg.files.resolve() not in target.parents or not target.is_file():
            return None
        return extract_text(target)[:max_chars]

    def nonhealth_words(self) -> set[str]:
        words: set[str] = set()
        for path, body in self.db.execute("SELECT path, body FROM docs"):
            if not access.is_health(path):
                words.update(re.findall(r"[a-z]{7,}", body.lower()))
        return words

    def sensitive_values(self) -> list[Sensitive]:
        return [Sensitive(*row) for row in self.db.execute("SELECT value, kind, label, path, owner FROM sensitive")]
