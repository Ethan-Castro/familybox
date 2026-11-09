"""Fill forms on the box: the assistant helps with a form but never sees the real numbers.

The assistant sends field values as plain text or as references like {{maya.ssn}}. The box looks each
reference up in the indexed files, but only in files the asker may read (access.can_read). It fills
the PDF here, stores it in <runtime>/forms/ (0600), and puts an approval item in front of every person
whose details are in it. The assistant gets back only what was filled, with references masked
("SSN ending 4322"); that text is also run through the answer gate before it leaves.

Who gets the PDF: once every owner has approved, it can be downloaded from the box's Forms page by an
owner who may read every file the values came from. So the PDF never shows anyone a detail they could
not already read on the box. If no owner qualifies, the box refuses to fill and says to split the form.

References:
  {{<person>.<field>}}   from people/<person>/** (for example {{maya.ssn}}, {{dana.passport_number}})
  {{family.<field>}}     from shared/** (for example {{family.insurance_member_id}})
"""

from __future__ import annotations

import contextlib
import fcntl
import json
import os
import re
import secrets
import time
from dataclasses import dataclass, field
from io import BytesIO
from pathlib import Path, PurePosixPath

from pypdf import PdfReader, PdfWriter

from . import access, gate
from .approvals import Approvals
from .config import Config, Person
from .store import Store

FORM_TTL_S = 7 * 24 * 3600          # a filled form is deleted after a week
MAX_FIELDS = 60
MAX_TEXT = 300
ID_ALPHABET = "abcdefghjkmnpqrstuvwxyz"   # letters only, so a form id can never look like part of a number
FAMILY = "family"

REF_RE = re.compile(r"\{\{\s*([A-Za-z0-9_-]+)\s*\.\s*([A-Za-z0-9_]+)\s*\}\}")
CTRL_RE = re.compile(r"[\x00-\x08\x0b-\x1f\x7f]")


class FormError(ValueError):
    """Something the asker can fix. The message is safe to show to the assistant."""


@dataclass(frozen=True)
class FieldDef:
    key: str
    label: str
    kind: str                   # ssn | id | health | dob | name | money | text
    pattern: re.Pattern
    doc: re.Pattern | None = None   # the file must also match this (e.g. only passports)
    multi: bool = False             # join every match in the file (allergies, medications)


def _p(rx: str) -> re.Pattern:
    return re.compile(rx, re.IGNORECASE | re.MULTILINE)


FIELDS: dict[str, FieldDef] = {f.key: f for f in [
    FieldDef("name", "full name", "name", _p(r"^\s*(?:name|employee|patient)\s*:\s*(?P<v>[^\n]+?)\s*$")),
    FieldDef("ssn", "SSN", "ssn",
             _p(r"^\s*(?:employee\s+)?(?:ssn|social security number)\s*:\s*(?P<v>\d{3}-\d{2}-\d{4})\b")),
    FieldDef("date_of_birth", "date of birth", "dob", _p(r"^\s*(?:date of birth|dob|birth date)\s*:\s*(?P<v>[^\n]+?)\s*$")),
    FieldDef("passport_number", "passport number", "id", _p(r"^\s*passport (?:number|no\.?)\s*:\s*(?P<v>[A-Za-z0-9-]{4,})")),
    FieldDef("passport_expiration", "passport expiration date", "text",
             _p(r"^\s*expiration date\s*:\s*(?P<v>[^\n]+?)\s*$"), doc=_p(r"passport")),
    FieldDef("medical_record_number", "medical record number", "id",
             _p(r"^\s*(?:medical record number|mrn)\s*:\s*(?P<v>[A-Za-z0-9-]{4,})")),
    FieldDef("allergies", "allergies", "health", _p(r"^\s*allerg(?:y|ies)\s*:\s*(?P<v>[^\n]+?)\s*$"), multi=True),
    FieldDef("conditions", "medical conditions", "health",
             _p(r"^\s*(?:conditions?|diagnos[ie]s|assessment)\s*:\s*(?P<v>[^\n(]+?)\s*(?:\([^)\n]*\))?\s*$"), multi=True),
    FieldDef("medications", "medications", "health",
             _p(r"^\s*(?:medications?|prescriptions?)\s*:\s*(?P<v>[^\n(]+?)\s*(?:\([^)\n]*\))?\s*$"), multi=True),
    FieldDef("immunizations", "immunizations", "health",
             _p(r"^\s*immunization\s*:\s*(?P<v>[^\n]+?)\s*$"), multi=True),
    FieldDef("employer", "employer", "text", _p(r"^\s*employer\s*:\s*(?P<v>[^\n]+?)\s*$")),
    FieldDef("w2_wages", "W-2 wages", "money", _p(r"^\s*box 1 wages[^:\n]*:\s*(?P<v>[\d,.]+)")),
    FieldDef("w2_federal_tax_withheld", "W-2 federal tax withheld", "money",
             _p(r"^\s*box 2 federal income tax withheld\s*:\s*(?P<v>[\d,.]+)")),
    FieldDef("agi", "adjusted gross income", "money", _p(r"^\s*adjusted gross income[^:\n]*:\s*(?P<v>[\d,.]+)")),
    FieldDef("insurance_plan", "insurance plan", "text", _p(r"^\s*plan\s*:\s*(?P<v>[^\n]+?)\s*$"),
             doc=_p(r"insurance")),
    FieldDef("insurance_member_id", "insurance member ID", "id", _p(r"^\s*member id\s*:\s*(?P<v>[A-Za-z0-9-]{4,})")),
    FieldDef("insurance_group_number", "insurance group number", "id",
             _p(r"^\s*group (?:number|no\.?)\s*:\s*(?P<v>[A-Za-z0-9-]{4,})")),
]}
ALIASES = {"full_name": "name", "social_security_number": "ssn", "dob": "date_of_birth", "birth_date": "date_of_birth",
           "passport": "passport_number", "mrn": "medical_record_number", "member_id": "insurance_member_id",
           "group_number": "insurance_group_number", "wages": "w2_wages", "allergy": "allergies",
           "condition": "conditions", "medication": "medications"}


# --- templates ------------------------------------------------------------------------------------

@dataclass
class Template:
    slug: str
    title: str
    description: str
    path: Path
    fields: dict[str, dict]     # name -> {"label", "hint"}


def templates_dir(cfg: Config) -> Path:
    return cfg.home / "forms"


def list_templates(cfg: Config) -> list[Template]:
    out = []
    d = templates_dir(cfg)
    if not d.is_dir():
        return out
    for pdf in sorted(d.glob("*.pdf")):
        if pdf.name.startswith(".") or not re.fullmatch(r"[a-z0-9_-]+", pdf.stem):
            continue
        try:
            reader = PdfReader(pdf)
            names = [n for n, f in (reader.get_fields() or {}).items() if f.get("/FT") == "/Tx"]
            title = (reader.metadata.title if reader.metadata else None) or pdf.stem
        except Exception:  # noqa: BLE001 - a broken template is skipped, not fatal
            continue
        hints = {}
        side = pdf.with_suffix(".json")
        if side.exists():
            with contextlib.suppress(ValueError):
                hints = json.loads(side.read_text())
        hf = hints.get("fields", {})
        fields = {n: {"label": str(hf.get(n, {}).get("label") or n),
                      "hint": str(hf.get(n, {}).get("hint") or "")} for n in names}
        out.append(Template(pdf.stem, str(hints.get("title") or title), str(hints.get("description") or ""),
                            pdf, fields))
    return out


def find_template(cfg: Config, name: str) -> Template:
    want = re.sub(r"[^a-z0-9]+", " ", str(name).lower()).strip()
    for t in list_templates(cfg):
        if want in (re.sub(r"[^a-z0-9]+", " ", t.slug).strip(), re.sub(r"[^a-z0-9]+", " ", t.title.lower()).strip()):
            return t
    names = ", ".join(t.slug for t in list_templates(cfg)) or "none"
    raise FormError(f"There is no form called {name!r}. Forms on this box: {names}.")


def describe_templates(cfg: Config) -> str:
    ts = list_templates(cfg)
    if not ts:
        return "There are no forms on this box yet."
    lines = []
    for t in ts:
        lines.append(f"{t.slug}: {t.title}")
        if t.description:
            lines.append(f"  {t.description}")
        for n, f in t.fields.items():
            hint = f" (fill with {f['hint']})" if f["hint"] else ""
            lines.append(f"  - {n}: {f['label']}{hint}")
    lines.append("")
    lines.append("Reference a private detail as {{person.field}} or {{family.field}}, for example {{maya.ssn}}. "
                 f"Fields: {', '.join(FIELDS)}. The box fills the real value itself; you never see it.")
    return "\n".join(lines)


# --- resolving references -------------------------------------------------------------------------

@dataclass
class Resolved:
    ref: str            # normalized "maya.ssn"
    owner: str | None   # person id, or None for shared family files
    field: FieldDef
    value: str
    path: str


def _person_lookup(cfg: Config, who: str) -> str | None:
    w = who.strip().lower()
    for p in cfg.people.values():
        if w in (p.id.lower(), p.display.lower()):
            return p.id
    return None


def _priority(path: str) -> tuple:
    parts = PurePosixPath(path).parts
    return (0 if "ids" in parts else 2 if access.is_health(path) else 1, path)


def resolve(cfg: Config, store: Store, asker: Person, who: str, key: str,
            cache: dict | None = None) -> Resolved:
    """Find one reference in files the asker may read. The same message covers 'not there' and 'not
    allowed', so a reference can't be used to learn what is in files the asker can't read."""
    fkey = ALIASES.get(key.lower(), key.lower())
    if fkey not in FIELDS:
        raise FormError(f"{{{{{who}.{key}}}}}: unknown detail. Known details: {', '.join(FIELDS)}.")
    fd = FIELDS[fkey]
    if who.lower() == FAMILY:
        owner, prefix = None, "shared/"
    else:
        owner = _person_lookup(cfg, who)
        if owner is None:
            raise FormError(f"{{{{{who}.{key}}}}}: there is nobody called {who!r} in this household.")
        prefix = f"people/{owner}/"
    ref = f"{owner or FAMILY}.{fkey}"
    if cache is not None and ref in cache:
        return cache[ref]
    rows = store.db.execute("SELECT path, body FROM docs").fetchall()
    cands = sorted(((p, b) for p, b in rows if p.startswith(prefix) and access.can_read(asker, p)),
                   key=lambda r: _priority(r[0]))
    for path, body in cands:
        text = body.split("\n", 1)[1] if "\n" in body else ""
        if fd.doc and not fd.doc.search(text):
            continue
        vals = [CTRL_RE.sub("", m["v"]).strip() for m in fd.pattern.finditer(text)]
        vals = [v for v in dict.fromkeys(vals) if v]
        if not vals:
            continue
        value = "; ".join(vals) if fd.multi else vals[0]
        r = Resolved(ref, owner, fd, value, path)
        if cache is not None:
            cache[ref] = r
        return r
    whose = "the family's shared files" if owner is None else f"files {asker.display} may read"
    raise FormError(f"{{{{{who}.{key}}}}}: the box can't use that detail; it isn't in {whose}.")


def masked(r: Resolved, display: dict[str, str]) -> str:
    whose = "the family's" if r.owner is None else f"{display.get(r.owner, r.owner)}'s"
    if r.field.kind == "ssn":
        return f"{whose} SSN ending {gate.digits(r.value)[-4:]}"
    if r.field.kind == "id" and len(re.sub(r"[^A-Za-z0-9]", "", r.value)) >= 7:
        return f"{whose} {r.field.label} ending {re.sub(r'[^A-Za-z0-9]', '', r.value)[-3:]}"
    return f"{whose} {r.field.label} (kept on the box)"


# --- the form store -------------------------------------------------------------------------------

def forms_dir(cfg: Config) -> Path:
    d = cfg.runtime / "forms"
    d.mkdir(parents=True, exist_ok=True, mode=0o700)
    os.chmod(d, 0o700)
    return d


def _write_private(path: Path, data: bytes) -> None:
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


@contextlib.contextmanager
def _locked(cfg: Config):
    fd = os.open(forms_dir(cfg) / ".lock", os.O_WRONLY | os.O_CREAT, 0o600)
    try:
        fcntl.flock(fd, fcntl.LOCK_EX)
        yield
    finally:
        fcntl.flock(fd, fcntl.LOCK_UN)
        os.close(fd)


def _index_path(cfg: Config) -> Path:
    return forms_dir(cfg) / "index.json"


def _load(cfg: Config) -> dict:
    p = _index_path(cfg)
    if not p.exists():
        return {}
    try:
        return json.loads(p.read_text())
    except ValueError:
        return {}


def _save(cfg: Config, data: dict) -> None:
    _write_private(_index_path(cfg), json.dumps(data, indent=1).encode())


def pdf_path(cfg: Config, form_id: str) -> Path:
    if not re.fullmatch(f"[{ID_ALPHABET}]{{10}}", form_id or ""):
        raise KeyError("no such form")
    return forms_dir(cfg) / f"{form_id}.pdf"


def _audit(cfg: Config, person_id: str, entry: dict) -> None:
    log = cfg.runtime / "audit" / f"{person_id}.jsonl"
    log.parent.mkdir(parents=True, exist_ok=True)
    with log.open("a") as f:
        f.write(json.dumps({"time": int(time.time())} | entry) + "\n")


# --- filling --------------------------------------------------------------------------------------

@dataclass
class FillResult:
    form_id: str
    text: str                       # what the assistant gets
    approvers: list[str] = field(default_factory=list)
    recipients: list[str] = field(default_factory=list)
    filled: list[str] = field(default_factory=list)


EMAIL_RE = re.compile(r"[\w.+-]+@[\w-]+(?:\.[\w-]+)+")
ID_TOKEN_RE = re.compile(r"\b(?=[A-Za-z0-9-]*\d)(?=[A-Za-z0-9-]*[A-Za-z])[A-Za-z0-9][A-Za-z0-9-]{7,}\b")


def _check_literal(fname: str, text: str) -> None:
    """Typed-in text may not carry SSN, card or ID-shaped numbers; those come only from references, so the
    box knows whose they are and asks that person. The rule looks only at the shape of the text, never at
    the family's stored values, so a refusal can't be used to test a guess."""
    t = EMAIL_RE.sub(" ", text)
    cards = [re.sub(r"\D", "", m.group(0)) for m in gate.CARD_RE.finditer(t)]
    if (gate.GENERIC_SSN_RE.search(t) or ID_TOKEN_RE.search(t)
            or any(13 <= len(n) <= 19 and gate.luhn_ok(n) for n in cards)):
        raise FormError(f"{fname}: typed-in text can't contain Social Security, card or ID numbers. "
                        "Use a reference like {{maya.ssn}} instead, and the box fills it in.")


def _gate_ok(cfg: Config, store: Store, asker: Person, text: str, resolved: list[Resolved]) -> bool:
    for r in resolved:
        nv = gate.normalize(r.value)
        if len(nv) >= 4 and nv in gate.normalize(text):
            return False
    res = gate.check(text, sensitive=store.sensitive_values(),
                     readable_owners=set(access.readable_owners(cfg, asker)), never_share=list(asker.never_share),
                     display={p.id: p.display for p in cfg.people.values()}, common_words=store.nonhealth_words())
    return res.outcome == "pass"


def _names(ids: list[str], display: dict[str, str]) -> str:
    names = [display.get(i, i) for i in ids]
    return names[0] if len(names) == 1 else ", ".join(names[:-1]) + " and " + names[-1]


def fill(cfg: Config, asker_id: str, form: str, for_person: str, fields: dict, *, source: str = "cli",
         store: Store | None = None) -> FillResult:
    asker = cfg.person(asker_id)
    display = {p.id: p.display for p in cfg.people.values()}
    store = store or Store(cfg)
    store.ensure_index()
    tpl = find_template(cfg, form)
    target = _person_lookup(cfg, str(for_person or asker.id))
    if target is None:
        raise FormError(f"There is nobody called {for_person!r} in this household.")
    if not isinstance(fields, dict) or not fields:
        raise FormError("Give at least one field to fill, as {\"field name\": \"text or {{person.detail}}\"}.")
    if len(fields) > MAX_FIELDS:
        raise FormError(f"Too many fields (at most {MAX_FIELDS}).")

    cache: dict = {}
    values: dict[str, str] = {}
    summary: list[str] = []
    used: list[Resolved] = []
    problems: list[str] = []
    for fname, raw in fields.items():
        fname = str(fname)
        if fname not in tpl.fields:
            problems.append(f"{fname}: this form has no such field.")
            continue
        if raw is None:
            continue
        if isinstance(raw, bool) or not isinstance(raw, (str, int, float)):
            problems.append(f"{fname}: the value must be text.")
            continue
        raw = CTRL_RE.sub("", str(raw))
        if len(raw) > MAX_TEXT:
            problems.append(f"{fname}: too long (at most {MAX_TEXT} characters).")
            continue
        refs = list(REF_RE.finditer(raw))
        literal = REF_RE.sub(" ", raw)
        if "{{" in literal or "}}" in literal:
            problems.append(f"{fname}: a reference must look like {{{{person.detail}}}}, for example {{{{maya.ssn}}}}.")
            continue
        if literal.strip():
            try:
                _check_literal(fname, literal)
            except FormError as e:
                problems.append(str(e))
                continue
        out, last, parts, ok = [], 0, [], True
        for m in refs:
            try:
                r = resolve(cfg, store, asker, m.group(1), m.group(2), cache)
            except FormError as e:
                problems.append(f"{fname}: {e}")
                ok = False
                break
            out.append(raw[last:m.start()])
            out.append(r.value)
            last = m.end()
            parts.append(masked(r, display))
            used.append(r)
        if not ok:
            continue
        out.append(raw[last:])
        value = "".join(out).strip()
        if not value:
            continue
        values[fname] = value
        if parts and not literal.strip():
            summary.append(f"- {fname}: {', '.join(parts)}")
        elif parts:
            summary.append(f"- {fname}: your text with {', '.join(parts)}")
        else:
            summary.append(f"- {fname}: your text")
    if problems:
        raise FormError("The form was not filled. Fix these and try again:\n" + "\n".join(f"- {p}" for p in problems))
    if not values:
        raise FormError("Nothing to fill: every field was empty.")

    uniq = list({(r.ref, r.path): r for r in used}.values())
    sources = sorted({r.path for r in uniq})
    approvers = sorted({r.owner for r in uniq if r.owner}) or [asker.id]
    recipients = [o for o in approvers if all(access.can_read(cfg.person(o), p) for p in sources)]
    if not recipients:
        raise FormError(f"The form was not filled. It mixes details that {_names(approvers, display)} each need to "
                        "approve, but none of them may see all the others' details, so nobody could receive it. "
                        "Fill it in separate parts instead.")

    # Fill the PDF here, on the box.
    reader = PdfReader(tpl.path)
    writer = PdfWriter(clone_from=reader)
    for page in writer.pages:
        writer.update_page_form_field_values(page, values, auto_regenerate=False)
    buf = BytesIO()
    writer.write(buf)

    with _locked(cfg):
        data = _load(cfg)
        form_id = "".join(secrets.choice(ID_ALPHABET) for _ in range(10))
        while form_id in data:
            form_id = "".join(secrets.choice(ID_ALPHABET) for _ in range(10))
        _write_private(pdf_path(cfg, form_id), buf.getvalue())
        what = sorted({r.field.label for r in uniq})
        held = []
        items = {}
        for o in approvers:
            mine = sorted({r.field.label for r in uniq if r.owner == o}) or what
            item_id = f"form-{form_id}-{o}"
            held.append(gate.Held(item_id, "form", f"Filled form: {tpl.title}",
                                  f"Approved. Download it from the Forms page on this box (form {form_id}).",
                                  o, f"forms/{form_id}.pdf"))
            items[o] = item_id
            who_for = display[target]
            question = (f"{display[asker.id]}'s assistant filled \"{tpl.title}\" for {who_for}. "
                        f"It uses {'your ' if o in [r.owner for r in uniq] else ''}{', '.join(mine) or 'only typed-in text'}.")
            Approvals(cfg).add(asker.id, question, [held[-1]])
        data[form_id] = {
            "form": tpl.slug, "title": tpl.title, "asker": asker.id, "for": target, "source": source,
            "created": int(time.time()), "status": "waiting",
            "approvers": approvers, "recipients": recipients, "items": items,
            "fields": [line[2:] for line in summary],
            "refs": [{"ref": r.ref, "kind": r.field.kind, "owner": r.owner, "path": r.path} for r in uniq],
            "sources": sources,
        }
        _save(cfg, data)

    filled = [n for n in tpl.fields if n in values]
    blank = [n for n in tpl.fields if n not in values]
    text = "\n".join([
        f"Form ready on the family box: {tpl.title} for {display[target]} (form id {form_id}).",
        f"Filled {len(filled)} of {len(tpl.fields)} fields:",
        *summary,
        *([f"Left blank: {', '.join(blank)}."] if blank else []),
        "The real values were filled in on the box. None of them were sent to you.",
        f"Waiting for {_names(approvers, display)} to approve on the box's web page (Approvals). "
        f"After that, {_names(recipients, display)} can download the filled PDF from the Forms page.",
    ])
    if not _gate_ok(cfg, store, asker, text, uniq):
        text = (f"Form ready on the family box: {tpl.title} (form id {form_id}). The real values were filled in on "
                f"the box. Waiting for {_names(approvers, display)} to approve on the box's web page.")
        if not _gate_ok(cfg, store, asker, text, uniq):
            text = "Form ready on the family box. Check the box's web page for approvals."
    _audit(cfg, asker.id, {"event": "form_fill", "source": source, "form_id": form_id, "form": tpl.slug,
                           "for": target, "fields": filled,
                           "refs": [{"ref": r.ref, "kind": r.field.kind, "owner": r.owner, "path": r.path}
                                    for r in uniq],
                           "approvers": approvers, "sent_to_assistant": text})
    return FillResult(form_id, text, approvers, recipients, filled)


# --- after filling: status, approvals, download ---------------------------------------------------

def _approval_status(cfg: Config, rec: dict) -> dict[str, str]:
    data = Approvals(cfg)._load()  # read-only peek at the shared approvals file
    return {o: (data.get(i) or {}).get("status", "missing") for o, i in rec.get("items", {}).items()}


def _deny_waiting(cfg: Config, rec: dict) -> None:
    appr = Approvals(cfg)
    st = _approval_status(cfg, rec)
    for o, i in rec.get("items", {}).items():
        if st.get(o) == "waiting":
            with contextlib.suppress(KeyError):
                appr.decide(o, i, False)


def _close(cfg: Config, form_id: str, rec: dict, status: str) -> None:
    rec["status"] = status
    rec["closed"] = int(time.time())
    with contextlib.suppress(FileNotFoundError, KeyError):
        pdf_path(cfg, form_id).unlink()
    _deny_waiting(cfg, rec)


def refresh(cfg: Config, now: float | None = None) -> dict:
    """Bring every form's status up to date: approved, denied, expired. Deletes PDFs that are done."""
    now = now or time.time()
    with _locked(cfg):
        data = _load(cfg)
        changed = False
        for fid, rec in data.items():
            if rec["status"] in ("denied", "expired", "deleted"):
                continue
            if now - rec["created"] > FORM_TTL_S:
                _close(cfg, fid, rec, "expired")
                changed = True
                continue
            st = _approval_status(cfg, rec)
            if any(v in ("denied", "missing") for v in st.values()):
                _close(cfg, fid, rec, "denied")
                changed = True
            elif st and all(v == "approved" for v in st.values()) and rec["status"] != "ready":
                rec["status"] = "ready"
                changed = True
        if changed:
            _save(cfg, data)
        return data


def forms_for(cfg: Config, person_id: str) -> list[dict]:
    """Forms this person asked for, must approve, or may download (newest first). No values inside."""
    out = []
    for fid, rec in refresh(cfg).items():
        if person_id in ({rec["asker"]} | set(rec["approvers"]) | set(rec["recipients"])):
            out.append({"id": fid, **rec, "approvals": _approval_status(cfg, rec)})
    return sorted(out, key=lambda r: -r["created"])


def decide(cfg: Config, person_id: str, form_id: str, approve: bool) -> dict:
    rec = refresh(cfg).get(form_id)
    if not rec or person_id not in rec.get("items", {}) or rec["status"] not in ("waiting",):
        raise KeyError("no such form waiting for you")
    if _approval_status(cfg, rec).get(person_id) != "waiting":
        raise KeyError("no such form waiting for you")
    Approvals(cfg).decide(person_id, rec["items"][person_id], approve)
    return refresh(cfg)[form_id]


def download(cfg: Config, person_id: str, form_id: str) -> tuple[str, bytes]:
    """The filled PDF, for a recipient, after every owner approved. Raises PermissionError otherwise."""
    rec = refresh(cfg).get(form_id)
    if not rec:
        raise KeyError("no such form")
    if person_id not in rec["recipients"]:
        raise PermissionError("this form isn't yours to download")
    person = cfg.person(person_id)
    if not all(access.can_read(person, p) for p in rec["sources"]):
        raise PermissionError("you may no longer read every file this form uses")
    if rec["status"] != "ready":
        raise PermissionError("this form is not approved yet" if rec["status"] == "waiting"
                              else f"this form was {rec['status']}")
    data = pdf_path(cfg, form_id).read_bytes()
    _audit(cfg, person_id, {"event": "form_download", "form_id": form_id, "form": rec["form"], "bytes": len(data)})
    name = re.sub(r"[^A-Za-z0-9_-]", "", f"{rec['form']}_{rec['for']}_{form_id}") + ".pdf"
    return name, data


def delete(cfg: Config, person_id: str, form_id: str) -> None:
    with _locked(cfg):
        data = _load(cfg)
        rec = data.get(form_id)
        if not rec or person_id not in ({rec["asker"]} | set(rec["approvers"]) | set(rec["recipients"])):
            raise KeyError("no such form")
        if rec["status"] not in ("denied", "expired", "deleted"):
            _close(cfg, form_id, rec, "deleted")
        _save(cfg, data)
    _audit(cfg, person_id, {"event": "form_delete", "form_id": form_id})
