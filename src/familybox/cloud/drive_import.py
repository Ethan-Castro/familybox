"""Read-only import of one Google Drive folder (plus one level of subfolders) into a person's folder.

Files land in <home>/files/people/<person>/from-drive/<folder>/... with 0600 permissions. Only
.txt .md .pdf .json .csv are downloaded; Google Docs are exported as plain text; everything else is
skipped. A manifest of Drive id and modifiedTime in <runtime>/cloud/<person>.import.json lets a
re-import skip files that have not changed. File contents go to the box's disk and nowhere else.
"""

from __future__ import annotations

import os
import re
import secrets
import time
import unicodedata
from pathlib import Path
from urllib.parse import quote

from ..config import Config
from ..store import Store
from ._common import DRIVE_API, CloudError, check_person, cloud_dir, raise_for_google, read_json, write_json
from .session import DriveSession

ALLOWED_SUFFIXES = {".txt", ".md", ".pdf", ".json", ".csv"}
FOLDER_MIME = "application/vnd.google-apps.folder"
GOOGLE_DOC_MIME = "application/vnd.google-apps.document"
MAX_FILE_BYTES = 50 * 1024 * 1024
DRIVE_ID_RE = re.compile(r"^[A-Za-z0-9_-]{10,}$")
FOLDER_URL_RE = re.compile(r"/folders/([A-Za-z0-9_-]{10,})")
FIELDS = "nextPageToken,files(id,name,mimeType,modifiedTime,size)"


def safe_name(name: str, fallback: str = "file") -> str:
    """A file name that is safe on any disk: no slashes, no leading dots, printable ASCII-ish only."""
    name = unicodedata.normalize("NFKC", name or "")
    name = re.sub(r"[^A-Za-z0-9._ ()-]+", "_", name).strip(" ._")
    name = re.sub(r"_+", "_", name)
    if not name or name in (".", ".."):
        name = fallback
    if len(name) > 120:
        stem, dot, ext = name.rpartition(".")
        name = (stem[: 110] + "." + ext[:9]) if dot and len(ext) <= 9 else name[:120]
    return name


def manifest_path(cfg: Config, person_id: str) -> Path:
    return cloud_dir(cfg) / f"{person_id}.import.json"


def person_root(cfg: Config, person_id: str) -> Path:
    """<home>/files/people/<person>/from-drive, after checking nothing in the way is a symlink."""
    files = cfg.files.resolve()
    people = files / "people"
    root = people / person_id / "from-drive"
    for p in (people, people / person_id, root):
        if p.is_symlink():
            raise CloudError(f"refusing to import: {p.relative_to(files)} is a symlink")
    root.mkdir(parents=True, exist_ok=True)
    for p in (people / person_id, root):
        os.chmod(p, 0o700)
    if root.resolve() != root or (people / person_id).resolve() not in root.resolve().parents:
        raise CloudError("refusing to import outside the person's own folder")
    return root


def _list_children(s: DriveSession, folder_id: str) -> list[dict]:
    out, token = [], None
    while True:
        params = {"q": f"'{folder_id}' in parents and trashed = false", "fields": FIELDS, "pageSize": 1000,
                  "supportsAllDrives": "true", "includeItemsFromAllDrives": "true", "orderBy": "name"}
        if token:
            params["pageToken"] = token
        r = s.request("GET", f"{DRIVE_API}/files", params=params)
        raise_for_google(r, "listing the folder")
        body = r.json()
        out.extend(body.get("files", []))
        token = body.get("nextPageToken")
        if not token:
            return out


def _escape_q(value: str) -> str:
    return value.replace("\\", "\\\\").replace("'", "\\'")


def resolve_folder(s: DriveSession, folder: str) -> dict:
    """Accept a folder id, a Drive folder link, or a folder name."""
    folder = (folder or "").strip()
    if not folder:
        raise CloudError("pick a Drive folder")
    m = FOLDER_URL_RE.search(folder)
    candidate = m.group(1) if m else folder
    if DRIVE_ID_RE.match(candidate):
        r = s.request("GET", f"{DRIVE_API}/files/{quote(candidate)}",
                      params={"fields": "id,name,mimeType", "supportsAllDrives": "true"})
        if r.status_code == 200 and r.json().get("mimeType") == FOLDER_MIME:
            return r.json()
        if r.status_code not in (200, 404):
            raise_for_google(r, "finding the folder")
    params = {"q": f"name = '{_escape_q(folder)}' and mimeType = '{FOLDER_MIME}' and trashed = false",
              "fields": "files(id,name,mimeType,modifiedTime)", "pageSize": 10,
              "supportsAllDrives": "true", "includeItemsFromAllDrives": "true"}
    r = s.request("GET", f"{DRIVE_API}/files", params=params)
    raise_for_google(r, "finding the folder")
    found = r.json().get("files", [])
    if not found:
        raise CloudError(f"no Drive folder named {folder!r}")
    if len(found) > 1:
        raise CloudError(f"{len(found)} Drive folders are named {folder!r}; pick one by its link or id")
    return found[0]


def _download(s: DriveSession, item: dict, dest: Path) -> int:
    if item["mimeType"] == GOOGLE_DOC_MIME:
        url, params = f"{DRIVE_API}/files/{quote(item['id'])}/export", {"mimeType": "text/plain"}
    else:
        url, params = f"{DRIVE_API}/files/{quote(item['id'])}", {"alt": "media", "supportsAllDrives": "true"}
    tmp = dest.with_name(f".{dest.name}.{secrets.token_hex(4)}.part")
    n = 0
    fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    try:
        with os.fdopen(fd, "wb") as f, s.stream("GET", url, params=params) as r:
            if r.status_code >= 400:
                r.read()
                raise_for_google(r, f"downloading {item.get('name', 'a file')}")
            for chunk in r.iter_bytes(65536):
                n += len(chunk)
                if n > MAX_FILE_BYTES:
                    raise CloudError("file is larger than 50 MB")
                f.write(chunk)
        os.chmod(tmp, 0o600)
        os.replace(tmp, dest)
    except BaseException:
        tmp.unlink(missing_ok=True)
        raise
    return n


def _plan_name(item: dict) -> tuple[str | None, str]:
    """(local file name or None to skip, reason)."""
    mime, name = item.get("mimeType", ""), item.get("name", "")
    if mime == GOOGLE_DOC_MIME:
        base = safe_name(name, "document")
        return (base if base.lower().endswith(".txt") else base + ".txt"), "google doc"
    if mime.startswith("application/vnd.google-apps."):
        return None, "Google file type that cannot be imported as text"
    suffix = Path(name).suffix.lower()
    if suffix not in ALLOWED_SUFFIXES:
        return None, f"type {suffix or '(none)'} is not allowed"
    if int(item.get("size") or 0) > MAX_FILE_BYTES:
        return None, "larger than 50 MB"
    return safe_name(name), "file"


def import_folder(cfg: Config, person_id: str, folder: str) -> dict:
    check_person(cfg, person_id)
    root = person_root(cfg, person_id)
    mpath = manifest_path(cfg, person_id)
    manifest = read_json(mpath, {}) or {}
    entries: dict = manifest.setdefault("files", {})
    imported, skipped = [], []
    files_root = cfg.files.resolve()

    with DriveSession(cfg, person_id) as s:
        top = resolve_folder(s, folder)
        top_dir = root / safe_name(top["name"], "drive-folder")
        work: list[tuple[dict, Path]] = []
        for item in _list_children(s, top["id"]):
            if item.get("mimeType") == FOLDER_MIME:
                sub_dir = top_dir / safe_name(item["name"], "folder")
                for sub in _list_children(s, item["id"]):
                    if sub.get("mimeType") == FOLDER_MIME:
                        skipped.append({"name": f"{item['name']}/{sub['name']}", "reason": "folder two levels down"})
                    else:
                        work.append((sub, sub_dir))
            else:
                work.append((item, top_dir))

        used: set[Path] = set()
        for item, folder_dir in work:
            local, reason = _plan_name(item)
            if local is None:
                skipped.append({"name": item.get("name", ""), "reason": reason})
                continue
            prev = entries.get(item["id"])
            dest = (files_root / prev["path"]) if prev else folder_dir / local
            if dest in used or (not prev and dest.exists()):
                stem, dot, ext = local.rpartition(".")
                tag = safe_name(item["id"][:8])
                dest = folder_dir / (f"{stem}-{tag}.{ext}" if dot else f"{local}-{tag}")
            used.add(dest)
            # Never write anywhere but this person's from-drive folder.
            dest_parent = dest.parent
            if root.resolve() not in (dest_parent.resolve(), *dest_parent.resolve().parents) or dest.is_symlink():
                skipped.append({"name": item.get("name", ""), "reason": "unsafe destination"})
                continue
            rel = dest.relative_to(files_root).as_posix()
            if prev and prev.get("modifiedTime") == item.get("modifiedTime") and dest.is_file():
                skipped.append({"name": item.get("name", ""), "reason": "unchanged"})
                continue
            dest_parent.mkdir(parents=True, exist_ok=True)
            os.chmod(dest_parent, 0o700)
            try:
                size = _download(s, item, dest)
            except CloudError as e:
                skipped.append({"name": item.get("name", ""), "reason": str(e)})
                continue
            entries[item["id"]] = {"modifiedTime": item.get("modifiedTime"), "path": rel, "bytes": size}
            imported.append(rel)

    manifest["last_import"] = {"at": int(time.time()), "folder": top["name"], "folder_id": top["id"],
                               "imported": len(imported), "skipped": len(skipped)}
    write_json(mpath, manifest)
    if imported:
        Store(cfg).reindex()
    return {"imported": len(imported), "skipped": len(skipped), "folder": top["name"],
            "folder_id": top["id"], "files": imported, "skipped_files": skipped}


def last_import(cfg: Config, person_id: str) -> dict | None:
    return (read_json(manifest_path(cfg, person_id), {}) or {}).get("last_import")
