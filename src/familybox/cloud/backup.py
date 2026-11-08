"""Encrypted backup of the whole box to Google Drive. Google only ever holds ciphertext.

What is backed up: <home>/files and <home>/family.toml. Never <home>/runtime (tokens, TLS keys,
sessions, the backup key, the search index).

File format (.fbx), version 1:
    magic  b"FBXBKUP"  (7 bytes)
    version            (1 byte, = 1)
    key id             (8 bytes, BLAKE2b of the key; lets restore say "wrong recovery code")
    secretstream header (24 bytes)
    chunks: libsodium secretstream XChaCha20-Poly1305, 64 KiB of tar each (+17 bytes), last one TAG_FINAL.
Every chunk is authenticated with the first 16 bytes as associated data, so the header can't be swapped.
"""

from __future__ import annotations

import base64
import hashlib
import io
import json
import os
import secrets
import tarfile
import tempfile
import time
from datetime import datetime, timezone
from pathlib import Path, PurePosixPath
from typing import BinaryIO

from nacl import bindings as sodium
from nacl.exceptions import CryptoError

from .. import config as config_mod
from ..config import Config
from ..store import Store
from ._common import DRIVE_API, DRIVE_UPLOAD, CloudError, admin_id, cloud_dir, raise_for_google, read_json, \
    write_json, write_private
from .session import DriveSession

MAGIC = b"FBXBKUP"
VERSION = 1
CHUNK = 64 * 1024
ABYTES = sodium.crypto_secretstream_xchacha20poly1305_ABYTES
HEADERBYTES = sodium.crypto_secretstream_xchacha20poly1305_HEADERBYTES
KEYBYTES = sodium.crypto_secretstream_xchacha20poly1305_KEYBYTES
TAG_FINAL = sodium.crypto_secretstream_xchacha20poly1305_TAG_FINAL
TAG_MESSAGE = sodium.crypto_secretstream_xchacha20poly1305_TAG_MESSAGE
PREFIX_LEN = len(MAGIC) + 1 + 8
MULTIPART_MAX = 5 * 1024 * 1024        # Google's advice: multipart up to 5 MB, resumable above
RESUMABLE_CHUNK = 8 * 1024 * 1024      # multiple of 256 KiB
BACKUP_MIME = "application/octet-stream"
TOP_LEVEL = ("files", "family.toml")


class BackupError(CloudError):
    pass


# --- key and recovery code ----------------------------------------------------------------------

def key_path(cfg: Config) -> Path:
    return cloud_dir(cfg) / "backup.key"


def key_id(key: bytes) -> bytes:
    return hashlib.blake2b(key, digest_size=8, person=b"familybox-keyid").digest()


def recovery_code(key: bytes) -> str:
    s = base64.b32encode(key).decode().rstrip("=")
    return "-".join(s[i:i + 4] for i in range(0, len(s), 4))


def parse_recovery_code(code: str) -> bytes:
    s = "".join(ch for ch in (code or "").upper() if ch.isalnum())
    s = s.replace("0", "O").replace("1", "I").replace("8", "B")  # common misreads; base32 has no 0, 1, 8
    try:
        key = base64.b32decode(s + "=" * (-len(s) % 8))
    except ValueError:
        raise BackupError("that recovery code is not valid") from None
    if len(key) != KEYBYTES:
        raise BackupError("that recovery code is the wrong length")
    return key


def init_backup_key(cfg: Config, *, force: bool = False) -> str:
    """Make the backup key and return its recovery code. Shown once: the box never prints it again."""
    path = key_path(cfg)
    if path.exists() and not force:
        raise BackupError("a backup key already exists; old backups need its recovery code. "
                          "Pass force=True only if you mean to replace it.")
    key = sodium.crypto_secretstream_xchacha20poly1305_keygen()
    write_private(path, key)
    return recovery_code(key)


def load_key(cfg: Config) -> bytes:
    try:
        key = key_path(cfg).read_bytes()
    except FileNotFoundError:
        raise BackupError("no backup key yet; run `familybox cloud backup-key` first") from None
    if len(key) != KEYBYTES:
        raise BackupError("the backup key file is damaged")
    return key


# --- encryption ---------------------------------------------------------------------------------

def encrypt_stream(src: BinaryIO, dst: BinaryIO, key: bytes) -> None:
    prefix = MAGIC + bytes([VERSION]) + key_id(key)
    state = sodium.crypto_secretstream_xchacha20poly1305_state()
    header = sodium.crypto_secretstream_xchacha20poly1305_init_push(state, key)
    dst.write(prefix + header)
    chunk = src.read(CHUNK)
    while True:
        nxt = src.read(CHUNK)
        tag = TAG_MESSAGE if nxt else TAG_FINAL
        dst.write(sodium.crypto_secretstream_xchacha20poly1305_push(state, chunk, prefix, tag))
        if not nxt:
            return
        chunk = nxt


def decrypt_stream(src: BinaryIO, dst: BinaryIO, key: bytes) -> None:
    prefix = src.read(PREFIX_LEN)
    if len(prefix) != PREFIX_LEN or not prefix.startswith(MAGIC):
        raise BackupError("this is not a familybox backup")
    if prefix[len(MAGIC)] != VERSION:
        raise BackupError(f"backup format version {prefix[len(MAGIC)]} is not supported")
    if not secrets.compare_digest(prefix[len(MAGIC) + 1:], key_id(key)):
        raise BackupError("wrong recovery code for this backup")
    header = src.read(HEADERBYTES)
    if len(header) != HEADERBYTES:
        raise BackupError("backup is cut short")
    state = sodium.crypto_secretstream_xchacha20poly1305_state()
    try:
        sodium.crypto_secretstream_xchacha20poly1305_init_pull(state, header, key)
        while True:
            c = src.read(CHUNK + ABYTES)
            if not c:
                raise BackupError("backup is cut short (no final chunk)")
            m, tag = sodium.crypto_secretstream_xchacha20poly1305_pull(state, c, prefix)
            dst.write(m)
            if tag == TAG_FINAL:
                if src.read(1):
                    raise BackupError("backup has extra data after the end")
                return
    except CryptoError:
        raise BackupError("backup failed its integrity check (damaged or changed)") from None


# --- tar ----------------------------------------------------------------------------------------

def _tar_filter(info: tarfile.TarInfo) -> tarfile.TarInfo | None:
    if not (info.isfile() or info.isdir()):
        return None  # no symlinks, devices or fifos in a backup
    parts = PurePosixPath(info.name).parts
    if any(p.startswith(".") and p.endswith((".tmp", ".part")) for p in parts):
        return None
    info.uid = info.gid = 0
    info.uname = info.gname = ""
    info.mode = 0o700 if info.isdir() else 0o600
    return info


def build_tar(cfg: Config, out: BinaryIO) -> None:
    home = cfg.home.resolve()
    runtime = cfg.runtime.resolve()
    with tarfile.open(fileobj=out, mode="w", format=tarfile.PAX_FORMAT) as tar:
        toml = home / "family.toml"
        if toml.is_file() and not toml.is_symlink():
            tar.add(toml, arcname="family.toml", filter=_tar_filter)
        files = home / "files"
        if files.is_dir() and not files.is_symlink():
            tar.add(files, arcname="files", recursive=False, filter=_tar_filter)
            for dirpath, dirnames, filenames in os.walk(files):
                d = Path(dirpath)
                # Do not walk into runtime even if someone moved it under files/.
                dirnames[:] = sorted(n for n in dirnames
                                     if not (d / n).is_symlink() and (d / n).resolve() != runtime)
                for n in sorted(dirnames) + sorted(filenames):
                    p = d / n
                    if p.is_symlink() or runtime in p.resolve().parents:
                        continue
                    tar.add(p, arcname=p.relative_to(home).as_posix(), recursive=False, filter=_tar_filter)


def _check_member(m: tarfile.TarInfo) -> PurePosixPath:
    name = m.name
    p = PurePosixPath(name)
    if not name or p.is_absolute() or name.startswith(("/", "\\")) or "\\" in name or ".." in p.parts:
        raise BackupError(f"backup has an unsafe path: {name!r}")
    if p.parts[0] not in TOP_LEVEL or (p.parts[0] == "family.toml" and len(p.parts) > 1):
        raise BackupError(f"backup has an unexpected path: {name!r}")
    if not (m.isfile() or m.isdir()):
        raise BackupError(f"backup has a link or special file: {name!r}")
    return p


def extract_tar(tar_path: Path, home: Path) -> dict:
    """Validate every member first, then write. Nothing is written if any member is unsafe."""
    home = home.resolve()
    with tarfile.open(tar_path, mode="r:") as tar:
        members = tar.getmembers()
        checked = [(m, _check_member(m)) for m in members]
        for m, p in checked:
            target = home.joinpath(*p.parts)
            # Refuse to follow a symlink that already sits on the way to the target.
            cur = home
            for part in p.parts[:-1]:
                cur = cur / part
                if cur.is_symlink() or (cur.exists() and not cur.is_dir()):
                    raise BackupError(f"restore path is blocked by a link or file: {cur.relative_to(home)}")
            if target.is_symlink():
                raise BackupError(f"restore target is a link: {p}")
        n_files = n_bytes = 0
        for m, p in checked:
            target = home.joinpath(*p.parts)
            if m.isdir():
                target.mkdir(parents=True, exist_ok=True)
                os.chmod(target, 0o700)
                continue
            target.parent.mkdir(parents=True, exist_ok=True)
            src = tar.extractfile(m)
            data = src.read() if src else b""
            write_private(target, data)
            n_files += 1
            n_bytes += len(data)
    return {"files": n_files, "bytes": n_bytes}


# --- Drive upload / download --------------------------------------------------------------------

def _upload(s: DriveSession, path: Path, name: str) -> str:
    meta = {"name": name, "mimeType": BACKUP_MIME, "appProperties": {"familybox": "backup", "format": str(VERSION)}}
    size = path.stat().st_size
    params = {"uploadType": "multipart", "fields": "id,name,size"}
    if size <= MULTIPART_MAX:
        boundary = "fbx" + secrets.token_hex(16)
        body = io.BytesIO()
        body.write(f"--{boundary}\r\nContent-Type: application/json; charset=UTF-8\r\n\r\n".encode())
        body.write(json.dumps(meta).encode())
        body.write(f"\r\n--{boundary}\r\nContent-Type: {BACKUP_MIME}\r\n\r\n".encode())
        body.write(path.read_bytes())
        body.write(f"\r\n--{boundary}--\r\n".encode())
        r = s.request("POST", DRIVE_UPLOAD, params=params, content=body.getvalue(),
                      headers={"Content-Type": f"multipart/related; boundary={boundary}"})
        raise_for_google(r, "uploading the backup")
        return r.json()["id"]
    # Larger backups: resumable upload in 8 MiB pieces.
    params["uploadType"] = "resumable"
    r = s.request("POST", DRIVE_UPLOAD, params=params, json=meta,
                  headers={"X-Upload-Content-Type": BACKUP_MIME, "X-Upload-Content-Length": str(size)})
    raise_for_google(r, "starting the backup upload")
    session_url = r.headers.get("Location")
    if not session_url:
        raise BackupError("Google did not return an upload address")
    with path.open("rb") as f:
        offset = 0
        while offset < size:
            piece = f.read(RESUMABLE_CHUNK)
            end = offset + len(piece) - 1
            r = s.request("PUT", session_url, content=piece,
                          headers={"Content-Range": f"bytes {offset}-{end}/{size}"})
            if r.status_code == 308:
                rng = r.headers.get("Range")
                offset = int(rng.rsplit("-", 1)[1]) + 1 if rng else 0
                f.seek(offset)
                continue
            raise_for_google(r, "uploading the backup")
            return r.json()["id"]
    raise BackupError("upload ended without a file id")


def _download(s: DriveSession, file_id: str, dest: Path) -> dict:
    r = s.request("GET", f"{DRIVE_API}/files/{file_id}", params={"fields": "id,name,size,sha256Checksum"})
    raise_for_google(r, "finding the backup")
    meta = r.json()
    with dest.open("wb") as f, s.stream("GET", f"{DRIVE_API}/files/{file_id}", params={"alt": "media"}) as resp:
        if resp.status_code >= 400:
            resp.read()
            raise_for_google(resp, "downloading the backup")
        for chunk in resp.iter_bytes(CHUNK):
            f.write(chunk)
    return meta


def _sha256(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as f:
        for b in iter(lambda: f.read(1 << 20), b""):
            h.update(b)
    return h.hexdigest()


def _state_path(cfg: Config) -> Path:
    return cloud_dir(cfg) / "backup_state.json"


def last_backup(cfg: Config) -> dict | None:
    return (read_json(_state_path(cfg), {}) or {}).get("last_backup")


def _tmpdir(cfg: Config) -> Path:
    d = cloud_dir(cfg) / "tmp"
    d.mkdir(exist_ok=True)
    os.chmod(d, 0o700)
    return d


def make_backup_file(cfg: Config, dest: Path) -> dict:
    """Write an encrypted backup to `dest` (on the box). Returns its size and sha256."""
    key = load_key(cfg)
    with tempfile.TemporaryFile(dir=_tmpdir(cfg)) as plain:
        build_tar(cfg, plain)
        plain.seek(0)
        fd = os.open(dest, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
        with os.fdopen(fd, "wb") as out:
            encrypt_stream(plain, out, key)
    return {"bytes": dest.stat().st_size, "sha256": _sha256(dest)}


def backup_now(cfg: Config) -> dict:
    admin = admin_id(cfg)
    load_key(cfg)  # fail early, before talking to Google
    stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    name = f"familybox-backup-{stamp}.fbx"
    tmp = _tmpdir(cfg) / f"{secrets.token_hex(8)}.fbx"
    try:
        info = make_backup_file(cfg, tmp)
        with DriveSession(cfg, admin) as s:
            file_id = _upload(s, tmp, name)
    finally:
        tmp.unlink(missing_ok=True)
    result = {"bytes": info["bytes"], "sha256": info["sha256"], "drive_file_id": file_id, "name": name}
    write_json(_state_path(cfg), {"last_backup": result | {"at": int(time.time()), "by": admin}})
    return result


def restore(cfg: Config, source: str, recovery_code_text: str) -> dict:
    """Restore from a Drive file id or a local .fbx path into the box's home."""
    key = parse_recovery_code(recovery_code_text)
    tmpdir = _tmpdir(cfg)
    local = Path(source).expanduser()
    cipher_tmp = None
    try:
        if local.is_file():
            cipher = local
        else:
            if not all(ch.isalnum() or ch in "-_" for ch in source) or not source:
                raise BackupError(f"{source!r} is neither a file on this box nor a Drive file id")
            cipher_tmp = cipher = tmpdir / f"{secrets.token_hex(8)}.fbx"
            with DriveSession(cfg, admin_id(cfg)) as s:
                meta = _download(s, source, cipher)
            remote_sha = meta.get("sha256Checksum")
            if remote_sha and remote_sha.lower() != _sha256(cipher):
                raise BackupError("download did not match Google's checksum")
        digest = _sha256(cipher)
        known = last_backup(cfg)
        if known and known.get("drive_file_id") == source and known.get("sha256") != digest:
            raise BackupError("this backup does not match the checksum recorded when it was made")
        with tempfile.NamedTemporaryFile(dir=tmpdir, suffix=".tar", delete=False) as plain:
            plain_path = Path(plain.name)
            try:
                with cipher.open("rb") as src:
                    decrypt_stream(src, plain, key)
            except BaseException:
                plain.close()
                plain_path.unlink(missing_ok=True)
                raise
        try:
            os.chmod(plain_path, 0o600)
            try:
                counts = extract_tar(plain_path, cfg.home)
            except tarfile.TarError:
                raise BackupError("backup decrypted but its archive is damaged") from None
        finally:
            plain_path.unlink(missing_ok=True)
    finally:
        if cipher_tmp:
            cipher_tmp.unlink(missing_ok=True)
    Store(config_mod.load(cfg.home)).reindex()
    return {"restored_files": counts["files"], "bytes": counts["bytes"], "sha256": digest, "source": source}
