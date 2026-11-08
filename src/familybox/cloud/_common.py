"""Shared pieces for the Google Drive features: paths, private file writes, the HTTP client factory."""

from __future__ import annotations

import json
import os
import re
import secrets
from pathlib import Path
from typing import Callable

import httpx

from ..config import Config

GOOGLE_AUTH_URL = "https://accounts.google.com/o/oauth2/v2/auth"
GOOGLE_TOKEN_URL = "https://oauth2.googleapis.com/token"
GOOGLE_REVOKE_URL = "https://oauth2.googleapis.com/revoke"
GOOGLE_USERINFO_URL = "https://openidconnect.googleapis.com/v1/userinfo"
DRIVE_API = "https://www.googleapis.com/drive/v3"
DRIVE_UPLOAD = "https://www.googleapis.com/upload/drive/v3/files"

PERSON_ID_RE = re.compile(r"^[a-z0-9][a-z0-9_-]{0,63}$")


class CloudError(Exception):
    """A problem the person can act on (not connected, no key, wrong code). The message is safe to show."""


# --- HTTP ---------------------------------------------------------------------------------------
# Tests swap this for a factory that returns httpx.Client(transport=httpx.MockTransport(...)).

def _default_client() -> httpx.Client:
    return httpx.Client(timeout=httpx.Timeout(60.0, connect=15.0), follow_redirects=False)


_client_factory: Callable[[], httpx.Client] = _default_client


def set_client_factory(factory: Callable[[], httpx.Client] | None) -> None:
    """Use a different httpx.Client maker (tests, proxies). None restores the default."""
    global _client_factory
    _client_factory = factory or _default_client


def http() -> httpx.Client:
    return _client_factory()


# --- paths and private files --------------------------------------------------------------------

def cloud_dir(cfg: Config) -> Path:
    d = cfg.runtime / "cloud"
    d.mkdir(parents=True, exist_ok=True)
    os.chmod(d, 0o700)
    return d


def check_person(cfg: Config, person_id: str) -> str:
    if not isinstance(person_id, str) or not PERSON_ID_RE.match(person_id):
        raise CloudError("that is not a valid person id")
    cfg.person(person_id)  # KeyError for unknown people
    return person_id


def admin_id(cfg: Config) -> str:
    admins = sorted(p.id for p in cfg.people.values() if p.admin)
    if not admins:
        raise CloudError("no admin person in family.toml; backups use the admin's Google connection")
    return admins[0]


def write_private(path: Path, data: bytes) -> None:
    """Write a file only the box user can read (0600), atomically."""
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_name(f".{path.name}.{secrets.token_hex(4)}.tmp")
    fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    try:
        with os.fdopen(fd, "wb") as f:
            f.write(data)
            f.flush()
            os.fsync(f.fileno())
        os.chmod(tmp, 0o600)
        os.replace(tmp, path)
    except BaseException:
        tmp.unlink(missing_ok=True)
        raise


def read_json(path: Path, default=None):
    try:
        return json.loads(path.read_text())
    except FileNotFoundError:
        return default
    except ValueError:
        return default


def write_json(path: Path, data) -> None:
    write_private(path, json.dumps(data, indent=1, sort_keys=True).encode())


def raise_for_google(resp: httpx.Response, what: str) -> None:
    """Turn a Google error into a CloudError without echoing tokens or bodies we do not understand."""
    if resp.status_code < 400:
        return
    reason = ""
    try:
        body = resp.json()
        err = body.get("error")
        if isinstance(err, dict):
            reason = str(err.get("message", ""))[:200]
        elif isinstance(err, str):
            reason = err[:100]
    except ValueError:
        pass
    raise CloudError(f"Google said no to {what} (HTTP {resp.status_code}{': ' + reason if reason else ''})")
