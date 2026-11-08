"""Google Drive for the family box.

(A) Import: a person connects their Google account and pulls one Drive folder, read-only, into
    files/people/<person>/from-drive/.
(B) Backup: the whole box (files/ and family.toml, never runtime/) is encrypted on the box with
    libsodium secretstream and uploaded as an app-created Drive file. Google only holds ciphertext.

The web UI and the CLI call exactly these functions. See docs/CLOUD.md.
"""

from __future__ import annotations

from ..config import Config
from . import backup as _backup
from . import drive_import as _import
from . import oauth as _oauth
from ._common import CloudError, check_person, set_client_factory
from .backup import BackupError, init_backup_key, restore

__all__ = ["status", "begin_connect", "finish_connect", "import_folder", "backup_now", "init_backup_key",
           "restore", "disconnect", "CloudError", "BackupError", "set_client_factory"]


def status(cfg: Config, person_id: str) -> dict:
    check_person(cfg, person_id)
    tok = _oauth.load_token(cfg, person_id)
    return {
        "connected": bool(tok and tok.get("refresh_token")),
        "account_email": (tok or {}).get("account_email"),
        "last_import": _import.last_import(cfg, person_id),
        "last_backup": _backup.last_backup(cfg),
        "backup_key_set": _backup.key_path(cfg).exists(),
    }


def begin_connect(cfg: Config, person_id: str, redirect_uri: str) -> str:
    return _oauth.begin_connect(cfg, person_id, redirect_uri)


def finish_connect(cfg: Config, state: str, code: str) -> dict:
    person = _oauth.finish_connect_tokens(cfg, state, code)
    return status(cfg, person) | {"person": person}


def import_folder(cfg: Config, person_id: str, folder: str) -> dict:
    return _import.import_folder(cfg, person_id, folder)


def backup_now(cfg: Config) -> dict:
    return _backup.backup_now(cfg)


def disconnect(cfg: Config, person_id: str) -> dict:
    """Revoke the Google grant (best effort) and delete this person's tokens. Imported files stay."""
    check_person(cfg, person_id)
    _oauth.revoke_and_forget(cfg, person_id)
    return status(cfg, person_id)
