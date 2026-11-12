"""Signed automatic updates for the box's code.

A release is three files in one folder (a web address or a file:// folder):

  manifest.json       {"version", "commit", "sha256", "file", "created", "min_version"?}
  manifest.json.sig   base64 Ed25519 signature over the exact bytes of manifest.json
  <file>              the code as a tar.gz made by `git archive` (scripts/release.py makes all three)

The box installs a release only if all of these hold, checked in this order:
  1. the signature matches the release key pinned in this package (release_key.pub), checked before
     anything in the manifest is read;
  2. its version is newer than the installed one (no going back), and the installed version is at least
     its min_version, if it has one;
  3. the tarball's SHA-256 matches the manifest;
  4. no tarball entry is an absolute path, uses "..", is a device file, or links outside the folder.

Installing: unpack to <code>.next, `uv sync --frozen` there, import the box once there, then rename
<code> to <code>.prev and <code>.next to <code>, record the version, restart the service, and wait for
the page to answer. If it doesn't, put <code>.prev back and restart again. The box's home (its files,
logs and keys) is a different folder and is never touched.
"""

from __future__ import annotations

import base64
import binascii
import contextlib
import fcntl
import hashlib
import hmac
import json
import os
import posixpath
import re
import shutil
import ssl
import subprocess
import sys
import tarfile
import tempfile
import time
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Callable

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

DEFAULT_URL = "https://github.com/Ethan-Castro/familybox/releases/latest/download/"
MANIFEST = "manifest.json"
SIGNATURE = "manifest.json.sig"
RELEASE_RECORD = ".familybox-release.json"
PUBLIC_KEY_FILE = Path(__file__).with_name("release_key.pub")

MAX_MANIFEST = 64 * 1024
MAX_SIGNATURE = 1024
MAX_TARBALL = 200 * 1024 * 1024
MAX_UNPACKED = 1024 * 1024 * 1024           # a signed release this big would be a mistake; refuse it
MAX_MEMBERS = 50_000
NET_TIMEOUT = 30                             # seconds per network read
STEP_TIMEOUT = 15 * 60                       # seconds for uv sync or the self-check
HEALTH_TIMEOUT = 60.0

_FILE_NAME = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,120}\.tar\.gz$")
_HEX40 = re.compile(r"^[0-9a-f]{40}$")
_HEX64 = re.compile(r"^[0-9a-f]{64}$")


class UpdateError(Exception):
    """An update was refused or failed. The message is plain words for the person reading the log."""


# ---- keys and signatures --------------------------------------------------------------------------

def public_key_from_text(text: str | bytes) -> Ed25519PublicKey:
    """A public key written as base64 of its raw 32 bytes."""
    try:
        raw = base64.b64decode(text.strip(), validate=True)
    except (binascii.Error, ValueError):
        raise UpdateError("The release public key is not valid base64.") from None
    if len(raw) != 32:
        raise UpdateError("The release public key is not 32 bytes, so it is not an Ed25519 key.")
    return Ed25519PublicKey.from_public_bytes(raw)


def public_key_text(key: Ed25519PublicKey) -> str:
    return base64.b64encode(key.public_bytes(Encoding.Raw, PublicFormat.Raw)).decode()


def pinned_key() -> Ed25519PublicKey:
    """The release key this copy of the box trusts. It ships inside the code, so only a release signed
    by the old key can change it."""
    if not PUBLIC_KEY_FILE.exists():
        raise UpdateError(f"No release key in this install ({PUBLIC_KEY_FILE.name} is missing), so no update "
                          "can be trusted.")
    return public_key_from_text(PUBLIC_KEY_FILE.read_text())


def verify_manifest(raw: bytes, sig_text: bytes, key: Ed25519PublicKey) -> dict:
    """Check the signature over the exact manifest bytes, and only then read the manifest."""
    try:
        sig = base64.b64decode(sig_text.strip(), validate=True)
    except (binascii.Error, ValueError):
        raise UpdateError("The release signature file is not valid base64. Nothing was installed.") from None
    if len(sig) != 64:
        raise UpdateError("The release signature is the wrong length. Nothing was installed.")
    try:
        key.verify(sig, raw)
    except InvalidSignature:
        raise UpdateError("The release is not signed by our release key (the signature does not match). "
                          "Nothing was installed.") from None
    try:
        m = json.loads(raw)
    except ValueError:
        raise UpdateError("The signed manifest is not valid JSON.") from None
    return _check_fields(m)


def _check_fields(m) -> dict:
    if not isinstance(m, dict):
        raise UpdateError("The signed manifest is not a JSON object.")

    def whole(name, required=True):
        v = m.get(name)
        if v is None and not required:
            return None
        if not isinstance(v, int) or isinstance(v, bool) or v <= 0:
            raise UpdateError(f"The signed manifest's {name} is not a positive whole number.")
        return v

    whole("version")
    whole("min_version", required=False)
    if not isinstance(m.get("commit"), str) or not _HEX40.match(m["commit"]):
        raise UpdateError("The signed manifest's commit is not a git commit id.")
    if not isinstance(m.get("sha256"), str) or not _HEX64.match(m["sha256"]):
        raise UpdateError("The signed manifest's sha256 is not a SHA-256 in hex.")
    if not isinstance(m.get("file"), str) or not _FILE_NAME.match(m["file"]):
        raise UpdateError("The signed manifest's file name is not a plain .tar.gz name.")
    if not isinstance(m.get("created"), str):
        raise UpdateError("The signed manifest has no creation time.")
    return m


def sign_release(out_dir: Path, tarball: Path, *, version: int, commit: str, private_key: Ed25519PrivateKey,
                 min_version: int | None = None, created: str | None = None) -> dict:
    """Write manifest.json and manifest.json.sig next to a tarball already in out_dir. Used by
    scripts/release.py on the developer's laptop and by the tests; the box itself never signs."""
    if tarball.parent.resolve() != out_dir.resolve():
        raise UpdateError("The tarball must be in the release folder.")
    m = {"version": int(version), "commit": commit, "sha256": _sha256_file(tarball), "file": tarball.name,
         "created": created or datetime.now(timezone.utc).isoformat(timespec="seconds")}
    if min_version is not None:
        m["min_version"] = int(min_version)
    _check_fields(m)
    raw = (json.dumps(m, indent=1, sort_keys=True) + "\n").encode()
    (out_dir / MANIFEST).write_bytes(raw)
    (out_dir / SIGNATURE).write_bytes(base64.b64encode(private_key.sign(raw)) + b"\n")
    return m


def _sha256_file(path: Path) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


# ---- fetching -------------------------------------------------------------------------------------

class _HttpsOnlyRedirects(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        if urllib.parse.urlsplit(newurl).scheme != "https":
            raise UpdateError(f"The update server tried to send the box to a non-HTTPS address ({newurl}). Refused.")
        return super().redirect_request(req, fp, code, msg, headers, newurl)


def _check_source(source: str) -> str:
    scheme = urllib.parse.urlsplit(source).scheme
    if scheme not in ("https", "file"):
        raise UpdateError(f"Update source {source!r} must start with https:// or file://. Plain http is refused.")
    return source if source.endswith("/") else source + "/"


def _open(source: str, name: str):
    """A readable stream for one file of the release, plus its declared size if known."""
    url = source + urllib.parse.quote(name)
    if source.startswith("file:"):
        path = Path(urllib.request.url2pathname(urllib.parse.urlsplit(url).path))
        try:
            f = open(path, "rb")
        except FileNotFoundError:
            raise UpdateError(f"{name} is not in the update folder {source}.") from None
        return f, path.stat().st_size
    opener = urllib.request.build_opener(_HttpsOnlyRedirects(),
                                         urllib.request.HTTPSHandler(context=ssl.create_default_context()))
    req = urllib.request.Request(url, headers={"User-Agent": "familybox-updater"})
    try:
        r = opener.open(req, timeout=NET_TIMEOUT)
    except urllib.error.HTTPError as e:
        if e.code == 404:
            raise UpdateError(f"{name} was not found at {source} (404).") from None
        raise UpdateError(f"The update server answered {e.code} for {name}.") from None
    except (urllib.error.URLError, OSError) as e:
        reason = getattr(e, "reason", e)
        raise UpdateError(f"Could not reach the update server for {name}: {reason}.") from None
    length = r.headers.get("Content-Length")
    return r, int(length) if length and length.isdigit() else None


def fetch_bytes(source: str, name: str, cap: int) -> bytes:
    f, size = _open(source, name)
    with f:
        if size is not None and size > cap:
            raise UpdateError(f"{name} is {size} bytes, over the {cap}-byte limit. Refused.")
        data = f.read(cap + 1)
    if len(data) > cap:
        raise UpdateError(f"{name} is over the {cap}-byte limit. Refused.")
    return data


def fetch_to_file(source: str, name: str, cap: int, dest: Path) -> str:
    """Download to dest with a size cap and return its SHA-256."""
    f, size = _open(source, name)
    h = hashlib.sha256()
    total = 0
    with f:
        if size is not None and size > cap:
            raise UpdateError(f"{name} is {size} bytes, over the {cap}-byte limit. Refused.")
        with open(dest, "wb") as out:
            for chunk in iter(lambda: f.read(1 << 20), b""):
                total += len(chunk)
                if total > cap:
                    raise UpdateError(f"{name} is over the {cap}-byte limit. Refused.")
                h.update(chunk)
                out.write(chunk)
    return h.hexdigest()


# ---- unpacking ------------------------------------------------------------------------------------

def check_members(members: list[tarfile.TarInfo]) -> None:
    """Refuse the whole tarball if any entry could write outside its folder or is not a plain file,
    folder or link inside it."""
    if len(members) > MAX_MEMBERS:
        raise UpdateError(f"The release has more than {MAX_MEMBERS} entries. Refused.")
    total = 0
    for m in members:
        name = m.name
        if name.startswith("/") or name.startswith("\\") or re.match(r"^[A-Za-z]:", name):
            raise UpdateError(f"The release has an entry with an absolute path ({name}). Refused.")
        if ".." in name.replace("\\", "/").split("/"):
            raise UpdateError(f"The release has an entry that climbs out of its folder ({name}). Refused.")
        if m.ischr() or m.isblk() or m.isfifo() or m.isdev():
            raise UpdateError(f"The release has a device or pipe entry ({name}). Refused.")
        if m.issym() or m.islnk():
            target = m.linkname
            if target.startswith("/") or target.startswith("\\"):
                raise UpdateError(f"The release has a link to an absolute path ({name} -> {target}). Refused.")
            if m.islnk():      # a hard link names another entry by its archive path
                outside = ".." in target.replace("\\", "/").split("/")
            elif posixpath.normpath(target) != target:
                # "s/../.." can look inside on paper and lead out through another link. git never
                # writes targets like that, so refuse them rather than guess.
                raise UpdateError(f"The release has a link that may point outside its folder ({name} -> "
                                  f"{target}, not in plain form). Refused.")
            else:              # a symbolic link is read from the folder it sits in
                resolved = posixpath.normpath(posixpath.join(posixpath.dirname(name), target))
                outside = resolved == ".." or resolved.startswith("../")
            if outside:
                raise UpdateError(f"The release has a link that points outside its folder ({name} -> {target}). "
                                  "Refused.")
        elif not (m.isfile() or m.isdir()):
            raise UpdateError(f"The release has an entry of an unknown kind ({name}). Refused.")
        total += max(m.size, 0)
        if total > MAX_UNPACKED:
            raise UpdateError("The release unpacks to more than 1 GB. Refused.")


def safe_extract(tarball: Path, dest: Path) -> None:
    """Unpack into dest (which must not exist yet). Three layers: check every entry first, unpack with
    Python's "data" filter, then check where every link really points once unpacked."""
    try:
        with tarfile.open(tarball, "r:gz") as tf:
            members = tf.getmembers()
            check_members(members)
            dest.mkdir(mode=0o755)
            tf.extractall(dest, members=members, filter="data")
    except tarfile.TarError as e:
        raise UpdateError(f"The release tarball could not be unpacked safely: {e}.") from None
    except EOFError:
        raise UpdateError("The release tarball is cut short.") from None
    root = dest.resolve()
    for dirpath, dirnames, filenames in os.walk(dest):
        for n in dirnames + filenames:
            p = Path(dirpath) / n
            if p.is_symlink():
                real = p.resolve()
                if real != root and root not in real.parents:
                    raise UpdateError(f"The release has a link that points outside its folder "
                                      f"({p.relative_to(dest)}). Refused.")


# ---- the install ----------------------------------------------------------------------------------

def default_uv() -> str:
    """The uv that runs this box: `uv run` sets UV to its own path."""
    for cand in (os.environ.get("FAMILYBOX_UPDATE_UV"), os.environ.get("UV"),
                 str(Path.home() / ".local" / "bin" / "uv")):
        if cand and Path(cand).is_file() and os.access(cand, os.X_OK):
            return cand
    return shutil.which("uv") or "uv"


def default_code_dir() -> Path:
    return Path(os.environ.get("FAMILYBOX_CODE_DIR") or Path.home() / "familybox").expanduser()


def default_home() -> Path:
    return Path(os.environ.get("FAMILYBOX_HOME") or Path.home() / "familybox-home").expanduser()


def https_answers(port: int) -> bool:
    """Does the box's own page answer on this board? The box made its own certificate, so this one local
    check does not verify it."""
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}), urllib.request.HTTPSHandler(context=ctx))
    try:
        with opener.open(f"https://127.0.0.1:{port}/favicon.ico", timeout=3) as r:
            return r.status < 500
    except urllib.error.HTTPError as e:
        return e.code < 500
    except (urllib.error.URLError, OSError, ssl.SSLError):
        return False


class Log:
    """Appends to <home>/runtime/updates.log (0600) when that folder exists, else writes to stderr."""

    def __init__(self, home: Path | None, echo: bool = False):
        runtime = home / "runtime" if home else None
        self.path = runtime / "updates.log" if runtime and runtime.is_dir() else None
        self.echo = echo

    def __call__(self, msg: str) -> None:
        line = f"{datetime.now(timezone.utc).isoformat(timespec='seconds')}  {msg}\n"
        if self.path:
            fd = os.open(self.path, os.O_WRONLY | os.O_APPEND | os.O_CREAT, 0o600)
            try:
                os.write(fd, line.encode())
            finally:
                os.close(fd)
        if self.echo or not self.path:
            sys.stderr.write(line)


@dataclass
class Release:
    manifest: dict
    installed: dict
    source: str
    status: str            # "newer", "same", "older", "failed-before", "too-old-to-update"
    message: str

    @property
    def version(self) -> int:
        return self.manifest["version"]


@dataclass
class Result:
    status: str            # "installed", "up-to-date", "rolled-back"
    message: str
    version: int | None = None


@dataclass
class Updater:
    code_dir: Path = field(default_factory=default_code_dir)
    source: str = field(default_factory=lambda: os.environ.get("FAMILYBOX_UPDATE_URL") or DEFAULT_URL)
    public_key: Ed25519PublicKey | None = None
    home: Path | None = field(default_factory=default_home)
    port: int = 8443
    uv: str = field(default_factory=default_uv)
    # Commands; "{dir}" in any argument becomes the folder being prepared. None = the real defaults.
    sync_cmd: list[str] | None = None
    check_cmd: list[str] | None = None
    restart_cmd: list[str] | None = None
    restart: bool = True                    # False: skip the restart and the health check
    healthy: Callable[[], bool] | None = None
    health_timeout: float = HEALTH_TIMEOUT
    health_interval: float = 2.0
    log: Callable[[str], None] | None = None

    def __post_init__(self):
        self.code_dir = Path(self.code_dir).expanduser().absolute()
        self.source = _check_source(self.source)
        if self.public_key is None:
            self.public_key = pinned_key()
        if self.sync_cmd is None:
            self.sync_cmd = [self.uv, "sync", "--frozen", "--directory", "{dir}"]
        if self.check_cmd is None:
            self.check_cmd = [self.uv, "run", "--frozen", "--directory", "{dir}", "python", "-c",
                              "import familybox.web, familybox.box"]
        if self.restart_cmd is None:
            self.restart_cmd = ["systemctl", "--user", "restart", "familybox.service"]
        if self.healthy is None:
            port = self.port
            self.healthy = lambda: https_answers(port)
        if self.log is None:
            self.log = Log(self.home)

    # paths
    @property
    def next_dir(self) -> Path:
        return self.code_dir.with_name(self.code_dir.name + ".next")

    @property
    def prev_dir(self) -> Path:
        return self.code_dir.with_name(self.code_dir.name + ".prev")

    @property
    def failed_dir(self) -> Path:
        return self.code_dir.with_name(self.code_dir.name + ".failed")

    def installed(self) -> dict:
        p = self.code_dir / RELEASE_RECORD
        try:
            rec = json.loads(p.read_text())
        except FileNotFoundError:
            return {"version": 0}
        except ValueError:
            raise UpdateError(f"{p} is not valid JSON. Fix or remove it before updating.") from None
        if not isinstance(rec, dict) or not isinstance(rec.get("version", 0), int):
            raise UpdateError(f"{p} has no whole-number version. Fix or remove it before updating.")
        rec.setdefault("version", 0)
        return rec

    def _write_record(self, folder: Path, rec: dict) -> None:
        tmp = folder / (RELEASE_RECORD + ".tmp")
        tmp.write_text(json.dumps(rec, indent=1, sort_keys=True) + "\n")
        os.chmod(tmp, 0o644)
        os.replace(tmp, folder / RELEASE_RECORD)

    def _require_install(self) -> None:
        if not self.code_dir.is_dir():
            raise UpdateError(f"There is no install at {self.code_dir}.")
        if (self.code_dir / ".git").exists():
            raise UpdateError(f"{self.code_dir} is a git checkout, not an installed box. An update replaces the "
                              "whole folder, so it only runs on an install made from a release or a git archive.")

    @contextlib.contextmanager
    def _lock(self):
        """One update at a time on this box (the daily timer and someone at the terminal)."""
        with open(self.code_dir.with_name(self.code_dir.name + ".update.lock"), "a") as f:
            try:
                fcntl.flock(f, fcntl.LOCK_EX | fcntl.LOCK_NB)
            except BlockingIOError:
                raise UpdateError("Another update is already running.") from None
            yield

    # check
    def check(self) -> Release:
        with self._lock():
            return self._check()

    def _check(self) -> Release:
        self._recover()
        self._require_install()
        self.log(f"checking for an update at {self.source}")
        raw = fetch_bytes(self.source, MANIFEST, MAX_MANIFEST)
        try:
            sig = fetch_bytes(self.source, SIGNATURE, MAX_SIGNATURE)
        except UpdateError as e:
            raise UpdateError(f"The release has no signature, so it cannot be trusted ({e}) Nothing was "
                              "installed.") from None
        m = verify_manifest(raw, sig, self.public_key)
        inst = self.installed()
        have, offered = inst["version"], m["version"]
        if offered == have:
            status, msg = "same", f"Already up to date (version {have})."
        elif offered < have:
            status, msg = "older", (f"The release offered (version {offered}) is older than the one installed "
                                    f"(version {have}). Refusing to go back.")
        elif inst.get("failed_version") == offered:
            status, msg = "failed-before", (f"Version {offered} failed its check on this box before and was rolled "
                                            "back. Waiting for a newer release. To try it again, remove "
                                            f"failed_version from {self.code_dir / RELEASE_RECORD}.")
        elif m.get("min_version") and have < m["min_version"]:
            status, msg = "too-old-to-update", (f"Version {offered} can only be installed over version "
                                                f"{m['min_version']} or newer, and this box has {have}. "
                                                "Install the release in between first.")
        else:
            status, msg = "newer", f"Version {offered} (commit {m['commit'][:12]}) is available; this box has {have}."
        self.log(f"signature good. {msg}")
        return Release(manifest=m, installed=inst, source=self.source, status=status, message=msg)

    # apply
    def apply(self, release: Release | None = None) -> Result:
        """Install a release from check(), or check and install. Refusals raise UpdateError."""
        with self._lock():
            self._recover()
            if release is None or self.installed()["version"] != release.installed["version"]:
                release = self._check()          # nothing given, or the install changed since that check
            return self._apply_locked(release)

    def _apply_locked(self, rel: Release) -> Result:
        if rel.status != "newer":
            if rel.status in ("same", "failed-before"):
                return Result("up-to-date", rel.message, rel.installed["version"])
            raise UpdateError(rel.message + " Nothing was installed.")
        m = rel.manifest
        parent = self.code_dir.parent
        for stale in (self.next_dir, self.failed_dir):
            if stale.exists():
                self.log(f"removing a leftover {stale.name}")
                shutil.rmtree(stale)
        fd, tmp_name = tempfile.mkstemp(prefix=".familybox-download-", suffix=".tar.gz", dir=parent)
        os.close(fd)
        tmp = Path(tmp_name)
        try:
            self.log(f"downloading {m['file']}")
            digest = fetch_to_file(rel.source, m["file"], MAX_TARBALL, tmp)
            if not hmac.compare_digest(digest, m["sha256"]):
                raise UpdateError(f"The downloaded {m['file']} does not match the signed SHA-256. Refused; nothing "
                                  "was installed.")
            self.log(f"SHA-256 matches. unpacking to {self.next_dir.name}")
            safe_extract(tmp, self.next_dir)
            self.log(f"installing packages in {self.next_dir.name} (uv sync --frozen)")
            self._run(self.sync_cmd, self.next_dir, "Installing the release's packages failed")
            self.log("checking the new code starts (importing the box)")
            self._run(self.check_cmd, self.next_dir, "The new code did not import")
        except BaseException:
            shutil.rmtree(self.next_dir, ignore_errors=True)
            raise
        finally:
            tmp.unlink(missing_ok=True)

        # The swap. From here, a failure puts the previous install back.
        if self.prev_dir.exists():
            shutil.rmtree(self.prev_dir)
        os.rename(self.code_dir, self.prev_dir)
        try:
            os.rename(self.next_dir, self.code_dir)
        except OSError:
            os.rename(self.prev_dir, self.code_dir)
            shutil.rmtree(self.next_dir, ignore_errors=True)
            raise UpdateError("Could not move the new code into place; the old code is back. Nothing changed.") \
                from None
        rec = {"version": m["version"], "commit": m["commit"], "sha256": m["sha256"], "file": m["file"],
               "created": m["created"], "installed": datetime.now(timezone.utc).isoformat(timespec="seconds"),
               "previous_version": rel.installed["version"]}
        self._write_record(self.code_dir, rec)
        self.log(f"switched to version {m['version']}; the old code is in {self.prev_dir.name}")
        try:
            # A Python environment remembers the folder it was made in, so refresh it in its final place.
            self._run(self.sync_cmd, self.code_dir, "Refreshing the packages in place failed")
        except UpdateError as e:
            self.log(str(e))
            return self._roll_back(m["version"], "its packages could not be set up in place")
        if not self.restart:
            self.log("installed. The service was not restarted (asked not to); restart it to run the new code.")
            return Result("installed", f"Installed version {m['version']}. Restart the service to run it.",
                          m["version"])
        if not self._restart_and_wait():
            return self._roll_back(m["version"], f"the page did not answer within {self.health_timeout:.0f} s")
        self.log(f"version {m['version']} is running and the page answers")
        return Result("installed", f"Installed version {m['version']} and the box is answering.", m["version"])

    def _run(self, cmd: list[str], folder: Path, what: str) -> None:
        argv = [a.replace("{dir}", str(folder)) for a in cmd]
        env = {k: v for k, v in os.environ.items() if k not in ("VIRTUAL_ENV", "UV_PROJECT_ENVIRONMENT")}
        try:
            r = subprocess.run(argv, cwd=folder, env=env, capture_output=True, text=True, timeout=STEP_TIMEOUT)
        except FileNotFoundError:
            raise UpdateError(f"{what}: {argv[0]} was not found.") from None
        except subprocess.TimeoutExpired:
            raise UpdateError(f"{what}: it took longer than {STEP_TIMEOUT // 60} minutes.") from None
        if r.returncode != 0:
            tail = (r.stderr or r.stdout or "").strip().splitlines()[-3:]
            raise UpdateError(f"{what} (exit {r.returncode}): {' | '.join(tail)}")

    def _restart_and_wait(self) -> bool:
        self.log("restarting familybox.service")
        try:
            self._run(self.restart_cmd, self.code_dir, "Restarting the service failed")
        except UpdateError as e:
            self.log(str(e))
            return False
        deadline = time.monotonic() + self.health_timeout
        while True:
            if self.healthy():
                return True
            if time.monotonic() >= deadline:
                return False
            time.sleep(self.health_interval)

    def _roll_back(self, version: int, why: str) -> Result:
        self.log(f"version {version} failed: {why}. Putting the previous code back.")
        os.rename(self.code_dir, self.failed_dir)
        os.rename(self.prev_dir, self.code_dir)
        rec = self.installed()
        rec["failed_version"] = version
        self._write_record(self.code_dir, rec)
        shutil.rmtree(self.failed_dir, ignore_errors=True)
        if self.restart:
            ok = self._restart_and_wait()
            self.log("the previous version is running again" if ok else
                     "the previous version is back, but the page does not answer either; look at "
                     "`journalctl --user -u familybox.service`")
        msg = (f"Version {version} was installed but {why}, so the box went back to version {rec['version']}. "
               "It will not try that version again.")
        return Result("rolled-back", msg, rec["version"])

    def _recover(self) -> None:
        """If an earlier update stopped between its two renames, put the previous code back."""
        if not self.code_dir.exists() and self.prev_dir.is_dir():
            os.rename(self.prev_dir, self.code_dir)
            self.log(f"an earlier update stopped half way; moved {self.prev_dir.name} back to {self.code_dir.name}")


# ---- command line ---------------------------------------------------------------------------------

def add_cli(sub) -> None:
    u = sub.add_parser("update", help="check for, or install, a signed release of the box's code")
    usub = u.add_subparsers(dest="action", required=True)
    for name in ("check", "apply"):
        p = usub.add_parser(name)
        p.add_argument("--code-dir", default=None, help="the installed code (default FAMILYBOX_CODE_DIR or ~/familybox)")
        p.add_argument("--port", type=int, default=8443, help="the box page's port, for the check after restart")
        if name == "apply":
            p.add_argument("--yes", action="store_true", help="install without asking")
            p.add_argument("--no-restart", action="store_true",
                           help="install but do not restart the service (no health check, no automatic rollback)")


def run_cli(args) -> int:
    log = Log(default_home(), echo=sys.stderr.isatty())
    try:
        up = Updater(code_dir=Path(args.code_dir) if args.code_dir else default_code_dir(), port=args.port,
                     restart=not getattr(args, "no_restart", False), log=log)
        rel = up.check()
        print(rel.message)
        if args.action == "check":
            return 0 if rel.status in ("newer", "same", "failed-before") else 1
        if rel.status == "newer" and not args.yes:
            if not sys.stdin.isatty():
                print("Not installing without --yes (no one here to ask).")
                return 1
            if input(f"Install version {rel.version} now? The box restarts. [y/N] ").strip().lower() not in ("y", "yes"):
                print("Not installed.")
                return 1
        res = up.apply(rel)
        if res.message != rel.message:
            print(res.message)
        return 0 if res.status in ("installed", "up-to-date") else 1
    except UpdateError as e:
        log(f"stopped: {e}")              # to updates.log, or to the screen when there is no log folder
        if log.path and not log.echo:
            print(f"update: {e}", file=sys.stderr)
        return 1
