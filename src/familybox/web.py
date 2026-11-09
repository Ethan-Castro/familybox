"""The box's own private web page: sign in with a one-time code, upload files, approve held values.

LAN only, HTTPS with a self-signed certificate made on first run. No passwords: the box owner runs
`familybox code --as <person>` on the box and types the code on their phone.

What is stored in <runtime>/web/ (all 0600, folder 0700):
  secret           random key used to hash sign-in codes
  codes.json       hashed one-time codes, 10 minute lifetime, single use
  failures.json    times of wrong codes (5 per 10 minutes locks sign-in)
  remote_failures.json  the same, for codes typed on the remote consent page (its own lockout, so
                   internet traffic can never lock the home sign-in)
  sessions.json    hashed session ids -> person, CSRF token, expiry (12 hours)

Nothing here prints file contents or file names. Uploads and deletes append one line to the person's
audit log with the folder, a SHA-256 and the size.
"""

from __future__ import annotations

import contextlib
import datetime as dt
import fcntl
import hashlib
import hmac
import html
import json
import os
import re
import secrets
import socket
import time
from dataclasses import dataclass
from typing import Any
from pathlib import Path, PurePosixPath

from starlette.applications import Starlette
from starlette.requests import Request
from starlette.responses import HTMLResponse, RedirectResponse, Response
from starlette.routing import Route
from starlette.types import ASGIApp, Message, Receive, Scope, Send

from . import access
from .approvals import Approvals
from .config import Config, Person
from .store import TRANSCRIPT_SUFFIX, Store, photo_of

CODE_ALPHABET = "ABCDEFGHJKMNPQRSTUVWXYZ23456789"   # no 0/O, 1/I/L
CODE_LEN = 8
CODE_TTL_S = 10 * 60
LOCKOUT_MAX = 5
LOCKOUT_WINDOW_S = 10 * 60
SESSION_TTL_S = 12 * 60 * 60
COOKIE = "__Host-familybox"
PRE_COOKIE = "__Host-familybox-signin"

MAX_UPLOAD = 25 * 1024 * 1024
FORM_SLACK = 64 * 1024
ALLOWED_SUFFIXES = {".txt", ".md", ".pdf", ".json", ".csv"}
PERSON_FOLDERS = ("ids", "taxes", "health", "school", "other")
FOLDER_LABELS = {"ids": "IDs", "taxes": "Taxes", "health": "Health", "school": "School", "other": "Other",
                 "shared": "Shared with the whole family"}

CSP = ("default-src 'self'; style-src 'self'; img-src 'self' data:; "
       "form-action 'self' https://accounts.google.com; frame-ancestors 'none'")
GOOGLE_AUTH_PREFIX = "https://accounts.google.com/"


# --- small file helpers -----------------------------------------------------------------------

def _write_private(path: Path, data: bytes) -> None:
    """Atomic write with 0600 perms (temp file in the same folder, then rename)."""
    path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
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


def _audit(cfg: Config, person_id: str, entry: dict) -> None:
    log = cfg.runtime / "audit" / f"{person_id}.jsonl"
    log.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    fd = os.open(log, os.O_WRONLY | os.O_CREAT | os.O_APPEND, 0o600)
    with os.fdopen(fd, "a") as f:
        f.write(json.dumps({"time": int(time.time())} | entry) + "\n")


# --- sign-in codes and sessions ---------------------------------------------------------------

class WebState:
    """Codes, failures and sessions, kept on disk under <runtime>/web so the CLI and server share them."""

    def __init__(self, cfg: Config):
        self.cfg = cfg
        self.dir = cfg.runtime / "web"
        self.dir.mkdir(parents=True, exist_ok=True, mode=0o700)
        os.chmod(self.dir, 0o700)

    @contextlib.contextmanager
    def _lock(self):
        fd = os.open(self.dir / ".lock", os.O_WRONLY | os.O_CREAT, 0o600)
        try:
            fcntl.flock(fd, fcntl.LOCK_EX)
            yield
        finally:
            fcntl.flock(fd, fcntl.LOCK_UN)
            os.close(fd)

    def _load(self, name: str, default):
        p = self.dir / name
        if not p.exists():
            return default
        try:
            return json.loads(p.read_text())
        except ValueError:
            return default

    def _save(self, name: str, data) -> None:
        _write_private(self.dir / name, json.dumps(data).encode())

    def _secret(self) -> bytes:
        p = self.dir / "secret"
        if not p.exists():
            _write_private(p, secrets.token_bytes(32))
        return p.read_bytes()

    def _code_hash(self, code: str) -> str:
        return hmac.new(self._secret(), code.encode(), hashlib.sha256).hexdigest()

    @staticmethod
    def normalize(code: str) -> str:
        return re.sub(r"[\s-]", "", code or "").upper()

    def issue_code(self, person_id: str) -> str:
        self.cfg.person(person_id)  # raises KeyError for unknown people
        code = "".join(secrets.choice(CODE_ALPHABET) for _ in range(CODE_LEN))
        now = time.time()
        with self._lock():
            codes = {h: c for h, c in self._load("codes.json", {}).items() if c["expires"] > now}
            codes[self._code_hash(code)] = {"person": person_id, "expires": now + CODE_TTL_S}
            self._save("codes.json", codes)
        return code

    def locked(self, now: float | None = None, bucket: str = "failures.json") -> bool:
        now = now or time.time()
        fails = [t for t in self._load(bucket, []) if now - t < LOCKOUT_WINDOW_S]
        return len(fails) >= LOCKOUT_MAX

    def redeem(self, code: str, bucket: str = "failures.json") -> tuple[str | None, str | None]:
        """Returns (person_id, None) on success or (None, reason) where reason is 'locked' or 'wrong'.

        bucket is the file that counts wrong codes. The web sign-in uses failures.json; codes typed on
        pages the internet can reach use their own bucket, so they can never lock the home sign-in."""
        if bucket not in ("failures.json", "remote_failures.json"):
            raise ValueError("unknown failure bucket")
        now = time.time()
        code = self.normalize(code)
        with self._lock():
            fails = [t for t in self._load(bucket, []) if now - t < LOCKOUT_WINDOW_S]
            if len(fails) >= LOCKOUT_MAX:
                return None, "locked"
            codes = {h: c for h, c in self._load("codes.json", {}).items() if c["expires"] > now}
            hit = None
            if len(code) == CODE_LEN and all(ch in CODE_ALPHABET for ch in code):
                want = self._code_hash(code)
                for h in codes:
                    if hmac.compare_digest(h, want):
                        hit = h
            if hit is None:
                fails.append(now)
                self._save(bucket, fails)
                self._save("codes.json", codes)
                return None, ("locked" if len(fails) >= LOCKOUT_MAX else "wrong")
            person = codes.pop(hit)["person"]
            self._save("codes.json", codes)
        if person not in self.cfg.people:
            return None, "wrong"
        return person, None

    @staticmethod
    def _sid_hash(sid: str) -> str:
        return hashlib.sha256(sid.encode()).hexdigest()

    def new_session(self, person_id: str) -> str:
        sid = secrets.token_urlsafe(32)
        now = time.time()
        with self._lock():
            sessions = {k: v for k, v in self._load("sessions.json", {}).items() if v["expires"] > now}
            sessions[self._sid_hash(sid)] = {"person": person_id, "csrf": secrets.token_urlsafe(32),
                                             "created": int(now), "expires": now + SESSION_TTL_S}
            self._save("sessions.json", sessions)
        return sid

    def get_session(self, sid: str) -> dict | None:
        if not sid:
            return None
        s = self._load("sessions.json", {}).get(self._sid_hash(sid))
        if not s or s["expires"] <= time.time():
            return None
        return s

    def end_session(self, sid: str) -> None:
        with self._lock():
            sessions = self._load("sessions.json", {})
            sessions.pop(self._sid_hash(sid), None)
            self._save("sessions.json", sessions)


def issue_code(cfg: Config, person_id: str) -> str:
    return WebState(cfg).issue_code(person_id)


# --- TLS ---------------------------------------------------------------------------------------

def ensure_cert(cfg: Config) -> tuple[Path, Path, str]:
    """Self-signed certificate in <runtime>/tls, made once. Returns (cert, key, SHA-256 fingerprint)."""
    from cryptography import x509
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import ec
    from cryptography.x509.oid import NameOID
    import ipaddress

    tls = cfg.runtime / "tls"
    tls.mkdir(parents=True, exist_ok=True, mode=0o700)
    os.chmod(tls, 0o700)
    cert_p, key_p = tls / "cert.pem", tls / "key.pem"
    if not (cert_p.exists() and key_p.exists()):
        key = ec.generate_private_key(ec.SECP256R1())
        host = socket.gethostname().split(".")[0] or "familybox"
        names = [x509.DNSName("localhost"), x509.DNSName(host), x509.DNSName(f"{host}.local"),
                 x509.IPAddress(ipaddress.ip_address("127.0.0.1")), x509.IPAddress(ipaddress.ip_address("::1"))]
        subject = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, f"{cfg.name} ({host})"[:64])])
        now = dt.datetime.now(dt.timezone.utc)
        cert = (x509.CertificateBuilder().subject_name(subject).issuer_name(subject)
                .public_key(key.public_key()).serial_number(x509.random_serial_number())
                .not_valid_before(now - dt.timedelta(minutes=5)).not_valid_after(now + dt.timedelta(days=825))
                .add_extension(x509.SubjectAlternativeName(names), critical=False)
                .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
                .sign(key, hashes.SHA256()))
        _write_private(key_p, key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
                                                serialization.NoEncryption()))
        _write_private(cert_p, cert.public_bytes(serialization.Encoding.PEM))
    os.chmod(key_p, 0o600)
    cert = x509.load_pem_x509_certificate(cert_p.read_bytes())
    fp = cert.fingerprint(hashes.SHA256()).hex().upper()
    return cert_p, key_p, ":".join(fp[i:i + 2] for i in range(0, len(fp), 2))


# --- security headers ---------------------------------------------------------------------------

class SecurityHeaders:
    def __init__(self, app: ASGIApp):
        self.app = app

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] != "http":
            return await self.app(scope, receive, send)
        is_css = scope.get("path") == "/static/style.css"

        async def send_wrapped(message: Message) -> None:
            if message["type"] == "http.response.start":
                headers = [(k, v) for k, v in message.get("headers", [])
                           if k.lower() not in (b"cache-control", b"content-security-policy")]
                headers += [
                    (b"content-security-policy", CSP.encode()),
                    (b"x-content-type-options", b"nosniff"),
                    (b"referrer-policy", b"no-referrer"),
                    (b"x-frame-options", b"DENY"),
                    (b"cross-origin-opener-policy", b"same-origin"),
                    (b"strict-transport-security", b"max-age=31536000"),
                    (b"cache-control", b"max-age=3600" if is_css else b"no-store"),
                ]
                if not is_css:
                    headers.append((b"pragma", b"no-cache"))
                message["headers"] = headers
            await send(message)

        await self.app(scope, receive, send_wrapped)


# --- HTML ----------------------------------------------------------------------------------------

CSS = """
:root { color-scheme: light dark; --bg: #f7f7f5; --fg: #1d1d1b; --muted: #5d5d58; --card: #ffffff;
  --line: #d9d9d4; --accent: #1f5fae; --accent-fg: #ffffff; --ok: #1d6b3a; --bad: #a32020; }
@media (prefers-color-scheme: dark) {
  :root { --bg: #151614; --fg: #ececea; --muted: #a8a8a2; --card: #1f201e; --line: #3a3b38;
    --accent: #7fb0ec; --accent-fg: #0d1b2c; --ok: #7ccf98; --bad: #f08a8a; }
}
* { box-sizing: border-box; }
body { margin: 0; background: var(--bg); color: var(--fg);
  font: 17px/1.5 system-ui, -apple-system, "Segoe UI", Roboto, sans-serif; }
header { padding: 12px 16px; border-bottom: 1px solid var(--line); background: var(--card); }
header .box { font-weight: 600; }
header .who { color: var(--muted); font-size: 15px; }
nav { display: flex; flex-wrap: wrap; gap: 6px; margin-top: 8px; align-items: center; }
nav a, nav button { padding: 6px 10px; border-radius: 8px; text-decoration: none; color: var(--fg);
  border: 1px solid var(--line); background: transparent; font: inherit; font-size: 15px; cursor: pointer; }
nav a.here { background: var(--accent); color: var(--accent-fg); border-color: var(--accent); }
nav form { margin: 0; }
main { padding: 16px; max-width: 640px; margin: 0 auto; }
h1 { font-size: 24px; margin: 4px 0 12px; }
h2 { font-size: 19px; margin: 20px 0 8px; }
.card { background: var(--card); border: 1px solid var(--line); border-radius: 12px; padding: 14px; margin: 12px 0; }
label { display: block; font-weight: 600; margin: 12px 0 4px; }
input[type=text], input[type=file], select { width: 100%; padding: 10px; font: inherit; border-radius: 8px;
  border: 1px solid var(--line); background: var(--bg); color: var(--fg); }
input.code { letter-spacing: 4px; text-transform: uppercase; font-size: 22px; text-align: center; }
button.main, .button { display: inline-block; margin-top: 14px; padding: 10px 16px; border-radius: 8px;
  border: 0; background: var(--accent); color: var(--accent-fg); font: inherit; font-weight: 600;
  cursor: pointer; text-decoration: none; }
button.quiet { background: transparent; color: var(--fg); border: 1px solid var(--line); }
button.danger { background: transparent; color: var(--bad); border: 1px solid var(--bad); }
.row { display: flex; gap: 8px; flex-wrap: wrap; align-items: center; }
.row form { margin: 0; }
.muted { color: var(--muted); font-size: 15px; }
.ok { color: var(--ok); font-weight: 600; }
.bad { color: var(--bad); font-weight: 600; }
.value { font: 600 22px/1.3 ui-monospace, Menlo, Consolas, monospace; word-break: break-all;
  padding: 12px; border: 2px dashed var(--accent); border-radius: 8px; margin: 8px 0; }
ul.files { list-style: none; padding: 0; margin: 0; }
main img { max-width: 100%; height: auto; display: block; }
pre.value { white-space: pre-wrap; font-size: 16px; }
ul.files li { padding: 10px 0; border-bottom: 1px solid var(--line); }
ul.files li:last-child { border-bottom: 0; }
.name { word-break: break-all; }
"""

NAV = [("/", "Home"), ("/upload", "Upload"), ("/files", "Files"), ("/approvals", "Approvals"), ("/cloud", "Cloud")]


def esc(s) -> str:
    return html.escape(str(s), quote=True)


def _size(n: int) -> str:
    if n < 1024:
        return f"{n} bytes"
    if n < 1024 * 1024:
        return f"{n / 1024:.0f} KB"
    return f"{n / 1024 / 1024:.1f} MB"


@dataclass
class Sess:
    sid: str
    person: Person
    csrf: str


def _csrf_field(token: str) -> str:
    return f'<input type="hidden" name="csrf" value="{esc(token)}">'


def _page(cfg: Config, title: str, body: str, sess: Sess | None = None, here: str = "", status: int = 200,
          pending: int | None = None, nav: list[tuple[str, str]] | None = None) -> HTMLResponse:
    head = f'<div class="box">{esc(cfg.name)}</div>'
    if sess:
        links = []
        for href, label in (nav or NAV):
            text = label
            if href == "/approvals" and pending:
                text = f"{label} ({pending})"
            cls = ' class="here"' if href == here else ""
            links.append(f'<a href="{href}"{cls}>{esc(text)}</a>')
        links.append(f'<form method="post" action="/signout">{_csrf_field(sess.csrf)}'
                     f'<button type="submit">Sign out</button></form>')
        head += (f'<div class="who">Signed in as {esc(sess.person.display)}</div>'
                 f'<nav>{"".join(links)}</nav>')
    doc = (f'<!doctype html><html lang="en"><head><meta charset="utf-8">'
           f'<meta name="viewport" content="width=device-width, initial-scale=1">'
           f'<meta name="referrer" content="no-referrer">'
           f'<title>{esc(title)} | {esc(cfg.name)}</title><link rel="stylesheet" href="/static/style.css">'
           f'</head><body><header>{head}</header><main>{body}</main></body></html>')
    return HTMLResponse(doc, status_code=status)


# --- uploads ------------------------------------------------------------------------------------

class UploadError(ValueError):
    pass


def safe_filename(raw: str) -> str:
    """Last path part only, no hidden names, plain characters, allowed suffix."""
    name = (raw or "").replace("\\", "/").split("/")[-1]
    name = "".join(ch for ch in name if ch.isprintable()).strip()
    name = name.lstrip(". ")
    stem, dot, suffix = name.rpartition(".")
    if not dot:
        raise UploadError("That file has no type. Use .txt, .md, .pdf, .json or .csv.")
    suffix = "." + suffix.lower()
    if suffix not in ALLOWED_SUFFIXES:
        raise UploadError("That file type isn't allowed. Use .txt, .md, .pdf, .json or .csv.")
    stem = re.sub(r"[^A-Za-z0-9._ -]+", "_", stem)
    stem = re.sub(r"[ _]{2,}", "_", stem).strip(" ._-")[:100] or "file"
    if (stem + suffix).lower().endswith(TRANSCRIPT_SUFFIX):
        # Only the box writes a photo's text. An upload with this name could pass itself off as one.
        raise UploadError("Names ending in .transcript.txt are kept for the text the box reads from photos. "
                          "Rename the file and try again.")
    return stem + suffix


def check_content(suffix: str, data: bytes) -> None:
    if suffix == ".pdf":
        if not data.startswith(b"%PDF-"):
            raise UploadError("That doesn't look like a real PDF file.")
        return
    if b"\x00" in data:
        raise UploadError("That file doesn't look like plain text.")
    try:
        text = data.decode("utf-8-sig")
    except UnicodeDecodeError:
        raise UploadError("That file doesn't look like plain text.") from None
    if suffix == ".json":
        try:
            json.loads(text)
        except ValueError:
            raise UploadError("That .json file can't be read. Check that it's valid JSON.") from None


def upload_folder(cfg: Config, person: Person, choice: str) -> str:
    """Folder (relative to files/) for an upload choice, or raise."""
    if choice == "shared":
        return "shared"
    if choice in PERSON_FOLDERS:
        return f"people/{person.id}/{choice}"
    raise UploadError("Pick one of the folders in the list.")


def save_upload(cfg: Config, person: Person, choice: str, filename: str, data: bytes) -> str:
    """Write the file atomically with 0600 perms and no overwrite. Returns its path relative to files/."""
    if len(data) > MAX_UPLOAD:
        raise UploadError("That file is too big. The limit is 25 MB.")
    if not data:
        raise UploadError("That file is empty.")
    rel_folder = upload_folder(cfg, person, choice)
    name = safe_filename(filename)
    check_content(Path(name).suffix, data)
    root = cfg.files.resolve()
    folder = (root / rel_folder).resolve()
    if root not in folder.parents:
        raise UploadError("Pick one of the folders in the list.")
    folder.mkdir(parents=True, exist_ok=True, mode=0o700)
    stem, suffix = Path(name).stem, Path(name).suffix
    tmp = folder / f".upload-{secrets.token_hex(8)}.tmp"
    fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    try:
        with os.fdopen(fd, "wb") as f:
            f.write(data)
            f.flush()
            os.fsync(f.fileno())
        for i in range(1000):
            target = folder / (name if i == 0 else f"{stem}-{i}{suffix}")
            try:
                os.link(tmp, target)   # fails if the name is taken, so nothing is overwritten
                break
            except FileExistsError:
                continue
        else:
            raise UploadError("Too many files with that name. Rename it and try again.")
    finally:
        with contextlib.suppress(FileNotFoundError):
            tmp.unlink()
    os.chmod(target, 0o600)
    _audit(cfg, person.id, {"event": "upload", "folder": rel_folder,
                            "sha256": hashlib.sha256(data).hexdigest(), "bytes": len(data)})
    return target.relative_to(root).as_posix()


def can_delete(person: Person, rel_path: str) -> bool:
    p = PurePosixPath(rel_path)
    if p.is_absolute() or ".." in p.parts or not p.parts:
        return False
    if access.owner_of(rel_path) == person.id:
        return True
    return p.parts[0] == "shared" and person.admin


def _reindex(cfg: Config) -> None:
    store = Store(cfg)
    try:
        store.reindex()
    finally:
        store.db.close()


def photo_text_of(cfg: Config, rel: str) -> str | None:
    """The photo this file's text was read from, if that photo is still on the box."""
    photo = photo_of(rel)
    return photo if photo and (cfg.files / photo).is_file() else None


def readable_files(cfg: Config, person: Person) -> list[tuple[str, int]]:
    store = Store(cfg)
    try:
        files = store.files()
    finally:
        store.db.close()
    out = []
    for f in files:
        rel = f.relative_to(cfg.files).as_posix()
        if access.can_read(person, rel):
            out.append((rel, f.stat().st_size))
    return out


# --- cloud (optional module built elsewhere) ------------------------------------------------------

def _cloud():
    import importlib
    try:
        # import_module consults sys.modules, so a box without the cloud package (or a test's stand-in) works.
        return importlib.import_module("familybox.cloud")
    except ImportError:
        return None


CLOUD_MISSING = "Cloud connection isn't set up on this box yet."


# --- the app -------------------------------------------------------------------------------------

@dataclass
class WebContext:
    """What a plugin's web_routes(ctx) gets.

    cfg                      the box Config
    session_of(request)      -> Sess | None (Sess has sid, person, csrf)
    page(sess, title, body, here="", status=200) -> HTMLResponse in the box's look, with the nav bar
    need_signin(handler)     decorator: async handler(request, sess); redirects to /signin when signed out
    guarded_form(request, **form_kw) -> (sess, form) or a 403 Response: signed in + same origin + CSRF ok
    csrf_field(token)        hidden <input> for a form; use sess.csrf as the token
    forbidden(msg=...)       403 page
    esc(text)                HTML escape
    box()                    a shared familybox.box.Box (made on first use)
    """
    cfg: Config
    session_of: Any
    page: Any
    need_signin: Any
    guarded_form: Any
    csrf_field: Any
    forbidden: Any
    esc: Any
    box: Any


def create_app(cfg: Config, *, port: int = 8443, remote_only: bool = False, box=None) -> Starlette:
    """The box's web app. remote_only=True serves only familybox.remote.REMOTE_PATHS (the sign-in
    endpoints and /mcp), for the listener a tunnel points at: sign-in, files, approvals and the rest
    answer 404 there. box is an optional shared () -> Box getter."""
    state = WebState(cfg)
    from . import plugins
    nav = list(NAV)
    for extra in plugins.call_each("web_nav"):
        for label, path in extra or []:
            nav.append((path, label))

    def session_of(request: Request) -> Sess | None:
        sid = request.cookies.get(COOKIE, "")
        s = state.get_session(sid)
        if not s or s["person"] not in cfg.people:
            return None
        return Sess(sid, cfg.person(s["person"]), s["csrf"])

    def pending_count(person: Person) -> int:
        return len(Approvals(cfg).pending(person.id))

    def page(sess: Sess, title: str, body: str, here: str = "", status: int = 200) -> HTMLResponse:
        return _page(cfg, title, body, sess, here, status, pending_count(sess.person), nav)

    def forbidden(msg: str = "That request wasn't allowed. Go back, reload the page and try again.") -> HTMLResponse:
        return _page(cfg, "Not allowed", f'<h1>Not allowed</h1><p>{esc(msg)}</p><p><a href="/">Go home</a></p>',
                     status=403)

    def origin_ok(request: Request) -> bool:
        origin = request.headers.get("origin")
        if not origin or origin == "null":
            return origin is None
        host = request.headers.get("host", "")
        return origin.split("://", 1)[-1] == host

    async def guarded_form(request: Request, **kw):
        """For POSTs: signed in, same origin, CSRF token matches. Returns (sess, form) or a Response."""
        sess = session_of(request)
        if sess is None:
            return forbidden("You're signed out. Sign in again.")
        if not origin_ok(request):
            return forbidden()
        form = await request.form(**kw)
        token = form.get("csrf")
        if not isinstance(token, str) or not hmac.compare_digest(token, sess.csrf):
            await form.close()
            return forbidden()
        return sess, form

    def need_signin(handler):
        async def wrapped(request: Request):
            sess = session_of(request)
            if sess is None:
                return RedirectResponse("/signin", status_code=303)
            return await handler(request, sess)
        wrapped.__name__ = handler.__name__
        return wrapped

    # ---- sign in / out
    async def css(request: Request):
        return Response(CSS, media_type="text/css")

    def signin_page(pre: str, error: str = "", status: int = 200) -> HTMLResponse:
        err = f'<p class="bad">{esc(error)}</p>' if error else ""
        body = (f'<h1>Sign in</h1>'
                f'<p>Ask the person who runs the family box for a sign-in code. It works once and lasts 10 minutes.</p>'
                f'{err}<form method="post" action="/signin" class="card">{_csrf_field(pre)}'
                f'<label for="code">Your 8-letter code</label>'
                f'<input type="text" id="code" name="code" class="code" maxlength="12" autocomplete="one-time-code"'
                f' autocapitalize="characters" spellcheck="false" required>'
                f'<button class="main" type="submit">Sign in</button></form>')
        resp = _page(cfg, "Sign in", body, status=status)
        resp.set_cookie(PRE_COOKIE, pre, max_age=CODE_TTL_S * 3, secure=True, httponly=True, samesite="strict")
        return resp

    async def signin_get(request: Request):
        if session_of(request):
            return RedirectResponse("/", status_code=303)
        return signin_page(secrets.token_urlsafe(24))

    async def signin_post(request: Request):
        if not origin_ok(request):
            return forbidden()
        form = await request.form()
        pre = request.cookies.get(PRE_COOKIE, "")
        token = form.get("csrf")
        if not pre or not isinstance(token, str) or not hmac.compare_digest(token, pre):
            return forbidden()
        person_id, why = state.redeem(str(form.get("code", "")))
        if person_id is None:
            msg = ("Too many wrong codes. Wait 10 minutes, then try again." if why == "locked"
                   else "That code didn't work. Check it, or ask for a new one.")
            return signin_page(secrets.token_urlsafe(24), msg, status=429 if why == "locked" else 401)
        sid = state.new_session(person_id)
        resp = RedirectResponse("/", status_code=303)
        resp.set_cookie(COOKIE, sid, max_age=SESSION_TTL_S, secure=True, httponly=True, samesite="strict")
        resp.delete_cookie(PRE_COOKIE, secure=True, httponly=True, samesite="strict")
        return resp

    async def signout(request: Request):
        got = await guarded_form(request)
        if isinstance(got, Response):
            return got
        sess, _ = got
        state.end_session(sess.sid)
        resp = RedirectResponse("/signin", status_code=303)
        resp.delete_cookie(COOKIE, secure=True, httponly=True, samesite="strict")
        return resp

    # ---- home
    @need_signin
    async def home(request: Request, sess: Sess):
        n = pending_count(sess.person)
        waiting = (f'<p><a class="button" href="/approvals">{n} waiting for you to approve</a></p>' if n
                   else '<p class="muted">Nothing is waiting for your approval.</p>')
        body = (f'<h1>Hi, {esc(sess.person.display)}</h1>{waiting}'
                f'<div class="card"><h2>What you can do here</h2><ul>'
                f'<li><a href="/upload">Upload a file</a> into your folders or the family\'s shared folder.</li>'
                f'<li><a href="/files">See your files</a> and remove ones you no longer want on the box.</li>'
                f'<li><a href="/approvals">Approve or deny</a> details an assistant asked for.</li>'
                f'<li><a href="/cloud">Cloud</a>: bring files in from Google Drive, and back up the box.</li>'
                f'</ul></div><p class="muted">This page only works on your home network.</p>')
        return page(sess, "Home", body, "/")

    # ---- upload
    def upload_form(sess: Sess, msg: str = "", ok: bool = False, status: int = 200) -> HTMLResponse:
        note = f'<p class="{"ok" if ok else "bad"}">{esc(msg)}</p>' if msg else ""
        opts = "".join(f'<option value="{f}">My {FOLDER_LABELS[f]}</option>' for f in PERSON_FOLDERS)
        opts += f'<option value="shared">{FOLDER_LABELS["shared"]}</option>'
        body = (f'<h1>Upload a file</h1>{note}'
                f'<form method="post" action="/upload" enctype="multipart/form-data" class="card">'
                f'{_csrf_field(sess.csrf)}'
                f'<label for="folder">Where should it go?</label><select id="folder" name="folder">{opts}</select>'
                f'<label for="file">File</label>'
                f'<input type="file" id="file" name="file" accept=".txt,.md,.pdf,.json,.csv" required>'
                f'<p class="muted">Text, Markdown, PDF, JSON or CSV. Up to 25 MB. '
                f'Files in your folders are only for you. Shared files can be read by everyone in the family.</p>'
                f'<button class="main" type="submit">Upload</button></form>')
        return page(sess, "Upload", body, "/upload", status)

    @need_signin
    async def upload_get(request: Request, sess: Sess):
        return upload_form(sess)

    async def upload_post(request: Request):
        got = await guarded_form(request, max_files=1, max_fields=8, max_part_size=4096)
        if isinstance(got, Response):
            return got
        sess, form = got
        try:
            f = form.get("file")
            if f is None or isinstance(f, str):
                raise UploadError("Choose a file first.")
            if f.size is not None and f.size > MAX_UPLOAD:
                raise UploadError("That file is too big. The limit is 25 MB.")
            data = await f.read(MAX_UPLOAD + 1)
            save_upload(cfg, sess.person, str(form.get("folder", "")), f.filename or "", data)
        except UploadError as e:
            return upload_form(sess, str(e), status=400)
        finally:
            await form.close()
        _reindex(cfg)
        return upload_form(sess, "Uploaded. Your assistant can use it now.", ok=True)

    # ---- files
    def files_page(sess: Sess, msg: str = "", ok: bool = True) -> HTMLResponse:
        rows = []
        for rel, size in readable_files(cfg, sess.person):
            delete = ""
            photo = photo_text_of(cfg, rel)
            if photo:
                delete = (f'<span class="muted">Text read from the photo {esc(PurePosixPath(photo).name)}. '
                          f'To remove it, remove the photo on the <a href="/photos">Photos page</a>.</span>')
            elif can_delete(sess.person, rel):
                delete = (f'<form method="post" action="/files/delete">{_csrf_field(sess.csrf)}'
                          f'<input type="hidden" name="path" value="{esc(rel)}">'
                          f'<button class="danger" type="submit">Remove</button></form>')
            rows.append(f'<li><div class="name">{esc(rel)}</div>'
                        f'<div class="row"><span class="muted">{_size(size)}</span>{delete}</div></li>')
        note = f'<p class="{"ok" if ok else "bad"}">{esc(msg)}</p>' if msg else ""
        listing = f'<ul class="files">{"".join(rows)}</ul>' if rows else '<p class="muted">No files yet.</p>'
        body = (f'<h1>Your files</h1>{note}<p class="muted">These are the files your assistant can use when you ask '
                f'a question. You can remove your own files.</p><div class="card">{listing}</div>')
        return page(sess, "Files", body, "/files")

    @need_signin
    async def files_get(request: Request, sess: Sess):
        return files_page(sess)

    async def files_delete(request: Request):
        got = await guarded_form(request)
        if isinstance(got, Response):
            return got
        sess, form = got
        rel = str(form.get("path", "")).strip().lstrip("/")
        root = cfg.files.resolve()
        target = (root / rel).resolve()
        if (not can_delete(sess.person, rel) or root not in target.parents or not target.is_file()
                or target.relative_to(root).as_posix() != rel):
            return forbidden("You can only remove your own files.")
        if photo_text_of(cfg, rel):
            return forbidden("This is the text read from a photo. Remove the photo on the Photos page, "
                             "and its text goes with it.")
        data = target.read_bytes()
        target.unlink()
        _audit(cfg, sess.person.id, {"event": "delete", "folder": PurePosixPath(rel).parent.as_posix(),
                                     "sha256": hashlib.sha256(data).hexdigest(), "bytes": len(data)})
        _reindex(cfg)
        return files_page(sess, "Removed.")

    # ---- approvals
    def approvals_page(sess: Sess, extra: str = "") -> HTMLResponse:
        items = Approvals(cfg).pending(sess.person.id)
        cards = []
        for it in items:
            asker = cfg.people[it["asker"]].display if it["asker"] in cfg.people else it["asker"]
            asker = "You" if it["asker"] == sess.person.id else asker
            cards.append(
                f'<div class="card"><div><strong>{esc(it["label"])}</strong></div>'
                f'<div class="muted">{esc(asker)} asked: "{esc(it["question"])}"</div>'
                f'<div class="muted">From: {esc(it["path"])}</div>'
                f'<div class="row">'
                f'<form method="post" action="/approvals/{esc(it["id"])}/approve">{_csrf_field(sess.csrf)}'
                f'<button class="main" type="submit">Approve and show it here</button></form>'
                f'<form method="post" action="/approvals/{esc(it["id"])}/deny">{_csrf_field(sess.csrf)}'
                f'<button class="main quiet" type="submit">Deny</button></form></div></div>')
        listing = "".join(cards) or '<p class="muted">Nothing is waiting for you.</p>'
        body = (f'<h1>Approvals</h1>{extra}<p class="muted">When an assistant\'s answer included one of your private '
                f'details, the box held it back. Approving shows it on this page only. It is never sent to the '
                f'assistant.</p>{listing}')
        return page(sess, "Approvals", body, "/approvals")

    @need_signin
    async def approvals_get(request: Request, sess: Sess):
        return approvals_page(sess)

    async def approvals_decide(request: Request):
        got = await guarded_form(request)
        if isinstance(got, Response):
            return got
        sess, _ = got
        item_id = request.path_params["item_id"]
        if request.path_params["action"] not in ("approve", "deny"):
            return _page(cfg, "Not found", "<h1>Not found</h1>", sess, status=404)
        approve = request.path_params["action"] == "approve"
        appr = Approvals(cfg)
        if item_id not in {it["id"] for it in appr.pending(sess.person.id)}:
            return _page(cfg, "Not found", '<h1>Not found</h1><p>That item isn\'t waiting for you.</p>'
                         '<p><a href="/approvals">Back to approvals</a></p>', sess, status=404)
        result = appr.decide(sess.person.id, item_id, approve)
        if approve:
            extra = (f'<div class="card"><p class="ok">Approved. Here is your {esc(result["label"])}:</p>'
                     f'<div class="value">{esc(result["value"])}</div>'
                     f'<p class="muted">Only you can see this. It won\'t be shown again after you leave this page.</p>'
                     f'</div>')
        else:
            extra = '<p class="ok">Denied. Nothing was shared.</p>'
        return approvals_page(sess, extra)

    # ---- cloud
    def redirect_uri(request: Request) -> str:
        # Always the box's own callback, as reached by this browser. The cloud module decides whether
        # Google gets it directly (127.0.0.1) or the forwarder page (FAMILYBOX_OAUTH_REDIRECT, LAN boxes).
        return f"https://{request.url.netloc}/oauth/google/callback"

    def cloud_page(sess: Sess, cloud, msg: str = "", ok: bool = True, extra: str = "", status: int = 200):
        note = f'<p class="{"ok" if ok else "bad"}">{esc(msg)}</p>' if msg else ""
        try:
            st = cloud.status(cfg, sess.person.id) or {}
        except Exception:  # noqa: BLE001
            st = None
        if st is None:
            info = '<p class="bad">The box couldn\'t check the cloud connection right now.</p>'
            st = {}
        elif st.get("connected"):
            info = f'<p class="ok">Google Drive is connected{" as " + esc(st["account_email"]) if st.get("account_email") else ""}.</p>'
        else:
            info = '<p>Google Drive isn\'t connected yet.</p>'
        info += (f'<p class="muted">Last import: {esc(st.get("last_import") or "never")}<br>'
                 f'Last backup: {esc(st.get("last_backup") or "never")}<br>'
                 f'Backup key: {"set" if st.get("backup_key_set") else "not set"}</p>')
        c = _csrf_field(sess.csrf)
        body = (f'<h1>Cloud</h1>{note}{extra}<div class="card">{info}'
                f'<form method="post" action="/cloud/connect">{c}'
                f'<button class="main" type="submit">Connect Google Drive</button></form></div>')
        if st.get("connected"):
            body += (f'<form method="post" action="/cloud/import" class="card">{c}<h2>Bring files in</h2>'
                     f'<label for="drive_folder">Google Drive folder name</label>'
                     f'<input type="text" id="drive_folder" name="folder" maxlength="200" required>'
                     f'<p class="muted">Files are copied into your own "Other" folder on the box.</p>'
                     f'<button class="main" type="submit">Import</button></form>')
        if sess.person.admin:
            body += (f'<div class="card"><h2>Backups</h2><p class="muted">Backups are locked with a key before '
                     f'they leave the box.</p><div class="row">'
                     f'<form method="post" action="/cloud/backup">{c}'
                     f'<button class="main" type="submit">Back up now</button></form>'
                     f'<form method="post" action="/cloud/backup-key">{c}'
                     f'<button class="main quiet" type="submit">Create backup key</button></form></div></div>')
        return page(sess, "Cloud", body, "/cloud", status)

    def no_cloud(sess: Sess) -> HTMLResponse:
        return page(sess, "Cloud", f'<h1>Cloud</h1><div class="card"><p>{esc(CLOUD_MISSING)}</p></div>', "/cloud")

    @need_signin
    async def cloud_get(request: Request, sess: Sess):
        cloud = _cloud()
        return no_cloud(sess) if cloud is None else cloud_page(sess, cloud)

    async def cloud_connect(request: Request):
        got = await guarded_form(request)
        if isinstance(got, Response):
            return got
        sess, _ = got
        cloud = _cloud()
        if cloud is None:
            return no_cloud(sess)
        try:
            url = cloud.begin_connect(cfg, sess.person.id, redirect_uri(request))
        except Exception:  # noqa: BLE001
            return cloud_page(sess, cloud, "The box couldn't start the Google sign-in. Try again later.", False)
        if not isinstance(url, str) or not url.startswith(GOOGLE_AUTH_PREFIX):
            return cloud_page(sess, cloud, "The box couldn't start the Google sign-in. Try again later.", False)
        return RedirectResponse(url, status_code=303)

    async def cloud_import(request: Request):
        got = await guarded_form(request)
        if isinstance(got, Response):
            return got
        sess, form = got
        cloud = _cloud()
        if cloud is None:
            return no_cloud(sess)
        folder = str(form.get("folder", "")).strip()[:200]
        if not folder:
            return cloud_page(sess, cloud, "Type the name of a Google Drive folder.", False, status=400)
        try:
            r = cloud.import_folder(cfg, sess.person.id, folder)
        except Exception:  # noqa: BLE001
            return cloud_page(sess, cloud, "The import didn't work. Check the folder name and try again.", False)
        _reindex(cfg)
        return cloud_page(sess, cloud, f'Imported {int(r.get("imported", 0))} files. '
                                       f'Skipped {int(r.get("skipped", 0))}.')

    async def cloud_admin(request: Request):
        got = await guarded_form(request)
        if isinstance(got, Response):
            return got
        sess, _ = got
        if not sess.person.admin:
            return forbidden("Only the person who runs the box can do that.")
        cloud = _cloud()
        if cloud is None:
            return no_cloud(sess)
        if request.url.path == "/cloud/backup":
            try:
                r = cloud.backup_now(cfg)
            except Exception:  # noqa: BLE001
                return cloud_page(sess, cloud, "The backup didn't work. Try again later.", False)
            return cloud_page(sess, cloud, f'Backed up {_size(int(r.get("bytes", 0)))}. '
                                           f'Check code: {str(r.get("sha256", ""))[:12]}')
        try:
            code = cloud.init_backup_key(cfg)
        except Exception:  # noqa: BLE001
            return cloud_page(sess, cloud, "The box couldn't make a backup key.", False)
        extra = (f'<div class="card"><p class="ok">Your backup key is ready. Write this recovery code down and keep '
                 f'it somewhere safe. You need it to restore a backup. It is shown only once.</p>'
                 f'<div class="value">{esc(code)}</div></div>')
        return cloud_page(sess, cloud, extra=extra)

    async def oauth_callback(request: Request):
        cloud = _cloud()
        if cloud is None:
            return _page(cfg, "Cloud", f'<h1>Cloud</h1><p>{esc(CLOUD_MISSING)}</p>', status=404)
        state_param = request.query_params.get("state", "")
        code = request.query_params.get("code", "")
        if request.query_params.get("error") or not state_param or not code:
            return _page(cfg, "Google sign-in", '<h1>Google sign-in stopped</h1><p>Nothing was connected.</p>'
                         '<p><a href="/cloud">Back to Cloud</a></p>', status=400)
        try:
            r = cloud.finish_connect(cfg, state_param, code) or {}
        except Exception:  # noqa: BLE001
            return _page(cfg, "Google sign-in", '<h1>That sign-in link didn\'t work</h1>'
                         '<p>Nothing was connected. Start again from the Cloud page.</p>'
                         '<p><a href="/cloud">Back to Cloud</a></p>', status=400)
        who = f' as {esc(r["account_email"])}' if r.get("account_email") else ""
        return _page(cfg, "Google sign-in", f'<h1>Google Drive is connected{who}</h1>'
                     '<p><a class="button" href="/cloud">Back to Cloud</a></p>')

    routes = [
        Route("/static/style.css", css),
        Route("/signin", signin_get, methods=["GET"]),
        Route("/signin", signin_post, methods=["POST"]),
        Route("/signout", signout, methods=["POST"]),
        Route("/", home),
        Route("/upload", upload_get, methods=["GET"]),
        Route("/upload", upload_post, methods=["POST"], max_body_size=MAX_UPLOAD + FORM_SLACK),
        Route("/files", files_get),
        Route("/files/delete", files_delete, methods=["POST"]),
        Route("/approvals", approvals_get),
        Route("/approvals/{item_id}/{action}", approvals_decide, methods=["POST"]),
        Route("/cloud", cloud_get),
        Route("/cloud/connect", cloud_connect, methods=["POST"]),
        Route("/cloud/import", cloud_import, methods=["POST"]),
        Route("/cloud/backup", cloud_admin, methods=["POST"]),
        Route("/cloud/backup-key", cloud_admin, methods=["POST"]),
        Route("/oauth/google/callback", oauth_callback),
    ]
    _box: list = []

    def get_box():
        if box is not None:
            return box()
        if not _box:
            from .box import Box
            _box.append(Box(cfg))
        return _box[0]

    ctx = WebContext(cfg=cfg, session_of=session_of, page=page, need_signin=need_signin, guarded_form=guarded_form,
                     csrf_field=_csrf_field, forbidden=forbidden, esc=esc, box=get_box)
    for extra in plugins.call_each("web_routes", ctx):
        routes.extend(extra or [])   # after the core routes, so a plugin can never shadow them
    if remote_only:
        from .remote import REMOTE_PATHS
        routes = [r for r in routes if getattr(r, "path", None) in REMOTE_PATHS]
    app = Starlette(routes=routes, max_body_size=FORM_SLACK)
    return SecurityHeaders(app)


def serve(cfg: Config, *, lan: bool = False, port: int = 8443, remote_port: int | None = None) -> None:
    """Serve the web page. remote_port adds a second listener, always on 127.0.0.1, that serves only
    the routes assistants on the internet need. Point a tunnel at that port, never at the main one."""
    import asyncio

    import uvicorn

    if remote_port is not None and remote_port == port:
        raise SystemExit("--remote-port must be different from --port")
    cert, key, fp = ensure_cert(cfg)
    host = "0.0.0.0" if lan else "127.0.0.1"
    shared: list = []

    def box():
        if not shared:
            from .box import Box
            shared.append(Box(cfg))
        return shared[0]

    print(f"familybox web page on https://{'<this box>' if lan else '127.0.0.1'}:{port}/")
    if remote_port is not None:
        print(f"assistant-only listener on https://127.0.0.1:{remote_port}/ (sign-in for assistants and /mcp, "
              f"nothing else). Point the tunnel here.")
    print(f"certificate SHA-256 fingerprint: {fp}")
    print("check that your browser shows the same fingerprint before signing in.")
    print("sign-in codes: familybox code --as <person>", flush=True)
    # lifespan off: the app has no startup hooks (the /mcp session manager starts on first use).
    common = dict(ssl_certfile=str(cert), ssl_keyfile=str(key), access_log=False, log_level="warning",
                  server_header=False, lifespan="off")
    servers = [uvicorn.Server(uvicorn.Config(create_app(cfg, port=port, box=box), host=host, port=port, **common))]
    if remote_port is not None:
        servers.append(uvicorn.Server(uvicorn.Config(create_app(cfg, port=remote_port, remote_only=True, box=box),
                                                     host="127.0.0.1", port=remote_port, **common)))

    async def run_all():
        await asyncio.gather(*(s.serve() for s in servers))

    with contextlib.suppress(KeyboardInterrupt):
        asyncio.run(run_all())
