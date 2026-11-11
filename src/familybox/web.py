"""The box's own private web page: sign in with a one-time code, upload files, approve held values.

LAN only, HTTPS with a self-signed certificate made on first run. A new box opens on /setup. People
sign in with their own PIN, or with a one-time code from `familybox code --as <person>` or an invite.

What is stored in <runtime>/web/ (all 0600, folder 0700):
  secret           random key used to hash sign-in codes
  codes.json       hashed one-time codes, 10 minute lifetime, single use
  failures.json    times of wrong codes (5 per 10 minutes locks sign-in)
  remote_failures.json  the same, for codes typed on the remote consent page (its own lockout, so
                   internet traffic can never lock the home sign-in)
  sessions.json    hashed session ids -> person, CSRF token, expiry (12 hours)
  pins.json        scrypt hashes of PINs, and pin_failures.json, wrong PINs per person
                   (see familybox.household). Invites are codes that last 30 minutes.

  filed.json       files a person filed into a folder they can't read (a health drop-off), so the
                   Files page can say "1 file filed for Maya" without ever showing the name.

Nothing here prints file contents or file names. Uploads and deletes append one line to the person's
audit log with the folder, a SHA-256 and the size. A file put into someone else's folder is logged
on both people's logs.
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
INVITE_TTL_S = 30 * 60
LOCKOUT_MAX = 5
LOCKOUT_WINDOW_S = 10 * 60
SESSION_TTL_S = 12 * 60 * 60
COOKIE = "__Host-familybox"
PRE_COOKIE = "__Host-familybox-signin"

MAX_UPLOAD = 25 * 1024 * 1024           # one file
MAX_TOTAL_UPLOAD = 200 * 1024 * 1024    # one upload of many files, all together
MAX_FILES = 50                          # files in one upload
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
    from . import ledger
    ledger.append(cfg.runtime, person_id, {"time": int(time.time())} | entry)


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

    def issue_code(self, person_id: str, ttl: int = CODE_TTL_S) -> str:
        """A one-time sign-in code. ttl is how long it lasts in seconds (invites use INVITE_TTL_S)."""
        self.cfg.person(person_id)  # raises KeyError for unknown people
        if not 0 < ttl <= INVITE_TTL_S:
            raise ValueError("a code lasts at most 30 minutes")
        code = "".join(secrets.choice(CODE_ALPHABET) for _ in range(CODE_LEN))
        now = time.time()
        with self._lock():
            codes = {h: c for h, c in self._load("codes.json", {}).items() if c["expires"] > now}
            codes[self._code_hash(code)] = {"person": person_id, "expires": now + ttl}
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

    # Files a person put where they can't read them (health drop-off). Only the count is ever shown.
    def note_filed(self, uploader_id: str, rel: str) -> None:
        with self._lock():
            filed = self._load("filed.json", {})
            mine = filed.setdefault(uploader_id, [])
            if rel not in mine:
                mine.append(rel)
            self._save("filed.json", filed)

    def filed_counts(self, uploader_id: str) -> dict[str, int]:
        """owner id -> how many files this person filed for them that are still on the box."""
        out: dict[str, int] = {}
        root = self.cfg.files
        for rel in self._load("filed.json", {}).get(uploader_id, []):
            owner = access.owner_of(rel)
            if owner and (root / rel).is_file():
                out[owner] = out.get(owner, 0) + 1
        return out


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


class SetupGate:
    """While the box has no family yet, every page except /setup and the style sheet sends the browser
    to /setup. The setup page itself decides whether setup is still allowed (household.setup_open)."""

    OPEN = frozenset({"/setup", "/static/style.css"})

    def __init__(self, app: ASGIApp, cfg: Config):
        self.app = app
        self.cfg = cfg

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] == "http" and not self.cfg.people and scope.get("path") not in self.OPEN:
            return await RedirectResponse("/setup", status_code=303)(scope, receive, send)
        await self.app(scope, receive, send)


# --- forms before sign-in ---------------------------------------------------------------------

def origin_ok(request: Request) -> bool:
    """True when a POST comes from this page (or from a client that sends no Origin at all)."""
    origin = request.headers.get("origin")
    if not origin or origin == "null":
        return origin is None
    host = request.headers.get("host", "")
    return origin.split("://", 1)[-1] == host


def set_pre_cookie(resp: Response, token: str) -> Response:
    """The CSRF cookie for forms shown before anyone is signed in (/signin, /setup, /join)."""
    resp.set_cookie(PRE_COOKIE, token, max_age=CODE_TTL_S * 3, secure=True, httponly=True, samesite="strict")
    return resp


def pre_ok(request: Request, form) -> bool:
    """Same origin, and the form's csrf field matches the pre-sign-in cookie."""
    if not origin_ok(request):
        return False
    pre = request.cookies.get(PRE_COOKIE, "")
    token = form.get("csrf")
    return bool(pre) and isinstance(token, str) and hmac.compare_digest(token, pre)


def signed_in(state: "WebState", person_id: str, to: str = "/") -> RedirectResponse:
    """Start a session for person_id and send the browser on, with the session cookie set."""
    sid = state.new_session(person_id)
    resp = RedirectResponse(to, status_code=303)
    resp.set_cookie(COOKIE, sid, max_age=SESSION_TTL_S, secure=True, httponly=True, samesite="strict")
    resp.delete_cookie(PRE_COOKIE, secure=True, httponly=True, samesite="strict")
    return resp


# --- HTML ----------------------------------------------------------------------------------------

CSS = """
:root { color-scheme: light; --bg: #ffffff; --fg: #0d0d0d; --muted: #5e5e5e; --card: #ffffff;
  --line: rgba(0,0,0,.13); --soft: #f4f4f4; --accent: #0d0d0d; --accent-fg: #ffffff; --ok: #17723d;
  --bad: #b3261e; --radius: 6px; --pill: 9999px; }
* { box-sizing: border-box; }
html { -webkit-text-size-adjust: 100%; }
body { margin: 0; background: var(--bg); color: var(--fg);
  font: 17px/1.55 system-ui, -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, "Helvetica Neue", Arial,
  sans-serif; -webkit-font-smoothing: antialiased; }
a { color: var(--fg); text-underline-offset: 3px; text-decoration-thickness: 1px; }
header { padding: 16px 20px 14px; border-bottom: 1px solid var(--line); background: var(--bg); }
header .box { font-weight: 650; letter-spacing: -0.01em; }
header .who { color: var(--muted); font-size: 15px; margin-top: 2px; }
nav { display: flex; flex-wrap: wrap; gap: 8px; margin-top: 12px; align-items: center; }
nav a, nav button { padding: 6px 14px; border-radius: var(--pill); text-decoration: none; color: var(--fg);
  border: 1px solid var(--line); background: transparent; font: inherit; font-size: 15px; cursor: pointer; }
nav a:hover, nav button:hover { background: var(--soft); }
nav a.here { background: var(--accent); color: var(--accent-fg); border-color: var(--accent); }
nav form { margin: 0; }
main { padding: 28px 20px 48px; max-width: 680px; margin: 0 auto; }
h1 { font-size: 30px; line-height: 1.2; letter-spacing: -0.02em; font-weight: 650; margin: 4px 0 18px; }
h2 { font-size: 19px; letter-spacing: -0.01em; font-weight: 650; margin: 4px 0 10px; }
p { margin: 10px 0; }
.card { background: var(--card); border: 1px solid var(--line); border-radius: var(--radius); padding: 20px;
  margin: 16px 0; box-shadow: none; }
.card > :first-child { margin-top: 0; }
.card > :last-child { margin-bottom: 0; }
label { display: block; font-weight: 600; margin: 16px 0 6px; }
input[type=text], input[type=password], input[type=file], select, textarea { width: 100%; padding: 11px 14px;
  font: inherit; border-radius: var(--radius); border: 1px solid var(--line); background: var(--bg);
  color: var(--fg); }
input:focus, select:focus, textarea:focus, button:focus-visible, a:focus-visible {
  outline: 2px solid var(--fg); outline-offset: 2px; }
input.code { letter-spacing: 4px; text-transform: uppercase; font-size: 22px; text-align: center; }
button.main, .button { display: inline-block; margin-top: 16px; padding: 11px 22px; border-radius: var(--pill);
  border: 1px solid var(--accent); background: var(--accent); color: var(--accent-fg); font: inherit;
  font-weight: 600; cursor: pointer; text-decoration: none; line-height: 1.3; }
button.main:hover, .button:hover { background: #2b2b2b; border-color: #2b2b2b; }
button.quiet, button.main.quiet { background: transparent; color: var(--fg); border: 1px solid var(--line); }
button.quiet:hover, button.main.quiet:hover { background: var(--soft); border-color: var(--line); }
button.danger { display: inline-block; margin-top: 12px; padding: 9px 18px; border-radius: var(--pill);
  background: transparent; color: var(--bad); border: 1px solid var(--bad); font: inherit; font-weight: 600;
  cursor: pointer; }
button.danger:hover { background: #fbeceb; }
.row { display: flex; gap: 10px; flex-wrap: wrap; align-items: center; }
.row form { margin: 0; }
.muted { color: var(--muted); font-size: 15px; }
.ok { color: var(--ok); font-weight: 600; }
.bad { color: var(--bad); font-weight: 600; }
.value { font: 600 22px/1.3 ui-monospace, "SF Mono", Menlo, Consolas, monospace; word-break: break-all;
  padding: 14px 16px; border: 1px dashed var(--fg); border-radius: var(--radius); background: var(--soft);
  margin: 10px 0; }
main img { max-width: 100%; height: auto; display: block; border-radius: var(--radius); }
pre.value { white-space: pre-wrap; font-size: 16px; }
ul.files { list-style: none; padding: 0; margin: 0; }
ul.files li { padding: 12px 0; border-bottom: 1px solid var(--line); }
ul.files li:first-child { padding-top: 0; }
ul.files li:last-child { border-bottom: 0; padding-bottom: 0; }
ol.steps { margin: 0; padding-left: 22px; }
ol.steps li { padding: 10px 0; border-bottom: 1px solid var(--line); }
ol.steps li:last-child { border-bottom: 0; padding-bottom: 0; }
ol.steps .row { justify-content: space-between; }
ol.steps .ok { font-size: 14px; padding: 2px 10px; border: 1px solid var(--line); border-radius: var(--pill); }
.name { word-break: break-all; }
label.check { display: flex; gap: 10px; align-items: center; font-weight: 400; margin: 8px 0; }
fieldset { border: 1px solid var(--line); border-radius: var(--radius); margin: 16px 0; padding: 10px 16px 14px; }
legend { font-weight: 600; padding: 0 6px; }
.qr svg { display: block; max-width: 100%; height: auto; margin: 10px 0; }
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
          pending: int | None = None, nav: list[tuple[str, str]] | None = None,
          refresh: str = "") -> HTMLResponse:
    """refresh, when set, is a meta refresh such as "30;url=/approvals" (no script, so the CSP holds)."""
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
           + (f'<meta http-equiv="refresh" content="{esc(refresh)}">' if refresh else "") +
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
        raise UploadError("That file has no type. Use .txt, .md, .pdf, .json, .csv or a photo.")
    suffix = "." + suffix.lower()
    if suffix not in ALLOWED_SUFFIXES:
        raise UploadError("That file type isn't allowed. Use .txt, .md, .pdf, .json, .csv or a photo "
                          "(.jpg, .png, .webp).")
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


PHOTO_SUFFIXES = {".jpg", ".jpeg", ".png", ".webp", ".heic", ".heif"}   # sent to the photo reader
OUTSIDE_MSG = "That file's name points outside the folder you picked, so it was left out."


def flatten_name(raw: str) -> str:
    """One plain file name from what the browser sent. A whole-folder upload sends paths such as
    "Taxes/2025/w2.pdf": the top folder is dropped and the rest joined, so it becomes "2025_w2.pdf".
    Paths with "..", absolute paths and hidden parts (".git/...") are refused."""
    s = (raw or "").replace("\\", "/")
    if s.startswith("/") or re.match(r"^[A-Za-z]:/", s):
        raise UploadError(OUTSIDE_MSG)
    parts = [p for p in s.split("/") if p not in ("", ".")]
    if ".." in parts:
        raise UploadError(OUTSIDE_MSG)
    if not parts:
        raise UploadError("That file has no name.")
    if len(parts) > 1:
        if any(p.startswith(".") for p in parts):
            raise UploadError("That is a hidden system file, so it was left out.")
        parts = parts[1:]
    return "_".join(parts)


def upload_folder(cfg: Config, person: Person, choice: str, *, others: bool = False) -> str:
    """Folder (relative to files/) for an upload choice, or raise.

    others=True also takes "people/<id>/<folder>" for another person's folder the uploader may file
    into (access.can_file): the upload page offers those. Other callers keep to the person's own."""
    if choice == "shared":
        return "shared"
    if choice in PERSON_FOLDERS:
        return f"people/{person.id}/{choice}"
    if others:
        rel = access.canonical(choice)
        parts = PurePosixPath(rel).parts
        if (len(parts) == 3 and parts[0] == "people" and parts[1] in cfg.people and parts[1] != person.id
                and parts[2] in PERSON_FOLDERS and access.can_file(person, f"{rel}/x")):
            return rel
    raise UploadError("Pick one of the folders in the list.")


def filing_choices(cfg: Config, person: Person) -> list[tuple[str, str, bool]]:
    """(value, label, drop_off) for every other person's folder this person may file into.
    drop_off: they can put a file there but can't open it afterwards (a health folder)."""
    out = []
    for other in sorted(cfg.people.values(), key=lambda p: p.display.lower()):
        if other.id == person.id:
            continue
        for f in PERSON_FOLDERS:
            probe = f"people/{other.id}/{f}/x"
            if access.can_file(person, probe):
                out.append((f"people/{other.id}/{f}", f"{other.display}'s {FOLDER_LABELS[f]}",
                            not access.can_read(person, probe)))
    return out


def audit_filing(cfg: Config, person: Person, rel_folder: str, event: str, data: bytes) -> None:
    """One audit line for a new file. Filed into someone else's folder: a line on both logs."""
    entry = {"event": event, "folder": rel_folder, "sha256": hashlib.sha256(data).hexdigest(), "bytes": len(data)}
    owner = access.owner_of(rel_folder + "/x")
    if owner and owner != person.id:
        _audit(cfg, person.id, entry | {"for": owner})
        _audit(cfg, owner, entry | {"by": person.id})
    else:
        _audit(cfg, person.id, entry)


def save_upload(cfg: Config, person: Person, choice: str, filename: str, data: bytes, *,
                others: bool = False) -> str:
    """Write the file atomically with 0600 perms and no overwrite. Returns its path relative to files/.
    others: see upload_folder."""
    if len(data) > MAX_UPLOAD:
        raise UploadError("That file is too big. The limit is 25 MB.")
    if not data:
        raise UploadError("That file is empty.")
    rel_folder = upload_folder(cfg, person, choice, others=others)
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
    audit_filing(cfg, person, rel_folder, "upload", data)
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
    page(sess, title, body, here="", status=200, refresh="") -> HTMLResponse in the box's look, with the nav bar
                             (refresh: optional meta refresh such as "30;url=/approvals")
    need_signin(handler)     decorator: async handler(request, sess); redirects to /signin when signed out
    guarded_form(request, **form_kw) -> (sess, form) or a 403 Response: signed in + same origin + CSRF ok
    csrf_field(token)        hidden <input> for a form; use sess.csrf as the token
    forbidden(msg=...)       403 page
    esc(text)                HTML escape
    box()                    a shared familybox.box.Box (made on first use)
    state                    the shared WebState (codes, sessions)
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
    state: Any = None


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

    def page(sess: Sess, title: str, body: str, here: str = "", status: int = 200, refresh: str = "") -> HTMLResponse:
        return _page(cfg, title, body, sess, here, status, pending_count(sess.person), nav, refresh)

    def forbidden(msg: str = "That request wasn't allowed. Go back, reload the page and try again.") -> HTMLResponse:
        return _page(cfg, "Not allowed", f'<h1>Not allowed</h1><p>{esc(msg)}</p><p><a href="/">Go home</a></p>',
                     status=403)

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
        from . import household
        err = f'<p class="bad">{esc(error)}</p>' if error else ""
        with_pin = [p for p in sorted(cfg.people.values(), key=lambda p: p.display.lower())
                    if household.has_pin(state, p.id)]
        pin_form = ""
        if with_pin:
            opts = "".join(f'<option value="{esc(p.id)}">{esc(p.display)}</option>' for p in with_pin)
            pin_form = (f'<form method="post" action="/signin" class="card">{_csrf_field(pre)}'
                        f'<h2>Sign in with your PIN</h2>'
                        f'<label for="person">Your name</label><select id="person" name="person">{opts}</select>'
                        f'<label for="pin">Your PIN</label>'
                        f'<input type="password" id="pin" name="pin" inputmode="numeric" maxlength="12"'
                        f' autocomplete="current-password" required>'
                        f'<button class="main" type="submit">Sign in</button></form>')
        body = (f'<h1>Sign in</h1>{err}{pin_form}'
                f'<form method="post" action="/signin" class="card">{_csrf_field(pre)}'
                f'<h2>Sign in with a code</h2>'
                f'<p>Ask the person who runs the family box for a sign-in code. It works once and lasts 10 minutes.</p>'
                f'<label for="code">Your 8-letter code</label>'
                f'<input type="text" id="code" name="code" class="code" maxlength="12" autocomplete="one-time-code"'
                f' autocapitalize="characters" spellcheck="false" required>'
                f'<button class="main" type="submit">Sign in</button></form>')
        return set_pre_cookie(_page(cfg, "Sign in", body, status=status), pre)

    async def signin_get(request: Request):
        if session_of(request):
            return RedirectResponse("/", status_code=303)
        return signin_page(secrets.token_urlsafe(24))

    async def signin_post(request: Request):
        if not origin_ok(request):
            return forbidden()
        form = await request.form()
        if not pre_ok(request, form):
            return forbidden()
        if "pin" in form:
            from . import household
            person_id = str(form.get("person", ""))
            ok, why = household.check_pin(state, person_id, str(form.get("pin", "")))
            if not ok:
                msg = ("Too many wrong PINs for this name. Wait 10 minutes, or sign in with a code."
                       if why == "locked" else "That PIN didn't work. Check it and try again.")
                return signin_page(secrets.token_urlsafe(24), msg, status=429 if why == "locked" else 401)
            return signed_in(state, person_id)
        person_id, why = state.redeem(str(form.get("code", "")))
        if person_id is None:
            msg = ("Too many wrong codes. Wait 10 minutes, then try again." if why == "locked"
                   else "That code didn't work. Check it, or ask for a new one.")
            return signin_page(secrets.token_urlsafe(24), msg, status=429 if why == "locked" else 401)
        return signed_in(state, person_id)

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
    def first_steps(person: Person) -> str:
        """Plain first steps for a new box. Each one links to its page and says when it is done.
        A step whose page isn't on this box (its plugin is off) is left out."""
        from . import enclave
        have = {href for href, _ in nav} | {"/upload"}
        if "/family" in have:
            have.add("/settings/key")        # the key page comes with the Family page, but isn't in the nav
        try:
            n_files = len(readable_files(cfg, person))
        except Exception:  # noqa: BLE001 - the list is a hint, never a reason the home page fails
            n_files = 0
        steps = [("/upload", "Add your papers",
                  "Upload IDs, tax forms, school letters and more into your own folders.", n_files > 0)]
        if person.admin:
            steps.append(("/family", "Invite your family",
                          "Add each person, then send them a QR code so they pick their own PIN.",
                          len(cfg.people) > 1))
        steps.append(("/assistants", "Connect an assistant",
                      "Get a linking code so the AI assistant on your phone or computer can ask the box.", False))
        if person.admin:
            steps.append(("/settings/key", "Save the AI key",
                          "Paste your NEAR AI key once. The box needs it to answer questions and read photos.",
                          bool(enclave.api_key())))
        items = []
        for href, title, what, done in steps:
            if href not in have:
                continue
            mark = '<span class="ok">Done</span>' if done else ""
            items.append(f'<li><div class="row"><a href="{href}"><strong>{esc(title)}</strong></a>{mark}</div>'
                         f'<div class="muted">{esc(what)}</div></li>')
        return (f'<div class="card"><h2>First steps</h2><ol class="steps">{"".join(items)}</ol></div>'
                if items else "")

    @need_signin
    async def home(request: Request, sess: Sess):
        n = pending_count(sess.person)
        waiting = (f'<p><a class="button" href="/approvals">{n} waiting for you to approve</a></p>' if n
                   else '<p class="muted">Nothing is waiting for your approval.</p>')
        body = (f'<h1>Hi, {esc(sess.person.display)}</h1>{waiting}{first_steps(sess.person)}'
                f'<div class="card"><h2>What you can do here</h2><ul>'
                f'<li><a href="/upload">Upload a file</a> into your folders or the family\'s shared folder.</li>'
                f'<li><a href="/files">See your files</a> and remove ones you no longer want on the box.</li>'
                f'<li><a href="/approvals">Approve or deny</a> details an assistant asked for.</li>'
                f'<li><a href="/cloud">Cloud</a>: bring files in from Google Drive, and back up the box.</li>'
                f'<li><a href="/status">Box status</a>: is the box working, and is the AI key saved.</li>'
                f'</ul></div><p class="muted">This page only works on your home network.</p>')
        return page(sess, "Home", body, "/")

    # ---- upload
    def upload_form(sess: Sess, msg: str = "", ok: bool = False, status: int = 200, results: str = "") -> HTMLResponse:
        note = f'<p class="{"ok" if ok else "bad"}">{esc(msg)}</p>' if msg else ""
        opts = "".join(f'<option value="{f}">My {FOLDER_LABELS[f]}</option>' for f in PERSON_FOLDERS)
        opts += f'<option value="shared">{FOLDER_LABELS["shared"]}</option>'
        theirs = filing_choices(cfg, sess.person)
        for value, label, drop_off in theirs:
            extra = " (you can file here, but only they can open it)" if drop_off else ""
            opts += f'<option value="{esc(value)}">{esc(label + extra)}</option>'
        for_others = ("<p class=\"muted\">You can also file papers into the family folders you look after. "
                      "Health papers you file for someone else can only be opened by that person.</p>"
                      if theirs else "")
        accept = ",".join(sorted(ALLOWED_SUFFIXES | PHOTO_SUFFIXES))
        body = (f'<h1>Upload files</h1>{note}{results}'
                f'<form method="post" action="/upload" enctype="multipart/form-data" class="card">'
                f'{_csrf_field(sess.csrf)}'
                f'<label for="folder">Where should they go?</label><select id="folder" name="folder">{opts}</select>'
                f'{for_others}'
                f'<label for="file">Pick files</label>'
                f'<input type="file" id="file" name="file" accept="{accept}" multiple>'
                f'<label for="whole-folder">Or pick a whole folder</label>'
                f'<input type="file" id="whole-folder" name="file" webkitdirectory multiple>'
                f'<p class="muted">Text, Markdown, PDF, JSON, CSV, or photos and scans (JPG, PNG, WEBP). '
                f'Up to {MAX_FILES} files at once, each up to 25 MB, '
                f'{MAX_TOTAL_UPLOAD // (1024 * 1024)} MB in all. Photos go to the photo reader, which '
                f'writes down the text on them. Files in your folders are only for you. Shared files can be read '
                f'by everyone in the family.</p>'
                f'<button class="main" type="submit">Upload</button></form>')
        return page(sess, "Upload", body, "/upload", status)

    @need_signin
    async def upload_get(request: Request, sess: Sess):
        return upload_form(sess)

    def where_label(person: Person, rel_folder: str) -> str:
        owner = access.owner_of(rel_folder + "/x")
        kind = PurePosixPath(rel_folder).name
        if rel_folder == "shared":
            return FOLDER_LABELS["shared"]
        if owner == person.id:
            return f"My {FOLDER_LABELS.get(kind, kind)}"
        return f"{cfg.people[owner].display}'s {FOLDER_LABELS.get(kind, kind)}"

    async def read_photo(person: Person, rel: str) -> tuple[str, str]:
        """Send a just-saved photo to the photo reader. Returns (status, words)."""
        from . import enclave, vision
        owner_id = access.owner_of(rel)
        owner = cfg.people[owner_id] if owner_id and owner_id != person.id else person
        drop_off = not access.can_read(person, rel)
        if not enclave.api_key():
            who = "you" if owner is person else owner.display
            return "later", (f"Photo saved, not read yet. Once the AI key is saved, {who} can have it read "
                             f"from the Photos page.")
        res = await vision.transcribe_photo(cfg, owner, rel, source="web",
                                            by=person.id if owner is not person else None)
        if not res.ok:
            return "later", ("Photo saved, but the box couldn't read it right now. Nothing was shared. "
                             "It can be read again from the Photos page.")
        if drop_off:
            return "photo", "Photo saved and read. Only its owner can see what it says."
        found = (", ".join(f"{label} {vision.masked(v)}" for label, v in res.fields) if res.fields
                 else "no ID numbers")
        return "photo", f"Photo saved and read. Found: {found}."

    async def upload_post(request: Request):
        from starlette.exceptions import HTTPException
        try:
            # One more part than MAX_FILES: a browser sends an empty part for a file box left blank.
            got = await guarded_form(request, max_files=MAX_FILES + 1, max_fields=8, max_part_size=4096)
        except HTTPException:
            sess = session_of(request)
            if sess is None:
                raise
            return upload_form(sess, f"That was too many files. Upload up to {MAX_FILES} at a time.", status=400)
        if isinstance(got, Response):
            return got
        sess, form = got
        person = sess.person
        results: list[tuple[str, str, str]] = []     # (name as sent, status, words)
        changed = False
        try:
            choice = str(form.get("folder", ""))
            try:
                rel_folder = upload_folder(cfg, person, choice, others=True)
            except UploadError as e:
                return upload_form(sess, str(e), status=400)
            parts = [f for f in form.getlist("file") if not isinstance(f, str) and (f.filename or f.size)]
            if not parts:
                return upload_form(sess, "Choose a file or a folder first.", status=400)
            if len(parts) > MAX_FILES:
                return upload_form(sess, f"That was too many files. Upload up to {MAX_FILES} at a time.",
                                   status=400)
            drop_off = not access.can_read(person, rel_folder + "/x")
            where = where_label(person, rel_folder)
            total = 0
            for f in parts:
                shown = (f.filename or "").replace("\\", "/")[-120:] or "(no name)"
                try:
                    name = flatten_name(f.filename or "")
                    if f.size is not None and f.size > MAX_UPLOAD:
                        raise UploadError("That file is too big. The limit is 25 MB.")
                    if total + (f.size or 0) > MAX_TOTAL_UPLOAD:
                        raise UploadError(f"The upload went over {MAX_TOTAL_UPLOAD // (1024 * 1024)} MB in total, "
                                          f"so this file was left out. Upload it again on its own.")
                    data = await f.read(MAX_UPLOAD + 1)
                    total += len(data)
                    if total > MAX_TOTAL_UPLOAD:
                        raise UploadError(f"The upload went over {MAX_TOTAL_UPLOAD // (1024 * 1024)} MB in total, "
                                          f"so this file was left out. Upload it again on its own.")
                    if PurePosixPath(name).suffix.lower() in PHOTO_SUFFIXES:
                        from . import vision
                        try:
                            rel = vision.save_photo(cfg, person, choice, name, data, others=True)
                        except vision.PhotoError as e:
                            raise UploadError(str(e)) from None
                        changed = True
                        if drop_off:
                            state.note_filed(person.id, rel)
                        status, words = await read_photo(person, rel)
                    else:
                        rel = save_upload(cfg, person, choice, name, data, others=True)
                        changed = True
                        if drop_off:
                            state.note_filed(person.id, rel)
                        status, words = "saved", f"Saved in {where}."
                    if drop_off:
                        owner = cfg.people[access.owner_of(rel)].display
                        words += f" Filed for {owner}. Only {owner} can open it."
                    results.append((shown, status, words))
                except UploadError as e:
                    results.append((shown, "skipped", f"Left out: {e}"))
        finally:
            await form.close()
        if changed:
            _reindex(cfg)
        done = sum(1 for _, st, _ in results if st != "skipped")
        left = len(results) - done
        rows = "".join(f'<li><div class="name">{esc(n)}</div>'
                       f'<div class="{"bad" if st == "skipped" else "ok" if st != "later" else "muted"}">'
                       f'{esc(w)}</div></li>' for n, st, w in results)
        listing = f'<div class="card"><h2>What happened to each file</h2><ul class="files">{rows}</ul></div>'
        if done:
            msg = (f"Uploaded {done} file{'s' if done != 1 else ''}"
                   + (f", {left} left out" if left else "") + ". Your assistant can use "
                   + ("it" if done == 1 else "them") + " now.")
        else:
            msg = "Nothing was uploaded. See why below."
        return upload_form(sess, msg, ok=bool(done), status=200 if done else 400, results=listing)

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
        # Files this person filed where they can't read them: a count per person, never the names.
        filed = []
        for owner, n in sorted(state.filed_counts(sess.person.id).items()):
            if owner in cfg.people and owner != sess.person.id:
                who = cfg.people[owner].display
                filed.append(f'<li>{n} file{"s" if n != 1 else ""} filed for {esc(who)}. '
                             f'Only {esc(who)} can open {"them" if n != 1 else "it"}.</li>')
        filed_card = (f'<div class="card"><h2>Filed for others</h2><ul>{"".join(filed)}</ul></div>'
                      if filed else "")
        body = (f'<h1>Your files</h1>{note}<p class="muted">These are the files your assistant can use when you ask '
                f'a question. You can remove your own files.</p><div class="card">{listing}</div>{filed_card}')
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
    REVEAL_S = 30

    def approvals_page(sess: Sess, extra: str = "", status: int = 200, refresh: str = "") -> HTMLResponse:
        from . import household
        items = Approvals(cfg).pending(sess.person.id)
        needs_pin = household.has_pin(state, sess.person.id)
        cards = []
        for it in items:
            asker = cfg.people[it["asker"]].display if it["asker"] in cfg.people else it["asker"]
            asker = "You" if it["asker"] == sess.person.id else asker
            pin = ""
            if needs_pin:
                pin = (f'<label for="pin-{esc(it["id"])}">Your PIN, to show it</label>'
                       f'<input type="password" id="pin-{esc(it["id"])}" name="pin" inputmode="numeric"'
                       f' maxlength="{household.PIN_MAX}" autocomplete="current-password" required>')
            cards.append(
                f'<div class="card"><div><strong>{esc(it["label"])}</strong></div>'
                f'<div class="muted">{esc(asker)} asked: "{esc(it["question"])}"</div>'
                f'<div class="muted">From: {esc(it["path"])}</div>'
                f'<div class="row">'
                f'<form method="post" action="/approvals/{esc(it["id"])}/approve">{_csrf_field(sess.csrf)}{pin}'
                f'<button class="main" type="submit">Approve and show it here</button></form>'
                f'<form method="post" action="/approvals/{esc(it["id"])}/deny">{_csrf_field(sess.csrf)}'
                f'<button class="main quiet" type="submit">Deny</button></form></div></div>')
        listing = "".join(cards) or '<p class="muted">Nothing is waiting for you.</p>'
        body = (f'<h1>Approvals</h1>{extra}<p class="muted">When an assistant\'s answer included one of your private '
                f'details, the box held it back. Approving shows it on this page only. It is never sent to the '
                f'assistant.</p>{listing}')
        return page(sess, "Approvals", body, "/approvals", status, refresh)

    @need_signin
    async def approvals_get(request: Request, sess: Sess):
        return approvals_page(sess)

    async def approvals_decide(request: Request):
        got = await guarded_form(request, max_files=0, max_fields=4, max_part_size=1024)
        if isinstance(got, Response):
            return got
        sess, form = got
        item_id = request.path_params["item_id"]
        if request.path_params["action"] not in ("approve", "deny"):
            return _page(cfg, "Not found", "<h1>Not found</h1>", sess, status=404)
        approve = request.path_params["action"] == "approve"
        appr = Approvals(cfg)
        if item_id not in {it["id"] for it in appr.pending(sess.person.id)}:
            return _page(cfg, "Not found", '<h1>Not found</h1><p>That item isn\'t waiting for you.</p>'
                         '<p><a href="/approvals">Back to approvals</a></p>', sess, status=404)
        if approve:
            from . import household
            if household.has_pin(state, sess.person.id):
                # Showing a held value needs the PIN again, so an unlocked phone left on a table is not enough.
                # Wrong PINs count toward this person's PIN lockout, the same one sign-in uses.
                ok, why = household.check_pin(state, sess.person.id, str(form.get("pin", "")))
                if not ok:
                    msg = ("Too many wrong PINs. Wait 10 minutes, then try again." if why == "locked"
                           else "That PIN didn't work. Nothing was shown. Try again.")
                    return approvals_page(sess, f'<p class="bad">{esc(msg)}</p>',
                                          status=429 if why == "locked" else 401)
        result = appr.decide(sess.person.id, item_id, approve)
        if approve:
            extra = (f'<div class="card"><p class="ok">Approved. Here is your {esc(result["label"])}:</p>'
                     f'<div class="value">{esc(result["value"])}</div>'
                     f'<p class="muted">Only you can see this. Hides in {REVEAL_S} seconds, and it won\'t be shown '
                     f'again after that.</p></div>')
            return approvals_page(sess, extra, refresh=f"{REVEAL_S};url=/approvals")
        return approvals_page(sess, '<p class="ok">Denied. Nothing was shared.</p>')

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
        Route("/upload", upload_post, methods=["POST"], max_body_size=MAX_TOTAL_UPLOAD + FORM_SLACK),
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
                     csrf_field=_csrf_field, forbidden=forbidden, esc=esc, box=get_box, state=state)
    for extra in plugins.call_each("web_routes", ctx):
        routes.extend(extra or [])   # after the core routes, so a plugin can never shadow them
    if remote_only:
        from .remote import REMOTE_PATHS
        routes = [r for r in routes if getattr(r, "path", None) in REMOTE_PATHS]
    app = Starlette(routes=routes, max_body_size=FORM_SLACK)
    if remote_only:
        return SecurityHeaders(app)   # the internet listener never offers setup
    return SecurityHeaders(SetupGate(app, cfg))


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
