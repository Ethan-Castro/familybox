"""Remote MCP for ChatGPT, Claude and other assistants that connect over the internet.

The box is its own OAuth 2.1 authorization server, and /mcp is a protected resource:

  /.well-known/oauth-authorization-server          RFC 8414 metadata
  /.well-known/oauth-protected-resource[/mcp]      RFC 9728 metadata
  /register                                        RFC 7591 dynamic client registration
  /authorize                                       authorization code + PKCE (S256 only)
  /authorize/consent                               the family member types a one-time sign-in code
                                                   (familybox code --as X) and approves the link
  /token                                           code and refresh grants (refresh tokens rotate)
  /revoke                                          RFC 7009
  /mcp                                             streamable HTTP MCP; the person comes from the token

The protocol handlers come from the MCP SDK (mcp.server.auth). This module supplies the storage,
the consent page logic, and client authentication that compares hashed client secrets.

Everything secret is stored as a SHA-256 hash in <runtime>/remote/state.json (0600, folder 0700):
client secrets, authorization codes, access tokens, refresh tokens and per-person API tokens. A
copy of state.json reveals who linked which assistant, never a usable credential.

Lifetimes: consent request 10 minutes, authorization code 5 minutes (single use), access token
1 hour, refresh token 30 days from last use (rotated on every use; presenting an old one again
revokes the whole connection). API tokens last until revoked.
"""

from __future__ import annotations

import asyncio
import base64
import binascii
import contextlib
import contextvars
import fcntl
import hashlib
import hmac
import json
import logging
import os
import secrets
import time
from dataclasses import dataclass
from typing import Any
from urllib.parse import unquote, urlsplit

from mcp.server.auth.middleware.bearer_auth import AuthenticatedUser
from mcp.server.auth.middleware.client_auth import AuthenticationError, ClientAuthenticator
from mcp.server.auth.provider import (
    AccessToken,
    AuthorizationCode,
    AuthorizationParams,
    AuthorizeError,
    RefreshToken,
    RegistrationError,
    TokenError,
    construct_redirect_uri,
)
from mcp.shared.auth import OAuthClientInformationFull, OAuthToken
from starlette.authentication import AuthCredentials
from starlette.types import Receive, Scope, Send

from .config import Config

log = logging.getLogger("familybox.remote")

SCOPE = "family"
PENDING_TTL_S = 10 * 60
CODE_TTL_S = 5 * 60
ACCESS_TTL_S = 60 * 60
REFRESH_TTL_S = 30 * 24 * 60 * 60
UNLINKED_CLIENT_TTL_S = 24 * 60 * 60
MAX_CLIENTS = 200
MAX_PENDING = 50
MAX_REDIRECT_URIS = 10
MAX_URI_LEN = 2000
LAST_USED_EVERY_S = 60

ACCESS_PREFIX = "fba_"
REFRESH_PREFIX = "fbr_"
API_PREFIX = "fbk_"
CODE_PREFIX = "fbc_"

BLOCKED_SCHEMES = {"javascript", "data", "file", "vbscript", "about", "blob", "ftp", "ws", "wss", "filesystem"}
LOOPBACK_HOSTS = {"localhost", "127.0.0.1", "[::1]", "::1"}


def _h(secret: str) -> str:
    return hashlib.sha256(secret.encode()).hexdigest()


def _now() -> float:
    return time.time()


def _short_id(prefix: str) -> str:
    return f"{prefix}{secrets.token_hex(4)}"


def public_url(cfg: Config) -> str | None:
    """The box's public https address, if the owner set one (FAMILYBOX_PUBLIC_URL or [remote] public_url)."""
    url = os.environ.get("FAMILYBOX_PUBLIC_URL", "").strip()
    if not url:
        try:
            import tomllib
            data = tomllib.loads((cfg.home / "family.toml").read_text())
            url = str(data.get("remote", {}).get("public_url", "")).strip()
        except (OSError, ValueError):
            url = ""
    if not url:
        return None
    parts = urlsplit(url)
    if parts.scheme != "https" and parts.hostname not in LOOPBACK_HOSTS:
        raise ValueError("public_url must start with https://")
    if parts.query or parts.fragment or parts.path not in ("", "/"):
        raise ValueError("public_url must be just https://host[:port], with no path")
    return f"{parts.scheme}://{parts.netloc}"


def resource_of(base: str) -> str:
    return base.rstrip("/") + "/mcp"


def resource_matches(requested: str | None, base: str) -> bool:
    """RFC 8707: accept the /mcp address or the bare box address (some clients send either)."""
    if requested is None:
        return True
    r = requested.strip().rstrip("/")
    b = base.rstrip("/")
    return r.lower() in (b.lower(), resource_of(b).lower())


def check_redirect_uri(uri: str) -> None:
    """https anywhere, http only to this computer (loopback), app links (custom schemes) for desktop apps."""
    if len(uri) > MAX_URI_LEN:
        raise RegistrationError("invalid_redirect_uri", "redirect_uri is too long")
    parts = urlsplit(uri)
    scheme = parts.scheme.lower()
    if not scheme or scheme in BLOCKED_SCHEMES:
        raise RegistrationError("invalid_redirect_uri", f"redirect_uri scheme {scheme!r} is not allowed")
    if parts.fragment:
        raise RegistrationError("invalid_redirect_uri", "redirect_uri must not have a fragment")
    if scheme == "http" and (parts.hostname or "").lower() not in LOOPBACK_HOSTS:
        raise RegistrationError("invalid_redirect_uri", "http redirect_uri is only allowed for localhost")
    if scheme in ("http", "https") and not parts.hostname:
        raise RegistrationError("invalid_redirect_uri", "redirect_uri needs a host")


# --- storage ------------------------------------------------------------------------------------

EMPTY = {"clients": {}, "pending": {}, "codes": {}, "used_codes": {}, "grants": {}, "access": {}, "refresh": {},
         "retired": {}, "api": {}}


class RemoteStore:
    """All remote-access state in one JSON file under an exclusive lock, so the CLI and server agree."""

    def __init__(self, cfg: Config):
        self.cfg = cfg
        self.dir = cfg.runtime / "remote"
        self.dir.mkdir(parents=True, exist_ok=True, mode=0o700)
        os.chmod(self.dir, 0o700)
        self.path = self.dir / "state.json"
        self._last_used_mem: dict[str, float] = {}

    @contextlib.contextmanager
    def edit(self):
        """Yields the state dict; it is saved on exit. Expired items are dropped first."""
        fd = os.open(self.dir / ".lock", os.O_WRONLY | os.O_CREAT, 0o600)
        try:
            fcntl.flock(fd, fcntl.LOCK_EX)
            st = self._read()
            self._prune(st)
            yield st
            self._write(st)
        finally:
            fcntl.flock(fd, fcntl.LOCK_UN)
            os.close(fd)

    def read(self) -> dict:
        st = self._read()
        self._prune(st)
        return st

    def _read(self) -> dict:
        try:
            data = json.loads(self.path.read_text())
        except (OSError, ValueError):
            data = {}
        return {k: dict(data.get(k, {})) for k in EMPTY}

    def _write(self, st: dict) -> None:
        from .web import _write_private
        _write_private(self.path, json.dumps(st, indent=0).encode())

    @staticmethod
    def _prune(st: dict) -> None:
        now = _now()
        for k in ("pending", "codes", "access", "refresh"):
            st[k] = {h: v for h, v in st[k].items() if v["expires"] > now}
        st["used_codes"] = {h: v for h, v in st["used_codes"].items() if v["expires"] > now}
        st["retired"] = {h: v for h, v in st["retired"].items() if v["expires"] > now}
        live_clients = {g["client_id"] for g in st["grants"].values()}
        live_clients |= {p["client_id"] for p in st["pending"].values()}
        st["clients"] = {cid: c for cid, c in st["clients"].items()
                         if cid in live_clients or now - c.get("client_id_issued_at", now) < UNLINKED_CLIENT_TTL_S}

    @staticmethod
    def _drop_grant(st: dict, grant_id: str) -> dict | None:
        g = st["grants"].pop(grant_id, None)
        for k in ("access", "refresh", "retired", "used_codes"):
            st[k] = {h: v for h, v in st[k].items() if v.get("grant") != grant_id}
        return g

    # ---- connections (for the CLI and the web page)

    def connections(self, person_id: str) -> list[dict]:
        st = self.read()
        out = []
        for gid, g in st["grants"].items():
            if g["person"] == person_id:
                out.append({"id": gid, "kind": "oauth", "name": g.get("client_name") or "Unnamed assistant",
                            "returns_to": g.get("redirect_host", ""), "created": g["created"],
                            "last_used": g.get("last_used")})
        for tid, t in st["api"].items():
            if t["person"] == person_id:
                out.append({"id": tid, "kind": "token", "name": t.get("label") or "API token",
                            "returns_to": "", "created": t["created"], "last_used": t.get("last_used")})
        return sorted(out, key=lambda c: c["created"])

    def revoke(self, person_id: str, conn_id: str) -> bool:
        """Revoke one of person_id's connections. False if it isn't theirs or doesn't exist."""
        with self.edit() as st:
            g = st["grants"].get(conn_id)
            if g is not None and g["person"] == person_id:
                self._drop_grant(st, conn_id)
                return True
            t = st["api"].get(conn_id)
            if t is not None and t["person"] == person_id:
                st["api"].pop(conn_id)
                return True
        return False

    def revoke_all(self, person_id: str) -> int:
        with self.edit() as st:
            ids = [gid for gid, g in st["grants"].items() if g["person"] == person_id]
            for gid in ids:
                self._drop_grant(st, gid)
            tids = [tid for tid, t in st["api"].items() if t["person"] == person_id]
            for tid in tids:
                st["api"].pop(tid)
        return len(ids) + len(tids)

    def new_api_token(self, person_id: str, label: str = "") -> tuple[str, str]:
        """Returns (connection id, token). The token is shown once and stored only as a hash."""
        self.cfg.person(person_id)  # KeyError for unknown people
        token = API_PREFIX + secrets.token_urlsafe(32)
        tid = _short_id("t_")
        with self.edit() as st:
            st["api"][tid] = {"person": person_id, "hash": _h(token), "label": label.strip()[:60],
                              "created": int(_now()), "last_used": None}
        return tid, token

    # ---- bearer verification for /mcp

    def verify_bearer(self, token: str) -> dict | None:
        """{'person', 'client', 'conn', 'resource', 'expires', 'kind'} for a live token, else None."""
        if not token or len(token) > 200:
            return None
        th = _h(token)
        st = self.read()
        hit = None
        if token.startswith(API_PREFIX):
            for tid, t in st["api"].items():
                if hmac.compare_digest(t["hash"], th):
                    hit = {"person": t["person"], "client": f"token:{tid}", "conn": tid, "resource": None,
                           "expires": None, "kind": "token"}
        elif token.startswith(ACCESS_PREFIX):
            a = st["access"].get(th)
            if a is not None and a["grant"] in st["grants"]:
                hit = {"person": a["person"], "client": a["client_id"], "conn": a["grant"],
                       "resource": a.get("resource"), "expires": int(a["expires"]), "kind": "oauth"}
        if hit is None or hit["person"] not in self.cfg.people:
            return None
        self._touch(hit["conn"])
        return hit

    def _touch(self, conn: str) -> None:
        now = _now()
        if now - self._last_used_mem.get(conn, 0) < LAST_USED_EVERY_S:
            return
        self._last_used_mem[conn] = now
        with self.edit() as st:
            for k in ("grants", "api"):
                if conn in st[k]:
                    st[k][conn]["last_used"] = int(now)


# --- the OAuth provider (plugs into the SDK's handlers) --------------------------------------------

# The request's base address (https://host[:port]), set by the routes for each auth request.
current_base: contextvars.ContextVar[str] = contextvars.ContextVar("familybox_remote_base", default="")


class BoxCode(AuthorizationCode):
    person: str = ""
    client_name: str = ""
    redirect_host: str = ""
    code_hash: str = ""


class BoxRefresh(RefreshToken):
    grant: str = ""
    person: str = ""


class BoxProvider:
    """OAuthAuthorizationServerProvider for the family box."""

    def __init__(self, store: RemoteStore):
        self.store = store

    # ---- clients (RFC 7591)

    @staticmethod
    def _to_client(rec: dict) -> OAuthClientInformationFull:
        data = {k: v for k, v in rec.items() if k != "secret_hash"}
        return OAuthClientInformationFull.model_validate(data)

    async def get_client(self, client_id: str) -> OAuthClientInformationFull | None:
        if not client_id or len(client_id) > 100:
            return None
        rec = self.store.read()["clients"].get(client_id)
        return self._to_client(rec) if rec else None

    def client_secret_hash(self, client_id: str) -> str | None:
        rec = self.store.read()["clients"].get(client_id)
        return rec.get("secret_hash") if rec else None

    async def register_client(self, client_info: OAuthClientInformationFull) -> None:
        uris = [str(u) for u in (client_info.redirect_uris or [])]
        if not uris or len(uris) > MAX_REDIRECT_URIS:
            raise RegistrationError("invalid_redirect_uri", f"give 1 to {MAX_REDIRECT_URIS} redirect_uris")
        for u in uris:
            check_redirect_uri(u)
        if set(client_info.grant_types) - {"authorization_code", "refresh_token"}:
            raise RegistrationError("invalid_client_metadata",
                                    "only authorization_code and refresh_token grants are supported")
        if client_info.token_endpoint_auth_method not in ("none", "client_secret_post", "client_secret_basic"):
            raise RegistrationError("invalid_client_metadata", "unsupported token_endpoint_auth_method")
        rec = client_info.model_dump(mode="json", exclude_none=True)
        rec["client_name"] = (client_info.client_name or "").strip()[:80]
        secret = rec.pop("client_secret", None)
        if secret:
            rec["secret_hash"] = _h(secret)
        with self.store.edit() as st:
            if len(st["clients"]) >= MAX_CLIENTS:
                # Make room by dropping the oldest apps that never linked to anyone, so a flood of
                # registrations can't lock real assistants out.
                busy = {g["client_id"] for g in st["grants"].values()} | \
                       {p["client_id"] for p in st["pending"].values() if p.get("person")}
                idle = sorted((c.get("client_id_issued_at", 0), cid) for cid, c in st["clients"].items()
                              if cid not in busy)
                for _, cid in idle[:len(st["clients"]) - MAX_CLIENTS + 1]:
                    st["clients"].pop(cid)
                    st["pending"] = {h: p for h, p in st["pending"].items() if p["client_id"] != cid}
            if len(st["clients"]) >= MAX_CLIENTS:
                raise RegistrationError("invalid_client_metadata", "too many apps are linked to this box")
            st["clients"][client_info.client_id] = rec

    # ---- authorize: park the request until the family member approves it on the consent page

    async def authorize(self, client: OAuthClientInformationFull, params: AuthorizationParams) -> str:
        base = current_base.get()
        if not resource_matches(params.resource, base):
            raise AuthorizeError("invalid_target", "this box only issues tokens for its own /mcp address")
        scopes = params.scopes or [SCOPE]
        if set(scopes) - {SCOPE}:
            raise AuthorizeError("invalid_scope", f"the only scope is {SCOPE!r}")
        req_id = secrets.token_urlsafe(24)
        with self.store.edit() as st:
            if len(st["pending"]) >= MAX_PENDING:
                # Drop the oldest requests nobody has typed a code into yet.
                fresh = sorted((p["created"], h) for h, p in st["pending"].items() if not p.get("person"))
                for _, h in fresh[:len(st["pending"]) - MAX_PENDING + 1]:
                    st["pending"].pop(h)
            if len(st["pending"]) >= MAX_PENDING:
                raise AuthorizeError("temporarily_unavailable", "too many sign-in requests; try again soon")
            st["pending"][_h(req_id)] = {
                "client_id": client.client_id, "client_name": (client.client_name or "")[:80],
                "redirect_uri": str(params.redirect_uri),
                "redirect_explicit": params.redirect_uri_provided_explicitly,
                "state": params.state, "scopes": scopes, "code_challenge": params.code_challenge,
                "resource": resource_of(base), "created": int(_now()), "expires": _now() + PENDING_TTL_S,
                "person": None, "nonce": None}
        return f"/authorize/consent?req={req_id}"

    # The consent page calls these three.

    def pending(self, req_id: str) -> dict | None:
        if not req_id or len(req_id) > 100:
            return None
        return self.store.read()["pending"].get(_h(req_id))

    def bind_person(self, req_id: str, person_id: str) -> str | None:
        """After a good sign-in code: remember who is approving. Returns a one-time approval nonce."""
        nonce = secrets.token_urlsafe(24)
        with self.store.edit() as st:
            p = st["pending"].get(_h(req_id))
            if p is None:
                return None
            p["person"] = person_id
            p["nonce"] = _h(nonce)
        return nonce

    def finish(self, req_id: str, nonce: str, approve: bool) -> str | None:
        """Approve or deny a pending request. Returns the URL to send the browser back to, or None."""
        with self.store.edit() as st:
            p = st["pending"].get(_h(req_id))
            if p is None:
                return None
            if approve:
                if not p.get("person") or not p.get("nonce") or not nonce \
                        or not hmac.compare_digest(p["nonce"], _h(nonce)):
                    return None
            elif p.get("nonce") and not (nonce and hmac.compare_digest(p["nonce"], _h(nonce))):
                return None
            st["pending"].pop(_h(req_id))
            if not approve:
                return construct_redirect_uri(p["redirect_uri"], error="access_denied",
                                              error_description="The family member said no.", state=p["state"])
            code = CODE_PREFIX + secrets.token_urlsafe(32)
            st["codes"][_h(code)] = {
                "client_id": p["client_id"], "person": p["person"], "redirect_uri": p["redirect_uri"],
                "redirect_explicit": p["redirect_explicit"], "scopes": p["scopes"],
                "code_challenge": p["code_challenge"], "resource": p["resource"],
                "client_name": p["client_name"], "expires": _now() + CODE_TTL_S}
        return construct_redirect_uri(p["redirect_uri"], code=code, state=p["state"])

    # ---- token endpoint

    async def load_authorization_code(self, client: OAuthClientInformationFull, authorization_code: str):
        """Codes are single use: loading one consumes it, so a failed PKCE or redirect check burns it."""
        ch = _h(authorization_code or "")
        with self.store.edit() as st:
            used = st["used_codes"].get(ch)
            if used is not None:
                # RFC 6749 10.5: a code used twice means it leaked. Revoke what it produced.
                log.warning("authorization code reused; revoking connection %s", used.get("grant"))
                if used.get("grant"):
                    self.store._drop_grant(st, used["grant"])
                return None
            c = st["codes"].pop(ch, None)
            if c is None:
                return None
            st["used_codes"][ch] = {"grant": None, "expires": _now() + REFRESH_TTL_S}
        if c["client_id"] != client.client_id:
            return None
        return BoxCode(code=authorization_code, scopes=c["scopes"], expires_at=c["expires"],
                       client_id=c["client_id"], code_challenge=c["code_challenge"], redirect_uri=c["redirect_uri"],
                       redirect_uri_provided_explicitly=c["redirect_explicit"], resource=c["resource"],
                       subject=c["person"], person=c["person"], client_name=c.get("client_name", ""),
                       redirect_host=urlsplit(c["redirect_uri"]).netloc or urlsplit(c["redirect_uri"]).scheme,
                       code_hash=ch)

    def _issue(self, st: dict, grant_id: str, g: dict, scopes: list[str]) -> OAuthToken:
        access = ACCESS_PREFIX + secrets.token_urlsafe(32)
        refresh = REFRESH_PREFIX + secrets.token_urlsafe(32)
        now = _now()
        common = {"grant": grant_id, "person": g["person"], "client_id": g["client_id"], "scopes": scopes,
                  "resource": g["resource"]}
        st["access"][_h(access)] = common | {"expires": now + ACCESS_TTL_S}
        st["refresh"][_h(refresh)] = common | {"expires": now + REFRESH_TTL_S}
        return OAuthToken(access_token=access, token_type="Bearer", expires_in=ACCESS_TTL_S,
                          scope=" ".join(scopes), refresh_token=refresh)

    async def exchange_authorization_code(self, client: OAuthClientInformationFull, authorization_code) -> OAuthToken:
        code: BoxCode = authorization_code
        if not isinstance(code, BoxCode) or code.client_id != client.client_id:
            raise TokenError("invalid_grant", "authorization code does not exist")
        if code.person not in self.store.cfg.people:
            raise TokenError("invalid_grant", "that family member is no longer on this box")
        grant_id = _short_id("c_")
        g = {"person": code.person, "client_id": client.client_id,
             "client_name": code.client_name or client.client_name or "", "redirect_host": code.redirect_host,
             "resource": code.resource, "created": int(_now()), "last_used": None}
        with self.store.edit() as st:
            if client.client_id not in st["clients"]:
                raise TokenError("invalid_grant", "that app is no longer registered")
            st["grants"][grant_id] = g
            if code.code_hash in st["used_codes"]:
                st["used_codes"][code.code_hash]["grant"] = grant_id
            tok = self._issue(st, grant_id, g, code.scopes)
        from .web import _audit
        _audit(self.store.cfg, code.person, {"event": "assistant_linked", "connection": grant_id,
                                             "assistant": g["client_name"][:80], "returns_to": g["redirect_host"]})
        return tok

    async def load_refresh_token(self, client: OAuthClientInformationFull, refresh_token: str):
        rh = _h(refresh_token or "")
        with self.store.edit() as st:
            old = st["retired"].get(rh)
            if old is not None:
                # A refresh token that was already swapped for a new one: someone has a copy. Cut it off.
                log.warning("rotated refresh token reused; revoking connection %s", old["grant"])
                self.store._drop_grant(st, old["grant"])
                return None
            r = st["refresh"].get(rh)
        if r is None or r["client_id"] != client.client_id or r["grant"] not in st["grants"] \
                or r["person"] not in self.store.cfg.people:
            return None
        return BoxRefresh(token=refresh_token, client_id=r["client_id"], scopes=r["scopes"],
                          expires_at=int(r["expires"]), resource=r.get("resource"), subject=r["person"],
                          grant=r["grant"], person=r["person"])

    async def exchange_refresh_token(self, client: OAuthClientInformationFull, refresh_token, scopes: list[str]):
        rt: BoxRefresh = refresh_token
        rh = _h(rt.token)
        with self.store.edit() as st:
            r = st["refresh"].pop(rh, None)
            g = st["grants"].get(rt.grant)
            if r is None or g is None or r["client_id"] != client.client_id:
                raise TokenError("invalid_grant", "refresh token does not exist")
            st["retired"][rh] = {"grant": rt.grant, "expires": _now() + REFRESH_TTL_S}
            # Old access tokens for this connection stop working once a new one is issued.
            st["access"] = {h: a for h, a in st["access"].items() if a["grant"] != rt.grant}
            return self._issue(st, rt.grant, g, scopes or r["scopes"])

    async def load_access_token(self, token: str) -> AccessToken | None:
        if not token.startswith(ACCESS_PREFIX):
            return None
        a = self.store.read()["access"].get(_h(token))
        if a is None:
            return None
        return AccessToken(token=token, client_id=a["client_id"], scopes=a["scopes"], expires_at=int(a["expires"]),
                           resource=a.get("resource"), subject=a["person"])

    async def revoke_token(self, token) -> None:
        h = _h(token.token)
        with self.store.edit() as st:
            rec = st["access"].get(h) or st["refresh"].get(h)
            if rec is not None:
                self.store._drop_grant(st, rec["grant"])

    def revoke_for_client(self, client_id: str, token: str) -> bool:
        """Revoke the connection behind an access or refresh token, if that token belongs to client_id."""
        h = _h(token)
        with self.store.edit() as st:
            rec = st["access"].get(h) or st["refresh"].get(h)
            if rec is None or rec["client_id"] != client_id:
                return False
            self.store._drop_grant(st, rec["grant"])
        return True

    async def exchange_identity_assertion(self, client, params):
        raise TokenError("unsupported_grant_type", "not supported")


class HashedClientAuthenticator(ClientAuthenticator):
    """The SDK's client authentication, but client secrets are compared as SHA-256 hashes."""

    provider: BoxProvider

    async def authenticate_request(self, request) -> OAuthClientInformationFull:
        form = await request.form()
        client_id = form.get("client_id")
        if not isinstance(client_id, str) or not client_id:
            raise AuthenticationError("Missing client_id")
        client = await self.provider.get_client(client_id)
        if client is None:
            raise AuthenticationError("Invalid client_id")
        method = client.token_endpoint_auth_method
        given: str | None = None
        if method == "client_secret_basic":
            header = request.headers.get("Authorization", "")
            if not header.startswith("Basic "):
                raise AuthenticationError("Missing or invalid Basic authentication in Authorization header")
            try:
                decoded = base64.b64decode(header[6:], validate=True).decode("utf-8")
                basic_id, given = decoded.split(":", 1)
            except (ValueError, UnicodeDecodeError, binascii.Error):
                raise AuthenticationError("Invalid Basic authentication header") from None
            if unquote(basic_id) != client_id:
                raise AuthenticationError("Client ID mismatch in Basic auth")
            given = unquote(given)
        elif method == "client_secret_post":
            raw = form.get("client_secret")
            given = raw if isinstance(raw, str) else None
        elif method != "none":
            raise AuthenticationError("Unsupported auth method")
        stored = self.provider.client_secret_hash(client_id)
        if method != "none":
            if not stored:
                raise AuthenticationError("Client has no stored secret")
            if not given or not hmac.compare_digest(stored, _h(given)):
                raise AuthenticationError("Invalid client_secret")
            if client.client_secret_expires_at and client.client_secret_expires_at < int(_now()):
                raise AuthenticationError("Client secret has expired")
        return client


# --- /mcp: bearer check, then the asking person's own MCP server -------------------------------------

class _Runner:
    """Keeps one StreamableHTTPSessionManager running on the current event loop (started on first use)."""

    def __init__(self, make_manager):
        self.make_manager = make_manager
        self.loop = None
        self.manager = None
        self.task = None
        self.lock: asyncio.Lock | None = None

    async def get(self):
        loop = asyncio.get_running_loop()
        if self.loop is loop and self.manager is not None and self.task is not None and not self.task.done():
            return self.manager
        if self.lock is None or self.loop is not loop:
            self.lock = asyncio.Lock()
            self.loop = loop
            self.manager = None
        async with self.lock:
            if self.manager is not None and self.task is not None and not self.task.done():
                return self.manager
            mgr = self.make_manager()
            ready = asyncio.Event()

            async def run():
                async with mgr.run():
                    ready.set()
                    await asyncio.Event().wait()   # until the loop shuts down

            task = loop.create_task(run())
            waiter = loop.create_task(ready.wait())
            await asyncio.wait({task, waiter}, return_when=asyncio.FIRST_COMPLETED)
            if not ready.is_set():
                waiter.cancel()
                task.result()   # raises the startup error
                raise RuntimeError("MCP session manager stopped during startup")
            self.manager, self.task = mgr, task
            return mgr


@dataclass
class McpGateway:
    """ASGI app for /mcp. Every request must carry a live bearer token; it picks whose MCP server answers."""

    cfg: Config
    store: RemoteStore
    base_for: Any            # (scope) -> "https://host[:port]"
    box: Any                 # () -> Box

    def __post_init__(self):
        self._runners: dict[str, _Runner] = {}

    def _runner(self, person_id: str) -> _Runner:
        r = self._runners.get(person_id)
        if r is None:
            def make(pid=person_id):
                from mcp.server.streamable_http_manager import StreamableHTTPSessionManager
                from .mcp_server import build_server
                box = self.box()
                server = build_server(pid, box.mode, source="mcp-remote", cfg=self.cfg, box=box)
                return StreamableHTTPSessionManager(app=server._lowlevel_server, json_response=True,
                                                    stateless=False, max_sessions=50)
            r = self._runners[person_id] = _Runner(make)
        return r

    async def _deny(self, scope: Scope, send: Send, base: str, error: str | None, desc: str) -> None:
        meta = f"{base}/.well-known/oauth-protected-resource/mcp"
        parts = [f'resource_metadata="{meta}"', f'scope="{SCOPE}"']
        if error:
            parts = [f'error="{error}"', f'error_description="{desc}"'] + parts
        body = json.dumps({"error": error or "unauthorized", "error_description": desc}).encode()
        await send({"type": "http.response.start", "status": 401,
                    "headers": [(b"content-type", b"application/json"), (b"content-length", str(len(body)).encode()),
                                (b"www-authenticate", ("Bearer " + ", ".join(parts)).encode())]})
        await send({"type": "http.response.body", "body": body})

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] != "http":
            return
        base = self.base_for(scope)
        auth = ""
        for k, v in scope.get("headers", []):
            if k == b"authorization":
                auth = v.decode("latin-1")
                break
        if not auth.lower().startswith("bearer "):
            return await self._deny(scope, send, base, None, "Sign in to the family box to use it.")
        hit = self.store.verify_bearer(auth[7:].strip())
        if hit is None:
            return await self._deny(scope, send, base, "invalid_token", "This connection was revoked or expired.")
        if hit["resource"] is not None and hit["resource"].rstrip("/").lower() != resource_of(base).lower():
            return await self._deny(scope, send, base, "invalid_token", "This token is for a different address.")
        tok = AccessToken(token=hit["conn"], client_id=hit["client"], scopes=[SCOPE], expires_at=hit["expires"],
                          resource=hit["resource"], subject=hit["person"])
        scope = dict(scope)
        scope["user"] = AuthenticatedUser(tok)
        scope["auth"] = AuthCredentials([SCOPE])
        scope["familybox_person"] = hit["person"]
        mgr = await self._runner(hit["person"]).get()
        await mgr.handle_request(scope, receive, send)
