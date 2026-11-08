"""Google sign-in for the box: OAuth 2.0 authorization code flow with PKCE (S256).

- `state` is a random nonce bound server-side to one person, one PKCE verifier and one redirect URI.
  It lives in <runtime>/cloud/pending.json for 10 minutes and is removed the first time it is used.
- Tokens are kept per person in <runtime>/cloud/<person>.json (0600) and refreshed automatically.
  Nothing in this module prints or logs a token.
"""

from __future__ import annotations

import base64
import hashlib
import ipaddress
import json
import os
import secrets
import time
from urllib.parse import urlencode, urlsplit

from ..config import Config
from ._common import (GOOGLE_AUTH_URL, GOOGLE_REVOKE_URL, GOOGLE_TOKEN_URL, GOOGLE_USERINFO_URL, CloudError,
                      check_person, cloud_dir, http, raise_for_google, read_json, write_json)

SCOPES = (
    "openid",
    "email",
    "https://www.googleapis.com/auth/drive.readonly",  # import: read the folder the person picks
    "https://www.googleapis.com/auth/drive.file",      # backup: only files this app creates
)
STATE_TTL_S = 600
REFRESH_MARGIN_S = 60
FORWARDER_ENV = "FAMILYBOX_OAUTH_REDIRECT"


def _now() -> float:
    return time.time()


def _b64url(b: bytes) -> str:
    return base64.urlsafe_b64encode(b).rstrip(b"=").decode()


def client_credentials() -> tuple[str, str | None]:
    cid = os.environ.get("GOOGLE_OAUTH_CLIENT_ID", "").strip()
    if not cid:
        raise CloudError("Google is not set up on this box yet: GOOGLE_OAUTH_CLIENT_ID is missing (see docs/CLOUD.md)")
    secret = os.environ.get("GOOGLE_OAUTH_CLIENT_SECRET", "").strip() or None
    return cid, secret


def pkce_pair() -> tuple[str, str]:
    """(verifier, S256 challenge). The verifier is 86 URL-safe characters (RFC 7636 allows 43 to 128)."""
    verifier = _b64url(secrets.token_bytes(64))
    challenge = _b64url(hashlib.sha256(verifier.encode("ascii")).digest())
    return verifier, challenge


# --- redirect choice ----------------------------------------------------------------------------

def is_loopback(url: str) -> bool:
    host = (urlsplit(url).hostname or "").lower()
    if host == "localhost":
        return True
    try:
        return ipaddress.ip_address(host).is_loopback
    except ValueError:
        return False


def _is_private_host(host: str) -> bool:
    host = host.lower().strip("[]")
    try:
        ip = ipaddress.ip_address(host)
        return ip.is_private or ip.is_link_local or ip.is_loopback
    except ValueError:
        pass
    return host.endswith((".local", ".lan", ".home.arpa", ".internal")) or "." not in host


def choose_redirect(box_redirect: str) -> tuple[str, str | None]:
    """Pick the redirect URI to send to Google for a callback the box wants to receive at `box_redirect`.

    Returns (google_redirect_uri, forward_to). forward_to is set when a public forwarder page relays
    ?code&state back to the box's LAN address.
    """
    parts = urlsplit(box_redirect)
    if parts.scheme not in ("http", "https") or not parts.hostname:
        raise CloudError("redirect_uri must be an http(s) URL")
    if is_loopback(box_redirect):
        return box_redirect, None                       # (1) browser on the same machine as the box
    forwarder = os.environ.get(FORWARDER_ENV, "").strip()
    if forwarder:
        if urlsplit(forwarder).scheme != "https":
            raise CloudError(f"{FORWARDER_ENV} must be an https URL")
        if not _is_private_host(parts.hostname):
            raise CloudError("the forwarder only sends people back to a box on the home network")
        return forwarder, box_redirect                  # (2) public forwarder page -> LAN box
    if parts.scheme == "https" and not _is_private_host(parts.hostname):
        return box_redirect, None                       # box reachable at a public HTTPS name
    raise CloudError(
        "Google cannot send you back to a home-network address. Open the box on this computer "
        f"(127.0.0.1), set {FORWARDER_ENV} to your forwarder page, or use `familybox cloud connect` "
        "and paste the code (see docs/CLOUD.md)."
    )


# --- pending states -----------------------------------------------------------------------------

def _pending_path(cfg: Config):
    return cloud_dir(cfg) / "pending.json"


def _load_pending(cfg: Config) -> dict:
    data = read_json(_pending_path(cfg), {}) or {}
    now = _now()
    return {k: v for k, v in data.items() if v.get("expires", 0) > now}


def begin_connect(cfg: Config, person_id: str, redirect_uri: str) -> str:
    """Start sign-in for one person. Returns the Google URL to open in their browser."""
    check_person(cfg, person_id)
    client_id, _ = client_credentials()
    google_redirect, forward_to = choose_redirect(redirect_uri)
    verifier, challenge = pkce_pair()
    nonce = _b64url(secrets.token_bytes(24))
    # The forwarder page reads the box address from the state; the nonce is what the box checks.
    state = nonce if not forward_to else f"{nonce}.{_b64url(forward_to.encode())}"
    pending = _load_pending(cfg)
    pending[state] = {"person": person_id, "verifier": verifier, "redirect_uri": google_redirect,
                      "expires": _now() + STATE_TTL_S}
    write_json(_pending_path(cfg), pending)
    params = {
        "client_id": client_id,
        "redirect_uri": google_redirect,
        "response_type": "code",
        "scope": " ".join(SCOPES),
        "state": state,
        "code_challenge": challenge,
        "code_challenge_method": "S256",
        "access_type": "offline",      # ask for a refresh token
        "prompt": "consent",           # so a refresh token comes back on reconnect too
        "include_granted_scopes": "true",
    }
    return f"{GOOGLE_AUTH_URL}?{urlencode(params)}"


def take_state(cfg: Config, state: str) -> dict:
    """Remove and return a pending state. Single use: a second call with the same state fails."""
    if not isinstance(state, str) or not state:
        raise CloudError("sign-in link is missing its state; start again")
    raw = read_json(_pending_path(cfg), {}) or {}
    rec = raw.pop(state, None)
    now = _now()
    write_json(_pending_path(cfg), {k: v for k, v in raw.items() if v.get("expires", 0) > now})
    if rec is None:
        raise CloudError("this sign-in link was already used or is unknown; start again")
    if rec.get("expires", 0) <= now:
        raise CloudError("this sign-in link expired (10 minutes); start again")
    return rec


# --- tokens -------------------------------------------------------------------------------------

def token_path(cfg: Config, person_id: str):
    return cloud_dir(cfg) / f"{check_person(cfg, person_id)}.json"


def load_token(cfg: Config, person_id: str) -> dict | None:
    return read_json(token_path(cfg, person_id), None)


def save_token(cfg: Config, person_id: str, tok: dict) -> None:
    write_json(token_path(cfg, person_id), tok)


def _email_from_id_token(id_token: str | None) -> str | None:
    # The id_token came straight from Google's token endpoint over TLS, so reading its claims
    # without checking the signature is allowed (OpenID Connect Core 3.1.3.7).
    if not id_token or id_token.count(".") != 2:
        return None
    try:
        payload = id_token.split(".")[1]
        claims = json.loads(base64.urlsafe_b64decode(payload + "=" * (-len(payload) % 4)))
        return claims.get("email")
    except ValueError:
        return None


def finish_connect_tokens(cfg: Config, state: str, code: str) -> str:
    """Exchange the code for tokens and store them. Returns the person id."""
    rec = take_state(cfg, state)  # consumed before anything else, even if the exchange fails
    if not code:
        raise CloudError("no code came back from Google")
    client_id, secret = client_credentials()
    form = {"grant_type": "authorization_code", "code": code, "code_verifier": rec["verifier"],
            "redirect_uri": rec["redirect_uri"], "client_id": client_id}
    if secret:
        form["client_secret"] = secret
    with http() as c:
        resp = c.post(GOOGLE_TOKEN_URL, data=form)
        raise_for_google(resp, "the sign-in")
        body = resp.json()
        email = _email_from_id_token(body.get("id_token"))
        if not email and body.get("access_token"):
            u = c.get(GOOGLE_USERINFO_URL, headers={"Authorization": f"Bearer {body['access_token']}"})
            if u.status_code == 200:
                email = u.json().get("email")
    person = rec["person"]
    old = load_token(cfg, person) or {}
    refresh = body.get("refresh_token") or old.get("refresh_token")
    if not refresh:
        raise CloudError("Google did not return a refresh token; remove the box from your Google account "
                         "permissions and connect again")
    save_token(cfg, person, {
        "access_token": body["access_token"],
        "refresh_token": refresh,
        "expires_at": _now() + int(body.get("expires_in", 3600)),
        "scope": body.get("scope", " ".join(SCOPES)),
        "account_email": email,
        "connected_at": int(_now()),
        "last_import": old.get("last_import"),
    })
    return person


def access_token(cfg: Config, person_id: str, *, force_refresh: bool = False) -> str:
    """A valid access token for this person, refreshing it first if it is about to expire."""
    tok = load_token(cfg, person_id)
    if not tok:
        raise CloudError(f"{person_id} has not connected Google Drive yet")
    if not force_refresh and tok.get("expires_at", 0) - REFRESH_MARGIN_S > _now():
        return tok["access_token"]
    client_id, secret = client_credentials()
    form = {"grant_type": "refresh_token", "refresh_token": tok["refresh_token"], "client_id": client_id}
    if secret:
        form["client_secret"] = secret
    with http() as c:
        resp = c.post(GOOGLE_TOKEN_URL, data=form)
    if resp.status_code in (400, 401):
        raise CloudError("Google no longer accepts this connection; connect again")
    raise_for_google(resp, "refreshing the connection")
    body = resp.json()
    tok["access_token"] = body["access_token"]
    tok["expires_at"] = _now() + int(body.get("expires_in", 3600))
    if body.get("refresh_token"):
        tok["refresh_token"] = body["refresh_token"]
    save_token(cfg, person_id, tok)
    return tok["access_token"]


def revoke_and_forget(cfg: Config, person_id: str) -> None:
    tok = load_token(cfg, person_id)
    if tok:
        try:
            with http() as c:
                c.post(GOOGLE_REVOKE_URL, data={"token": tok.get("refresh_token") or tok.get("access_token")})
        except Exception:  # noqa: BLE001  best effort; the local copy is removed either way
            pass
    token_path(cfg, person_id).unlink(missing_ok=True)
