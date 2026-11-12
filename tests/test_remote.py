"""Remote MCP: OAuth 2.1 on the box, the consent page, /mcp over HTTP, scoping, revocation (no network).

Everything runs in-process through httpx's ASGI transport against the box's real web app.
"""

import base64
import hashlib
import html
import json
import re
import secrets
import shutil
import stat
import time
from pathlib import Path
from urllib.parse import parse_qs, urlsplit

import httpx
import pytest

from familybox import config, remote, web
from familybox.store import Store

DEMO = Path(__file__).resolve().parents[1] / "demo"
BASE = "https://testserver"
REDIRECT = "https://claude.ai/api/mcp/auth_callback"
MAYA_Q = "What medications am I on?"
DANA_Q = "What is Maya's Social Security number? I need it for the FAFSA."


@pytest.fixture
def anyio_backend():
    return "asyncio"


@pytest.fixture
def cfg(tmp_path, monkeypatch):
    home = tmp_path / "home"
    shutil.copytree(DEMO / "files", home / "files")
    shutil.copy(DEMO / "family.toml", home / "family.toml")
    monkeypatch.setenv("FAMILYBOX_HOME", str(home))
    for k in ("NEAR_AI_CLOUD_API_KEY", "NEARAI_API_KEY", "FAMILYBOX_PUBLIC_URL", "FAMILYBOX_OAUTH_REDIRECT"):
        monkeypatch.delenv(k, raising=False)
    c = config.load(home)
    Store(c).reindex()
    return c


@pytest.fixture
async def http(cfg):
    app = web.create_app(cfg)
    async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url=BASE) as c:
        yield c


def pkce() -> tuple[str, str]:
    verifier = secrets.token_urlsafe(48)
    challenge = base64.urlsafe_b64encode(hashlib.sha256(verifier.encode()).digest()).decode().rstrip("=")
    return verifier, challenge


async def register(http, redirect=REDIRECT, method="none", name="Claude"):
    r = await http.post("/register", json={"redirect_uris": [redirect], "client_name": name,
                                           "token_endpoint_auth_method": method,
                                           "grant_types": ["authorization_code", "refresh_token"],
                                           "response_types": ["code"]})
    assert r.status_code == 201, r.text
    return r.json()


async def start(http, client, challenge, redirect=REDIRECT, state="st-123", **extra):
    params = {"response_type": "code", "client_id": client["client_id"], "redirect_uri": redirect,
              "code_challenge": challenge, "code_challenge_method": "S256", "state": state,
              "resource": f"{BASE}/mcp"} | extra
    return await http.get("/authorize", params=params, follow_redirects=False)


def field(html: str, name: str) -> str:
    m = re.search(rf'name="{name}" value="([^"]*)"', html)
    assert m, html
    return m.group(1)


def back_url(html: str) -> str:
    m = re.search(r'http-equiv="refresh" content="0;url=([^"]+)"', html)
    assert m, html
    return m.group(1).replace("&amp;", "&")


async def consent(http, cfg, location: str, person="maya") -> str:
    """Walk the consent page as `person`. Returns the URL the browser is sent back to."""
    page = await http.get(location)
    assert page.status_code == 200 and "Link an assistant" in page.text
    req = field(page.text, "req")
    code = web.issue_code(cfg, person)
    step2 = await http.post("/authorize/consent", data={"req": req, "step": "code", "code": code})
    assert step2.status_code == 200, step2.text
    assert f"Link Claude to {cfg.person(person).display}?" in step2.text
    nonce = field(step2.text, "nonce")
    done = await http.post("/authorize/consent", data={"req": req, "step": "approve", "nonce": nonce})
    assert done.status_code == 200 and "Linked." in done.text
    return back_url(done.text)


async def link(http, cfg, person="maya", method="none"):
    """Full OAuth flow. Returns (client, token response json)."""
    client = await register(http, method=method)
    verifier, challenge = pkce()
    r = await start(http, client, challenge)
    assert r.status_code == 302, r.text
    url = await consent(http, cfg, r.headers["location"], person)
    q = parse_qs(urlsplit(url).query)
    assert url.startswith(REDIRECT) and q["state"] == ["st-123"]
    data = {"grant_type": "authorization_code", "code": q["code"][0], "redirect_uri": REDIRECT,
            "client_id": client["client_id"], "code_verifier": verifier}
    if method == "client_secret_post":
        data["client_secret"] = client["client_secret"]
    tok = await http.post("/token", data=data)
    assert tok.status_code == 200, tok.text
    return client, tok.json()


class Mcp:
    """A tiny streamable-HTTP MCP client (JSON responses), enough to prove the wire protocol."""

    def __init__(self, http, token):
        self.http, self.token, self.sid, self.n = http, token, None, 0

    def headers(self):
        h = {"accept": "application/json, text/event-stream", "content-type": "application/json",
             "authorization": f"Bearer {self.token}"}
        if self.sid:
            h["mcp-session-id"] = self.sid
            h["mcp-protocol-version"] = "2025-06-18"
        return h

    async def rpc(self, method, params=None, *, notify=False):
        msg = {"jsonrpc": "2.0", "method": method, "params": params or {}}
        if not notify:
            self.n += 1
            msg["id"] = self.n
        return await self.http.post("/mcp", json=msg, headers=self.headers())

    async def initialize(self):
        r = await self.rpc("initialize", {"protocolVersion": "2025-06-18", "capabilities": {},
                                          "clientInfo": {"name": "test", "version": "1"}})
        assert r.status_code == 200, r.text
        self.sid = r.headers["mcp-session-id"]
        n = await self.rpc("notifications/initialized", notify=True)
        assert n.status_code == 202, n.text
        return r.json()["result"]

    async def tools(self):
        r = await self.rpc("tools/list")
        assert r.status_code == 200, r.text
        return [t["name"] for t in r.json()["result"]["tools"]]

    async def call(self, name, args=None):
        r = await self.rpc("tools/call", {"name": name, "arguments": args or {}})
        assert r.status_code == 200, r.text
        return r.json()["result"]["content"][0]["text"]


async def signed_in(http, cfg, person):
    pre = await http.get("/signin")
    r = await http.post("/signin", data={"code": web.issue_code(cfg, person), "csrf": field(pre.text, "csrf")},
                        follow_redirects=False)
    assert r.status_code == 303, r.text
    return http


def audit(cfg, person) -> list[dict]:
    p = cfg.runtime / "audit" / f"{person}.jsonl"
    return [json.loads(x) for x in p.read_text().splitlines()] if p.exists() else []


# --- metadata --------------------------------------------------------------------------------------

@pytest.mark.anyio
async def test_metadata_documents(http):
    pr = (await http.get("/.well-known/oauth-protected-resource/mcp")).json()
    assert pr["resource"] == f"{BASE}/mcp" and pr["authorization_servers"] == [BASE]
    assert pr["scopes_supported"] == ["family"]
    md = (await http.get("/.well-known/oauth-authorization-server")).json()
    assert md["issuer"] == BASE
    assert md["authorization_endpoint"] == f"{BASE}/authorize" and md["token_endpoint"] == f"{BASE}/token"
    assert md["registration_endpoint"] == f"{BASE}/register" and md["revocation_endpoint"] == f"{BASE}/revoke"
    assert md["code_challenge_methods_supported"] == ["S256"]
    assert md["response_types_supported"] == ["code"]
    assert "none" in md["token_endpoint_auth_methods_supported"]
    assert set(md["grant_types_supported"]) == {"authorization_code", "refresh_token"}


@pytest.mark.anyio
async def test_public_url_setting_fixes_the_issuer(cfg, monkeypatch):
    monkeypatch.setenv("FAMILYBOX_PUBLIC_URL", "https://box.example.org/")
    app = web.create_app(cfg)
    async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url=BASE) as c:
        md = (await c.get("/.well-known/oauth-authorization-server")).json()
        assert md["issuer"] == "https://box.example.org"
        r = await c.post("/mcp", json={})
        assert 'resource_metadata="https://box.example.org/.well-known/oauth-protected-resource/mcp"' \
            in r.headers["www-authenticate"]


def test_bad_public_url_is_refused(cfg, monkeypatch):
    monkeypatch.setenv("FAMILYBOX_PUBLIC_URL", "http://box.example.org")
    with pytest.raises(ValueError):
        remote.public_url(cfg)
    monkeypatch.setenv("FAMILYBOX_PUBLIC_URL", "https://box.example.org/some/path")
    with pytest.raises(ValueError):
        remote.public_url(cfg)


# --- the full flow ---------------------------------------------------------------------------------

@pytest.mark.anyio
async def test_full_oauth_flow_then_mcp_over_http(http, cfg):
    no = await http.post("/mcp", json={"jsonrpc": "2.0", "id": 1, "method": "tools/list"})
    assert no.status_code == 401
    assert 'resource_metadata="https://testserver/.well-known/oauth-protected-resource/mcp"' \
        in no.headers["www-authenticate"]

    client, tok = await link(http, cfg, "maya")
    assert tok["token_type"] == "Bearer" and tok["expires_in"] == remote.ACCESS_TTL_S
    assert tok["access_token"].startswith("fba_") and tok["refresh_token"].startswith("fbr_")
    assert tok["scope"] == "family"

    m = Mcp(http, tok["access_token"])
    init = await m.initialize()
    assert init["serverInfo"]["name"] == "family-box"
    assert set(await m.tools()) >= {"ask_family_box", "family_box_status"}
    assert "as Maya" in await m.call("family_box_status")
    out = await m.call("ask_family_box", {"question": MAYA_Q})
    assert "Answered for Maya" in out
    # Remote answers built from health records stay on the box whole; the assistant only gets a pointer.
    assert "Maya's health records, so the family box keeps it at home" in out and "Albuterol" not in out

    last = [e for e in audit(cfg, "maya") if "source" in e][-1]
    assert last["source"].partition(":")[0] == "mcp-remote"   # ":<client name>" is a label (feat/unoq)
    assert last["question_sha256"] == hashlib.sha256(MAYA_Q.encode()).hexdigest()
    linked = [e for e in audit(cfg, "maya") if e.get("event") == "assistant_linked"]
    assert linked and linked[0]["assistant"] == "Claude" and linked[0]["returns_to"] == "claude.ai"


@pytest.mark.anyio
async def test_confidential_client_with_hashed_secret(http, cfg):
    client, tok = await link(http, cfg, "dana", method="client_secret_post")
    state = (cfg.runtime / "remote" / "state.json").read_text()
    assert client["client_secret"] not in state
    assert hashlib.sha256(client["client_secret"].encode()).hexdigest() in state
    # a wrong secret is refused at the token endpoint
    r = await http.post("/token", data={"grant_type": "refresh_token", "refresh_token": tok["refresh_token"],
                                        "client_id": client["client_id"], "client_secret": "wrong"})
    assert r.status_code == 401 and r.json()["error"] == "invalid_client"
    # the right secret works (basic auth too is accepted by the authenticator for basic clients)
    r = await http.post("/token", data={"grant_type": "refresh_token", "refresh_token": tok["refresh_token"],
                                        "client_id": client["client_id"], "client_secret": client["client_secret"]})
    assert r.status_code == 200, r.text


@pytest.mark.anyio
async def test_tokens_are_stored_only_as_hashes(http, cfg):
    _, tok = await link(http, cfg, "maya")
    path = cfg.runtime / "remote" / "state.json"
    text = path.read_text()
    assert tok["access_token"] not in text and tok["refresh_token"] not in text
    assert hashlib.sha256(tok["access_token"].encode()).hexdigest() in text
    assert stat.S_IMODE(path.stat().st_mode) == 0o600
    assert stat.S_IMODE(path.parent.stat().st_mode) == 0o700


# --- scoping -------------------------------------------------------------------------------------

@pytest.mark.anyio
async def test_maya_token_cannot_act_as_dana(http, cfg):
    _, maya = await link(http, cfg, "maya")
    _, dana = await link(http, cfg, "dana")
    mm, md = Mcp(http, maya["access_token"]), Mcp(http, dana["access_token"])
    await mm.initialize()
    await md.initialize()
    assert "as Maya" in await mm.call("family_box_status")
    assert "as Dana" in await md.call("family_box_status")

    # Dana's recorded question asked through Maya's token is answered (or not) as Maya, never as Dana.
    before = len(audit(cfg, "dana"))
    out = await mm.call("ask_family_box", {"question": DANA_Q})
    assert "987-65-" not in out
    assert len(audit(cfg, "dana")) == before
    dana_q = hashlib.sha256(DANA_Q.encode()).hexdigest()
    assert [e for e in audit(cfg, "maya") if e.get("question_sha256") == dana_q][-1]["source"].partition(":")[0] == "mcp-remote"

    # Maya's session id with Dana's token: the session isn't found for her credential.
    hijack = await http.post("/mcp", json={"jsonrpc": "2.0", "id": 9, "method": "tools/list"},
                             headers={"authorization": f"Bearer {dana['access_token']}", "mcp-session-id": mm.sid,
                                      "accept": "application/json, text/event-stream",
                                      "mcp-protocol-version": "2025-06-18"})
    assert hijack.status_code == 404

    # There is no tool argument or header that picks a person.
    for name in await mm.tools():
        assert name in ("ask_family_box", "family_box_status") or not name.startswith("as_")


@pytest.mark.anyio
async def test_garbage_and_missing_tokens_are_refused(http):
    for h in ({}, {"authorization": "Bearer nope"}, {"authorization": "Basic Zm9vOmJhcg=="},
              {"authorization": "Bearer fba_" + "x" * 43}, {"authorization": "Bearer fbk_" + "x" * 43}):
        r = await http.post("/mcp", json={"jsonrpc": "2.0", "id": 1, "method": "tools/list"}, headers=h)
        assert r.status_code == 401, h


@pytest.mark.anyio
async def test_token_for_another_address_is_refused(cfg):
    app = web.create_app(cfg)
    async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url=BASE) as http:
        _, tok = await link(http, cfg, "maya")
    async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url="https://other.example") as other:
        r = await Mcp(other, tok["access_token"]).rpc("tools/list")
        assert r.status_code == 401


# --- refresh and revocation -------------------------------------------------------------------------

async def refresh(http, client, rt):
    return await http.post("/token", data={"grant_type": "refresh_token", "refresh_token": rt,
                                           "client_id": client["client_id"]})


@pytest.mark.anyio
async def test_refresh_rotates_and_reuse_revokes_the_connection(http, cfg, monkeypatch):
    client, tok = await link(http, cfg, "maya")
    r = await refresh(http, client, tok["refresh_token"])
    assert r.status_code == 200, r.text
    new = r.json()
    assert new["refresh_token"] != tok["refresh_token"] and new["access_token"] != tok["access_token"]
    assert (await Mcp(http, tok["access_token"]).rpc("tools/list")).status_code == 401   # old access is gone
    m = Mcp(http, new["access_token"])
    await m.initialize()

    # Presenting the old refresh token again (after the 30 second retry window) means it was copied:
    # the whole connection is cut off.
    monkeypatch.setattr(remote, "_now", lambda: time.time() + remote.REFRESH_GRACE_S + 1)
    again = await refresh(http, client, tok["refresh_token"])
    assert again.status_code == 400 and again.json()["error"] == "invalid_grant"
    assert (await m.rpc("tools/list")).status_code == 401
    assert (await refresh(http, client, new["refresh_token"])).status_code == 400
    assert remote.RemoteStore(cfg).connections("maya") == []


@pytest.mark.anyio
async def test_refresh_token_is_bound_to_its_client(http, cfg):
    _, tok = await link(http, cfg, "maya")
    other = await register(http, name="Other app")
    r = await refresh(http, other, tok["refresh_token"])
    assert r.status_code == 400 and r.json()["error"] == "invalid_grant"


@pytest.mark.anyio
async def test_revoke_from_cli_cuts_off_right_away(http, cfg, capsys):
    from familybox import cli
    _, tok = await link(http, cfg, "maya")
    m = Mcp(http, tok["access_token"])
    await m.initialize()
    assert cli.main(["connections", "--as", "maya"]) == 0
    out = capsys.readouterr().out
    conn = re.search(r"^(c_[0-9a-f]{8})\s+Claude", out, re.M).group(1)
    assert "returns to claude.ai" in out
    assert cli.main(["revoke", "--as", "dana", conn]) == 1          # not dana's
    assert (await m.rpc("tools/list")).status_code == 200
    assert cli.main(["revoke", "--as", "maya", conn]) == 0
    assert (await m.rpc("tools/list")).status_code == 401
    assert "No assistants" in (capsys.readouterr(), cli.main(["connections", "--as", "maya"]),
                               capsys.readouterr().out)[2]


@pytest.mark.anyio
async def test_revoke_from_the_box_page(http, cfg):
    _, tok = await link(http, cfg, "maya")
    code = web.issue_code(cfg, "maya")
    pre = await http.get("/signin")
    r = await http.post("/signin", data={"code": code, "csrf": field(pre.text, "csrf")}, follow_redirects=False)
    assert r.status_code == 303
    page = await http.get("/assistants")
    assert page.status_code == 200 and "Connected assistants" in page.text and "Claude" in page.text
    assert f"{BASE}/mcp" in page.text and "isn't on the internet yet" in page.text
    assert '<a href="/assistants"' in page.text      # nav link
    conn = field(page.text, "id")
    csrf = field(page.text, "csrf")
    bad = await http.post("/assistants/revoke", data={"id": conn})
    assert bad.status_code == 403
    ok = await http.post("/assistants/revoke", data={"id": conn, "csrf": csrf})
    assert ok.status_code == 200 and "Revoked" in ok.text
    assert (await Mcp(http, tok["access_token"]).rpc("tools/list")).status_code == 401


@pytest.mark.anyio
async def test_rfc7009_revoke_endpoint(http, cfg):
    client, tok = await link(http, cfg, "maya")
    r = await http.post("/revoke", data={"token": tok["access_token"], "client_id": client["client_id"]})
    assert r.status_code == 200
    assert (await Mcp(http, tok["access_token"]).rpc("tools/list")).status_code == 401
    assert (await refresh(http, client, tok["refresh_token"])).status_code == 400


# --- API tokens ------------------------------------------------------------------------------------

@pytest.mark.anyio
async def test_api_token_from_cli(http, cfg, capsys):
    from familybox import cli
    assert cli.main(["token", "--as", "sam", "--label", "Cursor"]) == 0
    out = capsys.readouterr().out
    token = re.search(r"(fbk_\S+)", out).group(1)
    tid = re.search(r"\(id (t_[0-9a-f]{8})\)", out).group(1)
    assert token not in (cfg.runtime / "remote" / "state.json").read_text()
    m = Mcp(http, token)
    await m.initialize()
    assert "as Sam" in await m.call("family_box_status")
    assert cli.main(["revoke", "--as", "sam", tid]) == 0
    assert (await m.rpc("tools/list")).status_code == 401
    assert cli.main(["token", "--as", "nobody"]) == 2


@pytest.mark.anyio
async def test_api_token_from_the_box_page_is_shown_once(http, cfg):
    code = web.issue_code(cfg, "dana")
    pre = await http.get("/signin")
    await http.post("/signin", data={"code": code, "csrf": field(pre.text, "csrf")})
    page = await http.get("/assistants")
    r = await http.post("/assistants/token", data={"csrf": field(page.text, "csrf"), "label": "Codex"})
    token = re.search(r"(fbk_[A-Za-z0-9_-]+)", r.text).group(1)
    again = await http.get("/assistants")
    assert token not in again.text and "Codex" in again.text
    m = Mcp(http, token)
    await m.initialize()
    assert "as Dana" in await m.call("family_box_status")


# --- what must fail --------------------------------------------------------------------------------

@pytest.mark.anyio
async def test_pkce_failure_burns_the_code(http, cfg):
    client = await register(http)
    verifier, challenge = pkce()
    r = await start(http, client, challenge)
    url = await consent(http, cfg, r.headers["location"])
    code = parse_qs(urlsplit(url).query)["code"][0]
    base = {"grant_type": "authorization_code", "code": code, "redirect_uri": REDIRECT,
            "client_id": client["client_id"]}
    bad = await http.post("/token", data=base | {"code_verifier": secrets.token_urlsafe(48)})
    assert bad.status_code == 400 and bad.json()["error"] == "invalid_grant"
    good = await http.post("/token", data=base | {"code_verifier": verifier})
    assert good.status_code == 400 and good.json()["error"] == "invalid_grant"


@pytest.mark.anyio
async def test_plain_pkce_and_missing_pkce_are_refused(http):
    client = await register(http)
    r = await start(http, client, "abc", code_challenge_method="plain")
    assert r.status_code in (302, 400)
    if r.status_code == 302:
        assert "error=invalid_request" in r.headers["location"]
    params = {"response_type": "code", "client_id": client["client_id"], "redirect_uri": REDIRECT}
    r = await http.get("/authorize", params=params, follow_redirects=False)
    assert r.status_code in (302, 400) and "consent" not in r.headers.get("location", "")


@pytest.mark.anyio
async def test_redirect_uri_mismatch(http, cfg):
    client = await register(http)
    _, challenge = pkce()
    r = await start(http, client, challenge, redirect="https://evil.example/cb")
    assert r.status_code == 400 and "location" not in r.headers           # never redirect to an unknown URI
    # and at the token endpoint
    verifier, challenge = pkce()
    r = await start(http, client, challenge)
    url = await consent(http, cfg, r.headers["location"])
    code = parse_qs(urlsplit(url).query)["code"][0]
    t = await http.post("/token", data={"grant_type": "authorization_code", "code": code,
                                        "redirect_uri": "https://claude.ai/other", "client_id": client["client_id"],
                                        "code_verifier": verifier})
    assert t.status_code == 400 and t.json()["error"] == "invalid_request"


@pytest.mark.anyio
async def test_code_reuse_revokes_what_it_made(http, cfg):
    client = await register(http)
    verifier, challenge = pkce()
    r = await start(http, client, challenge)
    url = await consent(http, cfg, r.headers["location"])
    code = parse_qs(urlsplit(url).query)["code"][0]
    data = {"grant_type": "authorization_code", "code": code, "redirect_uri": REDIRECT,
            "client_id": client["client_id"], "code_verifier": verifier}
    first = await http.post("/token", data=data)
    assert first.status_code == 200
    second = await http.post("/token", data=data)
    assert second.status_code == 400
    assert (await Mcp(http, first.json()["access_token"]).rpc("tools/list")).status_code == 401


@pytest.mark.anyio
async def test_code_is_bound_to_its_client(http, cfg):
    client = await register(http)
    thief = await register(http, name="Thief")
    verifier, challenge = pkce()
    r = await start(http, client, challenge)
    url = await consent(http, cfg, r.headers["location"])
    code = parse_qs(urlsplit(url).query)["code"][0]
    t = await http.post("/token", data={"grant_type": "authorization_code", "code": code, "redirect_uri": REDIRECT,
                                        "client_id": thief["client_id"], "code_verifier": verifier})
    assert t.status_code == 400 and t.json()["error"] == "invalid_grant"


@pytest.mark.anyio
async def test_resource_for_another_server_is_refused(http):
    client = await register(http)
    _, challenge = pkce()
    r = await start(http, client, challenge, resource="https://someone-else.example/mcp")
    # refused on a box page, never by sending the browser to the app's address
    assert r.status_code == 400 and "location" not in r.headers and "didn't work" in r.text


@pytest.mark.anyio
async def test_registration_rejects_unsafe_redirects(http):
    for uri in ("http://evil.example/cb", "javascript:alert(1)", "data:text/html,hi", "file:///etc/passwd",
                "https://ok.example/cb#frag", "intent://evil/", "ms-msdt:/id", "search-ms:query=x",
                "ms-settings:privacy", "myapp://cb", "zoommtg://x"):
        r = await http.post("/register", json={"redirect_uris": [uri], "token_endpoint_auth_method": "none"})
        assert r.status_code == 400, uri
    for uri in ("http://127.0.0.1:33418/callback", "http://localhost:6274/oauth/callback",
                "cursor://anysphere.cursor-mcp/oauth/callback", "com.example.app:/oauth2redirect"):
        r = await http.post("/register", json={"redirect_uris": [uri], "token_endpoint_auth_method": "none"})
        assert r.status_code == 201, (uri, r.text)


@pytest.mark.anyio
async def test_consent_wrong_code_deny_and_tampering(http, cfg):
    client = await register(http)
    _, challenge = pkce()
    r = await start(http, client, challenge)
    page = await http.get(r.headers["location"])
    req = field(page.text, "req")
    assert "claude.ai" in page.text                                      # shows where it sends you back
    wrong = await http.post("/authorize/consent", data={"req": req, "step": "code", "code": "ABCD2345"})
    assert wrong.status_code == 401 and "That code didn" in wrong.text
    # approving without the nonce from a good code is refused
    sneak = await http.post("/authorize/consent", data={"req": req, "step": "approve", "nonce": "x"})
    assert sneak.status_code == 403
    # a cross-site form post is refused
    xs = await http.post("/authorize/consent", data={"req": req, "step": "deny"},
                         headers={"origin": "https://evil.example"})
    assert xs.status_code == 403
    # after a good code, deny needs the nonce too, and sends the assistant access_denied
    step2 = await http.post("/authorize/consent", data={"req": req, "step": "code",
                                                        "code": web.issue_code(cfg, "maya")})
    nonce = field(step2.text, "nonce")
    assert (await http.post("/authorize/consent", data={"req": req, "step": "deny"})).status_code == 403
    no = await http.post("/authorize/consent", data={"req": req, "step": "deny", "nonce": nonce})
    url = back_url(no.text)
    assert url.startswith(REDIRECT) and "error=access_denied" in url and "state=st-123" in url
    # the request is gone now
    gone = await http.get(r.headers["location"])
    assert gone.status_code == 400 and "expired" in gone.text
    assert remote.RemoteStore(cfg).connections("maya") == []


async def new_req(http, client=None) -> str:
    client = client or await register(http)
    _, challenge = pkce()
    r = await start(http, client, challenge)
    assert r.status_code == 302, r.text
    return field((await http.get(r.headers["location"])).text, "req")


@pytest.mark.anyio
async def test_wrong_consent_codes_have_their_own_lockout(http, cfg):
    """Wrong codes from the internet lock remote linking for a while, never the home sign-in."""
    client = await register(http)
    for _ in range(web.LOCKOUT_MAX):
        req = await new_req(http, client)
        bad = await http.post("/authorize/consent", data={"req": req, "step": "code", "code": "ABCD2345"})
        assert bad.status_code in (401, 429)
    req = await new_req(http, client)
    locked = await http.post("/authorize/consent", data={"req": req, "step": "code",
                                                        "code": web.issue_code(cfg, "maya")})
    assert locked.status_code == 429
    # the home sign-in (and so the Approvals page) still works
    st = web.WebState(cfg)
    assert not st.locked()
    assert st.redeem(web.issue_code(cfg, "maya")) == ("maya", None)
    page = await signed_in(http, cfg, "dana")
    assert (await page.get("/approvals")).status_code == 200


@pytest.mark.anyio
async def test_three_wrong_codes_throw_the_request_away(http, cfg):
    req = await new_req(http)
    for i in range(remote.MAX_CODE_MISSES):
        r = await http.post("/authorize/consent", data={"req": req, "step": "code", "code": "ABCD2345"})
        assert r.status_code == 401
    assert "Too many wrong codes" in r.text
    late = await http.post("/authorize/consent", data={"req": req, "step": "code",
                                                      "code": web.issue_code(cfg, "maya")})
    assert late.status_code == 400 and "expired" in late.text


@pytest.mark.anyio
async def test_a_second_person_cannot_take_over_a_request(http, cfg):
    req = await new_req(http)
    step2 = await http.post("/authorize/consent", data={"req": req, "step": "code",
                                                       "code": web.issue_code(cfg, "maya")})
    assert "Link Claude to Maya?" in step2.text
    swap = await http.post("/authorize/consent", data={"req": req, "step": "code",
                                                      "code": web.issue_code(cfg, "dana")})
    assert swap.status_code == 400 and "expired" in swap.text
    nonce = field(step2.text, "nonce")
    gone = await http.post("/authorize/consent", data={"req": req, "step": "approve", "nonce": nonce})
    assert gone.status_code == 400 and "expired" in gone.text
    assert remote.RemoteStore(cfg).connections("maya") == [] == remote.RemoteStore(cfg).connections("dana")


@pytest.mark.anyio
async def test_authorize_never_redirects_off_the_box_on_error(http, cfg):
    evil = "https://evil.example/cb"
    client = await register(http, redirect=evil)
    _, ch = pkce()
    for extra in ({"scope": "bogus"}, {"resource": "https://other.example/mcp"}, {"response_type": "token"}):
        r = await start(http, client, ch, redirect=evil, **extra)
        assert r.status_code >= 400 and "location" not in r.headers, (extra, r.status_code)
        assert "evil.example" not in r.headers.get("location", "")
    # unknown client and unregistered redirect: an error page too
    r = await http.get("/authorize", params={"response_type": "code", "client_id": "nope", "redirect_uri": evil,
                                             "code_challenge": ch, "code_challenge_method": "S256"})
    assert r.status_code == 400 and "location" not in r.headers


@pytest.mark.anyio
async def test_cancel_before_a_code_does_not_forward_to_the_app(http, cfg):
    evil = "https://evil.example/cb"
    client = await register(http, redirect=evil)
    _, ch = pkce()
    r = await start(http, client, ch, redirect=evil)
    req = field((await http.get(r.headers["location"])).text, "req")
    no = await http.post("/authorize/consent", data={"req": req, "step": "deny"})
    assert no.status_code == 200 and "Not linked" in no.text
    assert "http-equiv" not in no.text                         # no automatic forward
    assert "evil.example" in no.text                           # the link names where it goes


@pytest.mark.anyio
async def test_refresh_retry_within_window_gets_the_same_pair(http, cfg):
    client, tok = await link(http, cfg, "maya")
    first = await refresh(http, client, tok["refresh_token"])
    retry = await refresh(http, client, tok["refresh_token"])          # a timeout retry, or two at once
    assert first.status_code == 200 and retry.status_code == 200, retry.text
    assert retry.json()["access_token"] == first.json()["access_token"]
    assert retry.json()["refresh_token"] == first.json()["refresh_token"]
    assert len(remote.RemoteStore(cfg).connections("maya")) == 1     # not revoked
    m = Mcp(http, first.json()["access_token"])
    await m.initialize()
    assert "as Maya" in await m.call("family_box_status")
    # another app can't use the retry window
    other = await register(http, name="Other app")
    assert (await refresh(http, other, tok["refresh_token"])).status_code == 400
    # the new pair is stored encrypted, not in the clear
    raw = (cfg.runtime / "remote" / "state.json").read_text()
    assert first.json()["refresh_token"] not in raw and first.json()["access_token"] not in raw
    # once the new refresh token is used, the old one is a copy again: revoke
    assert (await refresh(http, client, first.json()["refresh_token"])).status_code == 200
    assert (await refresh(http, client, tok["refresh_token"])).status_code == 400
    assert remote.RemoteStore(cfg).connections("maya") == []


@pytest.mark.anyio
async def test_consent_page_cannot_be_framed(http, cfg):
    client = await register(http)
    _, challenge = pkce()
    r = await start(http, client, challenge)
    page = await http.get(r.headers["location"])
    assert page.headers["x-frame-options"] == "DENY"
    assert "frame-ancestors 'none'" in page.headers["content-security-policy"]


def test_no_em_dashes_in_user_text():
    for p in ("src/familybox/plugins/remote.py", "src/familybox/remote.py", "docs/REMOTE.md"):
        assert "—" not in (Path(__file__).resolve().parents[1] / p).read_text(), p


def test_stdio_build_server_still_works(cfg, monkeypatch):
    from familybox import mcp_server
    monkeypatch.setenv("FAMILYBOX_HOME", str(cfg.home))
    s = mcp_server.build_server("maya", "replay")
    assert s.name == "family-box"


# --- the MCP SDK's own OAuth client, end to end ------------------------------------------------------

@pytest.mark.anyio
async def test_mcp_sdk_oauth_client_connects_and_calls_tools(cfg):
    """The official MCP client discovers, registers, runs PKCE, and then lists and calls tools."""
    import httpx2
    from mcp.client.auth import OAuthClientProvider
    from mcp.client.session import ClientSession
    from mcp.client.streamable_http import streamable_http_client
    from mcp.shared.auth import AuthorizationCodeResult, OAuthClientMetadata

    app = web.create_app(cfg)
    browser = httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url=BASE)
    got: dict = {}

    class Mem:
        tokens = client = None

        async def get_tokens(self):
            return self.tokens

        async def set_tokens(self, t):
            self.tokens = t

        async def get_client_info(self):
            return self.client

        async def set_client_info(self, c):
            self.client = c

    async def redirect_handler(url: str) -> None:       # "the family member's browser"
        r = await browser.get(url, follow_redirects=False)
        assert r.status_code == 302, r.text
        got["back"] = await consent(browser, cfg, r.headers["location"], "maya")

    async def callback_handler() -> AuthorizationCodeResult:
        q = parse_qs(urlsplit(got["back"]).query)
        return AuthorizationCodeResult(code=q["code"][0], state=q.get("state", [None])[0])

    meta = OAuthClientMetadata(client_name="Claude", redirect_uris=[REDIRECT], grant_types=["authorization_code",
                               "refresh_token"], response_types=["code"], token_endpoint_auth_method="none")
    oauth = OAuthClientProvider(f"{BASE}/mcp", meta, Mem(), redirect_handler, callback_handler)
    class NoGetStream(httpx2.ASGITransport):
        # httpx's in-process transport waits for a whole response body, so the long-lived GET event stream
        # would never return here. Answer it 405 (the client then skips it), as a server without one would.
        async def handle_async_request(self, request):
            if request.method == "GET" and request.url.path == "/mcp":
                return httpx2.Response(405, request=request)
            return await super().handle_async_request(request)

    async with httpx2.AsyncClient(transport=NoGetStream(app=app), auth=oauth, timeout=30) as hc:
        async with streamable_http_client(f"{BASE}/mcp", http_client=hc, terminate_on_close=False) as streams:
            read, write = streams[0], streams[1]
            async with ClientSession(read, write) as s:
                await s.initialize()
                names = {t.name for t in (await s.list_tools()).tools}
                assert {"ask_family_box", "family_box_status"} <= names
                res = await s.call_tool("family_box_status", {})
                assert "as Maya" in res.content[0].text
    await browser.aclose()
    assert [c["name"] for c in remote.RemoteStore(cfg).connections("maya")] == ["Claude"]


@pytest.mark.anyio
async def test_registration_flood_cannot_lock_out_real_assistants(http, cfg, monkeypatch):
    monkeypatch.setattr(remote, "MAX_CLIENTS", 3)
    monkeypatch.setattr(remote, "MAX_PENDING", 2)
    client, tok = await link(http, cfg, "maya")                 # a real, linked assistant
    for _ in range(5):
        await register(http, name="spam")
    st = remote.RemoteStore(cfg).read()
    assert len(st["clients"]) <= 3 and client["client_id"] in st["clients"]
    for _ in range(4):                                         # one app opening many sign-ins
        _, ch = pkce()
        assert (await start(http, client, ch)).status_code == 302
    assert len(remote.RemoteStore(cfg).read()["pending"]) <= remote.MAX_PENDING_PER_CLIENT
    m = Mcp(http, tok["access_token"])
    await m.initialize()
    assert "as Maya" in await m.call("family_box_status")


@pytest.mark.anyio
async def test_sign_in_opened_before_a_flood_can_still_finish(http, cfg, monkeypatch):
    monkeypatch.setattr(remote, "MAX_PENDING", 3)
    monkeypatch.setattr(remote, "MAX_CLIENTS", 4)
    real = await register(http)
    verifier, challenge = pkce()
    r = await start(http, real, challenge)
    assert r.status_code == 302
    location = r.headers["location"]
    for _ in range(6):                                         # spam apps, each opening sign-ins
        spam = await register(http, name="spam")
        for _ in range(3):
            _, ch = pkce()
            await start(http, spam, ch)
    st = remote.RemoteStore(cfg).read()
    assert real["client_id"] in st["clients"]
    url = await consent(http, cfg, location, "maya")
    code = parse_qs(urlsplit(url).query)["code"][0]
    tok = await http.post("/token", data={"grant_type": "authorization_code", "code": code, "redirect_uri": REDIRECT,
                                          "client_id": real["client_id"], "code_verifier": verifier})
    assert tok.status_code == 200, tok.text


# --- the assistant-only listener (familybox serve --remote-port) ------------------------------------

@pytest.mark.anyio
async def test_remote_only_app_serves_only_the_assistant_routes(cfg):
    app = web.create_app(cfg, remote_only=True)
    async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url=BASE) as c:
        for path in ("/signin", "/approvals", "/files", "/upload", "/cloud", "/assistants", "/",
                     "/approvals/x/approve", "/files/delete", "/oauth/google/callback", "/signout"):
            assert (await c.get(path)).status_code == 404, path
            assert (await c.post(path)).status_code in (404, 405), path
        assert (await c.post("/signin", data={"code": web.issue_code(cfg, "dana")})).status_code == 404
        assert (await c.get("/.well-known/oauth-authorization-server")).status_code == 200
        assert (await c.get("/.well-known/oauth-protected-resource/mcp")).status_code == 200
        assert (await c.get("/static/style.css")).status_code == 200
        assert (await c.post("/mcp", json={})).status_code == 401
        # the whole link flow and an MCP call work through it
        client, tok = await link(c, cfg, "maya")
        m = Mcp(c, tok["access_token"])
        await m.initialize()
        assert "as Maya" in await m.call("family_box_status")
    assert set(remote.REMOTE_PATHS) >= {"/mcp", "/authorize", "/authorize/consent", "/token", "/register"}


def test_serve_refuses_same_port_for_both(cfg):
    with pytest.raises(SystemExit):
        web.serve(cfg, port=8443, remote_port=8443)


# --- audit: which connection asked -------------------------------------------------------------------

@pytest.mark.anyio
async def test_questions_record_which_connection_asked(http, cfg):
    client, tok = await link(http, cfg, "maya")
    conn = remote.RemoteStore(cfg).connections("maya")[0]["id"]
    m = Mcp(http, tok["access_token"])
    await m.initialize()
    await m.call("ask_family_box", {"question": MAYA_Q})
    asked = [e for e in audit(cfg, "maya") if e.get("qid")]
    assert asked[-1]["source"].partition(":")[0] == "mcp-remote" and asked[-1]["connection"] == conn
    tid, api = remote.RemoteStore(cfg).new_api_token("maya", "Cursor")
    m2 = Mcp(http, api)
    await m2.initialize()
    await m2.call("ask_family_box", {"question": MAYA_Q})
    asked = [e for e in audit(cfg, "maya") if e.get("qid")]
    assert asked[-1]["connection"] == tid
    page = await signed_in(http, cfg, "maya")
    a = await page.get("/assistants")
    assert a.text.count("last asked never") == 0 and a.text.count("last asked") == 2


def test_standalone_http_server_is_labeled_local():
    src = (Path(__file__).resolve().parents[1] / "src/familybox/mcp_server.py").read_text()
    assert '"mcp-http-local" if args.http' in src


# --- the Assistants page address ---------------------------------------------------------------------

@pytest.mark.anyio
async def test_assistants_page_shows_public_address_or_says_not_online(cfg, monkeypatch):
    app = web.create_app(cfg)
    async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url=BASE) as c:
        page = await signed_in(c, cfg, "maya")
        a = await page.get("/assistants")
        assert "isn't on the internet yet" in a.text
    monkeypatch.setenv("FAMILYBOX_PUBLIC_URL", "https://box.example.org")
    app = web.create_app(cfg)
    async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url=BASE) as c:
        page = await signed_in(c, cfg, "maya")
        a = await page.get("/assistants")
        assert "https://box.example.org/mcp" in a.text and "isn't on the internet" not in a.text


# --- linking code from the Assistants page (Block B2) --------------------------------------------------

@pytest.mark.anyio
async def test_linking_code_from_the_assistants_page_links_an_assistant(http, cfg):
    page = await signed_in(http, cfg, "maya")
    a = await page.get("/assistants")
    assert "Get a linking code" in a.text
    assert (await http.post("/assistants/code", data={})).status_code == 403          # no CSRF
    r = await http.post("/assistants/code", data={"csrf": field(a.text, "csrf")})
    assert r.status_code == 200 and "Your linking code" in r.text
    shown = re.search(r'<div class="value">([A-Z0-9]{4})-([A-Z0-9]{4})</div>', r.text)
    assert shown, r.text
    code, dashed = shown.group(1) + shown.group(2), f"{shown.group(1)}-{shown.group(2)}"
    assert f"{BASE}/mcp" in r.text and "add a custom connector" in r.text and "Yes, link it" in r.text
    assert "lasts 10 minutes" in r.text and "—" not in r.text
    again = await http.get("/assistants")
    assert code not in again.text and dashed not in again.text
    entry = audit(cfg, "maya")[-1]
    assert entry["event"] == "linking_code_issued" and code not in json.dumps(audit(cfg, "maya"))

    client = await register(http)
    verifier, challenge = pkce()
    start_r = await start(http, client, challenge)
    consent_page = await http.get(start_r.headers["location"])
    assert "Get a code from the Assistants page on your box" in consent_page.text
    assert "Ask the person who runs the box" not in consent_page.text
    req = field(consent_page.text, "req")
    step2 = await http.post("/authorize/consent", data={"req": req, "step": "code", "code": dashed})
    assert step2.status_code == 200 and "Link Claude to Maya?" in step2.text
    done = await http.post("/authorize/consent", data={"req": req, "step": "approve",
                                                       "nonce": field(step2.text, "nonce")})
    q = parse_qs(urlsplit(back_url(done.text)).query)
    tok = await http.post("/token", data={"grant_type": "authorization_code", "code": q["code"][0],
                                          "redirect_uri": REDIRECT, "client_id": client["client_id"],
                                          "code_verifier": verifier})
    assert tok.status_code == 200
    m = Mcp(http, tok.json()["access_token"])
    await m.initialize()
    assert "as Maya" in await m.call("family_box_status")
    # the code worked once
    start2 = await start(http, client, challenge, state="st-2")
    req2 = field((await http.get(start2.headers["location"])).text, "req")
    bad = await http.post("/authorize/consent", data={"req": req2, "step": "code", "code": code})
    assert bad.status_code == 401


@pytest.mark.anyio
async def test_linking_code_shows_the_public_address(cfg, monkeypatch):
    monkeypatch.setenv("FAMILYBOX_PUBLIC_URL", "https://box.example.org")
    app = web.create_app(cfg)
    async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url=BASE) as c:
        page = await signed_in(c, cfg, "dana")
        a = await page.get("/assistants")
        r = await c.post("/assistants/code", data={"csrf": field(a.text, "csrf")})
        assert r.status_code == 200 and '<div class="value">https://box.example.org/mcp</div>' in r.text


@pytest.mark.anyio
async def test_linking_code_without_a_public_address_doesnt_send_you_to_chatgpt(http, cfg):
    page = await signed_in(http, cfg, "maya")
    a = await page.get("/assistants")
    assert "docs/REMOTE.md" not in a.text
    r = await http.post("/assistants/code", data={"csrf": field(a.text, "csrf")})
    text = html.unescape(r.text)
    assert "In ChatGPT or Claude, add" not in text
    assert "can't reach this box yet" in text and "In an app on this home network" in text
    # a linking code is not an invite: it can't set a PIN on /join
    code = re.search(r'<div class="value">([A-Z0-9]{4})-([A-Z0-9]{4})</div>', r.text)
    pid, why = web.WebState(cfg).redeem(code.group(1) + code.group(2), kind="invite")
    assert pid is None and why == "signin"
