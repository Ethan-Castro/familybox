"""Approver devices: tokens, the bearer JSON API, the owner's Devices page and the CLI (no network)."""

import json
import re
import shutil
import stat
from pathlib import Path

import pytest
from starlette.testclient import TestClient

from familybox import cli, config, devices, web
from familybox.approvals import Approvals
from familybox.box import Box
from familybox.devices import Devices
from familybox.gate import Held
from familybox.store import Store

DEMO = Path(__file__).resolve().parents[1] / "demo"
PASSPORT = "X10483921"          # fictional, from demo/files/people/dana/ids/passport_dana.txt
SSN = "987-65-4320"
API = "/api/device/v1"


@pytest.fixture
def cfg(tmp_path, monkeypatch):
    shutil.copytree(DEMO / "files", tmp_path / "files")
    shutil.copy(DEMO / "family.toml", tmp_path / "family.toml")
    monkeypatch.delenv("FAMILYBOX_OAUTH_REDIRECT", raising=False)
    monkeypatch.delenv("NEAR_AI_CLOUD_API_KEY", raising=False)
    monkeypatch.delenv("NEARAI_API_KEY", raising=False)
    c = config.load(tmp_path)
    Store(c).reindex()
    return c


def client(cfg) -> TestClient:
    return TestClient(web.create_app(cfg), base_url="https://testserver")


def bearer(token: str) -> dict:
    return {"Authorization": f"Bearer {token}"}


def hold(cfg, *, asker="maya", owner="dana", kind="id", label="Passport Number", value=PASSPORT,
         item_id="p1", source="mcp-remote:chatgpt", question="What is my mom's passport number?") -> str:
    path = f"people/{owner}/ids/passport_{owner}.txt"
    return Approvals(cfg).add(asker, question, [Held(item_id, kind, label, value, owner, path)], source=source)[0]


def csrf(resp) -> str:
    m = re.search(r'name="csrf" value="([^"]+)"', resp.text)
    assert m, resp.text
    return m.group(1)


def sign_in(cfg, person):
    c = client(cfg)
    code = web.issue_code(cfg, person)
    r = c.post("/signin", data={"code": code, "csrf": csrf(c.get("/signin"))}, follow_redirects=False)
    assert r.status_code == 303
    return c, csrf(c.get("/"))


# --- tokens ----------------------------------------------------------------------------------------

def test_tokens_are_hashed_at_rest_and_files_private(cfg):
    dev_id, token = Devices(cfg).add("dana", "Kitchen button")
    assert devices.TOKEN_RE.match(token)
    raw = (cfg.runtime / "devices" / "devices.json").read_text()
    assert token not in raw and token.split("_", 2)[2] not in raw
    assert json.loads(raw)[dev_id]["scope"] == "approve"
    d = cfg.runtime / "devices"
    assert stat.S_IMODE(d.stat().st_mode) == 0o700
    assert stat.S_IMODE((d / "devices.json").stat().st_mode) == 0o600


def test_check_token_rejects_wrong_forged_and_removed(cfg):
    devs = Devices(cfg)
    dev_id, token = devs.add("dana")
    assert devs.check_token(token)["person"] == "dana"
    other_id, other = devs.add("maya")
    forged = f"fbd_{dev_id}_{other.split('_', 2)[2]}"     # right id, someone else's secret
    for bad in ("", "fbd_", token + "x", token[:-1] + ("A" if token[-1] != "A" else "B"), forged,
                f"Bearer {token}", token.upper()):
        assert devs.check_token(bad) is None, bad
    assert devs.remove("maya", dev_id) is False          # only the owner removes it
    assert devs.remove("dana", dev_id) is True
    assert devs.check_token(token) is None


def test_device_for_removed_person_is_refused(cfg):
    devs = Devices(cfg)
    _, token = devs.add("dana")
    data = json.loads((devs.dir / "devices.json").read_text())
    for d in data.values():
        d["person"] = "nobody"
    (devs.dir / "devices.json").write_text(json.dumps(data))
    assert devs.check_token(token) is None


def test_names_are_cleaned(cfg):
    dev_id, _ = Devices(cfg).add("dana", "<script>alert(1)</script>" + "x" * 80)
    name = Devices(cfg).list("dana")[0]["name"]
    assert "<" not in name and len(name) <= devices.NAME_MAX


def test_describe_wording(cfg):
    base = {"asker": "maya", "owner": "dana", "kind": "id", "label": "Passport Number"}
    assert devices.describe(cfg, base | {"source": "mcp-remote:chatgpt"}) == \
        "Maya's ChatGPT wants Dana's passport number"
    assert devices.describe(cfg, base | {"source": "mcp-stdio"}) == "Maya's assistant wants Dana's passport number"
    assert devices.describe(cfg, base | {"source": "cli"}) == "Maya wants Dana's passport number"
    assert devices.describe(cfg, base | {"source": ""}) == "Maya wants Dana's passport number"
    assert devices.describe(cfg, base | {"kind": "ssn", "label": "SSN", "source": "claude"}) == \
        "Maya's Claude wants Dana's Social Security number"
    # Health details are never named on a screen others can see.
    assert devices.describe(cfg, base | {"kind": "health", "label": "Medication", "source": ""}) == \
        "Maya wants Dana's health detail"


# --- the bearer API --------------------------------------------------------------------------------

def test_pending_lists_only_this_persons_items_without_values(cfg):
    hold(cfg, item_id="p1")
    hold(cfg, item_id="s1", kind="ssn", label="SSN", value=SSN, source="mcp-stdio")
    hold(cfg, item_id="m1", owner="maya", asker="dana", value="P55501234")
    _, token = Devices(cfg).add("dana", "Kitchen button")
    c = client(cfg)
    r = c.get(f"{API}/pending", headers=bearer(token))
    assert r.status_code == 200
    assert r.headers["cache-control"] == "no-store"
    body = r.json()
    assert body["device"]["person"] == "Dana" and body["device"]["scope"] == "approve"
    assert [i["id"] for i in body["items"]] == ["p1", "s1"]
    assert body["items"][0]["text"] == "Maya's ChatGPT wants Dana's passport number"
    assert body["items"][0]["assistant"] == "ChatGPT"
    for leak in (PASSPORT, SSN, "987654320", "P55501234", "passport_dana.txt", "people/", "mom's passport"):
        assert leak not in r.text
    assert set(body["items"][0]) == {"id", "text", "asker", "assistant", "what", "created"}


def test_pending_is_oldest_first(cfg):
    hold(cfg, item_id="new1")
    hold(cfg, item_id="old1")
    data = Approvals(cfg)._load()
    data["old1"]["created"] = data["new1"]["created"] - 100
    Approvals(cfg)._save(data)
    _, token = Devices(cfg).add("dana")
    items = client(cfg).get(f"{API}/pending", headers=bearer(token)).json()["items"]
    assert [i["id"] for i in items] == ["old1", "new1"]


@pytest.mark.parametrize("headers", [{}, {"Authorization": "Bearer nope"}, {"Authorization": "Basic Zm9vOmJhcg=="},
                                     {"Authorization": "bearer"}])
def test_api_needs_a_device_token(cfg, headers):
    hold(cfg)
    r = client(cfg).get(f"{API}/pending", headers=headers)
    assert r.status_code == 401 and PASSPORT not in r.text
    assert "bearer" in r.headers["www-authenticate"].lower()


def test_token_in_query_string_is_not_accepted(cfg):
    _, token = Devices(cfg).add("dana")
    assert client(cfg).get(f"{API}/pending?token={token}").status_code == 401


def test_web_session_cookie_is_not_a_device_token(cfg):
    hold(cfg)
    dana, page_csrf = sign_in(cfg, "dana")
    assert dana.get(f"{API}/pending").status_code == 401
    r = dana.post(f"{API}/items/p1/approve", data={"csrf": page_csrf})
    assert r.status_code == 401
    assert Approvals(cfg).pending("dana")


def test_approve_by_bearer_needs_no_csrf_and_returns_no_value(cfg):
    hold(cfg)
    _, token = Devices(cfg).add("dana")
    r = client(cfg).post(f"{API}/items/p1/approve", headers=bearer(token))
    assert r.status_code == 200, r.text
    assert r.json() == {"id": "p1", "status": "approved"}
    assert PASSPORT not in r.text
    assert Approvals(cfg)._load()["p1"]["status"] == "approved"
    assert not Approvals(cfg).pending("dana")
    audit = (cfg.runtime / "audit" / "dana.jsonl").read_text()
    assert '"device_decision"' in audit and PASSPORT not in audit


def test_deny_by_bearer(cfg):
    hold(cfg)
    _, token = Devices(cfg).add("dana")
    r = client(cfg).post(f"{API}/items/p1/deny", headers=bearer(token))
    assert r.json() == {"id": "p1", "status": "denied"}
    assert Approvals(cfg)._load()["p1"]["status"] == "denied"


def test_device_cannot_decide_someone_elses_item(cfg):
    hold(cfg, item_id="m1", owner="maya", asker="dana", value="P55501234")
    _, token = Devices(cfg).add("dana")
    r = client(cfg).post(f"{API}/items/m1/approve", headers=bearer(token))
    assert r.status_code == 404 and "P55501234" not in r.text
    assert Approvals(cfg).pending("maya")


def test_decide_twice_or_unknown_or_bad_action(cfg):
    hold(cfg)
    _, token = Devices(cfg).add("dana")
    c = client(cfg)
    assert c.post(f"{API}/items/p1/approve", headers=bearer(token)).status_code == 200
    assert c.post(f"{API}/items/p1/deny", headers=bearer(token)).status_code == 404
    assert Approvals(cfg)._load()["p1"]["status"] == "approved"
    assert c.post(f"{API}/items/zzz/approve", headers=bearer(token)).status_code == 404
    hold(cfg, item_id="p2")
    assert c.post(f"{API}/items/p2/reveal", headers=bearer(token)).status_code == 404
    assert c.get(f"{API}/items/p2/approve", headers=bearer(token)).status_code == 405
    assert Approvals(cfg).pending("dana")


def test_requests_with_an_origin_header_are_refused(cfg):
    hold(cfg)
    _, token = Devices(cfg).add("dana")
    for origin in ("https://evil.example", "https://testserver", "null"):
        r = client(cfg).post(f"{API}/items/p1/approve", headers=bearer(token) | {"Origin": origin})
        assert r.status_code == 403
    assert Approvals(cfg).pending("dana")


def test_wrong_tokens_lock_out_the_address(cfg):
    _, token = Devices(cfg).add("dana")
    c = client(cfg)
    for _ in range(10):
        assert c.get(f"{API}/pending", headers=bearer("fbd_00000000_" + "a" * 43)).status_code == 401
    assert c.get(f"{API}/pending", headers=bearer(token)).status_code == 429


def test_device_token_does_not_open_web_pages(cfg):
    _, token = Devices(cfg).add("dana")
    c = client(cfg)
    for path in ("/", "/approvals", "/devices", "/files"):
        r = c.get(path, headers=bearer(token), follow_redirects=False)
        assert r.status_code == 303 and r.headers["location"] == "/signin"


# --- the owner's Devices page ---------------------------------------------------------------------

def test_devices_page_reveals_a_button_approved_value_once(cfg):
    hold(cfg)
    dev_id, token = Devices(cfg).add("dana", "Kitchen button")
    client(cfg).post(f"{API}/items/p1/approve", headers=bearer(token))

    maya, maya_csrf = sign_in(cfg, "maya")
    assert maya.post("/devices/show/p1", data={"csrf": maya_csrf}).status_code == 404

    dana, page_csrf = sign_in(cfg, "dana")
    page = dana.get("/devices").text
    assert "Kitchen button" in page and "Approved on Kitchen button" in page and PASSPORT not in page
    assert "Maya&#x27;s ChatGPT wants Dana&#x27;s passport number" in page
    assert dana.post("/devices/show/p1").status_code == 403                  # CSRF still needed on the web
    r = dana.post("/devices/show/p1", data={"csrf": page_csrf})
    assert r.status_code == 200 and PASSPORT in r.text
    r2 = dana.post("/devices/show/p1", data={"csrf": page_csrf})
    assert r2.status_code == 404 and PASSPORT not in r2.text


def test_denied_items_are_never_revealed(cfg):
    hold(cfg)
    _, token = Devices(cfg).add("dana")
    client(cfg).post(f"{API}/items/p1/deny", headers=bearer(token))
    dana, page_csrf = sign_in(cfg, "dana")
    r = dana.post("/devices/show/p1", data={"csrf": page_csrf})
    assert r.status_code == 404 and PASSPORT not in r.text


def test_reveal_window_expires(cfg):
    hold(cfg)
    devs = Devices(cfg)
    _, token = devs.add("dana")
    devs.decide(devs.check_token(token), "p1", True)
    import time
    with pytest.raises(KeyError):
        devs.reveal("dana", "p1", now=time.time() + devices.REVEAL_WINDOW_S + 1)
    assert devs.reveal("dana", "p1")["value"] == PASSPORT


def test_remove_device_from_web(cfg):
    dev_id, token = Devices(cfg).add("dana", "Kitchen button")
    maya, maya_csrf = sign_in(cfg, "maya")
    assert maya.post(f"/devices/remove/{dev_id}", data={"csrf": maya_csrf}).status_code == 404
    dana, page_csrf = sign_in(cfg, "dana")
    assert dana.post(f"/devices/remove/{dev_id}").status_code == 403
    assert Devices(cfg).check_token(token)
    r = dana.post(f"/devices/remove/{dev_id}", data={"csrf": page_csrf})
    assert r.status_code == 200 and "Removed" in r.text
    assert client(cfg).get(f"{API}/pending", headers=bearer(token)).status_code == 401


def test_nav_has_devices_link(cfg):
    dana, _ = sign_in(cfg, "dana")
    assert 'href="/devices"' in dana.get("/").text


# --- the box records where a held question came from ----------------------------------------------

def test_box_stores_source_on_held_items(cfg, tmp_path):
    # A replayed answer that includes Dana's SSN, asked by Sam over MCP: the gate holds it.
    from familybox import enclave
    replay_dir = tmp_path / "replays"
    replay_dir.mkdir()
    q = "What is Dana's SSN?"
    rec = {"answer": f"Dana's SSN is {SSN}.", "model": "test/model", "tokens_in": 1, "tokens_out": 1,
           "attestation": {"model_reports_verified": 1, "verified_at_ms": 1, "seconds": 0.1, "e2ee": True},
           "turns": [{"seconds": 0.1, "signature_kind": "provider_tee", "signer": "0x1234567890",
                      "tool_calls": [{"name": "read_file", "arguments": {"path": "people/dana/ids/ssn_card_dana.txt"}}],
                      "content": None},
                     {"seconds": 0.1, "signature_kind": "provider_tee", "signer": "0x1234567890",
                      "tool_calls": [], "content": f"Dana's SSN is {SSN}."}]}
    (replay_dir / f"{enclave.replay_key('dana', q)}.json").write_text(json.dumps(rec))
    ans = Box(cfg, mode="replay", replay_dir=replay_dir).ask("dana", q, source="mcp-remote")
    assert ans.outcome == "held", ans
    item = Approvals(cfg)._load()[ans.held_ids[0]]
    assert item["source"] == "mcp-remote"
    _, token = Devices(cfg).add("dana")
    items = client(cfg).get(f"{API}/pending", headers=bearer(token)).json()["items"]
    assert items[0]["text"] == "Dana's assistant wants Dana's Social Security number"


# --- CLI -------------------------------------------------------------------------------------------

def test_cli_add_list_remove(cfg, monkeypatch, capsys):
    monkeypatch.setenv("FAMILYBOX_HOME", str(cfg.home))
    assert cli.main(["device", "add", "--as", "dana", "--name", "Kitchen button",
                     "--url", "https://familybox.local:8443"]) == 0
    out = capsys.readouterr().out
    blob = json.loads(out[out.index("{"):out.index("}") + 1])
    assert blob["box_url"] == "https://familybox.local:8443"
    assert devices.TOKEN_RE.match(blob["token"])
    assert re.fullmatch(r"([0-9A-F]{2}:){31}[0-9A-F]{2}", blob["cert_sha256"])
    assert "—" not in out
    assert Devices(cfg).check_token(blob["token"])["person"] == "dana"

    assert cli.main(["device", "list", "--as", "dana"]) == 0
    listing = capsys.readouterr().out
    assert "Kitchen button" in listing and blob["token"] not in listing
    dev_id = listing.split()[0]
    assert cli.main(["device", "remove", "--as", "maya", dev_id]) == 1
    assert cli.main(["device", "remove", "--as", "dana", dev_id]) == 0
    assert Devices(cfg).check_token(blob["token"]) is None
    assert cli.main(["device", "add", "--as", "nobody"]) == 2
