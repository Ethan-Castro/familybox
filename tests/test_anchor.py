"""NEAR anchoring of log chain heads: identity, dry run, Borsh + signing, send/check against a fake RPC,
and the Log web page. No network: httpx is faked everywhere."""

import base64
import hashlib
import json
import re
import shutil
import stat
import struct
from pathlib import Path

import httpx
import pytest
from nacl.signing import SigningKey, VerifyKey
from starlette.testclient import TestClient

from familybox import cli, config, ledger, near_anchor as na, web
from familybox.plugins import anchor as plugin
from familybox.store import Store

DEMO = Path(__file__).resolve().parents[1] / "demo"
NEAR_ENV = ("NEAR_ACCOUNT_ID", "NEAR_ANCHOR_PRIVATE_KEY", "NEAR_ANCHOR_CONTRACT", "NEAR_NETWORK", "NEAR_RPC_URL")


@pytest.fixture
def cfg(tmp_path, monkeypatch):
    home = tmp_path / "home"
    shutil.copytree(DEMO / "files", home / "files")
    shutil.copy(DEMO / "family.toml", home / "family.toml")
    for k in NEAR_ENV + ("NEAR_AI_CLOUD_API_KEY", "NEARAI_API_KEY"):
        monkeypatch.delenv(k, raising=False)
    monkeypatch.setenv("FAMILYBOX_HOME", str(home))
    c = config.load(home)
    Store(c).reindex()
    return c


@pytest.fixture
def no_network(monkeypatch):
    def boom(*a, **k):
        raise AssertionError("dry run must not touch the network")
    monkeypatch.setattr(httpx.Client, "send", boom)


def fill(cfg, person="maya", n=3):
    for i in range(n):
        ledger.append(cfg.runtime, person, {"time": 1700000000 + i, "outcome": "pass"})


def test_plugin_is_loaded():
    from familybox import plugins
    assert plugin in plugins.load_plugins()


# --- identity and hashing --------------------------------------------------------------------------

def test_identity_is_private_and_stable(cfg):
    a = na.load_identity(cfg.runtime)
    assert re.fullmatch(r"fb-[0-9a-f]{20}", a["box_id"]) and len(bytes.fromhex(a["salt"])) == 32
    assert stat.S_IMODE(na.identity_path(cfg.runtime).stat().st_mode) == 0o600
    assert na.load_identity(cfg.runtime) == a


def test_person_hash_is_salted(cfg, tmp_path):
    a = na.load_identity(cfg.runtime)
    b = na.load_identity(tmp_path / "other-box")
    h = na.person_hash(a, "maya")
    assert re.fullmatch(r"[0-9a-f]{64}", h)
    assert h != na.person_hash(b, "maya") and h != na.person_hash(a, "dana")
    assert h != hashlib.sha256(b"maya").hexdigest()


def test_anchor_args_validation():
    good = ("fb-0123456789abcdef0123", "a" * 64, "b" * 64, 3)
    assert na.anchor_args(*good)["count"] == 3
    for bad in [("BAD ID!", *good[1:]), (good[0], "A" * 64, *good[2:]), (good[0], good[1], "b" * 63, 3),
                (*good[:3], 0), (*good[:3], True), (*good[:3], "3")]:
        with pytest.raises(na.AnchorError):
            na.anchor_args(*bad)


# --- dry run -----------------------------------------------------------------------------------------

def test_dry_run_payload_is_exact(cfg, no_network, capsys):
    fill(cfg, n=4)
    rep = ledger.verify_all(cfg.runtime, "maya")
    assert cli.main(["anchor", "--as", "maya"]) == 0
    out = capsys.readouterr().out
    assert "Nothing was sent" in out and "\u2014" not in out
    tx = json.loads(out[out.index("{"):out.rindex("}") + 1])
    ident = na.load_identity(cfg.runtime)
    call = tx["actions"][0]["FunctionCall"]
    want = {"box_id": ident["box_id"], "person_hash": na.person_hash(ident, "maya"), "head_hash": rep.head, "count": 4}
    assert call["method_name"] == "anchor" and call["args"] == want and call["deposit"] == "0"
    assert json.loads(base64.b64decode(call["args_base64"])) == want
    assert call["gas"] == na.DEFAULT_GAS
    assert "maya" not in json.dumps(call) and "Maya" not in json.dumps(call)
    assert not ledger.checkpoints(cfg.runtime, "maya")     # a plain dry run changes nothing


def test_dry_run_save_keeps_checkpoint_that_catches_truncation(cfg, no_network, capsys):
    fill(cfg, n=3)
    assert cli.main(["anchor", "--as", "maya", "--save"]) == 0
    capsys.readouterr()
    cps = ledger.checkpoints(cfg.runtime, "maya")
    assert len(cps) == 1 and cps[0]["count"] == 3
    path = ledger.log_path(cfg.runtime, "maya")
    path.write_text("".join(x + "\n" for x in path.read_text().splitlines()[:2]))
    ledger._write_head(cfg.runtime, "maya", 1, json.loads(path.read_text().splitlines()[-1])["entry_hash"])
    assert cli.main(["log", "verify", "--as", "maya"]) == 1
    assert "local checkpoint says entry 3" in capsys.readouterr().out


def test_dry_run_refuses_a_broken_log(cfg, no_network, capsys):
    fill(cfg, n=3)
    path = ledger.log_path(cfg.runtime, "maya")
    ls = path.read_text().splitlines()
    del ls[1]
    path.write_text("".join(x + "\n" for x in ls))
    assert cli.main(["anchor", "--as", "maya"]) == 1
    out = capsys.readouterr().out
    assert "will not be anchored" in out and "FunctionCall" not in out


def test_dry_run_everyone(cfg, no_network, capsys):
    fill(cfg, "maya", 2)
    assert cli.main(["anchor"]) == 0
    out = capsys.readouterr().out
    assert "Maya: dry run" in out and "Dana: nothing to anchor yet" in out


def test_settings_validation(cfg):
    with pytest.raises(na.AnchorError):
        na.settings(cfg.runtime, {"NEAR_ACCOUNT_ID": "Not An Account"})
    with pytest.raises(na.AnchorError):
        na.settings(cfg.runtime, {"NEAR_NETWORK": "devnet"})
    s = na.settings(cfg.runtime, {"NEAR_NETWORK": "mainnet"})
    assert s.rpc_url == na.RPC_DEFAULTS["mainnet"] and not s.live_ready


# --- keys, base58, Borsh -----------------------------------------------------------------------------

def test_base58_roundtrip():
    for data in [b"", b"\0", b"\0\0\x01", bytes(range(32)), b"\xff" * 64]:
        assert na.b58decode(na.b58encode(data)) == data
    assert na.b58encode(b"hello world") == "StV1DL6CwTryKyV"   # standard Bitcoin-alphabet vector


def test_keygen_is_private_and_not_printed(cfg, capsys):
    assert cli.main(["anchor", "keygen"]) == 0
    out = capsys.readouterr().out
    secret = json.loads(na.key_path(cfg.runtime).read_text())["private_key"]
    assert stat.S_IMODE(na.key_path(cfg.runtime).stat().st_mode) == 0o600
    assert secret.split(":")[1] not in out and na.public_key_of(secret) in out
    assert na.keygen(cfg.runtime) == na.public_key_of(secret)        # stable without --force
    assert len(na.b58decode(secret.split(":")[1])) == 64


def test_mismatched_key_rejected():
    a, b = SigningKey.generate(), SigningKey.generate()
    bad = "ed25519:" + na.b58encode(bytes(a) + bytes(b.verify_key))
    with pytest.raises(na.AnchorError):
        na.public_key_of(bad)
    with pytest.raises(na.AnchorError):
        na.public_key_of("secp256k1:abc")


def _parse_tx(b: bytes) -> dict:
    """A tiny independent Borsh reader for the one transaction shape we send."""
    i = 0

    def take(n):
        nonlocal i
        out = b[i:i + n]; i += n
        return out

    def u32():
        return struct.unpack("<I", take(4))[0]

    def string():
        return take(u32()).decode()

    tx = {"signer_id": string()}
    assert take(1) == b"\0"
    tx["public_key"] = take(32)
    tx["nonce"] = struct.unpack("<Q", take(8))[0]
    tx["receiver_id"] = string()
    tx["block_hash"] = take(32)
    assert u32() == 1 and take(1) == b"\x02"
    tx["method_name"] = string()
    tx["args"] = take(u32())
    tx["gas"] = struct.unpack("<Q", take(8))[0]
    tx["deposit"] = int.from_bytes(take(16), "little")
    tx["_end"] = i
    return tx


def test_borsh_and_signature():
    sk = SigningKey.generate()
    secret = "ed25519:" + na.b58encode(bytes(sk) + bytes(sk.verify_key))
    args = na.args_bytes({"box_id": "fb-x0x", "count": 1})
    tx = na.encode_transaction(signer_id="family.testnet", public_key=bytes(sk.verify_key), nonce=42,
                               receiver_id="anchor.family.testnet", block_hash=b"\x07" * 32,
                               method_name="anchor", args=args, gas=na.DEFAULT_GAS)
    p = _parse_tx(tx)
    assert p["_end"] == len(tx)
    assert (p["signer_id"], p["nonce"], p["receiver_id"], p["method_name"], p["args"], p["gas"], p["deposit"]) == \
        ("family.testnet", 42, "anchor.family.testnet", "anchor", args, na.DEFAULT_GAS, 0)
    signed = na.sign_transaction(tx, secret)
    assert signed[:len(tx)] == tx and signed[len(tx)] == 0 and len(signed) == len(tx) + 65
    VerifyKey(bytes(sk.verify_key)).verify(hashlib.sha256(tx).digest(), signed[len(tx) + 1:])


# --- send and check against a fake NEAR RPC ------------------------------------------------------------

class FakeNear:
    def __init__(self, contract, perm=None, failure=None):
        self.contract, self.failure = contract, failure
        self.perm = perm or {"FunctionCall": {"allowance": "250000000000000000000000", "receiver_id": contract,
                                              "method_names": ["anchor"]}}
        self.sent: list[dict] = []
        self.stored: dict = {}
        self.block = na.b58encode(b"\x09" * 32)

    def __call__(self, request: httpx.Request) -> httpx.Response:
        body = json.loads(request.content)
        m, p = body["method"], body["params"]
        if m == "query" and p["request_type"] == "view_access_key":
            res = {"nonce": 100, "permission": self.perm, "block_hash": self.block}
        elif m == "block":
            res = {"header": {"hash": self.block, "height": 1}}
        elif m == "send_tx":
            raw = base64.b64decode(p["signed_tx_base64"])
            tx = _parse_tx(raw)
            self.sent.append(tx | {"raw": raw})
            if self.failure:
                res = {"status": {"Failure": self.failure}}
            else:
                a = json.loads(tx["args"])
                self.stored[(a["box_id"], a["person_hash"])] = {"head_hash": a["head_hash"], "count": a["count"]}
                res = {"status": {"SuccessValue": ""}}
        elif m == "query" and p["request_type"] == "call_function":
            a = json.loads(base64.b64decode(p["args_base64"]))
            val = self.stored.get((a["box_id"], a["person_hash"]))
            res = {"result": list(json.dumps(val).encode())}
        else:
            return httpx.Response(200, json={"jsonrpc": "2.0", "id": body["id"], "error": {"message": "nope"}})
        return httpx.Response(200, json={"jsonrpc": "2.0", "id": body["id"], "result": res})


@pytest.fixture
def live(cfg, monkeypatch):
    """Settings for a fake testnet account, with all RPC calls going to a FakeNear."""
    pub = na.keygen(cfg.runtime)
    monkeypatch.setenv("NEAR_ACCOUNT_ID", "family.testnet")
    monkeypatch.setenv("NEAR_ANCHOR_CONTRACT", "anchor.family.testnet")
    fake = FakeNear("anchor.family.testnet")
    real_init = na.Rpc.__init__

    def init(self, url, http=None, timeout=20.0):
        real_init(self, url, httpx.Client(transport=httpx.MockTransport(fake)))
    monkeypatch.setattr(na.Rpc, "__init__", init)
    return fake, pub


def test_send_signs_and_records_checkpoint(cfg, live, capsys):
    fake, pub = live
    fill(cfg, n=3)
    rep = ledger.verify_all(cfg.runtime, "maya")
    assert cli.main(["anchor", "send", "--as", "maya"]) == 0
    out = capsys.readouterr().out
    tx = fake.sent[0]
    assert tx["signer_id"] == "family.testnet" and tx["receiver_id"] == "anchor.family.testnet"
    assert tx["nonce"] == 101 and tx["block_hash"] == b"\x09" * 32 and tx["deposit"] == 0
    assert "ed25519:" + na.b58encode(tx["public_key"]) == pub
    assert json.loads(tx["args"])["head_hash"] == rep.head and json.loads(tx["args"])["count"] == 3
    unsigned = tx["raw"][:tx["_end"]]
    VerifyKey(tx["public_key"]).verify(hashlib.sha256(unsigned).digest(), tx["raw"][tx["_end"] + 1:])
    h = na.tx_hash(unsigned)
    assert h in out
    cp = ledger.checkpoints(cfg.runtime, "maya")[-1]
    assert cp["count"] == 3 and cp["head"] == rep.head and cp["tx_hash"] == h
    secret = json.loads(na.key_path(cfg.runtime).read_text())["private_key"]
    assert secret.split(":")[1] not in out


def test_check_matches_and_catches_rewrite(cfg, live, capsys):
    fill(cfg, n=3)
    assert cli.main(["anchor", "send", "--as", "maya"]) == 0
    fill(cfg, n=2)
    assert cli.main(["anchor", "check", "--as", "maya"]) == 0
    assert "matches NEAR" in capsys.readouterr().out
    # Rebuild the whole log from scratch (new hashes everywhere), with the local checkpoints wiped too.
    ledger.log_path(cfg.runtime, "maya").unlink()
    ledger.head_path(cfg.runtime, "maya").unlink()
    ledger.checkpoints_path(cfg.runtime, "maya").unlink()
    for i in range(5):
        ledger.append(cfg.runtime, "maya", {"time": 1, "outcome": "refused", "i": i})
    assert cli.main(["log", "verify", "--as", "maya"]) == 0    # locally it looks fine...
    capsys.readouterr()
    assert cli.main(["anchor", "check", "--as", "maya"]) == 1   # ...NEAR says otherwise
    assert "does NOT match" in capsys.readouterr().out


def test_check_nothing_anchored(cfg, live, capsys):
    assert cli.main(["anchor", "check", "--as", "maya"]) == 0
    assert "nothing anchored" in capsys.readouterr().out


@pytest.mark.parametrize("perm", ["FullAccess",
                                  {"FunctionCall": {"receiver_id": "other.testnet", "method_names": ["anchor"]}},
                                  {"FunctionCall": {"receiver_id": "anchor.family.testnet", "method_names": ["x"]}}])
def test_send_refuses_wrong_key(cfg, live, capsys, perm):
    fake, _ = live
    fake.perm = perm
    fill(cfg, n=1)
    assert cli.main(["anchor", "send", "--as", "maya"]) == 1
    assert "error:" in capsys.readouterr().out and not fake.sent
    assert not ledger.checkpoints(cfg.runtime, "maya")


def test_send_reports_on_chain_failure(cfg, live, capsys):
    fake, _ = live
    fake.failure = {"ActionError": {"kind": {"FunctionCallError": {"ExecutionError": "count went down"}}}}
    fill(cfg, n=1)
    assert cli.main(["anchor", "send", "--as", "maya"]) == 1
    assert "failed on-chain" in capsys.readouterr().out
    assert not ledger.checkpoints(cfg.runtime, "maya")


def test_send_without_settings_is_refused(cfg, capsys):
    fill(cfg, n=1)
    assert cli.main(["anchor", "send", "--as", "maya"]) == 1
    assert "missing NEAR_ACCOUNT_ID" in capsys.readouterr().out


def test_status(cfg, capsys):
    assert cli.main(["anchor", "status"]) == 0
    st = json.loads(capsys.readouterr().out)
    assert st["ready_to_send"] is False and st["box_id"].startswith("fb-")


# --- the Log page ---------------------------------------------------------------------------------------

def sign_in(cfg, person):
    c = TestClient(web.create_app(cfg), base_url="https://testserver")
    page = c.get("/signin")
    token = re.search(r'name="csrf" value="([^"]+)"', page.text).group(1)
    r = c.post("/signin", data={"code": web.issue_code(cfg, person), "csrf": token}, follow_redirects=False)
    assert r.status_code == 303
    return c


def test_log_page(cfg):
    fill(cfg, "maya", 2)
    fill(cfg, "dana", 1)
    c = sign_in(cfg, "maya")
    home = c.get("/")
    assert 'href="/log"' in home.text
    r = c.get("/log")
    assert r.status_code == 200
    assert ledger.head(cfg.runtime, "maya")[1] in r.text and "checks out: 2 entries" in r.text
    assert ledger.head(cfg.runtime, "dana")[1] not in r.text and "Dana" not in r.text.split("</nav>", 1)[1]
    assert "\u2014" not in r.text

    admin = sign_in(cfg, "dana").get("/log")
    assert ledger.head(cfg.runtime, "maya")[1] in admin.text and "Maya's log" in admin.text


def test_log_page_shows_broken_chain(cfg):
    fill(cfg, "maya", 3)
    path = ledger.log_path(cfg.runtime, "maya")
    ls = path.read_text().splitlines()
    ls[0], ls[1] = ls[1], ls[0]
    path.write_text("".join(x + "\n" for x in ls))
    r = sign_in(cfg, "maya").get("/log")
    assert "does not check out" in r.text


def test_log_page_needs_signin(cfg):
    c = TestClient(web.create_app(cfg), base_url="https://testserver")
    assert c.get("/log", follow_redirects=False).status_code == 303
