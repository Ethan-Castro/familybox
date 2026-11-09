"""Pinning NEAR's serving code: fingerprints, trust on first use, change blocks, owner review (no network).

Every verification result here is fake: hand-built SDK MeasuredDeployment objects and synthetic TDX
quotes. The real fingerprints from live NEAR runs are in pins/near-ai-cloud.json and docs/BUILD_LOG.md.
"""

import asyncio
import hashlib
import json
import re
import shutil
import types
from pathlib import Path

import pytest
from nearai_inference_sdk import MeasuredDeployment, RuntimeMeasurements, TdxQuoteVerificationResult
from nearai_inference_sdk.types.compose_manager import VerifiedComposeManagerAttestation
from starlette.testclient import TestClient

import familybox.pinning as pinning
from familybox import config, enclave, web
from familybox.box import Box
from familybox.pinning import Checker, Measured, PinError, PinStore, measure, running_workload
from familybox.plugins import pinning as plugin
from familybox.store import Store

DEMO = Path(__file__).resolve().parents[1] / "demo"
MODEL = "deepseek-ai/DeepSeek-V4.1-Flash-1017"


@pytest.fixture
def cfg(tmp_path, monkeypatch):
    home = tmp_path / "home"
    shutil.copytree(DEMO / "files", home / "files")
    shutil.copy(DEMO / "family.toml", home / "family.toml")
    monkeypatch.delenv("NEAR_AI_CLOUD_API_KEY", raising=False)
    monkeypatch.delenv("NEARAI_API_KEY", raising=False)
    monkeypatch.delenv("FAMILYBOX_PIN_LEVEL", raising=False)
    monkeypatch.delenv("FAMILYBOX_MODEL", raising=False)
    monkeypatch.setattr(pinning, "REPO_PINS", tmp_path / "no-shipped-pins.json")
    c = config.load(home)
    Store(c).reindex()
    return c


# ---------------------------------------------------------------- fake verification results

def app_compose(images=("nearaidev/cloud-api@sha256:" + "a" * 64,), label="gpu02", envs=("ENV",), kms=True,
                name="dstack-0.5.12") -> str:
    lines = ["services:"]
    for i, img in enumerate(images):
        lines += [f"  svc{i}:", f"    image: {img}", "    environment:", f"      - INSTANCE_LABEL={label}",
                  "      - LOG_LEVEL=info"]
    return json.dumps({"manifest_version": 2, "name": name, "runner": "docker-compose",
                       "docker_compose_file": "\n".join(lines) + "\n", "kms_enabled": kms, "gateway_enabled": False,
                       "public_logs": False, "allowed_envs": list(envs)})


def actions(*items):
    return tuple(items)


def up(file, sha, ts="2026-11-08T20:55:56+00:00", services=None, tag="v0.0.553"):
    a = {"timestamp": ts, "action": "compose_up", "tag": tag, "commit": "c" * 40, "file": file, "file_sha256": sha}
    if services is not None:
        a["services"] = services
    return a


def down(file, ts="2026-11-08T21:00:00+00:00", services=None):
    a = {"timestamp": ts, "action": "compose_down", "file": file}
    if services is not None:
        a["services"] = services
    return a


STARTED = {"timestamp": "2026-11-08T06:14:35+00:00", "action": "compose_manager_started",
           "image": "nearaidev/compose-manager@sha256:" + "b" * 64}
SERVE = "prod/DeepSeek-V4.1-Flash-1017-vLLM-DEP8-Abliterated.yaml"


def deployment(compose=None, os_hash="9" * 64, acts=None) -> MeasuredDeployment:
    compose = compose or app_compose()
    cm = None
    if acts is not None:
        cm = VerifiedComposeManagerAttestation(actions=acts, tcb_status="UpToDate", advisory_ids=(),
                                               runtime_measurements=RuntimeMeasurements())
    return MeasuredDeployment(app_compose=compose,
                              runtime_measurements=RuntimeMeasurements(
                                  os_image_hash=os_hash, compose_hash=hashlib.sha256(compose.encode()).hexdigest()),
                              compose_manager=cm)


TD = [{"mrtd": "1" * 96, "rtmr0": "2" * 96, "rtmr1": "3" * 96, "rtmr2": "4" * 96}]


def fake_quote(compose: str, version: int = 4, mrtd: bytes = b"\x11" * 48) -> tuple[str, TdxQuoteVerificationResult]:
    """A synthetic TDX quote laid out like a real one, and the result an SDK verifier would return."""
    header = version.to_bytes(2, "little") + bytes(46)
    pre = b"\x02\x00" + (584).to_bytes(4, "little") if version == 5 else b""
    mrcfg = b"\x01" + hashlib.sha256(compose.encode()).digest() + bytes(15)
    body = bytearray(584)
    body[136:184] = mrtd
    body[184:232] = mrcfg
    for i, off in enumerate((328, 376, 424)):
        body[off:off + 48] = bytes([0x20 + i]) * 48
    body[472:520] = b"\x33" * 48
    body[520:584] = b"\x44" * 64
    q = header + pre + bytes(body)
    res = TdxQuoteVerificationResult(tcb_status="UpToDate", advisory_ids=(), debug_enabled=False,
                                     report_data=b"\x44" * 64, mr_config_id=mrcfg, rt_mr3=b"\x33" * 48)
    return q.hex(), res


def model_measurements(compose=None, acts=None, os_hash="9" * 64, td=TD):
    acts = actions(STARTED, up(SERVE, "f" * 64)) if acts is None else acts
    return measure("model", MODEL, deployment(compose, os_hash, acts), td)


# ---------------------------------------------------------------- quote parsing

@pytest.mark.parametrize("version", [4, 5])
def test_td_measurements_read_quote_fields(version):
    compose = app_compose()
    q, res = fake_quote(compose, version)
    m = pinning.td_measurements(bytes.fromhex(q))
    assert m["mrtd"] == "11" * 48 and m["rtmr0"] == "20" * 48 and m["rtmr2"] == "22" * 48
    assert m["mrconfigid"] == res.mr_config_id.hex() and m["rtmr3"] == res.rt_mr3.hex()


def test_td_measurements_reject_unknown_or_short_quotes():
    with pytest.raises(ValueError):
        pinning.td_measurements((3).to_bytes(2, "little") + bytes(700))
    with pytest.raises(ValueError):
        pinning.td_measurements((4).to_bytes(2, "little") + bytes(100))


def test_quote_log_keeps_measurements_by_compose_and_cross_checks():
    asyncio.run(_quote_log())


async def _quote_log():
    compose = app_compose()
    q, res = fake_quote(compose)
    log = pinning.QuoteLog(inner=lambda _q: res)
    assert await log(q) is res
    assert log.lookup(compose) == [{"mrtd": "11" * 48, "rtmr0": "20" * 48, "rtmr1": "21" * 48, "rtmr2": "22" * 48}]
    assert log.lookup(app_compose(label="other")) == []
    # A verifier result that does not match the bytes we parsed fails closed.
    bad = TdxQuoteVerificationResult(tcb_status="UpToDate", advisory_ids=(), debug_enabled=False,
                                     report_data=b"\x00" * 64, mr_config_id=res.mr_config_id, rt_mr3=res.rt_mr3)
    with pytest.raises(PinError):
        await pinning.QuoteLog(inner=lambda _q: bad)(q)


# ---------------------------------------------------------------- fingerprints

def test_instance_labels_and_the_known_per_instance_envs_do_not_change_the_fingerprint():
    a = model_measurements(app_compose(label="gpu02", envs=("A", "AWS_REGION", "AWS_ACCESS_KEY_ID")))[0]
    b = model_measurements(app_compose(label="gpu04", envs=("A",)))[0]
    assert a.fp == b.fp
    assert a.info["compose_hash"] != b.info["compose_hash"]      # the raw compose hash differs per instance
    assert a.info["allowed_envs_per_instance"] == ["AWS_ACCESS_KEY_ID", "AWS_REGION"]   # shown, not checked


@pytest.mark.parametrize("envs", [("A", "MODEL_DISCOVERY_SERVER_URL"), ("A", "COMPOSE_MANAGER_IMAGE"),
                                  ("A", "AWS_REGION_2"), ()])
def test_a_new_or_removed_allowed_env_changes_the_fingerprint(envs):
    """An allowed env is a value NEAR can inject at runtime unmeasured, so a new one needs a review."""
    base = model_measurements(app_compose(envs=("A",)))[0]
    assert model_measurements(app_compose(envs=envs))[0].fp != base.fp


def test_the_gateway_fingerprints_every_allowed_env():
    a = measure("gateway", None, deployment(app_compose(envs=("A",))), TD)[0]
    b = measure("gateway", None, deployment(app_compose(envs=("A", "AWS_REGION"))), TD)[0]
    assert a.fp != b.fp


def test_only_the_instance_label_line_is_masked():
    c = json.loads(app_compose())
    c["docker_compose_file"] = c["docker_compose_file"].replace("LOG_LEVEL=info", "HOST_IP=10.0.0.1")
    d = json.loads(json.dumps(c))
    d["docker_compose_file"] = d["docker_compose_file"].replace("HOST_IP=10.0.0.1", "HOST_IP=10.9.9.9")
    a = measure("gateway", None, deployment(json.dumps(c)), TD)[0]
    b = measure("gateway", None, deployment(json.dumps(d)), TD)[0]
    assert a.fp != b.fp


@pytest.mark.parametrize("change", [
    {"compose": app_compose(images=("nearaidev/cloud-api@sha256:" + "e" * 64,))},
    {"compose": app_compose(kms=False)},
    {"compose": app_compose(name="dstack-0.5.13")},
    {"os_hash": "8" * 64},
    {"td": [TD[0] | {"rtmr1": "5" * 96}]},
])
def test_code_changes_change_the_platform_fingerprint(change):
    base = model_measurements()[0]
    other = model_measurements(**change)[0]
    assert base.component == f"model/{MODEL}" and base.fp != other.fp


def test_compose_text_change_outside_images_changes_the_fingerprint():
    c = json.loads(app_compose())
    c["docker_compose_file"] = c["docker_compose_file"].replace("LOG_LEVEL=info", "ENTRYPOINT_URL=http://x")
    a = measure("gateway", None, deployment(app_compose()), TD)[0]
    b = measure("gateway", None, deployment(json.dumps(c)), TD)[0]
    assert a.fp != b.fp


def test_missing_quote_measurements_fail_closed():
    with pytest.raises(PinError):
        measure("gateway", None, deployment(), [])


def test_workload_reports_the_latest_compose_up():
    w = running_workload(actions(
        STARTED, up("prod/old.yaml", "1" * 64, ts="2026-10-01T00:00:00+00:00"),
        up(SERVE, "2" * 64, ts="2026-11-01T00:00:00+00:00"),
        up(SERVE, "3" * 64, ts="2026-11-02T00:00:00+00:00", services=["proxy"]),
        up(SERVE, "3" * 64, ts="2026-11-03T00:00:00+00:00", services=["dry"]),              # a dry run
        down(SERVE, ts="2026-11-04T00:00:00+00:00", services=["registrar"]),                  # one service
        up("prod/rotate-compose-manager-token.yaml", "4" * 64, ts="2026-11-05T00:00:00+00:00"),
        down("prod/rotate-compose-manager-token.yaml", ts="2026-11-05T00:00:05+00:00")))      # one-off job
    assert (w["file"], w["file_sha256"]) == (SERVE, "3" * 64)
    assert w["deployed_at"].startswith("2026-11-02")
    assert w["service_updates"] == {"proxy": "3" * 64, "registrar": "down"}
    assert w["compose_manager_image"] == STARTED["image"]
    assert w["standing"] == sorted([f"prod/old.yaml {'1' * 64}", f"{SERVE} {'3' * 64}"])
    assert running_workload(())["file"] is None and running_workload(())["standing"] == []


def test_every_compose_file_still_standing_is_in_the_workload_fingerprint():
    main = up(SERVE, "f" * 64, ts="2026-11-08T01:00:00+00:00")
    again = up(SERVE, "f" * 64, ts="2026-11-08T03:00:00+00:00")
    bench = up("experiments/bench.yaml", "b" * 64, ts="2026-11-08T02:00:00+00:00")
    plain = model_measurements(acts=actions(STARTED, main, again))[2]
    extra = model_measurements(acts=actions(STARTED, main, bench, again))[2]
    assert plain.fields != extra.fields and plain.fp != extra.fp      # a second file left running shows
    assert extra.info["file"] == SERVE                                # the newest deploy is still reported
    taken_down = model_measurements(acts=actions(STARTED, main, bench, down("experiments/bench.yaml"), again))[2]
    assert taken_down.fp == plain.fp                                  # brought up, then fully taken down
    one_off = model_measurements(acts=actions(STARTED, main, up("prod/rotate.yaml", "4" * 64, services=["rotate"]),
                                              down("prod/rotate.yaml", services=["rotate"]), again))[2]
    assert one_off.fp == plain.fp                                     # its only service was taken down
    half = model_measurements(acts=actions(STARTED, main, up("x.yaml", "4" * 64, services=["a", "b"]),
                                           down("x.yaml", services=["a"]), again))[2]
    assert half.fp != plain.fp                                        # one service is still up


def test_workload_change_is_its_own_component():
    a = model_measurements()
    b = model_measurements(acts=actions(STARTED, up(SERVE, "e" * 64, ts="2026-11-08T21:54:53+00:00")))
    assert [m.component for m in a] == [f"model/{MODEL}", f"model/{MODEL}/manager", f"model/{MODEL}/workload"]
    assert a[0].fp == b[0].fp and a[1].fp == b[1].fp and a[2].fp != b[2].fp
    assert b[2].deployed_at.startswith("2026-11-08T21")


def test_compose_manager_image_is_its_own_component():
    other = dict(STARTED, image="nearaidev/compose-manager@sha256:" + "c" * 64)
    a = model_measurements()
    b = model_measurements(acts=actions(other, up(SERVE, "f" * 64)))
    assert a[0].fp == b[0].fp and a[2].fp == b[2].fp and a[1].fp != b[1].fp


def test_each_quote_for_one_compose_is_fingerprinted_alone():
    """Two instances sharing one app-compose must not make a fingerprint depend on timing."""
    other = TD[0] | {"rtmr0": "8" * 96}
    one = model_measurements(td=TD)
    both = model_measurements(td=[other, TD[0], TD[0]])
    assert len(both) == 4 and [m.component for m in both[:2]] == [f"model/{MODEL}"] * 2
    assert one[0].fp in {m.fp for m in both[:2]}
    assert all(len(m.fields["td"]) == 1 for m in both[:2])


# ---------------------------------------------------------------- the pin store

def test_first_use_pins_then_same_passes_then_change_blocks_then_accept_unblocks(cfg):
    store = PinStore(cfg)
    first = model_measurements()
    assert [store.check(m, "q1")["status"] for m in first] == ["first_use"] * 3
    assert [store.check(m, "q2")["status"] for m in model_measurements()] == ["match"] * 3

    changed = model_measurements(acts=actions(STARTED, up(SERVE, "e" * 64, ts="2026-11-07T10:00:00+00:00")))
    assert store.check(changed[0], "q3")["status"] == "match"
    assert store.check(changed[1], "q3")["status"] == "match"
    with pytest.raises(PinError, match=r"NEAR changed its serving code on November 7, 2026; the owner must review"):
        store.check(changed[2], "q3")
    with pytest.raises(PinError):
        store.check(changed[2], "q4")                                 # still blocked, same review
    waiting = store.reviews("waiting")
    assert len(waiting) == 1 and waiting[0]["component"] == f"model/{MODEL}/workload"
    assert store.blocking_review(["gateway", f"model/{MODEL}"])["id"] == waiting[0]["id"]

    d = store.diff(waiting[0]["id"])
    assert {"field": "info.file_sha256", "before": "f" * 64, "after": "e" * 64} in [
        c | {"field": "info." + c["field"]} for c in d["info_changes"]]
    assert d["changes"][0]["field"] == "standing"

    store.decide(waiting[0]["id"], True, "dana")
    assert store.blocking_review() is None
    assert store.check(changed[2], "q5")["status"] == "match"
    assert store.check(first[2], "q6")["status"] == "match"          # the old version stays trusted

    events = [h["event"] for h in store.history()]
    assert events == ["pinned", "pinned", "pinned", "changed", "accepted"]
    assert store.verify_history()


def test_accept_only_drops_older_versions(cfg):
    store = PinStore(cfg)
    first = model_measurements()[2]
    store.check(first, "q1")
    new = model_measurements(acts=actions(STARTED, up(SERVE, "e" * 64)))[2]
    with pytest.raises(PinError):
        store.check(new, "q2")
    store.decide(store.reviews()[0]["id"], True, "dana", only=True)
    with pytest.raises(PinError, match="NEAR changed"):
        store.check(first, "q3")                                      # the old one needs a new review now
    assert len(store.reviews("waiting")) == 1


def test_reject_keeps_blocking_and_can_be_reversed(cfg):
    store = PinStore(cfg)
    store.check(model_measurements()[2], "q1")
    new = model_measurements(acts=actions(STARTED, up(SERVE, "e" * 64)))[2]
    with pytest.raises(PinError):
        store.check(new, "q2")
    rid = store.reviews()[0]["id"]
    store.decide(rid, False, "dana")
    assert store.blocking_review() is None                            # nothing waiting...
    with pytest.raises(PinError, match="code the owner rejected"):
        store.check(new, "q3")                                        # ...but that code is still refused
    assert store.check(model_measurements()[2], "q4")["status"] == "match"
    store.decide(rid, True, "dana")
    assert store.check(new, "q5")["status"] == "match"
    with pytest.raises(KeyError):
        store.decide(rid, True, "dana")                               # already decided
    with pytest.raises(KeyError):
        store.decide("../../etc", True, "dana")


def test_several_instances_seen_in_the_first_verification_are_all_pinned(cfg):
    store = PinStore(cfg)
    a = measure("gateway", None, deployment(), TD)[0]
    b = measure("gateway", None, deployment(), [TD[0] | {"mrtd": "7" * 96}])[0]
    assert store.check(a, "q1")["status"] == "first_use"
    assert store.check(b, "q1")["status"] == "same_run"
    c = measure("gateway", None, deployment(), [TD[0] | {"mrtd": "6" * 96}])[0]
    with pytest.raises(PinError):
        store.check(c, "q2")                                          # a later question: that is a change


def test_shipped_pins_replace_trust_on_first_use(cfg, tmp_path):
    m = measure("gateway", None, deployment(), TD)[0]
    shipped = tmp_path / "shipped.json"
    shipped.write_text(json.dumps({"version": 1, "components": {"gateway": [{"fields": m.fields}]}}))
    assert PinStore(cfg, shipped=shipped).check(m, "q1")["status"] == "shipped"

    other_cfg = config.load(cfg.home)
    shutil.rmtree(cfg.runtime)
    store = PinStore(other_cfg, shipped=shipped)
    different = measure("gateway", None, deployment(os_hash="1" * 64), TD)[0]
    with pytest.raises(PinError, match="NEAR changed"):
        store.check(different, "q1")                                  # not trusted on first use
    assert store.reviews()[0]["component"] == "gateway"


def test_damaged_or_deleted_pin_files_fail_closed(cfg, tmp_path):
    store = PinStore(cfg)
    store.check(model_measurements()[0], "q1")
    store.path.write_text("{not json")
    with pytest.raises(PinError, match="damaged"):
        store.check(model_measurements()[0], "q2")
    store.path.unlink()
    with pytest.raises(PinError, match="missing"):                    # history remembers there were pins
        store.check(model_measurements()[0], "q3")
    bad = tmp_path / "bad.json"
    bad.write_text("[]")
    shutil.rmtree(cfg.runtime)
    with pytest.raises(PinError, match="shipped"):
        PinStore(cfg, shipped=bad).check(model_measurements()[0], "q4")


def test_history_is_append_only_and_tamper_evident(cfg):
    store = PinStore(cfg)
    for m in model_measurements():
        store.check(m, "q1")
    assert store.verify_history() and len(store.history()) == 3
    assert store.load()["history"]["count"] == 3
    text = store.history_path.read_text()
    lines = text.splitlines()
    tampered = {
        "first entry removed": lines[1:],
        "an earlier entry edited": [lines[0].replace("pinned", "edited"), *lines[1:]],
        "the newest entry edited": [*lines[:-1], lines[-1].replace("pinned", "edited")],
        "the newest entry removed": lines[:-1],
        "the two newest removed": lines[:1],
        "everything removed": [],
    }
    for why, kept in tampered.items():
        store.history_path.write_text("".join(x + "\n" for x in kept))
        assert not store.verify_history(), why
    store.history_path.write_text(text)
    assert store.verify_history()
    data = store.load()
    del data["history"]                                               # removing the head from pins.json shows too
    store.save(data)
    assert not store.verify_history()
    assert oct(store.path.stat().st_mode & 0o777) == "0o600"


def test_a_damaged_history_line_is_reported_not_a_crash(cfg, monkeypatch, capsys):
    from familybox import cli
    monkeypatch.setenv("FAMILYBOX_HOME", str(cfg.home))
    store = PinStore(cfg)
    store.check(model_measurements()[0], "q1")
    with store.history_path.open("a") as f:
        f.write("{not json\n")
    assert len(store.history()) == 1 and not store.verify_history()
    assert cli.main(["pins", "show"]) == 0
    assert "chain intact: NO" in capsys.readouterr().out
    assert cli.main(["pins", "history"]) == 0
    assert "chain intact: NO" in capsys.readouterr().out
    admin, _ = sign_in(cfg, "dana")
    page = admin.get("/pins")
    assert page.status_code == 200 and "BROKEN" in page.text


def test_a_matching_check_does_not_rewrite_the_pin_file_every_time(cfg, monkeypatch):
    store = PinStore(cfg)
    for m in model_measurements():
        store.check(m, "q1")
    saves = []
    real = store.save
    monkeypatch.setattr(store, "save", lambda d: (saves.append(1), real(d)))
    for m in model_measurements():
        assert store.check(m, "q2")["status"] == "match"
    assert saves == []
    t = pinning.time.time()
    monkeypatch.setattr(pinning.time, "time", lambda: t + pinning.SAVE_EVERY_S + 1)
    assert store.check(model_measurements()[0], "q3")["status"] == "match"
    assert saves == [1]                                               # last_ok refreshed after a while


def test_levels(cfg, monkeypatch):
    store = PinStore(cfg)
    for m in model_measurements():
        store.check(m, "q1")
    new_workload = model_measurements(acts=actions(STARTED, up(SERVE, "e" * 64)))[2]
    monkeypatch.setenv("FAMILYBOX_PIN_LEVEL", "platform")
    assert PinStore(cfg).check(new_workload, "q2")["status"] == "changed_allowed"
    with pytest.raises(PinError):
        PinStore(cfg).check(model_measurements(os_hash="1" * 64)[0], "q3")
    new_manager = model_measurements(acts=actions(dict(STARTED, image="evil/compose-manager@sha256:" + "0" * 64),
                                                  up(SERVE, "f" * 64)))[1]
    with pytest.raises(PinError, match="NEAR changed"):
        PinStore(cfg).check(new_manager, "q4")                        # platform still stops a new manager
    assert f"model/{MODEL}/manager" in {r["component"] for r in PinStore(cfg).reviews("waiting")}
    monkeypatch.setenv("FAMILYBOX_PIN_LEVEL", "nonsense")
    assert PinStore(cfg).level == "strict"
    monkeypatch.delenv("FAMILYBOX_PIN_LEVEL")
    (cfg.home / "family.toml").write_text((cfg.home / "family.toml").read_text() + '\n[pins]\nlevel = "off"\n')
    assert PinStore(cfg).level == "off"


# ---------------------------------------------------------------- the box, end to end with a fake SDK client

class FakeSDK:
    """Stands in for nearai_inference_sdk.InferenceClient. verify() runs the verifiers the box passed,
    the way the SDK does: quote verifier, then the deployment callbacks; their errors get wrapped."""

    def __init__(self):
        self.gateway = deployment(app_compose(name="dstack-gw"))
        self.model = deployment(acts=actions(STARTED, up(SERVE, "f" * 64)))
        self.verifies = 0
        self.prompts = 0
        self.kwargs = None
        sdk = self

        class Client:
            def __init__(self, api_key, **kw):
                sdk.kwargs = kw
                self.kw = kw
                self.chat = types.SimpleNamespace(completions=types.SimpleNamespace(create=self.create))

            async def __aenter__(self):
                return self

            async def __aexit__(self, *a):
                return None

            async def _verify_one(self, dep, quote_verifier, callback):
                q, res = fake_quote(dep.app_compose)
                try:
                    if quote_verifier:
                        await quote_verifier(q)
                    if callback:
                        await callback(dep)
                except Exception as e:
                    raise RuntimeError("provenance.verification_failed") from e

            async def verify(self, model):
                sdk.verifies += 1
                gv = self.kw.get("gateway_verification")
                mv = self.kw.get("model_verification")
                policy = self.kw.get("deployment_policy")
                await self._verify_one(sdk.gateway, gv and gv.verifiers.tdx_quote, gv and gv.verifiers.deployment)
                await self._verify_one(sdk.model, mv and mv.verifiers.tdx_quote,
                                       policy and (lambda d: policy(model, d)))
                return types.SimpleNamespace(models=(object(),), verified_at=1)

            async def create(self, **kw):
                sdk.prompts += 1
                msg = types.SimpleNamespace(content="Your blood type is on file.", tool_calls=None)
                return types.SimpleNamespace(id="c1", choices=[types.SimpleNamespace(message=msg)], usage=None)

            async def verify_response(self, cid):
                return types.SimpleNamespace(signature_kind="provider_tee", signature=types.SimpleNamespace(
                    signer=types.SimpleNamespace(signing_address="0x" + "ab" * 20)))

        self.Client = Client


@pytest.fixture
def fake_sdk(monkeypatch):
    import nearai_inference_sdk
    sdk = FakeSDK()
    monkeypatch.setattr(nearai_inference_sdk, "InferenceClient", sdk.Client)

    def fake_dcap(q: str) -> TdxQuoteVerificationResult:   # what the real Intel check returns for a good quote
        m = pinning.td_measurements(bytes.fromhex(q))
        return TdxQuoteVerificationResult(tcb_status="UpToDate", advisory_ids=(), debug_enabled=False,
                                          report_data=bytes.fromhex(m["report_data"]),
                                          mr_config_id=bytes.fromhex(m["mrconfigid"]),
                                          rt_mr3=bytes.fromhex(m["rtmr3"]))
    monkeypatch.setattr("nearai_inference_sdk.utils.intel.verify_dcap_quote", fake_dcap)
    monkeypatch.setenv("NEAR_AI_CLOUD_API_KEY", "test-not-a-key")
    return sdk


def events(cfg, ans):
    path = cfg.runtime / "events" / ans.person / f"{ans.qid}.jsonl"
    return [json.loads(line) for line in path.read_text().splitlines()]


def test_box_pins_on_first_question_and_blocks_a_change_before_any_prompt(cfg, fake_sdk):
    box = Box(cfg, mode="live")
    a1 = box.ask("maya", "What is my blood type?")
    assert a1.outcome != "error", a1.text
    assert fake_sdk.kwargs["deployment_policy"] and fake_sdk.kwargs["gateway_verification"]
    pin_events = [e for e in events(cfg, a1) if e["step"] == "pinning"]
    assert {e["component"]: e["status"] for e in pin_events} == {
        "gateway": "first_use", f"model/{MODEL}": "first_use", f"model/{MODEL}/manager": "first_use",
        f"model/{MODEL}/workload": "first_use"}
    assert box.ask("maya", "What is my blood type?").outcome != "error"

    # NEAR redeploys the model's serving code.
    fake_sdk.model = deployment(acts=actions(STARTED, up(SERVE, "e" * 64, ts="2026-11-08T21:54:53+00:00")))
    prompts = fake_sdk.prompts
    a3 = box.ask("maya", "What is my blood type?", source="mcp-remote")
    assert a3.outcome == "error"
    assert "NEAR changed its serving code on November 8, 2026; the owner must review" in a3.text
    assert fake_sdk.prompts == prompts                                # the question never reached the model
    audit = [json.loads(x) for x in (cfg.runtime / "audit" / "maya.jsonl").read_text().splitlines()]
    assert audit[-1]["outcome"] == "error" and "NEAR changed" in audit[-1]["reasons"][0]

    # While the review waits, the pre-check stops questions without even contacting NEAR.
    verifies = fake_sdk.verifies
    a4 = box.ask("sam", "When is my W-2 due?")
    assert a4.outcome == "error" and "owner must review" in a4.text
    assert fake_sdk.verifies == verifies
    assert any(e["step"] == "pre_check_stopped" for e in events(cfg, a4))

    PinStore(cfg).decide(PinStore(cfg).reviews()[0]["id"], True, "dana")
    assert box.ask("maya", "What is my blood type?").outcome != "error"


def test_replay_mode_skips_pinning(cfg, fake_sdk):
    store = PinStore(cfg)
    store.check(model_measurements()[2], "q1")
    with pytest.raises(PinError):
        store.check(model_measurements(acts=actions(STARTED, up(SERVE, "e" * 64)))[2], "q2")
    ans = Box(cfg, mode="replay").ask("maya", "What is my blood type?")
    assert "owner must review" not in ans.text
    assert not any(e["step"] in ("pinning", "pre_check_stopped") for e in events(cfg, ans))
    assert fake_sdk.verifies == 0


def test_plugins_cannot_change_locked_enclave_settings(cfg, fake_sdk):
    box = Box(cfg, mode="live")
    box.client_options.append(lambda b, p, c: {"e2ee": False})
    ans = box.ask("maya", "What is my blood type?")
    assert ans.outcome == "error" and "locked enclave settings: e2ee" in ans.text
    assert fake_sdk.prompts == 0


def test_two_hooks_setting_one_option_fail_closed(cfg, fake_sdk):
    box = Box(cfg, mode="live")
    box.client_options.append(lambda b, p, c: {"deployment_policy": None})
    ans = box.ask("maya", "What is my blood type?")
    assert ans.outcome == "error" and "same enclave option" in ans.text and fake_sdk.prompts == 0


def test_level_off_turns_pinning_off(cfg, fake_sdk, monkeypatch):
    monkeypatch.setenv("FAMILYBOX_PIN_LEVEL", "off")
    Box(cfg, mode="live").ask("maya", "What is my blood type?")
    assert "deployment_policy" not in fake_sdk.kwargs
    assert not PinStore(cfg).path.exists()


def test_check_now_reports_a_change_without_raising(cfg, fake_sdk):
    first = asyncio.run(pinning.check_now(cfg))
    assert [r["status"] for r in first] == ["first_use"] * 4
    fake_sdk.gateway = deployment(app_compose(name="dstack-gw", images=("evil@sha256:" + "0" * 64,)))
    second = asyncio.run(pinning.check_now(cfg))
    assert second[0]["component"] == "gateway" and second[0]["status"] == "changed"


# ---------------------------------------------------------------- CLI and web page

def make_review(cfg) -> str:
    store = PinStore(cfg)
    store.check(model_measurements()[2], "q1")
    with pytest.raises(PinError):
        store.check(model_measurements(acts=actions(STARTED, up(SERVE, "e" * 64)))[2], "q2")
    return store.reviews()[0]["id"]


def test_cli_show_diff_accept(cfg, monkeypatch, capsys):
    from familybox import cli
    monkeypatch.setenv("FAMILYBOX_HOME", str(cfg.home))
    rid = make_review(cfg)
    assert cli.main(["pins", "show"]) == 0
    out = capsys.readouterr().out
    assert "waiting for the owner: 1" in out and rid in out and "chain intact: yes" in out
    assert cli.main(["pins", "diff", rid]) == 0
    assert "standing" in capsys.readouterr().out
    assert cli.main(["pins", "accept", "--as", "maya", rid]) == 2      # not the admin
    assert cli.main(["pins", "accept", "--as", "dana", "all"]) == 0
    assert f"accepted {rid}" in capsys.readouterr().out
    assert cli.main(["pins", "history"]) == 0
    assert "accepted" in capsys.readouterr().out
    assert cli.main(["pins", "diff", "nope"]) == 2
    assert "no such review" in capsys.readouterr().out
    assert cli.main(["pins", "export", "--platform-only"]) == 0
    assert json.loads(capsys.readouterr().out)["components"] == {}


def sign_in(cfg, person):
    c = TestClient(web.create_app(cfg), base_url="https://testserver")
    tok = re.search(r'name="csrf" value="([^"]+)"', c.get("/signin").text).group(1)
    r = c.post("/signin", data={"code": web.issue_code(cfg, person), "csrf": tok}, follow_redirects=False)
    assert r.status_code == 303
    home = c.get("/")
    return c, re.search(r'name="csrf" value="([^"]+)"', home.text).group(1)


def test_web_page_shows_the_change_and_only_the_admin_decides(cfg):
    rid = make_review(cfg)
    kid, ktok = sign_in(cfg, "maya")
    page = kid.get("/pins")
    assert page.status_code == 200 and 'href="/pins"' in page.text
    assert "NEAR changed its serving code" in page.text and "Only Dana can review this" in page.text
    assert "Trust the new code" not in page.text
    assert kid.post(f"/pins/{rid}/accept", data={"csrf": ktok}).status_code == 403
    assert PinStore(cfg).reviews("waiting")

    admin, atok = sign_in(cfg, "dana")
    page = admin.get("/pins")
    assert "Trust the new code" in page.text and "standing" in page.text and "—" not in page.text
    assert admin.post(f"/pins/{rid}/accept", data={"csrf": "wrong"}).status_code == 403
    assert admin.post(f"/pins/{rid}/delete", data={"csrf": atok}).status_code == 404
    r = admin.post(f"/pins/{rid}/accept", data={"csrf": atok})
    assert r.status_code == 200 and "will answer again" in r.text
    assert not PinStore(cfg).reviews("waiting")
    assert admin.post(f"/pins/{rid}/accept", data={"csrf": atok}).status_code == 404
    assert TestClient(web.create_app(cfg), base_url="https://testserver").get(
        "/pins", follow_redirects=False).status_code == 303          # signed out


def test_plugin_registers_its_hooks(cfg):
    box = Box(cfg, mode="replay")
    assert plugin.pre_check in box.pre_checks and plugin.client_options in box.client_options


def test_shipped_pins_file_matches_its_own_fingerprints():
    data = json.loads((Path(__file__).resolve().parents[1] / "pins" / "near-ai-cloud.json").read_text())
    assert set(data["components"]) == {"gateway", f"model/{MODEL}", f"model/{MODEL}/manager"}
    for name, entries in data["components"].items():
        for e in entries:
            assert pinning.fingerprint_of(e["fields"]) == e["fp"]
            if not name.endswith("/manager"):
                assert all(len(t["mrtd"]) == 96 for t in e["fields"]["td"]) and len(e["fields"]["td"]) == 1
                assert "allowed_envs" in e["fields"]
    assert "—" not in json.dumps(data)


def test_shipped_pins_are_rebuilt_from_the_committed_raw_captures(capsys):
    """The stable-versus-per-instance table in BUILD_LOG can be checked from spikes/captures."""
    import runpy
    root = Path(__file__).resolve().parents[1]
    runpy.run_path(str(root / "spikes" / "pin_stability.py"), run_name="not_main")["main"]()
    out = capsys.readouterr().out
    shipped = json.loads((root / "pins" / "near-ai-cloud.json").read_text())["components"]
    for name, entries in shipped.items():
        assert f"att3  {name:<55} {entries[0]['fp'][:16]}" in out


def test_measured_dataclass_fp_is_stable():
    m = Measured("gateway", {"b": 1, "a": [1, 2]})
    assert m.fp == Measured("gateway", {"a": [1, 2], "b": 1}).fp


def test_a_quote_that_fails_the_intel_check_stops_the_question(cfg, fake_sdk, monkeypatch):
    def reject(q):
        raise RuntimeError("bad quote")
    monkeypatch.setattr("nearai_inference_sdk.utils.intel.verify_dcap_quote", reject)
    ans = Box(cfg, mode="live").ask("maya", "What is my blood type?")
    assert ans.outcome == "error" and fake_sdk.prompts == 0
    assert not PinStore(cfg).path.exists()                            # nothing unverified was ever pinned


def test_a_pinning_plugin_that_did_not_load_stops_live_questions(cfg, fake_sdk, monkeypatch):
    from familybox import plugins
    real = plugins.load_plugins
    monkeypatch.setattr(plugins, "load_plugins", lambda: [m for m in real() if m.__name__ != plugin.__name__])
    box = Box(cfg, mode="live")
    assert plugin.client_options not in box.client_options
    ans = box.ask("maya", "What is my blood type?")
    assert ans.outcome == "error" and "the NEAR code check did not load" in ans.text
    assert fake_sdk.prompts == 0 and fake_sdk.verifies == 0
    monkeypatch.setenv("FAMILYBOX_PIN_LEVEL", "off")                  # the owner turned pinning off on purpose
    assert Box(cfg, mode="live").ask("maya", "What is my blood type?").outcome != "error"


def test_the_box_needs_pinning_even_with_no_pins_yet(cfg, fake_sdk, monkeypatch, tmp_path):
    from familybox import box as box_mod
    from familybox import plugins
    monkeypatch.setattr(plugins, "load_plugins", lambda: [])
    monkeypatch.setenv("FAMILYBOX_PARAPHRASE_CHECK", "off")          # this test is about the pinning guard only
    assert not (cfg.runtime / "pins.json").exists()
    assert Box(cfg, mode="live").ask("maya", "What is my blood type?").outcome == "error"   # repo ships pins
    monkeypatch.setattr(box_mod, "REPO_PINS", tmp_path / "none.json")
    assert Box(cfg, mode="live").ask("maya", "What is my blood type?").outcome != "error"   # nothing to guard


def test_pins_check_reports_network_trouble_plainly(cfg, monkeypatch, capsys):
    from familybox import cli

    async def boom(*a, **k):
        raise OSError("network is unreachable")
    monkeypatch.setenv("FAMILYBOX_HOME", str(cfg.home))
    monkeypatch.setattr(pinning, "check_now", boom)
    assert cli.main(["pins", "check"]) == 1
    err = capsys.readouterr().err
    assert "could not check NEAR right now" in err and "Traceback" not in err


def test_a_second_privacy_check_that_did_not_load_stops_live_questions(cfg, fake_sdk, monkeypatch):
    from familybox import plugins
    real = plugins.load_plugins
    monkeypatch.setattr(plugins, "load_plugins",
                        lambda: [m for m in real() if not m.__name__.endswith(".paraphrase")])
    ans = Box(cfg, mode="live").ask("maya", "What is my blood type?")
    assert ans.outcome == "error" and "second privacy check did not load" in ans.text
    assert fake_sdk.prompts == 0
    monkeypatch.setenv("FAMILYBOX_PARAPHRASE_CHECK", "off")          # the owner turned it off on purpose
    assert Box(cfg, mode="live").ask("maya", "What is my blood type?").outcome != "error"
