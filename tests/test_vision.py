"""Photo transcription: both copies kept, the enclave call fails closed, the gate covers the transcript.

The enclave is mocked here. tests/test_vision_live.py makes one real call when a key is set.
"""

import asyncio
import hashlib
import io
import json
import re
import shutil
import stat
import struct
import sys
import types
import zlib
from pathlib import Path

import pytest
from PIL import Image
from starlette.testclient import TestClient

from familybox import cli, config, enclave, vision, web
from familybox.box import Box
from familybox.plugins import photos
from familybox.store import Store

ROOT = Path(__file__).resolve().parents[1]
DEMO = ROOT / "demo"
sys.path.insert(0, str(ROOT / "scripts"))
import make_photo_fixtures  # noqa: E402

SSN_TEXT = """SOCIAL SECURITY (SAMPLE)
THIS NUMBER HAS BEEN ESTABLISHED FOR
987-65-4329
JORDAN OKAFOR
Fields:
Document type: Social Security card
Name: JORDAN OKAFOR
SSN: 987-65-4329"""
CARD_TEXT = """BLUE PINE HEALTH (FICTIONAL)
Fields:
- **Member ID:** BPF 5530 2178
- Group #: 77120"""


@pytest.fixture
def cfg(tmp_path, monkeypatch):
    home = tmp_path / "home"
    shutil.copytree(DEMO / "files", home / "files")
    shutil.copy(DEMO / "family.toml", home / "family.toml")
    monkeypatch.delenv("NEARAI_API_KEY", raising=False)
    monkeypatch.delenv("FAMILYBOX_VISION_MODEL", raising=False)
    monkeypatch.setenv("NEAR_AI_CLOUD_API_KEY", "test-key-not-real")
    c = config.load(home)
    Store(c).reindex()
    return c


@pytest.fixture(scope="session")
def pics(tmp_path_factory):
    out = tmp_path_factory.mktemp("pics")
    return {p.name: p.read_bytes() for p in make_photo_fixtures.main(out)}


class FakeEnclave:
    """Stands in for transcribe_live. Records what it was sent."""

    def __init__(self, text=SSN_TEXT, signature_kind="provider_tee", error=None):
        self.text, self.signature_kind, self.error = text, signature_kind, error
        self.calls = []

    async def __call__(self, prep, *, api_key, model, emit=None, attestation_max_age_s=300):
        self.calls.append({"prep": prep, "model": model, "api_key": api_key})
        if emit:
            emit("attestation", model=model, reports_verified=1, verified_at=1, seconds=0.1, e2ee=True,
                 replayed=False)
        if self.error:
            raise enclave.EnclaveError(self.error)
        if emit:
            emit("turn", index=0, seconds=0.1, signature_kind=self.signature_kind, signer="0xabcdef0123...",
                 tool_calls=[], replayed=False)
        return vision.Transcription(self.text, model, "0xabcdef0123456789abcdef", self.signature_kind, 0.1,
                                    {"model_reports_verified": 1}, 10, 20)


@pytest.fixture
def fake(monkeypatch):
    def use(**kw):
        f = FakeEnclave(**kw)
        monkeypatch.setattr(vision, "TRANSCRIBER", [f])
        return f
    return use


def add(cfg, person, folder, name, data, **kw):
    return asyncio.run(vision.add_photo(cfg, cfg.person(person), folder, name, data, **kw))


def png_header_only(w: int, h: int) -> bytes:
    """A PNG whose header claims w x h pixels (no real image data needed to read the size)."""
    def chunk(kind: bytes, body: bytes) -> bytes:
        return struct.pack(">I", len(body)) + kind + body + struct.pack(">I", zlib.crc32(kind + body) & 0xFFFFFFFF)
    return (b"\x89PNG\r\n\x1a\n" + chunk(b"IHDR", struct.pack(">IIBBBBB", w, h, 8, 2, 0, 0, 0))
            + chunk(b"IDAT", zlib.compress(b"\x00" * 64)) + chunk(b"IEND", b""))


# --- the photo itself ------------------------------------------------------------------------------

def test_fixtures_are_fictional_and_use_the_reserved_ssn():
    text = json.dumps(make_photo_fixtures.CARDS)
    assert "987-65-4329" in text and "FICTIONAL" in text.upper()
    assert set(re.findall(r"\d{3}-\d{2}-\d{4}", text)) <= {f"987-65-432{i}" for i in range(10)}


@pytest.mark.parametrize("name,data,msg", [
    ("a.gif", b"GIF89a....", "isn't a photo type"),
    ("a.heic", b"\x00\x00\x00\x18ftypheic", "HEIC"),
    ("a.jpg", b"\x00\x00\x00\x18ftypheic" + b"\x00" * 20, "HEIC"),
    ("a.png", b"", "empty"),
    ("a.png", b"\xff\xd8\xff\xe0 jpeg bytes", "doesn't look like a real photo"),
    ("a.jpg", b"%PDF-1.7", "doesn't look like a real photo"),
])
def test_check_photo_rejects(name, data, msg):
    with pytest.raises(vision.PhotoError, match=msg):
        vision.check_photo(Path(name).suffix, data)


def test_check_photo_size_limit(monkeypatch):
    monkeypatch.setattr(vision, "MAX_PHOTO_BYTES", 100)
    with pytest.raises(vision.PhotoError, match="too big"):
        vision.check_photo(".png", b"\x89PNG\r\n\x1a\n" + b"\x00" * 200)


def test_prepare_drops_location_data_and_turns_upright():
    im = Image.new("RGB", (400, 200), "white")
    exif = Image.Exif()
    exif[0x0112] = 6                                  # orientation: rotate 90 degrees
    exif[0x010F] = "FICTIONAL CAMERA"
    gps = exif.get_ifd(0x8825)
    gps[1], gps[2] = "N", (40.0, 44.0, 54.0)           # a GPS position
    buf = io.BytesIO()
    im.save(buf, "JPEG", exif=exif)
    assert b"FICTIONAL CAMERA" in buf.getvalue()

    prep = vision.prepare(buf.getvalue())
    assert prep.mime == "image/jpeg" and prep.data.startswith(b"\xff\xd8\xff")
    assert b"FICTIONAL CAMERA" not in prep.data and b"Exif" not in prep.data
    sent = Image.open(io.BytesIO(prep.data))
    assert not sent.getexif()
    assert (sent.width, sent.height) == (200, 400)     # rotated upright


def test_prepare_shrinks_big_photos_and_flattens_transparency():
    im = Image.new("RGBA", (3200, 1600), (0, 0, 0, 0))
    buf = io.BytesIO()
    im.save(buf, "PNG")
    prep = vision.prepare(buf.getvalue())
    assert max(prep.width, prep.height) == vision.MAX_SIDE_SENT
    assert (prep.original_width, prep.original_height) == (3200, 1600)
    assert Image.open(io.BytesIO(prep.data)).getpixel((5, 5)) == (255, 255, 255)


def test_prepare_refuses_huge_or_broken_images():
    with pytest.raises(vision.PhotoError, match="too large or too small"):
        vision.prepare(png_header_only(20000, 20000))     # never decoded
    with pytest.raises(vision.PhotoError, match="too large or too small"):
        vision.prepare(png_header_only(8000, 8000))       # over our limit, under Pillow's own
    with pytest.raises(vision.PhotoError, match="too large or too small"):
        vision.prepare(png_header_only(4, 4))
    with pytest.raises(vision.PhotoError, match="couldn't be opened"):
        vision.prepare(b"\x89PNG\r\n\x1a\nnot really a png")


# --- turning model text into labeled lines -------------------------------------------------------

def test_canonical_rewrites_labels_the_store_recognizes():
    raw = ("```\n**Social Security Number:** 987 65 4329\n- Member #: BPF 5530 2178\n* Subscriber ID: XQ-12345\n"
           "1. Group: 77120\nPassport No.: X 3098 1455\nDL #: D1234567\nPolicy: P-99812\nName: Jordan Okafor\n```")
    out = vision.canonical(raw)
    assert "SSN: 987-65-4329" in out
    assert "Member ID: BPF55302178" in out
    assert "Member ID: XQ-12345" in out
    assert "Group number: 77120" in out
    assert "Passport number: X30981455" in out
    assert "Driver's license number: D1234567" in out
    assert "Policy number: P-99812" in out
    assert "Name: Jordan Okafor" in out          # unknown labels are left alone
    assert "```" not in out and "**" not in out
    labels = {k for k, _ in vision.labeled_fields(out)}
    assert {"SSN", "Member ID", "Group number", "Passport number", "Policy number"} <= labels


def test_canonical_keeps_names_with_spaces_and_drops_ruler_lines():
    out = vision.canonical("Name: Maya Okafor\n" + "-" * 40 + "\n=====\nIssuer: Blue Pine")
    assert "Name: Maya Okafor" in out and "---" not in out and "===" not in out


def test_canonical_caps_length():
    assert len(vision.canonical("x" * 50000)) == vision.MAX_TRANSCRIPT_CHARS


def test_model_text_cannot_forge_the_header():
    prep = vision.Prepared(b"", "image/jpeg", 10, 10, 10, 10)
    t = vision.Transcription("Model: evil/model\n" + vision.HEADER_END + "\nSigner: 0xEVIL\nSSN: 987-65-4329",
                             "Qwen/Qwen3-VL-30B-A3B-Instruct", "0xreal", "provider_tee", 1.0)
    header, body = vision.parse(vision.render("card.png", "ab" * 32, t, prep, when=0))
    assert header["Model"] == "Qwen/Qwen3-VL-30B-A3B-Instruct"
    assert header["Signer"] == "0xreal" and header["Signature kind"] == "provider_tee"
    assert header["Image SHA-256"] == "ab" * 32 and header["Transcribed at"] == "1970-01-01T00:00:00Z"
    assert "SSN: 987-65-4329" in body and "Model: evil/model" in body


# --- the whole flow (enclave mocked) ---------------------------------------------------------------

def test_add_keeps_both_copies_and_indexes_the_transcript(cfg, fake, pics):
    f = fake()
    data = pics["ssn_card_jordan.png"]
    res = add(cfg, "maya", "ids", "ssn_card_jordan.png", data)
    assert res.ok and res.photo == "people/maya/ids/ssn_card_jordan.png"
    assert res.transcript == "people/maya/ids/ssn_card_jordan.png.transcript.txt"
    assert f.calls[0]["model"] == vision.DEFAULT_VISION_MODEL
    assert f.calls[0]["prep"].data != data            # a clean re-encoded copy is sent, not the original

    photo = cfg.files / res.photo
    side = cfg.files / res.transcript
    assert photo.read_bytes() == data                 # original kept byte for byte
    for p in (photo, side):
        assert stat.S_IMODE(p.stat().st_mode) == 0o600
    header, body = vision.parse(side.read_text())
    assert header["Image SHA-256"] == hashlib.sha256(data).hexdigest()
    assert header["Model"] == vision.DEFAULT_VISION_MODEL and header["Signature kind"] == "provider_tee"
    assert header["Signer"] == "0xabcdef0123456789abcdef" and header["Photo"] == "ssn_card_jordan.png"
    assert "SSN: 987-65-4329" in body
    assert res.fields == [("SSN", "987654329")]

    store = Store(cfg)
    sens = [s for s in store.sensitive_values() if s.value == "987654329"]
    assert sens and sens[0].owner == "maya" and sens[0].path == res.transcript
    hits = store.search(cfg.person("maya"), "Jordan Okafor social security")
    assert any(h.get("photo") == res.photo and h["path"] == res.transcript for h in hits)
    # Reading the photo gives its transcript, never the image bytes.
    assert "987-65-4329" in store.read(cfg.person("maya"), res.photo)
    # Sam's also_reads covers Maya's ids folder, so he may get the text (and the gate still guards it).
    assert "987-65-4329" in store.read(cfg.person("sam"), res.photo)


def test_reading_a_photo_without_transcript_gives_nothing(cfg):
    (cfg.files / "people/maya/ids").mkdir(parents=True, exist_ok=True)
    (cfg.files / "people/maya/ids/raw.png").write_bytes(b"\x89PNG\r\n\x1a\nbinary")
    assert Store(cfg).read(cfg.person("maya"), "people/maya/ids/raw.png") is None


def test_events_and_audit_never_hold_the_values(cfg, fake, pics):
    fake()
    res = add(cfg, "maya", "ids", "ssn.png", pics["ssn_card_jordan.png"])
    ev = [json.loads(x) for x in (cfg.runtime / "events/maya" / f"{res.qid}.jsonl").read_text().splitlines()]
    assert [e["step"] for e in ev] == ["photo", "attestation", "turn", "transcript"]
    audit = (cfg.runtime / "audit/maya.jsonl").read_text()
    assert '"photo_upload"' in audit and '"photo_transcribe"' in audit
    for blob in (json.dumps(ev), audit):
        assert "4329" not in blob and "JORDAN" not in blob.upper()


@pytest.mark.parametrize("kw,why", [
    ({"error": "policy.model_attestation_required"}, "policy.model_attestation_required"),
    ({"signature_kind": "gateway"}, "not provider_tee"),
    ({"text": "  \n```\n```"}, "no text"),
])
def test_enclave_failures_keep_the_photo_and_index_nothing(cfg, fake, pics, kw, why):
    fake(**kw)
    res = add(cfg, "maya", "ids", "ssn.png", pics["ssn_card_jordan.png"])
    assert not res.ok and why in res.error and res.transcript is None
    assert (cfg.files / res.photo).is_file()
    assert not vision.transcript_path(cfg.files / res.photo).exists()
    assert not [s for s in Store(cfg).sensitive_values() if s.value == "987654329"]
    assert '"ok": false' in (cfg.runtime / "audit/maya.jsonl").read_text()


def test_no_key_means_nothing_is_sent(cfg, fake, pics, monkeypatch):
    f = fake()
    monkeypatch.delenv("NEAR_AI_CLOUD_API_KEY")
    res = add(cfg, "maya", "ids", "ssn.png", pics["ssn_card_jordan.png"])
    assert not res.ok and "not set" in res.error and f.calls == []


def test_retry_after_failure_writes_the_transcript(cfg, fake, pics):
    fake(error="boom")
    res = add(cfg, "maya", "ids", "ssn.png", pics["ssn_card_jordan.png"])
    fake()
    again = asyncio.run(vision.transcribe_photo(cfg, cfg.person("maya"), res.photo))
    assert again.ok and (cfg.files / again.transcript).is_file()


def test_names_never_overwrite_and_never_reuse_someone_elses_transcript(cfg, fake, pics):
    fake()
    first = add(cfg, "maya", "ids", "card.png", pics["ssn_card_jordan.png"])
    second = add(cfg, "maya", "ids", "card.png", pics["ssn_card_jordan.png"])
    assert (first.photo, second.photo) == ("people/maya/ids/card.png", "people/maya/ids/card-1.png")
    # A stray transcript file already sitting where card-2.png's would go: the photo gets another name.
    (cfg.files / "people/maya/ids/card-2.png.transcript.txt").write_text("SSN: 987-65-4320")
    third = add(cfg, "maya", "ids", "card.png", pics["ssn_card_jordan.png"])
    assert third.photo == "people/maya/ids/card-3.png"


@pytest.mark.parametrize("raw,clean", [
    ("../../etc/passwd.png", "passwd.png"),
    ("card.png.transcript.png", "card.png.png"),
    (".hidden.JPG", "hidden.jpg"),
    ("my  card!!.jpeg", "my_card.jpeg"),
])
def test_safe_photo_name(raw, clean):
    assert vision.safe_photo_name(raw) == clean


def test_bad_folder_and_others_photos(cfg, fake, pics):
    fake()
    with pytest.raises(vision.PhotoError, match="Pick one"):
        add(cfg, "maya", "../dana", "x.png", pics["ssn_card_jordan.png"])
    res = add(cfg, "dana", "ids", "p.jpg", pics["passport_page_dana.jpg"])
    with pytest.raises(vision.PhotoError, match="only read your own"):
        asyncio.run(vision.transcribe_photo(cfg, cfg.person("maya"), res.photo))
    # Dana's also_reads covers Maya's ids folder for answers, but the original photo is Maya's alone.
    m = add(cfg, "maya", "ids", "s.png", pics["ssn_card_jordan.png"])
    assert vision.can_view(cfg.person("maya"), m.photo)
    assert not vision.can_view(cfg.person("dana"), m.photo)
    assert vision.can_view(cfg.person("sam"), "shared/insurance/card.png")
    assert not vision.can_view(cfg.person("sam"), "shared/../people/maya/ids/s.png")


def test_transcript_mismatch_is_detected(cfg, fake, pics):
    fake()
    res = add(cfg, "maya", "ids", "s.png", pics["ssn_card_jordan.png"])
    assert vision.info(cfg, res.photo).matches
    (cfg.files / res.photo).write_bytes(pics["insurance_card_maya.png"])
    assert not vision.info(cfg, res.photo).matches


def test_remove_deletes_both(cfg, fake, pics):
    fake()
    res = add(cfg, "maya", "ids", "s.png", pics["ssn_card_jordan.png"])
    with pytest.raises(vision.PhotoError):
        vision.remove_photo(cfg, cfg.person("sam"), res.photo)
    vision.remove_photo(cfg, cfg.person("maya"), res.photo)
    assert not (cfg.files / res.photo).exists() and not (cfg.files / res.transcript).exists()
    assert not [s for s in Store(cfg).sensitive_values() if s.value == "987654329"]


def test_vision_model_setting(cfg, monkeypatch):
    assert vision.vision_model(cfg) == vision.DEFAULT_VISION_MODEL
    toml = (cfg.home / "family.toml").read_text().replace("[box]", '[box]\nvision_model = "z-ai/glm-5.3-flash"')
    (cfg.home / "family.toml").write_text(toml)
    assert vision.vision_model(cfg) == "z-ai/glm-5.3-flash"
    monkeypatch.setenv("FAMILYBOX_VISION_MODEL", "other/model")
    assert vision.vision_model(cfg) == "other/model"


# --- the gate covers numbers printed on the card ----------------------------------------------------

def write_replay(replay_dir: Path, person: str, question: str, answer: str, tool_calls: list) -> None:
    replay_dir.mkdir(parents=True, exist_ok=True)
    turn = {"seconds": 0.1, "signature_kind": "provider_tee", "signer": "0x1234567890abcdef"}
    rec = {"answer": answer, "model": "test/model", "tokens_in": 1, "tokens_out": 1,
           "attestation": {"model_reports_verified": 1, "verified_at_ms": 1, "seconds": 0.1, "e2ee": True},
           "turns": [turn | {"tool_calls": tool_calls, "content": None},
                     turn | {"tool_calls": [], "content": answer}]}
    (replay_dir / f"{enclave.replay_key(person, question)}.json").write_text(json.dumps(rec))


def test_gate_holds_a_number_read_from_a_photo(cfg, fake, pics, tmp_path):
    fake(text=CARD_TEXT)
    res = add(cfg, "maya", "other", "card.png", pics["insurance_card_maya.png"])
    q = "what's my member id?"
    write_replay(tmp_path / "r", "maya", q, "Your member ID is BPF 5530 2178.",
                 [["read_file", json.dumps({"path": res.photo})]])
    ans = Box(cfg, mode="replay", replay_dir=tmp_path / "r").ask("maya", q)
    assert ans.outcome == "held" and "5530" not in ans.text
    assert ans.files_read == [res.photo] and ans.held_ids


def test_gate_refuses_another_persons_photo_number(cfg, fake, pics, tmp_path):
    fake()
    assert add(cfg, "dana", "health", "ssn.png", pics["ssn_card_jordan.png"]).ok
    q = "what is the number on mom's card?"
    write_replay(tmp_path / "r", "maya", q, "It is 987-65-4329.", [])
    ans = Box(cfg, mode="replay", replay_dir=tmp_path / "r").ask("maya", q)
    assert ans.outcome == "refused" and "4329" not in ans.text
    assert Store(cfg).read(cfg.person("maya"), "people/dana/health/ssn.png") is None
    assert any("another person's ssn" in r for r in ans.reasons)


# --- transcribe_live with a mocked SDK client --------------------------------------------------------

class _Obj(types.SimpleNamespace):
    pass


def make_sdk(monkeypatch, *, models=(1,), signature_kind="provider_tee", content="SSN: 987-65-4329"):
    seen = {"created": [], "init": []}

    class Client:
        def __init__(self, key, **kw):
            seen["init"].append(kw)
            self.chat = _Obj(completions=_Obj(create=self._create))

        async def __aenter__(self):
            return self

        async def __aexit__(self, *a):
            return False

        async def verify(self, model):
            return _Obj(models=list(models), verified_at=123)

        async def _create(self, **kw):
            seen["created"].append(kw)
            return _Obj(id="c1", usage=_Obj(prompt_tokens=5, completion_tokens=7),
                        choices=[_Obj(message=_Obj(content=content, tool_calls=None))])

        async def verify_response(self, cid):
            return _Obj(signature_kind=signature_kind, signature=_Obj(signer=_Obj(signing_address="0xfeedbeef00")))

    import nearai_inference_sdk
    monkeypatch.setattr(nearai_inference_sdk, "InferenceClient", Client)
    return seen


def _prep(pics):
    return vision.prepare(pics["ssn_card_jordan.png"])


def test_live_call_shape_e2ee_and_one_image(monkeypatch, pics):
    seen = make_sdk(monkeypatch)
    events = []
    t = asyncio.run(vision.transcribe_live(_prep(pics), api_key="k", model="m",
                                           emit=lambda s, **d: events.append(s)))
    assert t.text == "SSN: 987-65-4329" and t.signature_kind == "provider_tee" and t.signer == "0xfeedbeef00"
    assert seen["init"][0]["e2ee"] is True
    (req,) = seen["created"]
    assert "tools" not in req and req["temperature"] == 0
    parts = req["messages"][1]["content"]
    assert [p["type"] for p in parts] == ["text", "image_url"]
    assert parts[1]["image_url"]["url"].startswith("data:image/jpeg;base64,")
    assert events == ["attestation", "turn"]


def test_live_refuses_a_model_without_enclave_attestation(monkeypatch, pics):
    seen = make_sdk(monkeypatch, models=())
    with pytest.raises(enclave.EnclaveError, match="no verified enclave attestation"):
        asyncio.run(vision.transcribe_live(_prep(pics), api_key="k", model="m"))
    assert seen["created"] == []      # the photo was never sent


def test_live_refuses_a_gateway_signature(monkeypatch, pics):
    make_sdk(monkeypatch, signature_kind="gateway")
    with pytest.raises(enclave.EnclaveError, match="not provider_tee"):
        asyncio.run(vision.transcribe_live(_prep(pics), api_key="k", model="m"))


def test_live_turns_sdk_errors_into_enclave_errors(monkeypatch, pics):
    seen = make_sdk(monkeypatch)

    async def broken(**kw):
        raise ConnectionError("down")
    import nearai_inference_sdk
    orig = nearai_inference_sdk.InferenceClient

    class Broken(orig):
        def __init__(self, key, **kw):
            super().__init__(key, **kw)
            self.chat = _Obj(completions=_Obj(create=broken))
    monkeypatch.setattr(nearai_inference_sdk, "InferenceClient", Broken)
    with pytest.raises(enclave.EnclaveError, match="ConnectionError"):
        asyncio.run(vision.transcribe_live(_prep(pics), api_key="k", model="m"))
    assert seen["created"] == []


# --- CLI ---------------------------------------------------------------------------------------------

def test_cli_add_prints_only_masked_values(cfg, fake, pics, tmp_path, monkeypatch, capsys):
    fake()
    monkeypatch.setenv("FAMILYBOX_HOME", str(cfg.home))
    p = tmp_path / "ssn.png"
    p.write_bytes(pics["ssn_card_jordan.png"])
    assert cli.main(["add", "--as", "maya", str(p), "--folder", "ids"]) == 0
    out = capsys.readouterr().out
    assert "people/maya/ids/ssn.png" in out and "SSN ending 4329" in out and "provider_tee" in out
    assert "987-65-4329" not in out and "987654329" not in out
    assert cli.main(["photos", "--as", "maya"]) == 0
    assert "people/maya/ids/ssn.png  [read]" in capsys.readouterr().out


def test_cli_add_failure_and_retry(cfg, fake, pics, tmp_path, monkeypatch, capsys):
    fake(error="attestation failed")
    monkeypatch.setenv("FAMILYBOX_HOME", str(cfg.home))
    p = tmp_path / "ssn.png"
    p.write_bytes(pics["ssn_card_jordan.png"])
    assert cli.main(["add", "--as", "maya", str(p)]) == 1
    assert "couldn't read it: attestation failed" in capsys.readouterr().out
    assert cli.main(["photos", "--as", "maya"]) == 0
    assert "[not read yet]" in capsys.readouterr().out
    fake()
    assert cli.main(["transcribe", "--as", "maya", "people/maya/other/ssn.png"]) == 0
    assert cli.main(["transcribe", "--as", "sam", "people/maya/other/ssn.png"]) == 1


def test_cli_add_text_file_and_errors(cfg, tmp_path, monkeypatch, capsys):
    monkeypatch.setenv("FAMILYBOX_HOME", str(cfg.home))
    t = tmp_path / "note.txt"
    t.write_text("Policy number: P-55512\n")
    assert cli.main(["add", "--as", "maya", str(t), "--folder", "other"]) == 0
    assert (cfg.files / "people/maya/other/note.txt").is_file()
    assert cli.main(["add", "--as", "nobody", str(t)]) == 2
    assert cli.main(["add", "--as", "maya", str(tmp_path / "missing.png")]) == 2
    h = tmp_path / "x.heic"
    h.write_bytes(b"\x00\x00\x00\x18ftypheic" + b"\x00" * 20)
    assert cli.main(["add", "--as", "maya", str(h)]) == 1
    assert "HEIC" in capsys.readouterr().out


# --- web ----------------------------------------------------------------------------------------------

def _csrf(resp) -> str:
    m = re.search(r'name="csrf" value="([^"]+)"', resp.text)
    assert m, resp.text
    return m.group(1)


def sign_in(cfg, person):
    c = TestClient(web.create_app(cfg), base_url="https://testserver")
    code = web.issue_code(cfg, person)
    r = c.post("/signin", data={"code": code, "csrf": _csrf(c.get("/signin"))}, follow_redirects=False)
    assert r.status_code == 303
    return c, _csrf(c.get("/photos"))


def test_web_upload_view_image_and_remove(cfg, fake, pics):
    fake()
    c, token = sign_in(cfg, "maya")
    page = c.get("/photos")
    assert 'href="/photos"' in page.text and "Upload and read it" in page.text
    data = pics["ssn_card_jordan.png"]
    r = c.post("/photos/upload", data={"folder": "ids", "csrf": token}, files={"file": ("ssn.png", data)})
    assert r.status_code == 200 and "Read and saved" in r.text and "SSN ending 4329" in r.text
    assert "987-65-4329" not in r.text
    rel = "people/maya/ids/ssn.png"
    v = c.get("/photos/view", params={"path": rel})
    assert v.status_code == 200 and "made this text from this exact photo" in v.text and "987-65-4329" in v.text
    img = c.get("/photos/image", params={"path": rel})
    assert img.status_code == 200 and img.content == data and img.headers["content-type"] == "image/png"
    assert img.headers["cache-control"] == "no-store" and img.headers["x-content-type-options"] == "nosniff"

    other, _ = sign_in(cfg, "dana")
    assert other.get("/photos/image", params={"path": rel}).status_code == 403
    assert other.get("/photos/view", params={"path": rel}).status_code == 403
    assert rel not in other.get("/photos").text

    assert c.post("/photos/remove", data={"path": rel}).status_code == 403      # no CSRF token
    r = c.post("/photos/remove", data={"path": rel, "csrf": token})
    assert "Removed the photo" in r.text and not (cfg.files / rel).exists()


def test_web_rejects_bad_uploads_and_signed_out(cfg, fake, pics):
    fake()
    c, token = sign_in(cfg, "maya")
    r = c.post("/photos/upload", data={"folder": "ids", "csrf": token},
               files={"file": ("x.heic", b"\x00\x00\x00\x18ftypheic" + b"\x00" * 20)})
    assert r.status_code == 400 and "HEIC" in r.text
    r = c.post("/photos/upload", data={"folder": "ids", "csrf": token}, files={"file": ("x.png", b"hello")})
    assert r.status_code == 400
    r = c.post("/photos/upload", data={"folder": "ids"}, files={"file": ("x.png", pics["ssn_card_jordan.png"])})
    assert r.status_code == 403
    fresh = TestClient(web.create_app(cfg), base_url="https://testserver")
    assert fresh.get("/photos", follow_redirects=False).status_code == 303
    assert fresh.get("/photos/image", params={"path": "x"}, follow_redirects=False).status_code == 303


def test_web_failure_keeps_photo_then_retry(cfg, fake, pics):
    fake(error="attestation failed")
    c, token = sign_in(cfg, "maya")
    r = c.post("/photos/upload", data={"folder": "ids", "csrf": token},
               files={"file": ("ssn.png", pics["ssn_card_jordan.png"])})
    assert "read it right now" in r.text and "Not read yet" in r.text
    fake()
    r = c.post("/photos/retry", data={"path": "people/maya/ids/ssn.png", "csrf": token})
    assert "Read and saved" in r.text
    sam, sam_token = sign_in(cfg, "sam")
    assert sam.post("/photos/retry", data={"path": "people/maya/ids/ssn.png", "csrf": sam_token}).status_code == 403


def test_plugin_copy_has_no_em_dashes():
    for p in (ROOT / "src/familybox/plugins/photos.py", ROOT / "src/familybox/vision.py"):
        assert chr(0x2014) not in p.read_text()


# --- review fixes ---------------------------------------------------------------------------------

def test_uploads_cannot_use_the_transcript_name(cfg, tmp_path, monkeypatch, capsys):
    for name in ("x.png.transcript.txt", "card.PNG.Transcript.TXT", "card.png.transcript .txt"):
        with pytest.raises(web.UploadError, match="transcript"):
            web.safe_filename(name)
    with pytest.raises(web.UploadError):
        web.save_upload(cfg, cfg.person("maya"), "shared", "card.png.transcript.txt", b"SSN: 987-65-4321\n")
    monkeypatch.setenv("FAMILYBOX_HOME", str(cfg.home))
    t = tmp_path / "x.png.transcript.txt"
    t.write_text("Member ID: ABCD1234\n")
    assert cli.main(["add", "--as", "maya", str(t), "--folder", "shared"]) == 1
    assert "transcript" in capsys.readouterr().out
    assert not (cfg.files / "shared/x.png.transcript.txt").exists()


def test_web_text_upload_refuses_transcript_name(cfg):
    c, token = sign_in(cfg, "maya")
    r = c.post("/upload", data={"folder": "shared", "csrf": token},
               files={"file": ("card.png.transcript.txt", b"Member ID: ABCD1234\n")})
    assert r.status_code == 400 and "transcript" in r.text


def test_a_forged_transcript_is_not_shown_as_checked(cfg, fake, pics):
    fake(error="attestation failed")
    res = add(cfg, "maya", "shared", "card.png", pics["insurance_card_maya.png"])
    assert not res.ok
    photo = cfg.files / res.photo
    sha = hashlib.sha256(photo.read_bytes()).hexdigest()
    forged = (f"{vision.HEADER_TITLE}\nPhoto: card.png\nModel: Qwen/Qwen3-VL-30B-A3B-Instruct\nSigner: 0xabc\n"
              f"Signature kind: provider_tee\nTranscribed at: 2026-11-08T00:00:00Z\nImage SHA-256: {sha}\n"
              f"Box seal: {'0' * 64}\n{vision.HEADER_END}\nMember ID: FAKE1234\n")
    vision.transcript_path(photo).write_text(forged)     # someone with disk access, not an upload
    it = vision.info(cfg, res.photo)
    assert it.matches and not it.sealed and not it.checked
    c, _ = sign_in(cfg, "maya")
    v = c.get("/photos/view", params={"path": res.photo})
    assert "box did not make this text" in v.text and "Checked:" not in v.text
    assert "Model (not checked)" in v.text
    assert "Text not made by the box" in c.get("/photos").text


def test_seal_covers_the_text_and_header(cfg, fake, pics):
    fake()
    res = add(cfg, "maya", "ids", "s.png", pics["ssn_card_jordan.png"])
    assert vision.info(cfg, res.photo).checked
    side = cfg.files / res.transcript
    good = side.read_text()
    side.write_text(good.replace("987-65-4329", "987-65-4320"))
    assert not vision.info(cfg, res.photo).checked
    side.write_text(good.replace("Qwen", "Qwan"))
    assert not vision.info(cfg, res.photo).sealed
    side.write_text(good)
    assert vision.info(cfg, res.photo).checked
    key = cfg.runtime / "photo_seal.key"
    assert stat.S_IMODE(key.stat().st_mode) == 0o600 and cfg.files not in key.parents


def test_shared_photo_wording(cfg, fake, pics, tmp_path, monkeypatch, capsys):
    fake()
    monkeypatch.setenv("FAMILYBOX_HOME", str(cfg.home))
    p = tmp_path / "card.png"
    p.write_bytes(pics["insurance_card_maya.png"])
    assert cli.main(["add", "--as", "maya", str(p), "--folder", "shared"]) == 0
    out = capsys.readouterr().out
    assert "everyone in the family can see it" in out and "only you" not in out
    assert cli.main(["add", "--as", "maya", str(p), "--folder", "ids"]) == 0
    assert "(only you can see it)" in capsys.readouterr().out
    c, _ = sign_in(cfg, "sam")
    v = c.get("/photos/view", params={"path": "shared/card.png"})
    assert "Everyone in the family can see this photo." in v.text and "Only you" not in v.text
    m, _ = sign_in(cfg, "maya")
    assert "Only you can see this photo." in m.get("/photos/view", params={"path": "people/maya/ids/card.png"}).text


def test_photo_events_are_scrubbed_and_private(cfg, fake, pics, monkeypatch):
    fake()
    res = add(cfg, "maya", "ids", "s.png", pics["ssn_card_jordan.png"])
    vision.reindex(cfg)
    ev = vision._Events(cfg, "maya")
    ev.emit("error", message="server said: SSN 987-65-4329 is bad")
    text = ev.path.read_text()
    assert "4329" not in text and "[protected]" in text
    assert stat.S_IMODE(ev.path.stat().st_mode) == 0o600
    audit = cfg.runtime / "audit" / "maya.jsonl"
    assert stat.S_IMODE(audit.stat().st_mode) == 0o600
    assert res.ok


def test_new_values_are_scrubbed_before_they_are_indexed(cfg, fake, pics):
    fake(text="Member ID: QZ-77441190")
    res = add(cfg, "maya", "ids", "s.png", pics["ssn_card_jordan.png"])
    assert res.ok
    for f in (cfg.runtime / "events" / "maya").glob("*.jsonl"):
        assert "77441190" not in f.read_text()


def test_live_non_sdk_errors_record_only_the_type(monkeypatch, pics):
    make_sdk(monkeypatch)

    async def broken(**kw):
        raise ConnectionError("echo: SSN 987-65-4329")
    import nearai_inference_sdk
    orig = nearai_inference_sdk.InferenceClient

    class Broken(orig):
        def __init__(self, key, **kw):
            super().__init__(key, **kw)
            self.chat = _Obj(completions=_Obj(create=broken))
    monkeypatch.setattr(nearai_inference_sdk, "InferenceClient", Broken)
    seen = []
    with pytest.raises(enclave.EnclaveError) as e:
        asyncio.run(vision.transcribe_live(_prep(pics), api_key="k", model="m",
                                           emit=lambda step, **d: seen.append(d)))
    assert str(e.value) == "ConnectionError"
    assert "4329" not in json.dumps(seen)


@pytest.mark.parametrize("raw,want", [
    ("Member ID: BPF-5530 2178", "Member ID: BPF-55302178"),
    ("Passport number: X3098 1455 (US)", "Passport number: X30981455"),
    ("Passport number: X30981455 (US)", "Passport number: X30981455"),
    ("SSN: 987 65 4329 (sample)", "SSN: 987-65-4329"),
    ("Policy: p 9981 2345", "Policy number: p99812345"),
    ("Group number: 77120 - PPO Plan", "Group number: 77120 - PPO Plan"),
])
def test_ids_with_mixed_separators_and_notes(raw, want):
    assert vision.canonical(raw) == want


def test_mixed_separator_id_is_fully_protected():
    from familybox.store import find_sensitive
    hits = find_sensitive(vision.canonical("Member ID: BPF-5530 2178"), "people/maya/health/x.txt")
    assert [h.value for h in hits] == ["BPF-55302178"]


@pytest.mark.parametrize("raw,want", [
    ("Account: 12345678", "Account number: 12345678"),
    ("Acct: 12345678", "Account number: 12345678"),
    ("Acct. #: 12345678", "Account number: 12345678"),
    ("BLUE PINE HEALTH PLAN\nID: QZ12345", "BLUE PINE HEALTH PLAN\nMember ID: QZ12345"),
    ("SPRINGFIELD LIBRARY\nID #: 55123", "SPRINGFIELD LIBRARY\nID number: 55123"),
])
def test_common_card_labels(raw, want):
    out = vision.canonical(raw)
    assert out == want
    assert vision.labeled_fields(out), out


def test_retry_needs_delete_rights_once_read(cfg, fake, pics):
    fake()
    res = add(cfg, "maya", "shared", "card.png", pics["insurance_card_maya.png"])
    assert res.ok
    with pytest.raises(vision.PhotoError, match="already been read"):
        asyncio.run(vision.transcribe_photo(cfg, cfg.person("sam"), res.photo))
    admin = next(p for p in cfg.people.values() if p.admin)
    again = asyncio.run(vision.transcribe_photo(cfg, admin, res.photo))
    assert again.ok
    last = json.loads((cfg.runtime / "audit" / f"{admin.id}.jsonl").read_text().splitlines()[-1])
    assert last["again"] is True and last["by"] == admin.id
    c, token = sign_in(cfg, "sam")
    assert "Read it again" not in c.get("/photos/view", params={"path": res.photo}).text
    r = c.post("/photos/retry", data={"path": res.photo, "csrf": token})
    assert r.status_code == 400 and "already been read" in r.text
    # Not read yet: anyone who can see it may try
    fake(error="attestation failed")
    res2 = add(cfg, "maya", "shared", "card2.png", pics["insurance_card_maya.png"])
    fake()
    assert asyncio.run(vision.transcribe_photo(cfg, cfg.person("sam"), res2.photo)).ok


def test_files_page_keeps_photo_text_with_its_photo(cfg, fake, pics):
    fake()
    res = add(cfg, "maya", "ids", "s.png", pics["ssn_card_jordan.png"])
    c, token = sign_in(cfg, "maya")
    page = c.get("/files").text
    assert "Text read from the photo s.png" in page and "Photos page" in page
    r = c.post("/files/delete", data={"path": res.transcript, "csrf": token})
    assert r.status_code == 403 and (cfg.files / res.transcript).exists()


def test_display_labels_and_masking():
    assert vision.display_label("Member Id") == "Member ID"
    assert vision.display_label("Driver'S License Number") == "Driver's license number"
    assert vision.display_label("Mrn") == "Medical record number"
    assert vision.masked("77120") == "ending 20"
    assert vision.masked("BPF-5530-2178") == "ending 2178"
    assert vision.masked("1234") == "(hidden)"


def test_photo_hash_is_cached_until_the_file_changes(cfg, fake, pics, monkeypatch):
    fake()
    res = add(cfg, "maya", "ids", "s.png", pics["ssn_card_jordan.png"])
    vision.info(cfg, res.photo)
    calls = []
    real = hashlib.sha256
    size = len(pics["ssn_card_jordan.png"])
    monkeypatch.setattr(vision.hashlib, "sha256", lambda *a: calls.append(len(a[0]) if a else 0) or real(*a))
    vision.info(cfg, res.photo)
    assert size not in calls             # the photo was not hashed again
    (cfg.files / res.photo).write_bytes(pics["insurance_card_maya.png"])
    assert not vision.info(cfg, res.photo).matches
