"""Google Drive import and encrypted backup, against a fake Google (httpx.MockTransport, no network)."""

from __future__ import annotations

import base64
import hashlib
import io
import json
import os
import shutil
import stat
import tarfile
from pathlib import Path
from urllib.parse import parse_qs, urlsplit

import httpx
import pytest

from familybox import cloud, config
from familybox.cloud import backup as bk
from familybox.cloud import oauth

DEMO = Path(__file__).resolve().parents[1] / "demo"
FOLDER = "application/vnd.google-apps.folder"
GDOC = "application/vnd.google-apps.document"


def _jwt(claims: dict) -> str:
    enc = lambda d: base64.urlsafe_b64encode(json.dumps(d).encode()).rstrip(b"=").decode()  # noqa: E731
    return f"{enc({'alg': 'none'})}.{enc(claims)}.sig"


class FakeGoogle:
    """Just enough of accounts.google.com, oauth2.googleapis.com and the Drive v3 API."""

    def __init__(self):
        self.codes: dict[str, dict] = {}       # code -> {challenge, redirect_uri}
        self.access_n = 0
        self.valid_access: set[str] = set()
        self.refreshes = 0
        self.requests: list[httpx.Request] = []
        self.files: dict[str, dict] = {}        # id -> metadata (+ "content")
        self.uploads: dict[str, bytes] = {}
        self.downloads: list[str] = []
        self.next_id = 0

    def add(self, fid, name, mime, parent, content=b"", modified="2026-11-01T00:00:00Z"):
        self.files[fid] = {"id": fid, "name": name, "mimeType": mime, "parents": [parent],
                           "modifiedTime": modified, "size": str(len(content)), "content": content}

    def issue_code(self, url: str) -> tuple[str, str]:
        q = parse_qs(urlsplit(url).query)
        code = f"code-{len(self.codes)}"
        self.codes[code] = {"challenge": q["code_challenge"][0], "redirect_uri": q["redirect_uri"][0]}
        return q["state"][0], code

    def _new_access(self) -> str:
        self.access_n += 1
        tok = f"ya29.access-{self.access_n}"
        self.valid_access.add(tok)
        return tok

    def __call__(self, req: httpx.Request) -> httpx.Response:
        self.requests.append(req)
        url = req.url
        if url.host == "oauth2.googleapis.com" and url.path == "/token":
            form = parse_qs(req.content.decode())
            g = form["grant_type"][0]
            if g == "authorization_code":
                rec = self.codes.pop(form["code"][0], None)
                if not rec:
                    return httpx.Response(400, json={"error": "invalid_grant"})
                verifier = form["code_verifier"][0]
                calc = base64.urlsafe_b64encode(hashlib.sha256(verifier.encode()).digest()).rstrip(b"=").decode()
                if calc != rec["challenge"] or form["redirect_uri"][0] != rec["redirect_uri"]:
                    return httpx.Response(400, json={"error": "invalid_grant"})
                return httpx.Response(200, json={"access_token": self._new_access(), "expires_in": 3599,
                                                 "refresh_token": "1//refresh-secret", "scope": " ".join(oauth.SCOPES),
                                                 "id_token": _jwt({"email": "dana@example.com"})})
            if g == "refresh_token":
                if form["refresh_token"][0] != "1//refresh-secret":
                    return httpx.Response(400, json={"error": "invalid_grant"})
                self.refreshes += 1
                return httpx.Response(200, json={"access_token": self._new_access(), "expires_in": 3599})
        if url.host == "oauth2.googleapis.com" and url.path == "/revoke":
            return httpx.Response(200)
        auth = req.headers.get("authorization", "")
        if auth.removeprefix("Bearer ") not in self.valid_access:
            return httpx.Response(401, json={"error": {"message": "invalid credentials"}})
        if url.host == "upload.example" and req.method == "PUT":
            sess = self.resumable
            start_end, total = req.headers["content-range"].removeprefix("bytes ").split("/")
            start, end = (int(x) for x in start_end.split("-"))
            assert start == len(sess["data"]) and end - start + 1 == len(req.content)
            sess["data"] += req.content
            if len(sess["data"]) < int(total):
                return httpx.Response(308, headers={"Range": f"bytes=0-{len(sess['data']) - 1}"})
            return self._store_upload(sess["meta"], bytes(sess["data"]))
        if url.host == "www.googleapis.com" and url.params.get("uploadType") == "resumable":
            self.resumable = {"meta": json.loads(req.content), "data": bytearray()}
            return httpx.Response(200, headers={"Location": "https://upload.example/session/1"})
        if url.host == "www.googleapis.com" and url.path.startswith("/upload/drive/v3/files"):
            ctype = req.headers["content-type"]
            assert ctype.startswith("multipart/related; boundary=")
            boundary = ctype.split("boundary=")[1].encode()
            parts = req.content.split(b"--" + boundary)
            meta = json.loads(parts[1].split(b"\r\n\r\n", 1)[1].rstrip(b"\r\n"))
            body = parts[2].split(b"\r\n\r\n", 1)[1][:-2]
            return self._store_upload(meta, body)
        return self._drive(req)

    def _store_upload(self, meta: dict, body: bytes) -> httpx.Response:
        fid = f"backup{self.next_id}"
        self.next_id += 1
        self.uploads[fid] = body
        self.files[fid] = {"id": fid, "name": meta["name"], "mimeType": meta["mimeType"], "parents": ["root"],
                           "modifiedTime": "x", "size": str(len(body)), "content": body,
                           "sha256Checksum": hashlib.sha256(body).hexdigest()}
        return httpx.Response(200, json={"id": fid, "name": meta["name"]})

    def _drive(self, req: httpx.Request) -> httpx.Response:
        url = req.url
        if url.host == "www.googleapis.com" and url.path.startswith("/drive/v3/files"):
            rest = url.path.removeprefix("/drive/v3/files").strip("/")
            if not rest:
                q = url.params["q"]
                if " in parents" in q:
                    parent = q.split("'")[1]
                    found = [f for f in self.files.values() if parent in f["parents"]]
                else:
                    name = q.split("name = '")[1].split("' and")[0].replace("\\'", "'")
                    found = [f for f in self.files.values() if f["name"] == name and f["mimeType"] == FOLDER]
                return httpx.Response(200, json={"files": [{k: v for k, v in f.items() if k not in ("content", "parents")}
                                                            for f in found]})
            fid, _, action = rest.partition("/")
            f = self.files.get(fid)
            if not f:
                return httpx.Response(404, json={"error": {"message": "File not found"}})
            if action == "export":
                assert url.params["mimeType"] == "text/plain"
                self.downloads.append(fid)
                return httpx.Response(200, content=f["content"])
            if url.params.get("alt") == "media":
                if f["mimeType"].startswith("application/vnd.google-apps."):
                    return httpx.Response(403, json={"error": {"message": "use export"}})
                self.downloads.append(fid)
                return httpx.Response(200, content=f["content"])
            return httpx.Response(200, json={k: v for k, v in f.items() if k not in ("content", "parents")})
        return httpx.Response(404)


@pytest.fixture
def google(monkeypatch):
    g = FakeGoogle()
    monkeypatch.setenv("GOOGLE_OAUTH_CLIENT_ID", "test-client.apps.googleusercontent.com")
    monkeypatch.setenv("GOOGLE_OAUTH_CLIENT_SECRET", "test-secret")
    monkeypatch.delenv("FAMILYBOX_OAUTH_REDIRECT", raising=False)
    cloud.set_client_factory(lambda: httpx.Client(transport=httpx.MockTransport(g)))
    yield g
    cloud.set_client_factory(None)


@pytest.fixture
def cfg(tmp_path):
    home = tmp_path / "box"
    shutil.copytree(DEMO / "files", home / "files")
    shutil.copy(DEMO / "family.toml", home / "family.toml")
    return config.load(home)


REDIRECT = "http://127.0.0.1:8765/cloud/callback"


def connect(cfg, g, person="dana"):
    url = cloud.begin_connect(cfg, person, REDIRECT)
    state, code = g.issue_code(url)
    return cloud.finish_connect(cfg, state, code)


def mode(p: Path) -> int:
    return stat.S_IMODE(p.stat().st_mode)


# --- OAuth --------------------------------------------------------------------------------------

def test_auth_url_has_pkce_s256_and_scopes(cfg, google):
    url = cloud.begin_connect(cfg, "maya", REDIRECT)
    q = parse_qs(urlsplit(url).query)
    assert url.startswith("https://accounts.google.com/o/oauth2/v2/auth?")
    assert q["code_challenge_method"] == ["S256"]
    assert len(q["code_challenge"][0]) == 43
    assert q["redirect_uri"] == [REDIRECT]
    scopes = q["scope"][0].split()
    assert {"openid", "email", "https://www.googleapis.com/auth/drive.readonly",
            "https://www.googleapis.com/auth/drive.file"} == set(scopes)
    pending = json.loads((cfg.runtime / "cloud" / "pending.json").read_text())
    rec = pending[q["state"][0]]
    assert rec["person"] == "maya"
    # The verifier never leaves the box, and the challenge is its SHA-256.
    assert rec["verifier"] not in url
    calc = base64.urlsafe_b64encode(hashlib.sha256(rec["verifier"].encode()).digest()).rstrip(b"=").decode()
    assert calc == q["code_challenge"][0]


def test_connect_stores_tokens_0600_and_shows_email(cfg, google):
    st = connect(cfg, google, "dana")
    assert st["connected"] and st["account_email"] == "dana@example.com" and st["person"] == "dana"
    tok = cfg.runtime / "cloud" / "dana.json"
    assert mode(tok) == 0o600 and mode(tok.parent) == 0o700
    assert cloud.status(cfg, "maya")["connected"] is False


def test_state_is_single_use(cfg, google):
    url = cloud.begin_connect(cfg, "dana", REDIRECT)
    state, code = google.issue_code(url)
    cloud.finish_connect(cfg, state, code)
    with pytest.raises(cloud.CloudError, match="already used"):
        cloud.finish_connect(cfg, state, code)


def test_state_is_consumed_even_when_exchange_fails(cfg, google):
    url = cloud.begin_connect(cfg, "dana", REDIRECT)
    state, _ = google.issue_code(url)
    with pytest.raises(cloud.CloudError):
        cloud.finish_connect(cfg, state, "wrong-code")
    with pytest.raises(cloud.CloudError, match="already used"):
        cloud.finish_connect(cfg, state, "wrong-code")


def test_state_expires_after_ten_minutes(cfg, google, monkeypatch):
    url = cloud.begin_connect(cfg, "dana", REDIRECT)
    state, code = google.issue_code(url)
    real = oauth._now()
    monkeypatch.setattr(oauth, "_now", lambda: real + 601)
    with pytest.raises(cloud.CloudError):
        cloud.finish_connect(cfg, state, code)
    assert not (cfg.runtime / "cloud" / "dana.json").exists()


def test_unknown_state_and_unknown_person(cfg, google):
    with pytest.raises(cloud.CloudError):
        cloud.finish_connect(cfg, "made-up", "code")
    with pytest.raises(KeyError):
        cloud.begin_connect(cfg, "eve", REDIRECT)
    with pytest.raises(cloud.CloudError):
        cloud.begin_connect(cfg, "../dana", REDIRECT)


def test_lan_redirect_needs_forwarder(cfg, google, monkeypatch):
    with pytest.raises(cloud.CloudError, match="home-network"):
        cloud.begin_connect(cfg, "dana", "https://familybox.local:8443/cloud/callback")
    monkeypatch.setenv("FAMILYBOX_OAUTH_REDIRECT", "https://example.github.io/oauth-forwarder.html")
    url = cloud.begin_connect(cfg, "dana", "https://familybox.local:8443/cloud/callback")
    q = parse_qs(urlsplit(url).query)
    assert q["redirect_uri"] == ["https://example.github.io/oauth-forwarder.html"]
    nonce, box = q["state"][0].split(".")
    assert base64.urlsafe_b64decode(box + "==").decode() == "https://familybox.local:8443/cloud/callback"
    # The token exchange uses the forwarder URI, exactly what Google saw.
    state, code = google.issue_code(url)
    assert cloud.finish_connect(cfg, state, code)["connected"]
    # The forwarder will not send people to a public host.
    with pytest.raises(cloud.CloudError):
        cloud.begin_connect(cfg, "dana", "https://evil.example.com/cb")


def test_token_refreshes_when_expired(cfg, google):
    connect(cfg, google)
    first = oauth.access_token(cfg, "dana")
    assert google.refreshes == 0
    tok = json.loads((cfg.runtime / "cloud" / "dana.json").read_text())
    tok["expires_at"] = 0
    (cfg.runtime / "cloud" / "dana.json").write_text(json.dumps(tok))
    second = oauth.access_token(cfg, "dana")
    assert second != first and google.refreshes == 1
    saved = json.loads((cfg.runtime / "cloud" / "dana.json").read_text())
    assert saved["access_token"] == second and saved["refresh_token"] == "1//refresh-secret"
    assert mode(cfg.runtime / "cloud" / "dana.json") == 0o600


def test_revoked_access_token_triggers_refresh_on_401(cfg, google):
    connect(cfg, google)
    google.valid_access.clear()               # Google revoked the access token early
    google.add("F1", "Taxes", FOLDER, "root")
    r = cloud.import_folder(cfg, "dana", "Taxes")
    assert r["folder"] == "Taxes" and google.refreshes == 1


def test_disconnect_forgets_tokens(cfg, google):
    connect(cfg, google)
    st = cloud.disconnect(cfg, "dana")
    assert st["connected"] is False and not (cfg.runtime / "cloud" / "dana.json").exists()
    assert any(r.url.path == "/revoke" for r in google.requests)


# --- import -------------------------------------------------------------------------------------

def drive_tree(g: FakeGoogle):
    g.add("1MayaSchoolFolderId", "Maya school", FOLDER, "root")
    g.add("f-txt", "report card.txt", "text/plain", "1MayaSchoolFolderId", b"Report card: all A's\n")
    g.add("f-pdf", "transcript.pdf", "application/pdf", "1MayaSchoolFolderId", b"%PDF-1.4 fake")
    g.add("f-exe", "game.exe", "application/octet-stream", "1MayaSchoolFolderId", b"MZ")
    g.add("f-jpg", "photo.jpg", "image/jpeg", "1MayaSchoolFolderId", b"\xff\xd8")
    g.add("f-sheet", "Budget", "application/vnd.google-apps.spreadsheet", "1MayaSchoolFolderId")
    g.add("f-doc", "Essay draft", GDOC, "1MayaSchoolFolderId", b"My essay about otters.\n")
    g.add("f-evil", "../../dana/ids/passport_dana.txt", "text/plain", "1MayaSchoolFolderId", b"overwrite attempt\n")
    g.add("SUB", "Forms", FOLDER, "1MayaSchoolFolderId")
    g.add("f-csv", "grades.csv", "text/csv", "SUB", b"class,grade\nmath,A\n")
    g.add("SUBSUB", "Deeper", FOLDER, "SUB")
    g.add("f-deep", "deep.txt", "text/plain", "SUBSUB", b"too deep\n")


def test_import_writes_only_into_that_persons_folder(cfg, google):
    connect(cfg, google, "maya")
    drive_tree(google)
    before = {p: p.read_bytes() for p in cfg.files.rglob("*") if p.is_file()}
    r = cloud.import_folder(cfg, "maya", "Maya school")
    assert r["folder"] == "Maya school" and r["imported"] == 5
    root = cfg.files / "people" / "maya" / "from-drive" / "Maya school"
    assert (root / "report card.txt").read_bytes() == b"Report card: all A's\n"
    assert (root / "transcript.pdf").exists()
    assert (root / "Essay draft.txt").read_bytes() == b"My essay about otters.\n"   # exported Google Doc
    assert (root / "Forms" / "grades.csv").exists()
    # Every new file is under maya's from-drive folder with 0600; nothing else changed.
    after = {p: p.read_bytes() for p in cfg.files.rglob("*") if p.is_file()}
    new = set(after) - set(before)
    assert len(new) == 5
    for p in new:
        assert (cfg.files / "people" / "maya" / "from-drive") in p.parents
        assert mode(p) == 0o600
    assert all(after[p] == before[p] for p in before)
    assert (cfg.files / "people" / "dana" / "ids" / "passport_dana.txt").read_bytes() == \
        (DEMO / "files" / "people" / "dana" / "ids" / "passport_dana.txt").read_bytes()
    reasons = {s["name"]: s["reason"] for s in r["skipped_files"]}
    assert set(reasons) == {"game.exe", "photo.jpg", "Budget", "Forms/Deeper"}
    assert "f-exe" not in google.downloads and "f-jpg" not in google.downloads
    assert "f-deep" not in google.downloads
    # The search index now knows the new files.
    from familybox.store import Store
    hits = Store(cfg).search(cfg.person("maya"), "otters")
    assert hits and hits[0]["path"].startswith("people/maya/from-drive/")


def test_reimport_skips_unchanged_and_fetches_changed(cfg, google):
    connect(cfg, google, "maya")
    drive_tree(google)
    cloud.import_folder(cfg, "maya", "Maya school")
    google.downloads.clear()
    r = cloud.import_folder(cfg, "maya", "1MayaSchoolFolderId")      # by id this time
    assert r["imported"] == 0 and google.downloads == []
    assert sum(1 for s in r["skipped_files"] if s["reason"] == "unchanged") == 5
    google.files["f-txt"].update(content=b"Report card: updated\n", modifiedTime="2026-11-05T00:00:00Z")
    r = cloud.import_folder(cfg, "maya", "Maya school")
    assert r["imported"] == 1 and google.downloads == ["f-txt"]
    assert (cfg.files / "people/maya/from-drive/Maya school/report card.txt").read_bytes() == b"Report card: updated\n"
    st = cloud.status(cfg, "maya")
    assert st["last_import"]["folder"] == "Maya school"


def test_import_needs_that_persons_own_connection(cfg, google):
    connect(cfg, google, "dana")
    drive_tree(google)
    with pytest.raises(cloud.CloudError, match="not connected"):
        cloud.import_folder(cfg, "maya", "Maya school")


def test_import_refuses_symlinked_person_folder(cfg, google, tmp_path):
    connect(cfg, google, "maya")
    drive_tree(google)
    outside = tmp_path / "outside"
    outside.mkdir()
    (cfg.files / "people" / "maya" / "from-drive").symlink_to(outside)
    with pytest.raises(cloud.CloudError, match="symlink"):
        cloud.import_folder(cfg, "maya", "Maya school")
    assert list(outside.iterdir()) == []


def test_safe_name():
    from familybox.cloud.drive_import import safe_name
    assert "/" not in safe_name("../../etc/passwd") and not safe_name("../../etc/passwd").startswith(".")
    assert safe_name("..") == "file" and safe_name("") == "file"
    assert safe_name(".bashrc") == "bashrc"


# --- backup -------------------------------------------------------------------------------------

def snapshot(home: Path) -> dict[str, bytes]:
    out = {}
    for p in sorted(home.rglob("*")):
        rel = p.relative_to(home).as_posix()
        if p.is_file() and not rel.startswith("runtime/"):
            out[rel] = p.read_bytes()
    return out


def test_recovery_code_round_trip():
    key = os.urandom(32)
    code = bk.recovery_code(key)
    assert len(code.replace("-", "")) == 52 and all(len(g) <= 4 for g in code.split("-"))
    assert bk.parse_recovery_code(code) == key
    assert bk.parse_recovery_code(code.lower().replace("-", " ")) == key


def test_backup_key_is_0600_and_not_replaced_silently(cfg):
    code = cloud.init_backup_key(cfg)
    assert mode(cfg.runtime / "cloud" / "backup.key") == 0o600
    assert bk.parse_recovery_code(code) == (cfg.runtime / "cloud" / "backup.key").read_bytes()
    with pytest.raises(cloud.CloudError):
        cloud.init_backup_key(cfg)


def test_backup_round_trip_through_drive(cfg, google, tmp_path):
    connect(cfg, google, "dana")
    code = cloud.init_backup_key(cfg)
    (cfg.files / "people" / "sam" / "big.bin.txt").write_bytes(os.urandom(200_000))   # several chunks
    original = snapshot(cfg.home)
    r = cloud.backup_now(cfg)
    assert r["drive_file_id"] in google.uploads
    uploaded = google.uploads[r["drive_file_id"]]
    assert len(uploaded) == r["bytes"] and hashlib.sha256(uploaded).hexdigest() == r["sha256"]
    assert uploaded.startswith(bk.MAGIC + bytes([bk.VERSION]))
    assert google.files[r["drive_file_id"]]["name"].startswith("familybox-backup-")
    assert google.files[r["drive_file_id"]]["name"].endswith(".fbx")
    # Google only sees ciphertext: no plaintext SSN or file name in the upload.
    assert b"987-65-43" not in uploaded and b"passport_dana" not in uploaded
    assert cloud.status(cfg, "dana")["last_backup"]["drive_file_id"] == r["drive_file_id"]

    # Lose the box: a fresh home with only the Google connection and the recovery code.
    fresh = tmp_path / "fresh"
    fresh.mkdir()
    shutil.copy(cfg.home / "family.toml", fresh / "family.toml")
    (fresh / "runtime" / "cloud").mkdir(parents=True)
    shutil.copy(cfg.runtime / "cloud" / "dana.json", fresh / "runtime" / "cloud" / "dana.json")
    cfg2 = config.load(fresh)
    out = cloud.restore(cfg2, r["drive_file_id"], code)
    assert out["restored_files"] == len(original)
    assert snapshot(fresh) == original
    assert mode(fresh / "files" / "people" / "dana" / "ids" / "passport_dana.txt") == 0o600


def test_large_backup_uses_resumable_upload(cfg, google, monkeypatch):
    connect(cfg, google, "dana")
    code = cloud.init_backup_key(cfg)
    monkeypatch.setattr(bk, "MULTIPART_MAX", 1024)
    monkeypatch.setattr(bk, "RESUMABLE_CHUNK", 256 * 1024)
    (cfg.files / "shared" / "scan.txt").write_bytes(os.urandom(700_000))
    original = snapshot(cfg.home)
    r = cloud.backup_now(cfg)
    assert hashlib.sha256(google.uploads[r["drive_file_id"]]).hexdigest() == r["sha256"]
    shutil.rmtree(cfg.files)
    cloud.restore(cfg, r["drive_file_id"], code)
    assert snapshot(cfg.home) == original


def test_backup_never_contains_runtime_secrets(cfg, google):
    connect(cfg, google, "dana")
    cloud.init_backup_key(cfg)
    (cfg.runtime / "tls").mkdir()
    (cfg.runtime / "tls" / "box.key").write_text("PRIVATE KEY")
    key = (cfg.runtime / "cloud" / "backup.key").read_bytes()
    r = cloud.backup_now(cfg)
    plain = io.BytesIO()
    bk.decrypt_stream(io.BytesIO(google.uploads[r["drive_file_id"]]), plain, key)
    names = tarfile.open(fileobj=io.BytesIO(plain.getvalue())).getnames()
    assert "family.toml" in names and any(n.startswith("files/people/") for n in names)
    assert not any(n.startswith("runtime") or "backup.key" in n or n.endswith("dana.json") for n in names)
    raw = plain.getvalue()
    assert key not in raw and b"refresh-secret" not in raw and b"ya29." not in raw and b"PRIVATE KEY" not in raw


def test_tampering_one_byte_fails(cfg, tmp_path):
    code = cloud.init_backup_key(cfg)
    f = tmp_path / "b.fbx"
    bk.make_backup_file(cfg, f)
    data = bytearray(f.read_bytes())
    for pos in (bk.PREFIX_LEN + bk.HEADERBYTES + 10, len(data) // 2, len(data) - 1):
        bad = bytearray(data)
        bad[pos] ^= 0x01
        (tmp_path / "bad.fbx").write_bytes(bytes(bad))
        before = snapshot(cfg.home)
        with pytest.raises(cloud.BackupError):
            cloud.restore(cfg, str(tmp_path / "bad.fbx"), code)
        assert snapshot(cfg.home) == before
    (tmp_path / "short.fbx").write_bytes(bytes(data[:-200]))
    with pytest.raises(cloud.BackupError):
        cloud.restore(cfg, str(tmp_path / "short.fbx"), code)


def test_wrong_recovery_code_fails(cfg, tmp_path):
    cloud.init_backup_key(cfg)
    f = tmp_path / "b.fbx"
    bk.make_backup_file(cfg, f)
    wrong = bk.recovery_code(os.urandom(32))
    with pytest.raises(cloud.BackupError, match="wrong recovery code"):
        cloud.restore(cfg, str(f), wrong)
    with pytest.raises(cloud.BackupError):
        cloud.restore(cfg, str(f), "not a code")


def _encrypt_tar(cfg, members: list[tuple[tarfile.TarInfo, bytes | None]], path: Path):
    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w") as t:
        for info, data in members:
            t.addfile(info, io.BytesIO(data) if data is not None else None)
    buf.seek(0)
    with path.open("wb") as out:
        bk.encrypt_stream(buf, out, bk.load_key(cfg))


@pytest.mark.parametrize("kind", ["dotdot", "absolute", "symlink", "hardlink", "device", "outside_top"])
def test_malicious_tar_is_rejected(cfg, tmp_path, kind):
    code = cloud.init_backup_key(cfg)
    good = tarfile.TarInfo("files/shared/ok.txt")
    good.size = 3
    evil = tarfile.TarInfo({"dotdot": "files/../../escaped.txt", "absolute": "/tmp/fbx-escaped.txt",
                            "symlink": "files/link", "hardlink": "files/hard", "device": "files/dev",
                            "outside_top": "runtime/cloud/dana.json"}[kind])
    data: bytes | None = b"pwn"
    if kind == "symlink":
        evil.type, evil.linkname, data = tarfile.SYMTYPE, "/etc/passwd", None
    elif kind == "hardlink":
        evil.type, evil.linkname, data = tarfile.LNKTYPE, "family.toml", None
    elif kind == "device":
        evil.type, data = tarfile.CHRTYPE, None
    if data is not None:
        evil.size = len(data)
    f = tmp_path / "evil.fbx"
    _encrypt_tar(cfg, [(good, b"ok\n"), (evil, data)], f)
    with pytest.raises(cloud.BackupError):
        cloud.restore(cfg, str(f), code)
    # Nothing was written, not even the good member.
    assert not (cfg.files / "shared" / "ok.txt").exists()
    assert not (tmp_path / "escaped.txt").exists() and not (cfg.home.parent / "escaped.txt").exists()


def test_restore_does_not_follow_existing_symlink(cfg, tmp_path):
    code = cloud.init_backup_key(cfg)
    f = tmp_path / "b.fbx"
    bk.make_backup_file(cfg, f)
    outside = tmp_path / "outside"
    outside.mkdir()
    shutil.rmtree(cfg.files / "shared")
    (cfg.files / "shared").symlink_to(outside)
    with pytest.raises(cloud.BackupError):
        cloud.restore(cfg, str(f), code)
    assert list(outside.iterdir()) == []


def test_backup_needs_key_and_admin_connection(cfg, google):
    with pytest.raises(cloud.CloudError, match="backup key"):
        cloud.backup_now(cfg)
    cloud.init_backup_key(cfg)
    connect(cfg, google, "maya")                    # maya is not the admin
    with pytest.raises(cloud.CloudError, match="dana"):
        cloud.backup_now(cfg)


def test_status_shape(cfg, google):
    st = cloud.status(cfg, "sam")
    assert set(st) == {"connected", "account_email", "last_import", "last_backup", "backup_key_set"}


def test_cli_status_and_admin_only(cfg, google, monkeypatch, capsys):
    from familybox import cli
    monkeypatch.setenv("FAMILYBOX_HOME", str(cfg.home))
    assert cli.main(["cloud", "status", "--as", "maya"]) == 0
    assert json.loads(capsys.readouterr().out)["connected"] is False
    assert cli.main(["cloud", "backup", "--as", "maya"]) == 2


def test_cli_connect_paste_redirect_url(cfg, google, monkeypatch, capsys):
    from familybox import cli
    monkeypatch.setenv("FAMILYBOX_HOME", str(cfg.home))
    seen = {}

    def fake_input(prompt):
        url = [l for l in capsys.readouterr().out.splitlines() if l.startswith("https://accounts.google.com")][0]
        state, code = google.issue_code(url)
        seen["state"] = state
        return f"http://127.0.0.1:8765/cloud/callback?state={state}&code={code}&scope=email"
    monkeypatch.setattr("builtins.input", fake_input)
    assert cli.main(["cloud", "connect", "--as", "dana"]) == 0
    out = capsys.readouterr().out
    assert "connected dana as dana@example.com" in out
    assert "refresh-secret" not in out and "ya29." not in out
