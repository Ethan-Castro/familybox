"""The box's private web page: code sign-in, uploads, files, approvals and the cloud page (no network)."""

import json
import re
import shutil
import stat
import sys
import types
from pathlib import Path

import pytest
from starlette.testclient import TestClient

from familybox import config, web
from familybox.approvals import Approvals
from familybox.gate import Held
from familybox.store import Store

DEMO = Path(__file__).resolve().parents[1] / "demo"


@pytest.fixture
def cfg(tmp_path, monkeypatch):
    shutil.copytree(DEMO / "files", tmp_path / "files")
    shutil.copy(DEMO / "family.toml", tmp_path / "family.toml")
    monkeypatch.delenv("FAMILYBOX_OAUTH_REDIRECT", raising=False)
    c = config.load(tmp_path)
    Store(c).reindex()
    return c


@pytest.fixture
def no_cloud(monkeypatch):
    monkeypatch.setitem(sys.modules, "familybox.cloud", None)   # import now raises ImportError


def client(cfg) -> TestClient:
    return TestClient(web.create_app(cfg), base_url="https://testserver")


def csrf(resp) -> str:
    m = re.search(r'name="csrf" value="([^"]+)"', resp.text)
    assert m, resp.text
    return m.group(1)


def sign_in(cfg, person) -> tuple[TestClient, str]:
    c = client(cfg)
    code = web.issue_code(cfg, person)
    r = c.post("/signin", data={"code": code, "csrf": csrf(c.get("/signin"))}, follow_redirects=False)
    assert r.status_code == 303
    home = c.get("/")
    assert home.status_code == 200
    return c, csrf(home)


def upload(c, token, folder, name, data, **extra):
    return c.post("/upload", data={"folder": folder, "csrf": token} | extra, files={"file": (name, data)})


# --- sign-in -------------------------------------------------------------------------------------

def test_code_signs_in_once_then_fails(cfg):
    code = web.issue_code(cfg, "maya")
    assert len(code) == 8 and set(code) <= set(web.CODE_ALPHABET)
    c = client(cfg)
    r = c.post("/signin", data={"code": code.lower(), "csrf": csrf(c.get("/signin"))}, follow_redirects=False)
    assert r.status_code == 303
    cookie = r.headers["set-cookie"]
    assert "Secure" in cookie and "HttpOnly" in cookie and "SameSite=strict" in cookie.replace("Strict", "strict")
    assert "Signed in as Maya" in c.get("/").text

    c2 = client(cfg)
    r2 = c2.post("/signin", data={"code": code, "csrf": csrf(c2.get("/signin"))}, follow_redirects=False)
    assert r2.status_code == 401
    assert c2.get("/", follow_redirects=False).status_code == 303


def test_codes_are_stored_only_as_hashes(cfg):
    code = web.issue_code(cfg, "maya")
    for f in (cfg.runtime / "web").iterdir():
        if f.is_file():
            assert code not in f.read_bytes().decode(errors="replace")
            assert stat.S_IMODE(f.stat().st_mode) == 0o600


def test_wrong_codes_lock_out(cfg):
    good = web.issue_code(cfg, "dana")
    c = client(cfg)
    for _ in range(web.LOCKOUT_MAX):
        r = c.post("/signin", data={"code": "AAAAAAAA", "csrf": csrf(c.get("/signin"))})
        assert r.status_code in (401, 429)
    r = c.post("/signin", data={"code": good, "csrf": csrf(c.get("/signin"))}, follow_redirects=False)
    assert r.status_code == 429 and "Too many wrong codes" in r.text


def test_expired_session_is_rejected(cfg, monkeypatch):
    c, _ = sign_in(cfg, "maya")
    now = web.time.time()
    monkeypatch.setattr(web.time, "time", lambda: now + web.SESSION_TTL_S + 1)
    assert c.get("/", follow_redirects=False).status_code == 303


def test_pages_need_sign_in_and_send_security_headers(cfg):
    c = client(cfg)
    for path in ("/", "/upload", "/files", "/approvals", "/cloud"):
        r = c.get(path, follow_redirects=False)
        assert r.status_code == 303 and r.headers["location"] == "/signin"
    r = c.get("/signin")
    assert r.headers["content-security-policy"].startswith("default-src 'self'; style-src 'self'")
    assert "frame-ancestors 'none'" in r.headers["content-security-policy"]
    assert r.headers["x-content-type-options"] == "nosniff"
    # same-origin, not no-referrer: with no-referrer browsers send "Origin: null" on form posts, and the
    # box refuses those, so no form would work in a real browser.
    assert r.headers["referrer-policy"] == "same-origin"
    assert r.headers["cache-control"] == "no-store"
    assert c.get("/static/style.css").headers["content-type"].startswith("text/css")
    assert "http://" not in r.text and "https://" not in r.text   # no external assets
    assert "\u2014" not in r.text and "\u2014" not in web.CSS


def test_signin_without_csrf_is_refused(cfg):
    c = client(cfg)
    c.get("/signin")
    r = c.post("/signin", data={"code": web.issue_code(cfg, "maya")})
    assert r.status_code == 403


# --- uploads -------------------------------------------------------------------------------------

def test_upload_lands_private_and_indexed(cfg):
    c, token = sign_in(cfg, "maya")
    r = upload(c, token, "school", "Report Card.txt", b"Report card 2026: zebrafinch grades A")
    assert r.status_code == 200 and "Uploaded" in r.text
    f = cfg.files / "people/maya/school/Report Card.txt"
    assert f.read_bytes().startswith(b"Report card")
    assert stat.S_IMODE(f.stat().st_mode) == 0o600
    hits = Store(cfg).search(cfg.person("maya"), "zebrafinch")
    assert [h["path"] for h in hits] == ["people/maya/school/Report Card.txt"]
    assert Store(cfg).search(cfg.person("sam"), "zebrafinch")          # sam has also_reads on maya/school
    upload(c, token, "other", "notes.txt", b"private quokka notes")
    assert Store(cfg).search(cfg.person("maya"), "quokka")
    assert not Store(cfg).search(cfg.person("sam"), "quokka")
    log = (cfg.runtime / "audit/maya.jsonl").read_text()
    entries = [line for line in log.splitlines() if '"event": "upload"' in line]
    assert len(entries) == 2 and '"folder": "people/maya/school"' in entries[0] and '"sha256"' in entries[0]
    assert "Report Card" not in log and "zebrafinch" not in log and "notes.txt" not in log

    # Same name again gets a suffix instead of overwriting.
    upload(c, token, "school", "Report Card.txt", b"second copy")
    assert (cfg.files / "people/maya/school/Report Card-1.txt").read_bytes() == b"second copy"
    assert f.read_bytes().startswith(b"Report card")


def test_upload_to_shared(cfg):
    c, token = sign_in(cfg, "sam")
    assert upload(c, token, "shared", "wifi.md", b"# Wi-Fi\nnetwork okafor-home").status_code == 200
    assert (cfg.files / "shared/wifi.md").exists()


@pytest.mark.parametrize("name", ["../../family.toml.txt", "..\\..\\evil.txt", "/etc/passwd.txt",
                                  "a/../../evil.txt"])
def test_upload_filename_cannot_escape(cfg, name):
    # Block F refuses names with ".." or an absolute path (before, it kept only the last part). A
    # whole-folder upload sends paths, so a path that climbs out is now left out, not quietly renamed.
    c, token = sign_in(cfg, "maya")
    r = upload(c, token, "other", name, b"hello")
    assert r.status_code == 400 and "outside the folder" in r.text
    assert not (cfg.files / "people/maya/other").exists()
    assert not (cfg.home / "family.toml.txt").exists() and not (cfg.home / "evil.txt").exists()


@pytest.mark.parametrize("raw", ["C:\\Users\\evil.txt", "c:/x.txt", "\\\\server\\share\\x.txt", "..", "a/./../b.txt"])
def test_flatten_name_refuses_paths_that_climb_out(raw):
    # (The multipart parser already cuts Windows drive paths down to the last part, so this checks
    # the helper itself.)
    with pytest.raises(web.UploadError):
        web.flatten_name(raw)


def test_flatten_name_joins_subfolders():
    assert web.flatten_name("Taxes/2025/w2.pdf") == "2025_w2.pdf"
    assert web.flatten_name("w2.pdf") == "w2.pdf"
    assert web.flatten_name("./Taxes//w2.pdf") == "w2.pdf"


def test_upload_hidden_name_is_made_visible(cfg):
    c, token = sign_in(cfg, "maya")
    assert upload(c, token, "other", ".hidden.txt", b"hello").status_code == 200
    created = [p for p in (cfg.files / "people/maya/other").iterdir()]
    assert len(created) == 1 and not created[0].name.startswith(".")


@pytest.mark.parametrize("folder", ["../dana/ids", "people/dana/ids", "ids/../../dana", "", "tls"])
def test_upload_bad_folder_is_rejected(cfg, folder):
    c, token = sign_in(cfg, "maya")
    r = upload(c, token, folder, "x.txt", b"hello")
    assert r.status_code == 400
    assert not list((cfg.files / "people/dana").rglob("x.txt"))


@pytest.mark.parametrize("name,data", [("run.sh", b"echo hi"), ("photo.exe", b"MZ"), ("noext", b"hi"),
                                       ("fake.pdf", b"not a pdf"), ("bad.json", b"{nope"),
                                       ("bin.txt", b"\x00\x01\x02")])
def test_upload_bad_type_is_rejected(cfg, name, data):
    c, token = sign_in(cfg, "maya")
    assert upload(c, token, "other", name, data).status_code == 400
    assert not (cfg.files / "people/maya/other").exists()


def test_upload_oversize_is_rejected(cfg, monkeypatch):
    # Block F raised the route's body limit to the 200 MB total, so the 413 is now checked against a
    # total cap set to one file's size (sending 200 MB in a test would be slow).
    monkeypatch.setattr(web, "MAX_TOTAL_UPLOAD", web.MAX_UPLOAD)
    c, token = sign_in(cfg, "maya")
    r = upload(c, token, "other", "big.txt", b"a" * (web.MAX_UPLOAD + 1))
    assert r.status_code == 400 and "25 MB" in r.text
    r = upload(c, token, "other", "huge.txt", b"a" * (web.MAX_UPLOAD + web.FORM_SLACK + 10))
    assert r.status_code == 413
    assert not (cfg.files / "people/maya/other").exists()


def test_post_without_csrf_is_refused(cfg):
    c, token = sign_in(cfg, "maya")
    r = c.post("/upload", data={"folder": "other"}, files={"file": ("a.txt", b"hi")})
    assert r.status_code == 403
    r = c.post("/upload", data={"folder": "other", "csrf": "wrong"}, files={"file": ("a.txt", b"hi")})
    assert r.status_code == 403
    assert c.post("/files/delete", data={"path": "people/maya/ids/passport_maya.txt"}).status_code == 403
    assert (cfg.files / "people/maya/ids/passport_maya.txt").exists()
    # Another session's token doesn't work either.
    _, other_token = sign_in(cfg, "dana")
    assert c.post("/files/delete", data={"path": "people/maya/ids/passport_maya.txt",
                                          "csrf": other_token}).status_code == 403
    # A cross-site Origin is refused even with the right token.
    r = c.post("/files/delete", data={"path": "people/maya/ids/passport_maya.txt", "csrf": token},
               headers={"origin": "https://evil.example"})
    assert r.status_code == 403


def test_signed_out_post_is_refused(cfg):
    c = client(cfg)
    assert c.post("/upload", data={"folder": "other", "csrf": "x"}, files={"file": ("a.txt", b"hi")}).status_code == 403


# --- files ---------------------------------------------------------------------------------------

def test_files_page_lists_only_readable(cfg):
    c, _ = sign_in(cfg, "maya")
    text = c.get("/files").text
    assert "people/maya/health/records_maya_fhir.json" in text and "shared/home/car_registration.txt" in text
    assert "people/dana" not in text and "people/sam" not in text


def test_delete_own_file_only(cfg):
    c, token = sign_in(cfg, "maya")
    own = "people/maya/school/fafsa_checklist.txt"
    assert c.post("/files/delete", data={"path": own, "csrf": token}).status_code == 200
    assert not (cfg.files / own).exists()
    assert not Store(cfg).search(cfg.person("maya"), "fafsa")
    for path in ("people/dana/taxes/w2_2025_dana.txt", "shared/home/car_registration.txt",
                 "people/maya/../dana/ids/passport_dana.txt", "../family.toml"):
        assert c.post("/files/delete", data={"path": path, "csrf": token}).status_code == 403
    assert (cfg.files / "people/dana/taxes/w2_2025_dana.txt").exists()
    assert (cfg.files / "shared/home/car_registration.txt").exists()
    assert (cfg.home / "family.toml").exists()


def test_parent_cannot_delete_childs_file_but_admin_can_delete_shared(cfg):
    c, token = sign_in(cfg, "dana")
    text = c.get("/files").text
    assert "people/maya/ids/passport_maya.txt" in text        # readable through also_reads
    assert c.post("/files/delete", data={"path": "people/maya/ids/passport_maya.txt",
                                          "csrf": token}).status_code == 403
    assert (cfg.files / "people/maya/ids/passport_maya.txt").exists()
    assert c.post("/files/delete", data={"path": "shared/home/car_registration.txt",
                                          "csrf": token}).status_code == 200
    assert not (cfg.files / "shared/home/car_registration.txt").exists()


# --- approvals -----------------------------------------------------------------------------------

def held_item(cfg, owner="dana", value="987-65-4320"):
    return Approvals(cfg).add("sam", "What is Dana's SSN?",
                              [Held("h1", "ssn", "SSN", value, owner, "people/dana/ids/ssn_card_dana.txt")])[0]


def test_approve_reveals_value_only_to_owner(cfg):
    item = held_item(cfg)
    maya, maya_token = sign_in(cfg, "maya")
    assert "987-65-4320" not in maya.get("/approvals").text
    r = maya.post(f"/approvals/{item}/approve", data={"csrf": maya_token})
    assert r.status_code == 404 and "987-65-4320" not in r.text
    assert Approvals(cfg).pending("dana")

    dana, token = sign_in(cfg, "dana")
    page = dana.get("/approvals").text
    assert "What is Dana&#x27;s SSN?" in page and "987-65-4320" not in page
    r = dana.post(f"/approvals/{item}/approve", data={"csrf": token})
    assert r.status_code == 200 and "987-65-4320" in r.text
    assert r.headers["cache-control"] == "no-store"
    assert not Approvals(cfg).pending("dana")
    # It is not shown again, and approving twice does nothing.
    assert "987-65-4320" not in dana.get("/approvals").text
    assert "987-65-4320" not in dana.post(f"/approvals/{item}/approve", data={"csrf": token}).text


def test_deny_records_it(cfg):
    item = held_item(cfg)
    dana, token = sign_in(cfg, "dana")
    r = dana.post(f"/approvals/{item}/deny", data={"csrf": token})
    assert r.status_code == 200 and "987-65-4320" not in r.text
    assert Approvals(cfg)._load()[item]["status"] == "denied"
    from familybox import ledger
    rep = ledger.verify_all(cfg.runtime, "dana")
    last = json.loads(ledger.log_path(cfg.runtime, "dana").read_text().splitlines()[-1])
    assert rep.ok and last["event"] == "denied" and last["item_id"] == item
    assert "987-65-4320" not in ledger.log_path(cfg.runtime, "dana").read_text()


def test_web_approve_is_logged_without_the_value(cfg):
    from familybox import ledger
    item = held_item(cfg)
    dana, token = sign_in(cfg, "dana")
    assert dana.post(f"/approvals/{item}/approve", data={"csrf": token}).status_code == 200
    rep = ledger.verify_all(cfg.runtime, "dana")
    text = ledger.log_path(cfg.runtime, "dana").read_text()
    assert rep.ok and json.loads(text.splitlines()[-1])["event"] == "approved"
    assert "987-65-4320" not in text


def test_approve_needs_csrf(cfg):
    item = held_item(cfg)
    dana, _ = sign_in(cfg, "dana")
    r = dana.post(f"/approvals/{item}/approve")
    assert r.status_code == 403 and "987-65-4320" not in r.text
    assert Approvals(cfg).pending("dana")


# --- cloud ---------------------------------------------------------------------------------------

MISSING = web.esc(web.CLOUD_MISSING)


def test_cloud_fallback_without_module(cfg, no_cloud):
    c, token = sign_in(cfg, "dana")
    assert MISSING in c.get("/cloud").text
    for path in ("/cloud/connect", "/cloud/import", "/cloud/backup", "/cloud/backup-key"):
        r = c.post(path, data={"csrf": token, "folder": "x"}, follow_redirects=False)
        assert r.status_code == 200 and MISSING in r.text
    r = client(cfg).get("/oauth/google/callback?state=s&code=c")
    assert MISSING in r.text


@pytest.fixture
def fake_cloud(monkeypatch):
    calls = []
    m = types.ModuleType("familybox.cloud")

    def status(cfg, person_id):
        return {"connected": True, "account_email": f"{person_id}@example.com", "last_import": "2026-11-08",
                "last_backup": None, "backup_key_set": False}

    def begin_connect(cfg, person_id, redirect_uri):
        calls.append(("begin", person_id, redirect_uri))
        return "https://accounts.google.com/o/oauth2/v2/auth?state=abc"

    def finish_connect(cfg, state, code):
        calls.append(("finish", state, code))
        if state != "good":
            raise ValueError("bad state")
        return {"connected": True, "account_email": "dana@example.com"}

    def import_folder(cfg, person_id, folder):
        calls.append(("import", person_id, folder))
        return {"imported": 3, "skipped": 1, "folder": folder}

    def backup_now(cfg):
        calls.append(("backup",))
        return {"bytes": 2048, "sha256": "ab" * 32, "drive_file_id": "f1"}

    def init_backup_key(cfg):
        calls.append(("key",))
        return "RECOVER-1234-WXYZ"

    for f in (status, begin_connect, finish_connect, import_folder, backup_now, init_backup_key):
        setattr(m, f.__name__, f)
    monkeypatch.setitem(sys.modules, "familybox.cloud", m)
    return calls


def test_cloud_happy_paths(cfg, fake_cloud):
    c, token = sign_in(cfg, "dana")
    page = c.get("/cloud").text
    assert "Google Drive is connected as dana@example.com" in page and "Back up now" in page

    r = c.post("/cloud/connect", data={"csrf": token}, follow_redirects=False)
    assert r.status_code == 303 and r.headers["location"].startswith("https://accounts.google.com/")
    assert fake_cloud[-1] == ("begin", "dana", "https://testserver/oauth/google/callback")

    r = c.post("/cloud/import", data={"csrf": token, "folder": "Tax papers"})
    assert "Imported 3 files. Skipped 1." in r.text and fake_cloud[-1] == ("import", "dana", "Tax papers")

    r = c.post("/cloud/backup", data={"csrf": token})
    assert "Backed up 2 KB" in r.text and fake_cloud[-1] == ("backup",)

    r = c.post("/cloud/backup-key", data={"csrf": token})
    assert "RECOVER-1234-WXYZ" in r.text and r.headers["cache-control"] == "no-store"
    assert "RECOVER-1234-WXYZ" not in c.get("/cloud").text


def test_cloud_redirect_env_and_admin_only(cfg, fake_cloud, monkeypatch):
    monkeypatch.setenv("FAMILYBOX_OAUTH_REDIRECT", "https://testserver/oauth/google/callback")
    c, token = sign_in(cfg, "maya")
    assert "Back up now" not in c.get("/cloud").text
    c.post("/cloud/connect", data={"csrf": token}, follow_redirects=False)
    assert fake_cloud[-1] == ("begin", "maya", "https://testserver/oauth/google/callback")
    assert c.post("/cloud/backup", data={"csrf": token}).status_code == 403
    assert c.post("/cloud/backup-key", data={"csrf": token}).status_code == 403
    assert ("backup",) not in fake_cloud and ("key",) not in fake_cloud
    assert c.post("/cloud/connect", follow_redirects=False).status_code == 403   # no CSRF


def test_oauth_callback_checks_state_through_cloud(cfg, fake_cloud):
    c = client(cfg)   # no session: the redirect back from Google carries no SameSite=Strict cookie
    r = c.get("/oauth/google/callback?state=good&code=xyz")
    assert r.status_code == 200 and "connected as dana@example.com" in r.text
    assert fake_cloud[-1] == ("finish", "good", "xyz")
    r = c.get("/oauth/google/callback?state=forged&code=xyz")
    assert r.status_code == 400 and "didn" in r.text
    assert c.get("/oauth/google/callback?error=access_denied").status_code == 400


def test_cloud_bad_auth_url_is_not_followed(cfg, fake_cloud, monkeypatch):
    import sys
    fc = sys.modules["familybox.cloud"]  # the fake installed by the fixture, as the web page sees it
    monkeypatch.setattr(fc, "begin_connect", lambda *a: "https://evil.example/login")
    c, token = sign_in(cfg, "dana")
    r = c.post("/cloud/connect", data={"csrf": token}, follow_redirects=False)
    assert r.status_code == 200 and "couldn" in r.text


# --- TLS -----------------------------------------------------------------------------------------

def test_cert_is_made_once_with_private_key(cfg):
    cert, key, fp = web.ensure_cert(cfg)
    assert stat.S_IMODE(key.stat().st_mode) == 0o600
    assert stat.S_IMODE((cfg.runtime / "tls").stat().st_mode) == 0o700
    assert re.fullmatch(r"([0-9A-F]{2}:){31}[0-9A-F]{2}", fp)
    assert web.ensure_cert(cfg)[2] == fp


def test_cli_code_command(cfg, monkeypatch, capsys):
    from familybox import cli
    monkeypatch.setenv("FAMILYBOX_HOME", str(cfg.home))
    assert cli.main(["code", "--as", "maya"]) == 0
    out = capsys.readouterr().out
    code = re.search(r"([A-Z0-9]{4})-([A-Z0-9]{4})", out)
    assert code
    assert web.WebState(cfg).redeem(code.group(0))[0] == "maya"
    assert cli.main(["code", "--as", "nobody"]) == 2


# --- Block F: a whole family's papers in one sitting --------------------------------------------

def upload_many(c, token, folder, files):
    return c.post("/upload", data={"folder": folder, "csrf": token},
                  files=[("file", (name, data)) for name, data in files])


def png_bytes() -> bytes:
    import io
    from PIL import Image
    out = io.BytesIO()
    Image.new("RGB", (64, 40), "white").save(out, "PNG")
    return out.getvalue()


def test_upload_page_offers_many_files_and_a_whole_folder(cfg):
    c, _ = sign_in(cfg, "maya")
    text = c.get("/upload").text
    assert 'name="file"' in text and " multiple" in text and "webkitdirectory" in text
    assert "<script" not in text and "style=" not in text
    assert "\u2014" not in text


def test_many_files_each_get_a_result(cfg):
    c, token = sign_in(cfg, "maya")
    r = upload_many(c, token, "school", [("a.txt", b"alpha kiwibird"), ("b.md", b"# beta"),
                                         ("run.sh", b"echo hi"), ("fake.pdf", b"nope")])
    assert r.status_code == 200
    assert "Uploaded 2 files, 2 left out" in r.text
    assert r.text.count("Saved in My School") == 2
    assert "That file type isn" in r.text and "real PDF" in r.text
    assert (cfg.files / "people/maya/school/a.txt").exists() and (cfg.files / "people/maya/school/b.md").exists()
    assert Store(cfg).search(cfg.person("maya"), "kiwibird")
    log = (cfg.runtime / "audit/maya.jsonl").read_text()
    assert log.count('"event": "upload"') == 2 and "a.txt" not in log


def test_whole_folder_is_flattened_and_climbing_out_is_refused(cfg):
    c, token = sign_in(cfg, "maya")
    r = upload_many(c, token, "other", [
        ("Papers/2025/w2.txt", b"w2"), ("Papers/notes.txt", b"notes"),
        ("Papers/.git/config.txt", b"hidden"), ("Papers/../../evil.txt", b"evil"),
        ("/etc/passwd.txt", b"root"), ("Papers\\sub\\win.txt", b"win")])
    assert r.status_code == 200
    names = sorted(p.name for p in (cfg.files / "people/maya/other").iterdir())
    assert names == ["2025_w2.txt", "notes.txt", "sub_win.txt"]
    assert r.text.count("outside the folder") == 2 and "hidden system file" in r.text
    assert not list(cfg.home.rglob("evil.txt")) and not list(cfg.home.rglob("passwd.txt"))


def test_too_many_files_and_total_cap(cfg, monkeypatch):
    c, token = sign_in(cfg, "maya")
    r = upload_many(c, token, "other", [(f"f{i}.txt", b"x") for i in range(web.MAX_FILES + 1)])
    assert r.status_code == 400 and f"up to {web.MAX_FILES}" in r.text
    r = upload_many(c, token, "other", [(f"f{i}.txt", b"x") for i in range(web.MAX_FILES + 5)])
    assert r.status_code == 400 and f"up to {web.MAX_FILES}" in r.text
    assert not (cfg.files / "people/maya/other").exists()
    monkeypatch.setattr(web, "MAX_TOTAL_UPLOAD", 10)
    r = upload_many(c, token, "other", [("one.txt", b"12345678"), ("two.txt", b"12345678")])
    assert r.status_code == 200 and "in total" in r.text
    assert [p.name for p in (cfg.files / "people/maya/other").iterdir()] == ["one.txt"]


def test_no_file_chosen(cfg):
    c, token = sign_in(cfg, "maya")
    r = c.post("/upload", data={"folder": "other", "csrf": token}, files=[("file", ("", b""))])
    assert r.status_code == 400 and "Choose a file" in r.text


def test_can_file_is_separate_from_can_read(cfg):
    from familybox import access
    dana, sam, maya = cfg.person("dana"), cfg.person("sam"), cfg.person("maya")
    assert access.can_file(dana, "people/maya/ids/x.txt") and access.can_read(dana, "people/maya/ids/x.txt")
    # Health: the admin may drop off, but still can't read.
    assert access.can_file(dana, "people/maya/health/x.txt")
    assert not access.can_read(dana, "people/maya/health/x.txt")
    # Not for folders she doesn't look after, not for a non-admin, not by climbing out.
    assert not access.can_file(dana, "people/maya/other/x.txt")
    assert not access.can_file(sam, "people/maya/health/x.txt")
    assert not access.can_file(maya, "people/dana/health/x.txt")
    assert not access.can_file(dana, "people/maya/health/../../dana/x.txt")
    assert not access.can_file(dana, "people/maya/ids/../health/x.txt")
    assert not access.can_file(dana, "../people/maya/ids/x.txt")
    assert not access.can_file(dana, "people/maya/health")       # a folder, not a file in it


def test_parent_files_into_childs_folder_and_both_logs_show_it(cfg):
    c, token = sign_in(cfg, "dana")
    text = c.get("/upload").text
    assert 'value="people/maya/ids"' in text and "Maya&#x27;s IDs" in text
    assert 'value="people/maya/health"' in text and "only they can open it" in text
    assert 'value="people/maya/other"' not in text
    r = upload_many(c, token, "people/maya/ids", [("ssn card.txt", b"SSN card for Maya pangolin")])
    assert r.status_code == 200 and "Saved in Maya&#x27;s IDs" in r.text
    assert (cfg.files / "people/maya/ids/ssn card.txt").exists()
    assert Store(cfg).search(cfg.person("maya"), "pangolin")
    dana_log = (cfg.runtime / "audit/dana.jsonl").read_text()
    maya_log = (cfg.runtime / "audit/maya.jsonl").read_text()
    assert '"for": "maya"' in dana_log and '"by": "dana"' in maya_log
    assert "ssn card" not in dana_log + maya_log and "pangolin" not in dana_log + maya_log
    # Sam isn't an admin: no health drop-off for him, and the server refuses it too.
    c2, token2 = sign_in(cfg, "sam")
    assert 'value="people/maya/health"' not in c2.get("/upload").text
    assert upload(c2, token2, "people/maya/health", "x.txt", b"hi").status_code == 400
    # Maya can't file into Dana's folders.
    c3, token3 = sign_in(cfg, "maya")
    assert upload(c3, token3, "people/dana/ids", "x.txt", b"hi").status_code == 400
    assert not list((cfg.files / "people/dana").rglob("x.txt"))


def test_health_drop_off_is_file_only_never_read(cfg):
    c, token = sign_in(cfg, "dana")
    r = upload_many(c, token, "people/maya/health", [("flu shot.txt", b"Flu shot 2026 okapivaccine"),
                                                    ("dentist.txt", b"Dentist visit")])
    assert r.status_code == 200 and "Only Maya can open it" in r.text
    assert (cfg.files / "people/maya/health/flu shot.txt").exists()
    files = c.get("/files").text
    assert "2 files filed for Maya" in files
    assert "flu shot" not in files and "dentist" not in files and "people/maya/health" not in files
    assert not Store(cfg).search(cfg.person("dana"), "okapivaccine")
    assert Store(cfg).search(cfg.person("maya"), "okapivaccine")
    c2, _ = sign_in(cfg, "maya")
    assert "people/maya/health/flu shot.txt" in c2.get("/files").text
    # Dana still can't delete it.
    assert c.post("/files/delete", data={"path": "people/maya/health/flu shot.txt", "csrf": token}).status_code == 403
    maya_log = (cfg.runtime / "audit/maya.jsonl").read_text()
    assert maya_log.count('"by": "dana"') == 2 and "flu" not in maya_log
    # Once Maya removes one, the count goes down.
    (cfg.files / "people/maya/health/dentist.txt").unlink()
    assert "1 file filed for Maya" in c.get("/files").text


class _FakeReader:
    def __init__(self, text="SSN: 987-65-4329"):
        self.text, self.calls = text, 0

    async def __call__(self, prep, *, api_key, model, emit=None, attestation_max_age_s=300, client_options=None):
        from familybox import vision
        self.calls += 1
        return vision.Transcription(self.text, model, "0xabcdef0123456789abcdef", "provider_tee", 0.1,
                                    {"model_reports_verified": 1}, 10, 20)


@pytest.fixture
def reader(monkeypatch):
    from familybox import vision
    f = _FakeReader()
    monkeypatch.setattr(vision, "TRANSCRIBER", [f])
    monkeypatch.setenv("FAMILYBOX_PIN_LEVEL", "off")
    return f


def test_photo_on_upload_page_waits_without_a_key(cfg, reader, monkeypatch):
    monkeypatch.delenv("NEAR_AI_CLOUD_API_KEY", raising=False)
    monkeypatch.delenv("NEARAI_API_KEY", raising=False)
    c, token = sign_in(cfg, "maya")
    r = upload_many(c, token, "ids", [("card.png", png_bytes()), ("note.txt", b"a note")])
    assert r.status_code == 200 and "not read yet" in r.text and "AI key" in r.text
    assert reader.calls == 0
    assert (cfg.files / "people/maya/ids/card.png").exists()
    assert not (cfg.files / "people/maya/ids/card.png.transcript.txt").exists()
    assert "card.png" in c.get("/photos").text


def test_photo_on_upload_page_is_read_with_a_key(cfg, reader, monkeypatch):
    monkeypatch.setenv("NEAR_AI_CLOUD_API_KEY", "test-key-not-real")
    c, token = sign_in(cfg, "maya")
    r = upload_many(c, token, "ids", [("card.png", png_bytes()), ("scan.heic", b"\x00\x00\x00\x18ftypheic....")])
    assert r.status_code == 200 and "Photo saved and read" in r.text and "ending 4329" in r.text
    assert "987-65-4329" not in r.text
    assert "HEIC" in r.text and not (cfg.files / "people/maya/ids/scan.heic").exists()
    assert (cfg.files / "people/maya/ids/card.png.transcript.txt").exists()
    assert reader.calls == 1


def test_photo_drop_off_into_health_is_read_but_not_shown(cfg, reader, monkeypatch):
    monkeypatch.setenv("NEAR_AI_CLOUD_API_KEY", "test-key-not-real")
    c, token = sign_in(cfg, "dana")
    r = upload_many(c, token, "people/maya/health", [("zzcard.png", png_bytes())])
    assert r.status_code == 200 and "Only Maya can open it" in r.text
    assert "4329" not in r.text and "SSN" not in r.text
    assert (cfg.files / "people/maya/health/zzcard.png.transcript.txt").exists()
    files = c.get("/files").text
    assert "1 file filed for Maya" in files and "zzcard" not in files
    assert "zzcard" not in c.get("/photos").text
    maya_log = (cfg.runtime / "audit/maya.jsonl").read_text()
    assert '"event": "photo_upload"' in maya_log and '"by": "dana"' in maya_log


def test_home_is_a_question_box_and_the_menu_is_grouped(cfg):
    """Signed in, the home page is one question box that posts to the Activity plugin, with a side menu:
    everyday pages first, the rest under "Box settings"."""
    c, _ = sign_in(cfg, "maya")
    r = c.get("/")
    t = r.text
    assert '<body class="app">' in t and '<aside class="side">' in t and "Signed in as Maya" in t
    assert 'action="/activity/ask" class="composer"' in t and 'name="question"' in t and "autofocus" in t
    assert t.count('<input type="hidden" name="question"') == len(web.SUGGESTIONS)
    assert '<a href="/" class="here">New question</a>' in t
    menu = t[t.index("<nav>"):t.index("</nav>")]
    assert menu.index('href="/approvals"') < menu.index("Box settings") < menu.index('href="/cloud"')
    assert "<script" not in t and "style=" not in t and "—" not in t
    out = client(cfg).get("/signin").text                        # signed out: no menu
    assert '<body class="plain">' in out and "<aside" not in out
