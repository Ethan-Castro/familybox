"""The box's private web page: code sign-in, uploads, files, approvals and the cloud page (no network)."""

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
    assert r.headers["referrer-policy"] == "no-referrer"
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


@pytest.mark.parametrize("name", ["../../family.toml.txt", "..\\..\\evil.txt", "/etc/passwd.txt", ".hidden.txt"])
def test_upload_filename_cannot_escape(cfg, name):
    c, token = sign_in(cfg, "maya")
    assert upload(c, token, "other", name, b"hello").status_code == 200
    created = [p for p in (cfg.files / "people/maya/other").iterdir()]
    assert len(created) == 1 and not created[0].name.startswith(".")
    assert not (cfg.home / "family.toml.txt").exists() and not (cfg.home / "evil.txt").exists()


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


def test_upload_oversize_is_rejected(cfg):
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
    assert fake_cloud[-1] == ("begin", "dana", "https://127.0.0.1:8443/oauth/google/callback")

    r = c.post("/cloud/import", data={"csrf": token, "folder": "Tax papers"})
    assert "Imported 3 files. Skipped 1." in r.text and fake_cloud[-1] == ("import", "dana", "Tax papers")

    r = c.post("/cloud/backup", data={"csrf": token})
    assert "Backed up 2 KB" in r.text and fake_cloud[-1] == ("backup",)

    r = c.post("/cloud/backup-key", data={"csrf": token})
    assert "RECOVER-1234-WXYZ" in r.text and r.headers["cache-control"] == "no-store"
    assert "RECOVER-1234-WXYZ" not in c.get("/cloud").text


def test_cloud_redirect_env_and_admin_only(cfg, fake_cloud, monkeypatch):
    monkeypatch.setenv("FAMILYBOX_OAUTH_REDIRECT", "https://box.local:8443/oauth/google/callback")
    c, token = sign_in(cfg, "maya")
    assert "Back up now" not in c.get("/cloud").text
    c.post("/cloud/connect", data={"csrf": token}, follow_redirects=False)
    assert fake_cloud[-1] == ("begin", "maya", "https://box.local:8443/oauth/google/callback")
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
    import familybox.cloud as fc
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
