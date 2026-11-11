"""First-time setup, PINs, the Family page and invites (Block A). No network, temp homes only."""

import json
import os
import re
import shutil
import stat
import time
import tomllib
from pathlib import Path

import pytest
from starlette.testclient import TestClient

from familybox import access, config, household, remote, web
from familybox.household import HouseholdError
from familybox.store import Store

DEMO = Path(__file__).resolve().parents[1] / "demo"
PIN = "246813"


@pytest.fixture
def empty(tmp_path, monkeypatch):
    """A brand new box: no family.toml, setup window just opened."""
    monkeypatch.setattr(household, "STARTED", time.time())
    monkeypatch.delenv("FAMILYBOX_OAUTH_REDIRECT", raising=False)
    home = tmp_path / "newbox"
    home.mkdir()
    return config.load(home)


@pytest.fixture
def cfg(tmp_path, monkeypatch):
    shutil.copytree(DEMO / "files", tmp_path / "files")
    shutil.copy(DEMO / "family.toml", tmp_path / "family.toml")
    monkeypatch.delenv("FAMILYBOX_OAUTH_REDIRECT", raising=False)
    c = config.load(tmp_path)
    Store(c).reindex()
    return c


def client(c) -> TestClient:
    return TestClient(web.create_app(c), base_url="https://testserver")


def csrf(resp) -> str:
    m = re.search(r'name="csrf" value="([^"]+)"', resp.text)
    assert m, resp.text
    return m.group(1)


def sign_in(c, person) -> tuple[TestClient, str]:
    cl = client(c)
    code = web.issue_code(c, person)
    r = cl.post("/signin", data={"code": code, "csrf": csrf(cl.get("/signin"))}, follow_redirects=False)
    assert r.status_code == 303
    return cl, csrf(cl.get("/"))


def audit(c, pid) -> list[dict]:
    p = c.runtime / "audit" / f"{pid}.jsonl"
    return [json.loads(x) for x in p.read_text().splitlines() if x.strip()] if p.exists() else []


def do_setup(c, family="The Okafor family", name="Dana", pin=PIN, pin2=None):
    cl = client(c)
    r = cl.get("/setup")
    return cl, cl.post("/setup", data={"family": family, "name": name, "pin": pin, "pin2": pin2 or pin,
                                       "csrf": csrf(r)}, follow_redirects=False)


# --- config ---------------------------------------------------------------------------------------

def test_load_tolerates_an_empty_home(tmp_path):
    c = config.load(tmp_path)
    assert c.people == {} and c.name == "Family box"


def test_save_round_trips_and_keeps_other_tables(tmp_path):
    (tmp_path / "family.toml").write_text(
        '[box]\nname = "Old"\nvision_model = "v"\n\n[pins]\nlevel = "warn"\n\n'
        '[remote]\npublic_url = "https://box.example"\n\n[paraphrase_check]\nenabled = "off"\nthreshold = 0.5\n'
        '[people.a]\ndisplay = "A"\nadmin = true\n')
    people = {"b": config.Person(id="b", display='Bo "B" \\ Smith', admin=True, also_reads=("people/c/ids",),
                                 never_share=("Lake\nside",))}
    config.save(tmp_path, name="New", people=people)
    data = tomllib.loads((tmp_path / "family.toml").read_text())
    assert data["box"] == {"name": "New", "vision_model": "v"}
    assert data["pins"] == {"level": "warn"} and data["remote"]["public_url"] == "https://box.example"
    assert data["paraphrase_check"] == {"enabled": "off", "threshold": 0.5}
    assert list(data["people"]) == ["b"]
    c = config.load(tmp_path)
    assert c.people["b"] == people["b"]
    assert stat.S_IMODE((tmp_path / "family.toml").stat().st_mode) == 0o600


def test_reload_updates_the_shared_config_in_place(tmp_path):
    c = config.load(tmp_path)
    people = c.people
    config.save(tmp_path, name="Okafor", people={"dana": config.Person(id="dana", display="Dana", admin=True)})
    assert config.reload(c) is c
    assert c.people is people and list(c.people) == ["dana"] and c.name == "Okafor"


def test_stored_key_is_loaded_only_when_no_key_is_set(tmp_path, monkeypatch):
    for k in config.KEY_ENV:
        monkeypatch.setenv(k, "x")
        monkeypatch.delenv(k)
    kp = config.key_path(tmp_path)
    kp.parent.mkdir(parents=True)
    kp.write_text("test-key-not-real\n")
    config.load(tmp_path)
    assert os.environ["NEAR_AI_CLOUD_API_KEY"] == "test-key-not-real"
    monkeypatch.setenv("NEAR_AI_CLOUD_API_KEY", "already-set")
    config.load(tmp_path)
    assert os.environ["NEAR_AI_CLOUD_API_KEY"] == "already-set"


# --- household state ------------------------------------------------------------------------------

@pytest.mark.parametrize("pin,ok", [("246813", True), ("123456789012", True), ("12345", False),
                                    ("1234567890123", False), ("111111", False), ("12a456", False),
                                    ("١٢٣٤٥٦", False), ("", False)])
def test_pin_rules(pin, ok):
    assert (household.pin_problem(pin) is None) is ok


def test_pins_are_hashed_and_checked(cfg):
    st = web.WebState(cfg)
    household.set_pin(st, "maya", PIN)
    raw = (cfg.runtime / "web" / household.PINS).read_text()
    assert PIN not in raw and "maya" in raw
    assert stat.S_IMODE((cfg.runtime / "web" / household.PINS).stat().st_mode) == 0o600
    assert household.check_pin(st, "maya", PIN) == (True, None)
    assert household.check_pin(st, "maya", "999999") == (False, "wrong")
    assert household.check_pin(st, "sam", PIN) == (False, "wrong")      # no PIN set
    assert household.check_pin(st, "nobody", PIN) == (False, "wrong")
    with pytest.raises(HouseholdError):
        household.set_pin(st, "maya", "000000")


def test_pin_lockout_is_per_person(cfg):
    st = web.WebState(cfg)
    household.set_pin(st, "maya", PIN)
    household.set_pin(st, "dana", "135792")
    for _ in range(web.LOCKOUT_MAX):
        household.check_pin(st, "maya", "999999")
    assert household.check_pin(st, "maya", PIN) == (False, "locked")
    assert household.check_pin(st, "dana", "135792") == (True, None)    # a child can't lock a parent out
    now = time.time()
    assert not household.pin_locked(st, "maya", now + web.LOCKOUT_WINDOW_S + 1)


def test_setup_window(empty, monkeypatch):
    assert household.setup_open(empty)
    assert not household.setup_open(empty, household.STARTED + household.SETUP_WINDOW_S + 1)
    st = web.WebState(empty)
    person = household.setup_family(st, "Okafor", "Dana Okafor", PIN)
    assert person.id == "dana-okafor" and person.admin and empty.name == "Okafor"
    assert not household.setup_open(empty)
    with pytest.raises(HouseholdError):
        household.setup_family(st, "Other", "Eve", PIN)


def test_slugs_are_unique_and_plain():
    assert household.slug("Maya Okafor", []) == "maya-okafor"
    assert household.slug("Maya", ["maya", "maya-2"]) == "maya-3"
    assert household.slug("José", []) == "jose"
    assert household.slug("***", []) == "person"
    assert household.slug("../etc", []) == "etc"


def test_add_grant_and_access_match_can_read(cfg):
    st = web.WebState(cfg)
    kim = household.add_person(st, "Kim")
    assert kim.id == "kim" and "kim" in cfg.people and not kim.admin
    household.set_also_reads(st, "kim", ["people/maya/ids", "people/maya/school"])
    k = cfg.person("kim")
    assert access.can_read(k, "people/maya/ids/passport.txt")
    assert access.can_read(k, "people/maya/school/r.txt")
    assert not access.can_read(k, "people/maya/health/x.txt")
    assert not access.can_read(k, "people/maya/taxes/x.txt")
    assert config.load(cfg.home).people["kim"] == k             # it is on disk too
    for bad in (["people/maya/health"], ["people/kim/ids"], ["people/ghost/ids"], ["people/maya"],
                ["people/maya/ids/../health"]):
        with pytest.raises(HouseholdError):
            household.set_also_reads(st, "kim", bad)
    assert cfg.person("kim").also_reads == ("people/maya/ids", "people/maya/school")
    with pytest.raises(HouseholdError):
        household.add_person(st, "kim")                          # same name twice


def test_never_share_words(cfg):
    st = web.WebState(cfg)
    p = household.set_never_share(st, "maya", ["  Lakeside  Clinic ", "", "lakeside clinic", "Dr. Ruiz"])
    assert p.never_share == ("Lakeside Clinic", "Dr. Ruiz")
    with pytest.raises(HouseholdError):
        household.set_never_share(st, "maya", ["x" * 101])


def test_remove_person_cleans_up_and_never_reuses_the_id(cfg):
    st = web.WebState(cfg)
    household.set_pin(st, "maya", PIN)
    st.issue_code("maya")
    st.new_session("maya")
    gone = household.remove_person(st, "maya", by="dana")
    assert gone.id == "maya" and "maya" not in cfg.people
    assert not any(g.startswith("people/maya/") for p in cfg.people.values() for g in p.also_reads)
    assert not household.has_pin(st, "maya")
    assert all(v["person"] != "maya" for v in st._load("sessions.json", {}).values())
    assert all(v["person"] != "maya" for v in st._load("codes.json", {}).values())
    assert (cfg.files / "people/maya").is_dir()                  # files stay
    assert household.unowned_folders(cfg)[0][0] == "people/maya"
    assert household.add_person(st, "Maya").id == "maya-2"       # never inherits the old folder
    with pytest.raises(HouseholdError):
        household.remove_person(st, "dana", by="dana")


# --- setup gate and /setup ------------------------------------------------------------------------

def test_empty_home_sends_every_page_to_setup(empty):
    cl = client(empty)
    for path in ("/", "/signin", "/files", "/upload", "/family", "/join", "/approvals"):
        r = cl.get(path, follow_redirects=False)
        assert r.status_code == 303 and r.headers["location"] == "/setup", path
    assert cl.post("/signin", data={}, follow_redirects=False).headers["location"] == "/setup"
    assert cl.get("/static/style.css").status_code == 200
    r = cl.get("/setup")
    assert r.status_code == 200 and "Set up your family box" in r.text
    assert r.headers["content-security-policy"].startswith("default-src 'self'")
    assert "style=" not in r.text and "<script" not in r.text and "—" not in r.text


def test_setup_works_once(empty):
    cl, r = do_setup(empty)
    assert r.status_code == 303 and r.headers["location"] == "/"
    home = cl.get("/")
    assert "Signed in as Dana" in home.text and "The Okafor family" in home.text
    assert empty.person("dana").admin
    raw = (empty.runtime / "web" / household.PINS).read_text()
    assert PIN not in raw
    entries = audit(empty, "dana")
    assert [e["event"] for e in entries][-1] == "setup"
    assert PIN not in json.dumps(entries)
    # A second visitor can't run setup again.
    cl2 = client(empty)
    assert cl2.get("/setup", follow_redirects=False).headers["location"] == "/signin"
    r2 = cl2.post("/setup", data={"family": "x", "name": "Eve", "pin": PIN, "pin2": PIN, "csrf": "x"})
    assert r2.status_code == 403 and list(empty.people) == ["dana"]


def test_setup_refuses_bad_input_and_csrf(empty):
    _, r = do_setup(empty, pin2="246814")
    assert r.status_code == 400 and "match" in r.text and not empty.people
    _, r = do_setup(empty, pin="111111")
    assert r.status_code == 400 and not empty.people
    _, r = do_setup(empty, name="  ")
    assert r.status_code == 400 and not empty.people
    cl = client(empty)
    cl.get("/setup")
    r = cl.post("/setup", data={"family": "x", "name": "Eve", "pin": PIN, "pin2": PIN, "csrf": "wrong"})
    assert r.status_code == 403 and not empty.people
    r = cl.post("/setup", data={"family": "x", "name": "Eve", "pin": PIN, "pin2": PIN,
                                "csrf": csrf(cl.get("/setup"))}, headers={"origin": "https://evil.example"})
    assert r.status_code == 403 and not empty.people


def test_setup_closes_after_the_window(empty, monkeypatch):
    monkeypatch.setattr(household, "STARTED", time.time() - household.SETUP_WINDOW_S - 1)
    cl = client(empty)
    r = cl.get("/setup")
    assert r.status_code == 403 and "Unplug the box and plug it back in to start setup" in r.text
    assert 'name="csrf"' not in r.text
    monkeypatch.setattr(household, "STARTED", time.time())
    token = csrf(cl.get("/setup"))
    monkeypatch.setattr(household, "STARTED", time.time() - household.SETUP_WINDOW_S - 1)
    r = cl.post("/setup", data={"family": "x", "name": "Eve", "pin": PIN, "pin2": PIN, "csrf": token})
    assert r.status_code == 403 and not empty.people


# --- PIN sign-in ----------------------------------------------------------------------------------

def pin_signin(cl, person, pin):
    return cl.post("/signin", data={"person": person, "pin": pin, "csrf": csrf(cl.get("/signin"))},
                   follow_redirects=False)


def test_pin_sign_in_and_code_sign_in_both_work(cfg):
    st = web.WebState(cfg)
    household.set_pin(st, "maya", PIN)
    cl = client(cfg)
    page = cl.get("/signin").text
    assert "Sign in with your PIN" in page and '<option value="maya">Maya</option>' in page
    assert '<option value="sam">' not in page                   # only names with a PIN are listed
    r = pin_signin(cl, "maya", PIN)
    assert r.status_code == 303 and "Signed in as Maya" in cl.get("/").text
    cl2 = client(cfg)
    assert pin_signin(cl2, "maya", "999999").status_code == 401
    assert cl2.get("/", follow_redirects=False).status_code == 303
    sign_in(cfg, "sam")                                          # the old one-time code still works


def test_pin_sign_in_locks_out_one_name(cfg):
    st = web.WebState(cfg)
    household.set_pin(st, "maya", PIN)
    household.set_pin(st, "dana", "135792")
    cl = client(cfg)
    for _ in range(web.LOCKOUT_MAX):
        pin_signin(cl, "maya", "999999")
    r = pin_signin(cl, "maya", PIN)
    assert r.status_code == 429 and "Too many wrong PINs" in r.text
    assert pin_signin(client(cfg), "dana", "135792").status_code == 303
    sign_in(cfg, "maya")                                         # a code still works for Maya


def test_pin_sign_in_needs_csrf(cfg):
    household.set_pin(web.WebState(cfg), "maya", PIN)
    cl = client(cfg)
    cl.get("/signin")
    assert cl.post("/signin", data={"person": "maya", "pin": PIN}).status_code == 403


# --- Family page ----------------------------------------------------------------------------------

def test_family_pages_are_admin_only(cfg):
    cl, token = sign_in(cfg, "maya")
    assert cl.get("/family").status_code == 403
    for path, data in (("/family/add", {"name": "Eve"}), ("/family/access", {"person": "maya"}),
                       ("/family/remove", {"person": "sam", "confirm": "Sam"}),
                       ("/family/invite", {"person": "maya"})):
        assert cl.post(path, data=data | {"csrf": token}).status_code == 403, path
    assert "eve" not in cfg.people and "sam" in cfg.people
    anon = client(cfg)
    assert anon.get("/family", follow_redirects=False).headers["location"] == "/signin"
    assert anon.post("/family/add", data={"name": "Eve"}).status_code == 403


def test_family_page_add_and_access(cfg):
    cl, token = sign_in(cfg, "dana")
    page = cl.get("/family")
    assert page.status_code == 200 and "Add a person" in page.text
    assert "style=" not in page.text and "<script" not in page.text and "—" not in page.text
    assert 'value="people/maya/health"' not in page.text         # health is never offered
    r = cl.post("/family/add", data={"name": "Kim", "csrf": token})
    assert r.status_code == 200 and "Added Kim" in r.text and "kim" in cfg.people
    r = cl.post("/family/access", data={"person": "kim", "grant": ["people/maya/ids", "people/sam/taxes"],
                                        "never_share": "Lakeside Clinic\n\nDr. Ruiz", "csrf": token})
    assert r.status_code == 200 and "Saved for Kim" in r.text
    kim = cfg.person("kim")
    assert access.can_read(kim, "people/maya/ids/passport.txt")
    assert access.can_read(kim, "people/sam/taxes/w2.txt")
    assert not access.can_read(kim, "people/maya/school/r.txt")
    assert kim.never_share == ("Lakeside Clinic", "Dr. Ruiz")
    r = cl.post("/family/access", data={"person": "kim", "grant": ["people/maya/health"], "csrf": token})
    assert r.status_code == 400 and "Health" in r.text
    assert not access.can_read(cfg.person("kim"), "people/maya/health/x.txt")
    events = audit(cfg, "dana")
    added = [e for e in events if e["event"] == "person_added"]
    changed = [e for e in events if e["event"] == "access_changed"]
    assert added[-1]["person"] == "kim"
    assert changed[-1]["also_reads"] == ["people/maya/ids", "people/sam/taxes"]
    assert changed[-1]["never_share_count"] == 2 and "Lakeside" not in json.dumps(events)
    r = cl.post("/family/access", data={"person": "kim", "csrf": "wrong"})
    assert r.status_code == 403


def test_family_remove_needs_the_typed_name(cfg):
    cl, token = sign_in(cfg, "dana")
    maya, _ = sign_in(cfg, "maya")
    r = cl.post("/family/remove", data={"person": "maya", "confirm": "Mya", "csrf": token})
    assert r.status_code == 400 and "maya" in cfg.people
    r = cl.post("/family/remove", data={"person": "dana", "confirm": "Dana", "csrf": token})
    assert r.status_code == 400 and "dana" in cfg.people
    r = cl.post("/family/remove", data={"person": "maya", "confirm": " maya ", "csrf": token})
    assert r.status_code == 200 and "Removed Maya" in r.text and "maya" not in cfg.people
    assert "Files with no owner" in r.text and "people/maya" in r.text
    assert maya.get("/", follow_redirects=False).status_code == 303   # their session is gone
    assert audit(cfg, "dana")[-1]["event"] == "person_removed"


# --- invites --------------------------------------------------------------------------------------

def invite(cl, token, person):
    r = cl.post("/family/invite", data={"person": person, "csrf": token})
    assert r.status_code == 200, r.text
    code = re.search(r'<div class="value">([A-Z0-9]{8})</div>', r.text).group(1)
    return r, code


def join(cl, code, pin=PIN, pin2=None):
    page = cl.get(f"/join?c={code}")
    return cl.post("/join", data={"code": code, "pin": pin, "pin2": pin2 or pin, "csrf": csrf(page)},
                   follow_redirects=False)


def test_invite_shows_code_link_and_qr(cfg):
    cl, token = sign_in(cfg, "dana")
    r, code = invite(cl, token, "maya")
    assert f"https://testserver/join?c={code}" in r.text
    svg = re.search(r'<div class="qr">(<svg.*?</svg>)</div>', r.text, re.S).group(1)
    assert "style=" not in svg and "<script" not in svg and "href" not in svg
    assert "30 minutes" in r.text and "—" not in r.text
    ev = audit(cfg, "dana")[-1]
    assert ev["event"] == "invite_issued" and ev["person"] == "maya" and code not in json.dumps(ev)
    assert code not in (cfg.runtime / "web" / "codes.json").read_text()


def test_join_sets_a_pin_once(cfg):
    cl, token = sign_in(cfg, "dana")
    _, code = invite(cl, token, "maya")
    phone = client(cfg)
    page = phone.get(f"/join?c={code.lower()}")
    assert page.status_code == 200 and f'value="{code}"' in page.text and "style=" not in page.text
    assert join(phone, code, pin2="246814").status_code == 400    # PIN typo doesn't use up the invite
    assert join(phone, code, pin="111111").status_code == 400
    r = join(phone, code)
    assert r.status_code == 303 and "Signed in as Maya" in phone.get("/").text
    assert household.check_pin(web.WebState(cfg), "maya", PIN) == (True, None)
    assert join(client(cfg), code).status_code == 401             # works once
    assert audit(cfg, "maya")[-1]["event"] == "joined"
    assert PIN not in json.dumps(audit(cfg, "maya"))


def test_invite_expires_after_30_minutes(cfg, monkeypatch):
    cl, token = sign_in(cfg, "dana")
    _, code = invite(cl, token, "maya")
    now = time.time()
    monkeypatch.setattr(web.time, "time", lambda: now + web.INVITE_TTL_S + 1)
    phone = client(cfg)
    page = phone.get(f"/join?c={code}")
    r = phone.post("/join", data={"code": code, "pin": PIN, "pin2": PIN, "csrf": csrf(page)})
    assert r.status_code == 401 and not household.has_pin(web.WebState(cfg), "maya")


def test_issue_code_ttl(cfg):
    st = web.WebState(cfg)
    st.issue_code("maya", ttl=web.INVITE_TTL_S)
    exp = list(st._load("codes.json", {}).values())[0]["expires"]
    assert web.INVITE_TTL_S - 5 < exp - time.time() <= web.INVITE_TTL_S
    with pytest.raises(ValueError):
        st.issue_code("maya", ttl=web.INVITE_TTL_S + 1)


def test_join_needs_csrf(cfg):
    st = web.WebState(cfg)
    code = st.issue_code("maya", ttl=web.INVITE_TTL_S)
    phone = client(cfg)
    phone.get("/join")
    assert phone.post("/join", data={"code": code, "pin": PIN, "pin2": PIN}).status_code == 403
    assert not household.has_pin(st, "maya")


# --- the internet listener gains nothing -----------------------------------------------------------

def test_new_pages_are_not_on_the_remote_listener(cfg, empty):
    for path in ("/setup", "/family", "/family/add", "/family/access", "/family/remove", "/family/invite", "/join"):
        assert path not in remote.REMOTE_PATHS
    for c in (cfg, empty):
        cl = TestClient(web.create_app(c, remote_only=True), base_url="https://testserver")
        for path in ("/setup", "/family", "/join", "/signin"):
            assert cl.get(path, follow_redirects=False).status_code == 404, path
