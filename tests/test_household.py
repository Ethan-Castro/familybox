"""First-time setup, PINs, the Family page and invites (Block A). No network, temp homes only."""

import html
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


def test_stale_sign_in_tab_gets_a_fresh_form(cfg):
    """Two sign-in tabs: the older one's token no longer matches the cookie. The box shows a fresh form
    (nothing done) instead of a dead end, and signing in from it works."""
    household.set_pin(web.WebState(cfg), "maya", PIN)
    cl = client(cfg)
    old = csrf(cl.get("/signin"))
    cl.get("/signin")                                            # a second tab resets the cookie
    r = cl.post("/signin", data={"person": "maya", "pin": PIN, "csrf": old})
    assert r.status_code == 403 and "out of date" in r.text and web.COOKIE not in cl.cookies
    r = cl.post("/signin", data={"person": "maya", "pin": PIN, "csrf": csrf(r)})
    assert r.status_code == 200 and web.COOKIE in cl.cookies     # signed in, sent on to the home page
    r = client(cfg).post("/signin", data={"person": "maya", "pin": PIN, "csrf": old},
                         headers={"origin": "https://evil.example"})
    assert r.status_code == 403 and "out of date" not in r.text  # other sites still get the plain refusal


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


# --- Block B: the AI key and the status page ------------------------------------------------------

FAKE_KEY = "test-key-not-real-0123456789"


@pytest.fixture
def no_key(monkeypatch):
    for k in config.KEY_ENV:
        monkeypatch.setenv(k, "x")   # setenv first, so the delete is undone after the test
        monkeypatch.delenv(k)


def fake_check(monkeypatch, result, seen=None):
    from familybox import cli

    async def check(key, model):
        if seen is not None:
            seen.append((key, model))
        return result
    monkeypatch.setattr(cli, "check_attestation", check)


def test_key_page_is_admin_only(cfg, no_key):
    cl, token = sign_in(cfg, "maya")
    assert cl.get("/settings/key").status_code == 403
    r = cl.post("/settings/key", data={"csrf": token, "key": FAKE_KEY})
    assert r.status_code == 403 and "runs the box" in r.text
    assert cl.post("/settings/key/check", data={"csrf": token}).status_code == 403
    assert not config.key_path(cfg.home).exists() and "NEAR_AI_CLOUD_API_KEY" not in os.environ


def test_key_is_saved_private_and_never_shown(cfg, no_key):
    cl, token = sign_in(cfg, "dana")
    page = cl.get("/settings/key")
    assert page.status_code == 200 and "No key is saved yet" in page.text and "Check it" not in page.text
    assert cl.post("/settings/key", data={"key": FAKE_KEY}).status_code == 403          # no CSRF
    assert cl.post("/settings/key", data={"csrf": token, "key": FAKE_KEY},
                   headers={"origin": "https://evil.example"}).status_code == 403
    assert cl.post("/settings/key", data={"csrf": token, "key": "short"}).status_code == 400
    assert cl.post("/settings/key", data={"csrf": token, "key": "has a space in it ok"}).status_code == 400
    r = cl.post("/settings/key", data={"csrf": token, "key": f"  {FAKE_KEY}\n"})
    assert r.status_code == 200 and "A key is saved" in r.text and FAKE_KEY not in r.text
    kp = config.key_path(cfg.home)
    assert kp.read_text() == FAKE_KEY
    assert stat.S_IMODE(kp.stat().st_mode) == 0o600 and stat.S_IMODE(kp.parent.stat().st_mode) == 0o700
    assert os.environ["NEAR_AI_CLOUD_API_KEY"] == FAKE_KEY
    for path in ("/settings/key", "/status", "/"):
        assert FAKE_KEY not in cl.get(path).text
    assert [e["event"] for e in audit(cfg, "dana")][-1] == "ai_key_saved"
    assert FAKE_KEY not in json.dumps(audit(cfg, "dana"))
    assert FAKE_KEY not in (cfg.runtime / "web").joinpath("key_check.json").read_text()


def test_check_it_runs_the_verify_check(cfg, no_key, monkeypatch):
    seen = []
    fake_check(monkeypatch, {"ok": True, "model": cfg.model, "model_reports_verified": 1, "verified_at_ms": 1},
               seen)
    cl, token = sign_in(cfg, "dana")
    cl.post("/settings/key", data={"csrf": token, "key": FAKE_KEY})
    r = cl.post("/settings/key/check", data={"csrf": token})
    assert r.status_code == 200 and "The key works" in r.text and "Last check passed, just now" in r.text
    assert seen == [(FAKE_KEY, cfg.model)]
    assert "Last AI check: <span class=\"ok\">passed</span>" in cl.get("/status").text
    entry = audit(cfg, "dana")[-1]
    assert entry["event"] == "ai_key_checked" and entry["ok"] is True
    # a new key clears the old result
    cl.post("/settings/key", data={"csrf": token, "key": FAKE_KEY + "b"})
    assert "hasn't been checked yet" in cl.get("/settings/key").text


def test_check_failure_shows_only_a_short_reason(cfg, no_key, monkeypatch):
    cl, token = sign_in(cfg, "dana")
    cl.post("/settings/key", data={"csrf": token, "key": FAKE_KEY})
    fake_check(monkeypatch, {"ok": False, "model": cfg.model, "error": f"bad thing with {FAKE_KEY} inside"})
    r = cl.post("/settings/key/check", data={"csrf": token})
    assert "Last check failed" in r.text and FAKE_KEY not in r.text and "bad thing" not in r.text
    assert FAKE_KEY not in json.dumps(audit(cfg, "dana"))
    fake_check(monkeypatch, {"ok": False, "model": cfg.model, "error": "invalid_api_key"})
    r = cl.post("/settings/key/check", data={"csrf": token})
    assert "NEAR didn't accept the key" in html.unescape(r.text) and "reason:" not in r.text   # plain words, not the code
    fake_check(monkeypatch, {"ok": False, "model": cfg.model, "error": "timeout"})
    r = cl.post("/settings/key/check", data={"csrf": token})
    assert "couldn't reach NEAR in time" in html.unescape(r.text)
    assert "cloud.near.ai" in r.text                                   # where to get a key
    assert "Last AI check: <span class=\"bad\">failed</span>" in cl.get("/status").text


def test_check_without_a_key_does_not_call_near(cfg, no_key, monkeypatch):
    seen = []
    fake_check(monkeypatch, {"ok": True}, seen)
    cl, token = sign_in(cfg, "dana")
    r = cl.post("/settings/key/check", data={"csrf": token})
    assert r.status_code == 200 and seen == [] and "Save a key first" in r.text


def test_stored_key_is_used_after_a_restart(cfg, no_key):
    cl, token = sign_in(cfg, "dana")
    cl.post("/settings/key", data={"csrf": token, "key": FAKE_KEY})
    os.environ.pop("NEAR_AI_CLOUD_API_KEY")
    config.load(cfg.home)
    assert os.environ["NEAR_AI_CLOUD_API_KEY"] == FAKE_KEY


def test_status_page_in_plain_words(cfg, no_key):
    cl, token = sign_in(cfg, "dana")
    home = cl.get("/")
    assert '<a href="/status">Box status</a>' in home.text
    r = cl.get("/status")
    assert r.status_code == 200
    for words in ("The box is <span class=\"ok\">on</span>", "AI key: <span class=\"bad\">missing</span>",
                  "Last AI check: not run yet", "Files you can use: ", "Approvals waiting for you: 0",
                  "Assistants linked to you: 0", "NEAR code check", "Free space: "):
        assert words in r.text, words
    n = len(web.readable_files(cfg, cfg.person("dana")))
    assert f"Files you can use: {n}" in r.text and n > 0
    assert '<a href="/settings/key">' in r.text
    assert "—" not in r.text and "<script" not in r.text and "style=" not in r.text
    maya, _ = sign_in(cfg, "maya")
    m = maya.get("/status")
    assert m.status_code == 200 and "NEAR code check" not in m.text and 'href="/settings/key"' not in m.text
    assert "Ask the person who runs the box to save it" in m.text
    cl.post("/settings/key", data={"csrf": token, "key": FAKE_KEY})
    assert "AI key: <span class=\"ok\">saved</span>" in cl.get("/status").text


def test_status_needs_sign_in(cfg):
    assert client(cfg).get("/status", follow_redirects=False).headers["location"] == "/signin"
    assert client(cfg).get("/settings/key", follow_redirects=False).headers["location"] == "/signin"


def test_block_b_pages_are_not_on_the_remote_listener(cfg):
    paths = ("/settings/key", "/settings/key/check", "/status", "/assistants/code")
    for path in paths:
        assert path not in remote.REMOTE_PATHS
    cl = TestClient(web.create_app(cfg, remote_only=True), base_url="https://testserver")
    for path in paths:
        assert cl.get(path, follow_redirects=False).status_code == 404, path
        assert cl.post(path, follow_redirects=False).status_code == 404, path


def test_no_em_dashes_in_block_b_text():
    root = Path(__file__).resolve().parents[1]
    for p in ("src/familybox/plugins/household.py", "src/familybox/plugins/remote.py"):
        assert "—" not in (root / p).read_text(), p


def test_cli_verify_still_prints_the_same_shape(monkeypatch, capsys):
    import asyncio
    from familybox import cli
    fake_check(monkeypatch, {"ok": True, "model": "m", "model_reports_verified": 2, "verified_at_ms": 5})
    assert asyncio.run(cli._verify("test-key-not-real", "m")) == 0
    assert json.loads(capsys.readouterr().out) == {"model": "m", "gateway": "verified",
                                                   "model_reports_verified": 2, "verified_at_ms": 5}
    fake_check(monkeypatch, {"ok": False, "model": "m", "error": "nope"})
    assert asyncio.run(cli._verify("test-key-not-real", "m")) == 1
    assert json.loads(capsys.readouterr().out) == {"model": "m", "verified": False, "error": "nope"}


# --- Block C: PIN before a reveal, and starting over ---------------------------------------------

def held(c, value="987-65-4320"):
    from familybox.approvals import Approvals
    from familybox.gate import Held
    return Approvals(c).add("sam", "What is Dana's SSN?",
                            [Held("h1", "ssn", "SSN", value, "dana", "people/dana/ids/ssn_card_dana.txt")])[0]


def test_reveal_asks_for_the_pin_when_the_person_has_one(cfg):
    from familybox.approvals import Approvals
    item = held(cfg)
    household.set_pin(web.WebState(cfg), "dana", PIN)
    cl, token = sign_in(cfg, "dana")
    page = cl.get("/approvals").text
    assert 'name="pin"' in page and "Your PIN, to show it" in page and "987-65-4320" not in page
    r = cl.post(f"/approvals/{item}/approve", data={"csrf": token})
    assert r.status_code == 401 and "987-65-4320" not in r.text and "Nothing was shown" in r.text
    r = cl.post(f"/approvals/{item}/approve", data={"csrf": token, "pin": "135792"})
    assert r.status_code == 401 and "987-65-4320" not in r.text
    assert Approvals(cfg).pending("dana")
    r = cl.post(f"/approvals/{item}/approve", data={"csrf": token, "pin": PIN})
    assert r.status_code == 200 and "987-65-4320" in r.text
    assert '<meta http-equiv="refresh" content="30;url=/approvals">' in r.text
    assert "Hides in 30 seconds" in r.text and "<script" not in r.text and "style=" not in r.text
    assert not Approvals(cfg).pending("dana")
    assert PIN not in json.dumps(audit(cfg, "dana"))
    # Deny never needs the PIN, and an ordinary page has no refresh.
    item2 = held(cfg, "987-65-4321")
    assert cl.post(f"/approvals/{item2}/deny", data={"csrf": token}).status_code == 200
    assert 'http-equiv="refresh"' not in cl.get("/approvals").text


def test_reveal_without_a_pin_still_works_and_hides(cfg):
    item = held(cfg)
    cl, token = sign_in(cfg, "dana")
    assert 'name="pin"' not in cl.get("/approvals").text
    r = cl.post(f"/approvals/{item}/approve", data={"csrf": token})
    assert r.status_code == 200 and "987-65-4320" in r.text and "Hides in 30 seconds" in r.text
    assert '<meta http-equiv="refresh" content="30;url=/approvals">' in r.text


def test_wrong_reveal_pins_count_toward_the_pin_lockout(cfg):
    from familybox.approvals import Approvals
    item = held(cfg)
    st = web.WebState(cfg)
    household.set_pin(st, "dana", PIN)
    cl, token = sign_in(cfg, "dana")
    for _ in range(web.LOCKOUT_MAX - 1):
        assert cl.post(f"/approvals/{item}/approve", data={"csrf": token, "pin": "135792"}).status_code == 401
    r = cl.post(f"/approvals/{item}/approve", data={"csrf": token, "pin": "135792"})
    assert r.status_code == 429 and "Too many wrong PINs" in r.text
    r = cl.post(f"/approvals/{item}/approve", data={"csrf": token, "pin": PIN})   # right PIN, but locked
    assert r.status_code == 429 and "987-65-4320" not in r.text
    assert household.pin_locked(st, "dana") and not household.pin_locked(st, "maya")
    assert Approvals(cfg).pending("dana")
    # The same lockout stops PIN sign-in for Dana.
    other = client(cfg)
    r = other.post("/signin", data={"person": "dana", "pin": PIN, "csrf": csrf(other.get("/signin"))})
    assert r.status_code == 429


def test_reveal_pin_needs_csrf_and_the_owner(cfg):
    from familybox.approvals import Approvals
    item = held(cfg)
    household.set_pin(web.WebState(cfg), "dana", PIN)
    cl, _ = sign_in(cfg, "dana")
    assert cl.post(f"/approvals/{item}/approve", data={"pin": PIN}).status_code == 403
    maya, mtok = sign_in(cfg, "maya")
    r = maya.post(f"/approvals/{item}/approve", data={"csrf": mtok, "pin": PIN})
    assert r.status_code == 404 and "987-65-4320" not in r.text
    assert Approvals(cfg).pending("dana")
    assert not household.pin_locked(web.WebState(cfg), "dana")


def set_up_box(empty, monkeypatch):
    """A box set up on its page, with a file, a key, a session and a certificate."""
    for k in config.KEY_ENV:
        monkeypatch.setenv(k, "x")
        monkeypatch.delenv(k)
    cl, r = do_setup(empty)
    assert r.status_code == 303
    token = csrf(cl.get("/"))
    up = cl.post("/upload", data={"folder": "ids", "csrf": token},
                 files={"file": ("card.txt", b"Library card 12345")})
    assert up.status_code == 200
    cl.post("/settings/key", data={"csrf": token, "key": FAKE_KEY})
    web.ensure_cert(empty)
    return cl, token


def test_reset_wipes_the_box_and_reopens_setup(empty, monkeypatch, tmp_path):
    outside = tmp_path / "outside.txt"
    outside.write_text("keep me")
    cl, token = set_up_box(empty, monkeypatch)
    cert = (empty.runtime / "tls" / "cert.pem").read_bytes()
    monkeypatch.setattr(household, "STARTED", time.time() - household.SETUP_WINDOW_S - 1)   # window closed
    page = cl.get("/reset")
    assert page.status_code == 200 and "Type the family name" in page.text and "<script" not in page.text
    assert "—" not in page.text and "style=" not in page.text
    # wrong name, wrong PIN, no CSRF, other origin: nothing deleted
    assert cl.post("/reset", data={"csrf": token, "family": "Someone else", "pin": PIN}).status_code == 400
    assert cl.post("/reset", data={"csrf": token, "family": "The Okafor family", "pin": "135792"}).status_code == 401
    assert cl.post("/reset", data={"family": "The Okafor family", "pin": PIN}).status_code == 403
    assert cl.post("/reset", data={"csrf": token, "family": "The Okafor family", "pin": PIN},
                   headers={"origin": "https://evil.example"}).status_code == 403
    assert (empty.home / "family.toml").exists() and empty.people
    r = cl.post("/reset", data={"csrf": token, "family": "  the okafor   FAMILY ", "pin": PIN},
                follow_redirects=False)
    assert r.status_code == 303 and r.headers["location"] == "/setup"
    assert not (empty.home / "family.toml").exists() and not (empty.home / "files").exists()
    left = {p.name for p in empty.runtime.iterdir()}
    assert "tls" in left and not left & {"secrets", "audit", "approvals.json", "remote"}
    assert not any((empty.runtime / "web").iterdir())    # no PINs, sessions, codes or key check
    assert (empty.runtime / "tls" / "cert.pem").read_bytes() == cert
    assert not config.key_path(empty.home).exists() and "NEAR_AI_CLOUD_API_KEY" not in os.environ
    assert empty.people == {} and empty.name == "Family box"
    assert outside.read_text() == "keep me"
    # signed out, and setup is open again
    assert cl.get("/", follow_redirects=False).headers["location"] == "/setup"
    assert household.setup_open(empty)
    cl2, r2 = do_setup(empty, family="The Lee family", name="Jo")
    assert r2.status_code == 303 and empty.person("jo").admin
    assert "Library card" not in json.dumps(web.readable_files(empty, empty.person("jo")))


def test_reset_is_admin_only_and_needs_a_pin(cfg):
    maya, mtok = sign_in(cfg, "maya")
    assert maya.get("/reset").status_code == 403
    assert maya.post("/reset", data={"csrf": mtok, "family": cfg.name, "pin": PIN}).status_code == 403
    dana, token = sign_in(cfg, "dana")        # signed in with a code, no PIN yet
    page = dana.get("/reset")
    assert page.status_code == 200 and "invite yourself and pick a PIN" in page.text and 'name="pin"' not in page.text
    assert dana.post("/reset", data={"csrf": token, "family": cfg.name, "pin": PIN}).status_code == 400
    assert (cfg.home / "family.toml").exists() and (cfg.home / "files").exists()
    assert client(cfg).get("/reset", follow_redirects=False).headers["location"] == "/signin"


def test_reset_refuses_paths_outside_the_home(empty, monkeypatch, tmp_path):
    cl, token = set_up_box(empty, monkeypatch)
    elsewhere = tmp_path / "elsewhere"
    elsewhere.mkdir()
    (elsewhere / "precious.txt").write_text("not the box's")
    (empty.runtime / "link").symlink_to(elsewhere)
    r = cl.post("/reset", data={"csrf": token, "family": "The Okafor family", "pin": PIN})
    assert r.status_code == 409 and "Nothing was deleted" in r.text
    assert (elsewhere / "precious.txt").exists() and (empty.home / "family.toml").exists()
    assert (empty.home / "files").exists() and config.key_path(empty.home).exists()


def test_reset_refuses_the_demo_folder_in_the_code(tmp_path):
    (tmp_path / "pyproject.toml").write_text("")
    (tmp_path / "src" / "familybox").mkdir(parents=True)
    (tmp_path / "demo").mkdir()
    with pytest.raises(HouseholdError):
        household.reset_targets(config.load(tmp_path / "demo"))
    with pytest.raises(HouseholdError):
        household.reset_targets(config.load(DEMO))


def test_reset_is_not_on_the_remote_listener(cfg):
    assert "/reset" not in remote.REMOTE_PATHS
    cl = TestClient(web.create_app(cfg, remote_only=True), base_url="https://testserver")
    assert cl.get("/reset", follow_redirects=False).status_code == 404
    assert cl.post("/reset", follow_redirects=False).status_code == 404


def test_home_shows_first_steps(cfg, no_key):
    dana, token = sign_in(cfg, "dana")
    home = dana.get("/").text
    for words in ("First steps", "Add your papers", "Invite your family", "Connect an assistant", "Save the AI key"):
        assert words in home, words
    assert 'href="/settings/key"' in home and "—" not in home
    maya, _ = sign_in(cfg, "maya")
    m = maya.get("/").text
    assert "Add your papers" in m and "Connect an assistant" in m
    assert "Invite your family" not in m and "Save the AI key" not in m


def test_box_look_is_plain_and_local():
    css = web.CSS
    for want in ("#0d0d0d", "rgba(0,0,0,.13)", "9999px", "6px", "system-ui"):
        assert want in css, want
    assert "box-shadow: none" in css and "url(" not in css and "@import" not in css and "—" not in css
    for cls in (".card", "button.main", ".button", "button.quiet", "button.danger", ".row", ".muted", ".ok", ".bad",
                ".value", "ul.files", ".name", "label.check", "fieldset", "legend", ".qr", "nav a.here",
                "header .box", "header .who", "input.code"):
        assert cls in css, cls


# --- Block D: friendly name in the certificate, setup address on start ---------------------------

def test_new_certificate_covers_the_friendly_name(empty):
    cert_p, _, _ = web.ensure_cert(empty)
    names = web.cert_dns_names(cert_p)
    assert web.FRIENDLY_NAME == "familybox.local" and "familybox.local" in names and "localhost" in names
    assert len(names) == len(set(names))
    assert web.cert_names("familybox").count("familybox.local") == 1


def test_existing_certificate_is_left_alone(empty):
    """A certificate made before the friendly name was added keeps its fingerprint."""
    from cryptography import x509
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import ec
    import datetime as dt

    tls = empty.runtime / "tls"
    tls.mkdir(parents=True, mode=0o700)
    key = ec.generate_private_key(ec.SECP256R1())
    subject = x509.Name([x509.NameAttribute(x509.oid.NameOID.COMMON_NAME, "old box")])
    now = dt.datetime.now(dt.timezone.utc)
    old = (x509.CertificateBuilder().subject_name(subject).issuer_name(subject).public_key(key.public_key())
           .serial_number(1).not_valid_before(now).not_valid_after(now + dt.timedelta(days=1))
           .add_extension(x509.SubjectAlternativeName([x509.DNSName("localhost")]), critical=False)
           .sign(key, hashes.SHA256()))
    (tls / "key.pem").write_bytes(key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
                                                    serialization.NoEncryption()))
    (tls / "cert.pem").write_bytes(old.public_bytes(serialization.Encoding.PEM))
    before = (tls / "cert.pem").read_bytes()
    cert_p, _, _ = web.ensure_cert(empty)
    assert cert_p.read_bytes() == before and web.cert_dns_names(cert_p) == ["localhost"]


def test_serve_prints_the_setup_address_only_for_a_new_box(empty, cfg):
    lan = web.setup_lines(empty, lan=True, port=8443)
    assert any("https://familybox.local:8443/setup" in line for line in lan)
    assert any("15 minutes" in line for line in lan)
    assert "https://127.0.0.1:8443/setup" in "\n".join(web.setup_lines(empty, lan=False, port=8443))
    assert all("—" not in line for line in lan)
    assert web.setup_lines(cfg, lan=True, port=8443) == []


# --- review fixes: invites only set a first PIN; reset reopens the shared index ---------------------

def test_a_sign_in_or_linking_code_can_never_replace_a_pin_on_join(cfg):
    st = web.WebState(cfg)
    household.set_pin(st, "maya", "135792")
    maya, token = sign_in(cfg, "maya")
    r = maya.post("/assistants/code", data={"csrf": token})
    code = re.search(r'<div class="value">([A-Z0-9]{4})-([A-Z0-9]{4})</div>', r.text)
    code = code.group(1) + code.group(2)
    r = join(maya, code, pin="864209")
    assert r.status_code == 401 and "sign-in code" in r.text
    assert household.check_pin(st, "maya", "135792") == (True, None)
    assert household.check_pin(st, "maya", "864209")[0] is False
    household.check_pin(st, "maya", "135792")          # clear the wrong try above
    # a CLI code doesn't work on /join either
    assert join(client(cfg), web.issue_code(cfg, "maya"), pin="864209").status_code == 401
    # even an invite (made before the PIN, say) can't replace a PIN that exists now
    inv = st.issue_code("maya", ttl=web.INVITE_TTL_S, kind="invite")
    r = join(client(cfg), inv, pin="864209")
    assert r.status_code == 409 and "already have a PIN" in r.text
    assert household.check_pin(st, "maya", "135792") == (True, None)


def test_admin_cannot_invite_someone_who_already_has_a_pin(cfg):
    st = web.WebState(cfg)
    household.set_pin(st, "dana", PIN)
    household.set_pin(st, "maya", "135792")
    dana, token = sign_in(cfg, "dana")
    page = dana.get("/family").text
    assert 'value="maya"><button class="main quiet" type="submit">Invite Maya' not in page
    assert "Maya has joined and picked a PIN" in page and "Invite Sam with a QR code" in page
    for who in ("maya", "dana"):                      # not someone else, not yourself
        r = dana.post("/family/invite", data={"person": who, "csrf": token})
        assert r.status_code == 409 and "<svg" not in r.text, who
    assert household.check_pin(st, "maya", "135792") == (True, None)
    assert household.check_pin(st, "dana", PIN) == (True, None)
    # an invite for someone without a PIN is written to their log too
    invite(dana, token, "sam")
    ev = audit(cfg, "sam")[-1]
    assert ev["event"] == "invite_issued" and ev["by"] == "dana"


def test_an_invite_typed_on_sign_in_goes_to_join_and_signs_nobody_in(cfg):
    dana, token = sign_in(cfg, "dana")
    r, code = invite(dana, token, "maya")
    assert "/join</span> and type this code" in r.text and "sign-in page and type" not in r.text
    assert "not private" in r.text                    # the certificate warning is explained
    phone = client(cfg)
    r = phone.post("/signin", data={"code": code, "csrf": csrf(phone.get("/signin"))}, follow_redirects=False)
    assert r.status_code == 303 and r.headers["location"] == f"/join?c={code}"
    assert phone.get("/", follow_redirects=False).status_code == 303          # not signed in
    assert join(phone, code).status_code == 303                                # the invite is still good
    assert household.check_pin(web.WebState(cfg), "maya", PIN) == (True, None)


def test_change_my_pin_needs_the_current_pin(cfg):
    st = web.WebState(cfg)
    household.set_pin(st, "maya", "135792")
    maya, token = sign_in(cfg, "maya")
    assert 'href="/settings/pin"' in maya.get("/status").text
    page = maya.get("/settings/pin")
    assert page.status_code == 200 and "style=" not in page.text and "<script" not in page.text
    assert maya.post("/settings/pin", data={"current": "135792", "pin": "864209", "pin2": "864209"}).status_code == 403
    r = maya.post("/settings/pin", data={"csrf": token, "current": "999999", "pin": "864209", "pin2": "864209"})
    assert r.status_code == 401 and household.check_pin(st, "maya", "135792") == (True, None)
    r = maya.post("/settings/pin", data={"csrf": token, "current": "135792", "pin": "864209", "pin2": "864209"})
    assert r.status_code == 200 and household.check_pin(st, "maya", "864209") == (True, None)
    assert "864209" not in r.text and "864209" not in json.dumps(audit(cfg, "maya"))
    assert audit(cfg, "maya")[-1]["event"] == "pin_changed"
    sam, stok = sign_in(cfg, "sam")                     # no PIN yet: nothing to change, invite instead
    assert sam.post("/settings/pin", data={"csrf": stok, "current": "", "pin": "864209",
                                           "pin2": "864209"}).status_code == 400
    assert not household.has_pin(st, "sam")
    assert "/settings/pin" not in remote.REMOTE_PATHS


def test_a_refused_family_save_changes_nothing(cfg):
    cl, token = sign_in(cfg, "dana")
    cl.post("/family/access", data={"person": "sam", "grant": ["people/maya/ids"], "csrf": token})
    before = cfg.person("sam").also_reads
    assert before == ("people/maya/ids",)
    n = len(audit(cfg, "dana"))
    r = cl.post("/family/access", data={"person": "sam", "never_share": "x" * (household.WORD_MAX + 1),
                                        "csrf": token})
    assert r.status_code == 400 and "Nothing was saved" in r.text
    assert cfg.person("sam").also_reads == before
    assert config.load(cfg.home).person("sam").also_reads == before
    assert len(audit(cfg, "dana")) == n


def test_adding_a_person_says_how_to_file_their_papers(cfg, no_key):
    cl, token = sign_in(cfg, "dana")
    r = cl.post("/family/add", data={"name": "Kim", "csrf": token})
    assert "To file Kim's papers yourself, tick their folders" in html.unescape(r.text)
    # no grants yet, so the upload page points to the Family page
    household.set_also_reads(web.WebState(cfg), "dana", [])
    up = cl.get("/upload").text
    assert 'tick their folders on your card on the <a href="/family">Family page</a>' in up


def test_upload_page_warns_before_photos_without_a_key_and_key_comes_first(cfg, no_key):
    dana, token = sign_in(cfg, "dana")
    up = dana.get("/upload").text
    assert "The AI key isn't saved yet" in html.unescape(up) and 'href="/settings/key"' in up
    assert ".heic" not in re.search(r'accept="([^"]*)"', up).group(1)
    home = dana.get("/").text
    assert home.index("Save the AI key") < home.index("Add your papers")
    # nothing about "your assistant can use them now" while there is no key
    r = dana.post("/upload", data={"folder": "ids", "csrf": token}, files={"file": ("a.txt", b"hello")})
    assert r.status_code == 200 and "can use it now" not in r.text and "Save the AI key" in r.text


def test_drop_off_upload_doesnt_say_your_assistant_can_use_it(cfg, monkeypatch):
    monkeypatch.setenv("NEAR_AI_CLOUD_API_KEY", "test-key-not-real-0123456789")
    st = web.WebState(cfg)
    household.set_also_reads(st, "dana", ["people/maya/ids"])
    dana, token = sign_in(cfg, "dana")
    r = dana.post("/upload", data={"folder": "people/maya/health", "csrf": token},
                  files={"file": ("note.txt", b"checkup")})
    assert r.status_code == 200 and "Filed for Maya" in r.text and "Your assistant can use" not in r.text
    r = dana.post("/upload", data={"folder": "ids", "csrf": token}, files={"file": ("b.txt", b"mine")})
    assert "Your assistant can use it now" in r.text


def test_reset_reopens_the_shared_index_for_the_new_family(empty, monkeypatch):
    from familybox.box import Box
    for k in config.KEY_ENV:
        monkeypatch.setenv(k, "x")
        monkeypatch.delenv(k)
    shared: list = []

    def box():
        if not shared:
            shared.append(Box(empty, mode="replay"))
        return shared[0]

    cl = TestClient(web.create_app(empty, box=box), base_url="https://testserver")
    r = cl.post("/setup", data={"family": "The Okafor family", "name": "Dana", "pin": PIN, "pin2": PIN,
                                "csrf": csrf(cl.get("/setup"))}, follow_redirects=False)
    assert r.status_code == 303
    token = csrf(cl.get("/"))
    cl.post("/upload", data={"folder": "shared", "csrf": token},
            files={"file": ("old.txt", b"Zebracorn SSN 123-45-6789")})
    b = box()                                          # the shared box is open before the reset
    assert any(s.value == "123456789" for s in b.store.sensitive_values())
    r = cl.post("/reset", data={"csrf": token, "family": "The Okafor family", "pin": PIN}, follow_redirects=False)
    assert r.status_code == 303
    cl2 = TestClient(web.create_app(empty, box=box), base_url="https://testserver")
    r = cl2.post("/setup", data={"family": "The Lee family", "name": "Jo", "pin": PIN, "pin2": PIN,
                                 "csrf": csrf(cl2.get("/setup"))}, follow_redirects=False)
    assert r.status_code == 303
    t2 = csrf(cl2.get("/"))
    cl2.post("/upload", data={"folder": "shared", "csrf": t2},
             files={"file": ("new.txt", b"New family SSN 987-65-4321")})
    values = {s.value for s in b.store.sensitive_values()}
    assert "987654321" in values and "123456789" not in values
    paths = [h.get("path") for h in b.store.search(empty.person("jo"), "New family")]
    assert "shared/new.txt" in paths
    assert not b.store.search(empty.person("jo"), "Zebracorn")


def test_browser_style_sign_in(cfg):
    """A real browser sends Origin on form posts. With the page's referrer policy it is the page's own origin,
    and that must work; "Origin: null" (what no-referrer made browsers send) is still refused."""
    household.set_pin(web.WebState(cfg), "maya", PIN)
    cl = client(cfg)
    r = cl.get("/signin")
    assert r.headers["referrer-policy"] == "same-origin"
    r = cl.post("/signin", data={"person": "maya", "pin": PIN, "csrf": csrf(r)},
                headers={"origin": "https://testserver"})
    assert r.status_code == 200 and web.COOKIE in cl.cookies
    cl2 = client(cfg)
    r = cl2.post("/signin", data={"person": "maya", "pin": PIN, "csrf": csrf(cl2.get("/signin"))},
                 headers={"origin": "null"})
    assert r.status_code == 403 and web.COOKIE not in cl2.cookies
