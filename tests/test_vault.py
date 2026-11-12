"""Files encrypted at rest: keys, the locked page, setup, PIN changes, recovery and reset.

The Mac this is developed on can't run gocryptfs, so a stand-in backend moves the files out of the home
folder when "locked" and back when "opened", checking the password. The real gocryptfs path is tested on
the Pi (tests marked linux_vault)."""

from __future__ import annotations

import hashlib
import shutil
import time
from pathlib import Path

import pytest
from starlette.testclient import TestClient

from familybox import config, household, vault as vaultmod, web
from familybox.locked import create_locked_app

PIN, PIN2 = "246813", "975318"


class FakeMount:
    """Stands in for gocryptfs: while closed, the home's files live in <cipher>/data."""

    def init(self, cipher: Path, password: str) -> None:
        cipher.mkdir(parents=True, mode=0o700)
        (cipher / "pw").write_text(hashlib.sha256(password.encode()).hexdigest())
        (cipher / "data").mkdir()

    def is_mounted(self, home: Path) -> bool:
        return (home.parent / (home.name + ".open")).exists()

    def mount(self, cipher: Path, home: Path, password: str) -> None:
        assert (cipher / "pw").read_text() == hashlib.sha256(password.encode()).hexdigest(), "wrong box key"
        home.mkdir(parents=True, exist_ok=True)
        assert not any(home.iterdir()), "mount point not empty"
        for c in (cipher / "data").iterdir():
            shutil.move(str(c), home / c.name)
        (home.parent / (home.name + ".open")).touch()

    def unmount(self, home: Path) -> None:
        if not self.is_mounted(home):
            return
        cipher = vaultmod.vault_dir(home) / "cipher"
        for c in home.iterdir():
            shutil.move(str(c), cipher / "data" / c.name)
        (home.parent / (home.name + ".open")).unlink()


@pytest.fixture
def fake(monkeypatch):
    monkeypatch.setattr(vaultmod, "default_backend", lambda: FakeMount())
    vaultmod.remember(None)
    yield
    vaultmod.remember(None)


@pytest.fixture
def empty(tmp_path, monkeypatch, fake):
    home = tmp_path / "home"
    home.mkdir()
    monkeypatch.setenv("FAMILYBOX_HOME", str(home))
    for k in config.KEY_ENV:
        monkeypatch.delenv(k, raising=False)
    monkeypatch.setattr(household, "STARTED", time.time())
    return config.load()


def client(c, **kw) -> TestClient:
    return TestClient(web.create_app(c, **kw), base_url="https://testserver")


def csrf(resp) -> str:
    import re
    m = re.search(r'name="csrf" value="([^"]+)"', resp.text)
    assert m, resp.text[:500]
    return m.group(1)


def recovery_from(page: str) -> str:
    import re
    return re.search(r'<div class="value">([0-9A-Z-]+)</div>', page).group(1)


def setup(c, cl=None):
    cl = cl or client(c)
    r = cl.post("/setup", data={"family": "The Okafor family", "name": "Dana", "pin": PIN, "pin2": PIN,
                                "csrf": csrf(cl.get("/setup"))})
    assert r.status_code == 200 and "Save your recovery key" in r.text, r.text[:600]
    return cl, recovery_from(r.text)


# --- keys --------------------------------------------------------------------------------------

def test_keys_open_only_with_the_right_secret(tmp_path, fake):
    v = vaultmod.Vault(tmp_path / "home")
    key, code = v.create()
    assert v.encrypted() and len(key) == 32 and len(vaultmod.normalize_code(code)) == 24
    assert v.check_recovery(code) == key
    assert v.check_recovery(code.lower().replace("-", " ")) == key        # typed loosely still works
    assert v.check_recovery("0" * 24) is None
    cookie = v.add_device(key, "dana", "Dana", PIN)
    assert v.check_device(cookie, PIN) == (key, "dana")
    assert v.check_device(cookie, PIN2) is None
    dev_id = cookie.split(".")[0]
    assert v.check_device(f"{dev_id}.{'A' * 43}", PIN) is None             # the box alone isn't enough
    with pytest.raises(vaultmod.VaultError):
        v.add_device(b"\1" * 32, "eve", "Eve", PIN)                          # a key that isn't this box's
    raw = v.meta.read_text()
    assert code not in raw and key.hex() not in raw and PIN not in raw


def test_too_many_wrong_tries_wait(tmp_path, fake):
    v = vaultmod.Vault(tmp_path / "home")
    _, code = v.create()
    for _ in range(vaultmod.MAX_FAILS):
        assert v.check_recovery("WRONG") is None
    assert v.throttled() and v.check_recovery(code) is None


def test_setup_code_from_the_sticker(empty):
    v = vaultmod.Vault(empty.home)
    code = vaultmod.new_setup_code()
    v.set_setup_code(code)
    cl = client(empty)
    page = cl.get("/setup")
    assert 'name="setup_code"' in page.text
    r = cl.post("/setup", data={"family": "X", "name": "Eve", "pin": PIN, "pin2": PIN, "setup_code": "AAAA-AAAA",
                                "csrf": csrf(page)})
    assert r.status_code == 401 and not empty.people and not v.exists()
    r = cl.post("/setup", data={"family": "X", "name": "Dana", "pin": PIN, "pin2": PIN,
                                "setup_code": code.lower(), "csrf": csrf(r)})
    assert r.status_code == 200 and "dana" in empty.people


# --- setup encrypts, the box locks and unlocks ----------------------------------------------------

def test_setup_encrypts_and_a_power_cut_locks_the_box(empty):
    cl, code = setup(empty)
    v = vaultmod.Vault(empty.home)
    assert v.encrypted() and v.mounted() and (empty.home / "family.toml").exists()
    assert vaultmod.UNLOCK_COOKIE in cl.cookies                       # this phone can unlock it
    assert "encrypted on this box" in cl.get("/status").text
    assert (v.tls / "cert.pem").exists() or not (empty.runtime / "tls").exists()

    v.close()                                                         # the power cut
    assert not (empty.home / "family.toml").exists() and v.locked()
    restarted = []
    locked = TestClient(create_locked_app(config.load(), v, restart=lambda k: restarted.append(k)),
                        base_url="https://testserver")
    locked.cookies.set(vaultmod.UNLOCK_COOKIE, cl.cookies.get(vaultmod.UNLOCK_COOKIE))
    assert locked.get("/files", follow_redirects=False).headers["location"] == "/unlock"
    assert locked.post("/mcp", json={}).status_code == 503
    page = locked.get("/unlock")
    assert "This phone can unlock the box for <strong>Dana</strong>" in page.text
    r = locked.post("/unlock", data={"how": "pin", "pin": PIN2, "csrf": csrf(page)})
    assert r.status_code == 401 and v.locked() and not restarted
    r = locked.post("/unlock", data={"how": "pin", "pin": PIN, "csrf": csrf(r)})
    for _ in range(50):
        if restarted:
            break
        time.sleep(0.02)
    assert r.status_code == 200 and "Unlocked" in r.text and v.mounted() and len(restarted) == 1
    assert (empty.home / "family.toml").exists()


def test_a_phone_without_the_secret_unlocks_with_the_recovery_key(empty):
    _, code = setup(empty)
    v = vaultmod.Vault(empty.home)
    v.close()
    restarted = []
    locked = TestClient(create_locked_app(config.load(), v, restart=lambda k: restarted.append(k)),
                        base_url="https://testserver")
    page = locked.get("/unlock")
    assert "This phone can unlock" not in page.text and "recovery key" in page.text.lower()
    r = locked.post("/unlock", data={"how": "recovery", "code": "WRONG-CODE", "csrf": csrf(page)})
    assert r.status_code == 401 and v.locked()
    r = locked.post("/unlock", data={"how": "recovery", "code": code, "csrf": csrf(r)})
    assert r.status_code == 200 and v.mounted()


def test_changing_the_pin_keeps_this_phone_unlocking(empty):
    cl, _ = setup(empty)
    old = cl.cookies.get(vaultmod.UNLOCK_COOKIE)
    r = cl.post("/settings/pin", data={"current": PIN, "pin": PIN2, "pin2": PIN2, "csrf": csrf(cl.get("/settings/pin"))})
    assert r.status_code == 200 and "still unlocks the box" in r.text
    v = vaultmod.Vault(empty.home)
    new = cl.cookies.get(vaultmod.UNLOCK_COOKIE)
    assert new != old and v.check_device(new, PIN2) and not v.check_device(new, PIN)
    assert v.check_device(old, PIN) is None                          # the old phone secret is gone
    assert len(v.devices("dana")) == 1


def test_forgot_pin_with_the_recovery_key(empty):
    _, code = setup(empty)
    cl = client(empty)
    page = cl.get("/signin")
    assert 'href="/recover"' in page.text
    page = cl.get("/recover")
    r = cl.post("/recover", data={"person": "dana", "code": "NOPE", "pin": PIN2, "pin2": PIN2, "csrf": csrf(page)})
    assert r.status_code == 401
    r = cl.post("/recover", data={"person": "dana", "code": code, "pin": PIN2, "pin2": PIN2, "csrf": csrf(r)},
                follow_redirects=False)
    assert r.status_code == 303 and web.COOKIE in cl.cookies
    assert household.check_pin(web.WebState(empty), "dana", PIN2)[0]
    assert vaultmod.Vault(empty.home).check_device(cl.cookies.get(vaultmod.UNLOCK_COOKIE), PIN2)


def test_another_phone_is_added_after_a_restart_with_the_recovery_key(empty):
    _, code = setup(empty)
    vaultmod.remember(None)                                   # the service restarted: no key in memory
    other = client(empty)
    r = other.post("/signin", data={"person": "dana", "pin": PIN, "csrf": csrf(other.get("/signin"))})
    page = other.get("/settings/unlock")
    assert 'name="code"' in page.text
    r = other.post("/settings/unlock", data={"action": "add", "pin": PIN, "code": code, "csrf": csrf(page)})
    assert r.status_code == 200 and "can unlock the box now" in r.text
    assert len(vaultmod.Vault(empty.home).devices("dana")) == 2


def test_reset_forgets_the_keys(empty):
    cl, _ = setup(empty)
    v = vaultmod.Vault(empty.home)
    r = cl.post("/reset", data={"family": "The Okafor family", "pin": PIN, "csrf": csrf(cl.get("/reset"))},
                follow_redirects=False)
    assert r.status_code == 303 and not v.exists() and not v.cipher.exists() and not v.mounted()
    assert not empty.people


# --- the real thing, on Linux with gocryptfs ---------------------------------------------------------

@pytest.mark.skipif(not vaultmod.Gocryptfs.available(), reason="needs gocryptfs and FUSE (Linux)")
def test_gocryptfs_round_trip(tmp_path):
    home = tmp_path / "home"
    v = vaultmod.Vault(home, backend=vaultmod.Gocryptfs())
    key, code = v.create()
    v.open(key)
    try:
        (home / "secret.txt").write_text("Maya SSN 987-65-4322")
        assert v.mounted()
    finally:
        v.close()
    assert not v.mounted() and not (home / "secret.txt").exists()
    raw = b"".join(p.read_bytes() for p in v.cipher.rglob("*") if p.is_file())
    assert b"987-65-4322" not in raw
    v.open(v.check_recovery(code))
    try:
        assert (home / "secret.txt").read_text() == "Maya SSN 987-65-4322"
    finally:
        v.close()


def test_sealed_output_opens_only_with_the_laptop_key():
    from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey
    from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat
    priv = X25519PrivateKey.generate()
    pub = vaultmod._b64(priv.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw))
    blob = vaultmod.seal(pub, "ABCD-EFGH")
    assert "ABCD" not in blob
    from cryptography.hazmat.primitives.serialization import NoEncryption, PrivateFormat
    raw = priv.private_bytes(Encoding.Raw, PrivateFormat.Raw, NoEncryption())
    assert vaultmod.unseal(raw, blob) == "ABCD-EFGH"
    with pytest.raises(Exception):
        vaultmod.unseal(X25519PrivateKey.generate().private_bytes(Encoding.Raw, PrivateFormat.Raw, NoEncryption()),
                        blob)


def test_an_old_box_moves_into_the_encrypted_folder(tmp_path, fake):
    home = tmp_path / "home"
    (home / "files" / "shared").mkdir(parents=True)
    (home / "files" / "shared" / "a.txt").write_text("hello")
    (home / "runtime" / "tls").mkdir(parents=True)
    (home / "runtime" / "tls" / "cert.pem").write_text("CERT")
    (home / "family.toml").write_text("x")
    v = vaultmod.Vault(home)
    key, code, n = vaultmod.encrypt_existing(home, "The Okafor family", v)
    assert n == 3 and v.mounted() and (home / "files" / "shared" / "a.txt").read_text() == "hello"
    assert (v.tls / "cert.pem").read_text() == "CERT" and not (v.dir / "moving").exists()
    v.close()
    assert not (home / "family.toml").exists()
    v.open(v.check_recovery(code))
    assert (home / "family.toml").exists()
