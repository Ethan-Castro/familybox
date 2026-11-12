"""Signed updates: only a newer release signed by the pinned key is installed, and a bad one changes nothing.

Every release here is made on the spot with a throwaway key and read from a file:// folder. No network,
no real uv sync, no systemctl: those steps are small Python commands the tests control."""

from __future__ import annotations

import base64
import io
import json
import sys
import tarfile
from pathlib import Path

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from familybox import cli, updater
from familybox.updater import RELEASE_RECORD, UpdateError, Updater

OK = [sys.executable, "-c", "pass"]
FAIL = [sys.executable, "-c", "import sys; sys.exit(3)"]


@pytest.fixture
def key():
    return Ed25519PrivateKey.generate()


@pytest.fixture
def install(tmp_path):
    """A box install made the old way: code at <tmp>/familybox, no release record (version 0)."""
    code = tmp_path / "familybox"
    code.mkdir()
    (code / "VERSION.txt").write_text("old\n")
    (code / "src").mkdir()
    (code / "src" / "app.py").write_text("print('old')\n")
    return code


def snapshot(code: Path) -> dict:
    return {str(p.relative_to(code)): p.read_bytes() for p in sorted(code.rglob("*")) if p.is_file()}


def _tar(members: list[tuple[tarfile.TarInfo, bytes | None]]) -> bytes:
    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w:gz") as tf:
        for info, data in members:
            if data is not None:
                info.size = len(data)
                tf.addfile(info, io.BytesIO(data))
            else:
                tf.addfile(info)
    return buf.getvalue()


def file_entry(name: str, text: str) -> tuple[tarfile.TarInfo, bytes]:
    info = tarfile.TarInfo(name)
    info.mode = 0o644
    return info, text.encode()


def link_entry(name: str, target: str, kind=tarfile.SYMTYPE) -> tuple[tarfile.TarInfo, None]:
    info = tarfile.TarInfo(name)
    info.type = kind
    info.linkname = target
    return info, None


def good_members(label: str = "new"):
    return [file_entry("VERSION.txt", f"{label}\n"), file_entry("src/app.py", f"print('{label}')\n"),
            link_entry("src/readme-link", "../VERSION.txt")]


def make_release(folder: Path, key, version: int, members=None, min_version=None) -> Path:
    folder.mkdir(parents=True, exist_ok=True)
    tarball = folder / f"familybox-{version}.tar.gz"
    tarball.write_bytes(_tar(members if members is not None else good_members()))
    updater.sign_release(folder, tarball, version=version, commit="a" * 40, private_key=key,
                         min_version=min_version)
    return folder


def make_updater(code: Path, folder: Path, key, **kw) -> Updater:
    lines: list[str] = []
    kw.setdefault("restart_cmd", OK)
    kw.setdefault("healthy", lambda: True)
    up = Updater(code_dir=code, source=folder.as_uri(), public_key=key.public_key(), home=None,
                 sync_cmd=OK, check_cmd=OK, log=lines.append, health_interval=0.01, **kw)
    up.lines = lines
    return up


def assert_untouched(code: Path, before: dict):
    assert snapshot(code) == before
    for extra in (".next", ".prev", ".failed"):
        assert not code.with_name(code.name + extra).exists()
    assert not list(code.parent.glob(".familybox-download-*"))


# ---- a good release ------------------------------------------------------------------------------

def test_good_release_applies_and_records_version(install, tmp_path, key):
    rel = make_release(tmp_path / "rel", key, 202611120300)
    up = make_updater(install, rel, key)
    assert up.check().status == "newer"
    res = up.apply()
    assert res.status == "installed" and res.version == 202611120300
    assert (install / "VERSION.txt").read_text() == "new\n"
    assert (install / "src" / "readme-link").resolve() == (install / "VERSION.txt").resolve()
    rec = json.loads((install / RELEASE_RECORD).read_text())
    assert rec["version"] == 202611120300 and rec["previous_version"] == 0 and rec["commit"] == "a" * 40
    prev = install.with_name("familybox.prev")
    assert (prev / "VERSION.txt").read_text() == "old\n"
    assert not install.with_name("familybox.next").exists()
    # The same release again is a no-op.
    assert up.apply().status == "up-to-date"


def test_release_flow_runs_sync_check_and_restart_in_order(install, tmp_path, key):
    rel = make_release(tmp_path / "rel", key, 5)
    trace = tmp_path / "trace.txt"
    rec = [sys.executable, "-c", f"import sys; open({str(trace)!r}, 'a').write(sys.argv[1] + ' ' + sys.argv[2] + '\\n')"]
    up = make_updater(install, rel, key, restart_cmd=rec + ["restart", "{dir}"])
    up.sync_cmd = rec + ["sync", "{dir}"]
    up.check_cmd = rec + ["check", "{dir}"]
    assert up.apply().status == "installed"
    nxt, final = str(install.with_name("familybox.next")), str(install)
    assert trace.read_text().splitlines() == [f"sync {nxt}", f"check {nxt}", f"sync {final}", f"restart {final}"]


def test_newer_release_replaces_the_one_installed_by_an_update(install, tmp_path, key):
    make_updater(install, make_release(tmp_path / "r1", key, 1), key).apply()
    res = make_updater(install, make_release(tmp_path / "r2", key, 2, good_members("v2")), key).apply()
    assert res.status == "installed"
    assert (install / "VERSION.txt").read_text() == "v2\n"
    assert (install.with_name("familybox.prev") / "VERSION.txt").read_text() == "new\n"


# ---- refused: signature ---------------------------------------------------------------------------

def test_tampered_manifest_is_refused(install, tmp_path, key):
    rel = make_release(tmp_path / "rel", key, 9)
    m = json.loads((rel / "manifest.json").read_text())
    m["version"] = 99
    (rel / "manifest.json").write_text(json.dumps(m, indent=1, sort_keys=True) + "\n")
    before = snapshot(install)
    with pytest.raises(UpdateError, match="not signed by our release key"):
        make_updater(install, rel, key).apply()
    assert_untouched(install, before)


def test_signature_is_checked_before_the_manifest_is_read(install, tmp_path, key):
    rel = make_release(tmp_path / "rel", key, 9)
    (rel / "manifest.json").write_bytes(b"{not json")
    with pytest.raises(UpdateError, match="not signed by our release key"):
        make_updater(install, rel, key).check()


def test_wrong_key_is_refused(install, tmp_path, key):
    rel = make_release(tmp_path / "rel", Ed25519PrivateKey.generate(), 9)
    before = snapshot(install)
    with pytest.raises(UpdateError, match="not signed by our release key"):
        make_updater(install, rel, key).apply()
    assert_untouched(install, before)


@pytest.mark.parametrize("sig", [None, b"", b"not base64 at all!!", base64.b64encode(b"short")])
def test_missing_or_broken_signature_is_refused(install, tmp_path, key, sig):
    rel = make_release(tmp_path / "rel", key, 9)
    if sig is None:
        (rel / "manifest.json.sig").unlink()
    else:
        (rel / "manifest.json.sig").write_bytes(sig)
    before = snapshot(install)
    with pytest.raises(UpdateError, match="signature"):
        make_updater(install, rel, key).apply()
    assert_untouched(install, before)


# ---- refused: versions ----------------------------------------------------------------------------

def test_same_or_older_version_is_not_installed(install, tmp_path, key):
    make_updater(install, make_release(tmp_path / "r5", key, 5), key).apply()
    before = snapshot(install)
    prev_before = snapshot(install.with_name("familybox.prev"))

    same = make_updater(install, make_release(tmp_path / "same", key, 5, good_members("other")), key)
    assert same.check().status == "same"
    assert same.apply().status == "up-to-date"

    older = make_updater(install, make_release(tmp_path / "r3", key, 3, good_members("old-but-signed")), key)
    assert older.check().status == "older"
    with pytest.raises(UpdateError, match="older than the one installed"):
        older.apply()
    assert snapshot(install) == before
    assert snapshot(install.with_name("familybox.prev")) == prev_before


def test_min_version_is_enforced(install, tmp_path, key):
    rel = make_release(tmp_path / "rel", key, 10, min_version=7)
    before = snapshot(install)
    with pytest.raises(UpdateError, match="can only be installed over version 7"):
        make_updater(install, rel, key).apply()
    assert_untouched(install, before)


# ---- refused: the tarball -------------------------------------------------------------------------

def test_sha_mismatch_is_refused(install, tmp_path, key):
    rel = make_release(tmp_path / "rel", key, 9)
    (rel / "familybox-9.tar.gz").write_bytes(_tar(good_members("swapped after signing")))
    before = snapshot(install)
    with pytest.raises(UpdateError, match="does not match the signed SHA-256"):
        make_updater(install, rel, key).apply()
    assert_untouched(install, before)


@pytest.mark.parametrize("bad, why", [
    (file_entry("../escaped.txt", "x"), "climbs out"),
    (file_entry("src/../../escaped.txt", "x"), "climbs out"),
    (file_entry("/tmp/familybox-absolute.txt", "x"), "absolute path"),
    (link_entry("src/out", "../../escaped.txt"), "outside its folder"),
    (link_entry("abs", "/etc/passwd"), "absolute path"),
    (link_entry("hard", "../escaped.txt", tarfile.LNKTYPE), "outside its folder"),
    (link_entry("hardabs", "/etc/passwd", tarfile.LNKTYPE), "absolute path"),
    (link_entry("dev", "", tarfile.CHRTYPE), "device"),
    (link_entry("fifo", "", tarfile.FIFOTYPE), "device or pipe"),
])
def test_unsafe_tarball_entries_are_refused(install, tmp_path, key, bad, why):
    rel = make_release(tmp_path / "rel", key, 9, good_members() + [bad])
    before = snapshot(install)
    with pytest.raises(UpdateError, match=why):
        make_updater(install, rel, key).apply()
    assert_untouched(install, before)
    assert not (tmp_path / "escaped.txt").exists()


@pytest.mark.parametrize("second", [
    link_entry("deep/a/t", "s/../.."),          # on paper deep/, really one level above the root
    link_entry("deep/a/s/evil", "../escaped.txt"),  # written through s, so it lands at the root and points out
])
def test_symlink_chain_escape_is_refused(install, tmp_path, key, second):
    """Each link looks inside on its own; together with deep/a/s (-> the release root) they lead out."""
    members = good_members() + [link_entry("deep/a/s", "../.."), second]
    rel = make_release(tmp_path / "rel", key, 9, members)
    before = snapshot(install)
    with pytest.raises(UpdateError, match="outside"):
        make_updater(install, rel, key).apply()
    assert_untouched(install, before)
    assert not (tmp_path / "escaped.txt").exists()


def test_check_members_allows_links_that_stay_inside():
    infos = [m for m, _ in good_members()] + [link_entry("docs/x", "../src/app.py")[0],
                                              link_entry("src/h", "VERSION.txt", tarfile.LNKTYPE)[0]]
    updater.check_members(infos)


# ---- rollback -------------------------------------------------------------------------------------

def test_failed_health_check_rolls_back(install, tmp_path, key):
    rel = make_release(tmp_path / "rel", key, 7)
    restarts = []
    up = make_updater(install, rel, key, healthy=lambda: False, health_timeout=0.05,
                      restart_cmd=[sys.executable, "-c", "pass"])
    real_run = up._run

    def counting_run(cmd, folder, what):
        if what.startswith("Restarting"):
            restarts.append((folder / "VERSION.txt").read_text())
        return real_run(cmd, folder, what)
    up._run = counting_run
    before = snapshot(install)
    res = up.apply()
    assert res.status == "rolled-back" and res.version == 0
    assert restarts == ["new\n", "old\n"]                     # restarted on the new code, then the old again
    rec = json.loads((install / RELEASE_RECORD).read_text())
    assert rec == {"version": 0, "failed_version": 7}
    after = snapshot(install)
    after.pop(RELEASE_RECORD)
    assert after == before
    for extra in (".next", ".prev", ".failed"):
        assert not install.with_name("familybox" + extra).exists()
    # The same broken version is not tried again every day.
    again = make_updater(install, rel, key)
    assert again.check().status == "failed-before"
    assert again.apply().status == "up-to-date"
    assert (install / "VERSION.txt").read_text() == "old\n"


def test_failed_restart_command_rolls_back(install, tmp_path, key):
    rel = make_release(tmp_path / "rel", key, 7)
    res = make_updater(install, rel, key, restart_cmd=FAIL).apply()
    assert res.status == "rolled-back"
    assert (install / "VERSION.txt").read_text() == "old\n"


def test_failed_sync_or_self_check_leaves_install_untouched(install, tmp_path, key):
    rel = make_release(tmp_path / "rel", key, 7)
    before = snapshot(install)
    for attr in ("sync_cmd", "check_cmd"):
        up = make_updater(install, rel, key)
        setattr(up, attr, FAIL)
        with pytest.raises(UpdateError, match="exit 3"):
            up.apply()
        assert_untouched(install, before)


def test_half_finished_swap_is_recovered(install, tmp_path, key):
    install.rename(install.with_name("familybox.prev"))       # the box stopped between the two renames
    up = make_updater(install, make_release(tmp_path / "rel", key, 3), key)
    assert up.check().status == "newer"
    assert (install / "src" / "app.py").read_text() == "print('old')\n"


def test_git_checkout_is_never_replaced(install, tmp_path, key):
    (install / ".git").mkdir()
    with pytest.raises(UpdateError, match="git checkout"):
        make_updater(install, make_release(tmp_path / "rel", key, 3), key).apply()
    assert (install / "VERSION.txt").read_text() == "old\n"


# ---- sources and keys -----------------------------------------------------------------------------

@pytest.mark.parametrize("url", ["http://example.org/rel/", "ftp://example.org/", "/plain/path"])
def test_only_https_and_file_sources(install, key, url):
    with pytest.raises(UpdateError, match="https:// or file://"):
        Updater(code_dir=install, source=url, public_key=key.public_key(), home=None)


def test_oversized_manifest_is_refused(install, tmp_path, key):
    rel = make_release(tmp_path / "rel", key, 3)
    (rel / "manifest.json").write_bytes(b" " * (updater.MAX_MANIFEST + 1))
    with pytest.raises(UpdateError, match="limit"):
        make_updater(install, rel, key).check()


def test_committed_release_key_is_a_valid_ed25519_key():
    key = updater.pinned_key()
    assert updater.public_key_text(key) == updater.PUBLIC_KEY_FILE.read_text().strip()


def test_log_file_is_private_and_appended(tmp_path):
    (tmp_path / "runtime").mkdir()
    log = updater.Log(tmp_path)
    log("one")
    log("two")
    p = tmp_path / "runtime" / "updates.log"
    assert p.stat().st_mode & 0o777 == 0o600
    assert [ln.split("  ", 1)[1] for ln in p.read_text().splitlines()] == ["one", "two"]


# ---- command line ---------------------------------------------------------------------------------

def test_cli_check_and_apply(install, tmp_path, key, monkeypatch, capsys):
    rel = make_release(tmp_path / "rel", key, 11)
    monkeypatch.setattr(updater, "pinned_key", lambda: key.public_key())
    monkeypatch.setenv("FAMILYBOX_UPDATE_URL", rel.as_uri())
    monkeypatch.setenv("FAMILYBOX_CODE_DIR", str(install))
    monkeypatch.setenv("FAMILYBOX_HOME", str(tmp_path / "home"))
    monkeypatch.setenv("FAMILYBOX_UPDATE_UV", sys.executable)    # stands in for uv; the commands are swapped below
    real = updater.Updater.__post_init__

    def no_real_commands(self):
        real(self)
        self.sync_cmd, self.check_cmd = OK, OK
    monkeypatch.setattr(updater.Updater, "__post_init__", no_real_commands)

    assert cli.main(["update", "check"]) == 0
    assert "Version 11" in capsys.readouterr().out
    assert cli.main(["update", "apply"]) == 1                    # no terminal to ask, no --yes
    assert (install / "VERSION.txt").read_text() == "old\n"
    assert cli.main(["update", "apply", "--yes", "--no-restart"]) == 0
    assert "Installed version 11" in capsys.readouterr().out
    assert (install / "VERSION.txt").read_text() == "new\n"

    (rel / "manifest.json.sig").unlink()
    assert cli.main(["update", "check"]) == 1
    assert "no signature" in capsys.readouterr().err
