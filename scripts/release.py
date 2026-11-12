"""Make a signed familybox release on the developer's laptop. Publishes nothing.

  uv run python scripts/release.py --new-key        make the release key pair (once per project)
  uv run python scripts/release.py --show-public    print the public key the boxes trust
  uv run python scripts/release.py [OUT]            build a release of HEAD into OUT
                                                    (default dist/release-<version>/)

A release is the code at HEAD as a tar.gz from `git archive`, a manifest.json naming its version,
commit and SHA-256, and manifest.json.sig, an Ed25519 signature over the exact manifest bytes. Upload
the three files to a GitHub release (or any folder the boxes read with FAMILYBOX_UPDATE_URL).

The private key lives in ~/.config/familybox/release-signing.key (0600, in a 0700 folder), never in
the repo and never printed. Its public half is committed at src/familybox/release_key.pub; boxes trust
only that key. Losing the private key means boxes can only be updated by hand again; leaking it means
anyone could ship code to every box, so keep it off shared machines.
"""

from __future__ import annotations

import argparse
import os
import subprocess
import sys
import tarfile
from datetime import datetime, timezone
from pathlib import Path

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import (Encoding, NoEncryption, PrivateFormat,
                                                          load_pem_private_key)

REPO = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO / "src"))
from familybox import updater  # noqa: E402

KEY_DIR = Path.home() / ".config" / "familybox"
KEY_FILE = KEY_DIR / "release-signing.key"
PUB_FILE = REPO / "src" / "familybox" / "release_key.pub"


def git(*args: str) -> str:
    return subprocess.run(["git", "-C", str(REPO), *args], check=True, capture_output=True, text=True).stdout.strip()


def _outside_repo(path: Path) -> Path:
    path = path.expanduser().absolute()
    if path.resolve() == REPO or REPO in path.resolve().parents:
        sys.exit(f"refused: the private key must not live inside the repo ({path}).")
    return path


def new_key(key_file: Path) -> int:
    key_file = _outside_repo(key_file)
    if key_file.exists():
        sys.exit(f"refused: {key_file} already exists. Boxes trust the key that is there; replacing it would "
                 "lock them out of updates. Move it away yourself if you really mean to.")
    key_file.parent.mkdir(parents=True, exist_ok=True)
    os.chmod(key_file.parent, 0o700)
    key = Ed25519PrivateKey.generate()
    pem = key.private_bytes(Encoding.PEM, PrivateFormat.PKCS8, NoEncryption())
    fd = os.open(key_file, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(fd, "wb") as f:
        f.write(pem)
    pub = updater.public_key_text(key.public_key())
    PUB_FILE.write_text(pub + "\n")
    print(f"made the release key: {key_file} (private, 0600; never commit or share it)")
    print(f"wrote the public key to {PUB_FILE.relative_to(REPO)}; commit it so boxes trust this key:")
    print(f"  {pub}")
    return 0


def load_key(key_file: Path) -> Ed25519PrivateKey:
    key_file = _outside_repo(key_file)
    if not key_file.exists():
        sys.exit(f"no release key at {key_file}. Make one with --new-key (once).")
    mode = key_file.stat().st_mode & 0o777
    if mode & 0o077:
        sys.exit(f"refused: {key_file} can be read by other users (mode {mode:o}). Run: chmod 600 {key_file}")
    key = load_pem_private_key(key_file.read_bytes(), password=None)
    if not isinstance(key, Ed25519PrivateKey):
        sys.exit(f"{key_file} is not an Ed25519 key.")
    return key


def show_public(key_file: Path) -> int:
    committed = PUB_FILE.read_text().strip() if PUB_FILE.exists() else None
    if key_file.exists():
        pub = updater.public_key_text(load_key(key_file).public_key())
        print(pub)
        if committed != pub:
            print(f"warning: {PUB_FILE.relative_to(REPO)} holds a different key ({committed}). Boxes would "
                  "refuse releases signed with this one.", file=sys.stderr)
    elif committed:
        print(committed)
        print(f"(from {PUB_FILE.relative_to(REPO)}; there is no private key on this machine)", file=sys.stderr)
    else:
        sys.exit("no release key yet. Make one with --new-key.")
    return 0


def build(out: Path | None, key_file: Path, version: int | None, min_version: int | None) -> int:
    key = load_key(key_file)
    pub = updater.public_key_text(key.public_key())
    shipped = git("show", "HEAD:src/familybox/release_key.pub") if _in_head("src/familybox/release_key.pub") else ""
    if shipped.strip() != pub:
        sys.exit("refused: the public key committed at HEAD (src/familybox/release_key.pub) does not match the "
                 "private key, so boxes would refuse this release. Commit the right public key first.")
    if git("status", "--porcelain", "--untracked-files=no"):
        print("note: there are uncommitted changes; the release is HEAD only, without them.", file=sys.stderr)

    version = version or int(datetime.now(timezone.utc).strftime("%Y%m%d%H%M"))
    commit = git("rev-parse", "HEAD")
    out = (out or REPO / "dist" / f"release-{version}").expanduser().absolute()
    if out.exists() and any(out.iterdir()):
        sys.exit(f"refused: {out} already has files in it.")
    out.mkdir(parents=True, exist_ok=True)
    tarball = out / f"familybox-{version}.tar.gz"
    subprocess.run(["git", "-C", str(REPO), "archive", "--format=tar.gz", "-o", str(tarball), "HEAD"], check=True)

    m = updater.sign_release(out, tarball, version=version, commit=commit, private_key=key, min_version=min_version)

    # Check the result exactly as a box would, with the key the release itself ships.
    updater.verify_manifest((out / updater.MANIFEST).read_bytes(), (out / updater.SIGNATURE).read_bytes(),
                            updater.public_key_from_text(shipped))
    with tarfile.open(tarball, "r:gz") as tf:
        updater.check_members(tf.getmembers())

    size = tarball.stat().st_size
    print(f"release {version} of commit {commit[:12]} in {out}")
    print(f"  {tarball.name}  {size / 1e6:.1f} MB  sha256 {m['sha256']}")
    print(f"  {updater.MANIFEST}, {updater.SIGNATURE} (checked against the committed public key)")
    print("Nothing was published. To publish, attach these three files to a GitHub release.")
    return 0


def _in_head(path: str) -> bool:
    return subprocess.run(["git", "-C", str(REPO), "cat-file", "-e", f"HEAD:{path}"],
                          capture_output=True).returncode == 0


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(prog="release.py", description="Make a signed familybox release (publishes nothing).")
    ap.add_argument("out", nargs="?", type=Path, default=None, help="output folder (default dist/release-<version>/)")
    ap.add_argument("--new-key", action="store_true", help="make the release key pair (refuses to replace one)")
    ap.add_argument("--show-public", action="store_true", help="print the public key")
    ap.add_argument("--key", type=Path, default=KEY_FILE, help=f"private key file (default {KEY_FILE})")
    ap.add_argument("--version", type=int, default=None, help="release number (default: UTC time as YYYYMMDDHHMM)")
    ap.add_argument("--min-version", type=int, default=None,
                    help="boxes older than this version must install an earlier release first")
    a = ap.parse_args(argv)
    if a.new_key:
        return new_key(a.key)
    if a.show_public:
        return show_public(a.key)
    return build(a.out, a.key, a.version, a.min_version)


if __name__ == "__main__":
    sys.exit(main())
