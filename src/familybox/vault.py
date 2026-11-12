"""The family's files, encrypted at rest.

The box's home folder (family.toml, files/, runtime/) lives in an encrypted folder (gocryptfs) next to it,
`<home>.vault/cipher`, and is mounted in place only while the box is unlocked. The folder's password is
a random 32-byte box key. The box key itself is never stored in the clear. It is wrapped twice over:

- **Recovery key**: 24 characters shown once at setup, for the family to keep on paper. It unlocks the
  box from any phone and resets a forgotten PIN.
- **A phone that runs the box**: a random secret kept in an httpOnly cookie on the admin's phone,
  combined with that admin's PIN. Neither half alone opens anything, so a stolen box (no phone) or a
  stolen phone (no box, no PIN) is not enough.

After a power cut the folder is not mounted: the box starts in a locked mode that serves only the unlock
page. A restart of the box's own service (an update, a crash) leaves the folder mounted, because the
mount runs in its own systemd unit.

Kept in the clear in `<home>.vault/`: `vault.json` (the wrapped keys, salts and recent failed tries),
the TLS certificate (to serve the unlock page) and the setup-code hash. Nothing in there opens the files.

Not covered: someone with root on a running, unlocked box; data written to the card before encryption
was turned on (flash cards don't reliably erase old blocks, so start a real box with a new card).
"""

from __future__ import annotations

import base64
import contextlib
import hashlib
import hmac
import json
import os
import secrets
import shutil
import subprocess
import sys
import time
from pathlib import Path

from cryptography.hazmat.primitives.ciphers.aead import AESGCM

UNLOCK_COOKIE = "__Host-familybox-unlock"
RECOVERY_ALPHABET = "0123456789ABCDEFGHJKMNPQRSTVWXYZ"   # Crockford base32: no I, L, O, U
RECOVERY_LEN = 24                                         # 120 bits
SCRYPT_RECOVERY = {"n": 2 ** 15, "r": 8, "p": 1, "maxmem": 64 * 1024 * 1024}
SCRYPT_PIN = {"n": 2 ** 14, "r": 8, "p": 1, "maxmem": 64 * 1024 * 1024}
MAX_FAILS, FAIL_WINDOW_S = 10, 15 * 60
HANDOFF_ENV = "FAMILYBOX_VAULT_FD"
SETUP_CODE_LEN = 8

_KEY: bytes | None = None   # the box key, held in memory by the running box once someone has unlocked it


class VaultError(RuntimeError):
    pass


def remember(key: bytes | None) -> None:
    global _KEY
    _KEY = key


def current_key() -> bytes | None:
    return _KEY


def vault_dir(home: Path) -> Path:
    home = Path(home).resolve()
    return home.parent / f"{home.name}.vault"


# --- codes -------------------------------------------------------------------------------------

def new_recovery_key() -> str:
    raw = "".join(secrets.choice(RECOVERY_ALPHABET) for _ in range(RECOVERY_LEN))
    return "-".join(raw[i:i + 4] for i in range(0, RECOVERY_LEN, 4))


def normalize_code(text: str) -> str:
    t = "".join(ch for ch in str(text).upper() if ch.isalnum())
    return t.translate(str.maketrans({"O": "0", "I": "1", "L": "1", "U": "V"}))


def new_setup_code() -> str:
    raw = "".join(secrets.choice(RECOVERY_ALPHABET) for _ in range(SETUP_CODE_LEN))
    return f"{raw[:4]}-{raw[4:]}"


# --- wrapping ----------------------------------------------------------------------------------

def _b64(b: bytes) -> str:
    return base64.urlsafe_b64encode(b).decode().rstrip("=")


def _unb64(s: str) -> bytes:
    return base64.urlsafe_b64decode(s + "=" * (-len(s) % 4))


def _wrap(kek: bytes, box_key: bytes, wrap_id: str) -> dict:
    nonce = os.urandom(12)
    ct = AESGCM(kek).encrypt(nonce, box_key, b"familybox vault v1|" + wrap_id.encode())
    return {"nonce": _b64(nonce), "ct": _b64(ct)}


def _unwrap(kek: bytes, w: dict, wrap_id: str) -> bytes | None:
    try:
        return AESGCM(kek).decrypt(_unb64(w["nonce"]), _unb64(w["ct"]), b"familybox vault v1|" + wrap_id.encode())
    except Exception:  # noqa: BLE001 - wrong key or damaged entry: both mean "no"
        return None


def _recovery_kek(code: str, salt: bytes) -> bytes:
    return hashlib.scrypt(normalize_code(code).encode(), salt=salt, dklen=32, **SCRYPT_RECOVERY)


def _device_kek(secret: bytes, pin: str, salt: bytes) -> bytes:
    pin_part = hashlib.scrypt(str(pin).encode(), salt=salt, dklen=32, **SCRYPT_PIN)
    return hmac.new(secret, b"familybox unlock v1|" + pin_part, hashlib.sha256).digest()


def _write_private(path: Path, data: bytes) -> None:
    from .approvals import write_private
    write_private(path, data)


# --- encrypted folder backends -----------------------------------------------------------------

class Gocryptfs:
    """The real thing: gocryptfs (FUSE) on Linux. The mount runs in its own systemd user unit when it can,
    so restarting the box's service (updates) does not lock the files again."""

    @staticmethod
    def unit(home: Path) -> str:
        """One systemd unit per home folder, so a test box never touches the real box's mount."""
        return "familybox-vault-" + hashlib.sha256(str(Path(home).resolve()).encode()).hexdigest()[:10]

    @staticmethod
    def available() -> bool:
        return sys.platform.startswith("linux") and bool(shutil.which("gocryptfs")) and Path("/dev/fuse").exists()

    def init(self, cipher: Path, password: str) -> None:
        cipher.mkdir(parents=True, exist_ok=False, mode=0o700)
        # gocryptfs prints a master-key backup on init; it is dropped here, never logged.
        r = subprocess.run(["gocryptfs", "-init", "-q", str(cipher)], input=password + "\n", text=True,
                           capture_output=True, timeout=120, check=False)
        if r.returncode != 0:
            shutil.rmtree(cipher, ignore_errors=True)
            raise VaultError("could not create the encrypted folder")

    def is_mounted(self, home: Path) -> bool:
        return os.path.ismount(home)

    def mount(self, cipher: Path, home: Path, password: str) -> None:
        home.mkdir(parents=True, exist_ok=True, mode=0o700)
        if any(home.iterdir()):
            raise VaultError(f"{home} is not empty, so the encrypted folder can't be opened there")
        run_dir = os.environ.get("XDG_RUNTIME_DIR")
        if shutil.which("systemd-run") and run_dir and Path(run_dir).is_dir():
            # The password goes through a file in RAM (tmpfs), readable only by this user, deleted at once.
            pw = Path(run_dir) / f".familybox-vault-{secrets.token_hex(6)}"
            fd = os.open(pw, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
            try:
                os.write(fd, password.encode() + b"\n")
                os.close(fd)
                subprocess.run(["systemctl", "--user", "reset-failed", self.unit(home)], capture_output=True, timeout=10, check=False)
                r = subprocess.run(["systemd-run", "--user", "--quiet", f"--unit={self.unit(home)}", "--collect",
                                    "gocryptfs", "-fg", "-q", "-passfile", str(pw), str(cipher), str(home)],
                                   capture_output=True, text=True, timeout=30, check=False)
                if r.returncode != 0:
                    raise VaultError("could not start the encrypted folder")
                for _ in range(100):
                    if self.is_mounted(home):
                        break
                    time.sleep(0.1)
            finally:
                with contextlib.suppress(OSError):
                    os.close(fd)
                pw.unlink(missing_ok=True)
        else:
            r = subprocess.run(["gocryptfs", "-q", str(cipher), str(home)], input=password + "\n", text=True,
                               capture_output=True, timeout=60, check=False)
            if r.returncode != 0:
                raise VaultError("could not open the encrypted folder")
        if not self.is_mounted(home):
            raise VaultError("the encrypted folder did not open")

    def unmount(self, home: Path) -> None:
        if not self.is_mounted(home):
            return
        tool = shutil.which("fusermount3") or shutil.which("fusermount") or "fusermount"
        # Lazy (-z): the box's own search index may still be open; the folder detaches now and closes
        # once nothing uses it.
        subprocess.run([tool, "-u", "-z", str(home)], capture_output=True, timeout=30, check=False)
        if self.is_mounted(home):
            raise VaultError("the encrypted folder is busy and could not be closed")
        subprocess.run(["systemctl", "--user", "stop", self.unit(home)], capture_output=True, timeout=10, check=False)


class NoEncryption:
    """For computers without gocryptfs (a Mac laptop running the demo): keys and the recovery key still
    work (PIN reset), the files are not encrypted, and the Status page says so."""

    @staticmethod
    def available() -> bool:
        return True

    def init(self, cipher: Path, password: str) -> None:
        raise VaultError("this computer can't encrypt folders")

    def is_mounted(self, home: Path) -> bool:
        return False

    def mount(self, cipher: Path, home: Path, password: str) -> None:
        raise VaultError("this computer can't encrypt folders")

    def unmount(self, home: Path) -> None:
        return None


def default_backend():
    if os.environ.get("FAMILYBOX_ENCRYPT", "auto").lower() == "off":
        return NoEncryption()
    return Gocryptfs() if Gocryptfs.available() else NoEncryption()


# --- the vault ---------------------------------------------------------------------------------

class Vault:
    def __init__(self, home: Path, backend=None):
        self.home = Path(home).resolve()
        self.dir = vault_dir(self.home)
        self.meta = self.dir / "vault.json"
        self.cipher = self.dir / "cipher"
        self.tls = self.dir / "tls"
        self.setup_code_file = self.dir / "setup_code.json"
        self.backend = backend or default_backend()

    # state
    def exists(self) -> bool:
        return self.meta.is_file()

    def load(self) -> dict:
        try:
            data = json.loads(self.meta.read_text())
        except (OSError, ValueError):
            raise VaultError("the box's key file is missing or damaged") from None
        if not isinstance(data, dict) or data.get("version") != 1:
            raise VaultError("the box's key file is in an unknown format")
        data.setdefault("wraps", {})
        data.setdefault("fails", [])
        return data

    def save(self, data: dict) -> None:
        self._ensure_dir()
        _write_private(self.meta, json.dumps(data, indent=1).encode())

    def _ensure_dir(self) -> None:
        self.dir.mkdir(parents=True, exist_ok=True, mode=0o700)
        os.chmod(self.dir, 0o700)

    def encrypted(self) -> bool:
        return self.exists() and bool(self.load().get("encrypted"))

    def mounted(self) -> bool:
        return self.backend.is_mounted(self.home)

    def locked(self) -> bool:
        return self.encrypted() and not self.mounted()

    # creating
    def create(self, *, encrypt: bool | None = None) -> tuple[bytes, str]:
        """New box key and recovery key. With encrypt, also the encrypted folder (not yet mounted).
        Returns (box_key, recovery_key); the recovery key is shown once and never stored."""
        if self.exists():
            raise VaultError("this box already has keys")
        encrypt = not isinstance(self.backend, NoEncryption) if encrypt is None else encrypt
        box_key, code = os.urandom(32), new_recovery_key()
        salt = os.urandom(16)
        self._ensure_dir()
        if encrypt:
            if self.cipher.exists():
                shutil.rmtree(self.cipher)
            self.backend.init(self.cipher, box_key.hex())
        data = {"version": 1, "created": int(time.time()), "encrypted": bool(encrypt), "fails": [],
                "key_check": _key_check(box_key),
                "wraps": {"recovery": {"salt": _b64(salt), **_wrap(_recovery_kek(code, salt), box_key, "recovery")}}}
        self.save(data)
        return box_key, code

    def open(self, box_key: bytes) -> None:
        if self.encrypted() and not self.mounted():
            self.backend.mount(self.cipher, self.home, box_key.hex())

    def close(self) -> None:
        self.backend.unmount(self.home)

    def destroy(self) -> None:
        """Forget the keys and the encrypted folder (a reset). The TLS certificate stays."""
        with contextlib.suppress(VaultError):
            self.close()
        if self.cipher.exists():
            shutil.rmtree(self.cipher)
        self.meta.unlink(missing_ok=True)
        remember(None)

    # unwrapping
    def check_recovery(self, code: str) -> bytes | None:
        data = self.load()
        w = data["wraps"].get("recovery")
        if not w or self._throttled(data):
            return None
        key = _unwrap(_recovery_kek(code, _unb64(w["salt"])), w, "recovery")
        self._count(data, key is not None)
        return key

    def device_of(self, cookie: str | None) -> dict | None:
        dev_id, _, _ = str(cookie or "").partition(".")
        if not dev_id or not self.exists():
            return None
        w = self.load()["wraps"].get(f"device:{dev_id}")
        return w if isinstance(w, dict) else None

    def check_device(self, cookie: str | None, pin: str, *, count: bool = True) -> tuple[bytes, str] | None:
        """(box_key, person id) when this phone's secret plus that person's PIN open the box key."""
        dev_id, _, secret_b64 = str(cookie or "").partition(".")
        data = self.load()
        w = data["wraps"].get(f"device:{dev_id}")
        if not w or not secret_b64 or self._throttled(data):
            return None
        try:
            secret = _unb64(secret_b64)
        except ValueError:
            return None
        key = _unwrap(_device_kek(secret, pin, _unb64(w["salt"])), w, f"device:{dev_id}")
        if count:
            self._count(data, key is not None)
        return (key, w["person"]) if key else None

    def add_device(self, box_key: bytes, person: str, display: str, pin: str, *, replace_for_person=False) -> str:
        """Let one phone unlock the box with this person's PIN. Returns the cookie value for that phone."""
        data = self.load()
        if not self._key_matches(data, box_key):
            raise VaultError("that is not this box's key")
        if replace_for_person:
            data["wraps"] = {k: v for k, v in data["wraps"].items()
                             if not (k.startswith("device:") and v.get("person") == person)}
        dev_id, secret, salt = secrets.token_hex(8), os.urandom(32), os.urandom(16)
        data["wraps"][f"device:{dev_id}"] = {"person": person, "display": display, "created": int(time.time()),
                                             "salt": _b64(salt),
                                             **_wrap(_device_kek(secret, pin, salt), box_key, f"device:{dev_id}")}
        self.save(data)
        return f"{dev_id}.{_b64(secret)}"

    def devices(self, person: str | None = None) -> list[dict]:
        if not self.exists():
            return []
        out = [{"id": k.split(":", 1)[1], **{f: v.get(f) for f in ("person", "display", "created")}}
               for k, v in self.load()["wraps"].items() if k.startswith("device:")]
        return [d for d in out if person is None or d["person"] == person]

    def remove_devices(self, person: str) -> int:
        data = self.load()
        before = len(data["wraps"])
        data["wraps"] = {k: v for k, v in data["wraps"].items()
                         if not (k.startswith("device:") and v.get("person") == person)}
        self.save(data)
        return before - len(data["wraps"])

    def _key_matches(self, data: dict, box_key: bytes) -> bool:
        """A key we were handed (in memory, after an unlock) is checked against a stored fingerprint."""
        fp = data.get("key_check")
        return bool(fp) and hmac.compare_digest(fp, _key_check(box_key))

    # failed tries
    def _throttled(self, data: dict) -> bool:
        now = time.time()
        return len([t for t in data.get("fails", []) if now - t < FAIL_WINDOW_S]) >= MAX_FAILS

    def throttled(self) -> bool:
        return self.exists() and self._throttled(self.load())

    def _count(self, data: dict, ok: bool) -> None:
        now = time.time()
        fails = [t for t in data.get("fails", []) if now - t < FAIL_WINDOW_S]
        data["fails"] = [] if ok else fails + [now]
        self.save(data)

    # setup code (printed on the box's sticker)
    def set_setup_code(self, code: str) -> None:
        salt = os.urandom(16)
        self._ensure_dir()
        h = hashlib.scrypt(normalize_code(code).encode(), salt=salt, dklen=32, **SCRYPT_PIN)
        _write_private(self.setup_code_file, json.dumps({"salt": _b64(salt), "hash": _b64(h)}).encode())

    def needs_setup_code(self) -> bool:
        return self.setup_code_file.is_file()

    def check_setup_code(self, code: str) -> bool:
        try:
            d = json.loads(self.setup_code_file.read_text())
            h = hashlib.scrypt(normalize_code(code).encode(), salt=_unb64(d["salt"]), dklen=32, **SCRYPT_PIN)
            return hmac.compare_digest(h, _unb64(d["hash"]))
        except (OSError, ValueError, KeyError):
            return False


def _key_check(box_key: bytes) -> str:
    return hmac.new(box_key, b"familybox key check v1", hashlib.sha256).hexdigest()


# --- handing the key to the restarted process ----------------------------------------------------

def hand_off(box_key: bytes) -> None:
    """Before the box re-executes itself (after an unlock), pass the key through an inherited pipe so the
    new process holds it in memory too (to let more phones unlock the box later). Never via a file."""
    r, w = os.pipe()
    os.write(w, box_key)
    os.close(w)
    os.set_inheritable(r, True)
    os.environ[HANDOFF_ENV] = str(r)


def take_hand_off() -> None:
    fd = os.environ.pop(HANDOFF_ENV, None)
    if not fd:
        return
    with contextlib.suppress(ValueError, OSError):
        n = int(fd)
        key = os.read(n, 64)
        os.close(n)
        if len(key) == 32:
            remember(key)


# --- sealing a secret for the operator -----------------------------------------------------------

def seal(public_b64: str, text: str) -> str:
    """Encrypt text to an X25519 public key (the operator's laptop), so a recovery key printed by a remote
    command is unreadable in any job log. Format: base64(ephemeral public key | nonce | ciphertext)."""
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey, X25519PublicKey
    from cryptography.hazmat.primitives.kdf.hkdf import HKDF
    from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

    peer = X25519PublicKey.from_public_bytes(_unb64(public_b64))
    eph = X25519PrivateKey.generate()
    eph_pub = eph.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)
    k = HKDF(hashes.SHA256(), 32, salt=eph_pub, info=b"familybox seal v1").derive(eph.exchange(peer))
    nonce = os.urandom(12)
    return _b64(eph_pub + nonce + AESGCM(k).encrypt(nonce, text.encode(), b"familybox seal v1"))


def unseal(private_raw: bytes, blob: str) -> str:
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey, X25519PublicKey
    from cryptography.hazmat.primitives.kdf.hkdf import HKDF

    raw = _unb64(blob.strip())
    eph_pub, nonce, ct = raw[:32], raw[32:44], raw[44:]
    shared = X25519PrivateKey.from_private_bytes(private_raw).exchange(X25519PublicKey.from_public_bytes(eph_pub))
    k = HKDF(hashes.SHA256(), 32, salt=eph_pub, info=b"familybox seal v1").derive(shared)
    return AESGCM(k).decrypt(nonce, ct, b"familybox seal v1").decode()


def encrypt_existing(cfg_home: Path, family_name: str, vault: Vault | None = None) -> tuple[bytes, str, int]:
    """Move a box that was set up before encryption into an encrypted folder. Run with the box stopped.
    Returns (box_key, recovery_key, files moved). The plain copies are deleted afterwards, but a flash card
    may keep old blocks: a real box should start encrypted on a new card."""
    home = Path(cfg_home).resolve()
    v = vault or Vault(home)
    if v.exists():
        raise VaultError("this box already has keys")
    if isinstance(v.backend, NoEncryption):
        raise VaultError("this computer can't encrypt folders (it needs gocryptfs and FUSE on Linux)")
    if (home.parent / "pyproject.toml").is_file():
        raise VaultError("this is the demo folder inside the code folder; it is never encrypted")
    staging = v.dir / "moving"
    if staging.exists():
        raise VaultError(f"{staging} is left over from an earlier try; check it and remove it first")
    key, code = v.create(encrypt=True)
    data = v.load()
    data["name"] = family_name
    v.save(data)
    staging.mkdir(mode=0o700)
    names = [c.name for c in home.iterdir()]
    for n in names:
        os.rename(home / n, staging / n)
    if (staging / "runtime" / "tls").is_dir() and not v.tls.exists():
        shutil.copytree(staging / "runtime" / "tls", v.tls)
        os.chmod(v.tls, 0o700)
    count = sum(1 for p in staging.rglob("*") if p.is_file())
    try:
        v.open(key)
        for n in names:
            src, dst = staging / n, home / n
            if src.is_dir() and not src.is_symlink():
                shutil.copytree(src, dst, symlinks=True)
            else:
                shutil.copy2(src, dst, follow_symlinks=False)
        moved = sum(1 for p in home.rglob("*") if p.is_file())
        if moved != count:
            raise VaultError(f"copied {moved} of {count} files; nothing deleted")
    except Exception:
        with contextlib.suppress(Exception):
            v.close()
        for n in names:                      # put everything back as it was
            if (staging / n).exists() and not (home / n).exists():
                os.rename(staging / n, home / n)
        v.destroy()
        with contextlib.suppress(OSError):
            staging.rmdir()
        raise
    shutil.rmtree(staging)
    remember(key)
    return key, code, count
