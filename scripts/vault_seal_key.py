"""The operator's sealing key, kept only on this laptop (docs/private/, never committed).

  uv run python scripts/vault_seal_key.py public            print the public key (make it once)
  uv run python scripts/vault_seal_key.py open <file>       open sealed output into docs/private/<file>.txt

Opening writes the secret to a 0600 file and prints only where it went, never the secret itself."""
import base64
import os
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

from familybox.vault import unseal

PRIVATE = Path(__file__).resolve().parents[1] / "docs" / "private"
KEY = PRIVATE / "vault-seal.key"


def private_key() -> bytes:
    if not KEY.exists():
        PRIVATE.mkdir(parents=True, exist_ok=True, mode=0o700)
        raw = os.urandom(32)
        fd = os.open(KEY, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        os.write(fd, raw)
        os.close(fd)
    return KEY.read_bytes()


def main() -> int:
    cmd = sys.argv[1] if len(sys.argv) > 1 else ""
    if cmd == "public":
        pub = X25519PrivateKey.from_private_bytes(private_key()).public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)
        print(base64.urlsafe_b64encode(pub).decode().rstrip("="))
        return 0
    if cmd == "open" and len(sys.argv) == 4:
        blob, out = sys.argv[2], PRIVATE / f"{Path(sys.argv[3]).name}.txt"
        secret = unseal(private_key(), blob)
        fd = os.open(out, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
        os.write(fd, (secret + "\n").encode())
        os.close(fd)
        print(f"saved to {out}")
        return 0
    print(__doc__)
    return 2


if __name__ == "__main__":
    sys.exit(main())
