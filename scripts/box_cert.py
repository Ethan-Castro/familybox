"""A real certificate for the box, so phones open it with no warning.

    uv run --env-file .env python scripts/box_cert.py issue --name decision-tree.familybox.offlinebase.com \
        --ip 192.168.1.78 [--staging]

What it does, from this laptop:
  1. Points the name at the box's home-network address (an A record in offlinebase.com's DNS, on Vercel).
  2. Asks the box (through fleet exec) to make a new private key and a certificate request. The key is made
     on the box and never leaves it; only the request (public) comes back.
  3. Gets the certificate from Let's Encrypt with a DNS check: a temporary TXT record in offlinebase.com's
     DNS, removed afterwards. No email is registered.
  4. Sends the certificate (public) to the box, swaps it in (the old self-made one is kept as a backup)
     and restarts the box.

Let's Encrypt certificates last 90 days: run it again every 60 days (a real product would renew from a
small central service, so boxes never hold DNS credentials). --staging uses Let's Encrypt's test service.
"""
from __future__ import annotations

import argparse
import os
import re
import shutil
import subprocess
import sys
import tempfile
import textwrap
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
ZONE = "offlinebase.com"
SCOPE = os.environ.get("FAMILYBOX_DNS_SCOPE", "ethan-6436s-projects")
VERCEL = ["npx", "-y", "vercel@latest"]


def sh(cmd: list[str], **kw) -> subprocess.CompletedProcess:
    return subprocess.run(cmd, text=True, capture_output=True, **kw)


def fleet(command: str, timeout: int = 900) -> str:
    r = sh(["uv", "run", "--env-file", str(ROOT / ".env"), "python", str(ROOT / "scripts/fleet_exec.py"), "run",
            command], cwd=ROOT, timeout=timeout)
    if r.returncode != 0 or "[succeeded, exit 0]" not in r.stdout:
        raise SystemExit(f"box command failed:\n{r.stdout[-2000:]}\n{r.stderr[-2000:]}")
    return r.stdout


def relative(name: str) -> str:
    if not name.endswith("." + ZONE):
        raise SystemExit(f"{name} is not under {ZONE}")
    return name[: -len(ZONE) - 1]


def dns_records() -> str:
    return sh(VERCEL + ["dns", "ls", ZONE, "--scope", SCOPE], timeout=120).stdout


def ensure_a(name: str, ip: str) -> None:
    rel = relative(name)
    rows = [ln.split() for ln in dns_records().splitlines() if ln.strip().startswith("rec_")]
    have = [r for r in rows if len(r) >= 4 and r[1] == rel and r[2] == "A"]
    if any(r[3] == ip for r in have):
        print(f"DNS: {name} already points to {ip}")
        return
    for r in have:
        sh(VERCEL + ["dns", "rm", r[0], "--yes", "--scope", SCOPE], timeout=120)
    r = sh(VERCEL + ["dns", "add", ZONE, rel, "A", ip, "--scope", SCOPE], timeout=120)
    if r.returncode != 0:
        raise SystemExit(f"could not add the A record: {r.stderr[-500:]}")
    print(f"DNS: {name} now points to {ip}")


# The box side: a Python snippet run in the box's own environment through fleet exec.
BOX_TLS_DIR = textwrap.dedent('''
    from pathlib import Path
    from familybox import config
    from familybox.vault import Vault
    cfg = config.load(); v = Vault(cfg.home)
    tls = v.tls if (v.tls / "cert.pem").exists() else cfg.runtime / "tls"
''')

BOX_CSR = BOX_TLS_DIR + textwrap.dedent('''
    import os, sys
    from cryptography import x509
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import ec
    from cryptography.x509.oid import NameOID
    name = sys.argv[1]
    key = ec.generate_private_key(ec.SECP256R1())
    p = tls / "acme-key.pem"
    fd = os.open(p, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    os.write(fd, key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
                                   serialization.NoEncryption()))
    os.close(fd)
    csr = (x509.CertificateSigningRequestBuilder()
           .subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, name)]))
           .add_extension(x509.SubjectAlternativeName([x509.DNSName(name)]), critical=False)
           .sign(key, hashes.SHA256()))
    print("-----CSR-----"); print(csr.public_bytes(serialization.Encoding.PEM).decode()); print("-----END-----")
''')

BOX_INSTALL = BOX_TLS_DIR + textwrap.dedent('''
    import os, sys, time
    from cryptography import x509
    from cryptography.hazmat.primitives import serialization
    chain = sys.stdin.read()
    cert = x509.load_pem_x509_certificates(chain.encode())[0]
    key = serialization.load_pem_private_key((tls / "acme-key.pem").read_bytes(), None)
    pub = lambda k: k.public_bytes(serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo)
    assert pub(cert.public_key()) == pub(key.public_key()), "certificate does not match the box key"
    stamp = time.strftime("%Y%m%d%H%M")
    for n in ("cert.pem", "key.pem"):
        if (tls / n).exists():
            os.replace(tls / n, tls / f"before-{stamp}-{n}")
    fd = os.open(tls / "cert.pem", os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600); os.write(fd, chain.encode()); os.close(fd)
    os.replace(tls / "acme-key.pem", tls / "key.pem")
    print("installed until", cert.not_valid_after_utc.date())
''')


def box_python(snippet: str, *args: str, stdin: str | None = None) -> str:
    """Run a snippet with the box's code and home on the Pi. Input goes through a here-document."""
    quoted = " ".join(f"'{a}'" for a in args)
    feed = f" <<'FBEOF'\n{stdin}\nFBEOF" if stdin is not None else ""
    cmd = (f"cd ~/familybox && export FAMILYBOX_HOME=~/familybox-home && cat > /tmp/fb_cert_step.py <<'PYEOF'\n"
           f"{snippet}\nPYEOF\n~/.local/bin/uv run python /tmp/fb_cert_step.py {quoted}{feed}; "
           f"rc=$?; rm -f /tmp/fb_cert_step.py; exit $rc")
    return fleet(cmd)


HOOK = """#!/bin/sh
set -e
REL="_acme-challenge.$(echo "$CERTBOT_DOMAIN" | sed 's/\\.{zone}$//')"
{vercel} dns add {zone} "$REL" TXT "$CERTBOT_VALIDATION" --scope {scope} >/dev/null
for i in $(seq 1 60); do
  if dig +short TXT "$REL.{zone}" @ns1.vercel-dns.com | grep -q -- "$CERTBOT_VALIDATION"; then sleep 15; exit 0; fi
  sleep 5
done
echo "TXT record never showed up" >&2; exit 1
"""

CLEAN = """#!/bin/sh
REL="_acme-challenge.$(echo "$CERTBOT_DOMAIN" | sed 's/\\.{zone}$//')"
{vercel} dns ls {zone} --scope {scope} 2>/dev/null | awk -v n="$REL" '$2==n && $3=="TXT" {{print $1}}' | while read id; do
  {vercel} dns rm "$id" --yes --scope {scope} >/dev/null 2>&1
done
exit 0
"""


def issue(name: str, ip: str, staging: bool) -> None:
    if not shutil.which("dig"):
        raise SystemExit("needs dig")
    ensure_a(name, ip)
    out = box_python(BOX_CSR, name)
    m = re.search(r"-----CSR-----\n(.*?)-----END-----", out, re.S)
    if not m:
        raise SystemExit("the box did not return a certificate request")
    work = Path(tempfile.mkdtemp(prefix="fb-cert-"))
    try:
        (work / "req.pem").write_text(m.group(1))
        vercel = " ".join(VERCEL)
        for fname, body in (("hook.sh", HOOK), ("clean.sh", CLEAN)):
            (work / fname).write_text(body.format(zone=ZONE, scope=SCOPE, vercel=vercel))
            os.chmod(work / fname, 0o700)
        cmd = ["uvx", "certbot", "certonly", "--non-interactive", "--agree-tos", "--register-unsafely-without-email",
               "--manual", "--preferred-challenges", "dns", "--manual-auth-hook", str(work / "hook.sh"),
               "--manual-cleanup-hook", str(work / "clean.sh"), "--csr", str(work / "req.pem"),
               "--cert-path", str(work / "cert.pem"), "--fullchain-path", str(work / "fullchain.pem"),
               "--chain-path", str(work / "chain.pem"), "--config-dir", str(work / "cfg"),
               "--work-dir", str(work / "work"), "--logs-dir", str(work / "logs")]
        if staging:
            cmd.append("--staging")
        print("Let's Encrypt: checking the name through DNS (a minute or two)...")
        r = sh(cmd, timeout=900)
        if r.returncode != 0 or not (work / "fullchain.pem").exists():
            raise SystemExit(f"certbot failed:\n{r.stdout[-1500:]}\n{r.stderr[-1500:]}")
        chain = (work / "fullchain.pem").read_text().strip()
        print(box_python(BOX_INSTALL, stdin=chain).strip().splitlines()[-2])
        fleet("export XDG_RUNTIME_DIR=/run/user/$(id -u); systemctl --user restart familybox.service; sleep 6; "
              "systemctl --user is-active familybox.service")
        print(f"done: https://{name}:8443/")
    finally:
        shutil.rmtree(work, ignore_errors=True)


def main() -> int:
    ap = argparse.ArgumentParser()
    sub = ap.add_subparsers(dest="cmd", required=True)
    i = sub.add_parser("issue")
    i.add_argument("--name", required=True)
    i.add_argument("--ip", required=True)
    i.add_argument("--staging", action="store_true")
    args = ap.parse_args()
    issue(args.name, args.ip, args.staging)
    return 0


if __name__ == "__main__":
    sys.exit(main())
