"""Run commands on a fleet board through the Offline Base control plane's exec jobs (no SSH).

Env: JFLEET_TOKEN (admin personal access token, jpt_...), JFLEET_URL (default
http://decision-tree.local:8080/admin), JFLEET_NODE (default decision-tree).

  python scripts/fleet_exec.py run "uname -a"
  python scripts/fleet_exec.py push            # git archive HEAD -> ~/familybox on the board, checksum verified
  python scripts/fleet_exec.py install         # push, then scripts/pi_install.sh on the board

Every command is kept in the control plane's job history. The archive contains only files tracked
by git, so .env (API keys) never leaves this laptop.
"""

from __future__ import annotations

import base64
import hashlib
import json
import os
import subprocess
import sys
import time
import urllib.request
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
URL = os.environ.get("JFLEET_URL", "http://decision-tree.local:8080/admin").rstrip("/")
NODE = os.environ.get("JFLEET_NODE", "decision-tree")
TARGET_USER = os.environ.get("FAMILYBOX_PI_USER", "offlinebase")
CHUNK = 24_000  # base64 characters per exec command


def api(method: str, path: str, body: dict | None = None) -> dict | list:
    token = os.environ.get("JFLEET_TOKEN")
    if not token:
        sys.exit("JFLEET_TOKEN is not set")
    req = urllib.request.Request(
        URL + path, method=method, data=json.dumps(body).encode() if body is not None else None,
        headers={"Authorization": f"Bearer {token}", "Content-Type": "application/json",
                 "User-Agent": "familybox-fleet-exec/0.1"})
    with urllib.request.urlopen(req, timeout=30) as r:
        return json.loads(r.read() or b"{}")


def node_id() -> str:
    for n in api("GET", "/api/nodes"):
        if n.get("name") == NODE:
            return n["id"]
    sys.exit(f"no node named {NODE!r}")


def run(command: str, timeout_s: int = 600, quiet: bool = False) -> tuple[int, str]:
    # Run as the board's normal user, in their home, whatever user the agent runs as.
    wrapped = (f'if [ "$(id -u)" = 0 ]; then exec runuser -u {TARGET_USER} -- bash -lc {json.dumps(command)}; '
               f'else bash -lc {json.dumps(command)}; fi')
    job = api("POST", f"/api/nodes/{node_id()}/actions",
              {"action": "exec", "params": {"command": wrapped}, "timeout_s": timeout_s})
    while True:
        job = api("GET", f"/api/jobs/{job['id']}")
        task = job["tasks"][0]
        if task["status"] not in ("queued", "running"):
            break
        time.sleep(2)
    result = task.get("result") or {}
    out = result.get("output", task.get("output", ""))
    code = result.get("exit_code", 1 if task["status"] != "succeeded" else 0)
    if not quiet:
        print(out.rstrip())
        if task["status"] != "succeeded" or code:
            print(f"[{task['status']}, exit {code}{', ' + task['error'] if task.get('error') else ''}]")
    return code, out


def push() -> None:
    archive = subprocess.run(["git", "archive", "--format=tar.gz", "HEAD"], cwd=ROOT, capture_output=True,
                             check=True).stdout
    digest = hashlib.sha256(archive).hexdigest()
    b64 = base64.b64encode(archive).decode()
    parts = [b64[i:i + CHUNK] for i in range(0, len(b64), CHUNK)]
    print(f"pushing {len(archive)} bytes in {len(parts)} parts, sha256 {digest[:16]}...")
    run("mkdir -p ~/familybox-upload && rm -f ~/familybox-upload/fb.b64", quiet=True)
    for i, part in enumerate(parts, 1):
        code, _ = run(f"printf %s '{part}' >> ~/familybox-upload/fb.b64", quiet=True)
        if code:
            sys.exit(f"part {i} failed")
    code, out = run(
        "cd ~/familybox-upload && base64 -d fb.b64 > fb.tgz && "
        f"echo '{digest}  fb.tgz' | sha256sum -c - && mkdir -p ~/familybox && "
        "tar -xzf fb.tgz -C ~/familybox && rm -f fb.b64 fb.tgz && echo pushed-ok")
    if code or "pushed-ok" not in out:
        sys.exit("push failed (checksum or extract)")


def main() -> int:
    cmd = sys.argv[1] if len(sys.argv) > 1 else ""
    if cmd == "run":
        return run(" ".join(sys.argv[2:]))[0]
    if cmd == "push":
        push()
        return 0
    if cmd == "install":
        push()
        return run("cd ~/familybox && bash scripts/pi_install.sh", timeout_s=1800)[0]
    print(__doc__)
    return 2


if __name__ == "__main__":
    sys.exit(main())
