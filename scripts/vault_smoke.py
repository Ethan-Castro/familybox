"""On the Pi: the whole encrypted-box cycle with a throwaway copy of the demo family, on 127.0.0.1 only.

  uv run python scripts/vault_smoke.py

Encrypts the copy, starts the box (open), locks it as a power cut would, starts it again (locked page
only), unlocks it with the recovery key through the page like a phone would, and checks the full box comes
back with the files. The recovery key is generated here and never printed. Cleans up after itself."""
import http.cookiejar
import os
import re
import shutil
import ssl
import subprocess
import sys
import tempfile
import time
import urllib.parse
import urllib.request
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))
from familybox import vault as vaultmod  # noqa: E402

PORT = 8461
BASE = f"https://127.0.0.1:{PORT}"
CTX = ssl.create_default_context()
CTX.check_hostname = False
CTX.verify_mode = ssl.CERT_NONE
jar = http.cookiejar.CookieJar()
opener = urllib.request.build_opener(urllib.request.HTTPSHandler(context=CTX), urllib.request.HTTPCookieProcessor(jar))
results = []


def check(name, ok):
    results.append(bool(ok))
    print(("PASS " if ok else "FAIL ") + name, flush=True)


def get(path):
    try:
        with opener.open(BASE + path, timeout=10) as r:
            return r.status, r.read().decode()
    except urllib.error.HTTPError as e:
        return e.code, e.read().decode()


def post(path, data):
    req = urllib.request.Request(BASE + path, data=urllib.parse.urlencode(data).encode(),
                                 headers={"Origin": BASE, "Content-Type": "application/x-www-form-urlencoded"})
    try:
        with opener.open(req, timeout=30) as r:
            return r.status, r.read().decode()
    except urllib.error.HTTPError as e:
        return e.code, e.read().decode()


def start(env):
    p = subprocess.Popen([str(ROOT / ".venv/bin/familybox"), "serve", "--port", str(PORT)], env=env,
                         stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    for _ in range(80):
        try:
            if get("/favicon.ico")[0] in (204, 303):
                return p
        except Exception:  # noqa: BLE001
            pass
        time.sleep(0.25)
    raise SystemExit("box did not start")


work = Path(tempfile.mkdtemp(prefix="fb-vault-smoke-", dir=Path.home()))
home = work / "home"
home.mkdir()
shutil.copy(ROOT / "demo/family.toml", home)
shutil.copytree(ROOT / "demo/files", home / "files")
env = dict(os.environ, FAMILYBOX_HOME=str(home), FAMILYBOX_ENCRYPT="auto")
for k in ("NEAR_AI_CLOUD_API_KEY",):
    env.pop(k, None)
v = vaultmod.Vault(home, backend=vaultmod.Gocryptfs())
proc = None
try:
    _, code, n = vaultmod.encrypt_existing(home, "Smoke test family", v)
    check(f"encrypted the demo copy ({n} files) and opened it", v.mounted())
    raw = b"".join(p.read_bytes() for p in v.cipher.rglob("*") if p.is_file())
    check("the SSN is not readable in the encrypted folder", b"987-65-4322" not in raw)
    proc = start(env)
    check("open box serves the sign-in page", "Sign in" in get("/signin")[1])
    proc.terminate(); proc.wait(10)
    check("the box's restart left the files open", v.mounted())
    v.close()
    check("power cut: files closed", v.locked() and not (home / "family.toml").exists())
    proc = start(env)
    st, page = get("/files")
    check("locked box sends every page to the unlock page", "is locked" in page)
    token = re.search(r'name="csrf" value="([^"]+)"', page).group(1)
    st, page = post("/unlock", {"how": "recovery", "code": "0000-0000-0000-0000-0000-0000", "csrf": token})
    check("a wrong recovery key is refused", st == 401 and v.locked())
    token = re.search(r'name="csrf" value="([^"]+)"', page).group(1)
    st, page = post("/unlock", {"how": "recovery", "code": code, "csrf": token})
    check("the right recovery key unlocks", st == 200 and "Unlocked" in page)
    for _ in range(80):
        time.sleep(0.25)
        try:
            st, page = get("/signin")
            if st == 200 and "Sign in" in page:
                break
        except Exception:  # noqa: BLE001
            pass
    check("the box restarted itself as the full box", "Sign in with" in page)
    check("the files are back", (home / "family.toml").exists() and v.mounted())
finally:
    if proc:
        proc.terminate()
        try:
            proc.wait(10)
        except subprocess.TimeoutExpired:
            proc.kill()
    subprocess.run(["pkill", "-f", f"familybox serve --port {PORT}"], check=False)
    time.sleep(1)
    try:
        v.close()
    except vaultmod.VaultError:
        time.sleep(2)
        v.close()
    shutil.rmtree(work, ignore_errors=True)
print(f"{sum(results)} of {len(results)} checks passed")
sys.exit(0 if all(results) else 1)
