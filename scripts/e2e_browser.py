"""End-to-end check of the box page in a real browser (headless Chrome over the DevTools protocol).

    uv run --with websocket-client python scripts/e2e_browser.py [--live] [--out DIR]

Starts this repo's box on 127.0.0.1 with throwaway homes and drives every page the way a person would:

  1. new box: setup, PIN rules, adding a person, invite by code, joining on a second phone, admin-only
     pages, the AI key page, changing a PIN, the stale-tab case, reset back to setup
  2. demo family (fictional data, recorded answers): PIN sign-in, asking from the home page, the chat
     page, a held number approved by its owner with her PIN, a refused health file, uploads (several
     files and a photo), every other page, sign-out, and a phone-width pass
  3. --live: the same demo family with the NEAR key from .env (passed to the box process, never typed
     into a page): a live question; if NEAR's code changed since the shipped pins, the test follows the
     stop page's "Review the change" button, trusts the new code in that throwaway home only, and asks
     again

Every page is also checked for script errors, blocked resources and Content-Security-Policy reports, and
for sideways scrolling at phone width. PINs are random per run and never printed. Screenshots go to --out.
Exit code 0 only if every check passed.
"""
from __future__ import annotations

import argparse
import base64
import json
import os
import re
import secrets
import shutil
import socket
import ssl
import subprocess
import sys
import tempfile
import time
import urllib.request
from pathlib import Path

import websocket  # websocket-client

ROOT = Path(__file__).resolve().parents[1]
CHROME = os.environ.get("CHROME", "/Applications/Google Chrome.app/Contents/MacOS/Google Chrome")
SSL = ssl.create_default_context()
SSL.check_hostname = False
SSL.verify_mode = ssl.CERT_NONE
PHONE = {"width": 390, "height": 844, "deviceScaleFactor": 2, "mobile": True}
DESKTOP = {"width": 1280, "height": 900, "deviceScaleFactor": 1, "mobile": False}

results: list[tuple[str, bool, str]] = []


def check(name: str, ok, detail: str = "") -> bool:
    ok = bool(ok)
    results.append((name, ok, detail))
    print(f"  {'PASS' if ok else 'FAIL'}  {name}{'  (' + detail + ')' if detail and not ok else ''}", flush=True)
    return ok


def new_pin() -> str:
    while True:
        pin = "".join(secrets.choice("0123456789") for _ in range(6))
        if len(set(pin)) > 1:
            return pin


def free_port() -> int:
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


def env_file_value(name: str) -> str | None:
    if os.environ.get(name):
        return os.environ[name]
    try:
        for line in (ROOT / ".env").read_text().splitlines():
            k, _, v = line.partition("=")
            if k.strip() == name:
                return v.strip().strip('"').strip("'")
    except OSError:
        pass
    return None


# ---- the box -----------------------------------------------------------------------------------------

class BoxServer:
    def __init__(self, home: Path, key: str | None = None):
        self.home, self.port = home, free_port()
        env = dict(os.environ, FAMILYBOX_HOME=str(home))
        for k in ("NEAR_AI_CLOUD_API_KEY", "NEAR_AI_CLOUD_BASE_URL"):
            env.pop(k, None)
        if key:
            env["NEAR_AI_CLOUD_API_KEY"] = key
            base = env_file_value("NEAR_AI_CLOUD_BASE_URL")
            if base:
                env["NEAR_AI_CLOUD_BASE_URL"] = base
        self.env = env
        self.log = open(home.parent / f"box-{self.port}.log", "w")
        self.proc = subprocess.Popen(["uv", "run", "--directory", str(ROOT), "familybox", "serve",
                                      "--port", str(self.port)], env=env, stdout=self.log, stderr=self.log)
        self.base = f"https://127.0.0.1:{self.port}"
        for _ in range(120):
            try:
                urllib.request.urlopen(self.base + "/favicon.ico", context=SSL, timeout=2)
                return
            except Exception:  # noqa: BLE001
                if self.proc.poll() is not None:
                    raise SystemExit(f"the box did not start; see {self.log.name}")
                time.sleep(0.5)
        raise SystemExit("the box did not answer in 60 s")

    def set_pin(self, person: str, pin: str) -> None:
        subprocess.run(["uv", "run", "--directory", str(ROOT), "python", "-c",
                        "import sys; from familybox import config, household; from familybox.web import WebState;"
                        f"household.set_pin(WebState(config.load()), {person!r}, sys.stdin.read())"],
                       input=pin, text=True, env=self.env, check=True, capture_output=True)

    def hold(self, asker: str, question: str, owner: str, kind: str, label: str, path: str, value: str) -> None:
        """Put one held detail in the owner's Approvals, exactly as the answer gate stores it. The recorded
        demo answers are all clean (the model itself declined to write full numbers), so the approval flow
        needs a held item seeded this way. The live gate's holds are covered by the unit tests and eval."""
        subprocess.run(["uv", "run", "--directory", str(ROOT), "python", "-c",
                        "import sys, json; from familybox import config; from familybox.approvals import Approvals;"
                        "from familybox.gate import Held; a = json.loads(sys.stdin.read());"
                        "Approvals(config.load()).add(a['asker'], a['question'], [Held(**a['held'])], source='web')"],
                       input=json.dumps({"asker": asker, "question": question,
                                         "held": {"id": "e2eheld" + secrets.token_hex(4), "kind": kind,
                                                  "label": label, "value": value, "owner": owner, "path": path}}),
                       text=True, env=self.env, check=True, capture_output=True)

    def stop(self) -> None:
        self.proc.terminate()
        try:
            self.proc.wait(10)
        except subprocess.TimeoutExpired:
            self.proc.kill()
        self.log.close()


# ---- the browser -------------------------------------------------------------------------------------

class Browser:
    def __init__(self, out: Path):
        self.out = out
        self.port = free_port()
        self.profile = tempfile.mkdtemp(prefix="fb-e2e-chrome-")
        self.proc = subprocess.Popen([CHROME, "--headless=new", f"--remote-debugging-port={self.port}",
                                      f"--user-data-dir={self.profile}", "--ignore-certificate-errors",
                                      "--no-first-run", "--no-default-browser-check", "about:blank"],
                                     stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        for _ in range(60):
            try:
                info = json.load(urllib.request.urlopen(f"http://127.0.0.1:{self.port}/json/version", timeout=2))
                break
            except Exception:  # noqa: BLE001
                time.sleep(0.5)
        else:
            raise SystemExit("Chrome did not start")
        self.ws = websocket.create_connection(info["webSocketDebuggerUrl"], timeout=60, suppress_origin=True)
        self.n = 0
        self.events: list[dict] = []

    def send(self, method: str, session: str | None = None, **params) -> dict:
        self.n += 1
        msg = {"id": self.n, "method": method, "params": params}
        if session:
            msg["sessionId"] = session
        self.ws.send(json.dumps(msg))
        while True:
            m = json.loads(self.ws.recv())
            if m.get("id") == self.n:
                if "error" in m:
                    raise RuntimeError(f"{method}: {m['error']}")
                return m.get("result", {})
            if "method" in m:
                self.events.append(m)

    def pump(self, seconds: float) -> None:
        self.ws.settimeout(seconds)
        try:
            while True:
                m = json.loads(self.ws.recv())
                if "method" in m:
                    self.events.append(m)
        except (websocket.WebSocketTimeoutException, TimeoutError):
            pass
        finally:
            self.ws.settimeout(60)

    def person(self, name: str) -> Tab:
        """A fresh, separate browser profile: its own cookies, like another phone."""
        ctx = self.send("Target.createBrowserContext")["browserContextId"]
        return self.tab(name, ctx)

    def tab(self, name: str, ctx: str) -> Tab:
        tid = self.send("Target.createTarget", url="about:blank", browserContextId=ctx)["targetId"]
        sid = self.send("Target.attachToTarget", targetId=tid, flatten=True)["sessionId"]
        t = Tab(self, name, sid, ctx)
        for m in ("Page.enable", "Runtime.enable", "Log.enable", "Network.enable"):
            self.send(m, sid)
        self.send("Emulation.setDeviceMetricsOverride", sid, **DESKTOP)
        return t

    def close(self) -> None:
        try:
            self.ws.close()
        finally:
            self.proc.terminate()
            time.sleep(0.5)
            shutil.rmtree(self.profile, ignore_errors=True)


class Tab:
    def __init__(self, b: Browser, name: str, sid: str, ctx: str):
        self.b, self.name, self.sid, self.ctx = b, name, sid, ctx
        self.shots = 0

    # -- basics
    def js(self, expr: str):
        r = self.b.send("Runtime.evaluate", self.sid, expression=expr, returnByValue=True, awaitPromise=True)
        if "exceptionDetails" in r:
            raise RuntimeError(f"page script failed: {r['exceptionDetails'].get('text')}: {expr[:120]}")
        return r.get("result", {}).get("value")

    def _wait_load(self, timeout: float = 30) -> None:
        end = time.time() + timeout
        while time.time() < end:
            for i, m in enumerate(self.b.events):
                if m.get("sessionId") == self.sid and m["method"] == "Page.loadEventFired":
                    del self.b.events[i]
                    self.b.pump(0.3)
                    return
            self.b.pump(0.2)
        raise TimeoutError(f"{self.name}: page did not load")

    def _drop_loads(self) -> None:
        self.b.events = [m for m in self.b.events
                         if not (m.get("sessionId") == self.sid and m["method"] == "Page.loadEventFired")]

    def go(self, path_or_url: str) -> Tab:
        self._drop_loads()
        url = path_or_url if "://" in path_or_url else self.base + path_or_url
        self.b.send("Page.navigate", self.sid, url=url)
        self._wait_load()
        return self

    def act(self, script: str) -> Tab:
        """Run a script that submits a form or follows a link, then wait for the next page."""
        self._drop_loads()
        self.js(script)
        self._wait_load()
        return self

    def fill_submit(self, form_sel: str, values: dict, button_text: str | None = None) -> Tab:
        """Fill the fields of the first form matching form_sel and submit it with its own button."""
        return self.act(f"""(() => {{
            const forms = [...document.querySelectorAll({json.dumps(form_sel)})];
            const want = {json.dumps(button_text)};
            const f = want ? forms.find(f => [...f.querySelectorAll('button')].some(b => b.textContent.includes(want)))
                           : forms[0];
            if (!f) throw new Error('no form ' + {json.dumps(form_sel)} + ' ' + want);
            const vals = {json.dumps(values)};
            for (const [k, v] of Object.entries(vals)) {{
                const els = f.querySelectorAll('[name="' + k + '"]');
                if (!els.length) throw new Error('no field ' + k);
                els.forEach(el => {{ if (el.type === 'checkbox') el.checked = !!v; else el.value = v; }});
            }}
            const btn = [...f.querySelectorAll('button[type=submit],button:not([type])')]
                .find(b => !want || b.textContent.includes(want));
            f.requestSubmit(btn || undefined);
        }})()""")

    @property
    def base(self) -> str:
        return self._base

    @base.setter
    def base(self, v: str) -> None:
        self._base = v

    def path(self) -> str:
        return self.js("location.pathname")

    def h1(self) -> str:
        return (self.js("(document.querySelector('h1')||{}).textContent||''") or "").strip()

    def text(self) -> str:
        return self.js("document.body.innerText") or ""

    def html(self) -> str:
        return self.js("document.documentElement.outerHTML") or ""

    def has(self, sel: str) -> bool:
        return bool(self.js(f"!!document.querySelector({json.dumps(sel)})"))

    def shot(self, label: str) -> None:
        self.shots += 1
        data = self.b.send("Page.captureScreenshot", self.sid, format="png", captureBeyondViewport=True)["data"]
        p = self.b.out / f"{self.name}-{self.shots:02d}-{re.sub(r'[^a-z0-9]+', '-', label.lower())}.png"
        p.write_bytes(base64.b64decode(data))

    def phone(self, on: bool = True) -> None:
        self.b.send("Emulation.setDeviceMetricsOverride", self.sid, **(PHONE if on else DESKTOP))

    def no_sideways_scroll(self) -> bool:
        return bool(self.js("document.documentElement.scrollWidth <= window.innerWidth + 1"))

    def problems(self) -> list[str]:
        """Script errors, failed loads and CSP reports seen in this tab since the last call."""
        self.b.pump(0.2)
        out, keep = [], []
        for m in self.b.events:
            if m.get("sessionId") != self.sid:
                keep.append(m)
                continue
            p = m.get("params", {})
            if m["method"] == "Runtime.exceptionThrown":
                out.append("script error: " + str(p.get("exceptionDetails", {}).get("text")))
            elif m["method"] == "Log.entryAdded" and p.get("entry", {}).get("level") == "error":
                e = p["entry"]
                if e.get("source") != "network":   # loads are judged below, by what kind of resource failed
                    out.append(f"{e.get('source')}: {e.get('text', '')[:160]} {e.get('url', '')}")
            elif m["method"] == "Network.responseReceived" and p.get("type") != "Document" \
                    and p.get("response", {}).get("status", 0) >= 400:
                out.append(f"{p.get('type')} failed to load: {p['response'].get('status')} {p['response'].get('url')}")
            elif m["method"] == "Network.loadingFailed" and p.get("type") != "Document" and not p.get("canceled"):
                out.append(f"{p.get('type')} failed to load: {p.get('errorText')} "
                           f"{'(blocked: ' + str(p.get('blockedReason')) + ')' if p.get('blockedReason') else ''}")
            elif m["method"] == "Runtime.consoleAPICalled" and p.get("type") == "error":
                out.append("console error: " + str([a.get("value") for a in p.get("args", [])])[:160])
        self.b.events = keep
        return out


def page_ok(t: Tab, label: str, path: str, want_h1: str | None = None) -> None:
    t.go(path)
    h = t.h1()
    bad = h in ("Not allowed", "Not found", "Something went wrong") or "Traceback" in t.text()
    check(f"{t.name}: {label} page opens", not bad and (want_h1 is None or want_h1.lower() in h.lower()),
          f"path {t.path()}, heading {h!r}")
    probs = t.problems()
    check(f"{t.name}: {label} page has no browser errors", not probs, "; ".join(probs))


def wait_answer(t: Tab, timeout: float) -> bool:
    end = time.time() + timeout
    while time.time() < end:
        if t.has(".fb-answer") and not t.has(".fb-typing"):
            return True
        t.b.pump(1.0)
    return False


def ask(t: Tab, question: str, timeout: float) -> bool:
    t.go("/")
    t.fill_submit("form.composer", {"question": question})
    on_chat = t.path().startswith("/activity/")
    check(f"{t.name}: asking from the home page opens the chat page", on_chat, t.path())
    return on_chat and check(f"{t.name}: the answer arrives on the chat page", wait_answer(t, timeout))


# ---- part 1: a new box -------------------------------------------------------------------------------

def part_new_box(b: Browser, work: Path) -> None:
    print("\n1. A new box, set up from the browser")
    home = work / "new-home"
    home.mkdir()
    box = BoxServer(home)
    try:
        alex = b.person("alex")
        alex.base = box.base
        alex.go("/")
        check("alex: an empty box sends you to setup", alex.path() == "/setup", alex.path())
        alex.shot("setup")
        p1, p2, p3 = new_pin(), new_pin(), new_pin()
        alex.fill_submit('form[action="/setup"]', {"family": "Rivera", "name": "Alex", "pin": p1, "pin2": p2})
        check("alex: setup refuses PINs that don't match", alex.path() == "/setup" and "match" in alex.text().lower())
        alex.fill_submit('form[action="/setup"]', {"family": "Rivera", "name": "Alex", "pin": "111111",
                                                   "pin2": "111111"})
        check("alex: setup refuses a PIN of one repeated digit", alex.path() == "/setup")
        alex.fill_submit('form[action="/setup"]', {"family": "Rivera", "name": "Alex", "pin": p1, "pin2": p1})
        key = alex.js("(document.querySelector('.value')||{}).textContent||''").strip()
        check("alex: setup shows the recovery key once", "recovery key" in alex.h1().lower() and len(key) >= 24,
              alex.h1())
        alex.shot("recovery-key")
        alex.act("document.querySelector('a.main').click()")
        check("alex: setup signs you in on the home page", alex.path() == "/" and "Alex" in alex.text(),
              alex.path())
        check("alex: home page is a question box", alex.has("form.composer") and alex.has("aside.side"))
        alex.shot("home-after-setup")
        check("alex: setup page closes once the family exists",
              alex.go("/setup").path() != "/setup" or "already" in alex.text().lower(), alex.path())

        alex.go("/family")
        alex.fill_submit('form[action="/family/add"]', {"name": "Riley"})
        check("alex: adding Riley on the Family page", "Riley" in alex.text())
        alex.fill_submit('form[action="/family/invite"]', {}, "Invite Riley")
        code = alex.js("(document.querySelector('.value')||{}).textContent||''").strip()
        check("alex: the invite shows a code and a QR", bool(code) and alex.has(".qr svg"))
        alex.shot("invite")

        riley = b.person("riley")
        riley.base = box.base
        riley.go("/join?c=" + code)
        q = new_pin()
        riley.fill_submit('form[action="/join"]', {"pin": q, "pin2": q})
        check("riley: joining by invite signs Riley in", riley.path() == "/" and "Riley" in riley.text(),
              riley.path())
        riley.go("/family")
        check("riley: the Family page is for the person who runs the box only",
              riley.h1() in ("Not allowed",) or "Family" not in riley.h1() or "only" in riley.text().lower(),
              riley.h1())
        riley.go("/join?c=" + code)
        riley.fill_submit('form[action="/join"]', {"pin": q, "pin2": q})
        check("riley: an invite code works only once", riley.path() == "/join" or "didn't work" in riley.text()
              or "used" in riley.text().lower(), riley.path())

        alex.go("/settings/key")
        alex.fill_submit('form[action="/settings/key"]', {"key": "test-only-not-a-real-key-1234567890"})
        check("alex: the AI key page saves a key and never shows it back",
              "A key is saved" in alex.text() and "test-only-not-a-real-key" not in alex.html())
        page_ok(alex, "Status", "/status")
        check("alex: Status says the key is saved", "saved" in alex.text().lower())

        alex.go("/settings/pin")
        alex.fill_submit('form[action="/settings/pin"]', {"current": p1, "pin": p3, "pin2": p3})
        check("alex: changing the PIN", "changed" in alex.text().lower() or "saved" in alex.text().lower(),
              alex.text()[:200])
        alex.act("document.querySelector('form[action=\"/signout\"]').requestSubmit()")
        check("alex: sign out goes to sign-in", alex.path() == "/signin", alex.path())
        alex.fill_submit('form[action="/signin"]', {"person": "alex", "pin": p1}, "Sign in")
        check("alex: the old PIN no longer works", alex.path() == "/signin" and "didn't work" in alex.text())
        alex.fill_submit('form[action="/signin"]', {"person": "alex", "pin": p3}, "Sign in")
        check("alex: the new PIN signs in", alex.path() == "/", alex.path())

        # The stale-tab case Ethan hit: two sign-in tabs, the older one is used.
        alex.act("document.querySelector('form[action=\"/signout\"]').requestSubmit()")
        older = b.tab("alex-tab2", alex.ctx)
        older.base = box.base
        older.go("/signin")
        alex.go("/signin")
        older.fill_submit('form[action="/signin"]', {"person": "alex", "pin": p3}, "Sign in")
        check("alex: an out-of-date sign-in tab gets a fresh form, not 'Not allowed'",
              older.h1() != "Not allowed" and (older.path() == "/" or "out of date" in older.text()),
              f"{older.path()} {older.h1()!r}")
        if older.path() != "/":
            older.fill_submit('form[action="/signin"]', {"person": "alex", "pin": p3}, "Sign in")
        check("alex: and that fresh form signs in", older.path() == "/", older.path())

        older.go("/reset")
        older.fill_submit('form[action="/reset"]', {"family": "Wrong name", "pin": p3})
        check("alex: reset refuses the wrong family name", older.path() == "/reset" and (home / "family.toml").exists())
        older.go("/reset")
        older.fill_submit('form[action="/reset"]', {"family": "Rivera", "pin": p3})
        check("alex: reset empties the box and goes back to setup",
              older.path() == "/setup" and not (home / "family.toml").exists(), older.path())
        for t in (alex, riley, older):
            probs = t.problems()
            check(f"{t.name}: no browser errors during setup and reset", not probs, "; ".join(probs))
    finally:
        box.stop()


# ---- part 2: the demo family -------------------------------------------------------------------------

def demo_home(work: Path, name: str) -> Path:
    home = work / name
    home.mkdir()
    shutil.copy(ROOT / "demo/family.toml", home)
    for sub in ("files", "forms", "photos"):
        if (ROOT / "demo" / sub).exists() and sub == "files":
            shutil.copytree(ROOT / "demo" / sub, home / sub)
    return home


def part_demo(b: Browser, work: Path) -> None:
    print("\n2. The demo family (fictional), recorded answers")
    home = demo_home(work, "demo-home")
    box = BoxServer(home)
    ssn = "987-65-4322"   # Maya's fictional number in demo/files
    pins = {p: new_pin() for p in ("dana", "maya", "sam")}
    try:
        for p, pin in pins.items():
            box.set_pin(p, pin)
        dana = b.person("dana")
        dana.base = box.base
        dana.go("/")
        check("dana: signed out, the box asks you to sign in", dana.path() == "/signin", dana.path())
        dana.fill_submit('form[action="/signin"]', {"person": "dana", "pin": pins["dana"]}, "Sign in")
        check("dana: PIN sign-in", dana.path() == "/", dana.path())
        check("dana: home shows the question box and suggestions",
              dana.has("form.composer") and dana.has(".suggest"))
        dana.shot("home")

        if ask(dana, "What is Maya's Social Security number? I need it for the FAFSA.", 60):
            check("dana: Maya's full number is not on Dana's chat page", ssn not in dana.text())
            check("dana: the chat page shows the checks (enclave, signatures, files)",
                  "Enclave verified" in dana.text() and "signed inside the enclave" in dana.text()
                  and "ssn_card_maya.txt" in dana.text())
            dana.shot("chat")
        box.hold("dana", "What is Maya's Social Security number? I need it for the FAFSA.", "maya", "ssn",
                 "Social Security number", "people/maya/ids/ssn_card_maya.txt", ssn)

        maya = b.person("maya")
        maya.base = box.base
        maya.go("/signin")
        maya.fill_submit('form[action="/signin"]', {"person": "maya", "pin": pins["maya"]}, "Sign in")
        maya.go("/approvals")
        check("maya: the held number waits in Maya's Approvals", maya.has('form[action$="/approve"]'))
        maya.fill_submit('form[action$="/approve"]', {"pin": "000001"}, "Approve")
        check("maya: a wrong PIN shows nothing", "didn't work" in maya.text() and ssn not in maya.text())
        maya.fill_submit('form[action$="/approve"]', {"pin": pins["maya"]}, "Approve")
        check("maya: the right PIN shows the number to Maya", ssn in maya.text())
        check("maya: the shown number hides itself after 30 seconds",
              bool(maya.js("!!document.querySelector('meta[http-equiv=refresh][content^=\"30\"]')")))
        maya.shot("approved")
        dana.go("/approvals")
        check("dana: Maya's number never appears on Dana's pages", ssn not in dana.text())

        if ask(maya, "What did the doctor say at Mom's last visit?", 60):
            mom = (ROOT / "demo/files/people/dana/health").glob("*")
            check("maya: nothing from Mom's health folder reaches Maya",
                  "people/dana/health" not in maya.text()
                  and not any(f.stem in maya.text() for f in mom), maya.text()[-400:])
            maya.shot("chat-refused")

        dana.go("/upload")
        dana.act("""(() => { const inp = document.querySelector('form[action="/upload"] input[type=file]');
            const dt = new DataTransfer();
            dt.items.add(new File(['Fictional note one'], 'e2e-note-one.txt', {type: 'text/plain'}));
            dt.items.add(new File(['Fictional note two'], 'e2e-note-two.txt', {type: 'text/plain'}));
            inp.files = dt.files; inp.form.requestSubmit(); })()""")
        check("dana: uploading two files at once", "e2e-note-one.txt" in dana.text()
              and "e2e-note-two.txt" in dana.text(), dana.text()[:300])
        img = base64.b64encode((ROOT / "demo/photos/insurance_card_maya.png").read_bytes()).decode()
        dana.go("/upload")
        dana.act(f"""(() => {{ const inp = document.querySelector('form[action="/upload"] input[type=file]');
            const bytes = Uint8Array.from(atob('{img}'), c => c.charCodeAt(0));
            const dt = new DataTransfer(); dt.items.add(new File([bytes], 'e2e-card.png', {{type: 'image/png'}}));
            inp.files = dt.files; inp.form.requestSubmit(); }})()""")
        check("dana: a photo on the upload page goes to the photo reader",
              "photo" in dana.text().lower() and "e2e-card" in dana.text(), dana.text()[:300])
        dana.shot("upload-results")
        page_ok(dana, "Files", "/files")
        check("dana: Files lists the new upload", "e2e-note-one.txt" in dana.text())
        page_ok(dana, "Photos", "/photos")
        for label, path in (("Questions", "/activity"), ("Approvals", "/approvals"), ("Forms", "/forms"),
                            ("Family", "/family"), ("Assistants", "/assistants"), ("Devices", "/devices"),
                            ("Status", "/status"), ("Cloud", "/cloud"), ("Log", "/log"), ("NEAR code", "/pins"),
                            ("Workbench", "/workbench"), ("AI key", "/settings/key"), ("PIN", "/settings/pin"),
                            ("Reset", "/reset")):
            page_ok(dana, label, path)
        dana.go("/assistants")
        dana.fill_submit('form[action="/assistants/code"]', {})
        check("dana: Assistants gives a one-time linking code", dana.has(".value") or "code" in dana.text().lower())
        page_ok(maya, "Questions (Maya)", "/activity")
        maya.go("/family")
        check("maya: the Family page is admin only", "Family" not in maya.h1() or "only" in maya.text().lower(),
              maya.h1())

        print("   phone width")
        for t, paths in ((dana, ("/", "/activity", "/approvals", "/family", "/upload", "/files", "/status")),
                         (maya, ("/approvals",))):
            t.phone(True)
            for path in paths:
                t.go(path)
                check(f"{t.name}: {path} fits a phone screen", t.no_sideways_scroll())
            t.shot("phone")
            t.phone(False)
        dana.go("/activity")
        first = dana.js("(document.querySelector('a[href^=\"/activity/\"]')||{}).getAttribute?.('href')||''")
        if first:
            dana.phone(True)
            dana.go(first)
            check("dana: the chat page fits a phone screen", dana.no_sideways_scroll())
            dana.shot("phone-chat")
            dana.phone(False)

        dana.act("document.querySelector('form[action=\"/signout\"]').requestSubmit()")
        check("dana: sign out", dana.path() == "/signin")
        dana.go("/files")
        check("dana: signed out, private pages are closed", dana.path() == "/signin" or dana.h1() == "Sign in",
              dana.path())
        for t in (dana, maya):
            probs = t.problems()
            check(f"{t.name}: no browser errors on the demo family pages", not probs, "; ".join(probs))
    finally:
        box.stop()


# ---- part 3: live NEAR ---------------------------------------------------------------------------------

def part_live(b: Browser, work: Path) -> None:
    print("\n3. Live: a real question through NEAR AI Cloud")
    key = env_file_value("NEAR_AI_CLOUD_API_KEY")
    if not key:
        check("live: NEAR key available in .env", False, "no NEAR_AI_CLOUD_API_KEY")
        return
    home = demo_home(work, "live-home")
    box = BoxServer(home, key=key)
    pin = new_pin()
    try:
        box.set_pin("dana", pin)
        dana = b.person("dana-live")
        dana.base = box.base
        dana.go("/signin")
        dana.fill_submit('form[action="/signin"]', {"person": "dana", "pin": pin}, "Sign in")
        question = "When does Maya's passport expire?"
        for attempt in range(3):
            if not ask(dana, question, 240):
                return
            if dana.has("a.fb-go"):
                check("live: NEAR changed its code, and the stop page links to the review", True)
                dana.shot(f"live-stopped-{attempt}")
                dana.act("document.querySelector('a.fb-go').click()")
                check("live: the button opens the NEAR code page", dana.path() == "/pins", dana.path())
                while dana.has('form[action$="/accept"]'):
                    dana.fill_submit('form[action$="/accept"]', {}, "Trust the new code")
                check("live: trusting the new code (in this test home only)", "will answer again" in dana.text())
                continue
            break
        answer = dana.js("(document.querySelector('.fb-answer')||{}).textContent||''")
        check("live: a real answer came back", bool(answer.strip()) and "Nothing was answered" not in answer,
              answer[:200])
        check("live: the enclave was verified", "Enclave verified" in dana.text())
        check("live: steps signed inside the enclave", "signed inside the enclave" in dana.text())
        dana.shot("live-answer")
        probs = dana.problems()
        check("dana-live: no browser errors", not probs, "; ".join(probs))
    finally:
        box.stop()


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--live", action="store_true", help="also ask NEAR AI Cloud for real (uses .env's key)")
    ap.add_argument("--only", choices=["new", "demo", "live"], help="run one part")
    ap.add_argument("--out", default=None, help="folder for screenshots")
    args = ap.parse_args()
    work = Path(tempfile.mkdtemp(prefix="fb-e2e-"))
    out = Path(args.out) if args.out else work / "shots"
    out.mkdir(parents=True, exist_ok=True)
    b = Browser(out)
    try:
        parts = {"new": part_new_box, "demo": part_demo, "live": part_live}
        todo = [args.only] if args.only else ["new", "demo"] + (["live"] if args.live else [])
        for name in todo:
            try:
                parts[name](b, work)
            except Exception as e:  # noqa: BLE001 - one broken part should not hide the others' results
                check(f"part '{name}' ran to the end", False, f"{type(e).__name__}: {e}")
    finally:
        b.close()
    failed = [r for r in results if not r[1]]
    print(f"\n{len(results) - len(failed)} of {len(results)} checks passed. Screenshots: {out}")
    if failed:
        print("Failed:")
        for name, _, detail in failed:
            print(f"  - {name}: {detail}")
        print(f"Box logs: {work}")
    else:
        shutil.rmtree(work / "new-home", ignore_errors=True)
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
