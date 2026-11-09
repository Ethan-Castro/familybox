"""The UNO Q Approve button app (hardware/unoq-approve): config, HTTP client, button logic, LED frames,
the pinned HTTPS connection, the simulator, and the app against the real device API (mock HTTP only)."""

import http.server
import json
import shutil
import ssl
import sys
import threading
from pathlib import Path

import pytest
from starlette.testclient import TestClient

ROOT = Path(__file__).resolve().parents[1]
APP = ROOT / "hardware" / "unoq-approve"
sys.path.insert(0, str(APP / "python"))

import approver  # noqa: E402
import matrix_font  # noqa: E402

from familybox import config, web  # noqa: E402
from familybox.approvals import Approvals  # noqa: E402
from familybox.devices import Devices  # noqa: E402
from familybox.gate import Held  # noqa: E402
from familybox.store import Store  # noqa: E402

TOKEN = "fbd_0a1b2c3d_" + "A" * 43
FP = "AB:" * 31 + "AB"
PASSPORT = "X10483921"


class Clock:
    def __init__(self):
        self.t = 1000.0

    def __call__(self):
        return self.t


class FakeHTTP:
    """Records requests and answers from a script: {(method, path): (status, body)}."""

    def __init__(self, items=None):
        self.items = list(items or [])
        self.calls = []
        self.fail_next: tuple[int, bytes] | Exception | None = None

    def __call__(self, method, path, headers):
        self.calls.append((method, path, dict(headers)))
        if self.fail_next is not None:
            f, self.fail_next = self.fail_next, None
            if isinstance(f, Exception):
                raise f
            return f
        if headers.get("Authorization") != f"Bearer {TOKEN}":
            return 401, b"{}"
        if method == "GET" and path == "/api/device/v1/pending":
            return 200, json.dumps({"items": self.items}).encode()
        if method == "POST":
            _, _, _, _, _, item_id, action = path.split("/")
            if any(i["id"] == item_id for i in self.items):
                self.items = [i for i in self.items if i["id"] != item_id]
                return 200, json.dumps({"id": item_id, "status": action + "d"}).encode()
            return 404, b"{}"
        return 404, b"{}"


def item(i, text="Maya's ChatGPT wants Dana's passport number", created=1):
    return {"id": i, "text": text, "created": created}


def setup(items=None):
    http = FakeHTTP(items)
    clock = Clock()
    a = approver.Approver(approver.BoxClient(TOKEN, http), clock=clock)
    return a, http, clock


# --- config ----------------------------------------------------------------------------------------

def test_load_config_from_file_and_env(tmp_path):
    p = tmp_path / "approver.json"
    p.write_text(json.dumps({"box_url": "https://familybox.local:8443/", "token": TOKEN, "cert_sha256": FP}))
    c = approver.load_config(p, env={})
    assert c.box_url == "https://familybox.local:8443" and c.token == TOKEN and c.cert_sha256 == "ab" * 32
    c2 = approver.load_config(p, env={"FAMILYBOX_URL": "https://10.0.0.5:8443"})
    assert c2.box_url == "https://10.0.0.5:8443"


@pytest.mark.parametrize("bad", [
    {"box_url": "http://familybox.local:8443"},                 # never plain HTTP: the token would leak
    {"box_url": "https://<this box>:8443"},                     # placeholder left in
    {"token": "fbd_00000000_REPLACE-WITH-THE-TOKEN"},
    {"cert_sha256": "REPLACE:WITH:THE:FINGERPRINT"},
    {"cert_sha256": ""},
])
def test_load_config_rejects_bad_setup(tmp_path, bad):
    good = {"box_url": "https://familybox.local:8443", "token": TOKEN, "cert_sha256": FP}
    p = tmp_path / "approver.json"
    p.write_text(json.dumps(good | bad))
    with pytest.raises(ValueError):
        approver.load_config(p, env={})


def test_example_config_is_not_usable_as_is():
    with pytest.raises(ValueError):
        approver.load_config(APP / "approver.example.json", env={})


def test_missing_config_shows_setup_message():
    a = approver.Approver(None)
    assert a.screen()[0] == approver.ERROR_TEXT["setup"]
    assert a.press("short") is None


# --- HTTP client -----------------------------------------------------------------------------------

def test_client_sends_bearer_and_parses_items():
    http = FakeHTTP([item("b", created=5), item("a", created=2), {"id": 3, "text": "bad"}, "junk"])
    items = approver.BoxClient(TOKEN, http).pending()
    assert [i["id"] for i in items] == ["a", "b"]
    method, path, headers = http.calls[0]
    assert (method, path) == ("GET", "/api/device/v1/pending")
    assert headers["Authorization"] == f"Bearer {TOKEN}"
    assert "Cookie" not in headers and "Origin" not in headers


@pytest.mark.parametrize("status,body,kind", [(401, b"{}", "auth"), (404, b"{}", "gone"), (429, b"{}", "busy"),
                                              (500, b"{}", "server"), (200, b"not json", "server"),
                                              (200, b"[1]", "server"), (200, b'{"items": 3}', "server")])
def test_client_maps_errors(status, body, kind):
    with pytest.raises(approver.BoxError) as e:
        approver.BoxClient(TOKEN, lambda m, p, h: (status, body)).pending()
    assert e.value.kind == kind


def test_decide_quotes_the_id():
    http = FakeHTTP()
    with pytest.raises(approver.BoxError):
        approver.BoxClient(TOKEN, http).decide("../../pending", True)
    assert http.calls[0][1] == "/api/device/v1/items/..%2F..%2Fpending/approve"


# --- the button ------------------------------------------------------------------------------------

def test_press_approves_the_oldest_item_after_it_has_been_shown():
    a, http, clock = setup([item("old", created=1), item("new", "Sam's Claude wants Dana's SSN", created=9)])
    a.poll()
    text, n = a.screen()
    assert text.startswith("1 OF 2: Maya's ChatGPT wants Dana's passport number?") and n == 2
    assert a.press("short") is None                     # it only just appeared
    clock.t += approver.MIN_SHOWN_S
    assert a.press("short") == ("old", True)
    assert a.screen()[0] == "SENDING"
    assert a.press("short") is None                     # no double press while sending
    a.send("old", True)
    assert http.calls[-1][:2] == ("POST", "/api/device/v1/items/old/approve")
    assert a.screen()[0] == "APPROVED"
    assert a.press("short") is None                     # presses during the feedback are ignored
    clock.t += approver.FEEDBACK_S
    assert a.screen()[0].startswith("Sam's Claude wants Dana's SSN?")


def test_long_press_denies():
    a, http, clock = setup([item("x")])
    a.poll(); a.screen()
    clock.t += 2
    assert a.press("long") == ("x", False)
    a.send("x", False)
    assert http.calls[-1][1].endswith("/x/deny")
    assert a.screen()[0] == "DENIED"


def test_new_item_arriving_at_press_time_is_not_approved():
    a, http, clock = setup([item("first")])
    a.poll(); a.screen()
    clock.t += 5
    http.items.insert(0, item("sneaky", "Sam's Claude wants Dana's SSN", created=0))
    a.poll()                                            # oldest is now a different item, not yet on screen
    assert a.press("short") is None
    assert a.screen()[0] == "LOOK FIRST"
    clock.t += 1.5
    a.screen()                                          # the new oldest item is shown now
    assert a.press("short") is None                     # and must be readable for MIN_SHOWN_S first
    clock.t += approver.MIN_SHOWN_S
    assert a.press("short") == ("sneaky", True)


def test_press_with_nothing_waiting():
    a, _, clock = setup([])
    a.poll()
    assert a.screen() == ("", 0)
    assert a.press("short") is None
    assert a.screen()[0] == "NOTHING WAITING"


def test_item_already_decided_elsewhere():
    a, http, clock = setup([item("x")])
    a.poll(); a.screen(); clock.t += 2
    assert a.press("short") == ("x", True)
    http.items = []                                     # Dana approved it on her phone meanwhile
    a.send("x", True)
    assert a.screen()[0] == "ALREADY DECIDED"
    assert a.items == []


def test_send_failure_keeps_the_item():
    a, http, clock = setup([item("x")])
    a.poll(); a.screen(); clock.t += 2
    assert a.press("short")
    http.fail_next = approver.BoxError("unreachable")
    a.send("x", True)
    assert a.screen()[0] == "NOT SENT. TRY AGAIN"
    clock.t += approver.FEEDBACK_S
    assert a.screen()[0].startswith("Maya's ChatGPT")
    assert [i["id"] for i in a.items] == ["x"]


def test_poll_errors_show_plainly_and_block_presses():
    a, http, clock = setup([item("x")])
    a.poll(); a.screen(); clock.t += 2
    http.fail_next = approver.BoxError("unreachable")
    a.poll()
    assert a.screen() == ("CAN'T REACH THE BOX", 0)
    assert a.press("short") is None
    http.fail_next = (401, b"{}")
    a.poll()
    assert a.screen()[0] == approver.ERROR_TEXT["auth"]
    a.poll()                                            # recovers on the next good poll
    assert a.screen()[0].startswith("Maya's ChatGPT")
    assert a.press("short") is None                     # shown again from scratch
    clock.t += approver.MIN_SHOWN_S
    assert a.press("short") == ("x", True)


def test_runner_sends_from_its_thread():
    http = FakeHTTP([item("x")])
    a = approver.Approver(approver.BoxClient(TOKEN, http))
    r = approver.Runner(a, poll_s=0.05).start()
    try:
        import time
        deadline = time.time() + 3
        while not a.polled and time.time() < deadline:
            time.sleep(0.01)
        a.screen()
        a.shown_since -= approver.MIN_SHOWN_S
        r.press("short")
        while http.items and time.time() < deadline:
            time.sleep(0.01)
        assert http.items == []
        assert ("POST", "/api/device/v1/items/x/approve") in [c[:2] for c in http.calls]
    finally:
        r.stop()


# --- LED frames ------------------------------------------------------------------------------------

def test_font_glyphs_are_well_formed():
    for ch, g in matrix_font.GLYPHS.items():
        assert len(g) == 7, ch
        assert len({len(row) for row in g}) == 1, ch
        assert set("".join(g)) <= {"#", "."}, ch
    assert matrix_font.glyph("a") == matrix_font.GLYPHS["A"]
    assert matrix_font.glyph("’") == matrix_font.GLYPHS["'"]
    assert matrix_font.glyph("é") == matrix_font.GLYPHS["?"]


def test_short_text_is_centered_and_still():
    s = approver.Scroller()
    f1 = s.frame("OK", 0, 0.0)
    f2 = s.frame("OK", 0, 5.0)
    assert f1[:7] == f2[:7]
    cols = matrix_font.columns("OK")
    left = (13 - len(cols)) // 2
    assert all(f1[r][x] == 0 for r in range(7) for x in range(left))
    assert f1[0][left] == (cols[0] & 1)


def test_long_text_scrolls_in_from_the_right_and_loops():
    s = approver.Scroller(cols_per_s=10)
    text = "MAYA'S CHATGPT WANTS DANA'S PASSPORT NUMBER"
    width = len(matrix_font.columns(text))
    assert all(p == 0 for row in s.frame(text, 0, 0.0)[:7] for p in row)        # starts blank
    mid = s.frame(text, 0, 2.0)
    assert any(p for row in mid[:7] for p in row)
    period = (width + 13) / 10
    assert s.frame(text, 0, 2.0 + period)[:7] == mid[:7]


def test_bottom_row_counts_waiting_items_and_idle_heartbeat():
    s = approver.Scroller()
    assert s.frame("X", 3, 0.0)[7] == [1, 1, 1] + [0] * 10
    assert s.frame("X", 40, 0.0)[7] == [1] * 13
    assert s.frame("", 0, 2.0)[7][12] == 1 and s.frame("", 0, 3.0)[7][12] == 0


def test_pack_frame_matches_the_sketch_layout():
    f = [[0] * 13 for _ in range(8)]
    f[0][0] = 1          # pixel 0   -> word 0 bit 31
    f[2][6] = 1          # pixel 32  -> word 1 bit 31
    f[7][12] = 1         # pixel 103 -> word 3 bit 31 - 7
    w = approver.pack_frame(f)
    assert w == [1 << 31, 1 << 31, 0, 1 << 24]
    assert all(0 <= x < 2 ** 32 for x in w)
    assert approver.unpack_frame(w) == f
    full = approver.pack_frame([[1] * 13 for _ in range(8)])
    assert full[:3] == [2 ** 32 - 1] * 3 and full[3] == (2 ** 8 - 1) << 24


def test_sketch_unpacks_the_same_way():
    ino = (APP / "sketch" / "sketch.ino").read_text()
    assert "(w[i / 32] >> (31 - (i % 32))) & 1" in ino
    assert 'Bridge.provide_safe("show_frame"' in ino and 'Bridge.provide_safe("take_button"' in ino
    main = (APP / "python" / "main.py").read_text()
    assert 'Bridge.call("show_frame", *words' in main and 'Bridge.call("take_button"' in main


# --- against the real device API, through mock HTTP -------------------------------------------------

@pytest.fixture
def cfg(tmp_path, monkeypatch):
    shutil.copytree(ROOT / "demo" / "files", tmp_path / "files")
    shutil.copy(ROOT / "demo" / "family.toml", tmp_path / "family.toml")
    monkeypatch.delenv("FAMILYBOX_OAUTH_REDIRECT", raising=False)
    c = config.load(tmp_path)
    Store(c).reindex()
    return c


def test_app_against_the_box_api(cfg):
    Approvals(cfg).add("maya", "What is my mom's passport number?",
                       [Held("p1", "id", "Passport Number", PASSPORT, "dana", "people/dana/ids/passport_dana.txt")],
                       source="mcp-remote:chatgpt")
    _, token = Devices(cfg).add("dana", "Kitchen button")
    tc = TestClient(web.create_app(cfg), base_url="https://testserver")
    seen = []

    def transport(method, path, headers):
        r = tc.request(method, path, headers=headers)
        seen.append(r.text)
        return r.status_code, r.content

    clock = Clock()
    a = approver.Approver(approver.BoxClient(token, transport), clock=clock)
    a.poll()
    assert a.screen()[0].startswith("Maya's ChatGPT wants Dana's passport number?")
    clock.t += approver.MIN_SHOWN_S
    action = a.press("short")
    assert action == ("p1", True)
    a.send(*action)
    assert a.screen()[0] == "APPROVED"
    assert Approvals(cfg)._load()["p1"]["status"] == "approved"
    assert all(PASSPORT not in t for t in seen)


# --- pinned HTTPS on 127.0.0.1 (a real TLS handshake, no other network) -----------------------------

@pytest.fixture
def tls_server(cfg):
    cert, key, fp = web.ensure_cert(cfg)
    got = []

    class H(http.server.BaseHTTPRequestHandler):
        def do_GET(self):
            got.append(dict(self.headers))
            body = json.dumps({"items": [item("t1")]}).encode()
            self.send_response(200)
            self.send_header("content-type", "application/json")
            self.send_header("content-length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def log_message(self, *a):
            pass

    srv = http.server.HTTPServer(("127.0.0.1", 0), H)
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.load_cert_chain(str(cert), str(key))
    srv.socket = ctx.wrap_socket(srv.socket, server_side=True)
    t = threading.Thread(target=srv.serve_forever, daemon=True)
    t.start()
    yield f"https://127.0.0.1:{srv.server_address[1]}", fp, got
    srv.shutdown()


def test_pinned_https_accepts_the_right_certificate(tls_server):
    url, fp, got = tls_server
    items = approver.BoxClient(TOKEN, approver.pinned_https(url, fp, timeout=3)).pending()
    assert [i["id"] for i in items] == ["t1"]
    assert got[0]["Authorization"] == f"Bearer {TOKEN}"


def test_pinned_https_refuses_another_certificate_before_sending_the_token(tls_server):
    url, fp, got = tls_server
    with pytest.raises(approver.BoxError) as e:
        approver.BoxClient(TOKEN, approver.pinned_https(url, "00" * 32, timeout=3)).pending()
    assert e.value.kind == "cert"
    assert got == []


def test_unreachable_box():
    with pytest.raises(approver.BoxError) as e:
        approver.BoxClient(TOKEN, approver.pinned_https("https://127.0.0.1:9", "00" * 32, timeout=1)).pending()
    assert e.value.kind == "unreachable"


# --- simulator and copy -----------------------------------------------------------------------------

def test_simulator_script_runs_end_to_end(capsys):
    sys.path.insert(0, str(APP))
    import simulate
    rc = simulate.main(["--demo", "--requests", "2", "--script", "wait 2, short, wait 4.2, long, wait 0.5",
                        "--every", "0.5"])
    out = capsys.readouterr().out
    assert rc == 0
    assert "Maya's ChatGPT wants Dana's passport number" in out
    assert "APPROVED" in out and "DENIED" in out
    assert "decisions sent to the box: [('demo0001', 'approved'), ('demo0002', 'denied')]" in out


def test_simulator_draws_the_matrix():
    sys.path.insert(0, str(APP))
    import simulate
    f = [[0] * 13 for _ in range(8)]
    f[0][0] = 1
    out = simulate.draw(f, "HI", "keys", ansi=False)
    assert out.splitlines()[1] == "|#............|" and "HI" in out


def test_no_em_dashes_in_the_app():
    for p in APP.rglob("*"):
        if p.is_file() and p.suffix in (".py", ".ino", ".md", ".yaml", ".json"):
            assert "—" not in p.read_text(), p
