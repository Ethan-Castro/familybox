"""The Approve button's logic. Pure Python standard library, so it runs on the UNO Q's Linux side,
in the desktop simulator, and in tests.

  BoxClient   talks to the family box's device API over HTTPS, pinned to the box's certificate
  Approver    what is waiting, what the screen says, what a button press does
  Scroller    turns screen text into 8x13 LED frames
  Runner      a background thread for the network, so scrolling never stalls

The device never receives a held value. It only learns who asked, which assistant, and what kind of
detail ("Maya's assistant wants Dana's passport number", or "Maya's ChatGPT ..." when the assistant's
connection reports its name), and sends back approve or deny for one item. Items are named by a random
handle the box makes, never by the box's own id for the held detail.
"""

from __future__ import annotations

import hashlib
import http.client
import json
import os
import queue
import re
import socket
import ssl
import threading
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Callable
from urllib.parse import quote, urlsplit

from matrix_font import columns

API = "/api/device/v1"
WIDTH, HEIGHT = 13, 8
MAX_RESPONSE = 64 * 1024

POLL_S = 3.0          # how often to ask the box what is waiting
SLOW_POLL_S = 60.0    # after "not set up" or "too many wrong tries": ask much less often
MIN_SHOWN_S = 1.5     # a press only counts once the item has been on screen this long
FEEDBACK_S = 2.5      # how long "APPROVED" / "DENIED" stays up
HINT = "  PRESS = YES, HOLD = NO"

ERROR_TEXT = {
    "unreachable": "CAN'T REACH THE BOX",
    "auth": "THIS BUTTON IS NOT SET UP. ADD IT AGAIN ON THE BOX",
    "cert": "WRONG BOX CERTIFICATE. CHECK THE SETUP",
    "server": "THE BOX HAD A PROBLEM",
    "busy": "TOO MANY WRONG TRIES. WAIT 10 MINUTES",
    "setup": "NOT SET UP YET. SEE THE README",
}


class BoxError(Exception):
    def __init__(self, kind: str, detail: str = ""):
        super().__init__(f"{kind}: {detail}" if detail else kind)
        self.kind = kind     # unreachable | auth | cert | server | gone | busy


# --- config ----------------------------------------------------------------------------------------

@dataclass(frozen=True)
class DeviceConfig:
    box_url: str
    token: str
    cert_sha256: str     # hex, with or without colons


def normalize_fp(fp: str) -> str:
    fp = re.sub(r"[\s:]", "", fp or "").lower()
    if not re.fullmatch(r"[0-9a-f]{64}", fp):
        raise ValueError("cert_sha256 must be the box's 64 hex digit SHA-256 certificate fingerprint")
    return fp


def load_config(path: Path | None = None, env: dict | None = None) -> DeviceConfig:
    """data/approver.json (made by `familybox device add`), or FAMILYBOX_URL / FAMILYBOX_DEVICE_TOKEN /
    FAMILYBOX_CERT_SHA256. Raises ValueError when something is missing or wrong."""
    env = os.environ if env is None else env
    data: dict = {}
    if path is not None and path.exists():
        data = json.loads(path.read_text())
    url = env.get("FAMILYBOX_URL") or data.get("box_url", "")
    token = env.get("FAMILYBOX_DEVICE_TOKEN") or data.get("token", "")
    fp = env.get("FAMILYBOX_CERT_SHA256") or data.get("cert_sha256", "")
    parts = urlsplit(url)
    if parts.scheme != "https" or not parts.hostname or "<" in url:
        raise ValueError("box_url must look like https://box.local:8443")
    if not re.fullmatch(r"fbd_[0-9a-f]{8}_[A-Za-z0-9_-]{43}", token or ""):
        raise ValueError("token is missing or not a family box device token")
    return DeviceConfig(url.rstrip("/"), token, normalize_fp(fp))


# --- HTTP ------------------------------------------------------------------------------------------

Transport = Callable[[str, str, dict], tuple[int, bytes]]   # (method, path, headers) -> (status, body)


def pinned_https(box_url: str, cert_sha256: str, timeout: float = 5.0) -> Transport:
    """HTTPS to the box, trusting exactly one certificate: the one whose SHA-256 matches the pin.

    The box uses a self-signed certificate, so normal CA checks cannot work. Instead the certificate is
    checked against the fingerprint `familybox device add` printed, before the token is sent."""
    parts = urlsplit(box_url)
    host, port = parts.hostname, parts.port or 443
    pin = normalize_fp(cert_sha256)

    def send(method: str, path: str, headers: dict) -> tuple[int, bytes]:
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        ctx.minimum_version = ssl.TLSVersion.TLSv1_2
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE        # replaced by the fingerprint pin below
        conn = http.client.HTTPSConnection(host, port, timeout=timeout, context=ctx)
        try:
            conn.connect()
            der = conn.sock.getpeercert(binary_form=True)
            if not der or hashlib.sha256(der).hexdigest() != pin:
                raise BoxError("cert", "the box's certificate does not match the saved fingerprint")
            conn.request(method, path, body=b"" if method == "POST" else None, headers=headers)
            resp = conn.getresponse()
            body = resp.read(MAX_RESPONSE + 1)
            if len(body) > MAX_RESPONSE:
                raise BoxError("server", "reply too large")
            return resp.status, body
        except BoxError:
            raise
        except (OSError, socket.timeout, http.client.HTTPException, ssl.SSLError) as e:
            raise BoxError("unreachable", type(e).__name__) from None
        finally:
            conn.close()

    return send


class BoxClient:
    def __init__(self, token: str, transport: Transport):
        self.token = token
        self.transport = transport

    @classmethod
    def from_config(cls, cfg: DeviceConfig, timeout: float = 5.0) -> BoxClient:
        return cls(cfg.token, pinned_https(cfg.box_url, cfg.cert_sha256, timeout))

    def _call(self, method: str, path: str) -> dict:
        headers = {"Authorization": f"Bearer {self.token}", "Accept": "application/json",
                   "User-Agent": "familybox-unoq-approve/0.1"}
        status, body = self.transport(method, path, headers)
        if status == 401:
            raise BoxError("auth")
        if status == 404:
            raise BoxError("gone")
        if status == 429:
            raise BoxError("busy")
        if status != 200:
            raise BoxError("server", f"HTTP {status}")
        try:
            data = json.loads(body)
        except ValueError:
            raise BoxError("server", "not JSON") from None
        if not isinstance(data, dict):
            raise BoxError("server", "unexpected reply")
        return data

    def pending(self) -> list[dict]:
        data = self._call("GET", f"{API}/pending")
        items = data.get("items")
        if not isinstance(items, list):
            raise BoxError("server", "no items list")
        out = []
        for it in items:
            if isinstance(it, dict) and isinstance(it.get("id"), str) and isinstance(it.get("text"), str):
                try:
                    created = int(it.get("created") or 0)
                except (TypeError, ValueError):
                    created = 0
                out.append({"id": it["id"], "text": it["text"][:200], "created": created})
        out.sort(key=lambda x: (x["created"], x["id"]))
        return out

    def decide(self, item_id: str, approve: bool) -> dict:
        action = "approve" if approve else "deny"
        return self._call("POST", f"{API}/items/{quote(item_id, safe='')}/{action}")


# --- what the button does --------------------------------------------------------------------------

class Approver:
    """Thread-safe state. The network thread calls poll() and send(); the display loop calls screen() and
    press(). A press always refers to the item that is on screen, and only after it has been readable for
    MIN_SHOWN_S, so a new item that appears just as someone presses is never approved by accident."""

    def __init__(self, client: BoxClient | None, clock: Callable[[], float] = time.monotonic):
        self.client = client
        self.clock = clock
        self.items: list[dict] = []
        self.error: str | None = None if client else "setup"
        self.feedback: tuple[str, float] | None = None
        self.shown_id: str | None = None
        self.shown_since = 0.0
        self.busy = False
        self.polled = False
        self._lock = threading.Lock()

    # network side

    def poll(self) -> None:
        if self.client is None:
            return
        try:
            items = self.client.pending()
        except BoxError as e:
            with self._lock:
                self.error = e.kind if e.kind in ERROR_TEXT else "server"
            return
        with self._lock:
            self.items, self.error, self.polled = items, None, True

    def send(self, item_id: str, approve: bool) -> None:
        try:
            self.client.decide(item_id, approve)
        except BoxError as e:
            with self._lock:
                self.busy = False
                if e.kind == "gone":
                    self.items = [i for i in self.items if i["id"] != item_id]
                    self._say("ALREADY DECIDED")
                elif e.kind in ("auth", "busy"):
                    self.error = e.kind
                else:
                    self._say("NOT SENT. TRY AGAIN")
            return
        with self._lock:
            self.busy = False
            self.items = [i for i in self.items if i["id"] != item_id]
            self._say("APPROVED" if approve else "DENIED")

    # display side

    def _say(self, text: str, seconds: float = FEEDBACK_S) -> None:
        self.feedback = (text, self.clock() + seconds)
        self.shown_id = None

    def screen(self) -> tuple[str, int]:
        """(text to show, how many items are waiting). Empty text means nothing is waiting."""
        now = self.clock()
        with self._lock:
            n = len(self.items)
            if self.busy:
                return "SENDING", n
            if self.feedback and now < self.feedback[1]:
                return self.feedback[0], n
            self.feedback = None
            if self.error:
                self.shown_id = None
                return ERROR_TEXT[self.error], 0
            if not self.items:
                self.shown_id = None
                return "", 0
            cur = self.items[0]
            if cur["id"] != self.shown_id:
                self.shown_id, self.shown_since = cur["id"], now
            prefix = f"1 OF {n}: " if n > 1 else ""
            return f"{prefix}{cur['text']}?{HINT}", n

    def press(self, kind: str) -> tuple[str, bool] | None:
        """kind is 'short' (approve) or 'long' (deny). Returns (item id, approve) to send, or None."""
        now = self.clock()
        with self._lock:
            if self.busy or (self.feedback and now < self.feedback[1]) or self.error:
                return None
            if not self.items or self.shown_id != self.items[0]["id"]:
                self._say("NOTHING WAITING" if not self.items else "LOOK FIRST", 1.5)
                return None
            if now - self.shown_since < MIN_SHOWN_S:
                return None     # too soon after it appeared: ignore quietly
            self.busy = True
            return self.items[0]["id"], kind == "short"


# --- LED frames ------------------------------------------------------------------------------------

Frame = list[list[int]]   # HEIGHT rows of WIDTH 0/1


class Scroller:
    """Text on rows 0-6, scrolling right to left when it is wider than the matrix. Row 7 shows one dot per
    waiting item. When nothing is waiting, a single corner dot blinks so you can see the button is alive."""

    def __init__(self, cols_per_s: float = 14.0):
        self.cols_per_s = cols_per_s
        self.text: str | None = None
        self.start = 0.0
        self.cols: list[int] = []

    def frame(self, text: str, waiting: int, now: float) -> Frame:
        if text != self.text:
            self.text, self.start, self.cols = text, now, columns(text) if text else []
        grid = [[0] * WIDTH for _ in range(HEIGHT)]
        cols = self.cols
        if len(cols) <= WIDTH:
            left = (WIDTH - len(cols)) // 2
            window = [0] * left + cols + [0] * (WIDTH - left - len(cols))
        else:
            strip = [0] * WIDTH + cols + [0] * WIDTH
            off = int((now - self.start) * self.cols_per_s) % (len(cols) + WIDTH)
            window = strip[off:off + WIDTH]
        for x, col in enumerate(window):
            for r in range(7):
                grid[r][x] = (col >> r) & 1
        for x in range(min(waiting, WIDTH)):
            grid[7][x] = 1
        if not text and not waiting and int(now) % 2 == 0:
            grid[7][WIDTH - 1] = 1
        return grid


def pack_frame(frame: Frame) -> list[int]:
    """104 pixels into 4 unsigned 32-bit words for Bridge.call. Pixel i = row * 13 + col is bit
    (31 - i % 32) of word i // 32. sketch.ino unpacks the same way."""
    words = [0, 0, 0, 0]
    for r in range(HEIGHT):
        for c in range(WIDTH):
            if frame[r][c]:
                i = r * WIDTH + c
                words[i // 32] |= 1 << (31 - i % 32)
    return words


def unpack_frame(words: list[int]) -> Frame:
    return [[(words[(r * WIDTH + c) // 32] >> (31 - (r * WIDTH + c) % 32)) & 1 for c in range(WIDTH)]
            for r in range(HEIGHT)]


def frame_to_text(frame: Frame, on: str = "#", off: str = ".") -> str:
    return "\n".join("".join(on if p else off for p in row) for row in frame)


# --- threads ---------------------------------------------------------------------------------------

class Runner:
    """Network work on its own thread: poll every POLL_S, and send a decision as soon as it is pressed."""

    def __init__(self, approver: Approver, poll_s: float = POLL_S):
        self.approver = approver
        self.poll_s = poll_s
        self.decisions: queue.Queue = queue.Queue()
        self._stop = threading.Event()
        self._thread: threading.Thread | None = None

    def press(self, kind: str) -> None:
        action = self.approver.press(kind)
        if action:
            self.decisions.put(action)

    def wait_s(self) -> float:
        """Poll slowly while the box refuses this button, so a removed button can't lock out its address."""
        return max(self.poll_s, SLOW_POLL_S) if self.approver.error in ("auth", "busy") else self.poll_s

    def _safely(self, fn: Callable[[], None]) -> None:
        """Run one poll or send. Anything unexpected shows "THE BOX HAD A PROBLEM" and the loop keeps going,
        instead of the network thread dying and the screen freezing on SENDING."""
        try:
            fn()
        except Exception as e:   # noqa: BLE001  any bug in a reply must not stop the button
            print(f"familybox-unoq: unexpected {type(e).__name__} talking to the box", flush=True)
            with self.approver._lock:
                self.approver.busy = False
                self.approver.error = "server"

    def step(self) -> None:
        """One turn of the network loop: send a pressed decision if there is one, else poll."""
        try:
            item_id, approve = self.decisions.get(timeout=self.wait_s())
        except queue.Empty:
            self._safely(self.approver.poll)
            return
        self._safely(lambda: self.approver.send(item_id, approve))
        self._safely(self.approver.poll)

    def _loop(self) -> None:
        self._safely(self.approver.poll)
        while not self._stop.is_set():
            self.step()

    def start(self) -> Runner:
        if self.approver.client is not None:
            self._thread = threading.Thread(target=self._loop, name="familybox-net", daemon=True)
            self._thread.start()
        return self

    def stop(self) -> None:
        self._stop.set()
