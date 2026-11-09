"""UNO Q Linux side: poll the family box, scroll who is asking on the LED matrix, send button presses.

The sketch (sketch/sketch.ino) draws frames and reports the button. Everything else is in approver.py,
which is the same code the desktop simulator (simulate.py) runs.

Setup: put the JSON that `familybox device add --as <person>` prints into data/approver.json in this
app's folder (or set FAMILYBOX_URL, FAMILYBOX_DEVICE_TOKEN and FAMILYBOX_CERT_SHA256).
UNTESTED ON HARDWARE: see README.md.
"""

import os
import time
from pathlib import Path

from arduino.app_utils import App, Bridge

import approver

APP_DIR = Path(__file__).resolve().parent.parent
CONFIG = Path(os.environ.get("FAMILYBOX_APPROVER_CONFIG", APP_DIR / "data" / "approver.json"))

BUTTON_NONE, BUTTON_SHORT, BUTTON_LONG = 0, 1, 2

try:
    client = approver.BoxClient.from_config(approver.load_config(CONFIG))
except (ValueError, OSError) as e:
    print(f"approver: not set up ({e})")
    client = None

state = approver.Approver(client)
runner = approver.Runner(state).start()
scroller = approver.Scroller()
last_words = None


def loop():
    global last_words
    try:
        event = Bridge.call("take_button", timeout=2)
    except Exception as e:  # noqa: BLE001 - keep drawing even if one call fails
        print(f"approver: take_button failed: {type(e).__name__}")
        event = BUTTON_NONE
    if event == BUTTON_SHORT:
        runner.press("short")
    elif event == BUTTON_LONG:
        runner.press("long")

    text, waiting = state.screen()
    words = approver.pack_frame(scroller.frame(text, waiting, time.monotonic()))
    if words != last_words:
        try:
            Bridge.call("show_frame", *words, timeout=2)
            last_words = words
        except Exception as e:  # noqa: BLE001
            print(f"approver: show_frame failed: {type(e).__name__}")
    time.sleep(0.03)


App.run(user_loop=loop)
