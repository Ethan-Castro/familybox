# Family box Approve button (Arduino UNO Q)

A button you keep at home. When an assistant's answer included one of your private details, the family box
holds the detail back. This button scrolls who is asking on the UNO Q's LED matrix, for example
"Maya's ChatGPT wants Dana's passport number". Press the button to approve. Hold it for 1.5 seconds to deny.

> **UNTESTED ON HARDWARE.** Everything here was written from Arduino's documentation and tested only on a
> laptop: the logic, the box's device API, the HTTPS certificate pin, and the desktop simulator. The sketch
> has not been compiled or flashed, and no UNO Q has run this app yet. The steps below are the expected
> steps, not checked ones.

## What the button can and cannot do

- It can see: who asked, which assistant (when the box knows it), whose detail, and what kind of detail.
  Health details are only ever called "health detail", never "diagnosis" or "medication", because anyone
  in the room can read the matrix.
- It can do: approve or deny one item, for the one person it belongs to.
- It never receives the held value, the question, or a file name. Approving does not send the value to the
  assistant either. The owner can look at an approved value once, on the box's own page (Devices), signed in.
- Its token only works on the device API. It cannot ask questions, open the box's web page, or touch
  anyone else's items. Remove it any time with `familybox device remove` or on the Devices page.

## Try it without the board

```sh
python hardware/unoq-approve/simulate.py --demo
```

Space or Enter is a press (approve), H is a hold (deny), A adds a made-up request, Q quits. The demo uses
the made-up Okafor household only. To point the simulator at a real box, use the JSON from
`familybox device add` (next section):

```sh
python hardware/unoq-approve/simulate.py --config approver.json
```

Without a keyboard (for a recording): `--script "wait 3, short, wait 5, long, wait 3"`.

## Set up the box

On the family box (the Raspberry Pi), for the person whose button this is:

```sh
familybox device add --as dana --name "Kitchen button" --url https://<box name>.local:8443
```

It prints a token once, plus the box's certificate fingerprint, as JSON. The button checks that fingerprint
before it sends anything, so it only ever talks to your box. The box's page must listen on the home
network for the button to reach it:

```sh
familybox serve --lan
```

## Wire the button

A momentary push button between pin **D2** and **GND**. No resistor: the sketch uses the internal pull-up.
The board's built-in LED lights while the button is down.

## Put the app on the UNO Q (expected steps, untested)

The app follows Arduino App Lab's layout: `app.yaml`, `python/main.py` (Linux side), and
`sketch/sketch.ino` with `sketch/sketch.yaml` (microcontroller side). They talk over App Lab's Bridge:
the sketch provides `show_frame` (draw one 8x13 frame) and `take_button` (0 nothing, 1 press, 2 hold);
`python/main.py` calls them. All the logic is in `python/approver.py`, the same file the simulator runs.

**With Arduino App Lab**

1. Install Arduino App Lab, connect the UNO Q, and let it update the board.
2. My Apps, Create new app, name it "Family box Approve button".
3. Replace the new app's `python/main.py` with this folder's `python/main.py`, and add `python/approver.py`
   and `python/matrix_font.py` next to it.
4. Replace `sketch/sketch.ino` with this folder's `sketch/sketch.ino`. Keep the `sketch.yaml` App Lab made
   (this folder's copy is only a fallback).
5. Save the JSON from `familybox device add` as `data/approver.json` inside the app's folder. App Lab
   leaves `data/` out of exports unless you choose to include it, which keeps the token off shared copies.
6. Press Run. The matrix should show nothing but a blinking corner dot until something is waiting.

**With arduino-app-cli on the board**

1. Copy this folder to the board as `~/ArduinoApps/unoq-approve` (with `data/approver.json` inside it).
2. On the board: `arduino-app-cli app start ~/ArduinoApps/unoq-approve`
3. Logs: `arduino-app-cli app logs ~/ArduinoApps/unoq-approve`. Stop: `arduino-app-cli app stop ...`

Instead of `data/approver.json` you can set `FAMILYBOX_URL`, `FAMILYBOX_DEVICE_TOKEN` and
`FAMILYBOX_CERT_SHA256`, or point `FAMILYBOX_APPROVER_CONFIG` at the file.

## What the matrix shows

| Matrix | Meaning |
|---|---|
| Blinking dot, bottom right | Nothing waiting. The button is running. |
| Scrolling request, dots on the bottom row | One dot per waiting item. The oldest one is shown. |
| SENDING, then APPROVED or DENIED | Your press reached the box. |
| ALREADY DECIDED | Someone decided it on the box's page first. Nothing changed. |
| NOT SENT. TRY AGAIN | The box did not answer. The item is still waiting. |
| CAN'T REACH THE BOX | Check the box is on and running `familybox serve --lan`. |
| WRONG BOX CERTIFICATE | The box's certificate changed. Run `familybox device add` again. |
| THIS BUTTON IS NOT SET UP | The token was removed or is wrong. |

A press only counts once the request has been on screen for 1.5 seconds, so a new request that appears
just as you press is never approved by accident. Early presses are ignored.

## Things to check on real hardware

- The sketch compiles with the board's bundled `Arduino_LED_Matrix` and `Arduino_RouterBridge` libraries,
  and `Bridge.provide_safe` accepts the four `uint32_t` arguments of `show_frame`.
- Pixel 0 is the top left corner (text reads left to right, not mirrored or upside down).
- About 15 Bridge calls a second (frames plus button checks) keeps scrolling smooth.
- The App Lab Python container can reach the box over the home network, and `data/approver.json` is
  found at `../data/approver.json` from `python/main.py`.
- Debounce (30 ms) and hold time (1.5 s) feel right with the chosen button.
