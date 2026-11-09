// Family box Approve button: the UNO Q microcontroller side (STM32, Zephyr core).
// UNTESTED ON HARDWARE. See ../README.md.
//
// The Linux side (python/main.py) does all the thinking. This sketch only:
//   - draws 8x13 frames it is sent:  Bridge "show_frame"(w0, w1, w2, w3), 104 pixels packed in 4 words,
//     pixel i = row * 13 + col is bit (31 - i % 32) of word i / 32 (same packing as approver.pack_frame)
//   - reports the button:            Bridge "take_button"() -> 0 nothing, 1 short press, 2 long press
//
// Button: a momentary push button between pin D2 and GND (the internal pull-up is used, so no resistor).
// A press shorter than LONG_MS approves; holding it for LONG_MS denies (reported as soon as LONG_MS
// passes, so you know when to let go). The board's built-in LED lights while the button is down.

#include <Arduino_RouterBridge.h>
#include <Arduino_LED_Matrix.h>

const int BUTTON_PIN = 2;
const unsigned long DEBOUNCE_MS = 30;
const unsigned long MIN_PRESS_MS = 40;
const unsigned long LONG_MS = 1500;

Arduino_LED_Matrix matrix;
uint8_t pixels[104];

volatile int pendingEvent = 0;   // 0 none, 1 short, 2 long; the first event waits until it is taken
bool lastRaw = HIGH;
bool stable = HIGH;
unsigned long lastChange = 0;
unsigned long pressedAt = 0;
bool longSent = false;

void show_frame(uint32_t w0, uint32_t w1, uint32_t w2, uint32_t w3) {
  uint32_t w[4] = {w0, w1, w2, w3};
  for (int i = 0; i < 104; i++) {
    pixels[i] = (w[i / 32] >> (31 - (i % 32))) & 1;
  }
  matrix.draw(pixels);
}

int take_button() {
  int e = pendingEvent;
  pendingEvent = 0;
  return e;
}

void report(int e) {
  if (pendingEvent == 0) pendingEvent = e;
}

void setup() {
  pinMode(BUTTON_PIN, INPUT_PULLUP);
  pinMode(LED_BUILTIN, OUTPUT);
  digitalWrite(LED_BUILTIN, HIGH);   // built-in LED is active low: HIGH is off
  matrix.begin();
  matrix.setGrayscaleBits(1);
  matrix.clear();
  Bridge.begin();
  // provide_safe: these run between loop() passes, so they never race the matrix or the button code.
  Bridge.provide_safe("show_frame", show_frame);
  Bridge.provide_safe("take_button", take_button);
}

void loop() {
  unsigned long now = millis();
  bool raw = digitalRead(BUTTON_PIN);
  if (raw != lastRaw) {
    lastRaw = raw;
    lastChange = now;
  }
  if (now - lastChange >= DEBOUNCE_MS && raw != stable) {
    stable = raw;
    if (stable == LOW) {             // pressed
      pressedAt = now;
      longSent = false;
      digitalWrite(LED_BUILTIN, LOW);
    } else {                         // released
      digitalWrite(LED_BUILTIN, HIGH);
      if (!longSent && now - pressedAt >= MIN_PRESS_MS) report(1);
    }
  }
  if (stable == LOW && !longSent && now - pressedAt >= LONG_MS) {
    longSent = true;
    report(2);
  }
  // Keep loop() short: provide_safe calls are served between passes.
}
