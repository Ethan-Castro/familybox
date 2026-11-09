"""Approver devices: a physical Approve button (hardware/unoq-approve) for held items.

CLI (run on the box itself):
  familybox device add --as dana [--name "Kitchen button"] [--url https://box.local:8443]
  familybox device list --as dana
  familybox device remove --as dana <device id>

JSON API for the device, on the box's web server. Bearer token only, no cookies, so no CSRF token is
needed (a web page on another site cannot set an Authorization header without a CORS answer, and this
API never gives one). Requests that carry an Origin header are refused: devices never send one.
  GET  /api/device/v1/pending                        items waiting for the device's person, oldest first
  POST /api/device/v1/items/<id>/approve | /deny     decide one item
Responses never include a held value, the question text, a file path or the box's own held-item id:
<id> is a random handle the box made for that waiting item.

Web page for the owner (signed in): /devices lists their devices (remove one) and what the button
decided, and shows a button-approved value once, here on the owner's own screen.
"""

from __future__ import annotations

import json
import time

from starlette.requests import Request
from starlette.responses import JSONResponse, Response
from starlette.routing import Route

from familybox.devices import Devices, ITEM_ID_RE

API = "/api/device/v1"
FAIL_MAX = 10              # wrong tokens per address per window before the API stops answering it
FAIL_WINDOW_S = 10 * 60
FAIL_ADDRS_MAX = 1000      # addresses remembered at once; the oldest are forgotten first


# --- CLI -------------------------------------------------------------------------------------------

def cli(sub) -> None:
    d = sub.add_parser("device", help="approver devices (the Approve button)")
    dsub = d.add_subparsers(dest="device_action", required=True)
    a = dsub.add_parser("add", help="make a device token for this person (shown once)")
    a.add_argument("--as", dest="person", required=True)
    a.add_argument("--name", default="Approve button")
    a.add_argument("--url", default="https://<this box>:8443",
                   help="the box's address as the device will reach it on the home network")
    ls = dsub.add_parser("list")
    ls.add_argument("--as", dest="person", required=True)
    rm = dsub.add_parser("remove")
    rm.add_argument("--as", dest="person", required=True)
    rm.add_argument("id")


def run_cli(args, cfg) -> int | None:
    if args.cmd != "device":
        return None
    try:
        person = cfg.person(args.person)
    except KeyError as e:
        print(e.args[0])
        return 2
    devs = Devices(cfg)
    if args.device_action == "add":
        from familybox import web
        dev_id, token = devs.add(person.id, args.name)
        _, _, fp = web.ensure_cert(cfg)
        print(f"Added device {dev_id} for {person.display}. It can only approve or deny {person.display}'s "
              f"held items. It never sees the values.")
        print("This token is shown only once. Put it on the device, then close this window.\n")
        print(json.dumps({"box_url": args.url, "token": token, "cert_sha256": fp}, indent=1))
        print("\nOn the UNO Q, save that as data/approver.json inside the app folder.")
        print("The box's web page must be listening on the home network: familybox serve --lan")
        print(f"To remove it later: familybox device remove --as {person.id} {dev_id}")
    elif args.device_action == "list":
        items = devs.list(person.id)
        if not items:
            print(f"{person.display} has no approver devices.")
        for d in items:
            seen = time.strftime("%Y-%m-%d %H:%M", time.localtime(d["last_seen"])) if d["last_seen"] else "never"
            print(f"{d['id']}  {d['name']}  (scope: {d['scope']}, last seen: {seen})")
    elif args.device_action == "remove":
        if not devs.remove(person.id, args.id):
            print(f"no device {args.id!r} for {person.display}")
            return 1
        print(f"Removed device {args.id}. Its token no longer works.")
    return 0


class FailureLog:
    """Wrong-token attempts per address, for the lockout. Bounded: empty entries are dropped and at most
    FAIL_ADDRS_MAX addresses are remembered, so a stream of addresses can't grow it without limit."""

    def __init__(self, max_addrs: int = FAIL_ADDRS_MAX):
        self.max_addrs = max_addrs
        self.times: dict[str, list[float]] = {}

    def locked(self, addr: str, now: float) -> bool:
        recent = [t for t in self.times.get(addr, []) if now - t < FAIL_WINDOW_S]
        if recent:
            self.times[addr] = recent
        else:
            self.times.pop(addr, None)
        return len(recent) >= FAIL_MAX

    def record(self, addr: str, now: float) -> None:
        self.times.setdefault(addr, []).append(now)
        if len(self.times) > self.max_addrs:
            for stale in [a for a, ts in self.times.items() if now - ts[-1] >= FAIL_WINDOW_S]:
                del self.times[stale]
            while len(self.times) > self.max_addrs:
                del self.times[min(self.times, key=lambda a: self.times[a][-1])]


# --- web -------------------------------------------------------------------------------------------

def web_nav() -> list[tuple[str, str]]:
    return [("Devices", "/devices")]


def web_routes(ctx) -> list:
    cfg = ctx.cfg
    esc = ctx.esc
    failures = FailureLog()

    def client_addr(request: Request) -> str:
        return request.client.host if request.client else "?"

    def device_of(request: Request):
        """(device, None) or (None, error Response)."""
        now = time.time()
        addr = client_addr(request)
        if request.headers.get("origin") is not None:
            return None, JSONResponse({"error": "not allowed"}, status_code=403)
        if failures.locked(addr, now):
            return None, JSONResponse({"error": "too many wrong tokens; wait 10 minutes"}, status_code=429)
        auth = request.headers.get("authorization", "")
        scheme, _, token = auth.partition(" ")
        dev = Devices(cfg).check_token(token.strip(), now) if scheme.lower() == "bearer" else None
        if dev is None:
            failures.record(addr, now)
            return None, JSONResponse({"error": "device not recognized"}, status_code=401,
                                      headers={"www-authenticate": 'Bearer realm="familybox-device"'})
        return dev, None

    async def api_pending(request: Request):
        dev, err = device_of(request)
        if err:
            return err
        items = Devices(cfg).pending_for(dev)
        return JSONResponse({"device": {"id": dev["id"], "name": dev["name"],
                                        "person": cfg.person(dev["person"]).display, "scope": dev["scope"]},
                             "count": len(items), "items": items})

    async def api_decide(request: Request):
        dev, err = device_of(request)
        if err:
            return err
        action = request.path_params["action"]
        item_id = request.path_params["item_id"]
        if action not in ("approve", "deny") or not ITEM_ID_RE.match(item_id):
            return JSONResponse({"error": "not found"}, status_code=404)
        try:
            out = Devices(cfg).decide(dev, item_id, action == "approve")
        except KeyError:
            return JSONResponse({"error": "that item is not waiting for you"}, status_code=404)
        return JSONResponse(out)

    def devices_page(sess, extra: str = "", status: int = 200):
        devs = Devices(cfg)
        rows = []
        for d in devs.list(sess.person.id):
            seen = (time.strftime("%b %d, %H:%M", time.localtime(d["last_seen"])) if d["last_seen"]
                    else "not yet")
            rows.append(
                f'<div class="card"><div><strong>{esc(d["name"])}</strong></div>'
                f'<div class="muted">Can approve or deny your held items. Never sees the values. '
                f'Last checked in: {esc(seen)}</div>'
                f'<form method="post" action="/devices/remove/{esc(d["id"])}">{ctx.csrf_field(sess.csrf)}'
                f'<button class="main quiet" type="submit">Remove this device</button></form></div>')
        listing = "".join(rows) or '<p class="muted">You have no approver devices.</p>'
        decided = []
        for d in devs.recent_decisions(sess.person.id):
            when = time.strftime("%b %d, %H:%M", time.localtime(d["time"]))
            verb = "Approved" if d["approved"] else "Denied"
            show = ""
            if d["showable"]:
                show = (f'<form method="post" action="/devices/show/{esc(d["item"])}">'
                        f'{ctx.csrf_field(sess.csrf)}<button class="main" type="submit">Show it here</button></form>')
            decided.append(f'<div class="card"><div>{esc(verb)} on {esc(d["device"])}, {esc(when)}</div>'
                           f'<div class="muted">{esc(d["text"])}</div>{show}</div>')
        body = (f'<h1>Devices</h1>{extra}'
                f'<p class="muted">An approver device is a button you keep at home. It shows who is asking for '
                f'one of your private details, and you press it to approve (or hold it to deny). The value '
                f'is never sent to the device or to the assistant. You can look at it here, once.</p>'
                f'{listing}'
                f'<p class="muted">To add one, run this on the box: <code>familybox device add --as '
                f'{esc(sess.person.id)}</code></p>'
                f'<h2>Decided with your button</h2>'
                f'{"".join(decided) or "<p class=muted>Nothing yet.</p>"}')
        return ctx.page(sess, "Devices", body, "/devices", status)

    @ctx.need_signin
    async def devices_get(request: Request, sess):
        return devices_page(sess)

    async def devices_remove(request: Request):
        got = await ctx.guarded_form(request)
        if isinstance(got, Response):
            return got
        sess, _ = got
        if not Devices(cfg).remove(sess.person.id, request.path_params["dev_id"]):
            return devices_page(sess, '<p class="bad">That device isn\'t yours or is already gone.</p>', 404)
        return devices_page(sess, '<p class="ok">Removed. Its token no longer works.</p>')

    async def devices_show(request: Request):
        got = await ctx.guarded_form(request)
        if isinstance(got, Response):
            return got
        sess, _ = got
        try:
            r = Devices(cfg).reveal(sess.person.id, request.path_params["item_id"])
        except KeyError:
            return devices_page(sess, '<p class="bad">That value can\'t be shown here.</p>', 404)
        extra = (f'<div class="card"><p class="ok">Here is your {esc(r["label"])}:</p>'
                 f'<div class="value">{esc(r["value"])}</div>'
                 f'<p class="muted">Only you can see this. It won\'t be shown again after you leave this page.</p>'
                 f'</div>')
        return devices_page(sess, extra)

    return [
        Route(f"{API}/pending", api_pending, methods=["GET"]),
        Route(f"{API}/items/{{item_id}}/{{action}}", api_decide, methods=["POST"]),
        Route("/devices", devices_get, methods=["GET"]),
        Route("/devices/remove/{dev_id}", devices_remove, methods=["POST"]),
        Route("/devices/show/{item_id}", devices_show, methods=["POST"]),
    ]
