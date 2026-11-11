"""The family on the box's page: first-time setup, the Family page and invites.

  /setup            first visit to a new box: family name, your name and a PIN (15 minute window)
  /family           people, what each may also read, words never to share, invite, remove (admin only)
  /family/invite    a one-time invite: code, link and QR, good for 30 minutes
  /join             someone invited opens the link, sets their own PIN and is signed in
  /settings/key     paste the NEAR AI key once and check it (admin only); the key is never shown again
  /status           the box in plain words: AI key, last check, files, approvals, assistants, disk
  /reset            wipe the box back to new, with your PIN and the family name typed out (admin only)

None of these is in remote.REMOTE_PATHS: they work only on the home network page.
Every setup, invite, access change, removal and key change is written to the admin's audit log. A reset
deletes the logs with everything else, so it can't be logged on the box.
"""

from __future__ import annotations

import asyncio
import os
import re
import secrets
import shutil
import time

from starlette.requests import Request
from starlette.responses import RedirectResponse, Response
from starlette.routing import Route

from .. import household
from ..household import HouseholdError

ADMIN_ONLY = "Only the person who runs the box can do that."
KEY_MIN, KEY_MAX = 16, 512
KEY_CHECK_FILE = "key_check.json"     # in <runtime>/web: time and result of the last key check, never the key
KEY_CHECK_TIMEOUT_S = 60
_REASON = re.compile(r"[A-Za-z0-9_.-]{1,40}")


def web_nav():
    return [("Family", "/family")]


def _qr_svg(link: str) -> str:
    import segno
    # segno draws with fill and stroke attributes only (no style attributes), so the page's CSP holds.
    return segno.make(link, error="m").svg_inline(scale=5, border=4, light="#fff", title="Invite link")


def key_problem(key: str) -> str | None:
    """Why a pasted key can't be saved, in plain words, or None. Never repeats the key."""
    if not key:
        return "Paste the key first."
    if not KEY_MIN <= len(key) <= KEY_MAX:
        return "That doesn't look like a NEAR AI key. Check that you copied all of it."
    if any(ch.isspace() or not ch.isprintable() for ch in key):
        return "That doesn't look like a NEAR AI key. It should have no spaces in it."
    return None


def save_key(cfg, key: str) -> None:
    """Store the key 0600 in <runtime>/secrets/near_api_key and use it in this process from now on."""
    from .. import config
    from ..web import _write_private
    path = config.key_path(cfg.home)
    _write_private(path, key.encode())
    os.chmod(path.parent, 0o700)
    os.environ[config.KEY_ENV[0]] = key


def _attest(key: str, model: str) -> dict:
    """Run the same check as `familybox verify`, in its own event loop (called from a worker thread)."""
    from .. import cli
    return asyncio.run(cli.check_attestation(key, model))


def _reason(r: dict, key: str) -> str:
    """A short code for why the check failed, safe to keep and show. Free text is dropped."""
    why = str(r.get("error") or ("no_model_reports" if not r.get("ok") else ""))
    if not _REASON.fullmatch(why) or (key and key in why):
        return "other"
    return why


def _ago(ts) -> str:
    if not ts:
        return "never"
    s = max(0, int(time.time() - float(ts)))
    if s < 90:
        return "just now"
    if s < 90 * 60:
        return f"{s // 60} minutes ago"
    if s < 36 * 3600:
        return f"{round(s / 3600)} hours ago"
    return f"{round(s / 86400)} days ago"


def _disk(n: int) -> str:
    gb = n / 1024 ** 3
    return f"{gb:.1f} GB" if gb >= 1 else f"{n // 1024 ** 2} MB"


def web_routes(ctx):
    from .. import enclave
    from ..web import (COOKIE, INVITE_TTL_S, _audit, _page, origin_ok, pre_ok, readable_files, set_pre_cookie,
                       signed_in)

    cfg, esc, state = ctx.cfg, ctx.esc, ctx.state
    csrf = ctx.csrf_field

    def note(msg: str, ok: bool) -> str:
        return f'<p class="{"ok" if ok else "bad"}">{esc(msg)}</p>' if msg else ""

    # ---- first-time setup
    def setup_page(msg: str = "", status: int = 200) -> Response:
        if not household.setup_open(cfg):
            body = ('<h1>Setup is closed</h1><div class="card"><p>For safety, a new box can only be set up in the '
                    'first 15 minutes after it starts.</p><p>Unplug the box and plug it back in to start setup.</p>'
                    '</div>')
            return _page(cfg, "Setup", body, status=403 if status == 200 else status)
        pre = secrets.token_urlsafe(24)
        body = (f'<h1>Set up your family box</h1>{note(msg, False)}'
                f'<form method="post" action="/setup" class="card">{csrf(pre)}'
                f'<label for="family">Family name</label>'
                f'<input type="text" id="family" name="family" maxlength="{household.NAME_MAX}"'
                f' placeholder="The Okafor family" required>'
                f'<label for="name">Your name</label>'
                f'<input type="text" id="name" name="name" maxlength="{household.NAME_MAX}" autocomplete="given-name"'
                f' required>'
                f'<label for="pin">Choose a PIN</label>'
                f'<input type="password" id="pin" name="pin" inputmode="numeric" maxlength="{household.PIN_MAX}"'
                f' autocomplete="new-password" required>'
                f'<label for="pin2">Type the PIN again</label>'
                f'<input type="password" id="pin2" name="pin2" inputmode="numeric" maxlength="{household.PIN_MAX}"'
                f' autocomplete="new-password" required>'
                f'<p class="muted">{household.PIN_MIN} to {household.PIN_MAX} numbers. You use it to sign in on '
                f'this page. You will run the box: you can add your family next.</p>'
                f'<button class="main" type="submit">Set up the box</button></form>')
        return set_pre_cookie(_page(cfg, "Setup", body, status=status), pre)

    async def setup_get(request: Request):
        if cfg.people:
            return RedirectResponse("/" if ctx.session_of(request) else "/signin", status_code=303)
        return setup_page()

    async def setup_post(request: Request):
        if cfg.people:
            return ctx.forbidden("This box is already set up.")
        form = await request.form()
        if not pre_ok(request, form):
            return ctx.forbidden()
        if not household.setup_open(cfg):
            return setup_page(status=403)
        pin = str(form.get("pin", ""))
        if pin != str(form.get("pin2", "")):
            return setup_page("The two PINs don't match. Try again.", 400)
        try:
            person = household.setup_family(state, str(form.get("family", "")), str(form.get("name", "")), pin)
        except HouseholdError as e:
            if not household.setup_open(cfg):
                return ctx.forbidden("This box is already set up.") if cfg.people else setup_page(status=403)
            return setup_page(str(e), 400)
        _audit(cfg, person.id, {"event": "setup", "person": person.id})
        return signed_in(state, person.id)

    # ---- the Family page
    def family_page(sess, msg: str = "", ok: bool = True, extra: str = "", status: int = 200) -> Response:
        cards = []
        for p in sorted(cfg.people.values(), key=lambda p: (not p.admin, p.display.lower())):
            role = " (runs the box)" if p.admin else ""
            you = " (you)" if p.id == sess.person.id else ""
            boxes = []
            for path, _label in household.grant_choices(cfg, p.id):
                _, other, folder = path.split("/")
                checked = " checked" if path in {g.strip("/") for g in p.also_reads} else ""
                boxes.append(f'<label class="check"><input type="checkbox" name="grant" value="{esc(path)}"{checked}>'
                             f'{esc(cfg.people[other].display)}\'s {esc(folder)}</label>')
            grants = ("".join(boxes) if boxes
                      else '<p class="muted">Add another person first.</p>')
            words = "\n".join(p.never_share)
            remove = ""
            if p.id != sess.person.id:
                remove = (f'<form method="post" action="/family/remove">{csrf(sess.csrf)}'
                          f'<input type="hidden" name="person" value="{esc(p.id)}">'
                          f'<label for="confirm-{esc(p.id)}">To remove {esc(p.display)}, type their name</label>'
                          f'<input type="text" id="confirm-{esc(p.id)}" name="confirm" autocomplete="off" required>'
                          f'<p class="muted">Their files stay on the box. Nobody else can read them.</p>'
                          f'<button class="danger" type="submit">Remove {esc(p.display)}</button></form>')
            cards.append(
                f'<div class="card"><h2>{esc(p.display)}{role}{you}</h2>'
                f'<form method="post" action="/family/access">{csrf(sess.csrf)}'
                f'<input type="hidden" name="person" value="{esc(p.id)}">'
                f'<fieldset><legend>{esc(p.display)} can also read</legend>{grants}'
                f'<p class="muted">Health folders always stay private to their owner.</p></fieldset>'
                f'<label for="words-{esc(p.id)}">Words the box must never share in {esc(p.display)}\'s answers</label>'
                f'<textarea id="words-{esc(p.id)}" name="never_share" rows="3">{esc(words)}</textarea>'
                f'<p class="muted">One word or phrase per line, for example the name of a doctor.</p>'
                f'<button class="main" type="submit">Save</button></form>'
                f'<form method="post" action="/family/invite">{csrf(sess.csrf)}'
                f'<input type="hidden" name="person" value="{esc(p.id)}">'
                f'<button class="main quiet" type="submit">Invite {esc(p.display)} with a QR code</button></form>'
                f'{remove}</div>')
        unowned = household.unowned_folders(cfg)
        left = ""
        if unowned:
            rows = "".join(f'<li><span class="name">{esc(path)}</span> <span class="muted">{n} files</span></li>'
                           for path, n in unowned)
            left = (f'<div class="card"><h2>Files with no owner</h2><p class="muted">These belonged to people '
                    f'who were removed. Nobody can read them on this page.</p><ul class="files">{rows}</ul></div>')
        body = (f'<h1>Family</h1>{note(msg, ok)}{extra}'
                f'<form method="post" action="/family/add" class="card">{csrf(sess.csrf)}<h2>Add a person</h2>'
                f'<label for="new-name">Name</label>'
                f'<input type="text" id="new-name" name="name" maxlength="{household.NAME_MAX}" required>'
                f'<p class="muted">They get their own folders. Then invite them so they can set their own PIN.</p>'
                f'<button class="main" type="submit">Add</button></form>'
                f'{"".join(cards)}{left}')
        return ctx.page(sess, "Family", body, "/family", status)

    @ctx.need_signin
    async def family_get(request: Request, sess):
        if not sess.person.admin:
            return ctx.forbidden(ADMIN_ONLY)
        return family_page(sess)

    async def admin_form(request: Request):
        got = await ctx.guarded_form(request, max_files=0, max_fields=200, max_part_size=16 * 1024)
        if isinstance(got, Response):
            return got
        sess, form = got
        if not sess.person.admin:
            return ctx.forbidden(ADMIN_ONLY)
        return sess, form

    def target(form) -> str | None:
        pid = str(form.get("person", ""))
        return pid if pid in cfg.people else None

    async def family_add(request: Request):
        got = await admin_form(request)
        if isinstance(got, Response):
            return got
        sess, form = got
        try:
            person = household.add_person(state, str(form.get("name", "")))
        except HouseholdError as e:
            return family_page(sess, str(e), False, status=400)
        _audit(cfg, sess.person.id, {"event": "person_added", "person": person.id})
        return family_page(sess, f"Added {person.display}. Invite them so they can set their own PIN.")

    async def family_access(request: Request):
        got = await admin_form(request)
        if isinstance(got, Response):
            return got
        sess, form = got
        pid = target(form)
        if pid is None:
            return family_page(sess, "That person isn't in the family.", False, status=404)
        try:
            person = household.set_also_reads(state, pid, form.getlist("grant"))
            words = str(form.get("never_share", "")).splitlines()
            person = household.set_never_share(state, pid, words)
        except HouseholdError as e:
            return family_page(sess, str(e), False, status=400)
        # The folders granted are written to the log; the never-share words are not (only how many).
        _audit(cfg, sess.person.id, {"event": "access_changed", "person": pid,
                                     "also_reads": list(person.also_reads),
                                     "never_share_count": len(person.never_share)})
        return family_page(sess, f"Saved for {person.display}.")

    async def family_remove(request: Request):
        got = await admin_form(request)
        if isinstance(got, Response):
            return got
        sess, form = got
        pid = target(form)
        if pid is None:
            return family_page(sess, "That person isn't in the family.", False, status=404)
        want = cfg.people[pid].display
        if " ".join(str(form.get("confirm", "")).split()).lower() != want.lower():
            return family_page(sess, f"To remove {want}, type their name exactly.", False, status=400)
        try:
            gone = household.remove_person(state, pid, by=sess.person.id)
        except HouseholdError as e:
            return family_page(sess, str(e), False, status=400)
        _audit(cfg, sess.person.id, {"event": "person_removed", "person": pid})
        return family_page(sess, f"Removed {gone.display}. Their files stay on the box.")

    async def family_invite(request: Request):
        got = await admin_form(request)
        if isinstance(got, Response):
            return got
        sess, form = got
        pid = target(form)
        if pid is None:
            return family_page(sess, "That person isn't in the family.", False, status=404)
        code = state.issue_code(pid, ttl=INVITE_TTL_S)
        link = f"https://{request.url.netloc}/join?c={code}"
        who = cfg.people[pid].display
        _audit(cfg, sess.person.id, {"event": "invite_issued", "person": pid, "expires_in_s": INVITE_TTL_S})
        extra = (f'<div class="card"><h2>Invite for {esc(who)}</h2>'
                 f'<p>On {esc(who)}\'s phone, on the home Wi-Fi, scan this code with the camera.</p>'
                 f'<div class="qr">{_qr_svg(link)}</div>'
                 f'<p>Or open this link: <span class="name">{esc(link)}</span></p>'
                 f'<p>Or go to the sign-in page and type this code:</p><div class="value">{esc(code)}</div>'
                 f'<p class="muted">It works once and lasts 30 minutes. {esc(who)} then picks their own PIN.</p></div>')
        return family_page(sess, extra=extra)

    # ---- joining with an invite
    def join_page(code: str = "", msg: str = "", status: int = 200) -> Response:
        pre = secrets.token_urlsafe(24)
        body = (f'<h1>Join your family box</h1>{note(msg, False)}'
                f'<form method="post" action="/join" class="card">{csrf(pre)}'
                f'<label for="code">Invite code</label>'
                f'<input type="text" id="code" name="code" class="code" maxlength="12" value="{esc(code)}"'
                f' autocapitalize="characters" spellcheck="false" autocomplete="one-time-code" required>'
                f'<label for="pin">Choose your PIN</label>'
                f'<input type="password" id="pin" name="pin" inputmode="numeric" maxlength="{household.PIN_MAX}"'
                f' autocomplete="new-password" required>'
                f'<label for="pin2">Type the PIN again</label>'
                f'<input type="password" id="pin2" name="pin2" inputmode="numeric" maxlength="{household.PIN_MAX}"'
                f' autocomplete="new-password" required>'
                f'<p class="muted">{household.PIN_MIN} to {household.PIN_MAX} numbers. Only you should know it.</p>'
                f'<button class="main" type="submit">Join</button></form>')
        return set_pre_cookie(_page(cfg, "Join", body, status=status), pre)

    async def join_get(request: Request):
        raw = request.query_params.get("c", "")
        return join_page(state.normalize(raw)[:12])

    async def join_post(request: Request):
        if not origin_ok(request):
            return ctx.forbidden()
        form = await request.form()
        if not pre_ok(request, form):
            return ctx.forbidden()
        code = str(form.get("code", ""))
        pin = str(form.get("pin", ""))
        keep = state.normalize(code)[:12]
        # Check the PIN before using the code, so a typo in the PIN never uses up the invite.
        if pin != str(form.get("pin2", "")):
            return join_page(keep, "The two PINs don't match. Try again.", 400)
        why = household.pin_problem(pin)
        if why:
            return join_page(keep, why, 400)
        pid, reason = state.redeem(code)
        if pid is None:
            msg = ("Too many wrong codes. Wait 10 minutes, then try again." if reason == "locked"
                   else "That invite didn't work. It may have been used or be more than 30 minutes old. "
                        "Ask for a new one.")
            return join_page("", msg, 429 if reason == "locked" else 401)
        household.set_pin(state, pid, pin)
        _audit(cfg, pid, {"event": "joined", "person": pid})
        return signed_in(state, pid)

    # ---- the AI key
    def last_check() -> dict:
        got = state._load(KEY_CHECK_FILE, {})
        return got if isinstance(got, dict) else {}

    def check_line() -> str:
        last = last_check()
        if not last.get("time"):
            return '<p class="muted">The key hasn\'t been checked yet.</p>'
        when = esc(_ago(last["time"]))
        if last.get("ok"):
            return f'<p class="ok">Last check passed, {when}. The box can talk to NEAR\'s private AI.</p>'
        why = last.get("reason", "other")
        if why == "no_key":
            return f'<p class="bad">Last check, {when}: no key was saved.</p>'
        hint = "" if why == "other" else f' (reason: {esc(why)})'
        return (f'<p class="bad">Last check failed, {when}{hint}. Check that the key is right and that the box '
                f'is online, then try again.</p>')

    def key_page(sess, msg: str = "", ok: bool = True, status: int = 200) -> Response:
        saved = bool(enclave.api_key())
        have = ('<p class="ok">A key is saved.</p><p class="muted">For safety it is never shown again. To change '
                'it, paste a new one below.</p>' if saved
                else '<p>No key is saved yet. Without it the box can\'t answer questions or read photos.</p>')
        check = ""
        if saved:
            check = (f'<form method="post" action="/settings/key/check" class="card">{csrf(sess.csrf)}'
                     f'<h2>Check the key</h2>{check_line()}'
                     f'<p class="muted">The box asks NEAR to prove its AI runs in a sealed, private machine. '
                     f'No question is sent. This can take up to a minute.</p>'
                     f'<button class="main" type="submit">Check it</button></form>')
        body = (f'<h1>AI key</h1>{note(msg, ok)}<div class="card">{have}</div>'
                f'<form method="post" action="/settings/key" class="card">{csrf(sess.csrf)}'
                f'<h2>{"Replace the key" if saved else "Save the key"}</h2>'
                f'<label for="key">NEAR AI key</label>'
                f'<input type="password" id="key" name="key" maxlength="{KEY_MAX}" autocomplete="off"'
                f' spellcheck="false" autocapitalize="off" required>'
                f'<p class="muted">Copy it from your NEAR AI account and paste it here once. It stays on this box.'
                f'</p><button class="main" type="submit">Save the key</button></form>{check}'
                f'<p><a href="/status">Box status</a></p>')
        return ctx.page(sess, "AI key", body, "/settings/key", status)

    @ctx.need_signin
    async def key_get(request: Request, sess):
        if not sess.person.admin:
            return ctx.forbidden(ADMIN_ONLY)
        return key_page(sess)

    async def key_form(request: Request):
        got = await ctx.guarded_form(request, max_files=0, max_fields=4, max_part_size=4096)
        if isinstance(got, Response):
            return got
        sess, form = got
        if not sess.person.admin:
            return ctx.forbidden(ADMIN_ONLY)
        return sess, form

    async def key_post(request: Request):
        got = await key_form(request)
        if isinstance(got, Response):
            return got
        sess, form = got
        key = str(form.get("key", "")).strip()
        why = key_problem(key)
        if why:
            return key_page(sess, why, False, status=400)
        save_key(cfg, key)
        with state._lock():
            state._save(KEY_CHECK_FILE, {})        # the last check was for the old key
        _audit(cfg, sess.person.id, {"event": "ai_key_saved"})
        return key_page(sess, "Saved. Now press \"Check it\" to make sure it works.")

    async def key_check(request: Request):
        got = await key_form(request)
        if isinstance(got, Response):
            return got
        sess, _ = got
        key = enclave.api_key()
        if not key:
            r = {"ok": False, "error": "no_key"}
        else:
            try:
                r = await asyncio.wait_for(asyncio.to_thread(_attest, key, cfg.model), KEY_CHECK_TIMEOUT_S)
            except asyncio.TimeoutError:
                r = {"ok": False, "error": "timeout"}
            except Exception:  # noqa: BLE001 - never show the error text, it could hold anything
                r = {"ok": False, "error": "other"}
        ok = bool(r.get("ok"))
        reason = "" if ok else _reason(r, key or "")
        with state._lock():
            state._save(KEY_CHECK_FILE, {"time": int(time.time()), "ok": ok, "reason": reason})
        _audit(cfg, sess.person.id, {"event": "ai_key_checked", "ok": ok, "reason": reason})
        if ok:
            return key_page(sess, "The key works. NEAR proved its private AI is sealed.")
        if not key:
            return key_page(sess, "Save a key first, then check it.", False)
        return key_page(sess, "The check didn't pass.", False)

    # ---- status
    def pin_state() -> str:
        try:
            from ..pinning import PinStore
            store = PinStore(cfg)
            if store.level == "off":
                return '<li>NEAR code check: <span class="bad">turned off</span></li>'
            waiting = store.reviews("waiting")
        except Exception:  # noqa: BLE001 - a damaged pin file is itself the news
            return '<li>NEAR code check: <span class="bad">needs a look</span> (<a href="/pins">open it</a>)</li>'
        if waiting:
            return (f'<li>NEAR code check: <span class="bad">{len(waiting)} change(s) to review</span>. The box won\'t '
                    f'answer until you do (<a href="/pins">review</a>).</li>')
        return '<li>NEAR code check: <span class="ok">no changes waiting</span></li>'

    @ctx.need_signin
    async def status_get(request: Request, sess):
        from ..approvals import Approvals
        person = sess.person
        saved = bool(enclave.api_key())
        rows = ['<li>The box is <span class="ok">on</span>.</li>']
        if saved:
            rows.append('<li>AI key: <span class="ok">saved</span></li>')
        else:
            rows.append('<li>AI key: <span class="bad">missing</span>. The box can\'t answer questions yet.'
                        + (' <a href="/settings/key">Save it</a>' if person.admin else
                           ' Ask the person who runs the box to save it.') + '</li>')
        last = last_check()
        if last.get("time"):
            res = '<span class="ok">passed</span>' if last.get("ok") else '<span class="bad">failed</span>'
            rows.append(f'<li>Last AI check: {res}, {esc(_ago(last["time"]))}</li>')
        else:
            rows.append('<li>Last AI check: not run yet</li>')
        try:
            n_files = len(readable_files(cfg, person))
        except Exception:  # noqa: BLE001
            n_files = None
        rows.append(f'<li>Files you can use: {n_files if n_files is not None else "unknown"}</li>')
        rows.append(f'<li>Approvals waiting for you: {len(Approvals(cfg).pending(person.id))}</li>')
        try:
            from ..remote import RemoteStore
            n_conn = len(RemoteStore(cfg).connections(person.id))
        except Exception:  # noqa: BLE001
            n_conn = None
        rows.append(f'<li>Assistants linked to you: {n_conn if n_conn is not None else "unknown"}</li>')
        if person.admin:
            rows.append(pin_state())
        try:
            free = shutil.disk_usage(cfg.home).free
            low = free < 1024 ** 3
            rows.append(f'<li>Free space: <span class="{"bad" if low else "ok"}">{esc(_disk(free))}</span>'
                        f'{" (running low)" if low else ""}</li>')
        except OSError:
            rows.append('<li>Free space: unknown</li>')
        links = ('<p><a href="/settings/key">AI key</a> &middot; <a href="/reset">Start over</a></p>'
                 if person.admin else "")
        body = (f'<h1>Box status</h1><div class="card"><ul class="files">{"".join(rows)}</ul></div>{links}')
        return ctx.page(sess, "Status", body, "/status")

    # ---- reset
    def reset_page(sess, msg: str = "", status: int = 200) -> Response:
        if not household.has_pin(state, sess.person.id):
            form = ('<p>A reset needs your PIN, and you don\'t have one yet. On the <a href="/family">Family page</a>, '
                    'invite yourself and pick a PIN, then come back.</p>')
        else:
            form = (f'<form method="post" action="/reset">{csrf(sess.csrf)}'
                    f'<label for="family">Type the family name: {esc(cfg.name)}</label>'
                    f'<input type="text" id="family" name="family" maxlength="{household.NAME_MAX}" autocomplete="off"'
                    f' spellcheck="false" required>'
                    f'<label for="pin">Your PIN</label>'
                    f'<input type="password" id="pin" name="pin" inputmode="numeric" maxlength="{household.PIN_MAX}"'
                    f' autocomplete="current-password" required>'
                    f'<button class="danger" type="submit">Delete everything and start over</button></form>')
        body = (f'<h1>Start over</h1>{note(msg, False)}<div class="card">'
                f'<p><strong>This deletes everything on the box:</strong> every file, every person and PIN, all '
                f'sign-ins, linked assistants, approvals, logs and the saved AI key.</p>'
                f'<p class="muted">It can\'t be undone. Make a backup on the Cloud page first if you want to keep '
                f'anything. After the reset, set the box up again from this page within 15 minutes.</p>'
                f'{form}</div><p><a href="/status">Back to box status</a></p>')
        return ctx.page(sess, "Start over", body, "/reset", status)

    @ctx.need_signin
    async def reset_get(request: Request, sess):
        if not sess.person.admin:
            return ctx.forbidden(ADMIN_ONLY)
        return reset_page(sess)

    async def reset_post(request: Request):
        got = await ctx.guarded_form(request, max_files=0, max_fields=4, max_part_size=1024)
        if isinstance(got, Response):
            return got
        sess, form = got
        if not sess.person.admin:
            return ctx.forbidden(ADMIN_ONLY)
        if not household.has_pin(state, sess.person.id):
            return reset_page(sess, "A reset needs your PIN.", 400)
        typed = " ".join(str(form.get("family", "")).split())
        if typed.lower() != " ".join(cfg.name.split()).lower():
            return reset_page(sess, f"Type the family name exactly: {cfg.name}. Nothing was deleted.", 400)
        ok, why = household.check_pin(state, sess.person.id, str(form.get("pin", "")))
        if not ok:
            msg = ("Too many wrong PINs. Wait 10 minutes, then try again." if why == "locked"
                   else "That PIN didn't work. Nothing was deleted.")
            return reset_page(sess, msg, 429 if why == "locked" else 401)
        try:
            household.reset_box(state)
        except HouseholdError as e:
            return reset_page(sess, str(e), 409)
        # Shared search index: clear it now, so nothing from before the reset can come up in an answer.
        try:
            ctx.box().store.reindex()
        except Exception:  # noqa: BLE001 - the files are gone either way; a fresh index is built on restart
            pass
        resp = RedirectResponse("/setup", status_code=303)
        resp.delete_cookie(COOKIE, secure=True, httponly=True, samesite="strict")
        return resp

    return [
        Route("/setup", setup_get, methods=["GET"]),
        Route("/setup", setup_post, methods=["POST"]),
        Route("/family", family_get, methods=["GET"]),
        Route("/family/add", family_add, methods=["POST"]),
        Route("/family/access", family_access, methods=["POST"]),
        Route("/family/remove", family_remove, methods=["POST"]),
        Route("/family/invite", family_invite, methods=["POST"]),
        Route("/join", join_get, methods=["GET"]),
        Route("/join", join_post, methods=["POST"]),
        Route("/settings/key", key_get, methods=["GET"]),
        Route("/settings/key", key_post, methods=["POST"]),
        Route("/settings/key/check", key_check, methods=["POST"]),
        Route("/status", status_get, methods=["GET"]),
        Route("/reset", reset_get, methods=["GET"]),
        Route("/reset", reset_post, methods=["POST"]),
    ]
