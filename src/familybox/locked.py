"""The box after a power cut: its files are encrypted and nothing is open yet.

This tiny app serves only the unlock page (and the style sheet). Every other path, including /mcp for
assistants, says the box is locked. Unlocking takes either this phone's unlock secret (a cookie set when
the phone was set up) plus the PIN of the person it belongs to, or the family's recovery key. On success
the encrypted folder is opened and the box restarts itself as the full box, keeping the key in memory.
"""

from __future__ import annotations

import os
import sys
import threading
import time
from html import escape as esc

from starlette.applications import Starlette
from starlette.requests import Request
from starlette.responses import JSONResponse, RedirectResponse, Response
from starlette.routing import Route

from . import vault as vaultmod
from .config import Config

COOKIE_AGE_S = 400 * 24 * 3600      # browsers cap cookies at about 400 days; each unlock renews it


def set_unlock_cookie(resp: Response, value: str) -> Response:
    resp.set_cookie(vaultmod.UNLOCK_COOKIE, value, max_age=COOKIE_AGE_S, secure=True, httponly=True,
                    samesite="strict")
    return resp


def restart_into_box(box_key: bytes) -> None:
    """Replace this process with the full box, handing it the key through an inherited pipe."""
    time.sleep(0.6)   # let the "unlocked" page reach the browser first
    vaultmod.hand_off(box_key)
    os.execv(sys.executable, [sys.executable, *sys.argv])


def create_locked_app(cfg: Config, vault: vaultmod.Vault, *, restart=restart_into_box) -> Starlette:
    from .web import CSS, STALE_FORM, SecurityHeaders, _csrf_field, _page, pre_ok, pre_token, set_pre_cookie

    name = vault.load().get("name") or "Family box"

    def page(pre: str, msg: str = "", ok: bool = False, status: int = 200, cookie: str | None = None,
             refresh: str = "") -> Response:
        dev = vault.device_of(cookie)
        note = f'<p class="{"ok" if ok else "bad"}">{esc(msg)}</p>' if msg else ""
        if refresh:
            body = f'<h1>Unlocked</h1>{note}<p class="muted">The box is starting. This page reloads in a moment.</p>'
            resp = _page(cfg, "Unlocked", body, status=status, refresh=refresh)
            return resp
        pin_form = ""
        if dev:
            who = esc(dev.get("display") or dev.get("person") or "")
            pin_form = (f'<form method="post" action="/unlock" class="card">{_csrf_field(pre)}'
                        f'<input type="hidden" name="how" value="pin">'
                        f'<p>This phone can unlock the box for <strong>{who}</strong>.</p>'
                        f'<label for="pin">{who}\'s PIN</label>'
                        f'<input type="password" id="pin" name="pin" inputmode="numeric" maxlength="12"'
                        f' autocomplete="current-password" required autofocus>'
                        f'<button class="main" type="submit">Unlock the box</button></form>')
        rec_open = "" if dev else " open"
        rec_form = (f'<details class="card"{rec_open}><summary>Use the recovery key</summary>'
                    f'<form method="post" action="/unlock">{_csrf_field(pre)}'
                    f'<input type="hidden" name="how" value="recovery">'
                    f'<label for="code">Recovery key (24 letters and numbers, from setup)</label>'
                    f'<input type="text" id="code" name="code" maxlength="40" autocomplete="off" spellcheck="false"'
                    f' autocapitalize="characters" required>'
                    f'<button class="main" type="submit">Unlock with the recovery key</button></form></details>')
        body = (f'<h1>The family box is locked</h1>{note}'
                f'<p class="muted">{esc(name)}. The box restarted, so the family\'s files are encrypted until someone who runs '
                f'the box unlocks them. Nothing can be read or asked until then.</p>{pin_form}{rec_form}')
        resp = _page(cfg, "Locked", body, status=status)
        return set_pre_cookie(resp, pre)

    async def unlock_get(request: Request):
        return page(pre_token(request), cookie=request.cookies.get(vaultmod.UNLOCK_COOKIE))

    async def unlock_post(request: Request):
        cookie = request.cookies.get(vaultmod.UNLOCK_COOKIE)
        form = await request.form()
        if not pre_ok(request, form):
            return page(pre_token(request), STALE_FORM, status=403, cookie=cookie)
        if vault.throttled():
            return page(pre_token(request), "Too many wrong tries. Wait 15 minutes, then try again.", status=429,
                        cookie=cookie)
        how = str(form.get("how", ""))
        key = None
        if how == "pin":
            got = vault.check_device(cookie, str(form.get("pin", "")))
            key = got[0] if got else None
            wrong = "That PIN didn't unlock the box. Try again, or use the recovery key."
        elif how == "recovery":
            key = vault.check_recovery(str(form.get("code", "")))
            wrong = "That recovery key didn't work. Check it and try again."
        else:
            wrong = "Choose how to unlock the box."
        if key is None:
            return page(pre_token(request), wrong, status=401, cookie=cookie)
        try:
            vault.open(key)
        except vaultmod.VaultError as e:
            return page(pre_token(request), f"The key was right, but the files could not be opened: {e}.",
                        status=500, cookie=cookie)
        resp = page("", "Unlocked.", ok=True, refresh="4;url=/")
        threading.Thread(target=restart, args=(key,), daemon=True).start()
        return resp

    async def locked_api(request: Request):
        return JSONResponse({"error": "locked", "message": "The family box is locked. Someone who runs it has to "
                                                            "unlock it on the box page first."}, status_code=503)

    async def to_unlock(request: Request):
        return RedirectResponse("/unlock", status_code=303)

    async def css(request: Request):
        return Response(CSS, media_type="text/css")

    async def no_icon(request: Request):
        return Response(status_code=204)

    routes = [Route("/unlock", unlock_get, methods=["GET"]), Route("/unlock", unlock_post, methods=["POST"]),
              Route("/static/style.css", css), Route("/favicon.ico", no_icon),
              Route("/mcp", locked_api, methods=["GET", "POST", "DELETE"]),
              Route("/{rest:path}", to_unlock, methods=["GET", "POST"])]
    return SecurityHeaders(Starlette(routes=routes))
