"""Photos: upload a photo or scan, the box reads it once in a NEAR enclave, and keeps both copies.

CLI:
  familybox add --as maya card.jpg [--folder ids]     add a photo (or a text/PDF file) to your folders
  familybox photos --as maya                          your photos and whether each one has been read
  familybox transcribe --as maya people/maya/ids/card.jpg   read a photo again (after a failure)

Web: a "Photos" page to upload, look at your own originals and their transcripts, retry, and remove.

The original is never sent to an assistant. Only its owner can look at it on the box page, except in the
shared folder, where everyone in the family can. Assistants only ever get answers built from the transcript, through the gate.
"""

from __future__ import annotations

import asyncio
import hashlib
from pathlib import Path
from urllib.parse import quote

from familybox import vision

FOLDER_CHOICES = ("ids", "taxes", "health", "school", "other", "shared")
TEXT_TYPES = {".txt", ".md", ".pdf", ".json", ".csv"}
FORM_SLACK = 64 * 1024


# --- CLI -----------------------------------------------------------------------------------------

def cli(sub) -> None:
    a = sub.add_parser("add", help="add a photo or file to your folders on the box")
    a.add_argument("--as", dest="person", required=True)
    a.add_argument("--folder", choices=FOLDER_CHOICES, default="other")
    a.add_argument("path")
    p = sub.add_parser("photos", help="list your photos and their transcripts")
    p.add_argument("--as", dest="person", required=True)
    t = sub.add_parser("transcribe", help="read a stored photo again")
    t.add_argument("--as", dest="person", required=True)
    t.add_argument("photo", help="path on the box, as shown by `familybox photos`")


def _print_result(res: vision.PhotoResult) -> None:
    if res.ok:
        print(f"read by {res.model} in a verified enclave (signature {res.signature_kind}, "
              f"signer {res.signer[:10]}...)")
        print(f"transcript: {res.transcript}")
        if res.fields:
            print("found: " + ", ".join(f"{label} {vision.masked(v)}" for label, v in res.fields))
        else:
            print("found: no ID numbers")
        print("the full values stay on the box. Look at them on the box page under Photos.")
    else:
        print(f"the photo is saved, but the box couldn't read it: {res.error}")
        print(f"try again later: familybox transcribe --as <you> {res.photo}")


def _status(it: vision.PhotoInfo) -> str:
    if not it.transcript:
        return "not read yet"
    if it.checked:
        return "read"
    if not it.sealed:
        return "text not made by the box, read it again"
    return "transcript does not match this photo"


def run_cli(args, cfg) -> int | None:
    if args.cmd not in ("add", "photos", "transcribe"):
        return None
    try:
        person = cfg.person(args.person)
    except KeyError as e:
        print(e.args[0])
        return 2
    try:
        if args.cmd == "add":
            src = Path(args.path).expanduser()
            if not src.is_file():
                print(f"no such file: {args.path}")
                return 2
            data = src.read_bytes()
            suffix = src.suffix.lower()
            if suffix in TEXT_TYPES:
                from familybox import web
                try:
                    rel = web.save_upload(cfg, person, args.folder, src.name, data)
                except web.UploadError as e:
                    print(f"not added: {e}")
                    return 1
                vision.reindex(cfg)
                print(f"added {rel}")
                return 0
            res = asyncio.run(vision.add_photo(cfg, person, args.folder, src.name, data, source="cli"))
            seen = ("everyone in the family can see it" if vision.is_shared(res.photo) else "only you can see it")
            print(f"saved the original: {res.photo} ({seen})")
            _print_result(res)
            return 0 if res.ok else 1
        if args.cmd == "photos":
            items = vision.photos_for(cfg, person)
            if not items:
                print("no photos yet")
            for it in items:
                status = _status(it)
                print(f"{it.photo}  [{status}]")
            return 0
        res = asyncio.run(vision.transcribe_photo(cfg, person, args.photo.strip(), source="cli"))
        vision.reindex(cfg)
        _print_result(res)
        return 0 if res.ok else 1
    except vision.PhotoError as e:
        print(f"not added: {e}" if args.cmd == "add" else str(e))
        return 1


# --- web -----------------------------------------------------------------------------------------

def web_nav() -> list[tuple[str, str]]:
    return [("Photos", "/photos")]


def web_routes(ctx):
    from starlette.requests import Request
    from starlette.responses import Response
    from starlette.routing import Route

    from familybox.web import FOLDER_LABELS, PERSON_FOLDERS, can_delete

    esc, cfg = ctx.esc, ctx.cfg

    def link(rel: str) -> str:
        return "/photos/view?path=" + quote(rel, safe="")

    def photos_page(sess, msg: str = "", ok: bool = True, extra: str = "", status: int = 200):
        note = f'<p class="{"ok" if ok else "bad"}">{esc(msg)}</p>' if msg else ""
        opts = "".join(f'<option value="{f}">My {FOLDER_LABELS[f]}</option>' for f in PERSON_FOLDERS)
        opts += f'<option value="shared">{FOLDER_LABELS["shared"]}</option>'
        rows = []
        for it in vision.photos_for(cfg, sess.person):
            text = _status(it)
            state = f'<span class="{"ok" if text == "read" else "bad"}">{esc(text[:1].upper() + text[1:])}</span>'
            rows.append(f'<li><div class="name"><a href="{esc(link(it.photo))}">{esc(it.photo)}</a></div>'
                        f'<div class="row muted">{state}</div></li>')
        listing = f'<ul class="files">{"".join(rows)}</ul>' if rows else '<p class="muted">No photos yet.</p>'
        body = (f'<h1>Photos</h1>{note}{extra}'
                f'<form method="post" action="/photos/upload" enctype="multipart/form-data" class="card">'
                f'{ctx.csrf_field(sess.csrf)}'
                f'<label for="folder">Where should it go?</label><select id="folder" name="folder">{opts}</select>'
                f'<label for="file">Photo or scan</label>'
                f'<input type="file" id="file" name="file" accept=".jpg,.jpeg,.png,.webp,image/jpeg,image/png,'
                f'image/webp" required>'
                f'<p class="muted">JPG, PNG or WEBP, up to 25 MB. The box sends the photo once to a private, '
                f'checked NEAR AI model that writes down the text on it. Location data is removed first. '
                f'The box keeps the photo and the written-down text. Your assistant only ever sees answers '
                f'checked by the box, never the photo.</p>'
                f'<button class="main" type="submit">Upload and read it</button></form>'
                f'<div class="card"><h2>Your photos</h2>{listing}</div>')
        return ctx.page(sess, "Photos", body, "/photos", status)

    def result_note(res: vision.PhotoResult) -> tuple[str, bool]:
        if res.ok:
            found = (", ".join(f"{label} {vision.masked(v)}" for label, v in res.fields)
                     if res.fields else "no ID numbers")
            return f"Read and saved. Found: {found}.", True
        return ("The photo is saved, but the box couldn't read it right now. Nothing was shared. "
                "Open it below and try again later."), False

    @ctx.need_signin
    async def photos_get(request: Request, sess):
        return photos_page(sess)

    async def photos_upload(request: Request):
        got = await ctx.guarded_form(request, max_files=1, max_fields=8, max_part_size=4096)
        if isinstance(got, Response):
            return got
        sess, form = got
        try:
            f = form.get("file")
            if f is None or isinstance(f, str):
                raise vision.PhotoError("Choose a photo first.")
            if f.size is not None and f.size > vision.MAX_PHOTO_BYTES:
                raise vision.PhotoError("That photo is too big. The limit is 25 MB.")
            data = await f.read(vision.MAX_PHOTO_BYTES + 1)
            res = await vision.add_photo(cfg, sess.person, str(form.get("folder", "")), f.filename or "", data,
                                         source="web")
        except vision.PhotoError as e:
            return photos_page(sess, str(e), ok=False, status=400)
        finally:
            await form.close()
        msg, ok = result_note(res)
        return photos_page(sess, msg, ok)

    def viewable(sess, rel: str):
        rel = rel.strip().lstrip("/")
        if not vision.can_view(sess.person, rel):
            return None
        return vision.info(cfg, rel)

    @ctx.need_signin
    async def photos_view(request: Request, sess):
        it = viewable(sess, request.query_params.get("path", ""))
        if it is None:
            return ctx.forbidden("You can only look at your own photos.")
        c = ctx.csrf_field(sess.csrf)
        hidden = f'<input type="hidden" name="path" value="{esc(it.photo)}">'
        text = ""
        if it.transcript:
            target = vision.resolve_photo(cfg, it.photo)
            header, body_text = vision.parse(vision.transcript_path(target).read_text(errors="replace"))
            if it.checked:
                check = ('<p class="ok">Checked: the box made this text from this exact photo, '
                         'using the model below.</p>')
            elif not it.sealed:
                check = ('<p class="bad">The box did not make this text, so the details below are not checked. '
                         'Read the photo again.</p>')
            else:
                check = '<p class="bad">This text was not made from this photo. Read it again.</p>'
            claimed = "" if it.sealed else " (not checked)"
            text = (f'<div class="card"><h2>What the box read</h2>{check}'
                    f'<p class="muted">Model{claimed}: {esc(header.get("Model", "unknown"))}<br>'
                    f'Signature: {esc(header.get("Signature kind", "unknown"))}, signer '
                    f'{esc(header.get("Signer", "")[:10])}...<br>'
                    f'Read at: {esc(header.get("Transcribed at", "unknown"))}</p>'
                    f'<pre class="value">{esc(body_text.strip())}</pre></div>')
        else:
            text = '<div class="card"><p class="bad">The box hasn\'t read this photo yet.</p></div>'
        img = f'/photos/image?path={quote(it.photo, safe="")}'
        retry = remove = ""
        if not it.transcript or vision.can_reread(sess.person, it.photo):
            retry = (f'<form method="post" action="/photos/retry">{c}{hidden}'
                     f'<button class="main quiet" type="submit">Read it again</button></form>')
        if can_delete(sess.person, it.photo):
            remove = (f'<form method="post" action="/photos/remove">{c}{hidden}'
                      f'<button class="danger" type="submit">Remove photo and text</button></form>')
        body = (f'<h1>{esc(Path(it.photo).name)}</h1>'
                f'<p class="muted">{esc(it.photo)}. {esc(vision.who_sees(it.photo))}</p>'
                f'<div class="card"><img src="{esc(img)}" alt="The photo">'
                f'</div>{text}<div class="row">{retry}{remove}</div>'
                f'<p><a href="/photos">Back to photos</a></p>')
        return ctx.page(sess, "Photo", body, "/photos")

    @ctx.need_signin
    async def photos_image(request: Request, sess):
        it = viewable(sess, request.query_params.get("path", ""))
        if it is None:
            return Response("Not allowed", status_code=403, media_type="text/plain")
        data = vision.resolve_photo(cfg, it.photo).read_bytes()
        kind = vision.sniff(data)
        if kind not in ("png", "jpeg", "webp"):
            return Response("Not a photo", status_code=415, media_type="text/plain")
        return Response(data, media_type=f"image/{kind}",
                        headers={"content-disposition": "inline", "x-photo-sha256": hashlib.sha256(data).hexdigest()})

    async def photos_retry(request: Request):
        got = await ctx.guarded_form(request)
        if isinstance(got, Response):
            return got
        sess, form = got
        rel = str(form.get("path", "")).strip().lstrip("/")
        if viewable(sess, rel) is None:
            return ctx.forbidden("You can only read your own photos.")
        try:
            res = await vision.transcribe_photo(cfg, sess.person, rel, source="web")
        except vision.PhotoError as e:
            return photos_page(sess, str(e), ok=False, status=400)
        vision.reindex(cfg)
        msg, ok = result_note(res)
        return photos_page(sess, msg, ok)

    async def photos_remove(request: Request):
        got = await ctx.guarded_form(request)
        if isinstance(got, Response):
            return got
        sess, form = got
        rel = str(form.get("path", "")).strip().lstrip("/")
        try:
            vision.remove_photo(cfg, sess.person, rel)
        except vision.PhotoError as e:
            return ctx.forbidden(str(e))
        return photos_page(sess, "Removed the photo and its text.")

    return [
        Route("/photos", photos_get, methods=["GET"]),
        Route("/photos/upload", photos_upload, methods=["POST"], max_body_size=vision.MAX_PHOTO_BYTES + FORM_SLACK),
        Route("/photos/view", photos_view, methods=["GET"]),
        Route("/photos/image", photos_image, methods=["GET"]),
        Route("/photos/retry", photos_retry, methods=["POST"]),
        Route("/photos/remove", photos_remove, methods=["POST"]),
    ]
