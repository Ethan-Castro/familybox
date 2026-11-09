"""Forms plugin: fill a PDF form on the box without the assistant ever seeing the real numbers.

  MCP:  list_family_forms(), fill_family_form(form, for_person, fields)
  CLI:  familybox forms list
        familybox forms fill --as dana [--for maya] <form> '<json fields>'
        familybox forms mine --as dana
        familybox forms approve|deny --as maya <form id>
        familybox forms download --as dana <form id> <out.pdf>
  Web:  /forms (status, approve or deny, download once every owner has approved)

The logic lives in familybox.formfill; this module only wires it into the box.
"""

from __future__ import annotations

import json
import os
import sys
import time
from typing import Annotated

from pydantic import Field

from .. import formfill

STATUS_TEXT = {"waiting": "Waiting for approval", "ready": "Approved, ready to download",
               "denied": "Denied. The filled PDF was deleted.", "expired": "Expired. The filled PDF was deleted.",
               "deleted": "Deleted"}


# --- MCP ------------------------------------------------------------------------------------------

def mcp_tools(server, person, box) -> None:
    cfg = box.cfg

    @server.tool(name="list_family_forms", title="List family forms",
                 description="The fillable forms on the family box, their fields, and how to reference a private "
                             "detail (like {{maya.ssn}}) so the box fills it without showing it to you.")
    async def list_family_forms() -> str:
        return formfill.describe_templates(cfg)

    @server.tool(name="fill_family_form", title="Fill a family form",
                 description="Fill a form on the family box. Give each field either plain text, or a reference "
                             "to a private detail in the family's files such as {{maya.ssn}}, "
                             "{{dana.passport_number}}, {{maya.date_of_birth}} or {{family.insurance_member_id}}. "
                             "The box fills the real values itself and only tells you what was filled, masked. "
                             "The owner approves and downloads the PDF on the box's own page.")
    async def fill_family_form(
        form: Annotated[str, Field(min_length=1, max_length=100, description="Form name from list_family_forms.")],
        for_person: Annotated[str, Field(min_length=1, max_length=60,
                                         description="Who the form is about, for example maya.")],
        fields: Annotated[dict[str, str], Field(description="Field name -> text or {{person.detail}} reference.")],
    ) -> str:
        try:
            return formfill.fill(cfg, person.id, form, for_person, fields, source="mcp", store=box.store).text
        except formfill.FormError as e:
            return str(e)


# --- CLI ------------------------------------------------------------------------------------------

def cli(sub) -> None:
    p = sub.add_parser("forms", help="fill PDF forms on the box")
    fs = p.add_subparsers(dest="forms_action", required=True)
    fs.add_parser("list")
    f = fs.add_parser("fill")
    f.add_argument("--as", dest="person", required=True)
    f.add_argument("--for", dest="for_person", default=None, help="who the form is about (default: you)")
    f.add_argument("form")
    f.add_argument("fields", help='JSON object, e.g. \'{"student_ssn": "{{maya.ssn}}"}\'')
    m = fs.add_parser("mine")
    m.add_argument("--as", dest="person", required=True)
    for name in ("approve", "deny"):
        a = fs.add_parser(name)
        a.add_argument("--as", dest="person", required=True)
        a.add_argument("id")
    d = fs.add_parser("download")
    d.add_argument("--as", dest="person", required=True)
    d.add_argument("id")
    d.add_argument("out")


def run_cli(args, cfg) -> int | None:
    if args.cmd != "forms":
        return None
    act = args.forms_action
    if act == "list":
        print(formfill.describe_templates(cfg))
        return 0
    try:
        cfg.person(args.person)
    except KeyError as e:
        print(e.args[0])
        return 2
    try:
        if act == "fill":
            try:
                fields = json.loads(args.fields)
            except ValueError:
                print("fields must be a JSON object, for example '{\"student_ssn\": \"{{maya.ssn}}\"}'")
                return 2
            print(formfill.fill(cfg, args.person, args.form, args.for_person or args.person, fields,
                                source="cli").text)
        elif act == "mine":
            rows = formfill.forms_for(cfg, args.person)
            if not rows:
                print("No forms.")
            for r in rows:
                print(json.dumps({k: r[k] for k in ("id", "form", "for", "asker", "status", "approvals",
                                                    "recipients", "fields")}))
        elif act in ("approve", "deny"):
            rec = formfill.decide(cfg, args.person, args.id, act == "approve")
            if act == "deny":
                print("Denied. The filled PDF was deleted.")
            elif rec["status"] == "ready":
                print("Approved. Everyone has approved; the filled PDF can be downloaded now.")
            else:
                print("Approved. Still waiting for the others to approve.")
        elif act == "download":
            name, data = formfill.download(cfg, args.person, args.id)
            fd = os.open(args.out, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
            with os.fdopen(fd, "wb") as f:
                f.write(data)
            print(f"saved {name} to {args.out} (only you can read it)")
    except formfill.FormError as e:
        print(str(e))
        return 1
    except (KeyError, PermissionError) as e:
        print(f"error: {e.args[0] if e.args else e}", file=sys.stderr)
        return 1
    except FileExistsError:
        print(f"error: {args.out} already exists", file=sys.stderr)
        return 1
    return 0


# --- web ------------------------------------------------------------------------------------------

def web_nav() -> list[tuple[str, str]]:
    return [("Forms", "/forms")]


def web_routes(ctx) -> list:
    from starlette.responses import Response
    from starlette.routing import Route

    cfg, esc = ctx.cfg, ctx.esc
    display = {p.id: p.display for p in cfg.people.values()}

    def forms_page(sess, extra: str = "", status: int = 200):
        cards = []
        for r in formfill.forms_for(cfg, sess.person.id):
            me = sess.person.id
            fid = esc(r["id"])
            asker = "You" if r["asker"] == me else display.get(r["asker"], r["asker"])
            appr = ", ".join(f"{esc(display.get(o, o))}: {esc(s)}" for o, s in r["approvals"].items())
            fields = "".join(f"<li>{esc(line)}</li>" for line in r["fields"])
            buttons = []
            if r["status"] == "waiting" and r["approvals"].get(me) == "waiting":
                buttons.append(f'<form method="post" action="/forms/{fid}/approve">{ctx.csrf_field(sess.csrf)}'
                               f'<button class="main" type="submit">Approve</button></form>')
                buttons.append(f'<form method="post" action="/forms/{fid}/deny">{ctx.csrf_field(sess.csrf)}'
                               f'<button class="main quiet" type="submit">Deny</button></form>')
            if r["status"] == "ready" and me in r["recipients"]:
                buttons.append(f'<form method="post" action="/forms/{fid}/download">{ctx.csrf_field(sess.csrf)}'
                               f'<button class="main" type="submit">Download the filled PDF</button></form>')
            if r["status"] in ("waiting", "ready"):
                buttons.append(f'<form method="post" action="/forms/{fid}/delete">{ctx.csrf_field(sess.csrf)}'
                               f'<button class="main quiet" type="submit">Delete</button></form>')
            who_gets = ", ".join(display.get(o, o) for o in r["recipients"])
            cards.append(
                f'<div class="card"><div><strong>{esc(r["title"])}</strong> for {esc(display.get(r["for"], r["for"]))}'
                f'</div><div class="muted">{esc(asker)} asked, {esc(time.strftime("%Y-%m-%d %H:%M", time.localtime(r["created"])))}.'
                f' {esc(STATUS_TEXT.get(r["status"], r["status"]))}</div>'
                f'<div class="muted">Approvals: {appr}</div>'
                f'<div class="muted">Who can download it: {esc(who_gets)}</div>'
                f'<ul>{fields}</ul><div class="row">{"".join(buttons)}</div></div>')
        listing = "".join(cards) or '<p class="muted">No forms yet.</p>'
        body = (f'<h1>Forms</h1>{extra}<p class="muted">When an assistant fills a form, the box puts in the real '
                f'numbers itself. The assistant only sees which fields were filled. Everyone whose details are in '
                f'the form approves it here first. Filled forms are deleted after 7 days.</p>{listing}')
        return ctx.page(sess, "Forms", body, "/forms", status=status)

    @ctx.need_signin
    async def forms_get(request, sess):
        return forms_page(sess)

    async def forms_action(request):
        got = await ctx.guarded_form(request)
        if isinstance(got, Response):
            return got
        sess, _ = got
        fid, action = request.path_params["form_id"], request.path_params["action"]
        try:
            if action in ("approve", "deny"):
                formfill.decide(cfg, sess.person.id, fid, action == "approve")
                msg = "Approved." if action == "approve" else "Denied. The filled PDF was deleted."
                return forms_page(sess, f'<p class="ok">{esc(msg)}</p>')
            if action == "delete":
                formfill.delete(cfg, sess.person.id, fid)
                return forms_page(sess, '<p class="ok">Deleted.</p>')
            if action == "download":
                name, data = formfill.download(cfg, sess.person.id, fid)
                return Response(data, media_type="application/pdf",
                                headers={"content-disposition": f'attachment; filename="{name}"'})
        except KeyError:
            return forms_page(sess, '<p class="bad">That form isn\'t waiting for you.</p>', status=404)
        except PermissionError as e:
            return forms_page(sess, f'<p class="bad">You can\'t download that form: {esc(e.args[0])}.</p>',
                              status=403)
        return forms_page(sess, '<p class="bad">Not found.</p>', status=404)

    return [Route("/forms", forms_get),
            Route("/forms/{form_id}/{action}", forms_action, methods=["POST"])]
