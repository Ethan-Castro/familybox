"""Alert when NEAR's serving code changes (see familybox.pinning for what is pinned and why).

  pre-check       a waiting review stops every live question at once, with no network call
  client options  every live question checks the gateway and model reports it is about to use
  CLI             familybox pins show | check | diff <id> | accept --as <admin> <id> | reject ... | history
                  | export [--platform-only]
  web             /pins: the owner reviews what changed and accepts or rejects it
"""

from __future__ import annotations

import asyncio
import json
import sys

from .. import enclave
from ..pinning import Checker, PinError, PinStore, nice_date

NAV_LABEL = "NEAR code"


def _mode(box) -> str:
    return box.mode if box.mode != "auto" else ("live" if enclave.api_key() else "replay")


def _components(box) -> list[str]:
    return ["gateway", f"model/{box.cfg.model}"]


async def pre_check(box, person, question, ctx) -> None:
    """Stop at once while NEAR's code has an unreviewed change. Replay mode never talks to NEAR."""
    if _mode(box) == "replay":
        return
    store = PinStore(box.cfg)
    if store.level == "off":
        ctx.emit("pinning", status="off")
        return
    review = store.blocking_review(_components(box))
    if review is not None:
        ctx.emit("pinning", status="waiting_review", component=review["component"], review=review["id"])
        raise PinError(store.blocked_message(review))


def client_options(box, person, ctx) -> dict | None:
    store = PinStore(box.cfg)
    if store.level == "off":
        return None
    checker = Checker(store, ctx.qid, ctx.emit)
    ctx.data["pinning"] = checker.results
    return checker.client_options()


def register(box) -> None:
    box.pre_checks.append(pre_check)
    box.client_options.append(client_options)


# ---------------------------------------------------------------- CLI

def cli(sub) -> None:
    p = sub.add_parser("pins", help="what the box pinned about NEAR's serving code")
    ps = p.add_subparsers(dest="pins_action", required=True)
    ps.add_parser("show")
    c = ps.add_parser("check", help="verify NEAR now (attestation only, free) and compare with the pins")
    c.add_argument("--json", action="store_true")
    d = ps.add_parser("diff")
    d.add_argument("id")
    for name in ("accept", "reject"):
        a = ps.add_parser(name)
        a.add_argument("--as", dest="person", required=True)
        a.add_argument("id", help="review id, or 'all'")
        if name == "accept":
            a.add_argument("--only", action="store_true", help="trust only this version from now on")
    h = ps.add_parser("history")
    h.add_argument("--json", action="store_true")
    e = ps.add_parser("export", help="print trusted fingerprints in the shipped pins file format")
    e.add_argument("--platform-only", action="store_true", help="leave out the model workload (it changes often)")


def _print_diff(store: PinStore, rid: str) -> None:
    d = store.diff(rid)
    r = d["review"]
    print(f"review {r['id']}: {r['component']} ({r['status']})")
    print(f"  noticed {nice_date(r['detected_at'])}"
          + (f", NEAR deployed it {nice_date(r['deployed_at'])}" if r.get("deployed_at") else ""))
    if not d["changes"]:
        print("  no fingerprinted field changed")
    for ch in d["changes"] + [c | {"info": True} for c in d["info_changes"]]:
        tag = " (shown for information, not checked)" if ch.get("info") else ""
        if "added" in ch:
            for x in ch["removed"]:
                print(f"  - {ch['field']}: {x}{tag}")
            for x in ch["added"]:
                print(f"  + {ch['field']}: {x}{tag}")
        else:
            print(f"  {ch['field']}{tag}:\n      was {json.dumps(ch['before'])}\n      now {json.dumps(ch['after'])}")


def run_cli(args, cfg) -> int | None:
    if args.cmd != "pins":
        return None
    store = PinStore(cfg)
    try:
        act = args.pins_action
        if act == "show":
            data = store.load()
            print(f"checking level: {store.level}")
            if not data["components"]:
                print("nothing pinned yet. The first verified question (or `familybox pins check`) pins NEAR's code.")
            for name, comp in sorted(data["components"].items()):
                print(f"{name}: {len(comp['accepted'])} trusted version(s), from {comp.get('source', '?')} "
                      f"on {nice_date(comp.get('pinned_at'))}")
                for fp in comp["accepted"]:
                    print(f"    {fp[:16]}")
            waiting = store.reviews("waiting")
            print(f"waiting for the owner: {len(waiting)}")
            for r in waiting:
                print(f"  {r['id']}  {r['component']}  noticed {nice_date(r['detected_at'])}")
            print(f"history entries: {len(store.history())}, chain intact: {'yes' if store.verify_history() else 'NO'}")
        elif act == "check":
            from ..pinning import check_now
            results = asyncio.run(check_now(cfg, store=store))
            if args.json:
                print(json.dumps(results, indent=1))
            else:
                for r in results:
                    print(f"{r['component']}: {r['status']} ({r['fp'][:16]})")
                    if r.get("error"):
                        print(f"  {r['error']}")
            return 1 if any(r["status"] == "changed" for r in results) else 0
        elif act == "diff":
            _print_diff(store, args.id)
        elif act in ("accept", "reject"):
            try:
                person = cfg.person(args.person)
            except KeyError as e:
                print(e.args[0]); return 2
            if not person.admin:
                print(f"{args.person} is not the box admin; only the admin reviews NEAR's code"); return 2
            ids = [r["id"] for r in store.reviews("waiting")] if args.id == "all" else [args.id]
            if not ids:
                print("nothing is waiting"); return 0
            for rid in ids:
                r = store.decide(rid, act == "accept", person.id, only=getattr(args, "only", False))
                print(f"{'accepted' if act == 'accept' else 'rejected'} {rid} ({r['component']})")
        elif act == "export":
            data = store.load()
            comps = {}
            for name, comp in sorted(data["components"].items()):
                if args.platform_only and name.endswith("/workload"):
                    continue
                comps[name] = [{"fp": fp, "fields": data["fingerprints"][fp]["fields"],
                                "seen": nice_date(data["fingerprints"][fp].get("first_seen"))}
                               for fp in comp["accepted"] if fp in data["fingerprints"]]
            print(json.dumps({"version": 1, "about": "Expected NEAR AI Cloud measurement fingerprints. A box with "
                              "no pins of its own trusts these instead of trusting first use.",
                              "components": comps}, indent=1))
        elif act == "history":
            hist = store.history()
            if args.json:
                print(json.dumps(hist, indent=1))
            else:
                for h in hist:
                    extra = f" by {h['by']}" if h.get("by") else ""
                    print(f"{nice_date(h['time'])}  {h['event']:<9} {h.get('component', '')}  "
                          f"{str(h.get('fp', ''))[:16]}{extra}")
                print(f"chain intact: {'yes' if store.verify_history() else 'NO'}")
    except KeyError:
        print("no such review"); return 2
    except PinError as e:
        print(f"error: {e}", file=sys.stderr); return 1
    return 0


# ---------------------------------------------------------------- web

def web_nav() -> list[tuple[str, str]]:
    return [(NAV_LABEL, "/pins")]


def _change_rows(esc, changes: list[dict], info: bool = False) -> str:
    rows = []
    for ch in changes:
        note = ' <span class="muted">(for information)</span>' if info else ""
        if "added" in ch:
            items = [f"<li>Removed: <code>{esc(x)}</code></li>" for x in ch["removed"]]
            items += [f"<li>Added: <code>{esc(x)}</code></li>" for x in ch["added"]]
            rows.append(f'<div><strong>{esc(ch["field"])}</strong>{note}<ul>{"".join(items)}</ul></div>')
        else:
            rows.append(f'<div><strong>{esc(ch["field"])}</strong>{note}<ul>'
                        f'<li>Before: <code>{esc(json.dumps(ch["before"]))}</code></li>'
                        f'<li>Now: <code>{esc(json.dumps(ch["after"]))}</code></li></ul></div>')
    return "".join(rows)


def web_routes(ctx) -> list:
    from starlette.responses import Response
    from starlette.routing import Route

    esc = ctx.esc

    def admin_name() -> str:
        admins = [p.display for p in ctx.cfg.people.values() if p.admin]
        return admins[0] if admins else "the box admin"

    def pins_page(sess, msg: str = "", ok: bool = True, status: int = 200):
        store = PinStore(ctx.cfg)
        note = f'<p class="{"ok" if ok else "bad"}">{esc(msg)}</p>' if msg else ""
        try:
            data = store.load()
            waiting = store.reviews("waiting")
        except PinError as e:
            body = f'<h1>NEAR code</h1>{note}<p class="bad">{esc(str(e))}.</p>'
            return ctx.page(sess, "NEAR code", body, "/pins", status)
        intro = ('<p class="muted">The box remembers exactly which code NEAR used the first time it checked the '
                 'model\'s secure enclave. If NEAR changes that code, the box stops answering until the owner '
                 'looks at what changed and decides.</p>')
        if waiting:
            state = (f'<p class="bad">NEAR changed its serving code. The box is not answering questions until '
                     f'{esc(admin_name())} reviews it.</p>')
        elif data["components"]:
            state = '<p class="ok">NEAR is running the same code the box trusts.</p>'
        else:
            state = '<p class="muted">Nothing is pinned yet. The first checked question pins NEAR\'s code.</p>'
        cards = []
        for r in waiting:
            d = store.diff(r["id"])
            when = (f'NEAR deployed it on {esc(nice_date(r["deployed_at"]))}. ' if r.get("deployed_at") else "")
            rows = _change_rows(esc, d["changes"]) + _change_rows(esc, d["info_changes"], info=True)
            actions = ""
            if sess.person.admin:
                actions = (f'<div class="row">'
                           f'<form method="post" action="/pins/{esc(r["id"])}/accept">{ctx.csrf_field(sess.csrf)}'
                           f'<button class="main" type="submit">Trust the new code</button></form>'
                           f'<form method="post" action="/pins/{esc(r["id"])}/reject">{ctx.csrf_field(sess.csrf)}'
                           f'<button class="main quiet" type="submit">Keep blocking it</button></form></div>')
            cards.append(f'<div class="card"><div><strong>{esc(r["component"])}</strong></div>'
                         f'<div class="muted">Noticed on {esc(nice_date(r["detected_at"]))}. {when}'
                         f'Review {esc(r["id"])}.</div>{rows or "<p>No checked field changed.</p>"}{actions}</div>')
        if waiting and not sess.person.admin:
            cards.append(f'<p class="muted">Only {esc(admin_name())} can review this.</p>')
        pinned = "".join(
            f'<li><strong>{esc(name)}</strong>: {len(c["accepted"])} trusted version(s), since '
            f'{esc(nice_date(c.get("pinned_at")))}</li>' for name, c in sorted(data["components"].items()))
        hist = store.history()[-8:]
        hist_rows = "".join(f'<li>{esc(nice_date(h["time"]))}: {esc(h["event"])} {esc(h.get("component", ""))}'
                            f'{" by " + esc(h["by"]) if h.get("by") else ""}</li>' for h in reversed(hist))
        chain = "intact" if store.verify_history() else "BROKEN (someone edited it)"
        body = (f'<h1>NEAR code</h1>{note}{state}{intro}{"".join(cards)}'
                f'<h2>Trusted now</h2><ul>{pinned or "<li>Nothing yet</li>"}</ul>'
                f'<h2>Recent history</h2><ul>{hist_rows or "<li>Nothing yet</li>"}</ul>'
                f'<p class="muted">History log check: {chain}. Checking level: {esc(store.level)}.</p>')
        return ctx.page(sess, "NEAR code", body, "/pins", status)

    async def pins_get(request, sess):
        return pins_page(sess)

    async def pins_decide(request):
        got = await ctx.guarded_form(request)
        if isinstance(got, Response):
            return got
        sess, _ = got
        if not sess.person.admin:
            return ctx.forbidden("Only the person who runs the box can do that.")
        action = request.path_params["action"]
        if action not in ("accept", "reject"):
            return pins_page(sess, "That isn't something you can do here.", False, 404)
        store = PinStore(ctx.cfg)
        try:
            r = store.decide(request.path_params["rid"], action == "accept", sess.person.id)
        except KeyError:
            return pins_page(sess, "That review isn't waiting anymore.", False, 404)
        except PinError as e:
            return pins_page(sess, str(e), False, 500)
        if action == "accept":
            return pins_page(sess, f"Done. The box trusts the new {r['component']} code and will answer again.")
        return pins_page(sess, "Done. The box keeps blocking questions while NEAR serves that code.")

    return [Route("/pins", ctx.need_signin(pins_get)),
            Route("/pins/{rid}/{action}", pins_decide, methods=["POST"])]
