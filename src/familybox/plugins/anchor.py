"""Disclosure log plugin: a "Log" page with each person's chain head, and `familybox anchor`.

  familybox anchor --as maya              dry run: print the exact NEAR call for maya's chain head
  familybox anchor --as maya --save       dry run, and keep this head as a checkpoint saved on this box
  familybox anchor                        dry run for everyone in the family
  familybox anchor send --as maya         sign and send it (needs NEAR_ACCOUNT_ID, a key, NEAR_ANCHOR_CONTRACT)
  familybox anchor check --as maya        read the anchored head back from NEAR and check the log against it
  familybox anchor keygen                 make the box's anchoring key and print its public key
  familybox anchor status                 box id, settings, and what is still missing to go live

The chain itself (seq, prev_hash, entry_hash on every audit entry) is core: familybox.ledger. This
plugin only reads it. A log that does not verify is never anchored.
"""

from __future__ import annotations

import json
import time

from starlette.routing import Route

from familybox import ledger, near_anchor as na

COMMAND = "anchor"


# --- CLI -----------------------------------------------------------------------------------------

def cli(subparsers) -> None:
    p = subparsers.add_parser(COMMAND, help="put each person's log chain head on NEAR (dry run by default)")
    p.add_argument("action", nargs="?", default="dry-run", choices=["dry-run", "send", "check", "keygen", "status"])
    p.add_argument("--as", dest="person", default=None, help="one person (default: everyone)")
    p.add_argument("--save", action="store_true", help="dry run: also keep the head as a checkpoint saved on this box (not on NEAR)")
    p.add_argument("--force", action="store_true", help="keygen: replace the existing key")


def prepare(cfg, person_id: str, s: na.Settings | None = None) -> tuple[ledger.Report, dict | None, dict | None]:
    """(verify report, anchor args, transaction plan). args and plan are None when there is nothing to anchor."""
    rep = ledger.verify_all(cfg.runtime, person_id)
    if not rep.ok or rep.count == 0:
        return rep, None, None
    ident = na.load_identity(cfg.runtime)
    args = na.anchor_args(ident["box_id"], na.person_hash(ident, person_id), rep.head, rep.count)
    return rep, args, na.plan(s or na.settings(cfg.runtime), args)


def run_cli(args, cfg) -> int | None:
    if args.cmd != COMMAND:
        return None
    try:
        return _run(args, cfg)
    except (na.AnchorError, KeyError) as e:
        print(f"error: {e.args[0] if e.args else e}")
        return 1
    except (OSError, ValueError) as e:     # a damaged or unreadable file on the box: say so, no traceback
        print(f"error: something the box keeps for anchoring could not be read ({e})")
        return 1


def _people(cfg, args) -> list:
    if args.person:
        return [cfg.person(args.person)]
    return [cfg.people[k] for k in sorted(cfg.people)]


def _run(args, cfg) -> int:
    rt = cfg.runtime
    if args.action == "keygen":
        pub = na.keygen(rt, force=args.force)
        print("The box's anchoring key is saved on the box (never shown). Its public key is:\n")
        print(f"    {pub}\n")
        print("Add it to your NEAR account as a function-call key that can only call anchor() on the anchor")
        print("contract. The exact command is in docs/ANCHOR.md.")
        return 0
    s = na.settings(rt)
    if args.action == "status":
        ident = na.load_identity(rt)
        print(json.dumps({"box_id": ident["box_id"], "network": s.network, "rpc": s.rpc_url,
                          "contract": s.contract, "account_id": s.account_id,
                          "public_key": na.public_key_of(s.private_key) if s.private_key else None,
                          "ready_to_send": s.live_ready, "missing": s.missing()}, indent=1))
        return 0

    people = _people(cfg, args)
    if args.action == "send" and not s.live_ready:
        raise na.AnchorError("cannot send yet; missing " + ", ".join(s.missing()))
    rc = 0
    rpc = na.Rpc(s.rpc_url) if args.action in ("send", "check") else None
    last_nonce = None      # one key signs every transaction in this run: never reuse a nonce
    for person in people:
        if args.action == "check":
            try:
                rc = max(rc, _check(cfg, s, person, rpc))
            except na.AnchorError as e:   # one failure does not skip the rest of the family
                print(f"{person.display}: could not check against NEAR: {e.args[0] if e.args else e}")
                rc = 1
            continue
        rep, a, tx = prepare(cfg, person.id, s)
        if not rep.ok:
            print(f"{person.display}: the log does not check out, so it will not be anchored:")
            for p in rep.problems:
                print(f"  - {p}")
            rc = 1
            continue
        if a is None:
            print(f"{person.display}: nothing to anchor yet (no linked entries).")
            continue
        if args.action == "dry-run":
            print(f"{person.display}: dry run. Nothing was sent. This is the exact call the box would sign:")
            print(json.dumps(tx, indent=1))
            if args.save:
                ledger.add_checkpoint(rt, person.id, rep.count, rep.head, "a checkpoint saved on this box")
                print("kept this head as a checkpoint saved on this box (not on NEAR).")
            if not s.live_ready:
                print("to send it for real, the box still needs: " + ", ".join(s.missing()))
        elif args.action == "send":
            try:
                res = na.send_anchor(s, a, rpc=rpc, last_nonce=last_nonce)
            except na.AnchorError as e:   # one failure does not skip the rest of the family
                print(f"{person.display}: not anchored. error: {e.args[0] if e.args else e}")
                rc = 1
                continue
            last_nonce = res["nonce"]
            ledger.add_checkpoint(rt, person.id, rep.count, rep.head, f"NEAR anchor {res['tx_hash']}",
                                  tx_hash=res["tx_hash"], network=s.network, contract=s.contract)
            print(f"{person.display}: anchored {rep.count} entries on NEAR {s.network}. "
                  f"Transaction {res['tx_hash']}")
    return rc


def _check(cfg, s: na.Settings, person, rpc=None) -> int:
    ident = na.load_identity(cfg.runtime)
    got = na.view_anchor(s, ident["box_id"], na.person_hash(ident, person.id), rpc=rpc)
    if not got:
        box = na.view_box(s, ident["box_id"], rpc=rpc)
        writer = (box or {}).get("writer")
        if writer and s.account_id and writer != s.account_id:
            print(f"{person.display}: nothing anchored on NEAR yet. This box id is registered to another "
                  f"account ({writer}), not {s.account_id}, so the box cannot anchor under it. Make a new "
                  f"box id (move runtime/ledger/anchor_id.json aside) and register that one.")
            return 1
        print(f"{person.display}: nothing anchored on NEAR yet.")
        return 0
    cp = {"count": got.get("count"), "head": got.get("head_hash"), "where": "the NEAR anchor"}
    rep = ledger.verify(cfg.runtime, person.id, checkpoints=[cp] + ledger.checkpoints(cfg.runtime, person.id))
    if rep.ok:
        print(f"{person.display}: the log matches NEAR (anchored at entry {got.get('count')}, "
              f"now {rep.count} entries).")
        return 0
    print(f"{person.display}: the log does NOT match what is on NEAR:")
    for p in rep.problems:
        print(f"  - {p}")
    return 1


# --- web page --------------------------------------------------------------------------------------

def web_nav() -> list[tuple[str, str]]:
    return [("Log", "/log")]


def _when(ts) -> str:
    try:
        return time.strftime("%b %d, %H:%M", time.localtime(int(ts)))
    except (TypeError, ValueError):
        return ""


def _status_card(ctx, cfg, person, *, mine: bool) -> str:
    esc = ctx.esc
    rep = ledger.verify_all(cfg.runtime, person.id)
    cps = [c for c in ledger.checkpoints(cfg.runtime, person.id) if c.get("head")]
    who = "Your" if mine else f"{esc(person.display)}'s"
    near = [c for c in cps if c.get("tx_hash")]
    if rep.count == 0 and rep.ok:
        state = '<p class="muted">Nothing has been logged yet.</p>'
    elif rep.ok and near:
        state = (f'<p class="ok">{who} log checks out: {rep.count} entries, each linked to the one before, '
                 f'and it still matches what was anchored on NEAR.</p>')
    elif rep.ok:
        state = (f'<p class="ok">{who} log is linked correctly: {rep.count} entries, each linked to the one '
                 f'before.</p><p class="muted">It is not anchored on NEAR yet, so someone who can edit the '
                 f'box\'s files could still rewrite the whole log, or cut the newest entries off, without it '
                 f'showing here.</p>')
    else:
        items = "".join(f"<li>{esc(p)}</li>" for p in rep.problems[:10])
        state = f'<p class="bad">{who} log does not check out.</p><ul>{items}</ul>'
    notes = "".join(f'<p class="muted">Note: {esc(w)}</p>' for w in rep.warnings[:5])
    head = (f'<p>Chain head: <code>{esc(rep.head)}</code></p>' if rep.head else "")
    if near:
        last = near[-1]
        anchored = (f'<p class="muted">Last NEAR anchor: entry {esc(last.get("count"))}, '
                    f'{esc(_when(last.get("time")))}, transaction <code>{esc(last.get("tx_hash"))}</code>.</p>')
    else:
        anchored = '<p class="muted">Not anchored on NEAR yet.</p>'
    local = [c for c in cps if not c.get("tx_hash")]
    if local:
        anchored += (f'<p class="muted">Saved on this box (not on NEAR): entry {esc(local[-1].get("count"))}, '
                     f'{esc(_when(local[-1].get("time")))}.</p>')
    return f'<div class="card"><h2>{who} log</h2>{state}{notes}{head}{anchored}</div>'


def _recent(ctx, cfg, person, n: int = 15) -> str:
    path = ledger.log_path(cfg.runtime, person.id)
    if not path.exists():
        return ""
    rows = []
    for line in path.read_text(errors="replace").splitlines()[-n:][::-1]:
        try:
            e = json.loads(line)
        except ValueError:
            continue
        what = e.get("event") or e.get("outcome", "")
        via = e.get("source") or e.get("folder") or ""
        rows.append(f"<tr><td>{ctx.esc(e.get('seq', ''))}</td><td>{ctx.esc(_when(e.get('time')))}</td>"
                    f"<td>{ctx.esc(what)}</td><td>{ctx.esc(via)}</td></tr>")
    if not rows:
        return ""
    return ('<div class="card"><h2>Most recent</h2><table><tr><th>#</th><th>When</th><th>What</th><th>From</th>'
            f'</tr>{"".join(rows)}</table></div>')


def web_routes(ctx) -> list:
    cfg = ctx.cfg

    @ctx.need_signin
    async def log_page(request, sess):
        body = ('<h1>Log</h1><p>Every question an assistant asks, and every upload or delete, is written to a log. '
                'Each entry is linked to the one before it, so changing, removing or reordering any entry shows '
                'up here. The newest link (the chain head) can be put on the NEAR blockchain, so even the box '
                'cannot quietly rewrite its history once it is anchored.</p>')
        body += _status_card(ctx, cfg, sess.person, mine=True)
        body += _recent(ctx, cfg, sess.person)
        if sess.person.admin:
            others = [cfg.people[k] for k in sorted(cfg.people) if k != sess.person.id]
            body += "".join(_status_card(ctx, cfg, p, mine=False) for p in others)
        return ctx.page(sess, "Log", body, "/log")

    return [Route("/log", log_page)]
