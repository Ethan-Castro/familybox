"""familybox command line.

  familybox index                         rebuild the search index
  familybox ask --as maya "question"      ask as a family member (live with a key, else replay)
  familybox pending --as dana             list values waiting for dana's approval
  familybox approve --as dana <id>        approve and show the full value here (owner's screen)
  familybox deny --as dana <id>
  familybox log --as maya                 what left the box for maya
  familybox verify                        check the NEAR enclave attestation only (no inference)
  familybox code --as maya                one-time sign-in code for the box's web page (10 minutes)
  familybox serve [--lan] [--port 8443]   the box's private web page (HTTPS; --lan only on the box itself)

  familybox cloud status --as maya        Google Drive connection, last import, last backup
  familybox cloud connect --as maya       print the Google sign-in link, then paste the code back
  familybox cloud import --as maya "Folder name or link"
  familybox cloud backup-key --as dana    make the backup key and show its recovery code once (admin)
  familybox cloud backup --as dana        encrypt the box and upload it to the admin's Drive
  familybox cloud restore --as dana <drive file id or .fbx path>   asks for the recovery code
  familybox cloud disconnect --as maya
"""

from __future__ import annotations

import argparse
import asyncio
import json
import sys

from . import config, enclave
from .approvals import Approvals
from .box import Box
from .store import Store

OUTCOME_LABEL = {"pass": "answered", "masked": "answered (numbers removed)", "held": "answered (some details held)",
                 "refused": "blocked", "error": "stopped (verification failed)"}

CORE_COMMANDS = {"index", "ask", "pending", "log", "approve", "deny", "verify", "code", "serve", "cloud"}


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(prog="familybox")
    sub = ap.add_subparsers(dest="cmd", required=True)
    sub.add_parser("index")
    a = sub.add_parser("ask")
    a.add_argument("--as", dest="person", required=True)
    a.add_argument("--mode", choices=["auto", "live", "replay", "record"], default="auto")
    a.add_argument("--json", action="store_true")
    a.add_argument("question")
    for name in ("pending", "log"):
        p = sub.add_parser(name)
        p.add_argument("--as", dest="person", required=True)
    for name in ("approve", "deny"):
        p = sub.add_parser(name)
        p.add_argument("--as", dest="person", required=True)
        p.add_argument("id")
    sub.add_parser("verify")
    c = sub.add_parser("code")
    c.add_argument("--as", dest="person", required=True)
    sv = sub.add_parser("serve")
    sv.add_argument("--lan", action="store_true", help="listen on the home network (0.0.0.0); use only on the box")
    sv.add_argument("--port", type=int, default=8443)
    c = sub.add_parser("cloud")
    csub = c.add_subparsers(dest="action", required=True)
    for name in ("status", "connect", "import", "backup", "backup-key", "restore", "disconnect"):
        cp = csub.add_parser(name)
        cp.add_argument("--as", dest="person", required=True)
        if name == "connect":
            cp.add_argument("--redirect", default=None,
                            help="redirect URI registered in Google Cloud (default: FAMILYBOX_CLI_REDIRECT "
                                 f"or {CLI_REDIRECT_DEFAULT})")
        elif name == "import":
            cp.add_argument("folder", help="Drive folder name, link or id")
        elif name == "backup-key":
            cp.add_argument("--force", action="store_true", help="replace an existing key")
        elif name == "restore":
            cp.add_argument("source", help="Drive file id or path to a .fbx file")
    from . import plugins
    plugins.call_each("cli", sub)
    args = ap.parse_args(argv)
    cfg = config.load()

    if args.cmd not in CORE_COMMANDS:
        for m in plugins.load_plugins():
            run = getattr(m, "run_cli", None)
            if run is None:
                continue
            rc = run(args, cfg)
            if rc is not None:
                return int(rc)
        print(f"no handler for {args.cmd!r}", file=sys.stderr)
        return 2

    if args.cmd == "index":
        print(f"indexed {Store(cfg).reindex()} files")
    elif args.cmd == "ask":
        ans = Box(cfg, mode=args.mode).ask(args.person, args.question, source="cli")
        if args.json:
            print(json.dumps(ans.to_dict(), indent=1))
        else:
            e = ans.enclave
            print(f"[{OUTCOME_LABEL[ans.outcome]}]")
            print(ans.text)
            print()
            if e:
                print(f"enclave: {e['model']}, {e['turns']} turns, signatures {e['signatures']}"
                      f"{' (replayed recording)' if e['replayed'] else ''}")
            print(f"files read: {ans.files_read or 'none'}")
            if ans.files_denied:
                print(f"files refused: {ans.files_denied}")
            if ans.reasons:
                print(f"gate: {'; '.join(ans.reasons)}")
        return 0 if ans.outcome != "error" else 1
    elif args.cmd == "pending":
        for item in Approvals(cfg).pending(args.person):
            print(json.dumps(item))
    elif args.cmd in ("approve", "deny"):
        result = Approvals(cfg).decide(args.person, args.id, args.cmd == "approve")
        result.pop("decision", None)
        print(json.dumps(result))
    elif args.cmd == "log":
        path = cfg.runtime / "audit" / f"{args.person}.jsonl"
        print(path.read_text() if path.exists() else "(nothing yet)")
    elif args.cmd == "code":
        from . import web
        try:
            code = web.issue_code(cfg, args.person)
        except KeyError as e:
            print(e.args[0]); return 2
        print(f"sign-in code for {cfg.person(args.person).display}: {code[:4]}-{code[4:]}")
        print("type it on the box's web page within 10 minutes. It works once.")
    elif args.cmd == "serve":
        from . import web
        web.serve(cfg, lan=args.lan, port=args.port)
    elif args.cmd == "cloud":
        return _cloud(cfg, args)
    elif args.cmd == "verify":
        key = enclave.api_key()
        if not key:
            print("NEAR_AI_CLOUD_API_KEY is not set"); return 2
        return asyncio.run(_verify(key, cfg.model))
    return 0


CLI_REDIRECT_DEFAULT = "http://127.0.0.1:8765/cloud/callback"


def _parse_pasted(text: str) -> tuple[str | None, str]:
    """Accept the whole redirect URL from the address bar, its query string, or just the code."""
    from urllib.parse import parse_qs, urlsplit
    text = text.strip()
    if "code=" in text or "error=" in text:
        q = parse_qs(urlsplit(text).query if "://" in text else text.lstrip("?"))
        if "error" in q:
            raise SystemExit(f"Google returned an error: {q['error'][0]}")
        return (q.get("state") or [None])[0], (q.get("code") or [""])[0]
    return None, text


def _cloud(cfg, args) -> int:
    import getpass
    import os
    from . import cloud
    try:
        cfg.person(args.person)
    except KeyError as e:
        print(e.args[0]); return 2
    try:
        if args.action in ("backup", "backup-key", "restore") and not cfg.person(args.person).admin:
            print(f"{args.person} is not the box admin; backups and restores belong to the admin"); return 2
        if args.action == "status":
            print(json.dumps(cloud.status(cfg, args.person), indent=1))
        elif args.action == "connect":
            redirect = args.redirect or os.environ.get("FAMILYBOX_CLI_REDIRECT", CLI_REDIRECT_DEFAULT)
            url = cloud.begin_connect(cfg, args.person, redirect)
            from urllib.parse import parse_qs, urlsplit
            state = parse_qs(urlsplit(url).query)["state"][0]
            print("1. Open this link in a browser and sign in to Google:\n")
            print(url)
            print("\n2. Google sends the browser to a page that may not load. That is fine.")
            print("   Copy the whole address from the address bar (or just the code) and paste it here.\n")
            pasted_state, code = _parse_pasted(input("Paste here: "))
            if pasted_state and pasted_state != state:
                print("that address belongs to a different sign-in; run connect again"); return 1
            st = cloud.finish_connect(cfg, state, code)
            print(f"connected {args.person} as {st['account_email'] or 'unknown account'}")
        elif args.action == "import":
            r = cloud.import_folder(cfg, args.person, args.folder)
            print(f"imported {r['imported']}, skipped {r['skipped']} from Drive folder {r['folder']!r}")
            for f in r.get("files", []):
                print(f"  + {f}")
            for f in r.get("skipped_files", []):
                print(f"  - {f['name']}: {f['reason']}")
        elif args.action == "backup-key":
            code = cloud.init_backup_key(cfg, force=args.force)
            print("Backup recovery code. Write it down and keep it somewhere safe, away from the box.")
            print("It is shown only this once. Without it, nobody (not you, not Google) can open a backup.\n")
            print(f"    {code}\n")
        elif args.action == "backup":
            r = cloud.backup_now(cfg)
            print(json.dumps(r, indent=1))
        elif args.action == "restore":
            import sys as _sys
            code = getpass.getpass("Recovery code: ") if _sys.stdin.isatty() else _sys.stdin.readline()
            print(json.dumps(cloud.restore(cfg, args.source, code), indent=1))
        elif args.action == "disconnect":
            print(json.dumps(cloud.disconnect(cfg, args.person), indent=1))
    except cloud.CloudError as e:
        print(f"error: {e}"); return 1
    return 0


async def _verify(key: str, model: str) -> int:
    from nearai_inference_sdk import InferenceClient, get_sdk_error
    try:
        async with InferenceClient(key, e2ee=True, attestation_cache_time_to_live_ms=0) as c:
            att = await c.verify(model)
        print(json.dumps({"model": model, "gateway": "verified", "model_reports_verified": len(att.models),
                          "verified_at_ms": att.verified_at}))
        return 0 if att.models else 1
    except Exception as e:  # noqa: BLE001
        sdk = get_sdk_error(e)
        print(json.dumps({"model": model, "verified": False, "error": sdk.failure.code if sdk else str(e)}))
        return 1


if __name__ == "__main__":
    sys.exit(main())
