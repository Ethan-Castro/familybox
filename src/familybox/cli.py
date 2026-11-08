"""familybox command line.

  familybox index                         rebuild the search index
  familybox ask --as maya "question"      ask as a family member (live with a key, else replay)
  familybox pending --as dana             list values waiting for dana's approval
  familybox approve --as dana <id>        approve and show the full value here (owner's screen)
  familybox deny --as dana <id>
  familybox log --as maya                 what left the box for maya
  familybox verify                        check the NEAR enclave attestation only (no inference)
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
    args = ap.parse_args(argv)
    cfg = config.load()

    if args.cmd == "index":
        print(f"indexed {Store(cfg).reindex()} files")
    elif args.cmd == "ask":
        ans = Box(cfg, mode=args.mode).ask(args.person, args.question)
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
        print(json.dumps(Approvals(cfg).decide(args.person, args.id, args.cmd == "approve")))
    elif args.cmd == "log":
        path = cfg.runtime / "audit" / f"{args.person}.jsonl"
        print(path.read_text() if path.exists() else "(nothing yet)")
    elif args.cmd == "verify":
        key = enclave.api_key()
        if not key:
            print("NEAR_AI_CLOUD_API_KEY is not set"); return 2
        return asyncio.run(_verify(key, cfg.model))
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
