"""Red-team page plugin (off by default). See docs/REDTEAM.md.

  familybox redteam init <folder>            make a dedicated demo home with the fictional family
  familybox redteam serve --home <folder>    run only the /redteam page on https://127.0.0.1:<port>/
  familybox redteam status --home <folder>   scoreboard and today's spend

The /redteam route exists only when the red-team switch is on for the running home, and the switch
only turns on for a dedicated demo home (familybox.redteam.home.check_demo_home). A normal
`familybox serve` never has it.
"""

from __future__ import annotations

import json
from pathlib import Path

from familybox.redteam import home as rt_home


def register(box) -> None:
    if rt_home.settings_for(box.cfg) is None:
        return
    from familybox.redteam import guard
    guard.install(box)


def web_routes(ctx) -> list:
    settings = rt_home.settings_for(ctx.cfg)
    if settings is None:
        return []
    from familybox.redteam import pages
    return pages.for_cfg(ctx.cfg, settings).routes()


def cli(subparsers) -> None:
    p = subparsers.add_parser("redteam", help="red-team page for judges, on a dedicated demo home only")
    sub = p.add_subparsers(dest="redteam_action", required=True)
    i = sub.add_parser("init", help="copy the fictional demo family into a new folder")
    i.add_argument("folder")
    for name in ("serve", "status"):
        sp = sub.add_parser(name)
        sp.add_argument("--home", default=None, help="the demo home made by `familybox redteam init`")
    sv = sub.choices["serve"]
    d = rt_home.Settings()
    sv.add_argument("--port", type=int, default=8444)
    sv.add_argument("--replay-only", action="store_true", help="never call the live enclave model")
    sv.add_argument("--budget-usd", type=float, default=d.daily_budget_usd, help="hard daily budget in US dollars")
    sv.add_argument("--price-in", type=float, default=None,
                    help="US dollars per million input tokens (required for live mode; check NEAR AI Cloud)")
    sv.add_argument("--price-out", type=float, default=None,
                    help="US dollars per million output tokens (required for live mode; check NEAR AI Cloud)")
    sv.add_argument("--max-tokens-per-day", type=int, default=d.max_tokens_per_day)
    sv.add_argument("--live-per-visitor", type=int, default=d.live_per_visitor_per_hour, help="live tries per hour")
    sv.add_argument("--live-global", type=int, default=d.live_global_per_hour, help="live tries per hour, everyone")
    sv.add_argument("--trust-ip-header", default=None,
                    help="read the visitor address from this header (only behind a proxy you control)")


PRICE_NEEDED = ("live mode needs the real NEAR AI Cloud price for the model. Pass --price-in and --price-out "
                "(US dollars per million tokens), or use --replay-only")


def settings_from_args(args) -> rt_home.Settings:
    """Settings from `redteam serve` flags. Live mode refuses to start without both price flags."""
    from familybox import enclave
    d = rt_home.Settings()
    live = bool(enclave.api_key()) and not args.replay_only
    if live and (args.price_in is None or args.price_out is None):
        raise rt_home.RedTeamError(PRICE_NEEDED)
    for v in (args.price_in, args.price_out):
        if v is not None and v <= 0:
            raise rt_home.RedTeamError("prices must be more than zero")
    return rt_home.Settings(
        daily_budget_usd=args.budget_usd,
        price_in_per_m=d.price_in_per_m if args.price_in is None else args.price_in,
        price_out_per_m=d.price_out_per_m if args.price_out is None else args.price_out,
        max_tokens_per_day=args.max_tokens_per_day, live_per_visitor_per_hour=args.live_per_visitor,
        live_global_per_hour=args.live_global, replay_only=args.replay_only,
        trust_ip_header=(args.trust_ip_header or None) and args.trust_ip_header.lower())


def run_cli(args, cfg) -> int | None:
    if args.cmd != "redteam":
        return None
    from familybox import config
    if args.redteam_action == "init":
        try:
            new = rt_home.init_home(Path(args.folder))
        except rt_home.RedTeamError as e:
            print(f"error: {e}"); return 1
        print(f"made a red-team demo home at {new.home}")
        print(f"start the page with: familybox redteam serve --home {new.home}")
        return 0
    home_cfg = config.load(Path(args.home).expanduser()) if args.home else cfg
    if args.redteam_action == "status":
        try:
            rt_home.check_demo_home(home_cfg)
        except rt_home.RedTeamError as e:
            print(f"error: {e}"); return 1
        from familybox.redteam.ledger import Ledger
        print(json.dumps(Ledger(home_cfg, rt_home.Settings()).snapshot(), indent=1))
        return 0
    if args.redteam_action == "serve":
        try:
            settings = settings_from_args(args)
            rt_home.enable(home_cfg, settings)
            app = create_app(home_cfg)
        except rt_home.RedTeamError as e:
            rt_home.disable(home_cfg)
            print(f"error: {e}"); return 1
        serve(home_cfg, args.port, app)
        return 0
    return None


def create_app(cfg):
    """The red-team server app: the box's web app with only the red-team paths reachable."""
    from familybox import web
    from familybox.redteam.pages import OnlyRedTeam
    if rt_home.settings_for(cfg) is None:
        raise rt_home.RedTeamError("the red-team page is not switched on for this home")
    from familybox import enclave
    from familybox.box import Box
    from familybox.redteam import guard
    try:
        guard.check_composition(Box(cfg))
    except enclave.EnclaveError as e:
        raise rt_home.RedTeamError(str(e)) from e
    return OnlyRedTeam(web.create_app(cfg))


def serve(cfg, port: int, app=None) -> None:
    import uvicorn
    from familybox import enclave, web
    from familybox.redteam.ledger import Ledger
    cert, key, fp = web.ensure_cert(cfg)
    s = rt_home.settings_for(cfg)
    led = Ledger(cfg, s)
    live = bool(enclave.api_key()) and not s.replay_only
    print(f"red-team page on https://127.0.0.1:{port}/redteam (this computer only)")
    print(f"certificate SHA-256 fingerprint: {fp}")
    print(f"mode: {'live, within the limits below' if live else 'replay only'}")
    print(f"daily budget ${s.daily_budget_usd:.2f} at ${s.price_in_per_m}/M in and ${s.price_out_per_m}/M out; "
          f"each live try reserves up to ${led.worst_usd:.3f}")
    print(f"live tries per hour: {s.live_per_visitor_per_hour} per visitor, {s.live_global_per_hour} for everyone")
    if live and not s.trust_ip_header:
        print("note: without --trust-ip-header every visitor counts as this computer. That is right for local "
              "use only; behind a tunnel, every visitor would share one per-visitor limit.")
    print("", end="", flush=True)
    uvicorn.run(app or create_app(cfg), host="127.0.0.1", port=port, ssl_certfile=str(cert), ssl_keyfile=str(key),
                access_log=False, log_level="warning", server_header=False, proxy_headers=False)
