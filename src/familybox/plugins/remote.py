"""Remote MCP: lets ChatGPT and Claude (web, desktop, phone) use the box as a custom connector.

Adds to the box's web page (familybox serve):
  /mcp, the OAuth 2.1 endpoints and metadata (see familybox.remote), the consent page where a family
  member links an assistant with a one-time sign-in code, and an "Assistants" page that lists
  connected assistants with Revoke, gives out linking codes and makes API tokens.

Adds to the CLI:
  familybox token --as maya [--label "Cursor"]    API token for apps that only take a bearer header
  familybox connections --as maya                 linked assistants and API tokens
  familybox revoke --as maya <id> | --all         cut one (or every) connection off right away
"""

from __future__ import annotations

import datetime as dt
from urllib.parse import urlsplit

from starlette.requests import Request
from starlette.responses import JSONResponse, RedirectResponse, Response
from starlette.routing import Route

from .. import remote

REMOTE_BUCKET = "remote_failures.json"

# --- web ---------------------------------------------------------------------------------------------


def web_nav():
    return [("Assistants", "/assistants")]


def _when(ts) -> str:
    if not ts:
        return "never"
    return dt.datetime.fromtimestamp(int(ts)).strftime("%b %d, %Y %I:%M %p").replace(" 0", " ")


def web_routes(ctx):
    from mcp.server.auth.handlers.authorize import AuthorizationHandler
    from mcp.server.auth.handlers.register import RegistrationHandler
    from mcp.server.auth.handlers.token import TokenHandler
    from mcp.server.auth.routes import build_metadata, cors_middleware
    from mcp.server.auth.settings import ClientRegistrationOptions, RevocationOptions
    from mcp.server.transport_security import DEFAULT_MAX_REQUEST_BODY_SIZE, RequestBodyLimitMiddleware
    from mcp.shared.auth import ProtectedResourceMetadata
    from pydantic import AnyHttpUrl
    from starlette.middleware.cors import CORSMiddleware
    from starlette.routing import request_response

    from ..web import WebState, _page

    cfg, esc = ctx.cfg, ctx.esc
    fixed = remote.public_url(cfg)          # raises on a bad setting: the plugin is skipped (fail closed)
    store = remote.RemoteStore(cfg)
    provider = remote.BoxProvider(store)
    authn = remote.HashedClientAuthenticator(provider)
    reg_opts = ClientRegistrationOptions(enabled=True, valid_scopes=[remote.SCOPE], default_scopes=[remote.SCOPE])
    rev_opts = RevocationOptions(enabled=True)
    signin = WebState(cfg)

    def base_of_scope(scope) -> str:
        if fixed:
            return fixed
        host = ""
        for k, v in scope.get("headers", []):
            if k == b"host":
                host = v.decode("latin-1")
                break
        host = host or "localhost"
        hostname = urlsplit(f"//{host}").hostname or ""
        scheme = scope.get("scheme", "https") if hostname in remote.LOOPBACK_HOSTS else "https"
        return f"{scheme}://{host}"

    def base_of(request: Request) -> str:
        return base_of_scope(request.scope)

    def with_base(handler):
        async def wrapped(request: Request):
            tok = remote.current_base.set(base_of(request))
            try:
                return await handler(request)
            finally:
                remote.current_base.reset(tok)
        return wrapped

    def asgi(handler, methods, cors: bool):
        app = RequestBodyLimitMiddleware(request_response(with_base(handler)), DEFAULT_MAX_REQUEST_BODY_SIZE)
        if cors:
            app = CORSMiddleware(app=app, allow_origins="*", allow_methods=methods,
                                 allow_headers=["mcp-protocol-version", "authorization", "content-type"])
        return app

    # ---- metadata (RFC 8414, RFC 9728)

    async def as_metadata(request: Request):
        base = base_of(request)
        md = build_metadata(AnyHttpUrl(base), None, reg_opts, rev_opts)
        md.token_endpoint_auth_methods_supported = ["none", "client_secret_post", "client_secret_basic"]
        md.revocation_endpoint_auth_methods_supported = ["none", "client_secret_post", "client_secret_basic"]
        data = md.model_dump(mode="json", exclude_none=True)
        data["issuer"] = base   # exact string, no trailing slash (RFC 8414 section 3.3)
        return JSONResponse(data, headers={"cache-control": "no-store"})

    async def pr_metadata(request: Request):
        base = base_of(request)
        md = ProtectedResourceMetadata(resource=AnyHttpUrl(remote.resource_of(base)),
                                       authorization_servers=[AnyHttpUrl(base)], scopes_supported=[remote.SCOPE],
                                       resource_name=cfg.name)
        data = md.model_dump(mode="json", exclude_none=True)
        data["resource"] = remote.resource_of(base)
        data["authorization_servers"] = [base]
        return JSONResponse(data)

    # ---- consent page

    def origin_ok(request: Request) -> bool:
        origin = request.headers.get("origin")
        if not origin or origin == "null":
            return origin is None
        return origin.split("://", 1)[-1] == request.headers.get("host", "")

    def returns_to(p: dict) -> str:
        parts = urlsplit(p["redirect_uri"])
        return parts.netloc or f"the {parts.scheme} app"

    def consent_shell(title: str, body: str, status: int = 200):
        return _page(cfg, title, body, status=status)

    def expired_page():
        return consent_shell("Link expired", '<h1>This link has expired</h1><p>Nothing was linked. Go back to your '
                             'assistant and start connecting the family box again.</p>', 400)

    def code_form(req_id: str, p: dict, error: str = "", status: int = 200):
        err = f'<p class="bad">{esc(error)}</p>' if error else ""
        name = p.get("client_name") or "An assistant"
        body = (f'<h1>Link an assistant</h1>'
                f'<div class="card"><p><strong>{esc(name)}</strong> wants to ask {esc(cfg.name)} questions for you.</p>'
                f'<p class="muted">The app picks its own name, so check where it sends you back: '
                f'<strong>{esc(returns_to(p))}</strong>. Only continue if you started this yourself, just now, '
                f'from your assistant\'s settings.</p></div>{err}'
                f'<form method="post" action="/authorize/consent" class="card">'
                f'<input type="hidden" name="req" value="{esc(req_id)}"><input type="hidden" name="step" value="code">'
                f'<label for="code">Your 8-letter sign-in code</label>'
                f'<input type="text" id="code" name="code" class="code" maxlength="12" autocomplete="one-time-code"'
                f' autocapitalize="characters" spellcheck="false" required>'
                f'<p class="muted">Get a code from the Assistants page on your box. It works once and lasts '
                f'10 minutes.</p>'
                f'<button class="main" type="submit">Next</button></form>'
                f'<form method="post" action="/authorize/consent"><input type="hidden" name="req" value="{esc(req_id)}">'
                f'<input type="hidden" name="step" value="deny">'
                f'<button class="main quiet" type="submit">Cancel</button></form>')
        return consent_shell("Link an assistant", body, status)

    def approve_form(req_id: str, nonce: str, p: dict, person):
        name = p.get("client_name") or "this assistant"
        body = (f'<h1>Link {esc(name)} to {esc(person.display)}?</h1>'
                f'<div class="card"><p>You are <strong>{esc(person.display)}</strong>. If you say yes, {esc(name)} can '
                f'ask the family box questions as you.</p><ul>'
                f'<li>It only gets checked answers, never your files.</li>'
                f'<li>Full ID numbers and private health details stay on the box. You see them only on the box\'s '
                f'Approvals page, after you approve each one.</li>'
                f'<li>You can cut it off any time on the Assistants page, or with '
                f'<code>familybox revoke</code>.</li></ul>'
                f'<p class="muted">It will send you back to: <strong>{esc(returns_to(p))}</strong></p></div>'
                f'<div class="row"><form method="post" action="/authorize/consent">'
                f'<input type="hidden" name="req" value="{esc(req_id)}"><input type="hidden" name="nonce" value="{esc(nonce)}">'
                f'<input type="hidden" name="step" value="approve">'
                f'<button class="main" type="submit">Yes, link it</button></form>'
                f'<form method="post" action="/authorize/consent">'
                f'<input type="hidden" name="req" value="{esc(req_id)}"><input type="hidden" name="nonce" value="{esc(nonce)}">'
                f'<input type="hidden" name="step" value="deny">'
                f'<button class="main quiet" type="submit">No</button></form></div>')
        return consent_shell("Link an assistant", body)

    def go_back(url: str, linked: bool, vetted: bool):
        # A page, not a redirect: the page's form-action rule would block a form that redirects off the box.
        # Only after a family member signed in does it send the browser on by itself. Before that, the app
        # is unvetted, so the box never forwards to it: the page names where the link goes and stops.
        if not vetted:
            parts = urlsplit(url)
            where = parts.netloc or f"the {parts.scheme} app"
            body = (f'<h1>Not linked</h1><p>Nothing was linked. You can close this page.</p>'
                    f'<p class="muted">If you started this from your assistant, this link goes back to it: '
                    f'<strong>{esc(where)}</strong></p>'
                    f'<p><a href="{esc(url)}" rel="noreferrer">Go back to {esc(where)}</a></p>')
            return consent_shell("Not linked", body)
        head = "Linked. Taking you back now." if linked else "Not linked. Taking you back now."
        body = (f'<meta http-equiv="refresh" content="0;url={esc(url)}">'
                f'<h1>{esc(head)}</h1><p><a class="button" href="{esc(url)}">Continue</a></p>')
        return consent_shell("Link an assistant", body)

    async def consent_get(request: Request):
        req_id = request.query_params.get("req", "")
        p = provider.pending(req_id)
        if p is None:
            return expired_page()
        return code_form(req_id, p)

    async def consent_post(request: Request):
        if not origin_ok(request):
            return ctx.forbidden()
        form = await request.form(max_files=0, max_fields=8, max_part_size=4096)
        req_id = str(form.get("req", ""))
        step = str(form.get("step", ""))
        p = provider.pending(req_id)
        if p is None:
            return expired_page()
        if step == "code":
            # Codes typed here count against their own lockout (remote_failures.json), so traffic from the
            # internet can never lock the home sign-in or the Approvals page.
            person_id, why = signin.redeem(str(form.get("code", "")), bucket=REMOTE_BUCKET)
            if person_id is None:
                if why == "locked":
                    return code_form(req_id, p, "Too many wrong codes. Wait 10 minutes, then try again.", 429)
                if provider.miss(req_id):
                    return consent_shell("Link expired", '<h1>Too many wrong codes</h1><p>Nothing was linked. '
                                         'Go back to your assistant and start connecting the family box '
                                         'again.</p>', 401)
                return code_form(req_id, p, "That code didn't work. Check it, or ask for a new one.", 401)
            nonce = provider.bind_person(req_id, person_id)
            if nonce is None:
                return expired_page()
            return approve_form(req_id, nonce, p, cfg.person(person_id))
        if step in ("approve", "deny"):
            done = provider.finish(req_id, str(form.get("nonce", "")), step == "approve")
            if done is None:
                return ctx.forbidden("That request wasn't allowed. Start again from your assistant.")
            url, vetted = done
            return go_back(url, step == "approve", vetted)
        return ctx.forbidden()

    # ---- Assistants page

    def add_one(request: Request) -> str:
        if fixed:
            return (f'<p>In ChatGPT or Claude, add a custom connector with this address, then sign in with a '
                    f'code from the box:</p><div class="value">{esc(remote.resource_of(fixed))}</div>')
        return (f'<p>This box isn\'t on the internet yet, so ChatGPT and Claude on the web can\'t reach it. '
                f'The person who runs the box can set that up with the steps in docs/REMOTE.md '
                f'("Putting it on the internet").</p>'
                f'<p class="muted">Apps on this home network can use this address now:</p>'
                f'<div class="value">{esc(remote.resource_of(base_of(request)))}</div>')

    def last_asked(person_id: str) -> dict:
        """connection id -> time of the last question it asked, from the person's audit file."""
        out: dict = {}
        path = cfg.runtime / "audit" / f"{person_id}.jsonl"
        try:
            lines = path.read_text().splitlines()[-2000:]
        except OSError:
            return out
        import json
        for line in lines:
            try:
                e = json.loads(line)
            except ValueError:
                continue
            if e.get("connection") and e.get("qid"):
                out[e["connection"]] = e.get("time")
        return out

    def assistants_page(request, sess, extra: str = "", status: int = 200):
        rows = []
        asked = last_asked(sess.person.id)
        for c in store.connections(sess.person.id):
            kind = "Linked with a sign-in code" if c["kind"] == "oauth" else "API token"
            back = f' &middot; returns to {esc(c["returns_to"])}' if c["returns_to"] else ""
            rows.append(
                f'<li><div class="name"><strong>{esc(c["name"])}</strong></div>'
                f'<div class="muted">{kind}{back}<br>Linked {esc(_when(c["created"]))} &middot; '
                f'last used {esc(_when(c["last_used"]))} &middot; last asked {esc(_when(asked.get(c["id"])))}'
                f' &middot; id {esc(c["id"])}</div>'
                f'<form method="post" action="/assistants/revoke">{ctx.csrf_field(sess.csrf)}'
                f'<input type="hidden" name="id" value="{esc(c["id"])}">'
                f'<button class="danger" type="submit">Revoke</button></form></li>')
        listing = f'<ul class="files">{"".join(rows)}</ul>' if rows else '<p class="muted">No assistants yet.</p>'
        body = (f'<h1>Connected assistants</h1>{extra}'
                f'<p class="muted">These assistants can ask the family box questions as you. Revoking one stops it '
                f'right away.</p><div class="card">{listing}</div>'
                f'<div class="card"><h2>Add one</h2>{add_one(request)}'
                f'<form method="post" action="/assistants/code">{ctx.csrf_field(sess.csrf)}'
                f'<p class="muted">When the assistant asks for a code, get one here.</p>'
                f'<button class="main" type="submit">Get a linking code</button></form>'
                f'<form method="post" action="/assistants/token">{ctx.csrf_field(sess.csrf)}'
                f'<p class="muted">Some apps only take a token instead of a sign-in. Make one for them here. '
                f'It is shown once.</p>'
                f'<label for="label">What is it for?</label>'
                f'<input type="text" id="label" name="label" maxlength="60" placeholder="Cursor on my laptop">'
                f'<button class="main quiet" type="submit">Make a token</button></form></div>')
        return ctx.page(sess, "Assistants", body, "/assistants", status)

    @ctx.need_signin
    async def assistants_get(request: Request, sess):
        return assistants_page(request, sess)

    async def assistants_revoke(request: Request):
        got = await ctx.guarded_form(request)
        if isinstance(got, Response):
            return got
        sess, form = got
        if store.revoke(sess.person.id, str(form.get("id", ""))):
            from ..web import _audit
            _audit(cfg, sess.person.id, {"event": "assistant_revoked", "connection": str(form.get("id", ""))[:20],
                                         "by": "web"})
            return assistants_page(request, sess, '<p class="ok">Revoked. It can\'t ask anything now.</p>')
        return assistants_page(request, sess, '<p class="bad">That connection isn\'t yours or is already gone.</p>',
                               404)

    async def assistants_token(request: Request):
        got = await ctx.guarded_form(request)
        if isinstance(got, Response):
            return got
        sess, form = got
        tid, token = store.new_api_token(sess.person.id, str(form.get("label", "")))
        from ..web import _audit
        _audit(cfg, sess.person.id, {"event": "api_token_made", "connection": tid, "by": "web"})
        extra = (f'<div class="card"><p class="ok">Here is your token. Copy it into the app now. It won\'t be '
                 f'shown again. Anyone with it can ask the box as you, so keep it private.</p>'
                 f'<div class="value">{esc(token)}</div>'
                 f'<p class="muted">Send it as the header: Authorization: Bearer (then the token)</p></div>')
        return assistants_page(request, sess, extra)

    async def assistants_code(request: Request):
        got = await ctx.guarded_form(request, max_files=0, max_fields=4, max_part_size=4096)
        if isinstance(got, Response):
            return got
        sess, _ = got
        code = (ctx.state or signin).issue_code(sess.person.id)
        from ..web import CODE_TTL_S, _audit
        _audit(cfg, sess.person.id, {"event": "linking_code_issued", "by": "web", "expires_in_s": CODE_TTL_S})
        address = remote.resource_of(fixed or base_of(request))
        extra = (f'<div class="card"><h2>Your linking code</h2>'
                 f'<div class="value">{esc(code[:4])}-{esc(code[4:])}</div>'
                 f'<p class="muted">It works once and lasts 10 minutes. It links an assistant to you, '
                 f'{esc(sess.person.display)}, so don\'t share it. It won\'t be shown again.</p>'
                 f'<ol><li>In ChatGPT or Claude, add a custom connector with this address:'
                 f'<div class="value">{esc(address)}</div></li>'
                 f'<li>The assistant opens a page from this box. Type the code there.</li>'
                 f'<li>Check the name it shows, then choose "Yes, link it".</li></ol></div>')
        return assistants_page(request, sess, extra)

    async def revoke_endpoint(request: Request):
        """RFC 7009. Always 200 for unknown tokens; a token can only be revoked by the app it was issued to."""
        try:
            client = await authn.authenticate_request(request)
        except remote.AuthenticationError as e:
            return JSONResponse({"error": "invalid_client", "error_description": e.message}, status_code=401,
                                headers={"cache-control": "no-store"})
        form = await request.form()
        token = form.get("token")
        if not isinstance(token, str) or not token:
            return JSONResponse({"error": "invalid_request", "error_description": "token is required"},
                                status_code=400, headers={"cache-control": "no-store"})
        provider.revoke_for_client(client.client_id, token)
        return Response(status_code=200, headers={"cache-control": "no-store"})

    gateway = remote.McpGateway(cfg=cfg, store=store, base_for=base_of_scope, box=ctx.box)
    sdk_authorize = AuthorizationHandler(provider)

    async def authorize(request: Request):
        """The SDK's /authorize, except it never sends the browser to an app's address by itself.

        Anyone can register an app with any https address, so an error redirect (bad scope, bad
        resource, too many requests) would make the box an open redirector for phishing links
        (RFC 9700 section 4.11.2). Errors are shown on a box page instead."""
        resp = await sdk_authorize.handle(request)
        loc = resp.headers.get("location", "")
        if 300 <= resp.status_code < 400 and not loc.startswith("/authorize/consent?"):
            return consent_shell("Link didn't work", '<h1>This link didn\'t work</h1><p>Nothing was linked. '
                                 'Go back to your assistant and try connecting the family box again. If it keeps '
                                 'happening, the box may be busy, so wait a few minutes.</p>', 400)
        if resp.status_code >= 400:
            return consent_shell("Link didn't work", '<h1>This link didn\'t work</h1><p>Nothing was linked. '
                                 'Go back to your assistant and try connecting the family box again.</p>',
                                 resp.status_code)
        return resp
    token_handler = TokenHandler(provider, authn)
    reg_handler = RegistrationHandler(provider, options=reg_opts)

    return [
        Route("/.well-known/oauth-authorization-server", cors_middleware(as_metadata, ["GET", "OPTIONS"]),
              methods=["GET", "OPTIONS"]),
        Route("/.well-known/oauth-authorization-server/mcp", cors_middleware(as_metadata, ["GET", "OPTIONS"]),
              methods=["GET", "OPTIONS"]),
        Route("/.well-known/oauth-protected-resource", cors_middleware(pr_metadata, ["GET", "OPTIONS"]),
              methods=["GET", "OPTIONS"]),
        Route("/.well-known/oauth-protected-resource/mcp", cors_middleware(pr_metadata, ["GET", "OPTIONS"]),
              methods=["GET", "OPTIONS"]),
        Route("/authorize", asgi(authorize, ["GET", "POST"], cors=False), methods=["GET", "POST"]),
        Route("/authorize/consent", consent_get, methods=["GET"]),
        Route("/authorize/consent", consent_post, methods=["POST"]),
        Route("/token", asgi(token_handler.handle, ["POST", "OPTIONS"], cors=True), methods=["POST", "OPTIONS"]),
        Route("/register", asgi(reg_handler.handle, ["POST", "OPTIONS"], cors=True), methods=["POST", "OPTIONS"]),
        Route("/revoke", asgi(revoke_endpoint, ["POST", "OPTIONS"], cors=True), methods=["POST", "OPTIONS"]),
        Route("/mcp", gateway, methods=["GET", "POST", "DELETE"]),
        Route("/assistants", assistants_get, methods=["GET"]),
        Route("/assistants/revoke", assistants_revoke, methods=["POST"]),
        Route("/assistants/token", assistants_token, methods=["POST"]),
        Route("/assistants/code", assistants_code, methods=["POST"]),
    ]


# --- CLI ---------------------------------------------------------------------------------------------

COMMANDS = {"token", "connections", "revoke"}


def cli(sub) -> None:
    t = sub.add_parser("token", help="make an API token for an app that only takes a bearer header")
    t.add_argument("--as", dest="person", required=True)
    t.add_argument("--label", default="", help="what the token is for, e.g. \"Cursor on my laptop\"")
    c = sub.add_parser("connections", help="list assistants linked to a family member")
    c.add_argument("--as", dest="person", required=True)
    r = sub.add_parser("revoke", help="cut off a linked assistant or API token")
    r.add_argument("--as", dest="person", required=True)
    r.add_argument("id", nargs="?", help="the id from familybox connections")
    r.add_argument("--all", action="store_true", help="revoke every connection for this person")


def run_cli(args, cfg) -> int | None:
    if args.cmd not in COMMANDS:
        return None
    from ..web import _audit
    try:
        person = cfg.person(args.person)
    except KeyError as e:
        print(e.args[0])
        return 2
    store = remote.RemoteStore(cfg)
    if args.cmd == "token":
        tid, token = store.new_api_token(person.id, args.label)
        _audit(cfg, person.id, {"event": "api_token_made", "connection": tid, "by": "cli"})
        print(f"API token for {person.display} (id {tid}). It is shown only this once:\n")
        print(f"    {token}\n")
        print("Give it to the app as the header  Authorization: Bearer <token>")
        print(f"Anyone with it can ask the box as {person.display}. Revoke it with: "
              f"familybox revoke --as {person.id} {tid}")
        return 0
    if args.cmd == "connections":
        conns = store.connections(person.id)
        if not conns:
            print(f"No assistants are linked to {person.display}.")
            return 0
        for c in conns:
            kind = "linked with a sign-in code" if c["kind"] == "oauth" else "API token"
            back = f", returns to {c['returns_to']}" if c["returns_to"] else ""
            print(f"{c['id']}  {c['name']}  ({kind}{back})  linked {_when(c['created'])}, "
                  f"last used {_when(c['last_used'])}")
        return 0
    # revoke
    if args.all:
        n = store.revoke_all(person.id)
        _audit(cfg, person.id, {"event": "assistant_revoked", "connection": "all", "count": n, "by": "cli"})
        print(f"Revoked {n} connection(s) for {person.display}.")
        return 0
    if not args.id:
        print("Give the id from `familybox connections`, or --all.")
        return 2
    if store.revoke(person.id, args.id):
        _audit(cfg, person.id, {"event": "assistant_revoked", "connection": args.id[:20], "by": "cli"})
        print(f"Revoked {args.id}. It can't ask the box anything now.")
        return 0
    print(f"{args.id} isn't one of {person.display}'s connections.")
    return 1
