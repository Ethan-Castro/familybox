# Remote MCP: using the box from ChatGPT and Claude on the web

ChatGPT and Claude (web, desktop and phone) can add a "custom connector": an MCP server they reach
over the internet. The box's own web page (`familybox serve`) now is one. It speaks streamable HTTP
MCP at `/mcp` and runs its own sign-in, so no outside account service is involved.

**Status:** built and tested in-process (see "What was tested"). It has **not** been exposed to the
internet or tried with the real ChatGPT or Claude apps yet. Opening it to the internet needs Ethan's
OK first. The steps are below, and none of the tunnel steps have been run.

## How linking works (what a family member sees)

1. In ChatGPT or Claude, add a custom connector with the box's address, for example
   `https://box.example.org/mcp`.
2. The assistant opens a page on the box: "Claude wants to ask the Okafor family box questions for you."
   It shows where it will send you back (for example `claude.ai`).
3. The person who runs the box makes a one-time code: `familybox code --as maya`. Maya types it.
4. The box asks: "Link Claude to Maya?" Maya taps "Yes, link it" and lands back in Claude.
5. From then on, every question that assistant asks is asked **as Maya**: only Maya's files, the same
   checks on every answer, and held details go only to Maya's own Approvals page.

To cut an assistant off: the **Assistants** page on the box (Revoke button), or
`familybox connections --as maya` then `familybox revoke --as maya <id>`. It stops at once.

## Apps that only take a token

Some apps (Cursor, Codex, scripts) can't do a sign-in, only an `Authorization: Bearer` header:

```bash
uv run familybox token --as maya --label "Cursor on my laptop"   # shown once
```

Or use "Make a token" on the Assistants page. The token is stored only as a hash. It lasts until it
is revoked, so treat it like a password.

## The endpoints

| Path | What it is |
|---|---|
| `/.well-known/oauth-protected-resource/mcp` (and without `/mcp`) | RFC 9728: says `/mcp` is protected and who issues tokens |
| `/.well-known/oauth-authorization-server` | RFC 8414 metadata for the box's sign-in |
| `/register` | RFC 7591 dynamic client registration (the assistant registers itself) |
| `/authorize` | authorization code with PKCE. Only S256 is accepted |
| `/authorize/consent` | the page where the family member types the code and approves |
| `/token` | code and refresh grants |
| `/revoke` | RFC 7009 token revocation |
| `/mcp` | streamable HTTP MCP. Tools: `ask_family_box`, `family_box_status`, plus plugin tools |
| `/assistants` | the "Connected assistants" page (signed in) |

The protocol handlers are the MCP SDK's own (`mcp.server.auth` in mcp 2.3.0: authorize, token and
register handlers, metadata builders). The box supplies storage, the consent page, a client check
that compares hashed client secrets, and a revoke endpoint. The SDK's revoke handler requires a
`client_secret` field even from public clients, so the box uses its own.

## Setting the public address

The box works out its address from each request's `Host` header. Behind a tunnel, set it explicitly
so the sign-in metadata and token audience never depend on a header:

```bash
export FAMILYBOX_PUBLIC_URL=https://box.example.org     # or in family.toml:
# [remote]
# public_url = "https://box.example.org"
```

It must be `https://` and have no path. A bad value turns the remote feature off (the plugin is skipped)
rather than running with a wrong address.

## Putting it on the internet (needs Ethan's OK; not done)

Run all of this **on the Pi**, never from the laptop. The tunnel program on the Pi connects to the box
from the inside, so no port is opened on the home router.

**Never point a tunnel at the main web page (port 8443).** It has sign-in, upload, files and the
Approvals page, where full held values are shown. Behind a tunnel every request comes from
`127.0.0.1`, so the box can't tell internet traffic from the home network. Instead start the box with
an assistant-only listener and point the tunnel there:

```bash
FAMILYBOX_PUBLIC_URL=https://box.example.org uv run familybox serve --remote-port 8444
```

Port 8444 is a second listener, always on `127.0.0.1` (even with `--lan`), that serves only what
assistants need: `/mcp`, `/.well-known/oauth-protected-resource[/mcp]`,
`/.well-known/oauth-authorization-server[/mcp]`, `/register`, `/authorize`, `/authorize/consent`,
`/token`, `/revoke` and `/static/style.css`. Every other path, including `/signin`, `/approvals`,
`/files`, `/upload`, `/cloud` and `/assistants`, answers 404 there (tested in-process, and checked
once with real listeners on 127.0.0.1). The home page stays on 8443 for the home network. Both
listeners share one Box and the same state on disk.

The recipes below also filter paths in the tunnel, as a second layer.

### Option A: Cloudflare Tunnel (a fixed name on a domain Ethan owns)

```bash
# on the Pi
sudo apt install cloudflared               # or the .deb from Cloudflare
cloudflared tunnel login                   # opens a browser sign-in for the Cloudflare account
cloudflared tunnel create familybox
cloudflared tunnel route dns familybox box.example.org
cat > ~/.cloudflared/config.yml <<'EOF'
tunnel: familybox
credentials-file: /home/<user>/.cloudflared/<tunnel-id>.json
ingress:
  - hostname: box.example.org
    path: ^/(mcp|register|authorize(/consent)?|token|revoke|static/style\.css|\.well-known/oauth-(authorization-server|protected-resource)(/mcp)?)$
    service: https://localhost:8444        # the assistant-only listener, never 8443
    originRequest:
      originServerName: localhost          # the box's self-signed cert names localhost
      caPool: /path/to/familybox/runtime/tls/cert.pem
  - service: http_status:404               # everything else
EOF
FAMILYBOX_PUBLIC_URL=https://box.example.org uv run familybox serve --remote-port 8444 &
cloudflared tunnel run familybox
```

`caPool` is meant to pin the box's own certificate, so the tunnel checks it instead of skipping the
check (`noTLSVerify`). **This has not been tested.** The box's certificate is a self-signed leaf
(`CA:FALSE`), and cloudflared may refuse to use a leaf as its trust root. If it does, do not fall back
to `noTLSVerify`. Instead make a small certificate authority on the Pi, sign a `localhost` certificate
with it, put that certificate and key at `<runtime>/tls/cert.pem` and `key.pem` (the box reuses files
that are already there), and set `caPool` to the authority's certificate. Or use Option B, whose inside
hop never leaves the Pi.

Do not add Cloudflare Access in front of `/mcp`: ChatGPT and Claude can't pass it. Also not tested:
whether cloudflared passes the original `Host` header through. The consent page compares the
browser's `Origin` with `Host`, so if the box sees `localhost` instead, posting a sign-in code will be
refused until `httpHostHeader: box.example.org` is added under `originRequest`.

### Option B: Tailscale Funnel (no domain needed)

```bash
# on the Pi, already on the tailnet
sudo tailscale funnel --bg https+insecure://localhost:8444     # the assistant-only listener, never 8443
tailscale funnel status                    # shows https://decision-tree.<tailnet>.ts.net
FAMILYBOX_PUBLIC_URL=https://decision-tree.<tailnet>.ts.net uv run familybox serve --remote-port 8444
```

Because 8444 serves only the assistant routes, the whole port can be funneled. To filter in Tailscale
too, map each path on its own with `--set-path` (for example
`tailscale funnel --bg --set-path /mcp https+insecure://localhost:8444/mcp`, one per path in the list
above) instead of the whole port. Not tested.

`https+insecure` means Tailscale does not check the box's self-signed certificate on the hop inside
the Pi. That hop never leaves the Pi.

### Option C: Ethan's Base relay (unverified)

Not checked anywhere in this repo: whether the Base relay can forward MCP for ChatGPT and Claude web.
If it can, it would forward `https://<relay>/...` to the box's assistant-only listener
(`https://localhost:8444`), and `FAMILYBOX_PUBLIC_URL` would be set to the relay address. The exact
steps depend on the relay's config, which is not in this repo. Ethan to fill in.

## Connecting each assistant (once it's public)

Menu names change often. These are the current paths as far as we know, not yet tried against this box.

- **ChatGPT:** Settings, Apps and Connectors, Advanced, turn on Developer mode, then Create. URL
  `https://box.example.org/mcp`, authentication OAuth.
- **Claude (claude.ai, desktop, phone):** Settings, Connectors, Add custom connector. URL
  `https://box.example.org/mcp`. Leave the OAuth client fields empty (the box registers it).
- **Claude Code:** `claude mcp add --transport http family-box https://box.example.org/mcp`, then `/mcp`
  to sign in. With a token instead: add `--header "Authorization: Bearer fbk_..."`.
- **Codex** (`~/.codex/config.toml`): `[mcp_servers.family-box]` with `url = "https://box.example.org/mcp"`
  and `bearer_token_env_var = "FAMILYBOX_TOKEN"`.
- **Cursor** (`~/.cursor/mcp.json`): `"family-box": {"url": "https://box.example.org/mcp",
  "headers": {"Authorization": "Bearer fbk_..."}}`.

## Security notes

- **The person always comes from the token.** No tool argument, header or session id picks who is
  asking. Each person gets their own MCP server inside the box. A session started with Maya's token
  answers "not found" to Dana's token (tested).
- **What an assistant can get:** only `ask_family_box` answers, after the gate. It has no tool that
  lists or reads files. Held values still go only to the owner's Approvals page, never over MCP, and
  that page is not on the assistant-only listener a tunnel points at.
- **Linking needs the one-time code.** Codes are 8 characters from 31 letters and digits, single use,
  10 minutes. Wrong codes typed on the consent page have their own lockout
  (`<runtime>/web/remote_failures.json`, 5 wrong codes in 10 minutes), separate from the home sign-in.
  Someone on the internet can use it to stop assistants from **linking** for 10 minutes at a time
  (already linked assistants keep working), but never to lock the home sign-in or the Approvals page
  (tested). Three wrong codes on one sign-in request throw that request away.
- **One person per request.** The first family member to type a good code owns the request. A code
  for a different person throws the request away instead of switching who is linking.
- **Consent phishing:** an app picks its own name, so a fake "Claude" could send Maya a link. The
  consent page shows where it will send her back (`claude.ai` or not) and says to continue only if she
  started it herself, just now. This is the main human risk of open registration.
- **Stored only as hashes:** client secrets, authorization codes, access, refresh and API tokens
  (SHA-256 in `<runtime>/remote/state.json`, file 0600, folder 0700). A copy of that file shows who
  linked what, not a working credential.
- **Lifetimes:** consent request 10 minutes, code 5 minutes, access token 1 hour, refresh token 30 days
  from last use. Refresh tokens rotate on every use. An app that retries a refresh within 30 seconds
  (a timeout, or two at once) gets the same new pair back instead of being cut off. For those 30
  seconds the new pair is kept encrypted under a key made from the old refresh token, so `state.json`
  alone still holds no usable credential. If an old one comes back later, or after the new one was
  used, the box assumes it was copied and revokes the whole connection. Not yet tried with the real
  ChatGPT or Claude apps. A code used twice also revokes what it produced (RFC 6749
  section 10.5). A code that fails its PKCE or redirect check is burned.
- **Tokens are bound** to the app (client id), the person, and the box's `/mcp` address (RFC 8707). A
  linked assistant's token issued for one address is refused at another. A `resource` for some other
  server is refused. **API tokens are not bound to an address**: one works at any address that reaches
  the box, so treat it like a password.
- **Redirect addresses:** must be registered exactly. https anywhere, http only to this computer
  (localhost, for Claude Code and similar), and app links in reversed-domain form
  (`com.example.app:/callback`, RFC 8252 section 7.1) plus `cursor://`. Everything else is refused,
  including `javascript:`, `data:`, `file:`, `intent:`, `ms-*:`, `search-ms:` and plain http to other
  hosts.
- **No open redirect.** Anyone can register an app with any https address, so the box never sends a
  browser to an app's address by itself until a family member has signed in with a code. A bad
  `/authorize` request (wrong scope, wrong resource, box busy) shows an error page on the box instead
  of redirecting (RFC 9700 section 4.11.2). Cancel before a code is entered shows "Not linked" with a
  plain link that names where it goes.
- **Floods:** at most 200 registered apps, 50 waiting sign-in requests, and 3 waiting requests per
  app. An app that opens more pushes out only its own oldest request. Apps that are linked or partway
  through linking are never dropped to make room; only idle apps (never linked, no sign-in open) are.
  A sign-in that was open before a flood can still be finished (tested). When the box is full, new
  sign-ins are refused, so a big enough flood can still stop **new** assistants from linking for up to
  10 minutes. Linked assistants keep working. There is no per-address limit, because behind a tunnel
  every request comes from `127.0.0.1`.
- **The page itself:** the consent page can't be framed (`frame-ancestors 'none'`, `X-Frame-Options:
  DENY`), posts are same-origin only, responses are `no-store`, and no referrer is sent. The final step
  is a page that sends the browser back, because the page's `form-action 'self'` rule would block a
  form whose redirect leaves the box.
- **Not done yet:** the RFC 9207 `iss` parameter on the redirect, rate limits on `/register` and
  `/token` beyond the caps above, and a per-person switch to turn remote access off. The standalone
  `familybox-mcp --http` (one person, no sign-in, 127.0.0.1 only) is unchanged and must never be
  tunneled; the authenticated route is `familybox serve`'s `/mcp`.
- **Audit:** questions from remote assistants are logged with source `mcp-remote` and the
  `connection` id of the linked assistant or API token that asked, so after a leak the owner knows
  which one to revoke. The Assistants page shows "last asked" for each. The standalone
  `familybox-mcp --http` logs `mcp-http-local`. Linking, revoking and making tokens are logged in the
  person's audit file (`assistant_linked`, `assistant_revoked`, `api_token_made`), with no token
  values.

## What was tested

`uv run pytest -q tests/test_remote.py`, all in-process through httpx's ASGI transport against the
real web app, no network:

- the whole flow: metadata, registration, authorize, consent with a real sign-in code, token, then MCP
  `initialize`, `tools/list` and `tools/call` over HTTP (the answer comes back gated: Maya's health
  detail is held, not sent)
- the MCP SDK's own OAuth client discovering, registering, signing in and calling tools
- Maya's token can't act as Dana, and can't use Dana's session
- revocation from the CLI, the box page and `/revoke`; refresh rotation and reuse detection
- PKCE failure, plain PKCE refused, redirect mismatch at authorize and at token, code reuse,
  code and refresh tokens bound to their app, a token for another address, unsafe redirect URIs,
  wrong codes, denial, tampering and cross-site posts on the consent page, hashed storage, flood caps
- the assistant-only listener: `/signin`, `/approvals`, `/files`, `/upload`, `/cloud`, `/assistants`
  and the rest answer 404, and the whole link flow plus an MCP call work through it. Also run once
  for real: `familybox serve --port 18543 --remote-port 18544` on 127.0.0.1, where `/approvals` and
  `/signin` gave 404 on 18544 and the home page answered on 18543
- wrong consent codes never lock the home sign-in; 3 wrong codes burn one request; a second person
  can't take over a request; `/authorize` errors and Cancel never send the browser to the app's
  address; a sign-in opened before a flood still finishes; a refresh retried within 30 seconds gets the
  same pair; questions record which connection asked
