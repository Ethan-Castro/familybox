# Remote MCP: using the box from ChatGPT and Claude on the web

ChatGPT and Claude (web, desktop and phone) can add a "custom connector": an MCP server they reach
over the internet. The box's own web page (`familybox serve`) now is one. It speaks streamable HTTP
MCP at `/mcp` and runs its own sign-in, so no outside account service is involved.

**Status:** built and tested in-process (see "What was tested"). It has **not** been exposed to the
internet or tried with the real ChatGPT or Claude apps yet. Opening it to the internet needs Ethan's
OK first. The steps are below, and nothing here has been run.

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

Run all of this **on the Pi**, never from the laptop. The box keeps listening only on `127.0.0.1:8443`;
the tunnel program on the Pi connects to it from the inside, so no port is opened on the home router.

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
    service: https://localhost:8443
    originRequest:
      originServerName: localhost          # the box's self-signed cert names localhost
      caPool: /path/to/familybox/runtime/tls/cert.pem
  - service: http_status:404
EOF
FAMILYBOX_PUBLIC_URL=https://box.example.org uv run familybox serve &
cloudflared tunnel run familybox
```

`caPool` pins the box's own certificate, so the tunnel checks it instead of skipping the check
(`noTLSVerify`). Do not add Cloudflare Access in front of `/mcp`: ChatGPT and Claude can't pass it.
Access can still guard every other path (the upload page) if Ethan wants the LAN-only page to stay
off the internet; see "Exposing only what's needed".

### Option B: Tailscale Funnel (no domain needed)

```bash
# on the Pi, already on the tailnet
sudo tailscale funnel --bg https+insecure://localhost:8443
tailscale funnel status                    # shows https://decision-tree.<tailnet>.ts.net
FAMILYBOX_PUBLIC_URL=https://decision-tree.<tailnet>.ts.net uv run familybox serve
```

`https+insecure` means Tailscale does not check the box's self-signed certificate on the hop inside
the Pi. That hop never leaves the Pi, but Option A's pinned certificate is stricter.

### Option C: Ethan's Base relay

The relay already forwards MCP for ChatGPT and Claude web. It would forward `https://<relay>/...` to
the box's `https://localhost:8443`, passing through `/mcp`, `/.well-known/*`, `/register`,
`/authorize*`, `/token` and `/revoke`, and set `FAMILYBOX_PUBLIC_URL` to the relay address. The exact
steps depend on the relay's config, which is not in this repo. Ethan to fill in.

### Exposing only what's needed

The internet only needs these paths: `/mcp`, `/.well-known/oauth-protected-resource*`,
`/.well-known/oauth-authorization-server*`, `/register`, `/authorize`, `/authorize/consent`, `/token`,
`/revoke`, and `/static/style.css` (the consent page's look). Everything else (sign-in, upload, files,
approvals, cloud, assistants) can stay LAN only with a tunnel rule that returns 404 for other paths.

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
  lists or reads files. Held values still go only to the owner's Approvals page, never over MCP.
- **Linking needs the one-time code.** Codes are 8 characters from 31 letters and digits, single use,
  10 minutes, and share the web page's lockout (5 wrong codes in 10 minutes locks sign-in). Someone on
  the internet could use that lockout to stop sign-ins for 10 minutes at a time; they can't get in.
- **Consent phishing:** an app picks its own name, so a fake "Claude" could send Maya a link. The
  consent page shows where it will send her back (`claude.ai` or not) and says to continue only if she
  started it herself, just now. This is the main human risk of open registration.
- **Stored only as hashes:** client secrets, authorization codes, access, refresh and API tokens
  (SHA-256 in `<runtime>/remote/state.json`, file 0600, folder 0700). A copy of that file shows who
  linked what, not a working credential.
- **Lifetimes:** consent request 10 minutes, code 5 minutes, access token 1 hour, refresh token 30 days
  from last use. Refresh tokens rotate on every use. If an old one comes back, the box assumes it was
  copied and revokes the whole connection. A code used twice also revokes what it produced (RFC 6749
  section 10.5). A code that fails its PKCE or redirect check is burned.
- **Tokens are bound** to the app (client id), the person, and the box's `/mcp` address (RFC 8707). A
  token issued for one address is refused at another. A `resource` for some other server is refused.
- **Redirect addresses:** must be registered exactly. https anywhere, http only to this computer
  (localhost, for Claude Code and similar), and app links like `cursor://`. `javascript:`, `data:`,
  `file:` and plain http to other hosts are refused. The box never redirects to an address it doesn't
  know.
- **Floods:** at most 200 registered apps and 50 waiting sign-in requests. When full, the oldest that
  never linked to anyone are dropped first, so spam can't push out a real assistant.
- **The page itself:** the consent page can't be framed (`frame-ancestors 'none'`, `X-Frame-Options:
  DENY`), posts are same-origin only, responses are `no-store`, and no referrer is sent. The final step
  is a page that sends the browser back, because the page's `form-action 'self'` rule would block a
  form whose redirect leaves the box.
- **Not done yet:** the RFC 9207 `iss` parameter on the redirect, rate limits on `/register` and
  `/token` beyond the caps above, and a per-person switch to turn remote access off. The standalone
  `familybox-mcp --http` (one person, no sign-in, 127.0.0.1 only) is unchanged and must never be
  tunneled; the authenticated route is `familybox serve`'s `/mcp`.
- **Audit:** questions from remote assistants are logged with source `mcp-remote`. Linking, revoking
  and making tokens are logged in the person's audit file (`assistant_linked`, `assistant_revoked`,
  `api_token_made`), with no token values.

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
