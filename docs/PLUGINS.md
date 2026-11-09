# Plugins: how features plug into the box

Each feature is one module in `src/familybox/plugins/` (names starting with `_` are skipped). The box, the
web page, the MCP server and the CLI all load every module there. A module that fails to import, or a
loading hook that raises, is logged and skipped. Answer checks are the exception: once registered, an
error inside a pre or post check stops the question and nothing is answered.

## Hooks a plugin module may define

```python
def register(box) -> None                      # end of Box.__init__
def cli(subparsers) -> None                    # add argparse subcommands to `familybox`
def run_cli(args, cfg) -> int | None           # None when args.cmd is not yours
def web_routes(ctx) -> list                    # Starlette Route/Mount list (added after core routes)
def web_nav() -> list[tuple[str, str]]         # (label, path) links for the box page nav bar
def mcp_tools(server, person, box) -> None     # add tools with @server.tool(...)
```

## Inside register(box)

```python
box.tool_providers.append(provider)   # provider.tools(person) -> list[openai tool dict]
                                      # provider.run(person, name, args, ctx) -> str | None  (sync; None = not mine)
box.pre_checks.append(fn)             # async fn(box, person, question, ctx) -> None
                                      #   raise enclave.EnclaveError("why") to stop the question
box.post_checks.append(fn)            # async fn(box, person, question, draft, result, ctx) -> None
                                      #   result is gate.GateResult: result.bump("held"|"refused", reason),
                                      #   result.held.append(gate.Held(...)), result.text = ...
```

The model is offered the union of every provider's tools (the built-in `search_files` and `read_file`
come first; the first provider to offer a name wins). A tool the model was not offered is refused. A
provider that raises gives the model an error result. If a post check bumps to refused without changing
the text, the box replaces the text with the standard blocked message.

## The per-question ctx (familybox.box.Question)

`ctx.qid` (12 hex chars), `ctx.person`, `ctx.question`, `ctx.source` ("cli", "mcp-stdio", "mcp-http-local", "mcp-remote",
"web"), `ctx.started`, `ctx.files_read`, `ctx.files_denied`, `ctx.data` (scratch dict), `ctx.events`,
and `ctx.emit(step, **data)`, which appends one JSON line to `<runtime>/events/<person>/<qid>.jsonl`.
Never pass file text or answer text to emit. Known protected values are scrubbed from every event anyway.

Steps the core emits: `question`, `attestation`, `turn`, `tool`, `error`, `pre_check_stopped`, `gate`,
`post_checks`, `post_check_stopped`, `answer`. Attestation and turn events carry `replayed`.

## Web ctx (familybox.web.WebContext)

`cfg`, `session_of(request)`, `page(sess, title, body, here="", status=200)`, `need_signin(handler)`,
`guarded_form(request, **form_kw)` (returns `(sess, form)` or a 403 response), `csrf_field(token)`,
`forbidden(msg)`, `esc(text)`, `box()` (a shared Box, made on first use).

Tests can register a plugin at runtime with `monkeypatch.setattr(familybox.plugins, "EXTRA", [module])`.
See `tests/test_plugins.py`.
