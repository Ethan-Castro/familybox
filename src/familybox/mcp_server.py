"""MCP server: lets ChatGPT, Claude, Codex or Cursor ask the family box questions.

Each family member's assistant gets its own connection, configured with FAMILYBOX_PERSON
(stdio) so the box always knows who is asking. The assistant only ever receives the gated
answer; it has no tool that lists, searches or reads files directly.

  FAMILYBOX_HOME=demo FAMILYBOX_PERSON=maya familybox-mcp            # stdio
  FAMILYBOX_PERSON=maya familybox-mcp --http --port 8790             # streamable HTTP on 127.0.0.1
                                                                     # (no sign-in, logged as mcp-http-local)
"""

from __future__ import annotations

import argparse
import os
import sys
from typing import Annotated

from mcp.server.mcpserver import Context, MCPServer
from pydantic import Field

from . import config
from .box import Box

INSTRUCTIONS = """The family box holds this household's private documents: IDs, tax forms, insurance,
health records, school and home paperwork. You cannot see the documents. Ask the box a question in
plain language with ask_family_box and it answers using only the files this person may read.
Answers are checked before you receive them: full Social Security numbers, ID numbers and health
details are replaced with placeholders, and the full value is shown only on the owner's own device
after they approve. Do not ask for full identifiers; ask for what you need them for instead."""


def connection_of(ctx) -> str:
    """The remote connection id (set by familybox.remote.McpGateway on the HTTP request), else ""."""
    try:
        req = ctx.request_context.request
    except (ValueError, AttributeError):
        return ""
    scope = getattr(req, "scope", None) or {}
    return str(scope.get("familybox_connection", ""))[:40]


def build_server(person_id: str, mode: str = "auto", source: str = "mcp-stdio", *,
                 cfg: config.Config | None = None, box: Box | None = None) -> MCPServer:
    """cfg and box default to FAMILYBOX_HOME and a new Box; the remote /mcp route passes the web app's own."""
    cfg = cfg or config.load()
    person = cfg.person(person_id)
    box = box or Box(cfg, mode=mode)
    server = MCPServer(name="family-box", title=f"{cfg.name} ({person.display})",
                       instructions=INSTRUCTIONS, version="0.1.0", log_level="WARNING")

    @server.tool(name="ask_family_box", title="Ask the family box",
                 description="Ask a question about the family's documents. Returns a checked answer plus "
                             "how it was produced (verified enclave model, files read, what the box held back).")
    async def ask_family_box(
        question: Annotated[str, Field(min_length=3, max_length=2000,
                                       description="The question, in plain language.")],
        ctx: Context,
    ) -> str:
        ans = await box.ask_async(person.id, question, source=source, connection=connection_of(ctx))
        e = ans.enclave or {}
        lines = [ans.text, "", "---"]
        if ans.outcome == "error":
            lines.append("Not answered: the box could not verify the NEAR enclave, so nothing was sent.")
        else:
            lines.append(f"Answered for {person.display} by {e.get('model')} inside a verified NEAR AI enclave "
                         f"({e.get('turns')} encrypted turns, every reply enclave-signed"
                         f"{', replayed from a recording' if e.get('replayed') else ''}).")
            lines.append(f"Files read: {len(ans.files_read)}. Box check: {ans.outcome}.")
            if ans.held_ids:
                lines.append(f"{len(ans.held_ids)} detail(s) held for the owner's approval on their own device.")
        return "\n".join(lines)

    @server.tool(name="family_box_status", title="Family box status",
                 description="Who this connection asks as, and whether the box can reach a verified enclave.")
    async def family_box_status() -> str:
        from . import enclave
        live = bool(enclave.api_key()) and mode != "replay"
        return (f"Connected to {cfg.name} as {person.display}. Model: {cfg.model}. "
                f"Mode: {'live NEAR AI enclave' if live else 'replay (recorded demo answers)'}.")

    from . import plugins
    plugins.call_each("mcp_tools", server, person, box)
    return server


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(prog="familybox-mcp")
    ap.add_argument("--person", default=os.environ.get("FAMILYBOX_PERSON"))
    ap.add_argument("--mode", choices=["auto", "live", "replay"], default=os.environ.get("FAMILYBOX_MODE", "auto"))
    ap.add_argument("--http", action="store_true")
    ap.add_argument("--port", type=int, default=8790)
    args = ap.parse_args(argv)
    if not args.person:
        print("Set FAMILYBOX_PERSON or --person (who this assistant asks as).", file=sys.stderr)
        return 2
    server = build_server(args.person, args.mode, source="mcp-http-local" if args.http else "mcp-stdio")
    if args.http:
        server.run("streamable-http", host="127.0.0.1", port=args.port)
    else:
        server.run("stdio")
    return 0


if __name__ == "__main__":
    sys.exit(main())
