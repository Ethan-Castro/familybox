"""Feature plugins. Every module in this package is loaded by the box, the web page, MCP and the CLI.

Drop a file in src/familybox/plugins/ (names starting with "_" are skipped). A plugin module MAY define:

  register(box) -> None
      Called at the end of Box.__init__. Use it to add to box.tool_providers, box.pre_checks
      and box.post_checks (see familybox.box for the exact shapes).

  cli(subparsers) -> None
      Add argparse subcommands to the `familybox` command.
  run_cli(args, cfg) -> int | None
      Run a subcommand. Return None when args.cmd is not yours.

  web_routes(ctx) -> list[Route | Mount]
      Starlette routes for the box's web page. ctx is a familybox.web.WebContext.
  web_nav() -> list[tuple[str, str]]
      (label, path) links added to the web page's nav bar.

  mcp_tools(server, person, box) -> None
      Add MCP tools with @server.tool(...). person is the config.Person this connection asks as.

A plugin that fails to import, or whose hook raises while loading, is logged and skipped, so one
broken feature never takes the box down. Checks that guard answers (pre_checks, post_checks) are
different: once registered, an error inside them stops the question (fail closed).
"""

from __future__ import annotations

import importlib
import logging
import pkgutil
from types import ModuleType

log = logging.getLogger("familybox.plugins")

# Extra plugin modules added at runtime (tests, or a host program). load_plugins() returns them too.
EXTRA: list[ModuleType] = []


def load_plugins() -> list[ModuleType]:
    """Import every plugin module in this package, plus EXTRA. Import errors are logged and skipped."""
    mods: list[ModuleType] = []
    for info in sorted(pkgutil.iter_modules(__path__), key=lambda i: i.name):
        if info.name.startswith("_"):
            continue
        try:
            mods.append(importlib.import_module(f"{__name__}.{info.name}"))
        except Exception:  # noqa: BLE001 - a broken plugin is skipped, never fatal
            log.exception("plugin %s failed to import; skipped", info.name)
    for m in EXTRA:
        if m not in mods:
            mods.append(m)
    return mods


def call_each(hook: str, *args) -> list:
    """Call hook(*args) on every plugin that defines it. Errors are logged and skipped."""
    out = []
    for m in load_plugins():
        fn = getattr(m, hook, None)
        if fn is None:
            continue
        try:
            out.append(fn(*args))
        except Exception:  # noqa: BLE001
            log.exception("plugin %s hook %s failed; skipped", m.__name__, hook)
    return out
