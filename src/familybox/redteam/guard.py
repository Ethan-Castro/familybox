"""Per-question tool limits on a red-team demo home, and the worst-case cost of one live attempt.

The enclave loop already caps each question at enclave.MAX_TURNS turns of at most MAX_OUT_PER_TURN
output tokens. Input tokens grow with tool results, so on a red-team home every question also gets
at most MAX_TOOL_CALLS tool runs and each result is cut to MAX_RESULT_JSON characters once JSON
encoded. With those limits one attempt has a fixed upper bound, and the spending guard reserves that
bound before every live call.
"""

from __future__ import annotations

import json

from .. import enclave

MAX_TOOL_CALLS = 12
MAX_RESULT_JSON = 3000          # characters of json.dumps(result); the largest demo file fits
MAX_OUT_PER_TURN = 900          # enclave.ask_live sends max_tokens=900
CUT_NOTE = " [cut: tool results are limited on the red-team box]"

# Bound assumptions, in tokens. A token is at least one byte for a byte-level tokenizer, so a byte
# count bounds the token count. BASE covers the system prompt, tool schemas and a question of
# max_question_chars at 4 bytes per character. PER_TURN_HISTORY covers the "Tool calls: ..." text
# replayed each turn plus short error results for refused calls (about 4 bytes per output token,
# doubled for JSON escaping, rounded up).
BASE_OVERHEAD = 2000
PER_TURN_HISTORY = 8000
RESULT_WRAPPER = 100            # {"tool": ..., "arguments": ..., "result": ...} around each result
TEMPLATE_ROOM = 400             # chat template tokens and the person's name, inside BASE_OVERHEAD

NOT_COVERED = ("this red-team box has an extra add-on (a tool, or a check that can call a model) that its "
               "spending limit does not cover, so it will not answer")


def worst_case_tokens(max_question_chars: int) -> tuple[int, int]:
    """(input, output) token upper bound for one live attempt under the limits above."""
    turns = enclave.MAX_TURNS
    base = BASE_OVERHEAD + 4 * max_question_chars
    results = MAX_TOOL_CALLS * (MAX_RESULT_JSON + RESULT_WRAPPER)
    # turn t (0-based) re-sends the base, t turns of history, and every tool result so far (<= all)
    tokens_in = turns * (base + results) + PER_TURN_HISTORY * (turns * (turns - 1) // 2)
    tokens_out = turns * MAX_OUT_PER_TURN
    return tokens_in, tokens_out


def worst_case_usd(max_question_chars: int, price_in_per_m: float, price_out_per_m: float) -> float:
    tin, tout = worst_case_tokens(max_question_chars)
    return cost_usd(tin, tout, price_in_per_m, price_out_per_m)


def cost_usd(tokens_in: int, tokens_out: int, price_in_per_m: float, price_out_per_m: float) -> float:
    return (tokens_in * price_in_per_m + tokens_out * price_out_per_m) / 1_000_000


def cut(text: str, limit: int = MAX_RESULT_JSON) -> str:
    """Shorten text until json.dumps(text) fits in limit characters."""
    if len(json.dumps(text)) <= limit:
        return text
    budget = limit - len(json.dumps(CUT_NOTE))
    s = text
    while s and len(json.dumps(s)) > budget:
        s = s[: max(0, min(len(s) - 1, int(len(s) * 0.9)))]
    return s + CUT_NOTE


def base_bytes(box) -> int:
    """Bytes of the system prompt plus every tool schema the model is offered on this box."""
    people = list(box.cfg.people.values())
    tools = max((len(json.dumps(box.tools_for(p)).encode()) for p in people), default=0)
    return len(enclave.SYSTEM_PROMPT.encode()) + tools


def check_composition(box) -> None:
    """Raise enclave.EnclaveError unless the box has only the parts the worst-case bound covers.

    That is: ToolLimit first, then the built-in FileTools, no other tool provider, no post-check, and no
    pre-check except this module's own and the NEAR code check's (familybox.plugins.pinning, which only
    reads local pin files and adds verifiers, never tokens). Anything else (a plugin with more tools, a
    second model call, a code sandbox) would break worst_case_tokens(), so a red-team box refuses to run
    with it. The second privacy check and the workbench stay off on a red-team home by themselves
    (they look at familybox.redteam.home.settings_for in register()).
    """
    from ..box import FileTools
    tp = box.tool_providers
    pre = box.pre_checks
    ok = (len(tp) == 2 and type(tp[0]) is ToolLimit and tp[0].box is box and type(tp[1]) is FileTools
          and not box.post_checks and bool(pre) and pre[0] is composition_pre_check
          and all(_is_pin_check(c) for c in pre[1:])
          and base_bytes(box) <= BASE_OVERHEAD - TEMPLATE_ROOM)
    if not ok:
        raise enclave.EnclaveError(NOT_COVERED)


def _is_pin_check(check) -> bool:
    """The NEAR code check's own pre-check: it calls no model, so it costs nothing the bound must cover."""
    try:
        from ..plugins import pinning
    except Exception:  # noqa: BLE001 - if it cannot load, nothing can be it
        return False
    return check is pinning.pre_check


async def composition_pre_check(box, person, question, ctx) -> None:
    """Pre-check on a red-team box: stop the question unless check_composition() passes."""
    check_composition(box)


def install(box) -> None:
    """Called from the plugin's register(): the tool limit goes first, and the composition check runs."""
    box.tool_providers.insert(0, ToolLimit(box))
    box.pre_checks.insert(0, composition_pre_check)


class ToolLimit:
    """First tool provider on a red-team box. Offers no tools of its own; it counts and trims."""

    def __init__(self, box):
        self.box = box

    def tools(self, person) -> list[dict]:
        return []

    def run(self, person, name: str, args: dict, ctx) -> str | None:
        n = ctx.data.get("redteam_tool_calls", 0) + 1
        ctx.data["redteam_tool_calls"] = n
        if n > MAX_TOOL_CALLS:
            return json.dumps({"error": "tool limit reached for this question; answer with what you have"})
        for p in self.box.tool_providers:
            if p is self:
                continue
            out = p.run(person, name, args, ctx)
            if out is not None:
                return cut(out)
        return None
