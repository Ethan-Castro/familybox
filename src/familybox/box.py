"""One question, start to finish: who is asking, scoped tools, the enclave model, the gate, the log.

Extension points (filled by plugins in familybox/plugins/ through register(box)):

  box.tool_providers: list of objects with
      tools(person) -> list[dict]                        OpenAI tool dicts offered to the model
      run(person, name, args, ctx) -> str | None         sync; None means "not my tool"
  box.pre_checks:  list of async fn(box, person, question, ctx) -> None
      Raise enclave.EnclaveError to stop the question before the model sees it (any error stops it too).
  box.post_checks: list of async fn(box, person, question, draft, result, ctx) -> None
      result is the gate.GateResult. Change it in place: result.bump("held" | "refused", reason),
      result.held.append(gate.Held(...)), or result.text = ... . Any error stops the question.

ctx is a Question: qid, person, question, source, started, files_read, files_denied, data (a scratch
dict for plugins), events, and emit(step, **data) which appends one JSON line to
<runtime>/events/<person>/<qid>.jsonl. Known protected values are scrubbed from every event.
A tool run that adds to ctx.files_denied is recorded as a refused step (ok false, denied true).
"""

from __future__ import annotations

import asyncio
import hashlib
import inspect
import json
import logging
import re
import secrets
import time
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any

from . import access, enclave, gate
from .config import Config, Person
from .store import Sensitive, Store

REPO_REPLAYS = Path(__file__).resolve().parents[2] / "replays"
log = logging.getLogger("familybox.box")


@dataclass
class Answer:
    person: str
    question: str
    text: str
    outcome: str                      # pass | masked | held | refused | error
    reasons: list[str] = field(default_factory=list)
    held_ids: list[str] = field(default_factory=list)
    files_read: list[str] = field(default_factory=list)
    files_denied: list[str] = field(default_factory=list)
    enclave: dict = field(default_factory=dict)
    qid: str = ""
    source: str = ""

    def to_dict(self) -> dict:
        return asdict(self)


QID_RE = re.compile(r"[0-9a-f]{12}")


def new_qid() -> str:
    return secrets.token_hex(6)


class Question:
    """Per-question context handed to tool providers, checks and the enclave's emit callback."""

    def __init__(self, box: Box, person: Person, question: str, source: str, qid: str | None = None):
        self.box = box
        self.qid = qid or new_qid()
        self.person = person
        self.question = question
        self.source = source
        self.started = time.time()
        self.files_read: list[str] = []
        self.files_denied: list[str] = []
        self.data: dict[str, Any] = {}
        self.events: list[dict] = []
        self._scrub: list[Sensitive] | None = None

    @property
    def events_path(self) -> Path:
        return self.box.cfg.runtime / "events" / self.person.id / f"{self.qid}.jsonl"

    def _scrub_value(self, v):
        if isinstance(v, str):
            if self._scrub is None:
                self._scrub = [s for s in self.box.store.sensitive_values()
                               if len(gate.normalize(s.value)) >= (8 if s.kind == "health" else 4)]
            for s in self._scrub:
                v = gate.loose_pattern(s.value).sub("[protected]", v)
            return v
        if isinstance(v, dict):
            return {k: self._scrub_value(x) for k, x in v.items()}
        if isinstance(v, (list, tuple)):
            return [self._scrub_value(x) for x in v]
        return v

    def emit(self, step: str, **data) -> dict:
        """Record one step. Never pass file text or answer text; protected values are scrubbed anyway."""
        event = {"qid": self.qid, "t": round(time.time() - self.started, 3), "step": step,
                 **self._scrub_value(data)}
        self.events.append(event)
        path = self.events_path
        path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
        with path.open("a") as f:
            f.write(json.dumps(event, default=str) + "\n")
        return event


class FileTools:
    """The built-in tools: search and read only the files this person may read."""

    def __init__(self, store: Store):
        self.store = store

    def tools(self, person: Person) -> list[dict]:
        return list(enclave.TOOLS)

    def run(self, person: Person, name: str, args: dict, ctx: Question) -> str | None:
        if name == "search_files":
            return json.dumps(self.store.search(person, str(args.get("query", ""))) or [{"note": "no matches"}])
        if name == "read_file":
            path = str(args.get("path", ""))
            text = self.store.read(person, path)
            if text is None:
                ctx.files_denied.append(path)
                return json.dumps({"error": "not found or not yours to read"})
            ctx.files_read.append(path)
            return text
        return None


async def _maybe_await(x):
    return await x if inspect.isawaitable(x) else x


class Box:
    def __init__(self, cfg: Config, *, mode: str = "auto", replay_dir: Path | None = None):
        self.cfg = cfg
        self.store = Store(cfg)
        self.store.ensure_index()
        self.replay_dir = replay_dir or REPO_REPLAYS
        self.mode = mode  # live | replay | record | auto (live if a key is set, else replay)
        self.tool_providers: list = [FileTools(self.store)]
        self.pre_checks: list = []
        self.post_checks: list = []
        from . import plugins
        plugins.call_each("register", self)

    # ---- tools

    def tools_for(self, person: Person) -> list[dict]:
        """Union of every provider's tools for this person. The first provider to offer a name wins."""
        seen: dict[str, dict] = {}
        for p in self.tool_providers:
            for t in p.tools(person) or []:
                name = t.get("function", {}).get("name")
                if name and name not in seen:
                    seen[name] = t
        return list(seen.values())

    def run_tool(self, person: Person, name: str, args: dict, ctx: Question, offered: set[str]) -> str:
        if name not in offered:
            ctx.emit("tool", name=name, arguments=args, ok=False, why="not offered")
            return json.dumps({"error": f"unknown tool {name}"})
        for p in self.tool_providers:
            denied_before = len(ctx.files_denied)
            try:
                out = p.run(person, name, args, ctx)
            except Exception as e:  # noqa: BLE001 - a broken tool gives the model an error, not a crash
                log.exception("tool %s failed", name)
                ctx.emit("tool", name=name, arguments=args, ok=False, why=type(e).__name__)
                return json.dumps({"error": f"the {name} tool failed"})
            if out is not None:
                if len(ctx.files_denied) > denied_before:   # a refused read: say so in the event itself
                    ctx.emit("tool", name=name, arguments=args, ok=False, denied=True, why="not yours",
                             provider=type(p).__name__)
                else:
                    ctx.emit("tool", name=name, arguments=args, ok=True, provider=type(p).__name__)
                return out
        ctx.emit("tool", name=name, arguments=args, ok=False, why="no provider")
        return json.dumps({"error": f"unknown tool {name}"})

    # ---- asking

    def ask(self, person_id: str, question: str, *, source: str = "cli", qid: str | None = None) -> Answer:
        return asyncio.run(self.ask_async(person_id, question, source=source, qid=qid))

    async def ask_async(self, person_id: str, question: str, *, source: str = "cli",
                        qid: str | None = None) -> Answer:
        """qid: optional id chosen by the caller (12 lowercase hex characters), so a web page can
        point at the question's events before it finishes."""
        if qid is not None and not QID_RE.fullmatch(qid):
            raise ValueError("qid must be 12 lowercase hex characters")
        person = self.cfg.person(person_id)
        ctx = Question(self, person, question, source, qid)
        key = enclave.api_key()
        mode = self.mode if self.mode != "auto" else ("live" if key else "replay")
        ctx.emit("question", source=source, mode=mode, chars=len(question))

        def stopped(why: str, step: str) -> Answer:
            ctx.emit(step, message=why)
            return self._finish(ctx, Answer(person_id, question, f"The family box stopped this question "
                                            f"({why}). Nothing was answered.", "error", [why]))

        try:
            for chk in self.pre_checks:
                await _maybe_await(chk(self, person, question, ctx))
        except enclave.EnclaveError as e:
            return stopped(str(e), "pre_check_stopped")
        except Exception as e:  # noqa: BLE001 - a broken check fails closed
            log.exception("pre_check failed")
            return stopped(f"a safety check failed: {type(e).__name__}", "pre_check_stopped")

        tools = self.tools_for(person)
        offered = {t["function"]["name"] for t in tools}

        def run_tool(name: str, args: dict) -> str:
            return self.run_tool(person, name, args, ctx, offered)

        try:
            if mode == "replay":
                draft = enclave.ask_replay(replay_dir=self.replay_dir, person=person_id, question=question,
                                           run_tool=run_tool, emit=ctx.emit)
            else:
                if not key:
                    ctx.emit("error", message="NEAR_AI_CLOUD_API_KEY is not set")
                    raise enclave.EnclaveError("NEAR_AI_CLOUD_API_KEY is not set")
                draft = await enclave.ask_live(api_key=key, model=self.cfg.model, person_display=person.display,
                                               question=question, run_tool=run_tool, tools=tools, emit=ctx.emit,
                                               attestation_max_age_s=self.cfg.attestation_max_age_s)
                if mode == "record":
                    enclave.record(self.replay_dir, person_id, question, draft)
        except enclave.EnclaveError as e:
            return self._finish(ctx, Answer(person_id, question, f"The family box could not get a verified answer "
                                            f"({e}). Nothing was answered.", "error", [str(e)]))

        owners = set(access.readable_owners(self.cfg, person))
        file_owners = {access.owner_of(p) for p in ctx.files_read} - {None}
        never = list(person.never_share) + [t for o in file_owners for t in self.cfg.people[o].never_share
                                            if o in self.cfg.people]
        result = gate.check(draft.answer, sensitive=self.store.sensitive_values(), readable_owners=owners,
                            never_share=never, display={p.id: p.display for p in self.cfg.people.values()},
                            common_words=self.store.nonhealth_words())
        ctx.emit("gate", outcome=result.outcome, held=_held_summary(result.held), reasons=len(result.reasons))

        if self.post_checks:
            text_before = result.text
            try:
                for chk in self.post_checks:
                    await _maybe_await(chk(self, person, question, draft, result, ctx))
            except Exception as e:  # noqa: BLE001 - EnclaveError or a broken check: nothing is sent
                log.exception("post_check failed")
                why = str(e) if isinstance(e, enclave.EnclaveError) else f"a safety check failed: {type(e).__name__}"
                return stopped(why, "post_check_stopped")
            if result.outcome == "refused" and result.text == text_before and text_before != gate.REFUSED_TEXT:
                result.text = gate.REFUSED_TEXT
            ctx.emit("post_checks", outcome=result.outcome, held=_held_summary(result.held),
                     reasons=len(result.reasons))

        ans = Answer(person_id, question, result.text, result.outcome, result.reasons,
                     enclave={"model": draft.model, "replayed": draft.replayed, "attestation": draft.attestation,
                              "turns": len(draft.turns),
                              "signatures": sorted({t.signature_kind for t in draft.turns}),
                              "signer": draft.turns[-1].signer if draft.turns else None,
                              "tokens": [draft.tokens_in, draft.tokens_out]})
        if result.outcome == "held":
            from .approvals import Approvals
            ans.held_ids = Approvals(self.cfg).add(person_id, question, result.held)
        return self._finish(ctx, ans)

    def _finish(self, ctx: Question, ans: Answer) -> Answer:
        ans.qid, ans.source = ctx.qid, ctx.source
        ans.files_read, ans.files_denied = ctx.files_read, ctx.files_denied
        ctx.emit("answer", outcome=ans.outcome, held=len(ans.held_ids), files_read=len(ans.files_read),
                 files_denied=len(ans.files_denied), seconds=round(time.time() - ctx.started, 2))
        self._audit(ans)
        return ans

    def _audit(self, ans: Answer) -> None:
        log_path = self.cfg.runtime / "audit" / f"{ans.person}.jsonl"
        log_path.parent.mkdir(parents=True, exist_ok=True)
        entry = {
            "time": int(time.time()),
            "qid": ans.qid,
            "source": ans.source,
            "question_sha256": hashlib.sha256(ans.question.encode()).hexdigest(),
            "outcome": ans.outcome,
            "reasons": ans.reasons,
            "files_read": ans.files_read,
            "files_denied": ans.files_denied,
            "sent_to_assistant": ans.text,
            "held_ids": ans.held_ids,
            "enclave": ans.enclave,
        }
        with log_path.open("a") as f:
            f.write(json.dumps(entry) + "\n")


def _held_summary(held: list[gate.Held]) -> list[dict]:
    return [{"kind": h.kind, "label": h.label, "owner": h.owner, "path": h.path} for h in held]
