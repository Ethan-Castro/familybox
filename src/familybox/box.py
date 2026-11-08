"""One question, start to finish: who is asking, scoped tools, the enclave model, the gate, the log."""

from __future__ import annotations

import asyncio
import hashlib
import json
import time
from dataclasses import asdict, dataclass, field
from pathlib import Path

from . import access, enclave, gate
from .config import Config, Person
from .store import Store

REPO_REPLAYS = Path(__file__).resolve().parents[2] / "replays"


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

    def to_dict(self) -> dict:
        return asdict(self)


class Box:
    def __init__(self, cfg: Config, *, mode: str = "auto", replay_dir: Path | None = None):
        self.cfg = cfg
        self.store = Store(cfg)
        self.store.ensure_index()
        self.replay_dir = replay_dir or REPO_REPLAYS
        self.mode = mode  # live | replay | record | auto (live if a key is set, else replay)

    def _tools_for(self, person: Person, read_log: list[str], denied_log: list[str]):
        def run_tool(name: str, args: dict) -> str:
            if name == "search_files":
                return json.dumps(self.store.search(person, str(args.get("query", ""))) or [{"note": "no matches"}])
            if name == "read_file":
                path = str(args.get("path", ""))
                text = self.store.read(person, path)
                if text is None:
                    denied_log.append(path)
                    return json.dumps({"error": "not found or not yours to read"})
                read_log.append(path)
                return text
            return json.dumps({"error": f"unknown tool {name}"})
        return run_tool

    def ask(self, person_id: str, question: str) -> Answer:
        return asyncio.run(self.ask_async(person_id, question))

    async def ask_async(self, person_id: str, question: str) -> Answer:
        person = self.cfg.person(person_id)
        read_log: list[str] = []
        denied_log: list[str] = []
        run_tool = self._tools_for(person, read_log, denied_log)
        key = enclave.api_key()
        mode = self.mode if self.mode != "auto" else ("live" if key else "replay")
        try:
            if mode == "replay":
                draft = enclave.ask_replay(replay_dir=self.replay_dir, person=person_id, question=question,
                                           run_tool=run_tool)
            else:
                if not key:
                    raise enclave.EnclaveError("NEAR_AI_CLOUD_API_KEY is not set")
                draft = await enclave.ask_live(api_key=key, model=self.cfg.model, person_display=person.display,
                                               question=question, run_tool=run_tool,
                                               attestation_max_age_s=self.cfg.attestation_max_age_s)
                if mode == "record":
                    enclave.record(self.replay_dir, person_id, question, draft)
        except enclave.EnclaveError as e:
            ans = Answer(person_id, question, f"The family box could not get a verified answer ({e}). "
                         "Nothing was answered.", "error", [str(e)], files_read=read_log, files_denied=denied_log)
            self._audit(ans)
            return ans

        owners = set(access.readable_owners(self.cfg, person))
        file_owners = {access.owner_of(p) for p in read_log} - {None}
        never = list(person.never_share) + [t for o in file_owners for t in self.cfg.people[o].never_share
                                            if o in self.cfg.people]
        result = gate.check(draft.answer, sensitive=self.store.sensitive_values(), readable_owners=owners,
                            never_share=never, display={p.id: p.display for p in self.cfg.people.values()},
                            common_words=self.store.nonhealth_words())
        ans = Answer(person_id, question, result.text, result.outcome, result.reasons,
                     files_read=read_log, files_denied=denied_log,
                     enclave={"model": draft.model, "replayed": draft.replayed, "attestation": draft.attestation,
                              "turns": len(draft.turns),
                              "signatures": sorted({t.signature_kind for t in draft.turns}),
                              "signer": draft.turns[-1].signer if draft.turns else None,
                              "tokens": [draft.tokens_in, draft.tokens_out]})
        if result.outcome == "held":
            from .approvals import Approvals
            ans.held_ids = Approvals(self.cfg).add(person_id, question, result.held)
        self._audit(ans)
        return ans

    def _audit(self, ans: Answer) -> None:
        log = self.cfg.runtime / "audit" / f"{ans.person}.jsonl"
        log.parent.mkdir(parents=True, exist_ok=True)
        entry = {
            "time": int(time.time()),
            "question_sha256": hashlib.sha256(ans.question.encode()).hexdigest(),
            "outcome": ans.outcome,
            "reasons": ans.reasons,
            "files_read": ans.files_read,
            "files_denied": ans.files_denied,
            "sent_to_assistant": ans.text,
            "held_ids": ans.held_ids,
            "enclave": ans.enclave,
        }
        with log.open("a") as f:
            f.write(json.dumps(entry) + "\n")
