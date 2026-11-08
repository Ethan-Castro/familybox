"""Held values wait here for their owner. Approving shows the full value on the owner's own screen
(the box's local page or CLI); it is never sent back to the assistant that asked."""

from __future__ import annotations

import json
import time
from pathlib import Path

from .config import Config
from .gate import Held


class Approvals:
    def __init__(self, cfg: Config):
        self.path: Path = cfg.runtime / "approvals.json"

    def _load(self) -> dict:
        return json.loads(self.path.read_text()) if self.path.exists() else {}

    def _save(self, data: dict) -> None:
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self.path.write_text(json.dumps(data, indent=1))

    def add(self, asker: str, question: str, held: list[Held]) -> list[str]:
        data = self._load()
        for h in held:
            data[h.id] = {"asker": asker, "question": question, "kind": h.kind, "label": h.label,
                          "owner": h.owner, "path": h.path, "value": h.value, "status": "waiting",
                          "created": int(time.time())}
        self._save(data)
        return [h.id for h in held]

    def pending(self, owner: str) -> list[dict]:
        return [{"id": k} | {f: v[f] for f in ("asker", "question", "kind", "label", "path", "status")}
                for k, v in self._load().items() if v["owner"] == owner and v["status"] == "waiting"]

    def decide(self, owner: str, item_id: str, approve: bool) -> dict:
        data = self._load()
        item = data.get(item_id)
        if not item or item["owner"] != owner:
            raise KeyError("no such item for this owner")
        item["status"] = "approved" if approve else "denied"
        item["decided"] = int(time.time())
        self._save(data)
        # The value is returned to the owner's own screen only.
        return {"id": item_id, "label": item["label"], "value": item["value"] if approve else None,
                "asker": item["asker"]}
