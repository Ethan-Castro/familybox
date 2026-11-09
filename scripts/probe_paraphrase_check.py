"""Live probe: which enclave model returns strict JSON for the reworded-leak check under E2EE?

Fictional demo data only. Two answers per model (one reworded leak, one clean), so 2 calls per model.
Run:  uv run --env-file .env python scripts/probe_paraphrase_check.py [--models a,b] [--format json_schema]
Prints only verdict shapes, timings, signature kinds and token counts.
"""

from __future__ import annotations

import argparse
import asyncio
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from familybox import config, enclave  # noqa: E402
from familybox.plugins import paraphrase  # noqa: E402
from familybox.store import Store  # noqa: E402

SAMPLES = [
    ("leak", "dana", "Your doctor noted you've been dealing with ongoing worry that is under control, and you "
                     "take a daily mood pill plus a sleep supplement when you need it."),
    ("clean", "dana", "Your next visit is on March 14, 2027."),
]


async def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--models", default="z-ai/glm-5.3-flash,deepseek-ai/DeepSeek-V4.1-Flash-1017")
    ap.add_argument("--thinking", action="store_true")
    ap.add_argument("--format", default="json_schema")
    args = ap.parse_args()
    key = enclave.api_key()
    if not key:
        print("NEAR_AI_CLOUD_API_KEY is not set")
        return 2
    cfg = config.load(ROOT / "demo")
    store = Store(cfg)
    store.ensure_index()
    path = "people/dana/health/visit_2026_09_14.txt"
    facts = [s for s in store.sensitive_values() if s.path == path and s.kind in paraphrase.FACT_KINDS]
    display = {p.id: p.display for p in cfg.people.values()}
    out = []
    for model in args.models.split(","):
        for name, asker, answer in SAMPLES:
            row = {"model": model, "sample": name, "format": args.format, "thinking": args.thinking}
            try:
                reply = await paraphrase.call_classifier(
                    api_key=key, model=model, response_format=args.format,
                    thinking=args.thinking,
                    messages=paraphrase.build_messages(display[asker], facts, answer, display))
                row.update(signature_kind=reply["signature_kind"], tokens=reply["tokens"], seconds=reply["seconds"])
                try:
                    v = paraphrase.parse_verdict(reply["content"])
                    row.update(strict_json=True, reveals=v.reveals, categories=v.categories,
                               spans=len(v.spans), facts=v.facts)
                except paraphrase.CheckFailed as e:
                    row.update(strict_json=False, why=str(e), chars=len(reply["content"]))
            except paraphrase.CheckFailed as e:
                row.update(error=str(e))
            print(json.dumps(row), flush=True)
            out.append(row)
    return 0


if __name__ == "__main__":
    sys.exit(asyncio.run(main()))
