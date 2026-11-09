"""Which NEAR enclave model reads an image under E2EE with a provider_tee signature?

  uv run --env-file .env python spikes/probe_vision.py [photo] [model ...]

Sends one fictional photo per model through familybox.vision.transcribe_live (attestation verified,
E2EE on, provider_tee required). Stops at the first model that works unless --all is given.
Writes spikes/vision_probe_results.json. Never prints the API key.
"""

from __future__ import annotations

import asyncio
import json
import sys
import time
from pathlib import Path

from familybox import enclave, vision

ROOT = Path(__file__).resolve().parents[1]
MODELS = ["Qwen/Qwen3-VL-30B-A3B-Instruct", "z-ai/glm-5.3-flash"]


async def main(argv: list[str]) -> int:
    run_all = "--all" in argv
    argv = [a for a in argv if a != "--all"]
    photo = Path(argv[0]) if argv else ROOT / "demo/photos/ssn_card_jordan.png"
    models = argv[1:] or MODELS
    key = enclave.api_key()
    if not key:
        print("NEAR_AI_CLOUD_API_KEY is not set")
        return 2
    prep = vision.prepare(photo.read_bytes())
    results = []
    for model in models:
        events: list = []
        t = time.monotonic()
        try:
            tr = await vision.transcribe_live(prep, api_key=key, model=model,
                                              emit=lambda step, **d: events.append({"step": step, **d}))
            r = {"model": model, "ok": True, "signature_kind": tr.signature_kind,
                 "signer": enclave.short_signer(tr.signer), "seconds": tr.seconds,
                 "attestation": tr.attestation, "tokens": [tr.tokens_in, tr.tokens_out],
                 "raw_text": tr.text, "canonical": vision.canonical(tr.text),
                 "fields": vision.labeled_fields(vision.canonical(tr.text))}
        except enclave.EnclaveError as e:
            r = {"model": model, "ok": False, "error": str(e), "events": events}
        r["photo"] = photo.name
        r["total_seconds"] = round(time.monotonic() - t, 2)
        results.append(r)
        print(json.dumps(r, indent=1), flush=True)
        if r["ok"] and not run_all:
            break
    out = ROOT / "spikes" / "vision_probe_results.json"
    prev = json.loads(out.read_text()) if out.exists() else []
    out.write_text(json.dumps(prev + [{"run_at": int(time.time()), "results": results}], indent=1))
    return 0 if any(r["ok"] for r in results) else 1


if __name__ == "__main__":
    sys.exit(asyncio.run(main(sys.argv[1:])))
