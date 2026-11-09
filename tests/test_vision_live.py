"""One real transcription through a NEAR enclave (skipped without NEAR_AI_CLOUD_API_KEY).

  uv run --env-file .env pytest -q tests/test_vision_live.py

Costs well under a cent: one small fictional card, about 700 tokens in and 100 out.
"""

import asyncio
import sys
from pathlib import Path

import pytest

from familybox import enclave, vision

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))
import make_photo_fixtures  # noqa: E402

pytestmark = pytest.mark.skipif(not enclave.api_key(), reason="NEAR_AI_CLOUD_API_KEY is not set")


def test_live_transcription_of_a_fictional_ssn_card(tmp_path):
    photo = next(p for p in make_photo_fixtures.main(tmp_path) if p.name == "ssn_card_jordan.png")
    prep = vision.prepare(photo.read_bytes())
    t = asyncio.run(vision.transcribe_live(prep, api_key=enclave.api_key(), model=vision.DEFAULT_VISION_MODEL))
    assert t.signature_kind == "provider_tee" and t.signer
    body = vision.canonical(t.text)
    assert ("SSN", "987654329") in vision.labeled_fields(body)
