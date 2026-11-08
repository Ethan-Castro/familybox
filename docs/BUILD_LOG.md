# Build log

Every result here comes from a real run. Raw output for the Day-1 spike is in `spikes/day1_results.json`.

## 2026-11-08: Day-1 spike (encrypted tool loop on NEAR AI Cloud)

Setup: `nearai-inference-sdk==0.3.0` (MIT, public library), `InferenceClient(e2ee=True)`, fictional files in `spikes/fixtures/`.

**Results**
- **Attestation:** gateway plus DeepSeek-V4.1-Flash-1017 model report verified with a fresh nonce, in 1.9 s.
- **Encrypted tool loop works.** The question was "combined 2025 W-2 wages for Dana and Sam, and Maya's passport expiry".
  - The model called `search_files` twice, then `read_file` three times, then answered.
  - The answer was correct: $142,310.00 and May 2, 2027.
  - 3 turns, 4.9 s, 2,249 tokens in and 295 out (about $0.001).
- **Signatures:** every turn returned a `provider_tee` signature that verified against the attested model key. Signer `236f5a6b91dd47dc…` (ed25519).
- **Fail-closed checks:**
  - Without E2EE, a streamed reply carries only a `gateway` signature. Our `provider_tee` check rejects it.
  - A model without enclave attestation (`openai/gpt-5-nano`) is refused by the SDK before any request is sent (`policy.model_attestation_required`).

**Findings**
1. **NEAR bug: multi-turn tool history fails under E2EE.** On both glm-5.3-flash and DeepSeek-V4.1-Flash, any request whose history contains `assistant.tool_calls` plus `tool` messages returns 400 "Upstream request failed" with E2EE on. The same request without E2EE succeeds (`spikes/probe_turn2.py`).
   - Workaround: send `tools` natively each turn, and replay earlier calls and results as encrypted message text (`spikes/probe_text_history.py`). Every field stays encrypted.
   - Worth reporting to NEAR AI; not reported yet.
2. **Qwen3.8-27B** rejects requests that include tools, with or without E2EE. **glm-5.3-flash** works for one tool turn, but with text-replayed history it imitates the text format instead of calling tools. So DeepSeek-V4.1-Flash-1017 is the default model.
3. **The SDK is on E2EE protocol v3**, newer than the docs the research read. Each encrypted field's AAD binds the client's reply key and the field path. Tool definitions, tool calls and tool results are encrypted (`x-encrypt-all-fields: true`).
4. **Streaming:** with E2EE, streamed replies also get `provider_tee` signatures. Without E2EE they get `gateway` signatures (gateway signer `40599fb2…4acb`).

## 2026-11-08: Box core, first live end-to-end runs

Built: `config`, `access`, `store` (SQLite FTS5 plus an index of protected values), `enclave` (live, record, replay), `gate`, `approvals`, `box`, and the `familybox` CLI. Fictional Okafor household in `demo/`. 21 unit tests pass.

**Live runs** (DeepSeek-V4.1-Flash-1017; every turn E2EE and a verified `provider_tee` signature; recorded in `replays/`):

| Asker | Question | Turns | Files read | Gate |
|---|---|---|---|---|
| dana | combined W-2 wages + what's left for FAFSA | 4 | both W-2s, FAFSA checklist | pass after fix (see below) |
| dana | Maya's SSN for the FAFSA | 3 | Maya's SSN card, checklist | pass: model gave only "ending in 4322" |
| maya | what the doctor said at Mom's last visit | 6 | **none** (Mom's health folder is out of scope) | pass: "I can't see that" |
| maya | allergies for a sports form | 3 | Maya's FHIR record | held: model volunteered her asthma, gate held it for Maya |
| dana | car registration + insurance deductible | 3 | 2 shared files | pass: member ID given as last 4 only |
| maya | what medications am I on | 4 | Maya's FHIR record | held: drug and condition replaced with placeholders |

**Bug found and fixed:** "Lakeside" (Dana's employer) was masked as a health detail, because her visit notes mention "Lakeside Counseling". Health-word matching now ignores words that also appear in the family's non-health files. A regression test was added.
