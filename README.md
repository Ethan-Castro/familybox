# familybox: a household privacy box for AI assistants

**TEE attestation proves where the model ran. The household box decides what that model is ever allowed to reveal, and to whom.**

One small box at home (a Raspberry Pi) holds the family's SSNs, W-2s, passports and health records. Anyone in the family can ask ChatGPT, Claude, Codex or Cursor about them over MCP. The assistant never sees the documents.

- A **NEAR AI Cloud enclave model** (Intel TDX + NVIDIA GPU TEE) does the reasoning. It calls the box's read-only tools and sees only the asking person's files.
- The box **checks every answer** before the assistant gets it. Full SSNs, ID numbers and health details are replaced with placeholders. The full value appears only on the owner's own screen after they approve.

Built for the NEAR Hackathon 2026 (Privacy & Private AI; also AI Security & Defense). Diagram: [docs/how-it-works.html](docs/how-it-works.html).

## Try it in 2 minutes (no API key needed)

Requires Python 3.12+ and [uv](https://docs.astral.sh/uv/).

```bash
git clone <this repo> familybox && cd familybox
uv sync
export FAMILYBOX_HOME=$PWD/demo           # a fictional family: Dana, Sam and their daughter Maya

uv run familybox ask --as maya "What medications am I on?"
uv run familybox ask --as maya "What did the doctor say at Mom's last visit?"
uv run familybox ask --as dana "What were our combined 2025 W-2 wages, and what do we still need for Maya's FAFSA?"
uv run familybox pending --as maya        # values held for Maya's approval
uv run pytest -q tests                    # 97 tests
```

Without a key, `ask` replays recorded enclave conversations (`replays/`) for the six demo questions. The box's real tools, access checks and answer gate still run, and the output says "(replayed recording)". With a key, every question goes to NEAR AI Cloud live:

```bash
cp .env.example .env                      # add NEAR_AI_CLOUD_API_KEY
uv run --env-file .env familybox verify   # attestation only, no inference
uv run --env-file .env familybox ask --as dana "When does Maya's passport expire?"
```

### Connect an assistant (MCP)

Each family member's assistant gets its own connection, so the box always knows who is asking:

```bash
claude mcp add family-box-maya -e FAMILYBOX_HOME=$PWD/demo -e FAMILYBOX_PERSON=maya -- uv run --directory $PWD familybox-mcp
```

The assistant gets two tools, `ask_family_box` and `family_box_status`. It has no tool that lists, searches or reads files.

For ChatGPT and Claude on the web, `familybox serve` also serves MCP at `/mcp` with its own sign-in: the family member types a one-time code from the box to link their assistant. See [docs/REMOTE.md](docs/REMOTE.md).

### Put files on the box privately

```bash
uv run familybox code --as maya           # one-time 8-character sign-in code, valid 10 minutes
uv run familybox serve                    # https://127.0.0.1:8443 (on the Pi: --lan)
```

The page lets each person upload into their own folders (or `shared/`), see their files, and approve or deny held values. Uploads never leave the box. The page loads no outside scripts, fonts or analytics. Google Drive import and encrypted backup are in [docs/CLOUD.md](docs/CLOUD.md).

## How a question flows

1. **Who is asking:** the MCP connection is bound to one person.
2. **Verify first:** the box asks NEAR AI Cloud for fresh attestation (gateway + model, Intel TDX quote, NVIDIA evidence, TLS binding) through the official `nearai-inference-sdk`. If anything fails, the question stops.
3. **Encrypted to the enclave:** the question, the tool definitions, the tool calls and every tool result are end-to-end encrypted to the attested model key (E2EE v3).
4. **Scoped tools:** the model may call `search_files` and `read_file`. They only reach that person's folders plus `shared/`. Health folders are owner-only, even for parents.
5. **Enclave-signed:** every model turn must carry a `provider_tee` signature that verifies against the attested model key. A gateway-only signature is rejected.
6. **Answer gate:** the box knows the actual protected values in the files and recognizes them however they are written (dashes, spaces, spelled-out digits, a 5-digit run of an SSN, word forms of a diagnosis). The result is one of: pass, mask, hold for the owner's approval, or refuse (tripwire markers, another person's data).
7. **Audit:** each person has a log of what left the box for them, with the signer and the files read.

## Results (real runs, 2026-11-08)

**Attack suite** (`eval/attacks.py`, report in [eval/reports/attacks_2026-11-08.md](eval/reports/attacks_2026-11-08.md)): 30 attacks plus 8 normal questions, on DeepSeek-V4.1-Flash-1017 in NEAR AI Cloud. Leaks are judged by a checker in the eval script, not by the gate.

| Setup | Leaks / 30 attacks | Normal questions answered |
|---|---|---|
| **familybox** (scoped tools + answer gate) | **0** | 8/8 |
| Same model and scoped tools, reply returned as is ("trust the reply") | 5 | 8/8 |
| Same model, every file readable, no gate | 10 | 8/8 |

Attack categories: direct asks, encodings (spelled out, reversed, digit-shifted), piecing a number together, other people's data, health details, instructions planted in documents, and tripwires. Every model turn in every run carried a verified `provider_tee` signature.

These are single runs of a non-deterministic model on a hand-written suite with fictional data. Treat them as evidence, not proof. The first run found over-blocking in the gate, which was fixed (see [docs/BUILD_LOG.md](docs/BUILD_LOG.md)).

## What is proven, what is enforced, what is not covered

| Claim | Backed by |
|---|---|
| The model ran in a genuine Intel TDX + NVIDIA confidential-computing enclave | Hardware attestation, verified by the SDK with a fresh nonce (the box uses the SDK's default policy; it does not yet pin specific images or TCB levels) |
| Requests, tool calls and tool results were readable only inside that enclave | E2EE v3 to the attested model key |
| Each answer came from the attested model key | `provider_tee` signature over the exact request and response bytes |
| The assistant received only what passed the gate | The box's own code (software, auditable) |
| Each person's assistant reaches only their own files | The box's own code (access checks run before any file is read) |

**Not covered:**
- Anyone with root on the box can read everything.
- A stolen box without disk encryption exposes the files.
- NEAR's gateway still sees metadata: model, message count, sizes, timing and the API key.
- NEAR's attestation has known limits. Model instances share a signing key, so a signature doesn't identify the instance. Parts of the serving stack are pulled at runtime and are not in the measurement. See [docs/research/near_ai_cloud.md](docs/research/near_ai_cloud.md).
- The gate recognizes values that are in the files. A model could still paraphrase a fact the gate has no pattern for.

## What we found about NEAR AI Cloud

With E2EE on, a request whose history contains `assistant.tool_calls` plus `tool` messages returns 400 "Upstream request failed". This happens on glm-5.3-flash and DeepSeek-V4.1-Flash, and the same request without E2EE succeeds. familybox works around it by sending earlier tool calls and results as encrypted message text. Repro: `spikes/probe_turn2.py`. Details and model compatibility: [docs/BUILD_LOG.md](docs/BUILD_LOG.md).

## Layout

| Path | What |
|---|---|
| `src/familybox/` | `config`, `access`, `store` (SQLite FTS5 + protected-value index), `enclave`, `gate`, `approvals`, `box`, `cli`, `mcp_server`, `web`, `cloud/` |
| `demo/` | The fictional household: `family.toml` and `files/` |
| `replays/` | Recorded enclave conversations for the no-key demo |
| `eval/` | Attack suite, results and reports |
| `spikes/` | The Day-1 experiments and probes behind the design |
| `scripts/` | Pi installer and fleet exec helper (no SSH) |
| `docs/` | Plan, build log, cloud setup, diagram, research |

## Prior work and disclosures

- **All code in this repo was written during the hackathon**, from 2026-11-07 onward, after the 2026-10-19 announcement.
- **Libraries:**
  - [`nearai-inference-sdk`](https://github.com/nearai/inference-sdk) (MIT, by NEAR AI) handles attestation, E2EE and signature verification.
  - Also `mcp`, `starlette`, `uvicorn`, `httpx`, `pynacl` and `cryptography`.
- **AI coding assistants** (Claude Code) were used throughout.
- **Earlier projects by the author** inspired the design but are not part of this repo: Base Agent, a local MCP memory server and relay, and Muse Privacy, a privacy router for another hackathon.
- **How this compares** (details in [docs/research/landscape_2026-11-08.md](docs/research/landscape_2026-11-08.md)):
  - **TEE inference for private data** is established: NEAR AI Cloud, Tinfoil, Privatemode, Apple PCC, Google Private AI Compute. familybox builds on it rather than claiming it.
  - **Local PII redaction** is established: Perplexity Hybrid Compute, Latet, PrivAiTe, Presidio proxies, NEAR's `auto_redact`. These detect patterns in prompts. familybox instead checks the model's answer against the actual protected values in the family's files.
  - **Privateer** hands file work to a verified NEAR or Tinfoil enclave model from the same machine. Its docs say "the reply is the channel", and its PII gate scans prompts to unverified models. familybox keeps the data on a separate box and treats the asking assistant as untrusted.
  - **NEARpedia** (another hackathon entry) pairs MCP with verified NEAR AI inference over a public knowledge corpus. familybox applies the same verified path to private household data, adds per-person access, and adds a gate on every answer.
  - **PlanTwin** (research) checks a cloud planner's steps against local data. familybox checks the final answer, and pairs that with attested TEE inference.

## License

Apache-2.0. All people, numbers and records in `demo/`, `spikes/` and `replays/` are fictional. SSNs are from the 987-65-4320 to 987-65-4329 range reserved for advertising.
