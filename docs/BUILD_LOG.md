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

## 2026-11-08: Private upload page, Google Drive import and backup, attack suite

- **Merged** `familybox serve` (HTTPS page with one-time sign-in codes, uploads, file list, approvals) and `familybox.cloud` (Drive import over OAuth with PKCE, plus backups encrypted on the box with secretstream). Cloud is tested only against a fake Google. 97 tests pass.
- **Attack suite** (`eval/attacks.py`): 30 attacks plus 8 normal questions, each run in 3 setups on DeepSeek-V4.1-Flash-1017. Every model turn carried a `provider_tee` signature. Leaks are judged by a separate checker in the eval script.

| Run | box leaks | no_gate leaks | open leaks | utility (box / no_gate / open) | box refusals |
|---|---|---|---|---|---|
| run 1 (`eval/reports/attacks_2026-11-08_run1.md`) | 0 / 30 | 6 / 30 | 8 / 30 | 8/8, 8/8, 8/8 | 13, several of them over-blocking |
| run 2, after gate fixes (`eval/reports/attacks_2026-11-08.md`) | **0 / 30** | 5 / 30 | 10 / 30 | 8/8, 8/8, 8/8 | 2, both correct tripwire blocks |

- **Bugs run 1 exposed:** the gate refused safe polite refusals. Three causes, all fixed and covered by regression tests:
  - digits from separate numbers were joined into one false SSN run;
  - health stems were matched across word boundaries;
  - everyday words from visit notes ("continue") counted as health details.
- **Run 2 box outcomes on the 30 attacks:** 23 passed (the model declined safely), 4 held for the owner, 2 refused (tripwire), 1 error (turn limit, nothing answered).
- **Caveats:**
  - These are single runs and the model is not deterministic: the no-gate setup leaked 6 in run 1 and 5 in run 2.
  - Errors answer nothing. That happened 5 times in run 1 and 2 in run 2, mostly in the baseline setups.
  - The suite is 30 hand-written attacks against fictional data. It is evidence, not a proof.

## 2026-11-08: Running on the Raspberry Pi (decision-tree, Pi 5, 2 GB)

Installed through the fleet control plane's exec jobs, with no SSH (`scripts/fleet_exec.py install`).
- **Install:** the code was sent as a git archive of tracked files only, in 42 chunks; the sha256 checksum verified on the board.
- **Setup:** `scripts/pi_install.sh` ran as `offlinebase`. No sudo, no system packages, no services. It installed uv 0.13.7 and used the system Python 3.13.5.

**Results on the Pi**
- **Tests:** `uv sync` took 4 s; **97 tests passed in 4.35 s**.
- **Replay demo:** "What medications am I on?" as Maya. The real access checks and gate ran, and the drug and condition were held for Maya.
- **Attestation:** the Pi verified NEAR AI Cloud attestation itself, with no API key (gateway plus the DeepSeek-V4.1-Flash model report, Intel TDX quote and NVIDIA evidence, through the SDK). **5.04 s the first time, 1.61 s the second; 166 MB peak memory.**
- **Fleet unaffected:** the board still had about 1.6 GB available, the fleet agent kept running, and the control plane kept answering.
- **Not yet run on the Pi:** live answers. They need the NEAR key on the board, which is waiting on Ethan's OK.

## 2026-11-08: Plugin hooks for parallel feature work

- **What:** a plugin package (`src/familybox/plugins/`) so each new feature is one module. Hooks: box registration (tool providers, pre checks, post checks), CLI subcommands, web routes and nav links, MCP tools. Details in `docs/PLUGINS.md`.
- **Every question** now has a 12-character id. Each step is written to `runtime/events/<person>/<id>.jsonl` with protected values scrubbed. The audit log entry now records the id and where the question came from (cli, mcp-stdio, mcp-remote, web).
- **Fail closed:** an error in a pre or post check stops the question, and nothing is answered.
- **Enclave:** `ask_live` takes the tool list and an event callback. Replay mode sends the same events, marked as replayed.
- **Tests:** 113 passed (97 before plus 16 new plugin tests). No live calls were made.

## 2026-11-08: Tamper-evident logs, NEAR anchoring ready (branch feat/ledger)

- **Chained logs** (`src/familybox/ledger.py`, core): every audit entry now carries `seq`, `prev_hash` and `entry_hash` (sha256 over canonical JSON with a version prefix; the first entry links to a hash of the person's id). Both writers (answers in `box.py`, uploads and deletes in `web.py`) go through `ledger.append`, which takes a file lock so the CLI, web page and MCP servers never fork the chain. Older unchained lines are sealed by a `ledger_start` entry (their count and the sha256 of their bytes). A damaged line is sealed by `ledger_resume` and keeps being reported.
- **`familybox log verify --as <person>`** walks the chain and checks the saved head and every saved checkpoint. Tested: edits (also with the entry's own hash recomputed), deletions at the start, middle and end, reorders, duplicates, inserted lines, duplicate JSON keys, another person's log copied in, sealed old lines changed or removed, torn writes, and 200 appends from 5 threads at once.
- **Known limit, stated in the CLI and docs:** cutting the newest entries off the end and rewriting the head file cannot be seen from inside the box. Only a checkpoint or a NEAR anchor catches it (tested both ways).
- **Anchor plugin** (`plugins/anchor.py`, `near_anchor.py`): `familybox anchor` prints the exact `anchor()` call (dry run, no network). `--save` keeps a local checkpoint, `send` signs with a function-call key (Borsh + ed25519, written from scratch; refuses full-access keys and keys for other contracts, checked on-chain first), `check` reads `get()` back and verifies the log against it, and `keygen` makes the key (0600, never printed). Person ids go on-chain only as HMAC-SHA256 with a per-box salt. A **Log** page on the web shows the chain head and status (the admin also sees everyone's status).
- **Contract** (`contracts/disclosure-anchor/`, Rust near-sdk 5.x): `register_box` (payable, the caller becomes the writer), `anchor` (writer only, count never goes down, same count with a different head refused, storage paid from the box's deposit), `get`/`get_box` views, `top_up`, `set_writer` and `withdraw` (1 yoctoNEAR, so a function-call key cannot call them). NEP-297 event `familybox_anchor` 1.0.0 `anchored`. **Not compiled and its 19 unit tests not run:** this laptop has no Rust toolchain and none was installed.
- **No live NEAR calls.** Send and check were tested only against a fake RPC. Ethan has no testnet account yet; setup steps are in `docs/ANCHOR.md`.

### Review fixes for the ledger (same branch)

- **False "does not check out" while another process writes (high):** `verify()` read the log and then, much later, the head file, with no lock. A writer in another process (MCP server, web page, CLI) could add an entry in between. It now reads both while holding the per-person lock (shared). New test: a separate process appends nonstop while this one runs `verify_all` in a loop on a 2,000-entry log. It fails on the old code and passes now, zero failures.
- **Anchoring the whole family (medium):** `anchor send` now reads the key's nonce with finality `optimistic` and never uses less than the last nonce it used plus one, so back-to-back sends cannot reuse a nonce. One person's failure is reported and the rest are still anchored (exit code 1). Tested against the fake RPC with three people: nonces 101, 102, 103.
- **Power cut mid-write (medium):** a single piece of a line at the end of the file, with no newline and not valid JSON, is sealed with `reason: "torn_write"` and reported as a note, not a failure, so the log still checks out and can still be anchored. Its bytes stay pinned by the seal. Two bad lines, or an entry with its chain fields stripped, are still failures.
- **Approvals are logged (medium):** approving or denying a held value adds an `approved` or `denied` entry to the owner's chain (item id, label, kind, who asked). Never the value. Written before the value is released.
- **Wording (medium):** the README and the Log page no longer say "nothing was changed" as fact. Without a NEAR anchor the page says the log is linked correctly but a full rewrite would not show. Checkpoints from `--save` are labelled "Saved on this box (not on NEAR)".
- **Low:** the key must be limited to exactly `["anchor"]` (an empty list means any method); damaged `anchor_id.json` or `near_key.json` gives a plain error; network errors become plain errors; `anchor check` says when the box id is registered to another account; ANCHOR.md says the first dry run makes the box's anchor id. Borsh: added the transfer transaction vector from near-api-js's own tests as a reference fixture for the transaction layout (the FunctionCall action itself still has no outside vector).
- **Still not done:** the contract is still not compiled and `cargo test` was still not run (no Rust toolchain here). No live NEAR calls.
- **Tests:** 185 passed. No live calls were made.
