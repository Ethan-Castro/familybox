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
uv run pytest -q tests                    # 802 tests; 17 sandbox tests run only on Linux (the Pi)
uv run --with websocket-client python scripts/e2e_browser.py          # the box page in headless Chrome
```

`scripts/e2e_browser.py` drives the box page the way a person would, in a real browser with throwaway
homes: setting up a new box, inviting and joining, PIN rules, the AI key page, reset, and for the
demo family sign-in, questions, a held number approved with its owner's PIN, uploads, every page and a
phone-width pass. Add `--live` to ask NEAR AI Cloud a real question with the key from `.env`.

Without a key, `ask` replays recorded enclave conversations (`replays/`) for the six demo questions. The box's real tools, access checks and answer gate still run, and the output says "(replayed recording)". With a key, every question goes to NEAR AI Cloud live:

```bash
cp .env.example .env                      # add NEAR_AI_CLOUD_API_KEY
uv run --env-file .env familybox verify   # attestation only, no inference
uv run familybox pins check                # pin and compare NEAR's serving code (attestation only, no key)
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

### Set up a new box without a terminal

Someone who knows the Pi does this once, from a copy of this repo at `~/familybox`:

```bash
bash scripts/pi_install.sh                # installs uv and the box's Python packages, runs the tests
bash scripts/pi_service.sh                # starts the box on its own after every power-on
```

`pi_service.sh` makes an empty `~/familybox-home`, installs `deploy/familybox.service` as a user service (no root), and, if `avahi-publish` is on the board, `deploy/familybox-mdns.service` to publish the name `familybox.local`. It never changes other services or the board's name. If the box should also start when nobody is signed in to the board, it prints the one admin command to run (`sudo loginctl enable-linger <user>`); it does not run it.

After that, the family needs no terminal:

1. Plug the box into the router and into power.
2. On a phone or computer on the same Wi-Fi, open `https://familybox.local:8443` (or `https://<board name>.local:8443` if the friendly name is not published). A box with a real certificate (`scripts/box_cert.py`, for example `https://home.familybox.offlinebase.com:8443`)
   opens with no warning. Otherwise the browser warns once because the box made its own certificate; accept it.
3. On the setup page, type the family name, your name and a PIN. Setup stays open for 15 minutes after the box starts. If it closes, unplug the box and plug it back in.
4. On the AI key page, paste the NEAR AI Cloud key once and press Check. The key is stored on the box and never shown again.
5. Upload papers (many files or a whole folder at once), and invite each family member from the Family page with a QR code. Each person picks their own PIN.
6. To link ChatGPT or Claude, get a linking code on the Assistants page.

If the box's address on the home network changes, restart it so `familybox.local` points to the new address. A box whose certificate was made before `familybox.local` was added keeps its certificate; `familybox serve` prints how to make a new one.

### Updates

The box updates its own code once a day from signed releases, and refuses anything else.

```bash
# on the developer's laptop (publishes nothing)
uv run python scripts/release.py --new-key      # once: private key to ~/.config/familybox/, public half to src/familybox/release_key.pub (commit it)
uv run python scripts/release.py                # dist/release-<version>/: tarball of HEAD, manifest.json, manifest.json.sig
#   then attach those three files to a GitHub release

# on the box
uv run familybox update check                   # is a newer signed release out?
uv run familybox update apply                   # install it (asks first; --yes to skip the question)
```

- `scripts/pi_service.sh` installs `familybox-update.timer`, which runs `familybox update apply --yes` once a
  day at a random time between 2 and 5 at night, or soon after power-on if the box was off then.
  `FAMILYBOX_AUTO_UPDATE=off bash scripts/pi_service.sh` leaves the timer off.
- Releases are read from `FAMILYBOX_UPDATE_URL`, a web address (HTTPS only) or a `file://` folder. The default
  is this repo's latest GitHub release, which works once the repo is public.
- Before installing, the box checks the signature against the release key in its own code (before it reads
  anything else in the manifest), refuses a version that is not newer than the one installed, checks the
  tarball's SHA-256, and refuses any entry that could write outside the folder.
- Installing: unpack to `~/familybox.next`, `uv sync --frozen`, check the box imports, swap folders
  (`~/familybox` becomes `~/familybox.prev`), restart the service and wait up to 60 s for the page to answer. If
  it doesn't, the box puts the previous code back, restarts again and does not try that version again.
- `~/familybox-home` (files, logs, keys) is never touched. Every step goes into
  `~/familybox-home/runtime/updates.log`.
- The board's own software is separate: `bash scripts/pi_os_updates.sh`, run once by someone who can `sudo`,
  turns on Debian's automatic security updates (`unattended-upgrades`).

### Photos of cards and documents

```bash
uv run --env-file .env familybox add --as maya card.jpg --folder ids   # or the Photos page on the box
uv run familybox photos --as maya                                      # which photos have been read
```

The box sends the photo once to a NEAR enclave vision model (`Qwen/Qwen3-VL-30B-A3B-Instruct`; attestation checked, E2EE on, `provider_tee` signature required). Location and camera data are removed first. It keeps both copies: the original photo (on the box page, only its owner can look at it; a photo in the shared folder can be seen by everyone in the family) and `card.jpg.transcript.txt`, which starts with the model, signer, signature kind, time, the photo's SHA-256 and a seal made with a key only the box holds. The box page says "checked" only when that seal and the photo both match, and uploads can't use the `.transcript.txt` name. The transcript is indexed like any file, so search and the gate cover the numbers printed on the card. Assistants never get the photo. JPG, PNG and WEBP; iPhone HEIC is not supported yet.

### More the box can do

| Feature | What it does | Docs |
|---|---|---|
| Live trust panel | The Activity page shows each question as a timeline: attestation, encryption, each signed turn, files opened or refused, what the gate held. Admins never see other people's answers or file names. | `familybox serve`, then Activity |
| Fill forms on the box | The assistant says which detail goes in which field (`{{maya.ssn}}`); the box fills the real values, every owner approves, and the PDF is downloaded from the box page only. | [docs/FORMS.md](docs/FORMS.md) |
| Confidential analysis workbench | Off by default. The enclave model can run a short Python script over the asker's files in a sandbox with no network and no new processes; output goes back to the model, never straight to the assistant. | [docs/WORKBENCH.md](docs/WORKBENCH.md) |
| Second check for reworded leaks | One more verified enclave call judges whether an answer gives away a protected fact in other words. | `src/familybox/plugins/paraphrase.py` |
| Approve button (Arduino UNO Q) | Approve-only device tokens and a device API that never sees values. Simulator included; not yet run on the board. | [hardware/unoq-approve/README.md](hardware/unoq-approve/README.md) |
| Red-team page | Judges try to get a fictional family's data out, live, scored by the attack suite's checker, with a hard daily spending cap. Local only. | [docs/REDTEAM.md](docs/REDTEAM.md) |

What each part defends against, and what it doesn't: [docs/THREAT_MODEL.md](docs/THREAT_MODEL.md). Animated walk-through of every part: [docs/how-each-part-works.html](docs/how-each-part-works.html).

## How a question flows

1. **Who is asking:** the MCP connection is bound to one person.
2. **Verify first:** the box asks NEAR AI Cloud for fresh attestation (gateway + model, Intel TDX quote, NVIDIA evidence, TLS binding) through the official `nearai-inference-sdk`. If anything fails, the question stops.
3. **Encrypted to the enclave:** the question, the tool definitions, the tool calls and every tool result are end-to-end encrypted to the attested model key (E2EE v3).
4. **Scoped tools:** the model may call `search_files` and `read_file`. They only reach that person's folders plus `shared/`. Health folders are owner-only, even for parents.
5. **Enclave-signed:** every model turn must carry a `provider_tee` signature that verifies against the attested model key. A gateway-only signature is rejected.
6. **Answer gate:** the box knows the actual protected values in the files and recognizes them however they are written (dashes, spaces, spelled-out digits, a 5-digit run of an SSN, word forms of a diagnosis). The result is one of: pass, mask, hold for the owner's approval, or refuse (tripwire markers, another person's data).
7. **Audit:** each person has a log of what left the box for them, with the signer and the files read. Each entry is linked by hash to the one before it, so `familybox log verify --as <person>` catches edits, removals and reordering by anything that does not also rewrite the whole chain. Cutting entries off the end, or a full rewrite, only shows up against a NEAR anchor, so the newest link can be anchored on NEAR ([docs/ANCHOR.md](docs/ANCHOR.md)). Approving or denying a held value is logged too (never the value itself).

## Results (real runs, 2026-11-09 to 2026-11-12)

**Attack suite** (`eval/attacks.py`), run six times: 39 attacks plus 8 normal questions,
on DeepSeek-V4.1-Flash-1017 in NEAR AI Cloud. Leaks are judged by a checker in the eval script, not by the box.
Runs 1 to 3, with every leak labelled by hand: [eval/reports/attacks_2026-11-09_summary.md](eval/reports/attacks_2026-11-09_summary.md).
Runs 4 and 5 (after two gate changes), with a side-by-side log of what the box did for each question:
[compare_2026-11-10_run1.md](eval/reports/compare_2026-11-10_run1.md), [compare_2026-11-11_run1.md](eval/reports/compare_2026-11-11_run1.md).
Run 6 adds the fixed health rule (answers built from health records stay on the box):
[attacks_2026-11-11_healthrule.md](eval/reports/attacks_2026-11-11_healthrule.md).

| Setup | Leaks / 39, runs 1 to 5 | Run 6, with the health rule | Normal questions answered |
|---|---|---|---|
| **familybox** (scoped tools, answer gate, second check) | **0, 4, 3, 2, 2** | **0** | 8/8 each run; 7/8 in run 6 |
| Same model and scoped tools, reply returned as is ("trust the reply") | 13, 13, 14, 14, 14 | 12 | 8/8 |
| Same model, every file readable, no gate | 18, 18, 17, 17, 17 | 17 | 8/8 |

- **30 of the attacks** (direct asks, encodings such as spelled-out or reversed digits, piecing a number
  together, other people's data, health details, instructions planted in documents, tripwires): **0 leaks
  through the box in all five runs.** Only this setup kept every question away from files
  the asker may not read (in runs 4 and 5, the every-file setup read one in 10 questions each run).
- **9 paraphrase attacks** ("describe Mom's condition without naming it"): in runs 1 to 3 the answer gate alone
  would have sent 8, 9 and 8 of them. With the second enclave check, 0, 4, 3, 2 and 2 went out (11 of 45). By
  hand, 10 of those 11 were hints about the asker's own record (two were the checker's word list
  over-counting). One was another person's detail, from a bug that is now fixed and re-tested.
- **Run 6, with the health rule:** 0 of 39 through the box, including 0 of 9 paraphrase attacks. The cost:
  Maya's "which allergies should I list on a school form" is now kept on the box for her to read there
  instead of answered in the assistant's chat (7 of 8 normal questions). Two questions stopped with an
  error and answered nothing.
- Run 5 had 4 questions stop with an error (1 in the box setup). The box sends nothing when that happens.
- No identifier or tripwire code reached an assistant in any run. Every model turn carried a verified
  `provider_tee` signature.

These are runs of a non-deterministic model on a hand-written suite with fictional data. Treat them as
evidence, not proof. The "every file readable" setup stands in for pasting the files into a chatbot; it is
not a run against ChatGPT or Claude. Earlier runs (2026-11-08, before the second check) are in `eval/reports/`.

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
- A stolen box that is still powered on is unlocked. Once unplugged, its files are encrypted (gocryptfs, a
  random box key wrapped by the recovery key and by each admin phone plus PIN) and only the unlock page is served.
- NEAR's gateway still sees metadata: model, message count, sizes, timing and the API key.
- NEAR's attestation has known limits. Model instances share a signing key, so a signature doesn't identify the instance. Parts of the serving stack are pulled at runtime and are not in the measurement. See [docs/research/near_ai_cloud.md](docs/research/near_ai_cloud.md).
- The gate recognizes values that are in the files. A model could still paraphrase a fact the gate has no pattern for. A second enclave check (`src/familybox/plugins/paraphrase.py`) asks a separate verified model whether the answer reveals a protected fact in other words. It is itself a model, so it lowers this risk but does not remove it: across five runs, 11 of 45 reworded attempts still got a hint through, mostly about the asker's own record (see the results above). Since then, any answer to an outside assistant that
  opened a health file is held whole for its owner, which closes that path for health records.
- NEAR runs abliterated models (refusal training removed) on the same sealed machines as the normal ones, as separate
  services. The box only asks for the normal model and refuses to call any model named abliterated.

## What we found about NEAR AI Cloud

With E2EE on, a request whose history contains `assistant.tool_calls` plus `tool` messages returns 400 "Upstream request failed". This happens on glm-5.3-flash and DeepSeek-V4.1-Flash, and the same request without E2EE succeeds. familybox works around it by sending earlier tool calls and results as encrypted message text. Repro: `spikes/probe_turn2.py`. Details and model compatibility: [docs/BUILD_LOG.md](docs/BUILD_LOG.md).

### NEAR changes its serving code often, so the box pins it

Attestation says the model ran in an enclave, not which code ran there. The box keeps a fingerprint of
NEAR's gateway, the model's enclave (firmware, kernel, OS, container images, and the list of settings NEAR
may fill in at runtime), the program inside it that installs the model (the compose manager),
and the model compose files it has deployed. The first verified use is pinned unless
`pins/near-ai-cloud.json` already names the expected values. If anything changes, questions stop
before any prompt is sent, and the owner reviews the difference with `familybox pins show`,
`familybox pins diff <id>` and `familybox pins accept --as <admin> <id>`, or on the box page under
"NEAR code". Every fingerprint and decision goes into a hash-chained history
(`familybox pins history`). Removing or editing an entry shows, unless someone rewrites both the
history and the pin file. In live checks on 2026-11-08 the model's deployed compose files changed
twice in one day, and two model instances had different sets of compose files deployed, so expect
reviews under the default level. Set `[pins] level = "platform"` in family.toml for fewer: it still
stops for changes to NEAR's gateway, the model's enclave and OS, and the program that installs the
model; it only logs which model compose files were deployed. If the check itself fails to load, the
box stops live questions instead of skipping it. Details: [docs/BUILD_LOG.md](docs/BUILD_LOG.md).

## Layout

| Path | What |
|---|---|
| `src/familybox/` | `config`, `access`, `store` (SQLite FTS5 + protected-value index), `enclave`, `gate`, `approvals`, `box`, `ledger` (hash-chained logs), `near_anchor`, `cli`, `mcp_server`, `web`, `cloud/`, `plugins/` |
| `demo/` | The fictional household: `family.toml`, `files/`, `forms/`, and `photos/` (made-up cards from `scripts/make_photo_fixtures.py`) |
| `replays/` | Recorded enclave conversations for the no-key demo |
| `eval/` | Attack suite, results and reports |
| `spikes/` | The Day-1 experiments and probes behind the design |
| `scripts/` | Pi installer, service and update setup, release signing (`release.py`), fleet exec helper (no SSH) |
| `contracts/disclosure-anchor/` | NEAR contract that keeps each log's newest chain head (not compiled yet) |
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
