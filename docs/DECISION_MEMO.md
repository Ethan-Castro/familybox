# NEAR Hackathon 2026 decision memo: what to build (Privacy & Private AI, aiming for the Grand Prize)

Labels: **[C]** means confirmed (I saw it at the cited URL or path, or it showed up in a live keyless call). **[I]** means inferred or speculation. Scratchpad paths are relative to `/private/tmp/claude-501/-Users-ethancastro/bbb35d95-f9c7-4de1-a77a-3ce1b586f2a9/scratchpad/`. That folder is under `/private/tmp` and is cleared on reboot, so copy it into the new repo on Day 1.

---

## 1. Key research findings

### 1.1 Rules (source: https://nearhackathon.com/HACKATHON.md, copy at `nh/HACKATHON.md`)

**Dates and prizes**
- [C] Submission deadline and repo-public deadline: **2026-11-14T23:59Z**. Judging starts Nov 16. Results by Nov 18. Keep the demo up until Nov 18, ideally Nov 25 (Q-012).
- [C] Prizes: Grand Prize is $55K, one winner. Each of the 13 tracks pays $10K / $3K / $2K. The rules don't say whether a Grand Prize winner can also take a track prize.

**Judging**
- [C] Claude Code and Codex screen every project. They check reproducibility, verify features, write a structured report and give a preliminary score. Humans decide, and "a low AI score alone cannot reject" (Q-017).
- [C] No criteria or weights are published. The FAQ points to criteria from past hackathons: technical implementation, design, impact, originality, sustainability.
- [C] Human judges: Illia Polosukhin, Eddy Lazzarin, Mert Mumtaz, Avichal Garg, Kain Warwick, Haseeb Qureshi, Stepan Gershuni.
- [I] So the README is effectively part of the score. It needs "do X, see Y" steps, a replay mode that needs no key, and no claim that the code doesn't back up.
- [C] A video is needed in practice: "Screenshots are not enough when judges cannot open the demo" (Q-012).

**Multiple submissions**
- [C] One submission per project. Each repo can be submitted once (a repeat gets 409). Each email can file at most 2 submissions.
- [C] One person can be in at most 2 projects, and only if they are independent and **each README names the other** (Q-015).
- [C] SUBMITTING.md says "one per team", but HACKATHON.md is the authoritative rules file.

**Prior code**
- [C] Q-001: code written from the 2026-10-19 announcement counts. Earlier commits are baseline.
- [C] Q-003: separate the baseline with a branch, or with `pre-hackathon` / `hackathon-submission` tags plus a README diff link.
- [C] Q-004: an old project as-is is ineligible.
- [C] Q-005: libraries, your own older libraries (which count as baseline) and AI-generated code are all allowed. List them in the README.

**Integration and process**
- [C] No integration is mandatory (Q-011). Testnet-only projects are eligible (Q-010). NEAR Intents has no testnet.
- [C] $10 of inference credit is available through https://nearbuilders.org/join (Q-000).
- [C] Without Ethan's explicit yes, the agent may not submit, post on X, make the repo public, push, sign transactions or spend. It must never create NEAR accounts.

### 1.2 What NEAR AI Cloud attestation actually proves, and what it does not

**Proven, if you verify it yourself** [C: live dcap-qvl run on 2026-11-07 with `scripts/verify.py`; raw reports in `near/live/` and `crit/`]
- The gateway runs in a TDX CVM (dstack 0.5.12) with debug off and TCB status UpToDate.
  - `report_data` equals the signer (optionally hashed with the TLS SPKI) followed by our nonce.
  - MRCONFIGID equals `01||sha256(app_compose)`, and the RTMR3 replay matches.
  - TLS terminates inside that CVM. The SPKI is bound to the quote, but the docs say this only counts as proof over the same TLS connection.
- The model runs in a TDX CVM with 8 Hopper GPUs. Its signing key is bound to our nonce and the SPKI. The NVIDIA payload echoes our nonce (NRAS was not run).
- The compose-manager quote comes from the same CVM, with `report_data = actions_hash || nonce`.
  - **Correction to the first-pass research:** `actions_hash` *is* reproducible. It equals `sha256(json.dumps(actions, sort_keys=True, separators=(',',':'), ensure_ascii=False))` [C, live, `crit/`; the method is in nearai-cloud-verifier `py/model_verifier.py:67-103`].
  - So the whole actions log is bound to a hardware quote.
- Ed25519 model keys are live for glm-5.3-flash, Qwen3.8-27B and DeepSeek-V4.1-Flash-1017 [C, `crit/m_ed.json`].
  - `env::ed25519_verify` is stable in near-sdk. `env::ecrecover` requires the `unstable` feature [C, docs.rs].
  - The ecosystem report's suggestion to use ecrecover should be dropped.

**Not proven**
- **The running model image.** [C]
  - compose-manager pulls service files from `github.com/nearai/cvm-compose-files` at runtime.
  - The launcher hot-swaps compose-manager itself (`LAUNCHER_CHANNEL=latest`, `MIN_TAG_AGE_HOURS=0`), outside RTMR3.
  - The digest went `a320bb…` → `a0c073…` (Oct 29, Nov 4) while compose_hash stayed the same.
  - The actions log is quoted by hardware but written by software that can be swapped. A compose-manager that lies consistently cannot be caught.
- **Request integrity under `provider_tee`.** [C: `nearai/cloud-api@4ac61fd`, `crates/inference_providers/src/attested/nearai/mod.rs:1955-1970`]
  - The gateway re-serializes the body and relays `X-Request-Hash`, and that is the hash the model signs.
  - So a `provider_tee` signature does **not** prove the model processed your exact bytes.
  - B1, M1 and N2, and the first-pass research brief, all overclaim here.
- **Which instance served the request.** Instances share one KMS-derived signing key per model [C, docs]. KMS governance is unknown. All 5 consecutive glm reports came from a single `instance_id 19aea169…` [C].
- **Gateway confidentiality.**
  - Without E2EE the gateway sees plaintext.
  - Even with E2EE it sees model ID, roles, message count, lengths, timing and API key.
  - Its logs leave the enclave, governed only by a code-review policy [C: `cloud-api/.claude/rules/privacy-logging.md`].
  - Operator environment values are not measured.
- **GPU-to-CVM binding.** It exists only through the shared nonce [I]. TEE.fail-class physical attacks are out of scope (https://tee.fail/).
- **Silent fallback.** NEAR-served models can fall back to Chutes, which returns gateway signatures [C, code comment `inference_providers/src/lib.rs` ~585]. A client must treat a `gateway`-kind signature as a hard fail.
  - `moonshotai/kimi-k2.6` is labeled Chutes but has `base_url: https://openrouter.ai/api/v1` [C; what it means is unknown].
- **Signature retention.** The SDK default is 60 minutes; the agent skill says "persistent". Treat it as unknown and fetch immediately.
- **The official example repo** (`near-examples/nearai-cloud-verification-example`) doesn't verify the quote, `report_data`, RTMR3 or the compose hash [C].

### 1.3 Ecosystem pieces that matter
- **Keyless NEAR AI Cloud endpoints** [C]: `/v1/attestation/report` (nonce, `provider=near`, `include_tls_fingerprint`, `x-no-aliasing`), `/v1/model/list`, `/v1/attestation/pins`, `/v1/attestation/ita-token`.
  - Anonymous attestation is capped at 8 concurrent requests per gateway instance, then 429.
  - Reports requested with a nonce bypass the 10 s cache.
- **What needs a key:** inference and `/v1/signature/{id}` [C].
- **E2EE v2** [C]: per-field X25519 + XChaCha20, on chat, completions, embeddings and images. Not on the Responses API.
- **OHTTP** goes to the gateway only. With no third-party relay it gives no unlinkability [C, JS SDK docs].
- **Inference SDKs** for Python, JS, Rust and Go. The repo was pushed Nov 7 and has 0 stars, so expect churn [C].
- **Contracts** [C]: near-sdk 5.x, NEP-297 events (no storage cost), function-call keys, gas keys (NEP-611), yield/resume (NEP-519). Storage costs 1 NEAR per 100 KB.
- **On-chain DCAP** via the `shade-attestation` crate (dcap-qvl `contract` feature) is possible, but Shade is deprecated and gas costs are undocumented. Treat it as a stretch goal only [C/I].
- There is **no NEP** for TEE attestation or agent identity [C].

### 1.4 Competitive landscape
- [C] As of Nov 7: 258 submissions, 42 tagged privacy, 137 security (`GET /api/projects`). @near_ai counted 100 on Nov 3. [I] The final total will be several times larger.
- **Crowded** [C]:
  - "Analyze a document in the TEE plus a Verified panel" (the official expense-auditor prompt; Sealed Ledger is literally it).
  - Local placeholder redaction (Sealed Dossier, RedactGate, PrivatePay Agent, privacy-hybrid). NEAR's own `auto_redact` and `/v1/privacy/redact` make the basic version redundant.
  - TEE signatures anchored on-chain (TEE Receipts, Verdict, PredicTEE, Realsies).
  - AI judges in a TEE, payment firewalls, confidential intents, sealed disclosure.
- **Closest to the transparency-log idea, inside the hackathon:** TEE Receipts (signer-key history only), Measure (MPC nodes only), Verdict (one quote verified on-chain).
- **Outside the hackathon** [C]:
  - https://confidentialinference.net/weekly/1 : one independent monitor of NEAR's TEE models, off-chain.
  - Tinfoil: Rekor log plus freshness witnesses (https://docs.tinfoil.sh/verification/verification-in-tinfoil).
  - Phala's roadmap plans a deployment log (https://github.com/Dstack-TEE/private-ai-gateway/blob/main/docs/roadmap.md).
  - Brave's oracle, with a "public TEE key log" listed as unfinished (https://brave.com/blog/browser-ai-e2ee/).
  - C2SP tlog-witness, Apple PCC.
- **Open space** [I]: cross-session leakage budgets, records of what was withheld, independent continuous verification of runtime code, metadata unlinkability, behavioral tests of isolation.

### 1.5 What Muse Privacy and BASE actually implement
**Muse Privacy** (`~/muse-privacy`, `ethan/live`, public, no LICENSE)
- [C] What exists:
  - Rule detectors plus roster-based name matching.
  - A reversible, daily-rotating TagMap.
  - Floors that only tighten, a fail-closed `final_check`, receipts holding a sha256 of the outgoing text, a content-free audit.
  - An MCP connector with an OAuth relay (the Cloudflare one is live, the Modal one returns 404), 16 compliance presets, and an eval harness with McNemar comparisons.
  - 3931 tests collected; I did not run them.
- [C, repo-reported] Quality numbers:
  - Policy routing: 82% on a dev set, 65% on a 20-item holdout.
  - LFM3-VL-2B as router: 38%.
  - "Leaks" counts names and identifiers only.
  - No real users, and "Always approve" was on in live use.
  - Prompts and regexes are classroom-specific.
- [C] Eligibility: first commit Oct 27, which is after Oct 19, so it is technically in-window. But it was built for the Meta hackathon, which included a sole-ownership warranty (HANDOFF #15).

**BASE** (`~/base-subagent`, `base-agent-v0.1`, unmerged)
- [C] What exists:
  - A local MCP server with 8 tools: SQLite FTS5 memory and `ask_my_files`.
  - A secrets-only filter.
  - Per-agent permission groups and a content-free audit file with no tamper evidence.
  - A Cloudflare relay that sees plaintext.
- [C] What's missing:
  - It never calls a cloud model. Escalation code exists only in the old `prototype/bridge.py`, and goes to Anthropic or OpenRouter.
  - No NEAR code at all.
  - The real local/cloud router lives in `~/jetson-infra` (`POST /v1/route`).
  - The relay was deployed 2026-10-18, before the window.

---

## 2. All 12 concepts, compact

**B1 Base Escalate: Proof of Egress** [BASE]
- **Pitch:** Base answers locally. When a local answer isn't good enough, it escalates a minimized, E2EE question to a verified NEAR TEE model under a hashed policy, and anchors a receipt that the contract checks with `ed25519_verify`.
- **Problem / users:** Base and MCP users, compliance teams. Nobody can later prove what left the device, or what it went to.
- **Architecture:**
  - An `ask_private_cloud` MCP tool with an `escalate` permission.
  - A policy engine (canonical JSON, policy_hash).
  - A three-stage minimizer: secrets filter, OutboundGuard, local PAPILLON-style rewrite.
  - A fail-closed verifier, an E2EE client, a contract (`register_signer`, `register_policy`, `submit_receipt`) and a receipt viewer with replay.
- **NEAR tech:** attestation report, E2EE v2, `/v1/signature` `provider_tee` ed25519, near-sdk `ed25519_verify`, NEP-297, function-call keys.
- **Security:**
  - Proven: TDX, nonce freshness, key binding, signature over the gateway-relayed hash.
  - Software: minimization, budget, policy, ledger honesty.
  - Outside the TEE: runtime swaps, shared key, gateway metadata, semantic re-identification.
- **1 week:** verifier → E2EE → contract → tool and minimizer → budget UI → 50-item eval → README.
- **Demo:** a local answer gets a receipt, a consent card, the Verified panel ticks through, a testnet event fires, and two attacks are blocked (a non-TEE model and a flipped byte).
- **Risks:** too many components. Day 1 depends on whether the SDK exposes raw bytes.
- **Critique:** "Proof of Egress" overclaims. The on-chain check is circular, because an owner-only signer is registered from an evidence hash. The demo attacks are strawmen. Secure Minions already covers the core loop.

**B2 Base Recall Broker** [BASE]
- **Pitch:** many agents share one encrypted Base memory and get purpose-bound answers under grants recorded on NEAR. Memory consolidation runs in the TEE every night.
- **Architecture:** per-scope XChaCha encryption, a grant contract, a broker with NEP-413 signed requests, answer modes (fact, summary, yes/no), a night-shift E2EE consolidation, hourly Merkle receipts, a MEXTRA-style red team.
- **NEAR tech:** grants, NEP-297, NEP-413, implicit accounts, E2EE chat and embeddings, `provider_tee`.
- **Security:**
  - Proven: grants are owner-signed, encryption at rest, consolidation goes to the attested key.
  - Software: scoping, quotas, leak checks.
  - Outside: what the relay and vendor see, the device, inference across many answers.
- **1 week:** encryption migration, contract, broker, TEE call, Merkle log, red team.
- **Demo:** three agents, a denied scope, an injected Claude gets 3 facts, revocation within 4 s, a signed night-shift diff.
- **Critique:**
  - Cleartext grants on a public chain leak which sensitive scopes exist, which is a privacy regression.
  - The space is crowded (global-memory-mcp, UOMP, KASA, mnemo, SAIHM).
  - "0 vs 38/40 raw rows" is a strawman metric.
  - The MEXTRA citation is wrong (it is ACL 2025).
  - The least feasible of the twelve.

**B3 Base Witness** [BASE]
- **Pitch:** every Base device becomes a witness that logs on NEAR what each NEAR AI TEE model is actually running. Base escalates only to model states a quorum has accepted.
- **Architecture:**
  - A witness module in base-agent: nonce from a block hash, full verification, a state tuple (measurements, signing key, compose-manager digest, service file@commit, SPKI), then a provenance check against cvm-compose-files and cosign.
  - A registry contract (`observe` with `ed25519_verify`, status pending / accepted / contested / revoked), a cooling-off period, an escalation gate and a watchtower page.
  - Witnesses: laptop, cloud cron, a jetson via the fleet.
- **NEAR tech:** keyless attestation, `compose_manager_attestation`, `ed25519_verify`, NEP-297, view calls, function-call keys, block hashes.
- **Security:**
  - Proven: witness signatures, append-only history, each witness's own nonce-fresh quote check.
  - Software: provenance, quorum, cooldown, witness honesty.
  - Outside: a compose-manager that lies consistently, physical attacks, KMS, collusion among witnesses.
- **1 week:** harden the verifier, provenance, contract, 3 witnesses plus the gate, watchtower, collect data, README. The cheapest of the twelve.
- **Demo:** a real a320bb→a0c073 timeline, "observe now" with 3/3 witnesses, a contested flip, Base holding the request.
- **Risks:** the jetson depends on the fleet. There may be zero live drift during the week.
- **Critique:**
  - All witnesses belong to one owner.
  - Nothing binds the observation to the instance that serves the request, and there is a TOCTOU gap.
  - The "replayed report" demo step would fail the nonce check, so it has to be mocked.
  - "Contested" will false-positive on rolling deploys. Key states by (model, instance_id) instead.

**M1 Sealed Second Opinion** [Muse]
- **Pitch:** a NEAR TEE model acts as Muse Privacy's disclosure judge for uncertain items, not as the answerer. Local floors re-check its rewrite and can only make it stricter.
- **Architecture:**
  - A new `AttestedBackend` (about 600 lines): full verification including compose-manager service pinning, E2EE, a `provider_tee` check.
  - Strict-JSON router output, local re-check, extended receipts, a small `muse-policy` contract, and an A/B eval with a re-identification metric.
- **NEAR tech:** attestation, E2EE v2, `provider_tee` ed25519, near-sdk `ed25519_verify`, NEP-297.
- **Security:**
  - Proven: TDX, key binding, E2EE content.
  - Software: floors, the actions log.
  - Outside: shared key, runtime swaps, gateway metadata, whatever the frontier agent receives.
- **1 week:** verifier, backend, router wiring, contract, eval (under $2), UI and replay, disclosure. Uses about 3.9k existing tests.
- **Demo:** the local router re-identifies "the student whose dad was deployed", the TEE rewrite drops it, then the eval table.
- **Critique:** it claims `provider_tee` proves the body was unmodified, which is false. Secure Minions and PAPILLON are prior art. The contract is thin. It carries Meta-warranty and baseline risk. No critique pass was run.

**M2 Disclosure Allowance** [Muse]
- **Pitch:** a rolling 30-day, per-person budget of quasi-identifying attributes, plus a hash-chained, NEAR-anchored ledger of what was released and what was withheld.
- **Architecture:** an attribute accountant (rules plus TEE extraction), a budget engine as a floor, a Merkle ledger, `allowance.testnet` (guardian policy, `post_root`, `spot_check`), an auditor CLI, and a longitudinal linkage attack eval.
- **NEAR tech:** as M1, plus scoped function-call keys and NEP-413 or a guardian transaction.
- **Security:**
  - Proven: the ledger is immutable after anchoring, the policy is guardian-signed, sampled signatures check out.
  - Software: budget math, honest logging (the device can omit entries before anchoring), extraction accuracy.
  - Outside: device compromise, stylistic linkage.
- **1 week:** taxonomy and generator, TEE extraction, budget, ledger and contract, auditor and eval, UI, disclosure.
- **Demo:** 30 simulated days, the adversary links 9 of 25 without the allowance and 1 of 25 with it, a parent-side audit, a tamper check fails.
- **Critique:** extraction accuracy decides everything. Rarity weights from 25 students are crude. Classroom-only. Same baseline issues as M1. No critique pass was run.

**C1 Purpose-Bound Recall** [Combined]
- **Pitch:** BASE memory plus Muse egress plus TEE synthesis. Cloud agents query memory only under purpose grants. The frontier model never sees the memory set.
- **Architecture:** extract `muse_egress` as a library, a people index, purpose grants mirrored on-chain as hashes, a `recall()` tool with E2EE synthesis, E2EE embeddings, an extraction eval.
- **Security:**
  - Proven: synthesis inputs go only to the attested key, grants are user-signed.
  - Software: purpose adherence, floors.
  - Outside: the relay sees minimized answers in plaintext, embedding vectors stored locally.
- **1 week:** the largest scope of all, across two repos (one unmerged).
- **Demo:** a hiring grant, 41 memories, an injection refused, revocation on the phone.
- **Critique:** the purpose prompt is injectable, the roster-tuned guard will recall poorly on free-form notes, prior art is crowded, and two baselines need disclosure. Delivery unlikely.

**C2 Tripwire** [Combined]
- **Pitch:** a transparency log with a quarantine, where the jetson-infra router, Muse egress and BASE fail closed on immature model states.
- **Architecture:** hourly watchers (Pi plus Modal or the laptop), an A to F linter, a `tripwire` contract (report, corroborate, challenge, status, quarantine), full reports content-addressed off-chain, three consumers, a timeline page.
- **Security:** like B3, plus re-verifiable mirrored reports and consumers that check per session.
- **1 week:** state extraction, linter, contract, Pi watcher, consumer gates, page, README.
- **Demo:** a week of hourly history, the real Nov 4 entry, a simulated swap held on a jetson, a challenge.
- **Critique:**
  - Same holes as B3, plus fragile dependencies (Pi, ngrok, three repos).
  - It still says actions_hash is unreproducible, which is outdated.
  - The diplomatic framing toward NEAR is risky.

**N1 Tidemark** [New]
- **Pitch:** Certificate Transparency for private inference. Collectors fully verify each attestation. Every change to measurements, signer or runtime code goes into a NEAR contract with witness co-signatures. A drop-in guard for the OpenAI SDK blocks requests to states that are not logged or are still inside the cooldown.
- **Architecture:**
  - Collectors on GitHub Actions and the laptop.
  - A 10-check verifier with a verdict bitmap, including the compose-manager quote and actions, and a cvm-compose-files diff.
  - A normalizer, a log contract (propose, cosign, flag, k-of-n, storage only on transitions), `tidemark-guard` (npm and pip), a Next.js dashboard.
- **NEAR tech:** keyless attestation, model list, pins, `/v1/signature`, near-sdk, NEP-297, function-call keys, block-hash nonces.
- **Security:**
  - Proven: genuine nonce-fresh quotes, k witness keys, append-only history, the response signature.
  - Software: cooldown, flags, witness honesty, honesty of the actions log.
  - Outside: physical attacks, gateway plaintext and logs, unmeasured env, shared key, whether the code is any good.
- **1 week:** verifier → 18 models → contract → guards and a mock gateway → dashboard and witnesses → README → video.
- **Demo:** `tidemark watch` grades the models, the real drift timeline, a green guarded chat, the mock swap blocked "before any byte is sent", a judge runs `npx tidemark verify --replay`.
- **Risks:** scope (18 models, Chutes and Tinfoil, two guards), same-connection SPKI capture.
- **Critique:** witnesses are not independent, TOCTOU and no binding to the serving instance, outdated on actions_hash, prior art (Tinfoil, confidentialinference.net, Brave).

**N2 Overlap** [New]
- **Pitch:** rival parties seal briefs to an attested model. One stateless call returns a bounded verdict. A contract enforces commitments and a re-query budget.
- **Architecture:** the contract holds rooms, mechanism hashes and commitments. Party clients E2EE their briefs. An untrusted coordinator builds one request with a strict schema. The contract verifies the signature and checks the commitments appear in the request bytes. A MAGPIE-style eval.
- **Security as claimed:**
  - Proven: nobody but the model sees the briefs, signed inclusion, an enforced budget.
  - Software: the model follows the mechanism, statelessness.
  - Outside: metadata, outcome leakage, swaps.
- **1 week:** a two-party PoC on Day 1, contract, clients, mechanisms, eval, replay.
- **Demo:** a salary split screen, Seal, a ciphertext-only coordinator log, "Deal: 140 to 145k", the re-run refused, the leakage chart.
- **Critique (I agree with the security judge, and it is fatal):** the briefs are encrypted to the shared model key with no binding to the room or mechanism. Anyone who holds a ciphertext (the coordinator assembles every request) can resubmit it off-chain with their own system prompt and their own `X-Client-Pub-Key`, and read the plaintext answer. The on-chain budget only governs runs that get posted. The byte-inclusion check runs over bytes the gateway re-serializes, so it does not prove what the model processed.

**N3 Ferryman** [New]
- **Pitch:** an OHTTP relay registered on NEAR with a pooled key and blind-RSA tokens, plus E2EE to the model. The relay learns who asked but not what; the gateway learns neither.
- **Architecture:** a registry and token contract, a TS SDK that checks the OHTTP key config against the attested gateway key, a Cloudflare Worker relay with a spent-set, padding and jitter.
- **Security:**
  - Proven: HPKE to an attested gateway key, E2EE, blind tokens.
  - Software: relay keeps no logs, stake.
  - Outside: relay and gateway collusion, a small anonymity set.
- **1 week:** OHTTP spike, Worker, tokens and contract, SDK, a second relay, demo.
- **Demo:** a three-column "who sees what" view, a token unlinkable to the purchase, a malicious relay caught.
- **Critique:** the core is unconfirmed (outer auth from a third party, E2EE inside OHTTP). An anonymity set of one in the demo shows nothing. It mostly assembles known designs. Delivery unlikely.

**U1 Parallax** [Unconventional]
- **Pitch:** time nonce-bound attestation round trips from several regions. Since a nonce-bound quote cannot be produced faster than light travels, each round trip gives an upper bound on distance to the gateway, the model CVM and the GPUs. Post the bounds to NEAR.
- **Architecture:** witnesses (laptop, Vercel regions, GitHub Actions) on warm TLS connections, a geometry engine, a contract (minimum RTT, regions, `claim` → CONTRADICTED), a globe UI.
- **Security:**
  - Physically enforced: delay can only loosen a bound, never tighten it.
  - Software: calibration, witness honesty.
  - Outside: resolution is coarse, the shared TLS key, GPUs only shown to be near the CVM, not inside it.
- **1 week:** RTT measurement, regional witnesses, contract, globe, borrowed-GPU simulator, `npx parallax witness`.
- **Demo:** rings shrink on the globe, a fake Frankfurt claim is contradicted, a judge's own ring appears.
- **Critique:** quote generation plus GPU evidence plus the gateway-to-model hop may add hundreds of ms, which means continent-scale bounds. Platform identity from the PCK chain is speculative. NEAR's role is thin.

**U2 Tenant Zero** [Unconventional]
- **Pitch:** probe agents in separate orgs run canary-only, preregistered tests of privacy *behavior* (cross-tenant prefix-cache isolation first), with each verdict pinned on NEAR to the measurement that was live.
- **Architecture:**
  - Planter, prober and control roles.
  - P1: cache isolation via `cached_tokens` and time-to-first-token, with Mann-Whitney statistics and a positive control from the same org.
  - P2: signature lifetime. P3: alias pinning. P4: route consistency.
  - Measurement brackets before and after each round. A contract with preregister, report and sealed disclosure. A property matrix.
- **Security:**
  - Proven: block-derived canaries, preregistration ordering, signatures pinned to measurements.
  - Statistical: PASS means "nothing detected at this power".
  - Outside: untested channels and configurations.
- **1 week:** pilot with 2 keys, harness, contract, P2 to P4, scheduler, dashboard. About $0.10 of inference.
- **Demo:** run P1 live, the positive control separates, the cross-org distributions overlap, the 61-minute signature 404.
- **Critique:** needs two orgs' credits. `cached_tokens` may not be exposed. Optics of probing the sponsor whose founder is a judge. Prior art in prompt-cache audits (the security judge cites Gu et al. 2025; I did not verify it).

---

## 3. Scoring table (each criterion averaged across the 3 judges)

The criterion letters are the judges' own. The score maxima suggest something like novelty, demo/design, verifiability/security, feasibility and NEAR fit, but I wasn't given the rubric weights. For the qualitative columns I show the majority view, with any outlier in parentheses.

| id | name | cat | N | D | V | F | NEAR | mean | complexity | uncertainty | demo | security cred. | auto-eval risk | delivery |
|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|
| N1 | Tidemark | New | 15.7 | 18.3 | 15.0 | 14.7 | 9.0 | **72.7** | medium (1 high) | medium | strong | ok (1 strong) | low (1 medium) | likely (1 possible) |
| N2 | Overlap | New | 20.0 | 15.0 | 16.7 | 10.3 | 7.3 | **69.3** | high | high | exceptional (1 strong) | split: weak / strong / ok | medium (1 high) | possible |
| B3 | Base Witness | BASE | 15.3 | 16.7 | 13.3 | 15.3 | 8.0 | **68.7** | medium | medium | ok (1 strong) | ok | medium | likely |
| U2 | Tenant Zero | Unconv | 19.7 | 17.0 | 13.0 | 12.3 | 6.3 | **68.3** | medium | high (1 medium) | strong (1 ok) | strong (1 ok) | medium | possible (1 likely) |
| U1 | Parallax | Unconv | 22.3 | 14.0 | 13.7 | 12.0 | 5.3 | **67.3** | medium | high (1 medium) | exceptional (1 strong) | split: strong / ok / weak | medium | possible (1 likely) |
| M2 | Disclosure Allowance | Muse | 17.3 | 15.7 | 15.3 | 11.0 | 7.3 | **66.7** | high | medium (1 high) | strong | ok | medium | possible |
| M1 | Sealed Second Opinion | Muse | 13.0 | 17.0 | 15.3 | 13.7 | 6.7 | **65.7** | high | medium | strong | ok (1 strong) | medium | possible (1 likely) |
| C2 | Tripwire | Combined | 14.7 | 16.7 | 14.3 | 10.0 | 8.3 | **64.0** | high (1 very high) | medium (1 high) | strong | ok | medium (1 high) | possible |
| N3 | Ferryman | New | 16.0 | 18.3 | 13.7 | 8.0 | 6.7 | **62.7** | very high (1 high) | high | strong | strong (1 ok) | high | unlikely (1 possible) |
| B1 | Base Escalate | BASE | 10.7 | 14.7 | 13.3 | 9.0 | 7.3 | **55.0** | very high | high | ok | weak | high | unlikely (1 possible) |
| C1 | Purpose-Bound Recall | Combined | 11.3 | 13.0 | 13.7 | 5.0 | 6.3 | **49.3** | very high | high | ok (1 strong) | weak (1 ok) | high | unlikely |
| B2 | Base Recall Broker | BASE | 9.0 | 10.0 | 12.0 | 4.7 | 6.0 | **41.7** | very high | high | ok | weak | high | unlikely |

**Where the judges disagreed sharply**
- **N2, 22-point spread (57 vs 79; D 8 vs 20).** The security judge found the ciphertext-replay flaw; the others scored the design as described. I side with the security judge. The flaw comes straight from how E2EE v2 works (no binding to room or mechanism), so the high mean overstates N2.
- **U1, 11-point spread (60 vs 71; security weak vs strong).** The disagreement is about whether the physics bounds will be useful. Nobody has measured the minimum round trip yet. That is a Day-1 fact, not a matter of opinion.
- **N3, 14-point spread (55 vs 69).** The security judge scored the cryptography as unconfirmed; the others credited the design. All three agree delivery is unlikely.
- **U2 novelty, 16 vs 22.** The difference is prior art in prompt-cache auditing.
- **N1, 10-point spread (67 vs 77).** The security judge rated complexity high and delivery only possible, because of the 18-model, two-guard scope. Trimming the scope fixes that.
- **Shared blind spots.** Two judges docked N1 and C2 for treating actions_hash as unreproducible. It is reproducible, so that criticism is outdated and easy to fix. M1, M2, C1, C2, N1, N2, N3, U1 and U2 had no critique pass, so their scores faced less adversarial scrutiny than B1, B2 and B3 did.

---

## 4. Top 5

**1. N1 Tidemark (72.7).** It is the cleanest product framing of the one finding this research confirmed live and that nobody else in the field ships: the model's serving code changes outside the measurement while compose_hash stays put. The core is keyless and free, judges can rerun it, and it builds on a verifier that already passed live checks. It is all new code, so there is no baseline-disclosure baggage. Its weaknesses are real but fixable within the week:
- witnesses that all belong to one person;
- TOCTOU, and no binding to the serving instance;
- too much scope;
- prior art that narrows the novelty to "on-chain, multi-witness, enforced by consumers".

**2. N2 Overlap (69.3).** It has the most intuitive demo and the most original use of a stateless attested call. But on NEAR AI Cloud as it exists, the central guarantee doesn't hold. Ciphertexts encrypted to a shared model key can be replayed off-chain by whoever assembles the request. The byte-inclusion proof runs over a hash the gateway relays. Rescuing it means building your own enclave that holds a key per room, which is a different and larger project. Not recommended as specified.

**3. B3 Base Witness (68.7).** The same core idea as N1, framed through Base devices. It is the cheapest concept, and its premise and provenance matching are verified. It loses to N1 on product framing (there is no general-purpose guard), it depends on the fleet for the jetson witness, the base-agent-v0.1 baseline is unmerged and needs separating, and its "contested" rule and replayed-report demo step are both flawed. Its fixes (key states by instance_id, archive the full reports, redefine anomalies) should be folded into N1.

**4. U2 Tenant Zero (68.3).** It is the most distinctive idea that is genuinely independent of the log concept: behavioral attestation, preregistered on-chain, with a positive control. It costs almost nothing. The weak points:
- it needs credits for two orgs;
- `cached_tokens` may not be exposed, and timing alone may leave the test underpowered;
- a PASS is undramatic, and a FAIL has to stay sealed through judging;
- probing the sponsor's infrastructure while its founder judges carries optics risk.

P2 and P3 are cheap, near-certain results.

**5. U1 Parallax (67.3).** The most original idea of the twelve, with the best demo mechanic: a judge runs one command and their ring appears on the globe. Its value depends entirely on an unmeasured number, the minimum round trip including quote generation. If that is tens of ms or more, the bounds are continent-scale and the security story collapses into a visualization. NEAR's role is a thin store of events.

---

## 5. Deep comparison of the top 3 (N1, N2, B3)

N1 and B3 are the same primitive. In practice the choice is between the log (in N1 or B3 framing) and N2. U2 is the strongest distinct alternative.

### 5.1 N1 Tidemark

**Serious technical criticism**
- **Witnesses aren't independent.** GitHub Actions and the laptop belong to one builder, so "k-of-n" proves only one person's machines agree. Equivocation targeted by API key or org can't be seen by keyless witnesses.
- **TOCTOU.** The guard's pre-check and the completion are separate requests, and compose-manager can swap in between. The completion may also hit a different instance (the key is shared).
- **The actions log is written by software.** A compose-manager that is malicious but CI-signed can leave entries out. And `provenance_ok` will be true for anything NEAR's CI ships, because NEAR controls both the repo and the cosign identity.
- **Scope.** 18 models plus Chutes and Tinfoil shapes plus guards in JS and Python is too much.
- **Prior art.** confidentialinference.net already monitors this exact target off-chain. Tinfoil ships the vendor-side equivalent. Phala plans one.

**Proven, software-enforced, outside the TEE**
- **Cryptographically proven:**
  - Each observation is a genuine, current-TCB, non-debug TDX quote whose nonce was derived from NEAR block N. Its on-chain inclusion at block M bounds it in time to the window [N, M], and anyone can check that.
  - The compose-manager quote binds the full actions log to the same CVM via a reproducible actions_hash.
  - Witness signatures are verified on-chain with `ed25519_verify`.
  - The history is append-only.
  - In the guard: the response is signed by the attested key over the gateway-relayed request hash and the response hash. With E2EE, only the holder of the attested key can read the content.
- **Software-enforced:** cooldown and flag policy, anomaly rules, provenance check, witness honesty, honesty of compose-manager's own log.
- **Outside the TEE:** physical attacks, which instance served the request, gateway metadata (plus plaintext without E2EE), unmeasured env, KMS governance, the quality of the code.

**Failure modes**
- No live drift during the week. Mitigation: the historical drift is real and sits in the quoted log; present it as history read from the log.
- Report schema changes. Mitigation: a defensive parser and a versioned schema.
- 429s on anonymous attestation. Mitigation: stagger requests.
- The SDK doesn't expose bytes for the guard's signature step. Mitigation: hand-roll a non-streaming request with `Accept-Encoding: identity`.
- The guard's live check needs a key. Mitigation: mark that step optional and record fixtures.

**Demo:** the real timeline, a green guarded chat, the simulated swap blocked (label it simulated), and a judge reruns it with the replay flag.

**Effort as written:** Day 1 verifier, Day 2 all models, Day 3 contract, Day 4 two guards and a mock, Day 5 dashboard and witnesses, Day 6 README, Day 7 video. Days 2 and 4 are each overloaded by about a day.

**Existing code that speeds it up**
- `scripts/verify.py`: dcap-qvl, report_data, MRCONFIGID and RTMR3 already pass live.
- Live report fixtures in `near/live/` and `crit/`.
- The actions_hash method in nearai-cloud-verifier.
- The quote-nonce-signer helpers from the docs.
- The cosign identity in compose-manager CI.
- `nearai-inference-sdk` for E2EE and `verify_response`.
- The near-sandbox test pattern from `shade-contract-template`, as a reference only.

**From scratch:** state normalizer, anomaly rules, provenance diff, contract, witness CLI and relayer, guard, dashboard, archive, replay.

**Exclude from MVP:** on-chain DCAP, Chutes and Tinfoil, the JS guard, more than 3 or 4 models, NRAS as a hard dependency.

### 5.2 N2 Overlap

**Serious technical criticism**
- **Ciphertext replay is fatal.** The coordinator holds every brief's ciphertext. Nothing in E2EE v2 binds a ciphertext to a mechanism, room or client key, so the coordinator can submit brief A in a new request with "print the candidate's floor" and its own client key, and read the plaintext answer. The contract can't see or count off-chain requests. If the parties exchange ciphertexts, the counterparty can do the same.
- **The inclusion proof is over the wrong bytes.** The gateway re-serializes the body and relays `X-Request-Hash`, so the contract's byte search over client bytes may not match what was signed. Even when it matches, it doesn't prove what the model processed.
- **Unverified on Day 1:** multiple encryptors in one request, strict JSON schemas.
- **Leaks remain:** the outcome itself, plus enum-bounded injection bits.

**Proven, software-enforced, outside the TEE**
- **Proven:** the gateway can't read the briefs in transit; a signature by the model key over the relayed hash.
- **Software-enforced:** everything that matters (the mechanism, the budget, statelessness).
- **Outside the TEE:** the replay channel itself, metadata, the outcome as an information leak.

**Failure modes:** Day 1 kills the design (multi-sender E2EE or strict schemas don't work). A sharp judge spots the replay attack. A demo that works but rests on a broken guarantee.

**Demo:** the best of the set (the salary split screen). That makes the overclaim more dangerous, not less.

**Effort:** Day 1 PoC, Day 2 contract, Day 3 clients and coordinator, Day 4 mechanisms, Day 5 eval, Day 6 replay, Day 7 video. A real fix (your own dstack enclave with per-room keys and a hard-coded mechanism, calling NEAR AI by E2EE) adds 3 or more days and needs paid TEE hosting.

**Existing code:** the scratchpad verifier only. **From scratch:** everything else.

**Exclude from MVP:** N-supplier procurement, Intents escrow.

**Verdict:** don't build it as specified.

### 5.3 B3 Base Witness

**Serious technical criticism**
- Everything listed for N1, plus:
- the "contested" state as defined (different states in the same window) fires on every normal rollout;
- the replayed-report demo step contradicts its own freshness check;
- a jetson witness reached through the Pi control plane over ngrok adds a single point of failure;
- the escalation gate needs a paid key and an unmerged branch.

**Proven, software-enforced, outside:** same as N1. **Failure modes:** the same as N1, plus fleet downtime and baseline confusion over base-agent-v0.1 (Q-003).

**Effort:** Day 1 witness library, Day 2 provenance, Day 3 contract, Day 4 daemon plus 3 witnesses plus the gate, Day 5 watchtower, Day 6 data collection, Day 7 README. Realistic, with the jetson as the one at-risk item.

**Existing code:** the scratchpad verifier and the fixtures. The base-agent MCP server as the consumer (baseline, needs disclosure).

**From scratch:** the witness module, contract and watchtower.

**Exclude from MVP:** the jetson witness, phone alerts, the Base escalation gate.

**Bottom line:** B3's verified facts and fixes are worth more than its framing. Merge them into N1.

**Distinct runner-up (U2):** if you'd rather not build infrastructure, U2 is the only top concept independent of the log idea. Its downsides (credits for two orgs, optics, a likely undramatic PASS) make it a weaker primary bet than the refined N1.

---

## 6. Recommendation: build a refined Tidemark

This is a **refined merge**, and I'm saying so explicitly: N1's product framing, B3's verified facts and fixes, and U1's "a judge becomes a witness" demo mechanic.

**What changes from N1 as written**
1. **Instances and anomalies.** Key on-chain state by (model, instance_id). Replace "different states" with real anomalies:
   - a measurement or signer change;
   - an actions log for the same instance that isn't a prefix extension of the previous one (rollback or rewritten history);
   - a running file with no public commit in cvm-compose-files;
   - a compose-manager digest without the expected cosign identity;
   - a TCB downgrade;
   - a `gateway`-kind signature on a model that should be `provider_tee`.
2. **Re-verifiable by strangers.** Each observation commits by content hash to the full quote, event_log, app_compose and compose-manager actions, archived in the repo or a release. Only the hash and a compact tuple go on-chain. Reproduce actions_hash, which corrects the brief.
3. **Independent witnesses.** Run registered witnesses (GitHub Actions in 2 or 3 regions, plus the laptop), plus an open `uvx tidemark witness` that anyone, judges included, can run. It signs an observation with a local ed25519 key and posts it through a relayer, so no NEAR account is needed. Show community witnesses as a separate tier, and recruit at least one outside operator if Ethan agrees.
4. **Guard brackets the request.** Nonce-fresh attestation before the request, E2EE to the attested key, a check that the signature kind is `provider_tee`, then a second nonce-fresh attestation after. The request passes only if both brackets show a logged, matured, unflagged state. This narrows the TOCTOU gap without removing it. Say plainly that it detects problems; it doesn't prevent them, and it can't identify the serving instance.
5. **Trimmed scope.** The gateway plus 3 NEAR-operated models (glm-5.3-flash, Qwen3.8-27B, DeepSeek-V4.1-Flash-1017). A Python guard only. Chutes and Tinfoil out.
6. **Honest README.** A guarantees table (proven, software-enforced, outside), a comparison with confidentialinference.net, Tinfoil, Brave, Phala, TEE Receipts and Measure, and every simulated element labeled "SIMULATED".

**Why it beats the others**
- **Only real, confirmed findings.** It is the only top concept whose headline fact (code swapped outside the measurement) and whose mechanism (reproducible actions_hash, provenance matching) are both confirmed live. Nothing load-bearing is speculative.
- **Highest feasibility on all-new code.** No Meta warranty question, and no unmerged-branch baseline.
- **Keyless core.** The AI screener and human judges can run it for free, which addresses the main pattern by which projects fail.
- **What disqualifies the others:**
  - N2 has a cryptographic flaw.
  - B3 and C2 are the same idea with weaker framing and fleet dependencies.
  - U2 has optics risk and a likely undramatic result.
  - U1's bound quality is unmeasured.
  - M1 and M2 sit in the crowded redaction space and carry ownership risk.
  - B1, B2 and C1 are overscoped and overclaim.

**Why it could win (no probability claimed)**
- Judges will see the same "Verified" badge dozens of times. Tidemark's message is "every badge checks one moment; here is the history, and here is the change none of them would have caught."
- That speaks directly to NEAR AI's own "Assume we're lying" post, and to the transparency log Brave publicly lists as unfinished.
- It is infrastructure every other privacy entry could use.
- The on-chain part does real work: the guard reads it before every request.

**Honest caveat:** Grand Prize judges are mostly investors. An infrastructure entry has to make the stakes concrete for them, and first place in the privacy track is the more realistic target.

**What judges would find interesting**
- A verified, real finding about the sponsor's own stack, presented constructively.
- Time windows bounded by the chain.
- Judges themselves acting as independent witnesses.
- A "blocked before any byte was sent" moment.
- An unusually honest table of limits.

**The NEAR functionality that makes it special**
- **NEAR block hashes as public nonce sources:** an observation provably can't predate block N, and inclusion bounds it to block M.
- **`env::ed25519_verify`** (stable) for witness signatures and response signatures, since the model keys are ed25519.
- **NEP-297 events** for cheap repeat sightings, with storage paid only on state transitions (about 0.003 NEAR each).
- **View calls** read by the guard before every request.
- **Function-call keys** for each witness.
- **On the NEAR AI Cloud side:** keyless nonce-bound reports, `compose_manager_attestation`, `x-no-aliasing`, `include_tls_fingerprint`, E2EE v2 and `provider_tee` signatures.

**Demo plan (about 90 s)**
1. Dashboard for glm-5.3-flash. The real compose-manager digest change a320bb → a0c073 (Oct 29, Nov 4) with compose_hash unchanged. Each step links to its cvm-compose-files commit, archived quote and testnet transaction. Caption: "reconstructed from the hardware-quoted actions log."
2. One line: "Every Verified badge you've seen today would have passed both states."
3. A judge runs `uvx tidemark witness`. Their co-signature appears within about 2 blocks, with its [block N, block M] window shown.
4. A real chat through `tidemark-guard`: pre-check, E2EE, `provider_tee` verified, post-check on the same state.
5. Point the guard at the mock gateway (labeled SIMULATED) serving an unlogged digest. It is blocked before sending: "compose-manager a1f… unseen in log, cooldown 24h."
6. Flip one byte of an archived quote. Re-verification fails.

**Day plan**
- **Nov 8:** move the scratchpad verifier and fixtures into the repo, reproduce actions_hash, define the state tuple, pin Intel PCS.
- **Nov 9:** anomaly rules, provenance (GitHub API plus cosign), content-addressed archive.
- **Nov 10:** contract (`register_witness`, `observe`, `status`, `flag`) with sandbox tests, testnet deploy (needs Ethan's account).
- **Nov 11:** Actions witnesses start building hourly history; open witness CLI and relayer.
- **Nov 12:** guard with brackets (key needed for the live part), mock gateway.
- **Nov 13:** static dashboard, replay mode, README for the AI judge, LICENSE, disclosures.
- **Nov 14:** video, Ethan's X post, submission JSON shown to Ethan for a yes, `hackathon-submission` tag before 23:59Z.

**MVP exclusions:** on-chain DCAP, Chutes and Tinfoil, the JS guard, NRAS as a hard requirement, OHTTP, phone alerts, A to F grades beyond a simple pass/flag, Base, Muse and jetson consumers (a natural integration for Base after the hackathon), U2-style behavioral probes, Parallax geometry.

---

## 7. Second-submission opportunity

**What the rules allow:** yes. [C] A person may be in 2 projects if they are independent and each README names the other (Q-015). Each email can file 2 submissions, and each repo must be unique.

**Is it realistic?** Only conditionally. With one solo builder and 7 days, the refined Tidemark plan already uses the whole week, and a weak second entry splits attention without adding much.

**The candidates**
- **Parallax:** keyless and conceptually distinct. But it reuses attestation-fetch logic, which strains "independent", and its value depends on an unmeasured round-trip floor.
- **Tenant Zero:** cheap in tokens, but needs credits for a second org, carries optics risk, and a FAIL result has to stay sealed.

**My recommendation:** don't plan one. Revisit at the end of Nov 10 only if Tidemark's contract and collectors are live. Then spend at most 2 hours on a Parallax spike measuring minimum round trips from 2 or 3 regions, and continue only if the bounds come out regional rather than continental. Write it as a separate codebase, not a shared library.

---

## 8. Open questions for Ethan (decision-relevant only)

1. **NEAR AI Cloud API key.** Will you claim the $10 NEAR Builders credit (https://nearbuilders.org/join) and create an `sk-` key? Only the guard's live E2EE and signature step needs it; everything else is keyless. I can't create accounts or keys.
2. **NEAR accounts.** You need a testnet account to deploy the contract and fund the relayer, and a mainnet account for the payout field. You have to create both.
3. **Go / no-go on the refined Tidemark,** in a new repo. Which owner (Offline-Base org or personal) and which license (Apache-2.0 or MIT)?
4. **Prior-code disclosure.** The plan uses only the verifier and fixtures written Nov 7 (in-window) plus public libraries, with no Muse or BASE code. Do you agree? If you'd rather build M1 or M2, you first need to settle whether the Meta sole-ownership warranty (Muse HANDOFF #15) conflicts with entering it here.
5. **Diplomacy.** May I draft a short heads-up to NEAR AI before publishing? It would cover `MIN_TAG_AGE_HOURS=0`, the runtime swaps, and the kimi-k2.6 OpenRouter `base_url`. Do you want the kimi item in the demo at all, given that what it means is unverified?
6. **Outside witnesses.** May we invite other teams or the confidentialinference.net author to run a witness? This is the main fix for the independence criticism. You would do the outreach.
7. **Tracks to select.** Privacy plus security plus open is my suggestion; swarms would be a stretch. Do you want to mention OfflineBase or Base in the pitch?
8. **Hosting.** Should the dashboard go on Vercel (which team?) and stay up through Nov 25?