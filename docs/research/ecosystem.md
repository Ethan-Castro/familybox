# NEAR ecosystem for private and verifiable AI agents: status as of 2026-11-07

Every claim below is tagged **[C]** (confirmed: I saw it at the URL or file named) or **[I]** (inferred or speculation). The research was read-only. The only network calls were free, unauthenticated GETs, mainly `cloud-api.near.ai/v1/attestation/report` and `/v1/model/list`. I spent nothing, created no accounts and published nothing.

---

## 0. Summary for planners

- **NEAR AI Cloud is the production base layer** [C]. It is OpenAI-compatible, runs models in Intel TDX plus NVIDIA confidential GPUs, and gives per-response ECDSA or Ed25519 signatures. Official SDKs exist for JS, Python, Rust and Go.
  - Only **18 of 64** listed models are marked `verifiable: true` [C, probe of `/v1/model/list`]. The Anthropic, OpenAI and Gemini models are proxied and not TEE-verifiable.
- **Shade Agents are deprecated** [C]. https://docs.near.org/ai/shade-agents/getting-started/introduction says that after 2026-04-19 the framework is no longer maintained. Docs moved to `github.com/NearDeFi/shade-agent-framework/docs`.
  - Its **`shade-attestation` crate**, which runs TDX DCAP quote verification on-chain via `dcap-qvl` with the `contract` feature, is still the most reusable building block for an on-chain attestation registry [C, repo Cargo.toml].
- **The most meaningful combination** is an on-chain registry of attested model signing keys plus an on-chain verifier for the `provider_tee` response signatures NEAR AI already produces. Contracts can do the check with `env::ecrecover` and `keccak256`. This is feasible in one week on testnet, with caveats in section 9 [I, built from confirmed parts].
- **NEAR Intents has no testnet and never will** [C, FAQ]. Any real agent payment demo spends mainnet money. Under no-spend rules, limit Intents work to `dry: true` quotes and design.
- **The old NEAR AI Hub / agent registry (`nearai/nearai`) is archived** and marked "Deprecated" (pushed 2025-12-16) [C, GitHub API]. The current agent products are **IronClaw** (runtime) and **Agent Market** (market.near.ai, jobs, escrow, x402).

---

## 1. NEAR AI Cloud (private inference)

**Status: production [C].** Launched 2025-12-03 (near.ai/blog/introducing-near-ai-cloud-private-chat). Base URL `https://cloud-api.near.ai/v1`.

**Hardware and stack [C]** (docs.near.ai/cloud/private-inference):
- Private LLM Nodes have 8x H200 GPUs, TDX CVMs and the Private-ML-SDK.
- The gateway runs in its own TEE.

**Live probe of `/v1/attestation/report`** (`model=z-ai/glm-5.3-flash`, `provider=near`, `signing_algo=ecdsa`, no key) [C]:
- Returned HTTP 200, about 312 KB.
- Contains `gateway_attestation` (gateway `app_name` "dstack-0.5.12") and `model_attestations[]`. The model's `app_compose` name is "dstack-nvidia-0.5.11".
- Each attestation carries `intel_quote` (about 5,006 bytes), `event_log`, `tcb_info` (mrtd, rtmr0-3, compose_hash, os_image_hash), `signing_address`, `signing_public_key` and `nvidia_payload`.
- So NEAR AI Cloud runs on **Phala's dstack** [C].

**report_data layout [C]** (docs.near.ai/cloud/verification/reference/quote-nonce-signer):
- 64 bytes: first 32 are the signing identity (ECDSA address zero-padded, or the Ed25519 public key), last 32 are the client nonce.
- With TLS binding, the first 32 are `SHA-256(identity||tls_spki_fp)`.
- MRCONFIGID is `01 || sha256(app_compose) || 15 zero bytes`.
- RTMR3 is replayed from the event log with SHA-384.
- The probe matched this: `report_data` = signing address + zero padding + the nonce I sent.

**Response signatures [C]** (…/cloud-api/response-signatures):
- Fetch with `GET /v1/signature/{chat_id}?signing_algo=`.
- For `provider_tee`, the signed text is `<MODEL_ID>:<sha256(req bytes)>:<sha256(resp bytes)>`. For ECDSA this is EIP-191 personal-sign.
- For `gateway`, the text is `<req_hash>:<resp_hash>`. The gateway signs streamed completions by default, aliased models, and the Responses API.
- To get `provider_tee` you must send the canonical model ID with `x-no-aliasing: true`, keep the exact bytes, and use `Accept-Encoding: identity`.
- Documented limitation: "Instances of the same model share one signing key." The preflight evidence plus one signature "do not yet form a complete model-to-Gateway-to-final-response chain."

**SDK record retention [C]** (inference-sdk/index): response records expire after 60 minutes by default.

**Other features [C]:**
- E2EE (Ed25519 v2 protocol, Chat Completions only, NEAR vLLM models only).
- OHTTP (optional, Ed25519).
- Stateless Responses API (`store:false`).
- PII `/v1/privacy/classify` and `/redact`.
- Intel Trust Authority JWT endpoint.
- Usage, billing and cost-by-request-ID APIs.
- API-key spend limits.
- Verification Center at cloud.near.ai/verify, with an embeddable widget.

**Staking for Inference [C]** (docs.near.ai/cloud/staking-for-inference/overview): stake NEAR and the staking rewards become USD credits that accrue per second. The principal stays withdrawable.

**Direct per-model endpoints** (`{slug}.completions.near.ai`) are **experimental**: signatures can 404 across instances [C].

**SDKs [C]:**
- `npm i @nearai/inference-sdk` (Node 24.22.1+)
- `pip install nearai-inference-sdk` (Python 3.12+)
- `cargo add nearai-inference-sdk`
- Go: `github.com/nearai/inference-sdk/go`
- Each verifies gateway and model attestation and exposes `verify_response(id)`.
- Repo `nearai/inference-sdk` was pushed 2026-11-07 with 0 stars, so it is very new [C]. Expect API churn [I].
- Reference verifiers: `nearai/nearai-cloud-verifier` and `near-examples/nearai-cloud-verification-example` [C].

**One-week integration difficulty:**
- Inference: trivial, under a day [I].
- Full fail-closed verification (quote, nonce, RTMR3, MRCONFIGID, NRAS GPU, signature): 1–2 days with the SDK, 3+ by hand [I].

## 2. NEAR AI Private Chat

**Status: production consumer app [C]**, at private.near.ai. Frontend `nearai/private-chat` (React/Tauri). Backend `nearai/chat-api` (Rust) runs in a TDX CVM, uses `dstack-sdk`, and exposes its own `/v1/attestation/report` [C, GitHub README].

It is not a developer platform. It is useful as a reference architecture for a TEE app server in front of NEAR AI Cloud [I].

## 3. IronClaw (agent runtime)

**Status: stable releases [C].** `nearai/ironclaw` is Rust under Apache-2.0/MIT, with about 12.7k stars. Latest stable is v1.4.1 (2026-09-29). It launched at NEARCON in February 2026 (PR Newswire 2026-02-25).

**Features [C]:**
- WASM-sandboxed tools (Wasmtime), an encrypted credential vault injected at the host boundary, leak detection and endpoint allowlists.
- MCP client, Postgres memory with hybrid search, and routines/cron.
- 25+ LLM providers.
- One-click hosted instances "inside a TEE on NEAR AI Cloud". The marketing says "up to 5 agents … 130M tokens per month" on paid tiers.

**Gaps [I]:**
- I found no documented per-action on-chain receipts or attestation export from IronClaw itself.
- Hosted IronClaw is a paid tier, so it is off-limits under no-spend rules. A local build is free (Rust 1.96+, Node 22+).

**One-week difficulty [I]:** running it locally is easy. Writing a custom WASM tool that calls a NEAR contract to log receipts is moderate, about 2–3 days.

## 4. Agent Market (market.near.ai), the current agent registry and payments

**Status: live [C]** (near.ai/blog/what-is-agent-market, 2026-10-16; market.near.ai/llms.txt).

**What it does [C]:**
- Hire agents by the job, with escrow, disputes, reputation (0–100) and owner verification badges.
- Payouts in USD via Stripe Connect or USDC.

**Integration surfaces [C]:**
- Worker REST/MCP with an `aat_` token (`GET /v1/agents/me/assignments`, `POST /v1/assignments/{id}/submit`).
- Buyer MCP at `/mcp` (OAuth).
- **A2A + x402**: each agent sits at `https://<handle>.market.near.ai`. A call returns 402 with a price, the caller signs a USDC authorization, and the marketplace escrows payment until delivery.
- Public search: `GET /v1/agents?q=`, no auth.

**Relevance [I]:** this is the most production-ready path for agent-to-agent payment for private compute, but it is off-chain and centralized. Listing an agent needs an account, which is not allowed under the read-only rules. An agent could advertise a "TEE-attested" property, but I found no marketplace field that verifies one.

## 5. Shade Agents (TEE agents with Chain Signatures)

**Status: deprecated, unmaintained since 2026-04-19 [C].** The repo `NearDeFi/shade-agent-framework` is not archived and was last pushed 2026-10-14 [C].

**How the agent contract verifies attestation on-chain [C]** (docs/reference/agent-contract.md, `shade-contract-template/src/internal/attestation.rs`):
- **Init parameters:** `new(requires_tee, attestation_expiration_time_ms, owner_id, mpc_contract_id)`. The MPC contract is `v1.signer-prod.testnet` on testnet and `v1.signer` on mainnet.
- **Owner allowlists:** the owner manages `approved_measurements` (code) and `approved_ppids` (physical CPUs).
- **Registration:** `register_agent(attestation: DstackAttestation)` is payable and needs **0.00486 NEAR** of storage deposit.
  - The caller must be an **implicit account**.
  - Expected report_data is `account_id_bytes(32) || 0(32)`. This binds the quote to the agent key created in the TEE.
  - Verification calls `attestation.verify(expected_report_data, now_s, &approved_measurements, &approved_ppids)` and returns measurements, PPID and advisory IDs.
  - It stores `{measurements, ppid, valid_until_ms}` and emits an `AgentRegistered` event.
- **Gating:** `require_valid_agent()` gates methods. It re-checks expiry and that the measurements and PPID are still approved, and returns a promise that must be executed.
- **Local mode:** uses a whitelist plus mock measurements, with no real attestation.
- **Crate dependencies:** `shade-attestation` 0.2.0 uses `dcap-qvl =0.5.2` (features contract, borsh, ring) and `dstack-sdk-types`. The template targets `near-sdk =5.26.1` and includes sandbox tests (`near-sandbox`, `near-api`).

**Reuse caveat [I]:** NEAR AI Cloud quotes use a different report_data layout (signing address plus nonce, not a NEAR account ID). `shade-attestation`'s `verify` would need a fork or a variant that takes the expected report_data as given. The measurement allowlist would also have to track NEAR AI's image rollouts (MRTD, RTMR0-2, compose_hash). Gas use for on-chain DCAP is not documented. That it fits in one call is inferred from the MPC contract and Shade doing it in production [I].

**One-week difficulty:** forking the contract and deploying to testnet is moderate, 2–4 days [I]. Do not build a product on the deprecated Shade CLI or API [C deprecation, I advice].

## 6. Chain Signatures / MPC, including CKD (confidential key derivation / KMS)

**Status: production [C].**
- Signer contract: `v1.signer` (mainnet), `v1.signer-prod.testnet` (testnet).
- Threshold is 11 of 17 operators.
- "All Chain Signatures operations now run inside TEEs" (near.org/blog/chain-signatures-tee, 2026-10-23).
- Nodes submit dstack TDX attestations that the contract verifies (github.com/near/mpc docs/design/securing-mpc-with-tee).

**Domains [C]** (learn.near.mom, checked October 2026, community source):
- 0: ECDSA secp256k1
- 1: EdDSA ed25519
- 2: **CKD on BLS12-381** via `request_app_private_key`, giving deterministic app secrets the operators cannot learn
- 3: ForeignTx verification (newer)

`sign` is implemented with yield/resume.

**Docs [C]:** docs.near.org/chain-abstraction/chain-signatures covers derivation paths. Use a distinct path per chain to avoid replay.

**Relevance [I]:**
- CKD is the closest thing NEAR has to a decentralized KMS for TEE agents: persistent agent secrets and an encryption key for sealed memory that survive redeploys.
- OutLayer exposes CKD-backed "Upgradeable TEE Vault" keys [C, outlayer docs].
- Calling CKD directly from your own TEE app means implementing the request and decryption flow from the near/mpc design docs. That is hard in one week [I].
- Chain Signatures for foreign-chain signing is only meaningful if the agent must pay or act on EVM, BTC or SOL. Otherwise it is a gimmick for a private-inference project [I].

## 7. NEAR Intents (1Click API, solvers, Confidential Intents)

**Status: production, mainnet only [C].** "There is no testnet deployment and no plans for one" (docs.near-intents.org/resources/faqs).

**1Click API [C]:**
- Endpoint: `https://1click.chaindefuser.com/v0/quote` (supports `dry`), then a deposit to a quote-specific address, then `/v0/status`.
- `generate-intent` and `submit-intent` support signing standards `nep413`, `erc191`, `raw_ed25519`, `webauthn`, `ton_connect`, `sep53` and `tip191`.
- Unauthenticated requests carry an extra 25 bps fee. A partner JWT from partners.near-intents.org lowers it to 20 bps, or 1 bp on stablecoin routes.
- Protocol fee is 0.0001%.
- SDKs: TypeScript `@defuse-protocol/one-click-sdk-typescript`, Go, Rust (git-only). Also an Intents SDK, a React widget, and an agent skill `near-intents`.

**Verifier contract `intents.near` [C]:**
- Intent types: `add_public_key`, `remove_public_key`, `transfer`, withdrawals, `storage_deposit`, `token_diff`.
- Accounts can be implicit, derived from any ed25519 or secp256k1 key, so no NEAR account is needed. Named accounts register keys via `add_public_key`.
- Nonces are `[4-byte salt][28 bytes]`, with a deadline.

**Confidential Intents [C]:** live. Deposits and withdrawals cannot be linked. The `confidentiality` parameter takes `basic` or `advanced`. Solver liquidity lives on `intents.far`.

**How agents can transact [I]:**
- An agent key held in a TEE signs `transfer` intents (raw_ed25519 or erc191) for USDC between implicit accounts, for example to pay a private-compute provider.
- This needs no NEAR gas from the agent if a relayer or 1Click submits. It settles atomically in the Verifier.
- It costs real funds and has no testnet. Under no-spend rules only `dry` quotes and simulation are possible. `simulate_intents` is a view call [C, docs list].

**One-week difficulty [I]:** the quote and design flow is easy, 1 day. A real payment demo is 2–3 days but requires a mainnet spend.

## 8. NEAR smart contracts for attestation and receipt registries (cost, testnet)

**Storage [C]** (docs.near.org/protocol/storage/storage-staking):
- 1e19 yoctoNEAR per byte, which is **1 NEAR per 100 KB**, plus 40 bytes overhead per key-value record.
- 770 free bytes per account.
- Example: a receipt of about 200 bytes locks about **0.002 NEAR** [I, arithmetic].
- Emitting events only (NEP-297, docs.near.org/smart-contracts/anatomy/events) costs gas but no storage [C feature, I cost].

**Signature host functions [C]:**
- `env::ecrecover(hash, sig, v, malleability_flag)` exists in near-sdk but sits behind the `unstable` feature (docs.rs near_sdk::env::ecrecover).
- `env::ed25519_verify` is stable. Base gas is about 210 Ggas (nearcore PR #8031).
- `p256_verify` exists (NEP-635).
- `env::keccak256` exists [I, standard near-sdk].
- So a contract can check NEAR AI's EIP-191 `provider_tee` signatures: build the EIP-191 hash, recover the key, take keccak, compare with the registered `signing_address` [I, design].

**Yield/resume [C]** (NEP-519, docs.near.org/smart-contracts/anatomy/yield-resume): a contract can wait up to 200 blocks for an off-chain responder. This is the pattern for "contract asks for private inference, a TEE worker resumes with a signed result."

**Gas keys [C]** (NEP-611, protocol 86): a prepaid gas balance with up to 1,024 parallel nonce lanes. Good for a fleet of agents posting receipts.

**Meta-transactions [C]** (NEP-366, relayers) let agents post without holding NEAR.

**Testnet [C]:** faucet at docs.near.org/getting-started/faucet. The docs say it sends **5 testnet NEAR**, and it needs a browser.

**Tooling [C]:**
- CLI: `near-cli-rs`
- JS: `near-api-js`, `near-kit`
- Rust: `near-api`, `near-kit`
- Python: `near-kit` (`pip install near-kit`). The old `near/near-api-py` is archived.
- Contracts: Rust `near-sdk` 5.x, with `near-sandbox` for local tests.
- Agent skills: `npx skills add near/agent-skills`, which includes `near-ai-cloud`, `near-smart-contracts` and `near-intents`.

**Feasibility in a week [I]:**
- A simple registry (owner or verifier-posted signer allowlist plus on-chain ecrecover receipt check): 1–2 days.
- Full on-chain DCAP verification of NEAR AI quotes: 3–5 days, with risk around gas, collateral bundling and measurement churn.

## 9. OutLayer (FastNEAR): TEE off-chain compute for NEAR contracts

**Status: listed in official NEAR docs** (docs.near.org/primitives/off-chain-compute/outlayer) **as a third-party platform** with the warning "evaluate … before relying on it for production" [C]. A production price oracle `price-oracle.near` runs on it [C].

**Features [C]:**
- Rust compiled to WASI runs in TDX.
- The attestation covers the code hash, input hash and output.
- Called via contract yield/resume (paid in NEAR) or HTTPS (paid in USDC via Payment Keys).
- Encrypted secrets, VRF, CKD-backed vault keys, MPC vaults and persistent encrypted storage.

**Relevance [I]:** OutLayer can be the "confidential storage/KMS plus verifiable glue" layer. For example, a WASM job could verify a NEAR AI attestation off-chain and post the verdict, with OutLayer's own TEE proof, back to a contract. Using it requires paying, so under no-spend rules it is design-only.

## 10. Phala / dstack relationship

- **Phala is NEAR AI's "Confidential Cloud provider"** (Phala LinkedIn, 2025-12-03) [C].
- The Private ML SDK was co-built by Phala and NEAR AI (near.ai blog 2025-01-19) [C]. `nearai/private-ml-sdk` is now **archived** [C].
- The live NEAR AI gateway and model CVMs report dstack 0.5.11/0.5.12, and `key_provider_info` names "kms", i.e. the dstack KMS [C, probe].
- Shade and NEAR MPC also use dstack attestation, and the MPC node falls back to a Phala PCCS endpoint by default [C, near/mpc design doc].
- Verification uses Phala's `dcap-qvl` (Rust and Python) [C].
- **Implication [I]:** one verification codebase (dcap-qvl plus RTMR3 replay plus app_compose hashing) covers NEAR AI Cloud, Shade-style agents, MPC nodes and any dstack app on Phala Cloud. A self-hosted model on Phala dstack produces structurally compatible quotes, but its report_data convention differs.

## 11. Account abstraction [C]

- Multi-key accounts with FullAccess and FunctionCall keys (scoped, allowance-limited).
- Implicit accounts: 64-hex ed25519 and Ethereum-style.
- NEP-366 meta-transactions, gas keys (NEP-611), and NEP-641 "Offchain Authorizations for Smart Contracts" (Final).
- NEAR Auth: Web2 or passkey login secured by MPC (docs.near.org/web3-apps/tutorials/near-auth).
- NEP-413 signMessage.
- **Agent use [I]:** give each TEE agent a FunctionCall key scoped to the registry contract, or an implicit account whose key is generated inside the TEE, which is the Shade pattern. A human owner holds the full-access key and can revoke.

## 12. Agent identity and verifiable execution standards

- **No NEP exists** for agent identity, TEE attestation or verifiable execution. The NEPs README lists NEP-393 SBT, 413, 519, 611, 616, 635, 638 and 641, none agent-specific [C, github.com/near/NEPs].
- **gov.near.org RFC "Human-Bound Agent Credentials"** (ZK human plus agent-of-human credentials, optional NEAR AI TEE attestation, extends NEP-393): **proposal only** [C, gov.near.org/t/42715].
- Cross-ecosystem: **ERC-8004 "Trustless Agents"** (Identity, Reputation and Validation registries, with `tee-attestation` as a trust model) [C]. Phala has an ERC-8004 TEE agent example [C].
  - A NEAR-native ERC-8004-shaped registry would be novel rather than standard-conforming [I].
- Community: `MultiAgency/nearly`, NEP-413 claims over FastData KV [C]. It is small and experimental [I].

## 13. Other announced items (verify before relying on them)

- **Confidential GPU Marketplace** and **Nightshade 3.0 "live private shard"** were announced in the 2026-02-25 PR [C that they were announced]. I found no developer docs for either, so treat them as unverified or preview [I].
- **"NEAR AI Agent Hub"**: IronClaw docs mention an "Agent Hub" for hosted instances [C]. It is distinct from the archived 2024–25 NEAR AI Hub registry [C archived].

---

## 14. Readiness matrix

| Capability | Status | SDKs | One-week difficulty (no spend) |
|---|---|---|---|
| NEAR AI Cloud inference and verification | Prod [C] | JS, Py, Rust, Go [C] | Easy [I], but inference needs a paid key |
| Attestation report GET | Prod, public, no key [C, probed] | curl, dcap-qvl | Easy |
| Response signatures | Prod, with documented gaps [C] | SDK `verify_response` | Easy to moderate |
| Direct endpoints | Experimental [C] | — | Avoid |
| Private Chat | Prod consumer app [C] | — | N/A (reference only) |
| IronClaw | Stable v1.4.1 [C]; hosted is paid | Rust binary | Local: moderate |
| Agent Market and x402 | Live [C] | REST, MCP, A2A | Needs an account, so design-only |
| Shade Agents | **Deprecated** [C] | Rust contract and crate | Fork the crate only |
| Chain Signatures | Prod, TEE nodes [C] | JS (chainsig libs), Rust | Moderate; testnet available |
| CKD (MPC KMS) | Prod domain 2 [C, community source] | Low-level | Hard |
| OutLayer | Third-party, live [C] | Rust/WASI | Paid, so design-only |
| NEAR Intents / 1Click | Prod, **no testnet** [C] | TS, Go, Rust | Dry quotes only |
| Confidential Intents | Live [C] | 1Click | Dry quotes only |
| Contracts, events, yield/resume, gas keys | Prod [C] | near-sdk-rs, near-kit | Easy on testnet |
| Agent identity NEP | **None**; RFC only [C] | — | Novel work |

## 15. Combinations with private inference that are meaningful, not gimmicks

1. **On-chain registry of attested model signers plus a receipt verifier.** [I design; all parts C]
   - **Step 1, register:** an owner or a TEE-run verifier submits a NEAR AI model attestation, fetched with a nonce. The nonce could be derived from a recent block hash for freshness [I].
   - **Step 2, verify on-chain:** the contract checks the DCAP quote with `dcap-qvl` (contract feature, as in Shade and the MPC contract). It checks report_data `[0..20] == signing_address`, MRCONFIGID equals the hash of `app_compose`, and the RTMR3 replay. It checks MRTD and RTMR0-2 against an owner allowlist. It stores `signing_address → {model_id, compose_hash, valid_until}`.
   - **Step 3, receipts:** `submit_receipt(model_id, req_hash, resp_hash, sig)` builds the EIP-191 text `model:req:resp`, recovers the signer, and requires it to be a registered, unexpired signer. It emits a NEP-297 event or stores about 200 bytes (about 0.002 NEAR).
   - **Privacy:** only hashes go on-chain, so prompts stay private while third parties can audit that a specific attested model produced a specific output.
   - **Limits to state honestly:**
     - NVIDIA GPU evidence (an NRAS JWT) is not practical to verify on-chain; record it as verified off-chain [I].
     - The shared signing key across instances means the receipt proves "an attested instance of model X", not which instance [C].
     - `provider_tee` signatures need non-aliased, non-streaming Chat Completions with exact bytes kept. The Responses and Messages APIs give only gateway signatures [C].
     - The signature must be fetched within the record-retention window (60 minutes by default) [C].
     - Measurement churn when NEAR AI redeploys needs an owner update path, as Shade's approve/remove measurements does [C pattern].
2. **Policy commitments.** [I] The contract stores a hash of the app's verification policy: accepted `compose_hash` and `os_image_hash` values, model allowlist, TCB policy, and whether E2EE or TLS binding is required, following docs.near.ai's verification-policy page [C]. Each receipt references the policy hash, so a client can prove which policy a response was accepted under. This is cheap and meaningful.
3. **Contract-requested private inference via yield/resume.** [I] A contract yields. A TEE worker (an attested agent account in the Shade pattern, or OutLayer) calls NEAR AI with E2EE and resumes with `{resp_hash, sig}`, and the contract verifies as in item 1. Useful for DAO or AI-judge flows. The 200-block timeout fits typical inference latency [I].
4. **Agent-to-agent payment for private compute.** [I]
   - Off-chain and production-ready: Agent Market x402 USDC escrow [C].
   - On-chain: an Intents `transfer` of USDC between TEE-held implicit accounts, conditioned off-chain on a verified receipt from item 1.
   - Only on mainnet (no testnet) [C], so it is a design or demo-script item under no-spend rules.
   - It becomes non-gimmicky when the payer releases funds only after the contract-verified receipt exists. That needs an escrow contract reading the registry [I].
5. **Agent identity with attested runtime.** [I] Use the Shade pattern: an implicit account whose key is generated in the TEE, registered via quote report_data, gated by `require_valid_agent`, with a FunctionCall key scope. Extending the agent record with "uses only registered model signers" yields an "attested agent plus attested model" pair. This is novel; no NEP covers it [C absence].
6. **Weaker or gimmick-risk options** [I]:
   - Chain Signatures, unless the agent truly must act on other chains.
   - Staking for inference: real but tangential.
   - Writing raw prompts or responses on-chain: a privacy violation, never do it.
   - Writing the full 312 KB attestation on-chain: about 3 NEAR of storage; store a hash and emit an event instead.

## 16. Key URLs

- docs.near.ai/llms.txt
- docs.near.ai/cloud/verification/cloud-api/response-signatures
- docs.near.ai/cloud/verification/reference/quote-nonce-signer
- docs.near.ai/cloud/inference-sdk
- docs.near.org/ai/shade-agents/getting-started/introduction (deprecation notice)
- raw.githubusercontent.com/NearDeFi/shade-agent-framework/main/docs/reference/agent-contract.md
- github.com/near/mpc
- near.org/blog/chain-signatures-tee
- docs.near-intents.org/llms.txt
- docs.near-intents.org/resources/faqs (no testnet)
- docs.near.org/primitives/off-chain-compute/outlayer
- market.near.ai/llms.txt
- github.com/nearai/ironclaw
- docs.near.org/protocol/storage/storage-staking
- docs.near.org/smart-contracts/anatomy/yield-resume
- github.com/near/NEPs

Scratch files from the probes (attestation JSON, model list, fetched doc pages) are in `/private/tmp/claude-501/-Users-ethancastro/bbb35d95-f9c7-4de1-a77a-3ce1b586f2a9/scratchpad/`, under its `probe/` and `pages/` subfolders.