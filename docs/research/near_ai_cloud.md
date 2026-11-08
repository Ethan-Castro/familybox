# NEAR AI Cloud: technical research report (as of 2026-11-07)

Labels: **[C]** = CONFIRMED, with source (URL, file, or a live call I made). **[I]** = INFERRED or speculation. Live calls ran on 2026-11-07 from this Mac with no API key. Everything was read-only. I made no account, used no key, sent no POSTs, and spent nothing.

Local copies are in `/private/tmp/claude-501/-Users-ethancastro/bbb35d95-f9c7-4de1-a77a-3ce1b586f2a9/scratchpad/near/`:
- `pages/`: the docs pages
- `live/`: raw API responses and the extracted compose files
- `repos/`: cloned repos

The verifier script I wrote is `/private/tmp/claude-501/-Users-ethancastro/bbb35d95-f9c7-4de1-a77a-3ce1b586f2a9/scratchpad/scripts/verify.py`.

---

## 0. What I ran and what came back without a key

| Call (GET, no auth) | Status | Response shape |
|---|---|---|
| `https://cloud-api.near.ai/v1/models` | **200**, 65.7 KB | `{object:"list", data:[64 models]}`. Each model has `id, owned_by, pricing{input,output (USD per 1M), prompt, completion, input_cache_read}, context_length, max_output_length, supported_features, modalities` |
| `/v1/model/list` | **200**, 79 KB | `{models:[...], limit, offset, total:64}`. Each model has `metadata{verifiable, attestationSupported, providerType (vllm\|chutes\|tinfoil\|external), providerConfig (api_key shown as "***"), datacenters, quantization, aliases}` |
| `/v1/model/z-ai%2Fglm-5.3-flash` | **200** | Model details in nano-USD (`amount`, `scale:9`) |
| `/v1/health` | **200** | `{"status":"ok","version":"0.0.0"}` |
| `/health` | 404 | OpenAI-style error |
| `/v1/services` | **200** | One service: `web_search`, "Web search proxied to Brave Search API", `costPerUnit: 5000000` nano-USD, which is $0.005 per request |
| `/v1/attestation/report?signing_algo=ecdsa&nonce=<64hex>` | **200**, 69.5 KB | `{gateway_attestation{signing_address, signing_algo, intel_quote (10012 hex chars), event_log (JSON string), report_data, request_nonce, info{app_id, instance_id, app_cert, app_name:"dstack-0.5.12", compose_hash, os_image_hash, key_provider_info(kms), vm_config, tcb_info{mrtd, rtmr0-3, app_compose, ...}}}, ohttp_key_config, ohttp_attestation{signing_algo:ed25519, signing_key, key_config, signature}}` |
| same, plus `model=z-ai/glm-5.3-flash&provider=near&include_tls_fingerprint=true`, header `x-no-aliasing: true` | **200**, 317 KB | The gateway report plus `tls_cert_fingerprint`, `tls_certificate` (PEM), and `model_attestations[1]` with `{model_name, signing_address, signing_algo, signing_public_key (128 hex), request_nonce, intel_quote, nvidia_payload (98 KB, 8 HOPPER GPUs), event_log, info, tls_cert_fingerprint, ohttp_attestation, ohttp_key_config, compose_manager_attestation{actions[226], actions_hash, nonce, nonce_source:"client", quote, event_log, report_data, vm_config}}` |
| report for `moonshotai/kimi-k2.6` (Chutes) | 200 | Candidate in a different shape: `{provider:"chutes", verified:true, tcb_status, gpu_verdict:"PASS", e2e_pubkey, quote_b64, certificate_b64, measurement_config, ...}` |
| report for `z-ai/glm-5.3` (Tinfoil) | 200 | `{provider:"tinfoil", trust:"router_attested", router{format: sev-snp-guest/v2, report_b64}, model_entry{repo:"tinfoilsh/confidential-glm5-3-nvfp4", tag, registers}, verified:true}` |
| report for `anthropic/claude-sonnet-5` | **503** | "TEE attestation is not supported for external providers. External providers run outside of our Trusted Execution Environment." |
| `/v1/attestation/pins` | 200, 52 KB | `{tinfoil:{compiled:{routers:[{measurement, tag}...]}, ...}, chutes:{...}}` |
| `/v1/attestation/ita-token?nonce=...` | 200, 6.6 KB | `{gateway:{token:"<Intel Trust Authority JWT, PS384>"}}` |
| `/v1/signature/abc` | **401** | `missing_auth_header` (signatures need a key) |
| `/.well-known/ohttp-gateway` | 200 | `application/ohttp-keys`, 45 bytes. Matches `ohttp_key_config` in the report |
| `https://completions.near.ai/endpoints` | 200 | Registry of direct `{slug}.completions.near.ai` hosts. It lists models that are not in the catalog (gemma-4, gpt-oss-120b, test hosts) |

**My own cryptographic check of the live reports [C].** I ran dcap-qvl 0.x on Python 3.14, using Phala's PCCS for collateral. It passed for the gateway report (fetched twice, once with ecdsa and once with ed25519) and for the glm-5.3-flash model report:
- TCB status `UpToDate`, with no advisories
- TDX debug bit off
- `report_data` equals `signer(||TLS-SPKI hash) || my nonce`
- the echoed nonce matches
- MRCONFIGID equals `01 || sha256(app_compose) || 0x00*15`
- the RTMR3 event-log replay matches

The compose-manager quote also verified: `report_data` equals `actions_hash || my nonce`, and its MRTD, RTMR0-3 and MRCONFIGID are identical to the model quote's, so it comes from the same CVM. I could not reproduce `actions_hash` from the JSON with three serializations I tried. That format is unknown to me.

The live TLS certificate SPKI SHA-256 for cloud-api.near.ai is `73862c25…a5ad` (Let's Encrypt YE1 issuer). It equals the quote-bound `tls_cert_fingerprint`. This was over separate connections, so it is not the same-connection proof the docs require.

**Not executed:**
- NVIDIA NRAS verification (it is a POST to NVIDIA).
- Any chat completion or signature verification (both need a key).

The GPU payload's `nonce` field does equal my nonce [C].

---

## 1. Which models are TEE-hosted

The catalog has 64 models: 18 with `verifiable:true` and 46 that are plain external providers [C: `/v1/model/list`].

**NEAR-operated Confidential TEE.** These have `providerType: vllm` and run on dstack, Intel TDX plus NVIDIA H200 CC [C: metadata; the model report shows `dstack-nvidia-0.5.11`, 8 HOPPER GPUs, 4 NVSwitches]:

| Model | In / out USD per 1M | Notes |
|---|---|---|
| `z-ai/glm-5.3-flash` | 0.08 / 0.50 | Cache read 0.012, 1M context. Aliases include `zai-org/GLM-5.1-FP8` |
| `Qwen/Qwen3.8-27B` | 0.04 / 1.35 | |
| `Qwen/Qwen3.8-27B-abliterated` | | US+IN datacenters |
| `Qwen/Qwen3.6-35B-A3B-FP8` | 0.17 / 1.10 | |
| `Qwen/Qwen3-VL-30B-A3B-Instruct` | 0.15 / 0.55 | |
| `deepseek-ai/DeepSeek-V4.1-Flash-1017` | 0.3 / 1.2 | Also an `-abliterated` variant |
| `Qwen/Qwen3-Embedding-0.6B` | | |
| `Qwen/Qwen3-Reranker-0.6B` | | |
| `openai/whisper-large-v3` | | |
| `openai/privacy-filter` | | |
| `black-forest-labs/FLUX.2-klein-4B` | | |

**"Attested 3P" (third-party TEEs).**
- **Chutes:** `deepseek/deepseek-v3.2`, `moonshotai/kimi-k2.6`, `moonshotai/kimi-k3`, `qwen/qwen3.5-397b-a17b` [C]. Two of these report `isReady:false` [C].
- **Tinfoil (AMD SEV-SNP router):** `z-ai/glm-5.3` [C].

**Odd entries [C, meaning unknown].**
- `moonshotai/kimi-k2.6` is labeled `chutes`, but its `providerConfig` holds `base_url: https://openrouter.ai/api/v1` with backend `openai_compatible`. [I] This could be a fallback path that leaves the TEE. Verify before trusting it.
- `levanto/sage-2` is `verifiable:true` but `attestationSupported:false`, `providerType:external`, base URL `private.sage.levanto.ai`.

**"Incognito"/anonymised, not TEE.** All `anthropic/*`, `openai/gpt-*`/`o*`, `google/gemini-*`, `x-ai/grok-*`, `deepseek/deepseek-v4.1-flash*`, `qwen/qwen3.7-max`, `moonshotai/kimi-k3.1-pro`, `typesafe/jev-1.13` [C].

- The docs say these route through the TEE gateway "under NEAR AI's provider account", and that "TEE privacy and verifiability guarantees do not extend to the upstream provider" [C: docs.near.ai/cloud/models].
- The gateway image carries `OPENAI_API_KEY`, `ANTHROPIC_API_KEY` and `GEMINI_API_KEY` env slots [C: gateway app_compose `allowed_envs`].

**Caveat on aliases [C].** The gateway rewrites aliases. The quickstart and the example repo use `zai-org/GLM-5.1-FP8`, which the catalog now maps to `z-ai/glm-5.3-flash`, and `GLM-5`, `glm-latest`, `deepseek-ai/DeepSeek-V4-Flash` and others map there too. Send `x-no-aliasing: true` to make an alias fail instead of being rewritten [C: model-attestations doc].

---

## 2. What attestation proves, and what it does not

### Proven, when you do the verification yourself

1. **[C]** The gateway (cloud-api.near.ai) runs in an Intel TDX CVM built on dstack 0.5.12 with debug off.
   - Its measured config (`app_compose`, via MRCONFIGID and RTMR3) pins container digests: `nearaidev/cloud-api@sha256:d74c3c…`, `nearaidev/cvm-ingress@sha256:1653c2…`, an otel collector, and alpine init.
   - The signing key and the nonce are bound in `report_data`.
2. **[C] TLS is terminated inside the gateway CVM.** The `ingress` container (nginx with certbot) runs inside the measured compose for `DOMAIN=cloud-api.near.ai`. The quote can bind SHA-256 of the cert's SPKI (`include_tls_fingerprint=true`), and I observed the live SPKI matching it.
   - Docs: the binding is valid only if the cert and the report come over the **same TLS connection**. Browsers cannot do this [C: tls doc].
   - Caveats [I]:
     - The ingress persists certificates to S3 (`S3_BUCKET=${INGRESS_S3_BUCKET}` plus AWS creds). If the private key sits in S3 unencrypted or under a non-TEE key, someone with S3 access could impersonate the endpoint. The quote binding would still pass, because the attested fingerprint is the same key. I did not verify how that key is stored.
     - The IPs are 40.160.65.237 and 40.160.77.67, with server header `nginx/1.29.1`. There is no sign of a CDN in front.
3. **[C] Model CVM.** An NEAR-operated model report proves:
   - a TDX CVM with debug off and dstack-nvidia measurements
   - a model signing key (ecdsa address or ed25519 pubkey) bound to the nonce and the TLS SPKI
   - an NVIDIA payload carrying the same client nonce, for NRAS to check
4. **[C]** Freshness comes only from the client nonce, and only if that nonce is in the *verified quote*. Echoed HTTP fields are not evidence [C: quote-nonce-signer doc].

### Not proven, or explicitly disclaimed

- **No per-instance binding [C].** The docs say: "Instances of the same model share one signing key… a matching signer does not establish that the report and the completion came from the same serving instance." `model_attestations[]` "is not an inventory of every model instance."
- **No full chain [C].** The docs say: "Preflight Gateway and model evidence plus one response signature do not yet form a complete model-to-Gateway-to-final-response chain."
  - A `gateway` signature does not prove the model produced the upstream bytes.
  - A `provider_tee` signature is not bound to the gateway or the TLS evidence.
- **The gateway sees plaintext [C, by architecture].** TLS ends inside the gateway CVM, and the gateway parses, routes, rewrites streams, resolves aliases, and counts usage.
  - So "the operator cannot see prompts" reduces to trusting the attested gateway *code*, plus the env and config the operator injects, plus log handling.
  - The gateway's own repo rule says: "Production logs at `info` and above, and **those logs leave the enclave**" [C: `nearai/cloud-api/.claude/rules/privacy-logging.md`]. That rule bans logging content, but it is a code-review policy, not a hardware guarantee.
  - The gateway compose includes an otel collector that mounts `/var/run/docker.sock` and `/` read-only and ships to Datadog (`DD_API_KEY`, `MONITORING_INGEST_TOKEN`) [C: gateway app_compose].
- **Operator-controlled runtime config is not measured [C/I].** Only env var *names* are allowlisted in `app_compose` (`allowed_envs`: about 100 entries, including the DB host and password, `MODEL_DISCOVERY_SERVER_URL`, provider API keys, `CHUTES_MODELS`, `TINFOIL_MODELS`, `OHTTP_ENABLED`, `DB_ENCRYPTION_KEYS`, `PROXY_TOKEN`). [I] Their values come in as dstack-encrypted env from the operator, so the operator can change routing and feature flags without changing the measurement.
- **The running model image is NOT pinned by the quote [C, important].**
  - The model CVM's measured compose is a **compose-manager** bootstrap. It holds otel, certbot, `compose-manager` (image `${COMPOSE_MANAGER_IMAGE:-…@sha256:6e035c…}`, `pid: host`, `CAP_SYS_ADMIN`/`SYS_PTRACE`, `docker.sock`) and `compose-manager-launcher`.
  - At runtime, compose-manager pulls compose files from **github.com/nearai/cvm-compose-files** (public) and runs them. The launcher hot-swaps the compose-manager image on `LAUNCHER_CHANNEL=latest`, gated by a cosign identity matching `github.com/nearai/compose-manager/.github/workflows/.*`, with `MIN_TAG_AGE_HOURS` defaulting to 0.
  - RTMR3 holds only boot events (`app-id`, `compose-hash`, `instance-id`, `mr-kms`, `os-image-hash`, `key-provider`, two `nearai-replica-report-key-v1`). Nothing in it covers these swaps.
  - Observed: compose-manager restarted with digests `a320bb…` and then `a0c073…` on Oct 29 and Nov 4, while the measured compose-hash stayed the same.
  - Running services such as `prod/GLM-5.3-Flash-SGL-TP2x4-W4AFP8-V12Q8.yaml` at commit `5a5119f…` are visible only in `compose_manager_attestation.actions`. That is a log produced by the swappable compose-manager itself, quoted with your nonce.
  - The same production CVM ran `experiments/GLM-5.3-gpu23-local-engine-bench.yaml` in September [C: actions log].
  - [I] So model-code integrity = trust in NEAR's GitHub repos, CI, cosign identity, and the compose-manager's honesty about its log. It is not a hardware-pinned digest. The docs' "image provenance" page and SDK examples ("check image builds and Compose Manager deployment evidence") point the same way.
- **GPU-to-CPU binding is only via the shared nonce [I].** The TDX quote holds no GPU identity. The NRAS verdict proves *some* genuine CC-mode H100/H200s answered with your nonce. Cryptographically, it does not prove those GPUs sit inside that CVM. Hardware topology in `vm_config` (`num_gpus:8`) is operator-reported, and so is `datacenters`.
- **Retention [C, partial].**
  - Responses API: "does not store the raw request, response, output items, or conversation history."
  - `/v1/conversations` and `/v1/files` are retired (410).
  - Signatures are stored over SHA-256 digests, "never raw content" [C: stateless guide; OpenAPI tag text].
  - The gateway uses AWS RDS Postgres (`cloudapi-postgres-prod…us-east-1.rds.amazonaws.com`) with field encryption keys derived via dstack [C: compose; `docs/database-encryption.md`].
  - SDK response records "expire after 60 minutes by default" [C: SDK index].
  - I found no formal retention policy for chat-completion metadata (IDs, token counts, org) beyond billing and usage reporting [I].
- **Prompt cache [C/I].** The KV prefix cache lives in the TEE "per model deployment" [C: prompt-caching]. The gateway does prefix-affinity routing [C: `fleet.rs`]. [I] A shared cross-tenant prefix cache allows timing side channels (detecting cache hits on other tenants' prefixes).
- **Web search [C].** It goes out to Brave Search, so queries leave the TEE.
- **Third-party models.**
  - Chutes: its golden-measurement feed is unsigned, so NEAR pins are compiled in [C: `docs/security/attested-provider-runtime-trust.md`].
  - Tinfoil: SEV-SNP router, pinned by compiled values or Sigstore, with an admin PATCH able to add pins [C: `tinfoil-router-trust.md`].
  - `verified:true` in those candidates is the **gateway's** verdict. Clients have to redo the checks themselves. Per the docs, the JS SDK verifies Chutes model attestation and the Python SDK verifies only the gateway [C: models page].
- **Gateway-to-model hop [C, code comment].** The gateway's SPKI verifier has a "Bootstrap" state that accepts any WebPKI-valid cert before fingerprints are known, then switches to "Pinned" or "Blocked" [C: `crates/inference_providers/src/spki_verifier.rs`]. [I] There is a short window in which the gateway-to-model TLS is not pinned to attestation.

---

## 3. Per-response signatures [C: response-signatures doc, OpenAPI, example repo]

- **Fetching.** `GET /v1/signature/{chat_id or resp_*}?signing_algo=…&model=…` needs an API key (live: 401 without one).
  - It returns `{text, signature, signing_address, signing_algo, signature_kind}`.
  - A 2xx containing `error_code`/`message` means "unavailable". A 404 means not found yet, so retry for a bounded time.
- **What is signed:** `request_hash = SHA-256(exact request-body bytes)` and `response_hash = SHA-256(exact uncompressed response-body bytes, including SSE framing)`.
  - **`provider_tee`:** `text = "<canonical MODEL_ID>:<request_hash>:<response_hash>"`, signed by the model TEE key. It must match exactly one verified, retained preflight model report (same signer and algo).
  - **`gateway`:** `text = "<request_hash>:<response_hash>"`, signed by the gateway key. It must match the preflight `gateway_attestation`. This form contains no model ID.
- **Algorithms.**
  - `ecdsa`: Ethereum EIP-191 personal_sign. Recover the address.
  - `ed25519`: verify the UTF-8 `text` against the pubkey.
  - Defaults differ: `/v1/signature` defaults to ecdsa, while `/v1/attestation/report` defaults to ed25519 for the gateway and ecdsa for models. Always pass `signing_algo` explicitly.
- **When the gateway signs instead of the model:** streamed completions (it strips per-chunk usage), alias resolution, the Responses API, and Messages. Only `provider_tee` binds the output to a model TEE.
- **Not bound by the signature [C/I]:**
  - a timestamp, the nonce, the API key or org, which instance served the request, or the gateway-to-model link
  - [I] whether the request the model saw equals the one you sent, except that `request_hash` is over your exact bytes. A `provider_tee` signature therefore also implies the gateway forwarded the body unmodified.
- **Direct endpoints:** signatures are kept in per-instance memory, so lookups can 404 [C: direct-completions doc].
- **Skill vs docs.** The skill says "Chat signatures are persistent and can be queried at any time" [C: near/agent-skills]. The docs contradict that. The docs are newer.

---

## 4. Keys, credits, pricing, limits

- **Account and key [C: quickstart].**
  1. Sign up at cloud.near.ai.
  2. **Buy credits** in the Credits section.
  3. Create an `sk-` key.
  - Key types: `sk-` (API), JWT access, `rt_` refresh, `rpt-` reporting.
  - A new key can take up to 10 s to activate.
  - Per-key spend limits and expiry are supported [C: API reference].
- **Free credits.** I found none documented. No free tier is mentioned. [I] Credit types in the code include `grant` (`grant -> staking_farm -> transfer -> payment -> postpay` [C: `cloud-api/docs/credit-allocation.md`]), so promotional grants exist administratively. There is no public signup grant.
- **Staking for Inference [C].** Stake NEAR and the rewards accrue per second as credits (1 credit = $1). The principal stays withdrawable. The account and eligibility path includes AML checks (Lukka AML env vars in the gateway [C]).
- **Pricing [C: `/v1/models` live].** USD per 1M tokens.
  - glm-5.3-flash: 0.08 / 0.50
  - Qwen3.8-27B: 0.04 / 1.35
  - DeepSeek-V4.1-Flash: 0.30 / 1.20
  - Qwen3-VL-30B: 0.15 / 0.55
  - kimi-k3 (Chutes): 3.30 / 16.5
  - glm-5.3 (Tinfoil): 1.80 / 5.75
  - Claude Opus 5.5: 4 / 20
  - GPT-5.5: 5 / 30
  - Web search: $0.005 per request.
  - Attestation report retrieval is free and creates no billing records [C].
- **Rate limits.**
  - Default **64 concurrent requests per org per model** [C: `crates/services/src/completions/ports.rs` `DEFAULT_CONCURRENT_LIMIT`]. Admins can change it.
  - **Anonymous attestation:** 8 concurrent per gateway instance, then 429 with `Retry-After: 1` [C: `crates/api/src/routes/attestation/report.rs`]. Requests with a key bypass this.
  - Reports requested without a nonce are cached for 10 s. A nonce bypasses the cache [C: `lifecycle.rs`].
  - The ITA token endpoint passes through Intel's upstream 429s [C].
  - I found no published RPM or TPM figures.

---

## 5. End-to-end encryption [C: e2ee guide; SDK docs]

**E2EE to the model key.** This is the NEAR model E2EE protocol, version 2.
- Get the model's `signing_public_key` (Ed25519) from a verified `provider=near` report.
- Per field: an ephemeral X25519 key, ECDH, HKDF-SHA256 with info `"ed25519_encryption"`, then XChaCha20-Poly1305.
- Wire format: `eph_pub(32) || nonce(24) || ct+tag`, hex-encoded.
- Headers: `X-Signing-Algo: ed25519`, `X-Client-Pub-Key`, `X-Model-Pub-Key` (also a routing pin), `X-Encryption-Version: 2`, `x-no-aliasing: true`.
- The response `content`, `reasoning_content` and `reasoning` come back encrypted to the client key, with each stream chunk encrypted separately.
- A legacy ECDSA mode (secp256k1, HKDF, AES-256-GCM) also exists.

**Coverage.**
- Encrypted by default: message `content`, `reasoning*`, `audio.data`.
- `X-Encrypt-All-Fields: true` adds tool names, descriptions and schemas, `tool_calls`, `refusal`, and logprob tokens.
- **Not encrypted [C/I]:** the model ID, sampling parameters, message roles and count, lengths, timing, and the API key. [I] The gateway still sees all of that metadata.
- Supported on `/v1/chat/completions`, `/v1/completions`, `/v1/embeddings` and `/v1/images/generations`. **Not** on `/v1/responses`.
- Requires a NEAR-operated model. A Chutes key-routing variant exists [C: `cloud-api/docs/chutes-public-key-routing.md`].
- [I] Encrypted fields are still covered by the hashes in the signature, since the signature is over the exact bytes.

**OHTTP (RFC 9458) to the gateway [C].**
- `/.well-known/ohttp-gateway` serves the HPKE key config. `POST /ohttp` accepts `message/ohttp-req` or `message/ohttp-chunked-req`.
- The key config is signed by the gateway's ed25519 attested key. I observed `ohttp_attestation.signing_key` equal to the ed25519 `gateway_attestation.signing_address` `40599fb2…4acb`. I did not check the signature bytes.
- Optional, ed25519 only. Supported for Chat, Responses and Messages in the SDKs.
- The JS SDK docs say: "Authorization and custom headers sent on the outer request, along with the client's network address, are not hidden by OHTTP." That contradicts the claim in `nearai-cloud-verifier/py/ohttp_client.py` that the server "cannot link your request to your IP address or API key". [I] There is no third-party relay, so OHTTP here is extra encryption to the gateway, not unlinkability.

---

## 6. Gaps and trust assumptions

1. **Hardware roots.**
   - Intel: DCAP, PCS or PCCS. dcap-qvl uses **Phala's PCCS by default**, so pass `INTEL_PCS_URL` to remove Phala as a collateral source [C: quote-nonce-signer doc].
   - NVIDIA NRAS: the minimal flow trusts NRAS's TLS-authenticated verdict without validating the JWT locally [C].
   - AMD SEV-SNP: Tinfoil.
   - Chutes: own TDX plus GPU evidence.
   - All of this inherits TEE side-channel and physical-attack limits [I].
2. **dstack (Phala) and KMS.** Both CVMs use `kms_enabled: true` with the same KMS identity (`key_provider_info` id `3059…`) [C]. Signing keys come from KMS ("instances of the same model share one signing key"), and so do DB encryption keys (`dstack:` derivation) [C/I]. [I] Whoever controls KMS authorization (which compose-hashes are allowed to receive an app's keys) can authorize a new build that gets the *same* signing key. Clients that only pin a signing address therefore get no protection against upgrades. Pin measurements as well. I did not determine KMS governance (on-chain or operator-run).
3. **Upgrades and mutable code.** On models, compose-manager runs from GitHub at runtime with root-equivalent power (pid host, SYS_ADMIN, docker.sock), as described in section 2. On the gateway, a redeploy changes compose-hash and MRCONFIGID, so clients must keep allowlists current. No transparency log or delay is enforced (`MIN_TAG_AGE_HOURS=0`) [C/I].
4. **Operator env and secrets are not measured** (section 2). The gateway also connects to external Postgres, Valkey/Redis placement, S3, Datadog, Prometheus, Slack and Brave [C: compose `allowed_envs`].
5. **Logs leave the enclave**, constrained only by code-review policy [C].
6. **Incognito (frontier) models** are not TEE-protected upstream. The provider sees plaintext, minus NEAR's account substitution and an optional PII redaction step [C].
7. **Verification is opt-in and fails open in practice.** Plain OpenAI-SDK use verifies nothing. Streaming yields only gateway signatures. The browser cannot bind TLS. Direct endpoints are experimental, with per-instance reports and signature 404s (cloud-api#1087) [C].

### Problems in the official example repo

`near-examples/nearai-cloud-verification-example`, HEAD `12098c3`, Sep 16 2026 [C: source read].
- It does **not** verify the Intel TDX quote, `report_data` binding, RTMR3 or compose hash.
- It checks only the *echoed* `request_nonce` (an HTTP field), the NRAS verdict and `eat_nonce` (JWT decoded, signature not checked locally), and that the signature recovers to the `signing_address` given in the *unverified* HTTP report.
- It does not send `provider=near` or `x-no-aliasing`, and its default model ID is an alias.
- When `signature_kind` is missing it infers the kind from the shape of `text`, which the docs now say not to do.
- **Do not treat it as a sufficient verifier.** `nearai/nearai-cloud-verifier` (Aug 10 2026; Py/TS) adds dcap-qvl, Sigstore provenance, TLS/domain checks and OHTTP. The docs' Python/Node helpers (in quote-nonce-signer) are the most complete minimal reference.

### Official `near-ai-cloud` agent skill

`near/agent-skills/skills/near-ai-cloud/SKILL.md`, v1.1.0, repo HEAD Sep 28 2026 [C].

What it instructs:
- Use the OpenAI SDK with base URL `https://cloud-api.near.ai/v1`.
- Its 8-step flow:
  1. Generate a nonce.
  2. Request the model attestation.
  3. Submit `nvidia_payload` to NRAS.
  4. Verify `intel_quote` with dcap-qvl or proof.t16z.com.
  5. Check that the signer and nonce are in TDX `report_data` and the nonce matches NRAS `eat_nonce`.
  6. Make the chat request.
  7. Fetch `/v1/signature/{id}`.
  8. Recover the signer and compare it to the attested `signing_address`.
- It also has references on E2EE, gateway TLS, and "Private vs Anonymised" models.

Where it is **stale** compared with the live system:
- It says attestation "requires API key". Live: 200 without one, and the docs say the key is optional.
- It says signatures are "persistent".
- Its example models (DeepSeek-V3.1, GLM-4.7, gpt-oss-120b) are not in the current catalog.
- It omits `provider=near`, `x-no-aliasing`, the compose-manager evidence, and OHTTP.

### Other repos

| Repo | What it is |
|---|---|
| `nearai/private-ml-sdk` | dstack-nvidia guest-image build: production image vs dev image with sshd/strace; KMS; "reproducible builds" claimed [C: README] |
| `nearai/cloud-api` | Gateway source in Rust, public, HEAD `4ac61fd`, Nov 6 2026 |
| `nearai/cvm-compose-files`, `nearai/compose-manager`, `nearai/inference-sdk`, `nearai/cvm-ingress` | Public |
| `nearai/nearai-cloud-server` | Does not exist (404) [C] |

---

### Quick list for other agents

- **Fully keyless:** catalog, pricing, health, services, gateway and model attestation (with nonce), ITA token, pins, OHTTP keys, direct endpoint registry.
- **Needs a key:** inference, `/v1/signature/*`, usage, billing.
- **Strongest verifiable claim:** a genuine, current-TCB, non-debug TDX gateway that terminates TLS for cloud-api.near.ai, plus a TDX+H200 model CVM holding the response-signing and E2EE key. The attested launcher and boot config are measured.
- **Weakest links:**
  - the model serving image is swapped at runtime from GitHub, outside the measurement
  - the gateway sees plaintext metadata (and content without E2EE) and its logs leave the enclave
  - the signing key is shared per model and derived from KMS
  - there is no end-to-end chain from model to gateway to client
  - unmeasured operator env