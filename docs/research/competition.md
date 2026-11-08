# NEAR Hackathon 2026, Privacy & Private AI track: competitive and prior-art report (as of 2026-11-07)

Labels: **[C]** means CONFIRMED, with the source URL or file and what I saw. **[I]** means INFERRED or speculation. Everything was read-only: public GETs only, nothing submitted, posted or bought.

---

## 0. Summary

- **[C] The track is already busy.** The public submissions feed lists 258 projects so far, and 42 of them include the `privacy` track. AI Security has 137 and Agent Economy has 126. Most privacy entries follow one of three patterns:
  - an existing workflow re-run on NEAR AI Cloud's TEE with a "Verified" panel;
  - a TEE signature anchored on-chain;
  - an AI judge or oracle running in a TEE.
- **[C] The "redact locally, then call the cloud model" idea is taken by at least three submitted entries:** Sealed Dossier, RedactGate and PrivatePay Agent. A fourth, privacy-hybrid, is on GitHub.
- **[C] NEAR AI Cloud now does PII redaction itself on the server.** Its `cloud-api` has an `auto_redact` feature that runs inside the TEE, plus `/v1/privacy/classify` and `/v1/privacy/redact` endpoints. A plain PII-masking gateway competes with a feature NEAR already ships.
- **[C] Perplexity "Hybrid compute on Mac" (launched 2026-09-01) is the commercial version of the local-first intermediary.** A local model plus an on-device "privacy gate" classifier masks, keeps local, refuses or asks consent before data reaches the cloud.
- **[I] The open space** is not more redaction. It is the things nobody in the field measures or enforces:
  - leakage across a whole multi-turn session (disclosure budgets);
  - semantic minimization with measured leakage numbers (PAPILLON/Minions style) rather than placeholder swapping;
  - verification done by the user's own client;
  - metadata unlinkability (OHTTP-style) for apps other than Brave;
  - privacy at the agent-tool (MCP) egress point;
  - local memory that never ships raw to the cloud.

---

## 1. Hackathon facts that shape strategy

All from https://nearhackathon.com/HACKATHON.md, copy saved at `/private/tmp/claude-501/-Users-ethancastro/bbb35d95-f9c7-4de1-a77a-3ce1b586f2a9/scratchpad/nh/HACKATHON.md`.

- **[C] Dates.** Starts 2026-11-01; submissions close 2026-11-14T23:59Z; judging 11-16; results by 11-18.
- **[C] Code from 2026-10-19 counts.** Earlier commits are baseline (Q-001).
- **[C] Prizes.** $250K total: $55K grand prize, and $10K / $3K / $2K for 1st, 2nd and 3rd in each of 13 tracks.
- **[C] What to submit.** A public repo plus an X post tagging @NEARProtocol and #NEARHackathon with a video. You submit once, by POST; edits go through a manual request.
- **[C] Screening (Q-017).** "Claude Code and Codex screen every project": reproducibility check, feature verification, structured report and preliminary score. Humans decide.
- **[C] README guidance.** Write it "for a machine reader as well as a human one", with "do X - see Y" steps and no marketing.
- **[C] Local-only demos are allowed (Q-012)** with a public repo, reproducible README and video. A hosted demo is a plus.
- **[C] No integration is mandatory (Q-011).** The privacy track's hints are "PRIVATE AI, TEE, NEAR AI CLOUD".
- **[C] The official privacy prompt is a private expense auditor** (https://github.com/nearai/near-hackathon-prompt-examples/blob/main/tracks/03-privacy.md):
  - OpenAI-compatible call to a TEE model;
  - attestation fetched with a fresh nonce and shown in a "Verified" panel;
  - nothing kept on the server;
  - fictional sample documents.
- **[I] Expect many near-clones of that prompt.** Sealed Ledger (chaoticpunk/sealed-ledger) is literally it.
- **[C] Judge headshots on the site** are filed under avichal, bender, eddy, haseeb, illia, kain, mert and stepan-gershuni. Seen in image paths on nearhackathon.com; full identities not verified.
- **[C] Side event.** Build City × NEAR Legion "Private AI Hackathon NYC", 2026-11-11 (https://luma.com/private-ai-hack). Suggested directions: healthcare, finance/legal, agents with credentials, nonprofits. **[I]** This will add more generic private-document entries late in the window.

---

## 2. Current 2026 submissions (live data)

**[C] Source.** `GET https://nearhackathon.com/api/projects?page=N&pageSize=100` is public and returns name, tracks and demo_url. The total was 258 on 2026-11-07. Track counts:

| Track | Entries |
|---|---|
| security | 137 |
| agents | 126 |
| realworld | 52 |
| business | 44 |
| open | 42 |
| privacy | 42 |
| defi | 38 |
| thesis | 23 |
| swarms | 19 |
| nfts | 19 |
| games | 14 |
| social | 14 |
| memecoins | 8 |

Demo-post text was read through the public `api.fxtwitter.com` (no auth). Raw data is in `/private/tmp/claude-501/-Users-ethancastro/bbb35d95-f9c7-4de1-a77a-3ce1b586f2a9/scratchpad/nh/` (`all.json`, `rest_text.txt`).

**[C] Organizer signal:** @near_ai posted "100 projects submitted so far" on Nov 3. **[I]** The final count will likely be several times today's 258.

### 2a. Closest overlap with a local-first privacy intermediary

| Entry | What it does | Source |
|---|---|---|
| **Sealed Dossier** | Local SQLite full-text search over a case file, then swaps names/addresses/IDs for placeholders like `[PERSON_1]`. A leak check refuses to send if anything listed remains. Calls the NEAR AI Cloud TEE, checks the signature over the request/response hashes, restores names locally, and keeps a hash-chained receipt that verifies offline. Aimed at lawyers. | [C] github.com/archtum66-dev/sealed-dossier README; X post |
| **RedactGate** | Self-hosted OpenAI-compatible gateway. Detection uses regex packs, Presidio and optional LLM-NER; values are reversibly tokenized into an AES-GCM vault; the answer is re-inflated on the way back. Keeps a hash-chained audit log, with chain heads anchored to a NEAR contract. Aimed at tax firms (SINs), AGPL. | [C] github.com/ctmakc/redactgate (`near-hackathon` branch); X post |
| **PrivatePay Agent** | Redacts invoices locally, sends only sanitized text to the NEAR AI TEE, verifies attestation and the response signature before paying. | [C] X post text |
| **privacy-hybrid** (not seen in the submissions feed) | Local Ollama keeps documents, chats and memory. Cloud models see masked text only. Hard-stops on SSN, card, password and bank numbers. Web search sees only a generic query. Includes a threat model and a self-assessed security dashboard. | [C] github.com/hgharsha/privacy-hybrid, created 2026-11-03 |
| **VAULTRY** | Cross-chain wallet with "private on-device AI". | [C] X post text |
| **Lullwatch** | Pregnancy labour timer. AI and Whisper run in the NEAR TEE, the phone verifies the proof, voice playback is on-device. | [C] github.com/tomcode1000/lullwatch |
| **GhosterDex** | Agent pays for private AI from a private NEAR Intents balance and mints its own API key. Covers payment privacy for inference. | [C] github.com/zunem001/ghosterdex-near |
| **near-hermes-browser** | Full Hermes agent running in a browser tab (Pyodide). Non-extractable WebCrypto keys, spending policy, "TEE-verified inference". | [C] github.com/TerexitariusStomp/near-hermes-browser |

### 2b. The other privacy-track entries, by cluster

All from demo-post text or READMEs [C].

- **Same workflow, now in a TEE, with a proof:**
  - Sealed Ledger (expense audit; it is the official prompt)
  - Skyll (grading of minors' exams; existing product)
  - Lullwatch
  - Áurea (FHIR clinical summaries plus an on-chain consent registry)
  - Veridom Pay (TEE photo inspector, milestone NFT)
  - SentinelReview (contract audit)
- **TEE receipts and on-chain verification:**
  - TEE Receipts: anchors NEAR AI signatures on-chain with ecrecover and a history of signer keys
  - Verdict (Anshv784): contract verifies the TDX quote on-chain through `tee-verifier.testnet`
  - PredicTEE
  - Realsies: signed bot words in a chat game
  - Measure: checks that the 16 MPC chain-signature nodes run published TDX software
- **AI judge or oracle in a TEE:** PatchBond, Judge on NEAR, Hive, AgentEscrow (in the open track), Milestone Vault, Verdict (Baheet18).
- **Confidential finance and private intents:**
  - Jurat: proof of balance without revealing it
  - Nema: sealed price marks
  - Unpair: Zcash unlinking
  - Aureus and Charter: confidential-intents funds
  - NOVA Copy-Trading
  - PipTradeDex Private Intent
  - VeilProof
  - VRX
  - BEXLEY
- **Encrypted secrets, escrow and inheritance:** Morrowseal (dead-man vault with OutLayer TEE), DeadDrop, Redline and Sealed Exploit (sealed vulnerability disclosure), Skarbnik (zkVM).
- **Agent payment firewalls tagged privacy:** GetLeash, AgentGuard, Kinwarden, Supply, TAINT, Guardrail, GhostShift, Throughput Treasury. These are mostly security entries.
- **Other GitHub repos tagged privacy** (some may not be submitted yet): nema, sealed-ledger, private-flex-inference-auctions, chaoticpunk/sealed-ledger, x0ne-Engine. x0ne-Engine is a confidential inference engine on a GCP TDX+H100 VM; it is not marked as a hackathon entry.

### 2c. Common competitor tooling

**[C] OutLayer** (TDX enclave for WASM, sealed secrets, HTTPS from the enclave) appears all over: Verdict, Nema, Jurat, Morrowseal, PatchBond, AgentEscrow, Sealed Exploit. Its team published a list of "10 builds" ideas (kucoin.com/news/insight/NEAR/6ae974dcbbcb520007459f05).

---

## 3. Past NEAR and NEAR AI hackathons (privacy, TEE, agents)

- **[C] NEARCON Innovation Sandbox, Jan–Feb 2026.** 485 participants and 85 projects.
  - "Private Web & Private Life": winner **Argus** (github.com/VitalPointAI/argus), runner-up **AttestAI**.
  - NOVA bounty: **PrivateRAG** (client-side Pyodide PDF parsing, vectorless table-of-contents retrieval, encrypted storage on NOVA), Proof of Pulse, Privy Finance.
  - Sources: LinkedIn NEAR DevHub post 2026-02-20; nearn.io/nf-bo/8/28; coinlaunch.space.
- **[C] PAICE + NEAR (NEARCON Sandbox entry).** Three-layer TEE model cascade on NEAR AI Cloud plus SHA-256 score attestations on the `paice.near` contract. Its README says 0 mainnet attestations were ever written and it was not adopted (github.com/snapsynapse/paice-near-integration). **[I]** "Hash it to a NEAR contract" alone was not sticky.
- **[C] Useful Agents Hackathon, SF, March 2025.** Teams had to show benchmarks. 1st Postt, 2nd DiligenceAI, 3rd NEAR Food; NEAR Food got Phala and xTrace recognition for TEE privacy (near.org/blog/building-useful-agents-sf-hackathon...). **[I]** NEAR judges have previously rewarded measured, quantified utility.
- **[C] Other events:**
  - Coinbase Onchain AI Hackathon, Feb 2025: Chainsmokers (MCP chatbot), Mosaia (near.org blog).
  - One Trillion Agents hackathon: 2,049 participants, 147 projects (hackbox.co/hacklog).
  - Agents Without Masters, DoraHacks (DeFAI agents).
  - Oz Builder Day: Shade Agents prize to Verity; Phala prizes to VGuard and TEE Banking.
  - DoraHacks Shade Agent bounty.
- **[C] A serial hackathon winner** won the NEAR prize at BUIDL Asia Seoul 2025 with a "TEE mental-health assistant" (github.com/JingYuan0926). **[I]** The TEE therapist or health assistant is a known pattern.

---

## 4. Products in confidential and private AI: claims and gaps

| Product | What it claims [C] | Gap / note |
|---|---|---|
| **NEAR AI Cloud** (the track's platform) | TDX plus NVIDIA H200 CC; attestation via `/v1/attestation/report?model=` with a nonce; per-response signatures; OpenAI-compatible; same per-token price as normal inference (near.ai; docs.near.ai/cloud/private-inference; blog "Assume we're lying", 2026-10-02). Hosts `openai/privacy-filter` PII spans at $0.01/M tokens. `cloud-api` has **auto_redact**: inside the TEE it detects PII, swaps placeholders, sends only redacted text to the provider, and un-redacts the stream; mapping per request, never persisted (github.com/nearai/cloud-api `crates/services/src/auto_redact/mod.rs`). | [C] Its own docs say privacy-endpoint receipts are gateway-signed only: "no per-response signing contract with the model provider" (docs/privacy-signatures.md). [I] Redaction happens after plaintext reaches the gateway TEE, so it is not local-first. |
| **IronClaw 1.0** (NEAR AI) | Rust agent runtime in a TEE: credential vault, WASM tool sandbox, "secrets never reach the model", decide/act split through a "guard"; tops PinchBench, ClawBench and OfficeQA (near.ai/blog/introducing-ironclaw-1-0, 2026-07-27). | [I] Covers agent security; does not cover minimizing user data before it reaches the agent. |
| **Brave Leo × NEAR AI** | GLM 5.3 Flash in NEAR TEEs. Browser encrypts with OHTTP to an enclave key released only after Brave's open-source verifier checks TDX, NVIDIA and a reproducible build; Brave's relay strips the IP; search queries are issued from inside the TEE (brave.com/blog/browser-ai-e2ee, 2026-10-15). | [C] Brave lists as not done: moving verification into the browser itself, a public TEE key log, attestation of exact model weights (The Register, 2026-10-16). |
| **Apple PCC** | Stateless; enforceable guarantees; no privileged runtime access; non-targetability; verifiable transparency log of production images (security.apple.com/blog/private-cloud-compute). | Apple-only and first-party. Sets the standard others cite. |
| **Google Private AI Compute** | Gemini on TPU "Titanium Intelligence Enclaves" plus SEV-SNP; remote attestation; "not even Google" (blog.google, 2025-11-11). | [C] NCC audit (via The Register): safe "unless Google, as a whole organization, decides" otherwise; only binary digests published so far. |
| **Tinfoil** | Hopper/Blackwell CC, SEV, TDX; SDKs verify attestation and supply chain automatically; Chat, Inference and Containers; multi-GPU CC (tinfoil.sh). Supplies Duck.ai's "zero provider visibility" models. | Open models only. |
| **Privatemode (Edgeless)** | E2E encryption from the device; AMD + H100; client verifies attestation; local proxy exposing OpenAI- and Anthropic-compatible endpoints; BSI C5 "very strong attestation"; StGB §203 (privileged professions) ready (privatemode.ai, docs). | EU, enterprise focus. The local proxy is a close architectural cousin of a local intermediary, but it encrypts and does not minimize. |
| **Confident Security / OpenPCC** | Apache-2.0 open version of PCC: OHTTP relay, attestation, transparency, unlinkable anonymous requests including payment side channels; managed CONFSEC; "financial responsibility for any breach" (github.com/openpcc/openpcc; blog 2025-11-05). | [C] Their blog says "redaction and obfuscation are incomplete and prone to leaks", an argument against redaction-first products. |
| **Phala / RedPill** | Attested gateway in a TEE plus verified GPU-TEE providers (Phala, Tinfoil, NEAR AI, Chutes); signed receipts; channel binding fails closed; optional ACI field-level E2EE (redpill.ai/verify; docs.phala.com). | [C] "Optional middleware sees plaintext after gateway decryption." |
| **OLLM** | One API with TEE models (NEAR and Phala) and ZDR models (Vercel, contract only); per-request attestation receipts (docs.ollm.com). | [C] Out of scope: client compromise and "data exposure before requests are sent". That is the gap a local intermediary covers. |
| **Nillion nilAI** | OpenAI-compatible LLMs in NVIDIA CC TEEs; environment attestation plus signed responses; nilDB storage with MPC or homomorphic encryption (docs.nillion.com). | Same TEE-API commodity. |
| **Secret AI (SCRT Labs)** | SecretVMs (SGX/SEV/H100), confidential AI API, on-chain worker attestation, planned private-RAG database (secretai.scrtlabs.com; SecretFoundation docs). | Same commodity. |
| **Venice** | Proxy with history in local browser storage; modes Anonymous / Private (contract) / TEE (NEAR AI Cloud and Phala) / E2EE; E2EE disables search, memory and tools (venice.ai/privacy; docs.venice.ai). | [C] Venice states that E2EE loses memory and tools: a gap for private memory. |
| **Proton Lumo** | No logs; zero-access encrypted history; open models on Proton servers; prompts asymmetrically encrypted to the GPU servers (proton.me/support/lumo-privacy). | [I] Not attested or TEE-backed; trust is in Proton. |
| **Duck.ai** | Strips IP and metadata; ZDR agreements; Tinfoil TEE models labelled "zero provider visibility"; chats not stored by default (duckduckgo.com help pages). | Anonymizes identity, not the content of prompts. |
| **Maple AI / OpenSecret** | AWS Nitro enclave backend; client checks PCR0, nonce and Amazon root; chained to the model enclave's attestation; encrypted sync (maple.ai/proof; blog.opensecret.cloud). | [C] Their own FAQ: you do not attest the model enclave directly; the browser check code is served by Maple. |
| **Lucid Computing** | "AI Passport" receipt per inference covering model identity, auditor results, region; a GDPR mode auto-removes names, emails and phones; $13M seed reported (lucidcomputing.ai; dealroom 2026-11-04). | Enterprise, sovereign focus. |
| **Opaque** | Hardware-enforced agent governance, Agent Manifest, "Confidential MCP" (PRNewswire, 2026-06-23). | [C] opaque.co says "Our team is joining Anthropic". |
| **Fortanix Armet AI** | Turnkey agentic platform on NVIDIA CC; composite CPU+GPU attestation; HSM key release only after attestation; guardrails that anonymize (fortanix.com). | Enterprise. |
| **Anjuna Seaglass** | Runs any container confidentially with no code changes; policy-based attestation and secret release (anjuna.io). | Infrastructure, not an end-user product. |
| **Azure confidential AI** | H100 confidential VMs on SEV-SNP; Confidential Inferencing with OHTTP/HPKE, attested KMS key release and a transparency ledger; launched with Whisper (techcommunity.microsoft.com, 2024-09-24). | Narrow model coverage at launch. |

**[I] Pattern across all of the above:** the market treats "TEE + attestation + OpenAI-compatible API" as a commodity with at least 8 suppliers. The differentiators are now:
- client-side verification;
- metadata unlinkability (OHTTP, relays, payment privacy);
- transparency logs;
- what happens before the request leaves the device.

---

## 5. Prior art: local-first intermediaries between users and cloud LLMs

### 5a. PII redaction proxies

- **Microsoft Presidio.**
  - Does: [C] MIT; NER plus patterns; only its encrypt operator is reversible; not a proxy; moving to "Data Privacy Stack" community governance; the project itself warns it will miss things (nonimo.ai and lyzr.ai 2026 comparisons).
  - Gap: you build the proxy and round trip yourself.
- **LLM Guard.**
  - Does: [C] reversible Vault/Deanonymize round trip plus injection scanners.
  - Gap: [C] repo archived July 2026; Protect AI is now part of Palo Alto Networks.
- **Private AI (now Limina), Protecto, Skyflow.**
  - Does: [C] Limina is a de-identification API with 52 languages; Protecto offers consistent semantic tokens and role-based unmasking, from $250/month; Skyflow is a vault with tokens rehydrated per caller and an MCP gateway.
  - Gap: [C] vendor-reported accuracy with no independent benchmark; Skyflow's Kong plugin buffers whole completions (no streaming).
- **The wider field** is crowded and commoditized. [C] Comparison pages list 14 to 25 tools: LiteLLM+Presidio, Portkey, Cloudflare AI Gateway, Kong AI Sanitizer, Bedrock Guardrails, Nightfall, Lakera, Shadow, Rehydra, Maskflare, Nonimo and others (getshadow.dev/compare; maskflare.com).
- **Shared gaps** [I, supported by the OpenPCC blog and Presidio's own warning]:
  - entity-level masking leaks through context (quasi-identifiers, rare facts, writing style);
  - it breaks tasks that need the real value;
  - it measures entity recall, not re-identification risk;
  - it accumulates leakage across turns;
  - nobody proves what was not sent.

### 5b. Research protocols

- **Minions / MinionS (Stanford Hazy Research).**
  - Does: [C] the local model reads the long context. Minion: 30.4× lower remote cost at 87% of quality. MinionS: about 5.7× lower cost at 97.9% of quality with an 8B local model; local models under 3B are not effective (arXiv 2502.15964; blog 2025-02-24).
  - Secure Minions: [C] the remote step runs in an H100 CC enclave behind SEV-SNP, with attestation and an encrypted channel (Hazy blog 2025-05-12; ollama.com/blog/secureminions).
  - Gap: [I] optimized for cost, not for measuring privacy leakage.
- **PAPILLON (Columbia/Stanford, NAACL 2025).**
  - Does: [C] a local model rewrites the prompt for the untrusted model, then aggregates the answer locally. PUPA benchmark (PII from WildChat). Best pipeline: 85.5% quality retained, 7.5% leakage (aclanthology.org/2025.naacl-long.173; github Columbia-NLP-Lab/PAPILLON).
  - Gap: single turn; no attestation.
- **PlanTwin (UTS/CSIRO Data61, arXiv 2603.18377, IEEE TSC 2026).**
  - Does: [C] projects the local environment into a de-identified "digital twin" graph in four stages (extract, redact, generalize, schema). The cloud planner sees only the twin and a bounded capability interface. A local gatekeeper enforces **cumulative disclosure budgets** and multi-turn leakage control. Tested on 60 tasks across 10 domains: 3 of 4 planners reach planning-quality score > 0.79, within about 4% of the raw-context baseline.
  - Gap: [C] residual identifiability against structural-fingerprint adversaries; research code, not a product.

### 5c. Commercial hybrid

- **Perplexity Hybrid compute on Mac.**
  - Does: [C] launched 2026-09-01 for Pro, Max and Enterprise. Cloud orchestrator plus a local subagent (Gemma 4 E4B, Qwen3.6 35B-A3B, or a Perplexity model). An on-device classifier "privacy gate" masks, keeps local, refuses or asks consent; credentials, cards and government IDs get the strictest handling; Seatbelt sandbox; Mac needs 24 GB+ (perplexity.ai/hub/blog/introducing-hybrid-compute-on-mac; VentureBeat).
  - Gap: [I] the cloud side is ordinary Perplexity or frontier clouds with no TEE or attestation; Mac only; closed.

### 5d. MCP gateways and firewalls

- **Invariant MCP-Scan, now Snyk agent-scan.**
  - Does: [C] scans for tool poisoning, rug pulls, shadowing and toxic flows; pins tools by hash.
  - Gap: [C] tool names and descriptions are sent to Invariant's API. Mainly static scanning.
- **Lasso MCP Gateway (open source).**
  - Does: [C] proxies MCP servers; Presidio PII masking and secret masking; reputation scanner.
  - Gap: [C] advanced guardrails go through Lasso's API.
- **Opaque Confidential MCP.**
  - Does: [C] hardware-enforced governance of tool calls.
  - Gap: [C] enterprise product.
- **Shared gap** [I]: these are security gateways for prompt injection and DLP. None ties tool-call egress to a per-user disclosure budget with attested downstream inference.

### 5e. Agent memory products

- **Mem0 / OpenMemory.**
  - Does: [C] the hosted MCP at mcp.mem0.ai keeps memories in your Mem0 account.
  - Gap: [C] OpenMemory, the self-hosted local server, was "removed from the Mem0 repository on 29 July 2026" (pryzm-memory.com, 2026-09-23; this conflicts with older mem0.ai copy calling it local-first).
- **Letta.**
  - Does: [C] Apache-2.0 stateful agents, cloud or self-hosted.
  - Gap: [C] memory export is only "partly" possible (thecontinuitylayer.com).
- **Supermemory.**
  - Does: [C] MIT; has a local single binary.
  - Gap: [C] extraction LLM, Firecrawl, Gemini for PDFs and telemetry (on by default) can all leave the machine (supermemory.ai blog).
- **Venice E2EE mode.**
  - Gap: [C] "No web search or memory".
- **Shared gap** [I]: memory is either hosted in plaintext, or local but sent raw to whatever LLM extracts or uses it. Nobody pairs local memory with minimized, attested cloud use.

---

## 6. Conclusions

### Crowded (judges will see many)

1. **[C/I] "Upload a sensitive document, analyze it in the NEAR TEE, show a Verified panel."** Expense audit, grading, legal, medical, invoices. It is the official prompt, so expect dozens.
2. **[C] Agent payment and spending firewalls.** Security track at 137 and growing; many also tag privacy.
3. **[C] TEE signature receipts anchored or verified on-chain.** TEE Receipts, Verdict, PredicTEE, Realsies, PAICE in the past.
4. **[C] AI judge, arbiter or oracle in a TEE** for escrow, bounties and prediction markets.
5. **[C] Local PII placeholder redaction plus NEAR AI TEE plus a receipt.** Sealed Dossier, RedactGate, PrivatePay, privacy-hybrid; NEAR's own `auto_redact` makes the basic version redundant.
6. **[C] Confidential-intents trading or treasuries and sealed-bid markets.**
7. **[C] Encrypted inheritance, dead drops and sealed disclosure** (OutLayer-based).

### Open space (INFERRED, with the evidence behind each)

- **Leakage measured across sessions, not entities.** A disclosure budget across turns and sessions, with a re-identification metric (PlanTwin-style), scored on a public benchmark such as PUPA.
  - Why open: no hackathon entry reports leakage numbers.
  - Fit: NEAR judges have rewarded benchmarks (Useful Agents), and the AI screeners check "feature verification".
- **Semantic minimization before the TEE.** The local model rewrites or decomposes (PAPILLON or Minions) rather than swapping placeholders; only the minimum goes to NEAR AI Cloud, and the attested answer is merged locally. This goes beyond auto_redact, which leaves context-level leakage untouched.
- **Proof of what did not leave.** A signed local disclosure ledger (what was withheld, generalized or sent), combined with the TEE's signature over what was sent.
  - Why open: Sealed Dossier proves what was sent; nobody gives a user-auditable account of egress over time.
- **Verification by the user's own client, plus a key log.** Brave publicly lists in-browser verification, a TEE key transparency log and weight-level attestation as unfinished. tee-receipts only partly covers key history.
- **Metadata unlinkability for any app.** An OHTTP-style relay plus private payment for NEAR AI Cloud, so the provider sees neither content nor who asked. Brave does this only for Leo; GhosterDex only covers payment.
- **Private memory.** Local memory store where the cloud sees only minimized, purpose-bound facts in an attested TEE.
  - Why open: Mem0 dropped its local server; Venice E2EE disables memory; Supermemory Local still calls cloud services.
- **Privacy firewall at the agent-tool (MCP) egress point.** Per-tool data budgets, with downstream inference attested.
  - Why open: existing MCP gateways do injection and DLP and often send data to vendor APIs.
- **Plain-language guarantees and honest limits.** Say clearly what TEEs do not protect: side channels, client compromise, data before send. OLLM, Maple and Lucid document these limits; few hackathon entries do.

### What judges will see over and over (INFERRED)

- A "Verified ✓" badge built from nonce + attestation + signature, presented as the whole privacy story.
- Placeholder PII masking ([PERSON_1]) presented as novel.
- A hash of something written to a NEAR contract "for verifiability", with no consumer of that hash.
- Sector re-skins: legal, medical, tax, payroll, therapy, grading.
- Multi-track tagging (5 to 9 tracks per entry) and AI-written READMEs with badges.

**Practical implications:**
- Get past the AI screen with a reproducible "do X - see Y" README and a no-key replay mode (several top entries do this).
- Back every claim with a test.
- Disclose the baseline (Q-002 to Q-004).
- Compare yourself explicitly against NEAR's `auto_redact`, Sealed Dossier, RedactGate and Perplexity Hybrid, so judges see what is new.