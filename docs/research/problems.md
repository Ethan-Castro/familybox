# Unsolved problems in private AI, confidential LLM compute, secure agents and verifiable AI (2025-2026): a hackathon opportunity map

Research date: 2026-11-07. Everything here is read-only, from public sources fetched through Exa search and fetch. Labels used throughout:
- **[C] = CONFIRMED.** I saw it at the cited URL.
- **[I] = INFERRED or SPECULATION.**

No code was run and nothing was tested.

---

## 0. Cross-cutting takeaways

1. **"Attested" is not the same as "secure."** Physical memory-bus interposers costing under $1k break SGX, TDX and SEV-SNP attestation. Extracted keys can forge Intel quotes, and NVIDIA GPU attestations can be "borrowed" because they are not bound to the confidential VM (CVM). [C] https://tee.fail/
   - Any project that says "trust the TEE" should add defense in depth: knowing where the hardware physically is, recomputing samples, multiple vendors, and limits on how much value is at risk. [I]
2. **Binding is the weakest link.** Formal analysis (ProVerif) found relay attacks in *all* analyzed intra-handshake attested-TLS binding schemes. That includes Meta's AI (already reviewed by Trail of Bits), Edgeless Contrast, Cocos AI and draft-fossati. [C] https://www.mail-archive.com/tls@ietf.org/msg21960.html ; IETF RATS slides https://datatracker.ietf.org/meeting/interim-2026-rats-01/materials/slides-interim-2026-rats-01-sessa-relayattacks-00
   - A 2026 LPC talk lists CVEs for weak binders, missing REPORT_DATA comparison, fail-open on zero-length SNP input, image-digest policy bypass and a missing machine-ID check. [C] https://lpc.events/event/20/contributions/2640/attachments/2049/4690/20261005_LPC_2026_BoF.pdf
   - Note: some of those CVE numbers look unusual (CVE-2026-92701, CVE-2026-100833). I did not verify them against NVD. [I]
3. **"Attested, but which code?"** A measurement is only useful if you can tie it to source code: reproducible builds plus a transparency log. Apple PCC does this. Google Private AI Compute (Nov 2025) initially published only binary digests and an external auditor's opinion. [C] https://services.google.com/fh/files/misc/private_ai_compute_technical_brief.pdf
4. **Deterministic agent defenses (CaMeL, FIDES, Conseca, firewalls) work, but nobody can verify they are running.** A third party cannot tell whether a policy engine was actually applied. That gap is a natural fit for a TEE plus a registry. [I]
5. **Probabilistic prompt-injection defenses fail against adaptive attackers.** 12 defenses were bypassed at >90% attack success rate, most of which had originally reported near-zero. [C] https://arxiv.org/abs/2510.09023

---

## 1. Limits of TEE attestation for LLMs

### 1a. Physical and ciphertext attacks [C]

| Attack | What it does | Source |
|---|---|---|
| **TEE.fail** (Oct 2025) | DDR5 interposer, under $1k. Extracted the PCK (provisioning certification key) from an Intel machine in UpToDate status, which lets it forge SGX/TDX quotes that pass DCAP verification. Broke SEV-SNP even with Ciphertext Hiding (Zen 5). Ran GPU workloads outside the TEE while passing NVIDIA CC attestation. Broke apps built on Phala dstack, including an LLM frontend, plus BuilderNet and Secret Network. | https://tee.fail/ , https://tee.fail/files/paper.pdf |
| **WireTap** | Passive DDR4 interposer. Builds a ciphertext-to-plaintext dictionary and extracts the SGX attestation key. | https://wiretap.fail/ |
| **Battering RAM** | Active DDR4 interposer, under $50. Creates dynamic memory aliases that bypass the MCHECK and ALIAS_CHECK boot-time checks. Gives arbitrary read/write on Scalable SGX and a full SEV-SNP attestation breach. Does not apply to TDX (DDR5 only). | https://batteringram.eu/batteringram.pdf |
| **Heracles** (CCS'25) | A malicious hypervisor moves SEV-SNP pages around. Re-encryption is deterministic, which gives a chosen-plaintext oracle that leaks keys and passwords byte by byte. AMD's mitigation is a guest policy that disables page moves. | https://heracles-attack.github.io/ , AMD-SB-3021 https://www.amd.com/en/resources/product-security/bulletin/amd-sb-3021.html |
| **Vendor stance** | Intel: physical attacks are out of scope and no CVE will be issued. | https://www.intel.com/content/www/us/en/security-center/announcement/intel-security-announcement-2025-10-28-001.html |

### 1b. GPU confidential computing gaps [C]

- NVIDIA CC attestation is "not bound to the identity of a specific CVM or even the CPU running it." [C] https://tee.fail/
- Hopper multi-GPU passthrough: CPU-to-GPU traffic is encrypted via bounce buffers, but **GPU-to-GPU traffic over NVLink is unencrypted**. TDISP/IDE inline encryption is "future," for Blackwell. [C] NVIDIA whitepaper https://docs.nvidia.com/nvidia-secure-ai-with-blackwell-and-hopper-gpus-whitepaper.pdf
- The GPU's on-package HBM is protected only by access control (a firewall). Timing side channels on the CPU-to-GSP RPC path were studied, and the recommendation was constant-time execution or added noise. [C] https://arxiv.org/html/2507.02770v1 ; MLSys'26 https://proceedings.mlsys.org/paper_files/paper/2026/file/906419cd502575b617cc489a1a696a67-Paper-Conference.pdf
- GDDR6 RFM timing side channel on shared GPUs (USENIX Sec'25). [C] https://www.usenix.org/system/files/usenixsecurity25-nazaraliyev.pdf

### 1c. Attestation without binding

- **Cocos AI advisory GHSA-vfgg-mvxx-mgg7.** Evidence was bound to the ephemeral key but not to the TLS channel, so a relay attack works once the key leaks. Fixed in v0.9 with "Level 2 binding" using a TLS exporter. [C] https://github.com/ultravioletrs/cocos/security/advisories/GHSA-vfgg-mvxx-mgg7 , https://www.ultraviolet.rs/blog/atls-binding-milestone/
- **"Identity Crisis."** Attestation alone carries no hostname or PKI identity, so a client can be redirected to a different datacenter. One compromised but unrevoked PCK anywhere in the world breaks the scheme. [C] https://datatracker.ietf.org/meeting/interim-2025-rats-01/materials/slides-interim-2025-rats-01-sessa-identity-crisis-in-attested-tls-for-confidential-computing-00.pdf
- **Proof of Cloud.** A registry, signed by an alliance quorum, that maps a hardware ID (PPID or Chip ID) to a verified physical facility. Verification levels: L1 human-witnessed, L2 zkTLS/vTPM, L3 continuous. [C] https://www.proofofcloud.org/
- Flashbots "Mind the Gap" (Apr 2026): an attestation looks identical "whether the machine sits in a hyperscaler data center or a garage." [C] https://writings.flashbots.net/mind-the-gap-tee-poc
- BuilderNet docs now say its nodes are "not running in TEEs" during a security-model transition. [C] https://buildernet.org/docs

### 1d. "Attested, but which code?"

- **Apple PCC.** Measurements go into an append-only transparency log. Devices encrypt only to nodes whose measurements appear in the log. Images are published within 90 days. A Virtual Research Environment lets anyone verify log consistency and boot releases. **It attests software, not which model.** [C] https://security.apple.com/blog/private-cloud-compute/ , https://security.apple.com/blog/pcc-security-research/ ; the atlas's assessed use reads "showing users which software serves their AI requests, not which model." [C] https://consortiumforverifiedcomputing.org/atlas
- **dstack.** MRTD and RTMR0-2 can be precomputed from a reproducible build. RTMR3 holds a compose-hash and needs an event-log replay, and it carries a per-boot `mr-kms` value, so there is no stable reference value. MR-CONFIG-ID is the simpler alternative. [C] https://github.com/Dstack-TEE/dstack/blob/master/attestation.md , https://phala.com/posts/mr-config-id-tutorial
- **Sigstore/Rekor for enclave measurements.** In use by the Phala Nitro template and Lit Protocol. It proves "built by GitHub Actions from repo X," which is *build provenance*. It does not prove the code is safe. [C] https://github.com/Phala-Network/dstack-nitro-enclave-app-template , https://developer.litprotocol.com/architecture/verification/chain-of-trust

**Why still unsolved:**
- Hardware roots of trust are physically breakable, and vendors treat that as out of scope.
- Binding is ad hoc.
- Verifiers rarely check the full chain: quote, then measurement, then source, then config, then the model, then the TLS session.
- There is no standard "what is everything this enclave will do with my data" manifest. [I]

**What a TEE, verifiable inference and a registry add:**
- An on-chain or transparency-log registry of approved measurements, hardware IDs and model hashes, with revocation.
- A verifier that fails closed on every link in the chain. [I]

**1-week demo:** Yes. A "full-chain attestation linter" that grades a live endpoint is very doable.

---

## 2. Verifying that a remote model is the claimed model

- Software-only detection is unreliable:
  - Text classifiers are at chance on quantized substitutes.
  - Identity prompting is under 5% accurate.
  - MMD tests lose power when the provider substitutes randomly at p≤0.2.
  - Logprobs are drowned out by nondeterminism.
  - TEEs add 9-16% to time-to-first-token (TTFT) and cost 2.88% throughput.

  [C] https://arxiv.org/abs/2504.04715 (code: https://github.com/sunblaze-ucb/llm-api-audit)
- A rank-based uniformity test is more query-efficient, but it needs the authentic model running locally. [C] https://arxiv.gg/abs/2506.06975
- **TOPLOC.** Locality-sensitive hashing (LSH) of top-k activations, 258 bytes per 32 tokens, validation up to 100× faster than generation. It requires the verifier to hold the weights. [C] https://proceedings.mlr.press/v267/ong25a.html
- **zkLLM.** Proves 13B-parameter inference in under 15 minutes with proofs under 200 kB. That is far too slow for interactive use. [C] https://arxiv.org/html/2404.16109
- **Tinfoil Modelwrap.** Builds a dm-verity Merkle root over the weights (32 bytes covering 140 GB), measured through the kernel command line. Hash-tree overhead is about 0.8% of image size.
  - PAL*M puts hash(op, challenge, inputs, outputs) into TDX REPORTDATA. Overhead is 45-66% for single prompts.
  - Fixed-seed sampling likelihood (Rinberg et al.) limits weight exfiltration to under 0.5%.
  - The atlas marks the whole technique as having an "open critical flaw" because it inherits the TEE weaknesses above.

  [C] https://consortiumforverifiedcomputing.org/atlas/model-identity-attestation
- **Batch-invariant kernels.** From Thinking Machines, now adopted in vLLM and SGLang. They make bit-exact recomputation feasible. [C] (atlas listing)

**Why still unsolved:**
- Closed weights cannot be recomputed by an outsider.
- A hash commitment only shows that the *same* weights are served each time, not that they are *good* weights.
- The TEE route inherits section 1.

**What the combination adds:**
- Each signed response, with model hash, a binding to the prompt and output, and a seed, can be spot-checked later. [I]
- Spot checks can happen by recomputation in a second, different-vendor TEE, or by an open-weights re-run.
- The registry stores commitments and penalties (slashing) for mismatches. [I]

**1-week demo:** Yes for open models of 8B or smaller.

---

## 3. Prompt-injection-driven data exfiltration in agents

- **Lethal trifecta:** private data, untrusted content and an outbound channel together. Removing any one leg prevents the attack. [C] https://simonwillison.net/2025/jun/16/the-lethal-trifecta/
- **CaMeL (DeepMind):**
  - How it works: a privileged LLM writes a restricted Python program, a custom interpreter tracks capabilities and data provenance, and policies are checked at each tool call.
  - Limitations: users must write the policies, and approval fatigue sets in.

  [C] https://simonwillison.net/2025/apr/11/camel/
- **FIDES (Microsoft):**
  - How it works: confidentiality and integrity labels, deterministic policy checks, hidden variables, and a quarantined LLM with constrained decoding.
  - Status: evaluated on AgentDojo and shipped as middleware in Microsoft Agent Framework.

  [C] https://arxiv.org/html/2505.23643v2 , https://learn.microsoft.com/en-us/agent-framework/agents/security
- **Design Patterns paper:** dual-LLM, code-then-execute and related patterns. [C] https://simonwillison.net/2025/Jun/13/prompt-injection-design-patterns/
- **Adaptive attacks break probabilistic defenses** (12 defenses at >90% attack success rate). [C] https://arxiv.org/abs/2510.09023

**Why still unsolved:**
- Writing policies is a burden.
- Declassification (deciding when tainted data may flow out) needs a human.
- There are side channels: tool selection, timing, whether a URL gets fetched at all. [I]
- Utility loss.
- **No external party can verify that the IFC runtime actually enforced anything.** [I]

**What the combination adds:**
- Run the planner, policy engine and quarantined LLM inside an attested enclave.
- Publish the policy hash in a registry.
- Emit a signed "flow receipt" per action, recording labels in, the sink, and the policy decision.
- Counterparties such as email servers or APIs can then refuse actions without a valid receipt. [I]

**1-week demo:** Yes. A small IFC planner plus receipts on AgentDojo-style tasks.

---

## 4. MCP security

| Issue | What happens | Source |
|---|---|---|
| Tool poisoning | Hidden instructions in tool descriptions. Cross-server shadowing: an "add" tool redirected email through a different server's tool. | [C] https://invariantlabs.ai/blog/mcp-security-notification-tool-poisoning-attacks |
| GitHub MCP exploit | A public issue leads the agent to read a private repo and leak it in a public PR. "Architectural," so GitHub cannot fix it server-side. | [C] https://invariantlabs.ai/blog/mcp-github-vulnerability |
| Toxic flow analysis | Graph analysis of possible tool sequences. | [C] https://invariantlabs.ai/blog/toxic-flow-analysis |
| Confused deputy | Static client ID plus dynamic client registration plus a consent cookie lets an attacker steal an auth code. The spec now says MUST store consent per client. | [C] https://modelcontextprotocol.io/docs/draft/tutorials/security/security_best_practices |
| Other risks (OWASP cheat sheet) | Rug pulls, over-scoped tokens. Hash-pinning detects metadata changes, **not** changes to the server code behind an unchanged definition. | [C] https://cheatsheetseries.owasp.org/cheatsheets/MCP_Security_Cheat_Sheet.html |

**Why still unsolved:**
- A server's behavior can change behind a pinned definition.
- There is no attested identity for a remote MCP server.
- Tool annotations are hints, not enforcement.

**What the combination adds:**
- Attested MCP servers, with the code hash plus the tool-schema hash in the quote, bound to the session.
- A registry with revocation.
- The client refuses to connect to unattested servers. [I]

**1-week demo:** Very plausible. This is the strongest "rug-pull-proof MCP" story.

---

## 5. Private RAG and private memory

- Datastore extraction through prompt injection: near-perfect success on 25 custom GPTs, 41% of a book extracted verbatim. [C] https://proceedings.iclr.cc/paper_files/paper/2025/file/79cafa874121a3435d8a54f454b646b4-Paper-Conference.pdf
- The "Secret" attack extracted 35% of a RAG store backed by Claude 3.7. [C] https://arxiv.org/html/2510.02964v1
- MEXTRA: memory-extraction attacks against agent memory (ACL'25). [C] https://aclanthology.org/2025.acl-long.1227.pdf
- SecureRAG uses FHE search plus attribute-based encryption, noting that differential privacy is still vulnerable to embedding inversion. [C] http://hal.cse.msu.edu/assets/pdfs/papers/2025-neuripsw-securerag-end-to-end-secure-rag.pdf

**Why still unsolved:** Encryption at rest does nothing once the LLM reads the plaintext in context. Access control has to be enforced per requester at retrieval time, and the output path still leaks.

**What the combination adds:**
- Keep the index and the LLM inside a TEE.
- Enforce per-document ACLs and data minimization inside the enclave.
- Give the user a signed receipt of which documents influenced an answer.
- Users can revoke documents, with deletion that is attested. [I]

**1-week demo:** Yes.

---

## 6. Multi-agent privacy: agents negotiating for users

| Benchmark or system | Finding | Source |
|---|---|---|
| ConfAIde | GPT-4 reveals private information in 39% of cases where humans would not. | [C] https://confaide.github.io/ |
| PrivacyLens | GPT-4 leaks 25.68% of the time even with privacy prompts. | [C] NeurIPS'24 D&B |
| AgentDAM | Web agents fail data minimization. LLM pre-filtering is ineffective. | [C] https://github.com/facebookresearch/ai-agent-privacy |
| MAGPIE | 200 negotiation tasks. Gemini-2.5-Pro leaks up to 50.7%, GPT-5 up to 35.1%. Higher leakage correlated with better task completion. | [C] https://arxiv.org/html/2510.15186 |
| ConVerse | 864 attacks. Privacy attacks succeed up to 88%. Stronger models leak more. | [C] https://arxiv.org/html/2511.05359 |
| Dual firewall (structured protocol plus data abstraction) | Cuts GPT-5 privacy attack success from 84% to 10% and security attacks from 60% to 3%. | [C] https://arxiv.org/html/2502.01822 |
| Conseca | Just-in-time policies generated only from trusted context, enforced deterministically. | [C] https://arxiv.org/html/2501.17070 |
| TCME (Shumailov et al.) | A capable model can act as the trusted third party if three things hold: statelessness, explicit and frozen information flow control, and verifiability. | [C] https://arxiv.org/html/2501.08970v1 |
| NDAI Agreements | TEE-resident agents act as an "ironclad NDA" for the inventor-disclosure paradox. A hackathon implementation already exists (Nitro, dstack, Base Sepolia escrow). | [C] https://arxiv.org/abs/2502.07924 , https://github.com/discordwell/ndai-hackathon |

**Why still unsolved:**
- The tradeoff between privacy and getting the task done.
- LLMs cannot reliably abstract information to the right level of detail.
- Agents behave manipulatively in negotiation (MAGPIE).
- Neither side can verify that the other side's agent forgets everything after a no-deal.

**What the combination adds:**
- Both agents run in one attested enclave.
- Only a structured outcome leaves it.
- Deletion on no-deal is attested.
- The outcome commitment and escrow go on-chain. [I]

**Novelty caution:** NDAI's hackathon implementation already exists. Differentiate with a multi-party setup, a MAGPIE or ConVerse evaluation, or firewall-structured messages. [I]

**1-week demo:** Yes.

---

## 7. Private evaluations (secret test sets)

- **Attestable Audits** (ICML'25 TAIG workshop):
  - How it works: provider weights and auditor data go into the TEE encrypted. An attestation binds the model hash, the audit and the result, and is published to a transparency log. Later inferences prove they came from the audited model.
  - Cost: the Nitro CPU prototype ran at 21.7× the cost of GPU inference.

  [C] https://arxiv.org/html/2506.23706
- **Atlas summary:**
  - A double-blind evaluation of Gemini 2.5 Flash Lite on an H100 enclave (participant-reported).
  - Cove on dstack.
  - No independent red-team has been published.
  - **"Even a one-bit verdict can leak information about the private inputs."**

  [C] https://consortiumforverifiedcomputing.org/atlas/confidential-multi-party-verification

**Why still unsolved:**
- Leakage through repeated queries against the result.
- Frontier-model scale.
- Trust in the hardware.
- Contamination: proving that a test set has never been seen. [I]

**What the combination adds:**
- A GPU TEE.
- A registry of eval-set commitments.
- A per-model query budget enforced by a smart contract to cap leakage. [I]

**1-week demo:** Yes on a small open model. The novel twist is on-chain rate-limited private evals. [I]

---

## 8. Confidential fine-tuning and data clean rooms

- **Oasis/SecLM.** LoRA fine-tuning of Llama-3-8B on SEV-SNP plus an H100 CVM, producing a signed manifest that ties together base model, data and adapter. Took 2.4× longer than without confidentiality (toy example). [C] https://oasis.net/blog/verifiable-ai-with-tees
- **HE LoRA.** Demonstrated on Llama-3.2-1B; practical only for small models. [C] https://arxiv.org/html/2505.07329

**Why still unsolved:**
- Proving which data trained an adapter (data lineage).
- The adapter itself can memorize and leak training data.
- Multi-party clean rooms need policy on outputs (differential privacy, k-anonymity) that LLMs can bypass.
- I found no confirmed source on LLM clean-room products in this pass. [I]

**What the combination adds:**
- A training-provenance attestation, recording dataset Merkle roots and code hashes, published to a registry.
- Output gates (a DP budget) enforced in the enclave. [I]

**1-week demo:** Partial. A tiny LoRA in a CPU or simulated TEE is feasible. GPU CC access is the bottleneck.

---

## 9. Proof of human, delegation and consent receipts

| Item | Source |
|---|---|
| Personhood credentials paper | [C] https://arxiv.org/html/2408.07892v3 |
| Authenticated delegation: OAuth/OIDC extended with agent ID and delegation tokens (ICML'25 position paper) | [C] https://arxiv.org/html/2501.09674v1 |
| IETF draft "Verified Human Root Attestation" for delegation chains | [C] https://www.ietf.org/archive/id/draft-zagarella-verified-human-root-01.html |
| World AgentKit (Mar 2026): delegates World ID to agents through x402 | [C] https://world.org/blog/announcements/now-available-agentkit-proof-of-human-for-the-agentic-web |
| ERC-8004: Identity, Reputation and Validation registries, with TEE oracles as one trust model. Sybil attacks are acknowledged. | [C] https://eips.ethereum.org/EIPS/eip-8004 |
| Consent receipts (Kantara, ISO/IEC TS 27560) | [I] not fetched |

**Why still unsolved:**
- Consent is not tied to the *specific action and arguments* that are executed.
- The receipt does not prove the agent followed the consented scope.

**What the combination adds:**
- A user-signed scope, plus an enclave that enforces it, plus a per-action receipt.
- Receipts are anchored to the ERC-8004 Validation Registry. [I]

**1-week demo:** Yes.

---

## 10. Sealed-bid and private matching with TEE agents

- BuilderNet and Flashtestations run TEE sealed-bid orderflow sharing with on-chain attestation registration. [C] https://collective.flashbots.net/t/beyond-flashtestations/5342
- Current BuilderNet docs say its nodes are not in TEEs during a security transition. [C] https://buildernet.org/docs
- TCME frames the millionaire's problem as something an LLM can solve. [C] (TCME paper above)

**Why still unsolved:**
- After TEE.fail, the value-at-risk ceiling is low. NDAI formalizes this as a "security capacity Φ." [C]
- Agent errors.
- Collusion between the operator and a bidder.

**What the combination adds:**
- Cap value at risk per Proof-of-Cloud level.
- Commit-reveal on-chain as a fallback if the TEE fails. [I]

**1-week demo:** Yes, for example a job-matching or procurement agent that reveals only the match.

---

## TOP 8 hackathon-scale openings (ranked)

All of these are proposals [I]. Prior art is cited where I confirmed it.

1. **Rug-pull-proof attested MCP plus registry.**
   - Each MCP server runs in a TEE.
   - The quote binds the code hash, the full tool-schema hash (per OWASP) and a session-bound TLS exporter (Level 2 binding).
   - A registry (ERC-8004 style or Rekor) maps server name to approved hashes and supports revocation.
   - A client proxy fails closed.
   - Demo: replay Invariant's tool-poisoning and rug-pull attacks, and show both blocked.
   - Gap filled: OWASP says pinning cannot catch server code changes. Effort: low to medium.
2. **Verifiable IFC agent with "flow receipts."**
   - A FIDES or CaMeL-style planner and policy engine runs inside an enclave.
   - The policy hash is registered.
   - Every consequential tool call emits a signed receipt recording input labels, the sink and the decision.
   - Recipients verify receipts.
   - Demo: the GitHub-MCP lethal-trifecta scenario gets blocked, with an auditable receipt.
   - Gap filled: no third-party verifiability today.
3. **Attestation chain linter ("attested, but which code?").**
   - Takes an endpoint, fetches the quote, then checks each link and grades it A-F:
     - Is the quote fresh and nonce-bound?
     - Is the binding to TLS correct?
     - Do the measurements match a reproducible build?
     - Is there a Rekor or transparency-log entry?
     - Is the model hash present (Modelwrap-style)?
     - Is the GPU attestation bound to this CVM?
     - Is the hardware ID on a Proof-of-Cloud list?
   - Encodes the LPC CVE classes and the TEE.fail "borrowed GPU attestation" check.
   - Very feasible, and useful to the whole ecosystem.
4. **Private negotiation room with firewalls plus attested deletion.**
   - Two to N user agents meet in one enclave.
   - Messages use the structured firewall protocol (arXiv 2502.01822).
   - Only a structured outcome leaves, and deletion on no-deal is attested.
   - The outcome commitment and escrow go on-chain.
   - Evaluate on a MAGPIE or ConVerse subset, comparing leakage with and without the room.
   - Differentiate from the existing NDAI hackathon repo with multi-party support plus a benchmark.
5. **Model-substitution watchdog.**
   - An open-weights model (8B or smaller) is served with a dm-verity weight root plus PAL*M-style REPORTDATA = H(prompt‖output‖seed).
   - A second independent verifier recomputes random samples with batch-invariant kernels.
   - Mismatches go on-chain, with stake slashed.
   - Combines the TEE route with the recomputation route, so it is not single-trust.
6. **Rate-limited private eval oracle.**
   - The auditor's secret test set is committed on-chain.
   - Model providers submit to the enclave, and results are attested (Attestable Audits).
   - A smart contract caps queries per model and reports results coarsely, addressing the one-bit-leak and adaptive-overfitting problem the atlas flags.
7. **Scoped consent receipts for agent actions.**
   - The user signs a natural-language scope compiled to a policy (a Conseca-style trusted-context generator).
   - The enclave enforces it per action and emits receipts tied to a delegation token, optionally with a personhood credential.
   - Receipts are anchored in the ERC-8004 Validation Registry.
   - Demo: a vendor rejects an out-of-scope purchase with no valid receipt.
8. **Private memory / RAG vault with per-answer provenance.**
   - The index and LLM live in an enclave, with per-document ACLs and AgentDAM-style data minimization.
   - Each answer carries a signed list of the document hashes used.
   - Revocation and deletion are attested.
   - Red-team with the MEXTRA and Secret extraction prompts and report the extraction rate before and after.

**What you can claim honestly in any pitch [I]:**
- TEEs do **not** stop physical attackers (TEE.fail).
- Frame the guarantees as "secure against a remote or software operator, with physical risk bounded by Proof-of-Cloud and value caps."
- Never say "trustless."

**Feasibility notes [I]:**
- GPU-CC hardware access within a week is the main risk. Options:
  - Simulated or Nitro or dstack CPU TEEs, plus small models.
  - Existing confidential-inference providers. I did not check their availability or cost.
- No experiments were run for this report.