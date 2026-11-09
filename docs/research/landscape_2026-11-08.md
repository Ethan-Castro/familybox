# Hackathon landscape and positioning (from Ethan's deep-research runs, 2026-11-08)

The sources are four external deep-research reports Ethan ran. Some of their claims are checked against what this project has verified directly; corrections are noted.

## Other NEAR Hackathon 2026 projects (report 1)

- **Directory size:** the official directory showed 88 projects in a snapshot. Only about 18 could be checked one by one.
- **Closest technical analogue: NEARpedia** (github.com/UnityNodes/near-pedia; Open Innovation + Agent Economy, not Privacy).
  - A hosted NEAR knowledge RAG with 27 MCP tools for ChatGPT, Claude and Cursor.
  - Uses `@nearai/inference-sdk` with TDX attestation, an encrypted prompt and response-signature checks, and refuses to show unverified answers.
  - Live site, demo video, contract anchoring a database hash.
  - Very polished. Its corpus is public, and it has no local custody, no per-person access and no output gate.
- **Strong presentation in Privacy: Penstock.** An x402 paywall for HTTP/MCP tools via NEAR Intents, with confidential intents and real mainnet payment proof. No private inference.
- **Crowded in Security:** agent spending firewalls and policy engines (Veto, Allowance, Agent Spend Guard, SpactVault, Leash, presign-guard, XAUConnect). The pattern matches ours in spirit ("deterministic guard outside the model"), but they protect money and keys.
- **Likely crowded in Privacy:** the organizers' own starter is "upload a document to a NEAR TEE model, verify attestation, show a Verified panel".
- **Found 0 projects with any of:**
  - local device custody plus a remote NEAR TEE;
  - per-person household authorization;
  - output checked against the actual stored protected values.

## Existing products (report 2, corrected)

- **TEE inference for private data is established:** Apple PCC, Google Private AI Compute, NEAR AI Cloud, Tinfoil, Privatemode, Phala. Not novel on its own.
- **Local PII redaction is established:** Perplexity Hybrid, Latet, PrivAiTe, Protecto, Presidio proxies. All pattern or ML based.
- **Checking answers against the actual stored values: not found** in any product.
  - The closest is **PlanTwin** (arXiv 2603.18377). It is research, not a product: a local gate validates a cloud planner's steps against local objects. It has no TEE.
- **Per-person household access for confidential AI: not found.** Enterprise RBAC exists (Protecto), and family vault apps don't run AI over documents.
- **Correction, Privateer:** report 2 says Privateer gates outputs. Privateer's docs say its PII gate scans prompts to unverified models and is skipped on attested models; in `--private` mode "the reply is the channel".
- **Correction, PAAC:** report 2 misdescribes it. PAAC (arXiv 2605.08646) is a device-cloud planner/executor with typed placeholders.

## Judges (report 3, partly inferred)

- **Confirmed quotes:**
  - Illia: confidential hardware with attestation anyone can check; agents must be "ours".
  - Avichal Garg: user-owned, trust-minimized systems; AI makes this more urgent.
  - Mert Mumtaz: skeptical of "AI-washing".
  - Haseeb Qureshi: agent-intermediated crypto.
- **Inferred only:** Eddy Lazzarin, Kain Warwick and Stepan Gershuni (no quotes found).
- **Report's suggestion to add NEAR payments or on-chain hashes:** this is a judgment call. Only do it where it does real work (see the decisions in the main thread).

## Technical report (report 4): mostly unreliable

- **Wrong on several points:**
  - claims tool_calls must be encrypted manually (the SDK already does this, and the bug persists);
  - gives an SDK API snippet that doesn't exist (`deployment_policy` is a callback);
  - prices per 1K tokens (it's per 1M);
  - cites an SDK version older than ours (0.2.1 vs 0.3.0).
- **Usable:** no public fix exists for the E2EE tool-history bug, and the SDK does not pin deployments by default.

## Positioning adopted

"TEE attestation proves where the model ran. The household box decides what that model is ever allowed to reveal, and to whom."
