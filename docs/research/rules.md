# NEAR HACKATHON 2026: research report (fetched 2026-11-07)

Primary sources, all fetched with unauthenticated GETs:
- [S1] https://nearhackathon.com/ (homepage, rendered text)
- [S2] https://nearhackathon.com/HACKATHON.md (22 KB, text/markdown)
- [S3] https://github.com/nearai/near-hackathon-prompt-examples. Every file was read: README.md, 00-setup.md, SUBMITTING.md, tracks/01..13. Last commit was 2026-10-30.
- [S4] https://nearhackathon.com/request-changes
- [S5] https://nearhackathon.com/api/projects (public project directory JSON) and GET /api/applications, which returns `{"count":258}`
- [S6] https://cloud-api.near.ai/v1/models (public model list)
- Secondary: loops.house/near-hackathon, a TokenPost piece from Oct 24, and nitter mirrors of the @NEARProtocol and @ilblackdragon posts.

The site has no llms.txt, RULES.md, JUDGING.md, FAQ.md, robots.txt or sitemap. All of them return 404 (CONFIRMED). The only rules document is HACKATHON.md, plus the FAQ on the homepage.

---

## 1. HACKATHON.md is written for AI agents (CONFIRMED, S2)
- First line: "Instructions for the AI coding agent helping a team take part in NEAR HACKATHON... read it again before submitting, because dates and rules may change."
- The homepage [S1] says: "Hand HACKATHON.md to your coding agent... can file your submission."
- The agent must never do these without explicit human confirmation:
  - send the submission (print the full JSON first and wait for a yes)
  - post on X
  - make the repo public, push or force-push
  - sign transactions, spend tokens or deploy to mainnet
  - commit secrets
- Under "What the human decides", the agent may not guess or fill in placeholders for any field. It must never create or invent a NEAR account for the team.
- The agent must read the consent notice to the human word for word: "I agree that the organizers may use these details to review our submission and contact us about this hackathon."
- 00-setup.md [S3] tells the agent to:
  - read HACKATHON.md
  - run `npx skills add near/agent-skills` (skills: near-ai-cloud, near-api-js, near-dapp, near-intents, near-kit, near-smart-contracts)
  - use https://docs.near.org/llms.txt and https://docs.near-intents.org/llms.txt, and never guess contract addresses or endpoints
  - build on testnet first, with keys in .env
  - write a README for an AI judge from day one
  - confirm it has read HACKATHON.md by listing the 13 track ids

## 2. Dates, all UTC (CONFIRMED, S2 Facts table)
| Event | Time |
|---|---|
| Announcement (start of the eligible code window) | 2026-10-19 (Q-001) |
| Hackathon starts / submissions open | 2026-11-01T00:00:00Z |
| Development ends = submission deadline = repo must be public | **2026-11-14T23:59:00Z** |
| Judging starts | 2026-11-16T00:00:00Z |
| Results announced by | 2026-11-18T23:59:00Z |
| Keep a hosted demo up until | 2026-11-18, ideally 2026-11-25 (Q-012) |
| Payout | one payment in NEAR, no vesting, within 30 days of results (Q-016) |

Outside the submission window the API returns 403. Do not retry.

## 3. Prizes (CONFIRMED, S1 and S2)
- $250,000 pool, fixed in USD and paid in NEAR to the mainnet account given in the submission.
- Grand prize: $55K x 1.
- Each of the 13 tracks pays 1st $10K, 2nd $3K and 3rd $2K, which adds up to $130K, $39K and $26K.
- **No separate sponsor bounties are published** (CONFIRMED absence in S1, S2 and S3). Partners appear only as an ecosystem table and partner notes (Rhea, Agent Market, NEAR Business).
- It is not stated whether the grand-prize winner can also win a track (ambiguity).

## 4. Eligibility and team rules (CONFIRMED unless marked)
- Open to "Developers, designers and people with ideas." No sign-up; the submission is the registration. No wallet connection is needed to submit [S1 FAQ].
- Allowed team sizes: `1`, `2 - 4`, `4 - 6`, `6 - 8`, `8+`. The ranges overlap, which is an organizer quirk.
- **One submission per project.** A project can list several tracks and still counts as one submission.
- Each repository can be submitted only once; a repeat gets 409.
- Each email can file at most 2 submissions.
- One person can be in at most 2 projects, and only if they are independent and **each README names the other project** (Q-015). The same project cannot be entered twice.
- A mainnet NEAR account is required for the payout: a named account like `x.near` or a 64-character implicit account, matching the regex in S2. The team creates it itself.
- Testnet-only projects are eligible in every track. Use mainnet only where the integration exists only on mainnet (Q-010). NEAR Intents has no testnet: use mainnet with tiny amounts and `dry: true` quotes (Q-007).
- Mainnet costs are not reimbursed by default (Q-008).

## 5. Pre-existing code and how to disclose it (CONFIRMED, S2 Q-001 to Q-005)
- Q-001: code from the 2026-10-19 announcement onward counts. "Earlier commits are baseline."
- Q-002: an existing product on another chain is allowed. "Only the NEAR integration built in the window is judged. Disclose in README."
- Q-003: a new repo is not required. Use a "Dedicated branch, or tags pre-hackathon and hackathon-submission, plus a README section linking the diff."
- Q-004: an old project as-is is not eligible. A new feature built in the window is eligible if it is separated per Q-003. There is no minimum code size.
- Q-005: libraries, templates, boilerplate, your own older libraries and AI-generated code are all allowed. "List in README." Your own older libraries count as baseline.
- Q-013: the team keeps all rights. Organizers get non-exclusive promotional rights to the name, screenshots, video and repo link.
- Q-014: any license is fine (MIT is fine). Add a LICENSE file, and keep the repo public through judging.

## 6. Required submission artifacts (CONFIRMED)
1. **Public repository**, public by the deadline. Its README should be written "for a machine reader as well as a human one": what the product is, the problem it solves, and "do X - see Y" steps. "No marketing." [S2 Procedure 1]
2. **Public X demo post**, written and posted by the human. It must say the project was "built at NEAR HACKATHON", tag **@NEARProtocol** and **#NEARHackathon** (tagging @NearLegion and @NearBuilders is optional), and attach the demo video or screenshots.
   - Tips from S2: lead with the user problem, show one complete moment from user action to visible result, explain NEAR's role concretely (not "powered by NEAR"), and give a next step (links plus a real question).
3. **Submission**, sent once. Either POST https://nearhackathon.com/api/applications or use the form at https://nearhackathon.com/#apply. The body is limited to 12,000 bytes and must contain exactly these fields:
   - `requestId`: a UUID generated once and reused on retries
   - `projectName`: 2-80 characters
   - `leadName`: 2-80 characters
   - `email`: max 160 characters
   - `size`
   - `tracks`: an array of ids
   - `nearAddress`
   - `projectUrl`: the repo, max 300 characters, unique
   - `demoUrl`: the X post, max 300 characters
   - `idea`: 20-2000 characters covering the problem, the product and how NEAR fits in
   - `consent`: true
   - **`website` is a spam trap.** Any non-empty value gets the submission rejected. Do not add extra fields.
   - Status codes: 201 saved, 400 fix the listed fields and resend with the same requestId, 403 do not retry, 409 duplicate or email limit reached, 413 body too large, 503 retry with the same requestId.
   - Do not commit the payload, because it contains personal data.
4. **Changes after submitting** go through https://nearhackathon.com/request-changes [S4], never through a second submission.
   - Enter the original email, wallet and repo, then tick the fields to change: project name, team lead, email, team size, tracks, wallet, repo, demo link, idea, and "anything we should know?".
   - A Discord or Telegram handle is required. Organizers review each request by hand.
   - The form posts to `/api/corrections` (CONFIRMED in the site JS).
5. The SUBMITTING.md checklist [S3] adds two items:
   - no secrets anywhere in the repo history
   - every track the project fits is selected

## 7. How judging works
- **CONFIRMED (Q-017, S2):** "Claude Code and Codex role? Screening, not deciding: reproducibility check, feature verification, structured report, preliminary score. Humans decide; low AI score alone cannot reject."
- **CONFIRMED (S1 FAQ):** "Claude Code & Codex screen every project first: they check that it runs and does what the README says. The human judges above make the decisions."
- **CONFIRMED (Q-012):** a local-only demo is fine if there is a public repo, a reproducible README and an X post with a video. "Screenshots are not enough when judges cannot open the demo." A hosted demo is "a plus".
- **Criteria and weights: none published (CONFIRMED absence).** The only guidance is the FAQ [S1]: "Previous NEAR hackathons evaluated technical implementation, design, impact, originality and sustainability — a good guide to prepare by."
- Track-specific judging notes (CONFIRMED, S1, S2 and the track files):
  - thesis: "Judged on the evidence, not the conviction"
  - games: "Judged on the game loop, not the token — bonus if players never notice the chain"
  - memecoins: "Judged on the mechanic, not the chart"
  - social: "Don't rebuild the multisig"
- Human judges (CONFIRMED, S1): Illia Polosukhin (NEAR), Eddy Lazzarin (a16z crypto), Mert Mumtaz (Helius), Avichal Garg (Electric Capital), Kain Warwick (Synthetix & Infinex), Haseeb Qureshi (Dragonfly), Stepan Gershuni (cyber•Fund). The 8th judge slot is "Claude Code & Codex".
- **What likely makes a project fail (INFERRED from Q-017, Q-012 and Q-003):**
  - the repo is private or unreachable
  - the README steps cannot be reproduced, or features claimed in the README are not in the code
  - a local-only demo with screenshots and no video
  - no separation of baseline and in-window work (Q-003), or undisclosed pre-existing code (Q-002)
  - the NEAR integration is trivial or vague, given "Explain NEAR's role concretely"
  - secrets committed to the repo
  - the demo requires paid keys or real funds. Every track prompt asks for a dry-run, demo or simulation mode and fictional sample data so judges can run it for free. That is a strong pattern.
- **Hard disqualifiers (CONFIRMED):** a duplicate repo is rejected; the same project cannot be entered twice; an old project submitted as-is is ineligible (Q-004); a non-empty `website` field is rejected.

## 8. Required NEAR tech and NEAR AI Cloud
- **CONFIRMED (Q-011):** "Mandatory integrations? None. Hints are hints. Own contract on NEAR that fits the track is enough." The protocols listed in the Build and Hints columns are "hints and wishes, not requirements". Name the ones you use in the README.
- Privacy track hints: PRIVATE AI, TEE, NEAR AI CLOUD.
- NEAR AI credits (CONFIRMED, Q-000): buy with crypto or card at https://cloud.near.ai, or "claim $10 by joining NEAR Builders (https://nearbuilders.org/join)". The API key is generated in the dashboard.
- **CONFIRMED (S6):** https://cloud-api.near.ai/v1/models is public and lists 64 models. **Not all of them are TEE-hosted:**
  - The `anthropic/*`, `openai/gpt-*`, `google/*` and `x-ai/*` entries have no TEE wording in their descriptions.
  - TEE wording appears on:
    - `deepseek/deepseek-v3.2` ("Attested model served via Chutes TEE (verified end-to-end by NEAR AI)", owned_by "attested 3p")
    - `openai/privacy-filter` ("NEAR AI runs this model in a TEE"; PII span detection)
  - Other models with owned_by "attested 3p": kimi-k2.6, kimi-k3, qwen3.5-397b, glm-5.3.
  - Models with owned_by "nearai" (for example Qwen/Qwen3.8-27B, Qwen3-VL-30B-A3B, whisper-large-v3, Qwen3-Embedding) have US datacenters listed.
  - **INFERRED:** "nearai" and "attested 3p" models are the TEE and attestable ones. Any privacy project should pick from those and verify attestation, not call a proxied Claude or GPT model and claim privacy.

## 9. Tracks: official descriptions and starter-prompt ideas (CONFIRMED, S2 and S3)
These starter ideas are what most people will build, so treat them as "generic" to avoid or at least go beyond.

| id | Track: Build text (S2) | Hints | Starter prompt idea (S3) and key requirements |
|---|---|---|---|
| defi | Unstoppable DeFi: "Build exchanges, perps, lending, vaults and trading agents that settle across chains through NEAR Intents. Deep liquidity, no custodian, nobody to switch it off." | Trading, Intents, Chain Signatures | **Cross-chain DCA vault**: 1Click quotes, slippage limit, handling of REFUNDED/FAILED statuses, dry-run mode. Stretch: a contract-owned vault controlling a BTC address via Chain Signatures. |
| thesis | Investment Thesis: "...back it with data: onchain analytics, live dashboards and models anyone can re-run. Judged on the evidence, not the conviction." | Onchain data, dashboards, research | Hypothesis "**Intents volume is a better leading indicator than price**": BigQuery `bigquery-public-data.crypto_near_mainnet_us` (filter on block_date), Intents Explorer API (needs a JWT), one-command chart rebuild, THESIS.md with evidence for and against. |
| privacy | Privacy & Private AI: "Explore confidential computation, private finance and AI that protects sensitive data. Build intelligence without exposure." | Private AI, TEE, NEAR AI Cloud | **Private expense auditor** (see below). |
| business | Autonomous Business: "...treasury, sales, procurement, cross-chain payments via NEAR Intents and revenue sharing. Humans only set the constraints." | AI agents, Intents, Chain Signatures | **One-agent research shop**: sells reports, paid via Intents, buys its own NEAR AI inference, revenue split. config.yaml holds the spend cap, minimum price, split and kill switch. OutLayer custody or a function-call key, a public ledger, and a testnet loop under 2 minutes. |
| swarms | AI Swarms: "...coordination markets, bidding, collective purchasing, intent-based settlement and emergent economies between agents." | Multi-agent, Intents, sub-accounts | **Group-buying swarm for GPU hours**: sealed-bid rounds, one sub-account per agent, RULES.md first, a no-LLM simulation with 20 buyers and 5 sellers, a live page. |
| security | AI Security & Defense: "...spending limits, policy engines, sandboxed wallets, reputation and scam detection. Give AI money without giving it the keys to everything." | Agent security, function-call keys, TEE attestation | **Counterparty check (allow/warn/block)**: account age, contract code changes, prior interactions, a shared blocklist. Signing wrapper, a scoped function-call key, a prompt-injection attack demo. |
| agents | Agent Economy: "...agents that earn, spend, negotiate, hire other agents and pay for APIs, compute or data — with crypto directly or through NEAR Intents." | Agent commerce, Intents, Chain Signatures | **General contractor agent**: splits a task, hires on the Agent Market, counters once in negotiation, USDC/NEAR payments, receipts. Agent API demo keys rotate; the PingPay x402 facilitator is mentioned. |
| realworld | Real-World Money: "...payroll, invoicing, remittances, merchant payments and stablecoin rails for real businesses. Something a normal company could use tomorrow." | Stablecoins, Intents, meta transactions | **Freelancer crypto invoicing**: pay from any chain via 1Click, USDC on NEAR, a gasless meta-transaction relayer, status links, accountant-ready CSV. |
| games | Games With Real Economies: "NPCs with wallets, player-owned markets and economies that evolve without a dev patch. Judged on the game loop, not the token — bonus if players never notice the chain." | Agent NPCs, social login, Intents, NEP-245 | **Market-town game**: NPC merchant agents with dynamic prices, NEP-245 items, social login, a fast-forward week. |
| nfts | NFTs That Do Something: "NFTs as accounts — assets that own money, earn royalties, hold inventory, carry credentials, memberships or access rights." | Dynamic NFTs, NEP-171, sub-accounts | **Membership NFT with its own wallet sub-account**: a threat model for transfer, gated page, history, transfer tests. Note: Top Level Accounts names are NEP-171 NFTs, with no SDK yet. |
| memecoins | Memecoins With Mechanics: "...supply that reacts to the community, treasuries with rules, onchain rituals and challenges. Judged on the mechanic, not the chart." | NEP-141, token mechanics | **Streak coin**: daily check-ins mint or burn, immutable parameters, no admin key, sybil limits, a 60-day simulation. |
| social | Social Money: "...shared budgets, programmable rewards, collective ownership and reputation-based access on top of Sputnik DAO and Trezu. Don't rebuild the multisig." | Sputnik DAO, Trezu, named accounts | **Bounty board with earned trust**: tiered auto-approval. near.social writes always show as failed (CodeDoesNotExist), which is expected. |
| open | Open Innovation: "Have an idea that refuses to fit a category? Explore new ways for money, intelligence and ownership to work together." | Experimental, chain abstraction | **Inheritance / dead-man account**: Chain Signatures over BTC and ETH, guardians, a cancellable waiting period. It can be combined with any other track. |

### tracks/03-privacy.md in detail (CONFIRMED, S3)
- Start-here links:
  - https://docs.near.ai/cloud/quickstart
  - https://docs.near.ai/cloud/verification (returns 200)
  - https://github.com/near-examples/nearai-cloud-verification-example
  - https://docs.agentsonintents.com/integration/agent-api/overview
- Starter idea: **"a private expense auditor."** The user uploads receipts or a bank statement, a NEAR AI Cloud model categorizes the spending and flags anything unusual, and the app proves the analysis ran in a TEE.
- Requirements:
  1. Use the OpenAI-compatible API at `https://cloud-api.near.ai/v1` with the key in .env, and "Choose a TEE-hosted model from the models endpoint".
  2. "Fetch the attestation report with a fresh random nonce and verify it the way the verification docs describe. Show a 'Verified' panel listing what was checked."
  3. "Keep nothing server-side after a response returns. Say so in the README and make it obvious in the code."
  4. "Ship fictional sample documents so judges can run it without real data."
  5. Use the near-ai-cloud agent skill. Start with a minimal script that sends one completion and verifies attestation, then build the UI.
- INFERRED: the bar for privacy is real attestation verification with a nonce, statelessness that can be shown, and runnable fictional data. A generic "private chatbot" or "private expense, receipt or document analyzer" will be common.

## 10. Competitive landscape (CONFIRMED, S5, as of 2026-11-07)
- 258 submissions so far.
- Track tags: security 137, agents 126, realworld 52, business 44, open 42, **privacy 42**, defi 38, thesis 23, nfts 19, swarms 19, games 14, social 14, memecoins 8.
- Privacy-tagged project names: Veridom Pay, Throughput Treasury, ÁUREA CONTRACT FOR PRIVACY, Morrowseal, Jurat, AgentGuard, DeadDrop, TEE Receipts, PrivatePay Agent, Guardrail, ZEDEC PQOS aka. TIAMAT, Measure, Quittance, Judge on NEAR, PrivateDAO, Redline, VRX, Sealed Exploit, The Build City Hackathon, VAULTRY, RedactGate, Aureus, Charter, Penstock, NOVA Copy-Trading, GhosterDex, Skarbnik, PredicTEE, PipTradeDex Private Intent, GetLeash, Milestone Vault, Unpair, Sealed Dossier, Boyun, VeilProof, BEXLEY, Supply, GhostShift, Kinwarden, Sealed Ledger, Realsies, TAINT.
- The directory API shows only id, name, tracks and demo_url (no repo link or description). Full list saved at /private/tmp/claude-501/-Users-ethancastro/bbb35d95-f9c7-4de1-a77a-3ce1b586f2a9/scratchpad/near/allprojects.json
- INFERRED: Security and Agents are crowded. Memecoins, games, social, swarms and nfts are thin, which means less competition for the $10K/$3K/$2K places. Several names (TEE Receipts, Sealed Dossier, RedactGate, VeilProof, Sealed Ledger) suggest TEE-receipt and redaction ideas are already taken in privacy.

## 11. Contradictions and ambiguities
1. **"One submission per team" vs "per project".** SUBMITTING.md [S3] and loops.house say "one submission per team". HACKATHON.md says "one submission per project", allows up to 2 independent, cross-disclosed projects per person, and allows 2 submissions per email. HACKATHON.md is authoritative and is the live rules file.
2. **Code start date.** The hackathon "starts" 2026-11-01, but Q-001 counts code from the 2026-10-19 announcement, and the homepage says "Code written since the announcement counts". Submissions are still accepted only from Nov 1 to Nov 14.
3. **Screenshots vs video.** The demo post may have "video or screenshots" (S1, S2 step 3), but Q-012 says screenshots are not enough when judges cannot open the demo. Practical rule: always attach a video.
4. **Resubmission wording.** The FAQ answers "Can I resubmit?" with "Yes, no worries", but the answer actually means request changes. HACKATHON.md says "Never submit the project a second time."
5. **Testnet vs mainnet.** Testnet-only projects are eligible, but the payout account must be mainnet. Intents has no testnet at all.
6. **Credits.** Q-000 says buy credits, or claim $10 via nearbuilders.org/join. Loops.house says backend access "only works for registered builders" (secondary source, unverified).
7. **Judging criteria are unpublished.** There are only "previous hackathons" criteria with no weights. How the AI "preliminary score" is computed is not disclosed, and humans decide.
8. **Edits after the deadline.** Nothing says whether pushing after 2026-11-14T23:59Z is forbidden. Q-003 suggests a `hackathon-submission` tag. INFERRED: freeze and tag at the deadline, because judges review the repo from Nov 16.
9. **Grand prize stacking** (grand prize plus a track prize) is unspecified.
10. **Team-size buckets overlap** (`2 - 4`, `4 - 6`); pick the exact string as written.
11. HACKATHON.md warns that rules may change; re-fetch it before submitting.

## 12. Action-relevant takeaways (INFERRED)
- The README is effectively part of the judging interface. Include:
  - a numbered "do X, see Y" section
  - a disclosure section for baseline vs in-window work, with a branch or tag diff link
  - lists of libraries and AI-generated code
  - which NEAR features are used and why
  - a no-funds dry-run or demo mode with fictional data
  - LICENSE, .env.example, and no secrets in history
- If the project shares a person with another submission, both READMEs must name each other.
- For privacy: use a TEE or attested model from /v1/models, verify attestation with a nonce, show a Verified panel, run stateless with proof in code, and add a concrete NEAR on-chain element (for example an attestation hash or receipt written to a NEAR contract) so "how NEAR fits in" is not vague.