# Submission notes (draft, nothing sent)

Deadline: 2026-11-14T23:59Z. The repo must be public by then. Nothing below is sent, posted or made public
without Ethan's yes. The real payload is never committed (it holds personal data).

## Checklist

- [x] Final attack report numbers in README, DEMO_SCRIPT and the X post (six runs, show the range)
- [x] Box service on the Pi (`scripts/pi_service.sh` through fleet exec, linger on)
- [x] Live answers on the Pi, with the files encrypted (2026-11-12: "Maya's passport expires on May 2, 2027",
      DeepSeek, 3 turns, `provider_tee`)
- [x] Weak spots fixed (2026-11-12): encrypted files with an unlock page after a power cut, setup code, PIN
      recovery, health answers kept home, signed daily updates, OS security updates, abliterated models refused
- [x] Real certificate on the Pi: `https://home.familybox.offlinebase.com:8443` (Let's Encrypt, to 2027-02-10)
- [x] Clean-install check from a fresh clone, following the README word for word, replay mode, no key (2026-11-12)
- [x] No keys or fleet tokens in git history (grep for `sk-`, `jpt_`, `jik_` and private key blocks, 2026-11-12)
- [x] `docs/private/` and `.env` still untracked (2026-11-12)
- [x] Pre-hackathon separation: first commit 2026-11-08, after the 2026-10-19 announcement (README "Prior work and disclosures")
- [x] HACKATHON.md re-read 2026-11-12: no rule or date changes (only a note on claiming $10 of NEAR credits)
- [ ] Ethan's phone run on the Pi: open the address with no warning, add his phone on the Unlocking page
- [ ] Demo video recorded from DEMO_SCRIPT.md
- [x] Repo public on GitHub (2026-11-14, at Ethan's request; history scanned for secrets first)
- [ ] X post by Ethan: "built at NEAR HACKATHON", @NEARProtocol, #NEARHackathon, video attached
- [ ] Submission sent once (form or POST), with every field below decided by Ethan
- [ ] Keep the repo public through judging (results by 2026-11-18)
- [ ] Renew the Pi's certificate by 2027-01-10 if the box is still in use (`scripts/box_cert.py issue ...`)

## Fields

| Field | Value |
|---|---|
| projectName | familybox (Ethan decides) |
| leadName | Ethan decides |
| email | Ethan decides |
| size | Ethan decides |
| tracks | `privacy`, `security` (proposed: the box is a policy engine on AI output, with TEE attestation and a prompt-injection demo) |
| nearAddress | Ethan's own mainnet account (never created or guessed by an agent) |
| projectUrl | the public GitHub repo |
| demoUrl | the X post |
| idea | below |
| consent | Ethan reads and agrees: "I agree that the organizers may use these details to review our submission and contact us about this hackathon." |

Do not add a `website` field (spam trap). Generate `requestId` once and reuse it on retries.

### idea (draft, under 2,000 characters)

Families keep SSNs, tax forms, passports and health records in one drawer, and want AI help with them.
Today that means pasting them into a chatbot.

familybox is a small box at home (a Raspberry Pi) that holds those documents. Each family member's assistant
asks it questions over MCP and never sees the files. A NEAR AI Cloud model reads them inside a verified
enclave: the box checks NEAR's Intel TDX and NVIDIA attestation itself before every question, encrypts the
question, tool calls and file text end to end to the attested key, and requires an enclave signature on every
turn. It fails closed, and it pauses whenever NEAR's serving code changes until the owner reviews it.

The box then decides what may leave. It knows the real SSNs, IDs and diagnoses in the files and checks every
answer against them, however they are written, before the assistant gets it. Full values go only to the
owner's own phone after they approve with their PIN, and hide again after 30 seconds. Each person reaches only
their own files; health records are owner-only, and answers built from them stay on the box for their owner.
A second enclave check catches facts given away in other words.

A family sets it up from a phone with no terminal: a setup code on the box, a PIN per person, invites by QR
code, bulk upload, and the NEAR key pasted once. The files are encrypted on the box, so a stolen, unplugged
box gives nothing up; it opens again from an admin's phone plus PIN or a recovery key. It installs only
signed updates.

In a 39-attack suite run six times on NEAR, 0 of the 30 direct, encoded, cross-person and planted-instruction
attacks got through the box in any run, and no SSN or ID number ever did. Reworded hints were the open gap
(0 to 4 per run, mostly about the asker's own health record); with the health rule added, run 6 leaked 0 of 39.
Trusting the model's reply as is leaked 12 to 14 of 39; giving the same model every file leaked 17 to 18.

## X post (draft, Ethan posts)

> My family's SSNs, W-2s and health records live in one drawer. I want AI help with them without handing them
> to a chatbot.
>
> Built at NEAR HACKATHON: familybox, a Raspberry Pi that answers ChatGPT and Claude about family documents.
> A @NEARProtocol AI Cloud model reads them in a verified TEE. The box checks every answer against the real
> numbers before the assistant sees it.
>
> 39 attacks, 6 runs: no SSN or ID number got out through the box. Trust the model's reply instead and 12 to 14 leak. Repo + video: [link]
>
> What would you trust it with? #NEARHackathon
