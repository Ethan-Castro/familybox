# Submission notes (draft, nothing sent)

Deadline: 2026-11-14T23:59Z. The repo must be public by then. Nothing below is sent, posted or made public
without Ethan's yes. The real payload is never committed (it holds personal data).

## Checklist

- [x] Final attack report numbers in README, DEMO_SCRIPT and the X post (three runs, show the range)
- [x] Pi run on the merged build: 691 passed, 2 skipped, sandbox tests included, workbench ready (2026-11-09)
- [ ] Live answers on the Pi (needs the NEAR key on the board; Ethan's OK)
- [x] Clean-install check from a fresh clone, following the README word for word, replay mode, no key (2026-11-09: 675 passed, 17 skipped)
- [x] No keys or fleet tokens in git history (grep for `sk-` and `jpt_`; a dedicated scanner is still worth running)
- [x] `docs/private/` and `.env` still untracked (checked before the first push)
- [ ] Pre-hackathon separation: all code is from 2026-11-07 onward (README "Prior work and disclosures")
- [ ] Repo public on GitHub (Ethan pushes and flips it)
- [ ] Demo video recorded from DEMO_SCRIPT.md
- [ ] X post by Ethan: "built at NEAR HACKATHON", @NEARProtocol, #NEARHackathon, video attached
- [ ] Submission sent once (form or POST), with every field below decided by Ethan
- [ ] Keep the repo public through judging (results by 2026-11-18)

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

### idea (draft, about 1,300 characters)

Families keep SSNs, tax forms, passports and health records in one drawer, and want AI help with them.
Today that means pasting them into ChatGPT or Claude, which then keeps everything.

familybox is a small box at home (a Raspberry Pi) that holds those documents. Each family member's assistant
asks it questions over MCP and never sees the files. A NEAR AI Cloud model reads them inside a verified
enclave: the box checks NEAR's Intel TDX and NVIDIA attestation itself before every question, encrypts the
question, tool calls and file text end to end to the attested key, and requires an enclave signature on every
turn. It fails closed.

The box then decides what may leave. It knows the real SSNs, IDs and diagnoses in the files and checks every
answer against them, however they are written, before the assistant gets it. Full values go only to the
owner's own phone after they approve. Each person reaches only their own files; health records are
owner-only. A second enclave check catches facts given away in other words, and the box pins NEAR's serving
code and pauses if it changes.

In a 39-attack suite run three times on NEAR, 0 of the 30 direct, encoded, cross-person and planted-instruction attacks got through the box in every run, and no SSN or ID number ever did; with the model's reply trusted as is, 13 to 14 of 39 leaked. Reworded hints remain the open gap (0 to 4 per run, mostly about the asker's own records; one cross-person hint came from a bug since fixed). Includes a live trust timeline, photo transcription,
form filling, a sandboxed analysis workbench and a red-team page.

## X post (draft, Ethan posts)

> My family's SSNs, W-2s and health records live in one drawer. I want AI help with them without handing them
> to a chatbot.
>
> Built at NEAR HACKATHON: familybox, a Raspberry Pi that answers ChatGPT and Claude about family documents.
> A @NEARProtocol AI Cloud model reads them in a verified TEE. The box checks every answer against the real
> numbers before the assistant sees it.
>
> 39 attacks, 3 runs: no SSN or ID number got out through the box. Trust the model's reply instead and 13 leak. Repo + video: [link]
>
> What would you trust it with? #NEARHackathon
