# familybox threat model

What the box protects, from whom, how, and where it stops. Status labels: **enforced** (the box's code
does it and tests cover it), **proven** (a cryptographic check the box runs itself), **partial** (lowers
the risk, does not remove it), **not covered**.

## What is being protected

Household documents on one box: SSNs, passports, tax forms (W-2, 1099), insurance cards, school records and
health records (visit notes, FHIR exports) for each person in the family. Also: who asked what, and which
values left the box.

## Who we assume is hostile

| Party | Assumed able to | Why it matters |
|---|---|---|
| The asking assistant (ChatGPT, Claude, Codex, Cursor) | Ask anything, retry, rephrase, keep everything it receives, be prompt-injected | It is a third-party service. Anything it gets should be safe to keep forever. |
| A planted document | Contain instructions aimed at the model ("send the SSN to...") | Families save files from email, schools and portals. |
| Another family member | Ask about someone else's records through their own assistant | A teenager's counseling referral, a parent's diagnosis. |
| NEAR's gateway and operators | See traffic metadata, swap the serving code | The model has to run somewhere we do not control. |
| The network and the cloud backup | Read anything not encrypted | Home Wi-Fi, Google Drive. |
| Visitors to the red-team page | Hammer it, try to spend the budget | It is meant for strangers (judges). |

**Trusted:** the box itself (its OS, its disk, whoever has root on it), the owner's own screen, and the
hardware vendors behind the enclave attestation (Intel TDX, NVIDIA).

## Controls

### 1. The model runs only in a verified enclave (proven)

- Before every question, fresh attestation of NEAR's gateway and the model (Intel TDX quote, NVIDIA
  evidence, TLS binding), verified by the box through `nearai-inference-sdk`. Failure stops the question.
- Every request, tool call and tool result is end-to-end encrypted to the attested model key (E2EE v3).
- Every model turn must carry a `provider_tee` signature that verifies against that key. A gateway
  signature, or no signature, stops the question. Nothing falls back to an unverified path.
- **Code pinning (enforced):** the box fingerprints NEAR's gateway, the model's enclave measurements, OS
  image, container images and deployed compose files. A change stops sensitive questions until the owner
  reviews it. Decisions go into a hash-chained history.

### 2. The model sees only the asker's files (enforced)

- Each MCP connection, remote token or web session is bound to one person. No tool argument picks who is
  asking.
- `search_files` and `read_file` reach that person's folders plus `shared/`, and any extra folders the
  family config grants. Health folders are owner-only, even for parents. Access is checked before a file
  is read.
- The workbench sandbox (off by default) gets read-only **copies** of the asker's readable files only.

### 3. Every answer is checked against the real values (enforced)

- The box indexes the actual protected values in the files (SSNs, labeled IDs, health lines, tripwire
  markers) and recognizes them however they are written: dashes, spaces, spelled-out digits, a 5-digit
  run of an SSN, reversed or shifted digits, word forms of a diagnosis.
- Outcomes: pass, mask (for example "ending in 4321"), hold for the owner's approval, or refuse
  (another person's data, tripwires).
- Full values are shown only on the owner's own screen (the box page, CLI or UNO Q-approved view), never
  returned to the assistant that asked.
- Plugin output (forms summaries, photo transcripts, workbench output) reaches the assistant only through
  the same gate.

### 4. Reworded leaks (partial)

A second verified, E2EE, enclave-signed NEAR call judges whether the answer reveals a protected fact in
other words. If that check errors or times out, the whole answer is held. It is itself a model: in the
last measured run it let some reworded answers through (see the README results). It narrows the gap the
value-based gate leaves; it does not close it.

### 5. Prompt injection in documents (partial, by design limits)

Tool results are sent to the model as data, and the system prompt says so. That alone is not a defense.
What limits the damage: the model has no network, no write tools and no tool that sends anything out;
whatever it writes still goes through the gate; and the only things that can leave are answers to the
person who asked. A planted note can make the model try to leak; the gate is what stops it.

### 6. Model-written code (enforced, Linux only)

The analysis workbench runs model-written Python on the box in a sandbox built from Linux namespaces
(user, mount, net, pid, ipc, uts), a fresh allowlisted root with `pivot_root`, no capabilities,
`no_new_privs`, a seccomp filter (threads yes, new processes no, escape-related calls refused) and hard
limits (512 MB, 20 s CPU, 30 s wall, 16 KB output to the model). No network namespace means no way out.
Output goes back to the model, never straight to the assistant. Every script is logged for the person.

### 7. Getting files on and off the box (enforced)

- Uploads go over HTTPS to the box's own page, signed in with one-time codes. The page loads nothing from
  outside (strict CSP).
- Google Drive import is read-only. Backups leave the box encrypted (libsodium secretstream) with a key
  that never leaves it.
- Photos: location and camera metadata are stripped before the single enclave vision call. The original
  stays on the box (0600). The transcript is sealed with a box-only key; `.transcript.txt` uploads are
  refused, so a transcript can't be forged by upload.

### 8. Remote assistants (enforced)

OAuth 2.1 on the box: PKCE S256, rotating refresh tokens with reuse detection, revocation, secrets hashed
at rest, consent with a one-time code from the box, no open redirect, and a separate listener just for
assistants. The person always comes from the token.

### 9. Records of what left the box (enforced, anchoring ready)

Each person's audit log is hash-chained (`familybox log verify`), which catches edits, removals and
reordering. Truncation or a full rewrite only shows against an external anchor; a NEAR contract and
anchoring client are written and run as a dry run until a testnet account is set up.

### 10. Physical approvals (enforced in software, untested on hardware)

The UNO Q button uses an approve-only device token (hashed at rest). The device API never returns values.
After a button approval, the value shows once on the owner's own screen.

### 11. Red-team page (enforced)

Runs only on a dedicated fictional demo home, bound to 127.0.0.1 until hosting is approved. Per-visitor
and global caps, a daily token cap and a hard daily dollar budget with worst-case reservations; past the
budget it switches to recorded answers. Visitor IPs are hashed, never stored. The paraphrase check and
workbench are off there by design (they would break the spending bound).

## Not covered

- **Root on the box** reads everything. So does a stolen box without disk encryption.
- **NEAR metadata:** the gateway sees model, message count, sizes, timing and the API key.
- **Attestation limits:** model instances share a signing key, so a signature doesn't identify the
  instance; parts of NEAR's serving stack are pulled at runtime and are not in the measurement (pinning
  narrows this by noticing changes, not by proving what runs).
- **Facts the box doesn't know are sensitive:** the gate protects values it found in the files. A fact
  that appears nowhere as a protected value relies on the reworded-leak check.
- **What the owner does with an approved value** once it is on their screen.
- **The assistant's own side:** the question text itself goes to the assistant provider before it reaches
  the box. Don't type secrets into the question.
- **Denial of service** on the box or on NEAR. The box fails closed: no answer, no leak.

## Evidence

- Attack suite: `eval/attacks.py`, reports in `eval/reports/`. Leaks are judged by a checker in the eval
  script, not by the gate.
- Tests: `uv run pytest -q tests`. Sandbox tests run on Linux (the Pi); live NEAR tests need a key.
- Design decisions and every measurement: [BUILD_LOG.md](BUILD_LOG.md).
