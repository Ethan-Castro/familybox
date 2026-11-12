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
| Whoever serves the update files (GitHub, the network, a mirror) | Serve old, altered or made-up releases | The box installs new code on its own every day. |

**Trusted:** the box itself (its OS, its disk, whoever has root on it), the owner's own screen, the
hardware vendors behind the enclave attestation (Intel TDX, NVIDIA), and the release signing key on the
developer's laptop.

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

### 4. Reworded leaks (partial; health answers enforced)

**Health records (enforced, since 2026-11-12):** a fixed rule in `box.py` (`health_hold`), not a model.
Any answer to an outside assistant that opened a health file is held whole for the record's owner, and
the assistant gets only a note to read it on the box. Health folders are owner-only, so the owner is
always the asker. Asked on the box's own page, the owner reads it there. This closes the reworded-hint
gap for health records, which was most of it (10 of the 11 hints in five runs were about the asker's own
record). It costs usability: an assistant can no longer answer "what are my allergies" in its own chat.

**Everything else (partial):** a second verified, E2EE, enclave-signed NEAR call judges whether the answer
reveals a protected fact in other words. If that check errors or times out, the whole answer is held. It
is itself a model, so it narrows the gap the value-based gate leaves for IDs and other facts; it does not
close it.

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

### 11. Setup, PINs and reset on the box page (enforced)

- **Setup code:** a box can carry a setup code (printed on its sticker, stored only as a scrypt hash in
  `<home>.vault/setup_code.json`, made with `familybox vault setup-code`). With one, setup needs the code,
  so someone else on the home Wi-Fi can't claim a new box in its first 15 minutes. Without one (a laptop
  demo), the old rule applies: setup works only while the box has no family and for 15 minutes after it
  starts.
- **PINs:** 6 to 12 digits, not all the same, stored as scrypt hashes with a per-person salt, never logged.
  5 wrong tries in 10 minutes locks that person's PIN sign-in only, so a child cannot lock a parent out.
- **Forgotten PIN:** the person who runs the box resets their own PIN at `/recover` with the recovery key
  from setup. Ten wrong recovery keys in 15 minutes and it waits. Other family members still ask the person
  who runs the box.
- **Invites:** one-time codes that last 30 minutes and only set a first PIN; they cannot change an existing one.
- **Showing a held value:** the owner types their PIN again, and the value page goes back to the list after 30
  seconds. It covers approvals on the box page, not the UNO Q button or forms.
- **AI key:** pasted once on an admin-only page, stored 0600 on the box, never shown again.
- **Reset:** admin only, PIN plus the family name typed out. It wipes files, logs and the family list and
  destroys the encryption keys, so the old encrypted folder can never be opened again. The reset itself
  leaves no log entry.
- None of these pages are on the internet-facing listener.

### 11b. Files encrypted at rest (enforced on Linux with gocryptfs)

`src/familybox/vault.py`, `src/familybox/locked.py`. The home folder (family.toml, files, logs, PINs,
approvals, the search index) lives in a gocryptfs folder and is mounted only while the box is unlocked.

- **Keys:** a random 32-byte box key opens the folder. It is stored only wrapped (AES-GCM): once by the
  recovery key (24 characters, about 120 bits, scrypt), shown once at setup and never stored; and once per
  admin phone by a random secret kept in that phone's httpOnly, SameSite=Strict cookie, combined with the
  admin's PIN (scrypt). A stolen box has neither the phone secret nor the recovery key. A stolen phone has
  no box and no PIN.
- **After a power cut** the box serves only the unlock page; every other page and `/mcp` say it is locked.
  Ten wrong tries in 15 minutes and it waits. A restart of the box's own service (an update) keeps the
  folder open, because the mount runs in its own systemd unit.
- **Changing a PIN** re-wraps the phone it was changed on; that person's other phones stop unlocking until
  set up again (the recovery key always works).
- **Kept in the clear** in `<home>.vault/`: the wrapped keys, salts, recent failed tries, the setup-code
  hash and the TLS certificate (needed to serve the unlock page).
- **Limits:** root on a running, unlocked box reads everything. Files written to the card before
  encryption was turned on may survive on the flash; a real box starts encrypted on a new card. The Mac
  demo can't encrypt (no gocryptfs) and says so on the Status page.

### 11c. A trusted certificate (enforced when issued)

`scripts/box_cert.py`. The box gets a real name under offlinebase.com pointing to its home-network
address and a Let's Encrypt certificate issued through a DNS check, so phones open it with no warning
(and no habit of clicking past one). The private key is made on the box and never leaves it. Limits: the
name reveals the box's private address in public DNS; some routers block names that point to home
addresses ("DNS rebinding protection"); renewal is by hand every 60 days until a central renewal
service exists; the self-made certificate stays as the fallback.

### 12. Red-team page (enforced)

Runs only on a dedicated fictional demo home, bound to 127.0.0.1 until hosting is approved. Per-visitor
and global caps, a daily token cap and a hard daily dollar budget with worst-case reservations; past the
budget it switches to recorded answers. Visitor IPs are hashed, never stored. The paraphrase check and
workbench are off there by design (they would break the spending bound).

### 13. Updates to the box's code (enforced)

- **What is signed:** each release's `manifest.json` (version, git commit, the tarball's SHA-256 and file
  name). The signature is Ed25519, made by `scripts/release.py`, over the exact manifest bytes. The tarball is
  covered through its SHA-256.
- **Where the keys live:** the private key only on the developer's laptop, in
  `~/.config/familybox/release-signing.key` (0600, in a 0700 folder, never in the repo, never printed). The
  public key ships inside the box's code (`src/familybox/release_key.pub`), so only a release signed with the
  current key can change which key the box trusts.
- **Order of checks:** the signature is checked before anything in the manifest is read. Then the version
  must be newer than the installed one (`.familybox-release.json` in the code folder; none means 0), so an
  old signed release cannot be replayed to roll a box back. Then the SHA-256. Then every tarball entry:
  absolute paths, `..`, device files, pipes and links that lead outside the folder are refused, and the
  tarball is unpacked with Python's `data` filter and checked again once unpacked.
- **Getting the files:** HTTPS only (redirects to plain HTTP are refused) or a local folder; size caps
  (manifest 64 KB, tarball 200 MB) and timeouts.
- **Python packages:** `uv sync --frozen` installs exactly what the signed `uv.lock` names, and uv checks
  each download against the hashes in it.
- **A release that does not start:** if the page does not answer within 60 s of the restart, the previous
  code is put back and restarted, and that version is not tried again. The box's home is never touched.
- **Not covered:**
  - **A stolen release key.** Whoever has it can ship code to every box with the daily timer on. The key file
    has no passphrase; the laptop's login and disk encryption protect it. There is no way to revoke it from a
    distance: boxes would have to be fixed by hand.
  - **Holding updates back.** Someone who controls the download can keep serving an older release, or
    nothing. The box stays on what it has; it has no "too old" deadline.
  - **The board's own software.** `scripts/pi_os_updates.sh` turns on Debian's `unattended-upgrades`; those
    updates trust Debian's own archive signing, which familybox does not check. By default only Debian
    security updates are installed; packages from the Raspberry Pi archive (kernel, firmware) are not on
    that list. uv and Python themselves are not updated by either path.
  - **The packages' authors.** Hashes in `uv.lock` stop a changed download, not a bad version that was
    chosen on purpose or by mistake when the lock was made.

## Not covered

- **Root on a running, unlocked box** reads everything (see 11b for a stolen, powered-off box).
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
