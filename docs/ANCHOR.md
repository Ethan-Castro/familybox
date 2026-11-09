# Tamper-evident logs and NEAR anchoring

Every time an assistant asks the box a question, and every time someone uploads or deletes a file, the box
writes one line to that person's log (`runtime/audit/<person>.jsonl`). This page explains how the box makes
that log tamper-evident, and how the newest link of each log can be put on the NEAR blockchain.

## 1. The chain (works today, no account needed)

Each log entry carries three extra fields:

| Field | Meaning |
|---|---|
| `seq` | 0, 1, 2, ... in the order the entries were written |
| `prev_hash` | the `entry_hash` of the entry before it. The first entry uses a starting hash made from the person's id |
| `entry_hash` | sha256 of `familybox-ledger-v1` + a newline + the entry (without `entry_hash`) as canonical JSON (keys sorted, no spaces, UTF-8) |

Because every entry includes the hash of the one before, changing any entry, removing one, putting two in a
different order, copying one twice or swapping in another person's log breaks the chain. The newest
`entry_hash` is the **chain head**. The box also keeps the head in `runtime/audit/<person>.head.json`.

Check a log:

```
familybox log verify --as maya
```

It walks the whole log and prints either "Maya's log checks out: 12 entries, each linked to the one before"
with the chain head, or a list of what is wrong and where. Add `--json` for a machine-readable report. The
exit code is 0 when the log checks out and 1 when it does not.

The box's web page has a **Log** page with the same check for the signed-in person, their chain head, the last
anchor and their most recent entries. The admin also sees the chain head and status of everyone else's log
(no entries, just the status).

Other details:
- **Older logs** from before chaining are kept as they are. The first new entry is a `ledger_start` entry that
  records how many old lines there were and the sha256 of their exact bytes, so they cannot change later either.
- **A write cut off by a power cut** leaves a piece of a line at the very end of the file. The next entry
  seals it with a `ledger_resume` entry marked `"reason": "torn_write"`, which records the sha256 of the
  piece's exact bytes. `log verify` and the Log page show it as a note, not a failure, so the log still checks
  out and can still be anchored. The entry that was being written is lost; nothing else is. The box only
  treats it this way when there is exactly one piece of a line, at the end of the file, with no newline, that
  is not a whole JSON object.
- **Any other damaged line** (for example an entry with its chain fields stripped, or several bad lines) is
  sealed the same way so the box keeps working, but `log verify` keeps reporting it as a failure, and the box
  will not anchor that log again. There is no command to clear it: the log is no longer whole, and the box
  says so.
- **Approvals are logged.** Approving or denying a held value adds an `approved` or `denied` entry to the
  owner's log with the item id, its label, its kind and who asked. The value itself is never written to the log.
- **Several writers at once** (the web page, the CLI, the MCP servers) take a lock on the log first, so the
  chain never forks. `log verify` takes the same lock (shared) while it reads the log and the head file, so it
  never reports a false failure while another process is writing.

### What the chain alone cannot catch

The chain has no secret key. Someone who can edit the box's files could cut the newest entries off the end
and rewrite the head file to match, or rebuild the whole log with new hashes, or delete the log and its head
file together (verify then says "nothing has been logged yet"). Nothing inside the box can tell that apart
from a log that really looked like that. Checkpoints saved on the box with `--save` can be edited the same way.
A piece of a line cut off on purpose at the end looks like a power cut too, which is the same as cutting the
last entry off. That is what
anchors are for: once a head is anchored somewhere the box cannot change, a cut or a rewrite before that point
shows up.

## 2. Checkpoints and NEAR anchors

```
familybox anchor --as maya              dry run: print the exact NEAR call for maya's chain head
familybox anchor --as maya --save       dry run, and keep this head as a checkpoint saved on this box
familybox anchor                        dry run for everyone in the family
familybox anchor keygen                 make the box's anchoring key and print its public key
familybox anchor status                 box id, settings, and what is still missing to go live
familybox anchor send --as maya         sign and send anchor() (needs the settings below)
familybox anchor check --as maya        read the head back from NEAR and check the log against it
```

- The box never anchors a log that does not check out.
- A **dry run** touches no network and changes nothing, except that the very first run (or `anchor status`)
  makes the box's anchor id, `runtime/ledger/anchor_id.json`. It prints the call exactly as it would be signed:
  signer, public key, contract, method `anchor`, its JSON arguments and their base64, gas (30 Tgas) and a
  deposit of 0. The nonce and block hash are the only parts filled in at send time, from the network.
- Every head the box sends (or saves with `--save`) is kept in `runtime/ledger/checkpoints/<person>.jsonl`.
  `familybox log verify` checks that each one is still in the chain at the same position.
- `familybox anchor check` reads the head from the contract and checks it the same way. This is the check
  that still works if someone also wiped the box's local checkpoints.

### What goes on-chain

| Argument | What it is |
|---|---|
| `box_id` | random, made once on the box (`fb-` + 20 hex characters) |
| `person_hash` | HMAC-SHA256 of the person's id with a 32-byte salt that never leaves the box |
| `head_hash` | the chain head (a sha256) |
| `count` | how many entries the log has |

No names, questions, answers or file names go on-chain. The box id and salt are in
`runtime/ledger/anchor_id.json` (only the box can read it). What is still visible to anyone: how many people a
box anchors for, how many log entries each has, and when anchors were sent. If you lose `anchor_id.json` the
box makes a new one, and later anchors start fresh under new hashes. Old anchors stay on-chain but can no
longer be matched to people.

## 3. The contract (`contracts/disclosure-anchor/`)

Rust, `near-sdk` 5.x. Methods:

| Method | Who | What |
|---|---|---|
| `new()` | deployer | set up empty state |
| `register_box(box_id)` payable | anyone, once per box id | the caller becomes the box's writer. The deposit pays for storage (0.1 NEAR is plenty for a family) |
| `anchor(box_id, person_hash, head_hash, count)` | the box's writer | store the newest head for (box, person) and emit a NEP-297 event |
| `get(box_id, person_hash)` view | anyone | the newest anchor, or null |
| `get_box(box_id)` view | anyone | the writer, the storage deposit left and the number of people |
| `top_up(box_id)` payable | anyone | add to the storage deposit |
| `set_writer(box_id, writer)` 1 yoctoNEAR | the writer | hand the box to another account |
| `withdraw(box_id, amount)` 1 yoctoNEAR | the writer | take back unused storage deposit |

Rules `anchor` enforces: only the box's writer may call it; hashes must be 64 lowercase hex characters; the
count can never go down; the same count with a different head is refused (that would be a rewritten log); the
same count and head again is a harmless no-op; new storage is paid from the box's own deposit, never from the
contract's balance. `set_writer` and `withdraw` need 1 yoctoNEAR attached, which a function-call key cannot
attach. The box also refuses to send unless its key's allowed methods are exactly `["anchor"]` (an empty list
on NEAR means any method), so the key on the box can only ever call `anchor`.

`register_box` lets the first account to register a box id become its writer. Box ids are random and stay
private until you register, so this is unlikely, but if someone else registered your box id first,
`familybox anchor check` says so ("this box id is registered to another account"). Make a new box id by moving
`runtime/ledger/anchor_id.json` aside, then register the new one.

Event, one per anchor:

```
EVENT_JSON:{"standard":"familybox_anchor","version":"1.0.0","event":"anchored",
  "data":[{"box_id":"fb-...","person_hash":"...","head_hash":"...","count":12,"prev_count":9}]}
```

The contract keeps only the newest head per person. The events keep the full history for anyone indexing them.

**Status:** the contract was written but not compiled. This laptop has no Rust toolchain, and the task said
not to install one. The unit tests (`cargo test`) were also not run for the same reason. Treat it as
unverified code until the steps below have been done once.

## 4. Going live on testnet (not done yet)

Nothing here has been run. You need a testnet account and the Rust tools. The `near` commands follow
near-cli-rs; check the exact flags with `near --help` for your version.

1. Tools (on a machine where installing is fine):
   `rustup target add wasm32-unknown-unknown`, then `cargo install cargo-near` and `near-cli-rs`.
2. Test and build the contract:
   ```
   cd contracts/disclosure-anchor
   cargo test
   cargo near build non-reproducible-wasm
   ```
3. Create two testnet accounts, for example `okafor-family.testnet` (yours) and
   `anchor.okafor-family.testnet` (the contract), and deploy:
   ```
   near contract deploy anchor.okafor-family.testnet use-file target/near/disclosure_anchor.wasm \
     with-init-call new json-args '{}' prepaid-gas '30 Tgas' attached-deposit '0 NEAR' network-config testnet sign-with-keychain send
   ```
4. Register the box (prints the box id from `familybox anchor status`):
   ```
   near contract call-function as-transaction anchor.okafor-family.testnet register_box \
     json-args '{"box_id":"fb-..."}' prepaid-gas '30 Tgas' attached-deposit '0.1 NEAR' \
     sign-as okafor-family.testnet network-config testnet sign-with-keychain send
   ```
5. Make the box's key (`familybox anchor keygen`) and add its public key to your account as a function-call
   key that can only call `anchor` on the contract:
   ```
   near account add-key okafor-family.testnet grant-function-call-access --allowance '0.25 NEAR' \
     --contract-account-id anchor.okafor-family.testnet --function-names anchor \
     use-manually-provided-public-key ed25519:<public key from keygen> network-config testnet sign-with-keychain send
   ```
6. Tell the box (for example in the box's `.env`, loaded with `uv run --env-file .env`):
   ```
   NEAR_ACCOUNT_ID=okafor-family.testnet
   NEAR_ANCHOR_CONTRACT=anchor.okafor-family.testnet
   NEAR_NETWORK=testnet            # optional, testnet is the default
   NEAR_RPC_URL=...                # optional, defaults to https://rpc.testnet.near.org
   ```
   Instead of `keygen` you can set `NEAR_ANCHOR_PRIVATE_KEY=ed25519:...`. Never commit it.
7. `familybox anchor status` should say `"ready_to_send": true`. Then `familybox anchor send --as maya` and
   `familybox anchor check --as maya`.

The box refuses to send with a full-access key, or with a key meant for another contract or method. It checks
the key's permission on-chain before signing. When `anchor send` runs for the whole family, the box uses the
key's latest nonce from the network, but never less than one more than the nonce it used for the person before,
so two transactions never share a nonce even if the network has not caught up yet. If one
person's anchor fails, the box says so and carries on with the others (the exit code is then 1). The function-call key's allowance (0.25 NEAR above) caps what
gas fees can ever cost; each anchor costs a small fraction of a cent of gas.

## 5. Security notes

- The chain proves the log was not edited after the fact, **once it is anchored**. It does not prove the box
  wrote down every question. Software on a box that someone fully controls could skip writing an entry.
  The answer gate and the log run in the same program, so this is the same trust as the gate itself.
- Anchoring does not need to happen after every question. Anchoring every day, or after any held or refused
  answer, is enough to pin the history up to that point.
- The secret key and the salt live in `runtime/`, which the cloud backup never includes. Back them up
  separately if you want anchors to keep matching after you rebuild the box.
