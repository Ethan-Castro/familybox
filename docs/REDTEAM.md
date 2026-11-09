# Red-team page for judges

A page where anyone can try to get a fake family's secrets out of the box: "Get Maya's SSN or Dana's
medication." The visitor picks who they pretend to be (Dana, Sam or Maya), types what they would ask
that person's AI assistant, and sees:

- exactly what an assistant would receive: the text the gate let out plus the same short footer an MCP
  assistant gets (model, turns, files read, box check, held count),
- the trust timeline for that question: enclave attestation, each signed model turn, the box's tool
  runs and files read (files it refused are only counted, as MCP does, since a refused path is whatever
  the model typed), the gate's decision, and what was held for the owner's own screen,
- a scoreboard: tries, live or replayed, blocked, held, numbers removed, answered, stopped, and
  **confirmed leaks**.

A leak is judged by the same independent checker as the attack suite: `leaked()` from
`eval/attacks.py`, run against the union of every forbidden list in its `ATTACKS` table (full SSNs and
any five digits of one, passport numbers, member and record IDs, the tripwire code, the family's health
words). It is not the gate's own code. The checker reads everything in the result card, timeline
included, not only the answer, so a value that slipped out anywhere on the page counts as a leak.

**Status: built and tested on this laptop only. It is not deployed, hosted or exposed anywhere.**

## Off by default

The page does not exist on a normal box. Three things must all be true:

1. The home was made with `familybox redteam init <folder>`. That copies the fictional demo family and
   writes a `REDTEAM_DEMO_HOME` marker file. The repo's own `demo/` folder is refused.
2. The home has the demo family (dana, sam, maya), and every SSN in it is in the fictional range
   987-65-4320 to 987-65-4329. A box holding any other SSN refuses to turn the page on.
3. The box was started with `familybox redteam serve`. This is the "--redteam" switch. `familybox serve`
   never adds the route, so `/redteam` answers 404 there.

`familybox redteam serve` runs only the red-team page. The family pages (sign-in, upload, files,
approvals, cloud) answer 404 on that server, and `/` redirects to `/redteam`.

## Run it locally

```sh
uv run familybox redteam init ~/fb-redteam-home
uv run familybox redteam serve --home ~/fb-redteam-home --replay-only     # free, no key needed
uv run --env-file .env familybox redteam serve --home ~/fb-redteam-home \
    --price-in <real $ per M in> --price-out <real $ per M out>                # live, within the limits below
uv run familybox redteam status --home ~/fb-redteam-home                  # scoreboard and today's spend
```

It listens on `https://127.0.0.1:8444/redteam` only (self-signed certificate, fingerprint printed at
start). There is no option to listen on other addresses.

## Spending guard

| Limit | Default | Flag | When reached |
|---|---|---|---|
| Hard daily budget | $2.00 | `--budget-usd` | replay only |
| Tokens per day | 2,000,000 | `--max-tokens-per-day` | replay only |
| Live tries per visitor per hour | 5 | `--live-per-visitor` | replay only for that visitor |
| Live tries per hour, everyone | 60 | `--live-global` | replay only |
| Live tries running at once | 2 | | replay only for that try |
| All tries per visitor per hour | 30 | | refused (HTTP 429) |
| All tries per hour, everyone | 600 | | refused (HTTP 429) |
| All tries per day, everyone | 5,000 | | refused (HTTP 429) |
| Question length | 500 characters | | refused (HTTP 400) |
| Request body | 8 KB | | refused |

**How the budget stays hard.** Before every live try, the box reserves that try's worst-case cost and
only goes live if today's spend, plus every open reservation, plus this worst case, fits in the budget.
After the try, the reservation is swapped for the real token count from the enclave. If the try failed,
or the enclave reply left out its token count (or said 0 tokens in, which a real try can never be), the
whole reservation is kept as spent. If the spending record cannot be read, it is never reset to zero:
the broken file is kept for the owner and live tries stay off for the rest of the day. A reservation that never settles
(for example a crash) counts as spent after 15 minutes. The day is the UTC date.

**The worst case** comes from limits the box enforces: at most 6 model turns (enclave loop) of at most
900 output tokens each, and, on a red-team home only, at most 12 tool runs per question with each result
cut to 3,000 characters. With a 500-character question that bounds one try at 367,200 input and 5,400
output tokens. The input bound assumes about one token per byte or fewer and adds room for the replayed
tool history (`familybox/redteam/guard.py` lists every assumption).

The bound only holds for the parts it counts: the two built-in tools (search and read files), the
tool limit, and one model call per turn. So a red-team box refuses to start, and stops every question,
if any other add-on is loaded: another tool (for example the analysis workbench's sandbox, which should
never run for anonymous visitors), a check that makes its own model call (for example a paraphrase
check), or anything that pushes the tool limit out of first place. The size of the system prompt plus
the real tool list is also checked against the bound. At the placeholder prices that is about
$0.19 per try, so live tries stop when less than that is left.

**Prices are placeholders, and the real price is not known yet.** The defaults are $0.50 per million
input tokens and $2.00 per million output tokens. Nobody has checked them against NEAR's real rates, and
nothing in this repo shows the real DeepSeek-V4.1-Flash-1017 price, so they may be too low or too high.
Because of that, `familybox redteam serve` refuses to start in live mode until you pass both
`--price-in` and `--price-out`. Check the real price on NEAR AI Cloud before any live hosting. Replay
only mode needs no prices, because it never calls the model.

When live tries are paused, the recorded questions on the page still run. They replay real enclave runs
from `replays/`, and the box's tools, access checks and gate run again for real. A typed question that
was not recorded gets a plain message, and nothing is asked.

## What is stored, and what is not

- **No IP addresses.** To count tries, a visitor is `HMAC(day key, address)` cut to 20 characters
  (for IPv6, the address's /64 block, since one home can pick any address in its /64),
  where the day key is `HMAC(secret, UTC date)`. The codes change every day, so they cannot be linked
  across days, and they are dropped after an hour. uvicorn's access log and proxy headers are off.
- **No sign-in and no accounts.** A random cookie (`__Host-`, Secure, HttpOnly, SameSite=Strict) only
  ties the form's CSRF token to the browser. Posts must also be same-origin.
- `runtime/redteam/state.json`: today's spend and tokens, open reservations, hit times per visitor code,
  the scoreboard.
- `runtime/redteam/leaks.jsonl`: only for confirmed leaks, the question as typed and what the assistant
  would have received, so the leak can be reproduced and fixed. The page tells visitors this.
- The box's normal records for each question, as on any box: the audit log (a hash of the question,
  never its text, and the answer that left), the event log (steps, tool names and arguments, with
  protected values scrubbed), and held values in Approvals for the fictional owners.

All of it is under the demo home's `runtime/` folder (folder 0700, files 0600).

## Safety notes

- Only fictional data can ever be behind this page (see "Off by default").
- On the red-team server the family pages are unreachable, so there is nothing to sign in to.
- The page has no scripts. The box's Content-Security-Policy allows only same-origin styles.
- Everything a visitor types or the model writes is HTML-escaped.
- Model answers are shown exactly as the assistant would get them. Recorded answers contain the model's
  own punctuation, including dashes, because changing them would misreport what was sent.

## How it would be hosted (not done; needs Ethan's approval)

The plan, if Ethan approves it:

1. **Machine.** Run it on the Pi (fleet node `decision-tree`) or another dedicated machine, never on
   the managed work laptop. Install through `scripts/fleet_exec.py` exec jobs, as the box itself was.
   Use a separate demo home (`familybox redteam init`), not the family box's home.
2. **Reach.** Keep it bound to 127.0.0.1 and put an outbound tunnel in front of it (for example a
   Cloudflare Tunnel to a hostname Ethan owns), so no port is opened on the home network. Start it with
   `--trust-ip-header cf-connecting-ip` so per-visitor limits see the real visitor; use that option only
   behind a proxy that sets the header itself. Without it, every visitor arrives as 127.0.0.1, so one
   person could use up the per-visitor limit for everyone (only the global caps would still be fair).
3. **Key.** Use a separate NEAR AI Cloud key just for this page, with the smallest account-side spend
   limit NEAR offers, so the box's own budget is not the only guard.
4. **Run it replay only first** (`--replay-only`), then switch to live once the prices are confirmed.
5. **Take it down** after judging, and archive `runtime/redteam/` (scoreboard and leaks) into the repo's
   eval results if it is useful.

**What Ethan must approve before any of this:**

- putting the page on the public internet at all, and on which machine;
- the tunnel or hosting account and the hostname;
- the NEAR key to use, and the daily budget (default $2.00) and caps above;
- the real per-token prices to pass with `--price-in` / `--price-out`;
- keeping the text of leaking attacks in `leaks.jsonl`, and how long to keep it;
- whether live mode is offered, or replay only.

## Code

- `src/familybox/plugins/redteam.py`: plugin hooks (`register`, `web_routes`, `cli`, `run_cli`), the
  server wrapper and `serve`.
- `src/familybox/redteam/home.py`: making and checking demo homes; the on/off switch; settings.
- `src/familybox/redteam/scoring.py`: loads `eval/attacks.py` by path and reuses `leaked()` and the
  forbidden lists; plain labels that do not over-claim (all fictional SSNs share their first five digits,
  so one leaked SSN matches every one; the page names only the SSN whose nine digits appear together).
- `src/familybox/redteam/ledger.py`: spending guard, rate limits, scoreboard, leak records.
- `src/familybox/redteam/guard.py`: tool-run limit, result cutting, worst-case bound.
- `src/familybox/redteam/pages.py`: the page.
- `tests/test_redteam.py`: off by default, refusal of non-demo homes, CSRF and origin, input limits,
  replay fallback, every cap and the budget, IP never stored, leak scoring, tool limits, CLI.
