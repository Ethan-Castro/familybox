"""The live trust panel: read a question's events and audit entry, and render them as a timeline.

Data sources (nothing new is stored on disk):
  <runtime>/events/<person>/<qid>.jsonl   one line per step, written by box.Question.emit (already scrubbed)
  <runtime>/audit/<person>.jsonl          one line per finished question: reasons, files, what was sent

Who sees what:
  - Everyone sees their own questions in full: tool arguments, files, reasons and the exact text sent.
  - The admin also sees everyone else's questions, but only the trust facts: where the model ran, that
    each step was signed, which tools ran, how many files were opened or refused, and what the gate
    decided (passed, numbers removed, held, blocked). Search words, workbench code and output, the
    answer text, and the names of files the admin could not read themselves are hidden.
  - Health details are never described to anyone but their owner. When the gate holds or blocks
    something from a health file, other viewers (the admin included) only see "a private detail from
    one of Maya's files", not whether it was a condition, a medication or a visit.
  - A file path is only shown to someone who could open that file themselves, even on their own page.
  - Held values are never shown here, to anyone. They live only in Approvals.

The question text itself is never written to disk by the box (the audit keeps a SHA-256). The web
plugin keeps the text of questions asked on the web page in memory only, for the person who asked.
"""

from __future__ import annotations

import datetime as dt
import html
import json
import re
import time
from dataclasses import dataclass, field
from pathlib import Path

from . import access
from .box import QID_RE
from .config import Config, Person

STALE_S = 10 * 60          # a question with no new step for this long, and no answer, did not finish
MAX_LIST = 200

SOURCE_LABELS = {
    "web": "this web page",
    "cli": "the box's command line",
    "mcp-stdio": "an assistant app connected to the box (MCP)",
    "mcp-remote": "a web assistant such as ChatGPT or Claude (remote MCP)",
    "mcp-http-local": "an assistant app on this computer (local MCP, no sign-in)",
}
SOURCE_SHORT = {"web": "Web page", "cli": "Command line", "mcp-stdio": "Assistant app", "mcp-remote": "Web assistant",
                "mcp-http-local": "Local assistant"}


def _split_source(src: str) -> tuple[str, str | None]:
    """'mcp-stdio:claude-ai' -> ('mcp-stdio', 'Claude'). The part after ':' is the assistant's own name
    from the MCP handshake (feat/unoq); it is only a label, never used to decide who may read what."""
    base, _, client = (src or "").partition(":")
    if not client:
        return base, None
    from .devices import assistant_name
    return base, assistant_name(client) or client


def source_label(src: str) -> str:
    base, name = _split_source(src)
    how = SOURCE_LABELS.get(base, base or "an unknown connection")
    return f"{how}, which said it is {name}" if name else how


def source_short(src: str) -> str:
    base, name = _split_source(src)
    short = SOURCE_SHORT.get(base, base or "Unknown")
    return f"{short} ({name})" if name else short
OUTCOME_LABELS = {
    "pass": "Answered", "masked": "Answered, numbers removed", "held": "Answered, details held",
    "refused": "Blocked", "error": "Stopped", "running": "Running", "unfinished": "Did not finish",
}
OUTCOME_CLASS = {"pass": "ok", "masked": "ok", "held": "warn", "refused": "bad", "error": "bad",
                 "running": "info", "unfinished": "bad"}
GATE_TEXT = {
    "pass": "Nothing protected was found. The answer went out as written.",
    "masked": "Numbers that looked like Social Security or card numbers were removed.",
    "held": "Private details were swapped for placeholders. Their owner can approve them on their own screen.",
    "refused": "The whole answer was blocked. Nothing from it was sent.",
}


def esc(s) -> str:
    return html.escape(str(s), quote=True)


# --- reading -------------------------------------------------------------------------------------

def read_events(path: Path) -> list[dict]:
    """Every complete JSON line. A half-written last line (the question is still running) is skipped."""
    out = []
    try:
        lines = path.read_text().splitlines()
    except OSError:
        return []
    for line in lines:
        try:
            ev = json.loads(line)
        except json.JSONDecodeError:
            continue
        if isinstance(ev, dict) and isinstance(ev.get("step"), str):
            out.append(ev)
    return out


def audit_entry(cfg: Config, person_id: str, qid: str) -> dict | None:
    path = cfg.runtime / "audit" / f"{person_id}.jsonl"
    if not path.exists():
        return None
    found = None
    for line in path.read_text().splitlines():
        if f'"{qid}"' not in line:
            continue
        try:
            e = json.loads(line)
        except json.JSONDecodeError:
            continue
        if isinstance(e, dict) and e.get("qid") == qid:
            found = e
    return found


def status_of(events: list[dict], mtime: float, now: float | None = None) -> str:
    """The outcome once answered, else running, or unfinished if it crashed or went quiet."""
    for ev in reversed(events):
        if ev.get("step") == "answer":
            return str(ev.get("outcome", "error"))
        if ev.get("step") == "crashed":
            return "unfinished"
    now = time.time() if now is None else now
    return "running" if now - mtime < STALE_S else "unfinished"


@dataclass
class Summary:
    qid: str
    person: str
    started: float
    source: str
    mode: str
    status: str
    seconds: float | None
    steps: int


def visible_people(cfg: Config, viewer: Person) -> list[str]:
    return sorted(cfg.people) if viewer.admin else [viewer.id]


def _summary(person_id: str, path: Path, now: float) -> Summary | None:
    events = read_events(path)
    if not events:
        return None
    try:
        mtime = path.stat().st_mtime
    except OSError:
        return None
    if events[0].get("step") != "question":
        return None   # not a question (a photo read writes its own events); it has no answer to wait for
    first = events[0]
    last = events[-1]
    started = mtime - float(last.get("t") or 0)
    answer = next((e for e in reversed(events) if e.get("step") == "answer"), None)
    return Summary(path.stem, person_id, started, str(first.get("source", "")), str(first.get("mode", "")),
                   status_of(events, mtime, now), answer.get("seconds") if answer else None, len(events))


def list_activity(cfg: Config, viewer: Person, who: str | None = None, limit: int = MAX_LIST) -> list[Summary]:
    """Newest first. Only people this viewer may see; who narrows it to one person."""
    people = visible_people(cfg, viewer)
    if who:
        people = [p for p in people if p == who]
    now = time.time()
    out = []
    for pid in people:
        folder = cfg.runtime / "events" / pid
        if not folder.is_dir():
            continue
        for path in folder.glob("*.jsonl"):
            if not QID_RE.fullmatch(path.stem):
                continue
            s = _summary(pid, path, now)
            if s:
                out.append(s)
    out.sort(key=lambda s: s.started, reverse=True)
    return out[:limit]


def find(cfg: Config, viewer: Person, qid: str) -> tuple[str, Path] | None:
    """(person id, events path) if this viewer may see the question, else None (same answer either way)."""
    if not isinstance(qid, str) or not QID_RE.fullmatch(qid):
        return None
    for pid in visible_people(cfg, viewer):
        path = cfg.runtime / "events" / pid / f"{qid}.jsonl"
        if path.is_file():
            return pid, path
    return None


# --- formatting helpers --------------------------------------------------------------------------

def _fmt(secs_: float, seconds: bool) -> str:
    """The box's own clock, with its time zone named (a Pi left on UTC would otherwise look hours off).
    The page's script rewrites these into the reader's own time zone."""
    d = dt.datetime.fromtimestamp(secs_).astimezone()
    hour = d.hour % 12 or 12
    sec = f":{d.second:02d}" if seconds else ""
    zone = d.tzname() or ""
    return (f"{d.strftime('%b')} {d.day}, {hour}:{d.minute:02d}{sec} {'AM' if d.hour < 12 else 'PM'}"
            + (f" {zone}" if zone else ""))


def when(ts: float | None) -> str:
    if not ts:
        return ""
    return _fmt(ts, False)


def when_html(ts: float | None, seconds: bool = False) -> str:
    """A time element the page's script can show in the reader's own time zone."""
    if not ts:
        return ""
    return (f'<time class="fb-time" data-ts="{int(ts)}" data-sec="{1 if seconds else 0}">'
            f'{esc(_fmt(ts, seconds))}</time>')


def clock(ts) -> str:
    """verified_at from the SDK: epoch milliseconds (or seconds). Anything else is shown as is."""
    if not isinstance(ts, (int, float)) or isinstance(ts, bool):
        return esc(ts) if ts else "unknown"
    secs_ = ts / 1000 if ts > 1e11 else ts
    if secs_ < 1e9:
        return esc(ts)
    return when_html(secs_, seconds=True)


def secs(x) -> str:
    if isinstance(x, (int, float)) and not isinstance(x, bool):
        return f"{x:.1f} s" if x < 10 else f"{x:.0f} s"
    return ""


def badge(status: str) -> str:
    return (f'<span class="fb-badge {OUTCOME_CLASS.get(status, "info")}">'
            f'{esc(OUTCOME_LABELS.get(status, status))}</span>')


# --- the view ------------------------------------------------------------------------------------

@dataclass
class View:
    cfg: Config
    viewer: Person
    owner: str
    question_text: str | None = None
    full: bool = field(init=False)

    def __post_init__(self):
        self.full = self.viewer.id == self.owner

    def name(self, pid) -> str:
        if pid == self.viewer.id:
            return "you"
        p = self.cfg.people.get(pid) if isinstance(pid, str) else None
        return p.display if p else "the family"

    def owner_name(self) -> str:
        p = self.cfg.people.get(self.owner)
        return p.display if p else self.owner

    def path(self, rel) -> str:
        """A file path as this viewer may see it, already escaped. Only someone who could open the file
        themselves sees its name, even on their own question's page."""
        rel = str(rel or "")
        if not rel:
            return "a file"
        if access.can_read(self.viewer, rel):
            return f'<code class="fb-path">{esc(rel)}</code>'
        return self.private_file(access.owner_of(rel))

    def private_file(self, owner) -> str:
        if owner == self.viewer.id:
            return "one of your private files"
        if isinstance(owner, str) and owner in self.cfg.people:
            return f"one of {esc(self.cfg.people[owner].display)}'s private files"
        return "a private file"

    def hide_health(self, kind, rel) -> bool:
        """Health details are described only to their owner (and only on the owner's own page)."""
        rel = str(rel or "")
        if not (kind == "health" or (rel and access.is_health(rel))):
            return False
        owner = access.owner_of(rel) if rel else None
        return not (self.full and owner == self.viewer.id)

    def private_detail(self, rel) -> str:
        owner = access.owner_of(str(rel or "")) if rel else None
        if owner == self.viewer.id:
            return "a private detail from one of your files"
        if isinstance(owner, str) and owner in self.cfg.people:
            return f"a private detail from one of {esc(self.cfg.people[owner].display)}'s files"
        return "a private detail from a private file"

    def arguments(self, name: str, args) -> str:
        if isinstance(args, str):
            try:
                args = json.loads(args or "{}")
            except json.JSONDecodeError:
                args = {"arguments": args}
        if not isinstance(args, dict) or not args:
            return ""
        if name == "read_file" and "path" in args and len(args) == 1:
            return self.path(args["path"])
        if not self.full:
            return f'<span class="muted">(details only {esc(self.owner_name())} can see)</span>'
        parts = []
        for k, v in args.items():
            v = v if isinstance(v, str) else json.dumps(v)
            if len(v) > 300:
                v = v[:300] + "..."
            parts.append(f'<span class="fb-arg">{esc(k)}: <q>{esc(v)}</q></span>')
        return " ".join(parts)

    def reason(self, text: str) -> str:
        """Gate reasons in plain words. Tripwire values and never-share words are not repeated."""
        text = str(text)
        m = re.match(r"tripwire .* from (.+)$", text)
        if m:
            return f"a tripwire (a decoy code planted to catch leaks) from {self.path(m.group(1))}"
        if text.startswith("never-share term"):
            return "a word or phrase on the family's never-share list"
        m = re.match(r"another person's (\w+) from (.+)$", text)
        if m:
            if self.hide_health(m.group(1), m.group(2)):
                return f"someone else's private detail, {self.private_detail(m.group(2))}"
            return f"someone else's {esc(kind_noun(m.group(1)))} from {self.path(m.group(2))}"
        m = re.match(r"(\w+) from (.+) in a form that could not be masked$", text)
        if m:
            what = (self.private_detail(m.group(2)) if self.hide_health(m.group(1), m.group(2))
                    else f"{esc(kind_word(m.group(1)))} from {self.path(m.group(2))}")
            return f"{what} that could not be cleanly removed"
        m = re.match(r"(\w+) from (.+)$", text)
        if m:
            if self.hide_health(m.group(1), m.group(2)):
                return self.private_detail(m.group(2))
            return f"{esc(kind_word(m.group(1)))} from {self.path(m.group(2))}"
        if text in ("SSN-shaped number", "card number"):
            return {"SSN-shaped number": "a number shaped like a Social Security number",
                    "card number": "a card number"}[text]
        return esc(text) if self.full else "a safety check from a plugin"


KIND_NOUNS = {"ssn": "Social Security number", "id": "ID number", "health": "health detail",
              "tripwire": "tripwire"}


def kind_noun(kind: str) -> str:
    """The bare noun, for "someone else's ..." and similar."""
    return KIND_NOUNS.get(kind, kind)


def kind_word(kind: str) -> str:
    """The noun with its article: "a health detail", "an ID number"."""
    noun = kind_noun(kind)
    return f"{'an' if noun[:1].lower() in 'aeiou' else 'a'} {noun}"


# --- rendering -----------------------------------------------------------------------------------

def _item(cls: str, title: str, body: str = "", t=None, key: str = "") -> str:
    tm = f'<span class="fb-t">{esc(f"{t:.1f}")} s</span>' if isinstance(t, (int, float)) and t >= 0.05 else ""
    k = f' id="{esc(key)}"' if key else ""
    return (f'<li class="fb-step s-{cls}"{k}><div class="fb-head"><span class="fb-dot"></span>'
            f'<strong>{title}</strong>{tm}</div>{f"<div class=fb-body>{body}</div>" if body else ""}</li>')


def _held_list(view: View, held) -> str:
    if not isinstance(held, list) or not held:
        return ""
    rows = []
    for h in held:
        if not isinstance(h, dict):
            continue
        if view.hide_health(h.get("kind"), h.get("path")):
            rows.append(f'<li>{view.private_detail(h.get("path"))}</li>')
            continue
        rows.append(f'<li>{esc(h.get("label") or kind_word(str(h.get("kind"))))}, '
                    f'belongs to {esc(view.name(h.get("owner")))}, from {view.path(h.get("path"))}</li>')
    rows = list(dict.fromkeys(rows))
    return (f'<p class="muted">Held for their owner (the values are never shown here):</p>'
            f'<ul class="fb-list">{"".join(rows)}</ul>') if rows else ""


def _workbench(view: View, ev: dict, n: int) -> str:
    """A sandbox run, as plugins/workbench.py records it: code, output, ok (the sandbox ran), exit_code,
    signal, error, limits_hit, seconds, cpu_s, files_in_workspace. The code and output are the owner's."""
    ran = ev.get("ok")
    code_ = ev.get("exit_code")
    if ran is True and code_ == 0 and not ev.get("signal"):
        cls, title = "ok", "Ran code in the sealed workbench (no network, read-only files)"
    elif ran is True:
        cls, title = "bad", "Ran code in the sealed workbench, but the script failed"
    elif ran is False:
        cls, title = "bad", "Could not run code in the sealed workbench"
    else:
        cls, title = "info", "Ran code in the sealed workbench (no network, read-only files)"
    bits = []
    if isinstance(code_, int) and not isinstance(code_, bool):
        bits.append("finished normally" if code_ == 0 else f"the script stopped with an error (exit code {code_})")
    if isinstance(ev.get("signal"), int) and ev.get("signal"):
        bits.append(f"stopped by the box (signal {ev['signal']})")
    if secs(ev.get("seconds")):
        bits.append(f"took {secs(ev.get('seconds'))}")
    nfiles = ev.get("files_in_workspace")
    if isinstance(nfiles, int) and not isinstance(nfiles, bool):
        whose = "your" if view.full else f"{view.owner_name()}'s"
        bits.append(f"{nfiles} of {whose} file(s) copied in, read-only")
    limits = [str(x) for x in ev.get("limits_hit") or [] if isinstance(x, (str, int))]
    if limits:
        bits.append("hit the limit on " + ", ".join(limits))
    body = f'<p class="muted">{esc("; ".join(bits))}.</p>' if bits else ""
    err = ev.get("error")
    if isinstance(err, str) and err:
        body += (f'<p>{esc(err)}</p>' if view.full else '<p class="muted">The sandbox reported a problem.</p>')
    code = ev.get("code")
    if isinstance(code, str) and code:
        if view.full:
            body += (f'<details class="fb-code" id="wb-{n}"><summary>Show the code the model wrote '
                     f'({code.count(chr(10)) + 1} lines)</summary><pre><code>{esc(code)}</code></pre></details>')
        else:
            body += f'<p class="muted">The code is only shown to {esc(view.owner_name())}.</p>'
    output = ev.get("output")
    if isinstance(output, str) and output and view.full:
        body += (f'<details class="fb-code" id="wbo-{n}"><summary>Show what the script printed '
                 f'(the model saw this; the box checks the final answer)</summary>'
                 f'<pre><code>{esc(output)}</code></pre></details>')
    return _item(cls, title, body, ev.get("t"), f"ev-{n}")


def render_detail(view: View, events: list[dict], audit: dict | None, status: str) -> str:
    """The whole live part of the detail page. Re-rendered on every poll."""
    att = [e for e in events if e.get("step") == "attestation"]
    turns = [e for e in events if e.get("step") == "turn"]
    first = events[0] if events and events[0].get("step") == "question" else {}
    replayed = any(e.get("replayed") for e in att + turns)
    denied = set(audit.get("files_denied") or []) if audit else set()

    chips = []
    if att:
        a = att[-1]
        chips.append(("ok", "Enclave verified") if a.get("reports_verified") else ("bad", "Enclave not verified"))
        chips.append(("ok", "Encrypted end to end") if a.get("e2ee") else ("bad", "Not encrypted"))
    if turns:
        signed = sum(1 for t in turns if t.get("signature_kind") == "provider_tee")
        chips.append(("ok" if signed == len(turns) else "bad",
                      f"{signed} of {len(turns)} steps signed inside the enclave"))
    if replayed:
        chips.append(("info", "Replay of a recorded run"))
    chip_html = "".join(f'<span class="fb-badge {c}">{esc(t)}</span>' for c, t in chips)

    items = []
    pins_shown: set = set()
    for n, ev in enumerate(events):
        step, t = ev.get("step"), ev.get("t")
        key = f"ev-{n}"
        if step == "question":
            src = str(ev.get("source", ""))
            how = source_label(src)
            mode = ev.get("mode")
            mode_txt = {"live": "Live: the question goes to the NEAR AI enclave model.",
                        "record": "Live, and recorded for the demo.",
                        "replay": "Demo replay: recorded enclave turns are played back. The box's own file "
                                  "checks and answer gate run for real."}.get(mode, "")
            asker = "You" if view.full else esc(view.owner_name())
            body = ""
            if view.question_text is not None:
                body += f'<blockquote class="fb-q">{esc(view.question_text)}</blockquote>'
            body += f'<p class="muted">{esc(mode_txt)}</p>' if mode_txt else ""
            items.append(_item("info", f"{asker} asked through {esc(how)}", body, t, key))
        elif step == "attestation":
            ok = bool(ev.get("reports_verified"))
            body = (f'<p>Model <code>{esc(ev.get("model", ""))}</code>: '
                    f'{esc(ev.get("reports_verified") or 0)} attestation report(s) verified, '
                    f'checked {clock(ev.get("verified_at"))}, took {esc(secs(ev.get("seconds")) or "?")}.</p>')
            body += ('<p>End-to-end encryption is on: the question and file text are encrypted to a key that '
                     'only exists inside the enclave.</p>' if ev.get("e2ee") else
                     '<p class="bad">End-to-end encryption was not on.</p>')
            if ev.get("replayed"):
                body += '<p class="muted">Replayed: these are the results from when the run was recorded.</p>'
            items.append(_item("ok" if ok else "bad",
                               "Checked the model runs in a secure enclave (TEE)" if ok
                               else "Could not verify the enclave", body, t, key))
        elif step == "turn":
            kind = ev.get("signature_kind")
            signed = kind == "provider_tee"
            sig = ("signed inside the enclave" if signed else f"NOT signed inside the enclave ({esc(kind)})")
            body = (f'<p>{"Signed inside the enclave" if signed else "Signature: " + sig}'
                    f'{" by <code>" + esc(ev.get("signer", "")) + "</code>" if ev.get("signer") else ""}'
                    f'{", " + esc(secs(ev.get("seconds"))) if secs(ev.get("seconds")) else ""}.</p>')
            calls = ev.get("tool_calls") or []
            if calls:
                lis = "".join(f'<li><code>{esc(c.get("name", ""))}</code> '
                              f'{view.arguments(str(c.get("name", "")), c.get("arguments"))}</li>'
                              for c in calls if isinstance(c, dict))
                body += f'<p>The model asked the box to run:</p><ul class="fb-list">{lis}</ul>'
            else:
                body += '<p>The model wrote its draft answer. The box checks it before anyone sees it.</p>'
            idx = ev.get("index")
            num = idx + 1 if isinstance(idx, int) else "?"
            items.append(_item("ok" if signed else "bad", f"Model step {num}, {sig}", body, t, key))
        elif step == "tool":
            name = str(ev.get("name", ""))
            args = ev.get("arguments") or {}
            path = args.get("path") if isinstance(args, dict) else None
            if name == "read_file" and isinstance(path, str) and (ev.get("denied") or path in denied):
                items.append(_item("bad", f'Refused to open {view.path(path)}',
                                   "<p>Not this person's file to read. The model never saw it.</p>", t, key))
            elif name == "read_file" and isinstance(path, str) and ev.get("ok"):
                items.append(_item("ok", f"Opened {view.path(path)}", "", t, key))
            elif ev.get("ok"):
                items.append(_item("ok", f'Ran <code>{esc(name)}</code> {view.arguments(name, args)}', "", t, key))
            else:
                why = {"not offered": "the model asked for a tool it was not given",
                       "no provider": "no part of the box offers that tool"}.get(ev.get("why"), "the tool failed")
                items.append(_item("bad", f'Did not run <code>{esc(name)}</code>', f"<p>{esc(why)}.</p>", t, key))
        elif isinstance(step, str) and step.startswith("workbench"):
            items.append(_workbench(view, ev, n))
        elif step == "crashed":
            items.append(_item("bad", "Stopped: the box hit an internal problem",
                               "<p>The question did not finish. Nothing was answered.</p>", t, key))
        elif step in ("error", "pre_check_stopped", "post_check_stopped"):
            title = {"error": "Stopped: the box could not get a verified answer",
                     "pre_check_stopped": "Stopped by a safety check before the model was asked",
                     "post_check_stopped": "Stopped by a safety check after the model answered"}[step]
            msg = ev.get("message")
            body = f'<p>{esc(msg)}</p>' if msg and view.full else ""
            items.append(_item("bad", title, body + "<p>Nothing was answered.</p>", t, key))
        elif step == "gate":
            out = str(ev.get("outcome", ""))
            body = f'<p>{esc(GATE_TEXT.get(out, out))}</p>' + _held_list(view, ev.get("held"))
            items.append(_item(OUTCOME_CLASS.get(out, "info"),
                               f"Answer gate: {esc(OUTCOME_LABELS.get(out, out))}", body, t, key))
        elif step == "post_checks":
            out = str(ev.get("outcome", ""))
            items.append(_item(OUTCOME_CLASS.get(out, "info"), f"Extra safety checks: {esc(OUTCOME_LABELS.get(out, out))}",
                               _held_list(view, ev.get("held")), t, key))
        elif step == "answer":
            out = str(ev.get("outcome", ""))
            bits = [f"{ev.get('files_read', 0)} file(s) opened", f"{ev.get('files_denied', 0)} refused"]
            if ev.get("held"):
                bits.append(f"{ev['held']} detail(s) waiting for approval")
            if secs(ev.get("seconds")):
                bits.append(f"{secs(ev.get('seconds'))} in all")
            items.append(_item(OUTCOME_CLASS.get(out, "info"), f"Done: {esc(OUTCOME_LABELS.get(out, out))}",
                               f'<p class="muted">{esc(", ".join(bits))}.</p>', t, key))
        elif step == "pinning":
            # One line per part and result: the box checks NEAR's code several times per question.
            seen_key = (str(ev.get("component") or "").split("/")[0], ev.get("status"))
            if seen_key not in pins_shown:
                pins_shown.add(seen_key)
                items.append(_pin_item(view, ev, t, key))
        elif step == "paraphrase_check":
            items.append(_paraphrase_item(ev, t, key))
        else:
            items.append(_item("info", f"Step: {esc(step)}", "", t, key))
    if status == "running":
        items.append('<li class="fb-step s-info fb-wait"><div class="fb-head"><span class="fb-dot"></span>'
                     '<strong>Working...</strong></div></li>')

    # The reply first, like a chat. While the question runs, three dots and the step it is on.
    if audit:
        parts = [_sent(view, audit, first.get("source"))]
        if any(e.get("step") == "pinning" and e.get("status") in PIN_WAITING for e in events):
            parts.append(f'<p class="fb-todo">{_pin_next(view)}</p>')
    elif status == "unfinished":
        parts = ['<p class="bad">This question stopped before it finished. Nothing was answered.</p>']
    else:
        parts = ['<div class="fb-answer"><span class="fb-typing"><i></i><i></i><i></i></span>'
                 '<span class="muted">Working on it. The steps appear below as they happen.</span></div>']
    how = [f'<div class="fb-chips">{badge(status)}{chip_html}</div>', f'<ol class="fb-timeline">{"".join(items)}</ol>']
    if audit:
        how.append(_files_and_reasons(view, audit))
    parts.append(f'<section class="fb-how"><h2>How the box handled it</h2>{"".join(how)}</section>')
    return "".join(parts)


PIN_WAITING = ("waiting_review", "changed")
PIN_PART = {"gateway": "NEAR's front door (its gateway)", "model": "the model's sealed computer"}


def _pin_next(view: View) -> str:
    """What to do when a question stopped because NEAR's code changed. The admin gets the link."""
    if view.viewer.admin:
        return ('<a class="fb-go" href="/pins">Review the change</a> '
                '<span class="muted">You run this box, so the review is yours. Then ask again.</span>')
    admins = [p.display for p in view.cfg.people.values() if p.admin]
    who = esc(admins[0]) if admins else "the person who runs the box"
    return (f'<span class="muted">Ask {who} to open <strong>NEAR code</strong> on the box page and review the '
            f'change. Then ask again.</span>')


def _pin_item(view: View, ev: dict, t, key: str) -> str:
    status = ev.get("status")
    comp = str(ev.get("component") or "")
    part = PIN_PART.get(comp.split("/")[0], "NEAR's serving code")
    if status == "off":
        return _item("info", "NEAR code check is turned off", "", t, key)
    if status in PIN_WAITING:
        return _item("bad", "NEAR's code changed since the owner last approved it",
                     f"<p>What changed: {esc(part)}. The box does not send anything to code nobody has "
                     f"reviewed.</p><p>{_pin_next(view)}</p>", t, key)
    if status == "first_use":
        return _item("info", f"First look at NEAR's code for {esc(part)}; the box remembered it", "", t, key)
    if status == "changed_allowed":
        return _item("info", f"NEAR's code changed for {esc(part)}; this box is set to allow that and log it",
                     "", t, key)
    return _item("ok", f"NEAR's code matches the approved version: {esc(part)}", "", t, key)


PARAPHRASE_TEXT = {
    "pass": ("ok", "Second privacy check: nothing private was reworded into the answer"),
    "skipped": ("info", "Second privacy check: not needed"),
    "masked": ("ok", "Second privacy check: covered up a reworded private detail"),
    "refused": ("bad", "Second privacy check: stopped the answer"),
    "held_whole": ("bad", "Second privacy check: held the whole answer for its owner"),
    "held_check_failed": ("bad", "Second privacy check could not run, so the answer was held"),
    "not_loaded": ("bad", "Second privacy check did not load, so nothing was answered"),
}


def _paraphrase_item(ev: dict, t, key: str) -> str:
    """The check that looks for private facts written in other words. Its reason text stays off the page:
    it can name what it was looking for."""
    cls, title = PARAPHRASE_TEXT.get(str(ev.get("action")), ("info", "Second privacy check"))
    body = ""
    if ev.get("action") == "skipped" and ev.get("why") in ("turned off", "nothing would be sent",
                                                           "replayed demo answer"):
        body = f'<p class="muted">{esc(str(ev["why"]).capitalize())}.</p>'
    return _item(cls, title, body, t, key)


def _files_and_reasons(view: View, audit: dict) -> str:
    read = [p for p in audit.get("files_read") or [] if isinstance(p, str)]
    denied = [p for p in audit.get("files_denied") or [] if isinstance(p, str)]
    reasons = [r for r in audit.get("reasons") or [] if isinstance(r, str)]
    out = ['<div class="card"><h2>Files</h2>']
    out.append("<p>Opened: " + (", ".join(dict.fromkeys(view.path(p) for p in read)) or "none") + "</p>")
    out.append("<p>Refused: " + (", ".join(dict.fromkeys(view.path(p) for p in denied)) or "none") + "</p>")
    out.append('<p class="muted">The box only lets the model open files this person is allowed to read.</p>')
    if reasons:
        out.append("<h2>Why the gate acted</h2><ul class=\"fb-list\">"
                   + "".join(f"<li>{r}</li>" for r in dict.fromkeys(view.reason(r) for r in reasons)) + "</ul>")
    out.append("</div>")
    return "".join(out)


def answer_html(text: str) -> str:
    """The answer as chat text: escaped first, then **bold** and "- " bullets, the only marks the model uses often."""
    out = re.sub(r"\*\*(.+?)\*\*", r"<strong>\1</strong>", esc(text))
    return re.sub(r"(?m)^(\s*)[-*] ", "\\1\u2022 ", out)


def _sent(view: View, audit: dict, source) -> str:
    where = "shown on this page" if source == "web" else "sent to the assistant"
    if not view.full:
        return (f'<div class="fb-answer"><span class="muted">Only {esc(view.owner_name())} can see the answer '
                f'text.</span></div>')
    text = audit.get("sent_to_assistant", "")
    pending = ""
    if audit.get("held_ids"):
        pending = ('<p class="muted">Held details wait in <a href="/approvals">Approvals</a> for their owner. '
                   'Approving shows them on the owner\'s screen only.</p>')
    return (f'<div><div class="fb-answer">{answer_html(text)}</div>{pending}'
            f'<p class="fb-cap">Exactly what was {where}</p></div>')


def version(events: list[dict], audit: dict | None, status: str) -> str:
    return f"{len(events)}:{1 if audit else 0}:{status}"
