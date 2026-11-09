"""The live trust panel: read a question's events and audit entry, and render them as a timeline.

Data sources (nothing new is stored on disk):
  <runtime>/events/<person>/<qid>.jsonl   one line per step, written by box.Question.emit (already scrubbed)
  <runtime>/audit/<person>.jsonl          one line per finished question: reasons, files, what was sent

Who sees what:
  - Everyone sees their own questions in full: tool arguments, files, reasons and the exact text sent.
  - The admin also sees everyone else's questions, but only the trust facts: where the model ran, that
    each step was signed, which tools ran, what the gate decided. Search words, workbench code, the
    answer text and file names the admin could not read themselves are hidden. A child's health
    questions stay the child's.
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
}
SOURCE_SHORT = {"web": "Web page", "cli": "Command line", "mcp-stdio": "Assistant app", "mcp-remote": "Web assistant"}
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
    """The outcome once answered, else running, or unfinished if it went quiet."""
    for ev in reversed(events):
        if ev.get("step") == "answer":
            return str(ev.get("outcome", "error"))
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
    first = events[0] if events[0].get("step") == "question" else {}
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

def when(ts: float | None) -> str:
    if not ts:
        return ""
    d = dt.datetime.fromtimestamp(ts)
    hour = d.hour % 12 or 12
    return f"{d.strftime('%b')} {d.day}, {hour}:{d.minute:02d} {'AM' if d.hour < 12 else 'PM'}"


def clock(ts) -> str:
    """verified_at from the SDK: epoch milliseconds (or seconds). Anything else is shown as is."""
    if not isinstance(ts, (int, float)) or isinstance(ts, bool):
        return esc(ts) if ts else "unknown"
    secs = ts / 1000 if ts > 1e11 else ts
    if secs < 1e9:
        return esc(ts)
    d = dt.datetime.fromtimestamp(secs)
    hour = d.hour % 12 or 12
    return f"{d.strftime('%b')} {d.day}, {hour}:{d.minute:02d}:{d.second:02d} {'AM' if d.hour < 12 else 'PM'}"


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
        """A file path as this viewer may see it, already escaped."""
        rel = str(rel or "")
        if not rel:
            return "a file"
        if self.full or (access.can_read(self.viewer, rel) and not access.is_health(rel)):
            return f'<code class="fb-path">{esc(rel)}</code>'
        owner = access.owner_of(rel)
        return f"one of {esc(self.cfg.people[owner].display if owner in self.cfg.people else 'their')}'s private files"

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
            return f"someone else's {esc(kind_word(m.group(1)))} from {self.path(m.group(2))}"
        m = re.match(r"(\w+) from (.+) in a form that could not be masked$", text)
        if m:
            return f"{esc(kind_word(m.group(1)))} from {self.path(m.group(2))} that could not be cleanly removed"
        m = re.match(r"(\w+) from (.+)$", text)
        if m:
            return f"{esc(kind_word(m.group(1)))} from {self.path(m.group(2))}"
        if text in ("SSN-shaped number", "card number"):
            return {"SSN-shaped number": "a number shaped like a Social Security number",
                    "card number": "a card number"}[text]
        return esc(text) if self.full else "a safety check from a plugin"


def kind_word(kind: str) -> str:
    return {"ssn": "a Social Security number", "id": "an ID number", "health": "a health detail",
            "tripwire": "a tripwire"}.get(kind, kind)


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
        rows.append(f'<li>{esc(h.get("label") or kind_word(str(h.get("kind"))))}, '
                    f'belongs to {esc(view.name(h.get("owner")))}, from {view.path(h.get("path"))}</li>')
    return (f'<p class="muted">Held for their owner (the values are never shown here):</p>'
            f'<ul class="fb-list">{"".join(rows)}</ul>') if rows else ""


def _workbench(view: View, ev: dict, n: int) -> str:
    ok = ev.get("ok")
    cls = "ok" if ok else ("bad" if ok is False else "info")
    bits = []
    keys = ("exit_code", "seconds", "output_chars", "why", "message") if view.full else ("exit_code", "seconds")
    for k in keys:
        if k in ev and not isinstance(ev[k], (dict, list)):
            v = secs(ev[k]) if k == "seconds" else ev[k]
            bits.append(f'{esc(k.replace("_", " "))}: {esc(v)}')
    if isinstance(ev.get("files"), list):
        bits.append("files: " + ", ".join(view.path(f) for f in ev["files"]))
    body = f'<p class="muted">{"; ".join(bits)}</p>' if bits else ""
    code = ev.get("code")
    if isinstance(code, str) and code:
        if view.full:
            body += (f'<details class="fb-code" id="wb-{n}"><summary>Show the code the model wrote '
                     f'({code.count(chr(10)) + 1} lines)</summary><pre><code>{esc(code)}</code></pre></details>')
        else:
            body += f'<p class="muted">The code is only shown to {esc(view.owner_name())}.</p>'
    return _item(cls, "Ran code in the sealed workbench (no network, read-only files)", body, ev.get("t"), f"ev-{n}")


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
    for n, ev in enumerate(events):
        step, t = ev.get("step"), ev.get("t")
        key = f"ev-{n}"
        if step == "question":
            src = str(ev.get("source", ""))
            how = SOURCE_LABELS.get(src, src or "an unknown connection")
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
            if name == "read_file" and isinstance(path, str) and path in denied:
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
        else:
            items.append(_item("info", f"Step: {esc(step)}", "", t, key))
    if status == "running":
        items.append('<li class="fb-step s-info fb-wait"><div class="fb-head"><span class="fb-dot"></span>'
                     '<strong>Working...</strong></div></li>')

    parts = [f'<div class="fb-chips">{badge(status)}{chip_html}</div>']
    parts.append(f'<ol class="fb-timeline">{"".join(items)}</ol>')
    if audit:
        parts.append(_files_and_reasons(view, audit))
        parts.append(_sent(view, audit, first.get("source")))
    elif status == "unfinished":
        parts.append('<p class="bad">This question stopped before it finished. Nothing was answered.</p>')
    return "".join(parts)


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


def _sent(view: View, audit: dict, source) -> str:
    where = "shown on this page" if source == "web" else "sent to the assistant"
    if not view.full:
        return (f'<div class="card"><h2>What was {where}</h2><p class="muted">Only '
                f'{esc(view.owner_name())} can see the answer text.</p></div>')
    text = audit.get("sent_to_assistant", "")
    pending = ""
    if audit.get("held_ids"):
        pending = ('<p class="muted">Held details wait in <a href="/approvals">Approvals</a> for their owner. '
                   'Approving shows them on the owner\'s screen only.</p>')
    return (f'<div class="card"><h2>Exactly what was {where}</h2>'
            f'<pre class="fb-sent">{esc(text)}</pre>{pending}</div>')


def version(events: list[dict], audit: dict | None, status: str) -> str:
    return f"{len(events)}:{1 if audit else 0}:{status}"
