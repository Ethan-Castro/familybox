"""Activity: the live trust panel on the box's web page.

  GET  /activity                 your questions (the admin sees everyone's), plus an Ask box
  POST /activity/ask             ask the box from the browser (source "web"), then watch it run
  GET  /activity/<qid>           one question as a timeline: connection, attestation, signed turns,
                                 tools, files, workbench runs, gate decision, what was sent
  GET  /activity/<qid>/live      JSON for the page's own script to poll while the question runs
  GET  /activity/static/*        that script and its styles (served by the box, so the strict CSP holds)

Rendering and the who-sees-what rules live in familybox.activity.
"""

from __future__ import annotations

import json
import logging
import time
from collections import deque

from starlette.background import BackgroundTask
from starlette.requests import Request
from starlette.responses import JSONResponse, RedirectResponse, Response
from starlette.routing import Route

from familybox import activity as act
from familybox.box import new_qid

log = logging.getLogger("familybox.plugins.activity")

MAX_QUESTION = 1000
ASKS_PER_HOUR = 20
KEEP_TEXT = 200            # question texts kept in memory (web asks only)

CSS = """
.fb-wide { max-width: 760px; margin: 0 auto; }
.fb-chips { display: flex; flex-wrap: wrap; gap: 6px; margin: 8px 0 14px; }
.fb-badge { display: inline-block; padding: 3px 10px; border-radius: 999px; font-size: 14px; font-weight: 600;
  border: 1px solid currentColor; white-space: nowrap; }
.fb-badge.ok { color: var(--ok); } .fb-badge.bad { color: var(--bad); }
.fb-badge.warn { color: #9a5b00; } .fb-badge.info { color: var(--accent); }
@media (prefers-color-scheme: dark) { .fb-badge.warn { color: #f0b860; } }
ol.fb-timeline { list-style: none; margin: 0; padding: 0 0 0 4px; }
.fb-step { position: relative; padding: 0 0 14px 26px; border-left: 2px solid var(--line); margin-left: 8px; }
.fb-step:last-child { border-left-color: transparent; }
.fb-dot { position: absolute; left: -9px; top: 4px; width: 16px; height: 16px; border-radius: 50%;
  background: var(--card); border: 3px solid var(--accent); }
.fb-step.s-ok .fb-dot { border-color: var(--ok); } .fb-step.s-bad .fb-dot { border-color: var(--bad); }
.fb-step.s-warn .fb-dot { border-color: #c27a00; }
.fb-step.s-bad > .fb-head strong { color: var(--bad); }
.fb-head { display: flex; gap: 8px; align-items: baseline; justify-content: space-between; }
.fb-head strong { font-weight: 600; word-break: break-word; }
.fb-t { color: var(--muted); font-size: 13px; font-variant-numeric: tabular-nums; white-space: nowrap; }
.fb-body { color: var(--fg); font-size: 15px; }
.fb-body p { margin: 4px 0; }
.fb-list { margin: 4px 0; padding-left: 20px; font-size: 15px; }
.fb-list li { margin: 2px 0; word-break: break-word; }
code, .fb-path { font: 14px ui-monospace, Menlo, Consolas, monospace; word-break: break-all; }
.fb-arg q { font-style: italic; }
.fb-q { margin: 6px 0; padding: 8px 12px; border-left: 3px solid var(--accent); background: var(--bg); }
pre.fb-sent, .fb-code pre { white-space: pre-wrap; word-break: break-word; background: var(--bg);
  border: 1px solid var(--line); border-radius: 8px; padding: 10px; font: 14px/1.45 ui-monospace, Menlo, monospace;
  max-height: 420px; overflow: auto; margin: 6px 0; }
.fb-code summary { cursor: pointer; color: var(--accent); font-weight: 600; }
.fb-wait .fb-dot { animation: fbpulse 1.2s ease-in-out infinite; }
@keyframes fbpulse { 50% { opacity: .3; } }
@media (prefers-reduced-motion: reduce) { .fb-wait .fb-dot { animation: none; } }
textarea.fb-ask { width: 100%; min-height: 84px; padding: 10px; font: inherit; border-radius: 8px;
  border: 1px solid var(--line); background: var(--bg); color: var(--fg); resize: vertical; }
table.fb-table { width: 100%; border-collapse: collapse; font-size: 15px; }
.fb-table th, .fb-table td { text-align: left; padding: 8px 6px; border-bottom: 1px solid var(--line);
  vertical-align: top; }
.fb-table th { color: var(--muted); font-weight: 600; font-size: 14px; }
.fb-table a { color: var(--accent); }
.fb-filter a { margin-right: 10px; }
.fb-filter a.here { font-weight: 700; text-decoration: none; color: var(--fg); }
@media (max-width: 520px) { .fb-table .fb-hide { display: none; } }
/* a question as a chat: the question on the right, the checked answer on the left, then the steps */
.fb-chat { display: flex; flex-direction: column; gap: 24px; }
.fb-me { align-self: flex-end; max-width: 80%; background: var(--soft); color: var(--ink); border-radius: 22px;
  padding: 10px 18px; white-space: pre-wrap; word-break: break-word; }
.fb-answer { font-size: 16px; line-height: 1.6; white-space: pre-wrap; word-break: break-word; color: var(--fg); }
.fb-cap { color: var(--smoke); font-size: 12px; margin: 8px 0 0; }
.fb-typing { display: inline-flex; gap: 4px; vertical-align: middle; margin-right: 8px; }
.fb-typing i { width: 6px; height: 6px; border-radius: 50%; background: var(--smoke); animation: fbblink 1.2s infinite; }
.fb-typing i:nth-child(2) { animation-delay: .2s; } .fb-typing i:nth-child(3) { animation-delay: .4s; }
@keyframes fbblink { 0%, 80%, 100% { opacity: .25; } 40% { opacity: 1; } }
@media (prefers-reduced-motion: reduce) { .fb-typing i { animation: none; } }
.fb-todo { margin: 14px 0 0; display: flex; flex-wrap: wrap; align-items: center; gap: 10px 12px; }
.fb-go { display: inline-block; background: var(--accent); color: #fff; border-radius: 9999px; padding: 8px 16px;
  font-size: 14px; font-weight: 500; text-decoration: none; white-space: nowrap; }
.fb-go:hover { opacity: .85; }
.fb-how { border-top: 1px solid var(--line); padding-top: 20px; margin-top: 8px; }
.fb-how > h2 { font-size: 14px; font-weight: 500; color: var(--muted); margin: 0 0 12px; }
.fb-next { position: sticky; bottom: 0; background: linear-gradient(transparent, var(--bg) 28%); padding: 24px 0 16px; }
.sr { position: absolute; width: 1px; height: 1px; overflow: hidden; clip: rect(0 0 0 0); white-space: nowrap; }
"""

JS = r"""(function () {
  "use strict";
  var MONTHS = ["Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"];
  function two(n) { return (n < 10 ? "0" : "") + n; }
  // Times are rendered with the box's clock and zone; show them in the reader's own time zone instead.
  function localTimes(scope) {
    var els = scope.querySelectorAll("time.fb-time[data-ts]");
    for (var i = 0; i < els.length; i++) {
      var d = new Date(parseInt(els[i].getAttribute("data-ts"), 10) * 1000);
      if (isNaN(d.getTime())) { continue; }
      var h = d.getHours() % 12 || 12;
      var s = els[i].getAttribute("data-sec") === "1" ? ":" + two(d.getSeconds()) : "";
      els[i].textContent = MONTHS[d.getMonth()] + " " + d.getDate() + ", " + h + ":" + two(d.getMinutes()) +
        s + (d.getHours() < 12 ? " AM" : " PM");
      els[i].setAttribute("datetime", d.toISOString());
    }
  }
  localTimes(document);
  var root = document.getElementById("fb-live");
  if (!root) { return; }
  var url = root.getAttribute("data-poll");
  var tries = 0, fails = 0;
  function openIds() {
    var ids = [], els = root.querySelectorAll("details[open]");
    for (var i = 0; i < els.length; i++) { if (els[i].id) { ids.push(els[i].id); } }
    return ids;
  }
  function stopped() {
    if (document.getElementById("fb-stopped")) { return; }
    var p = document.createElement("p");
    p.id = "fb-stopped";
    p.className = "bad";
    p.textContent = "Live updates stopped. Reload the page.";
    root.parentNode.insertBefore(p, root);
  }
  function retry() {
    fails += 1;
    if (tries < 900) { setTimeout(tick, Math.min(3000 * Math.pow(2, fails - 1), 30000)); } else { stopped(); }
  }
  function tick() {
    tries += 1;
    fetch(url, { credentials: "same-origin", headers: { "Accept": "application/json" }, cache: "no-store" })
      .then(function (r) {
        if (r.ok) { return r.json(); }
        if (r.status === 401 || r.status === 404) { stopped(); } else { retry(); }
        return null;
      })
      .then(function (d) {
        if (!d) { return; }
        fails = 0;
        if (d.version !== root.getAttribute("data-version")) {
          var keep = openIds();
          root.innerHTML = d.html;
          localTimes(root);
          for (var i = 0; i < keep.length; i++) {
            var el = document.getElementById(keep[i]);
            if (el) { el.open = true; }
          }
          root.setAttribute("data-version", d.version);
        }
        root.setAttribute("data-status", d.status);
        if (d.status === "running") {
          if (tries < 900) { setTimeout(tick, 1000); } else { stopped(); }
        }
      })
      .catch(function () { retry(); });
  }
  if (url && root.getAttribute("data-status") === "running") { setTimeout(tick, 600); }
})();
"""


def web_nav():
    return [("Activity", "/activity")]


def web_routes(ctx):
    cfg = ctx.cfg
    esc = ctx.esc
    texts: dict[str, tuple[str, str]] = {}           # qid -> (asker id, question text), web asks only
    pending: dict[str, dict] = {}                    # qid -> {"owner", "started", "failed"} until it finishes
    recent: dict[str, deque] = {}                    # asker id -> times of recent web asks
    running: set[str] = set()                        # asker ids with a web question in flight

    def assets() -> str:
        return ('<link rel="stylesheet" href="/activity/static/activity.css">'
                '<script src="/activity/static/activity.js" defer></script>')

    async def css(request: Request):
        return Response(CSS, media_type="text/css")

    async def js(request: Request):
        return Response(JS, media_type="text/javascript")

    def text_for(sess, owner: str, qid: str) -> str | None:
        got = texts.get(qid)
        return got[1] if got and got[0] == owner == sess.person.id else None

    def ask_form(sess, msg: str = "", value: str = "") -> str:
        from familybox.web import composer
        note = f'<p class="bad">{esc(msg)}</p>' if msg else ""
        return (f'{note}{composer(sess.csrf, "Ask your family box", value, maxlength=MAX_QUESTION)}'
                f'<p class="muted">The model only sees files you are allowed to read. Every answer is checked by the '
                f'box before you see it, and you can follow each step.</p>')

    def list_page(sess, request: Request, msg: str = "", value: str = "", status: int = 200):
        viewer = sess.person
        who = request.query_params.get("who") if viewer.admin else None
        if who and who not in cfg.people:
            who = None
        rows = []
        for s in act.list_activity(cfg, viewer, who):
            person = cfg.people[s.person].display if s.person in cfg.people else s.person
            src = act.source_short(s.source)
            q = text_for(sess, s.person, s.qid)
            label = esc(q[:80] + ("..." if len(q) > 80 else "")) if q else "(question text is not kept)"
            rows.append(f'<tr><td><a href="/activity/{esc(s.qid)}">{act.when_html(s.started)}</a>'
                        f'<div class="muted">{label}</div></td>'
                        + (f'<td>{esc(person)}</td>' if viewer.admin else "")
                        + f'<td class="fb-hide">{esc(src)}</td><td>{act.badge(s.status)}</td></tr>')
        for qid, p in pending.items():   # web asks that have not written their first step yet
            if p["owner"] == viewer.id and not act.find(cfg, viewer, qid):
                rows.insert(0, f'<tr><td><a href="/activity/{esc(qid)}">{act.when_html(p["started"])}</a></td>'
                            + (f'<td>{esc(viewer.display)}</td>' if viewer.admin else "")
                            + f'<td class="fb-hide">Web page</td><td>{act.badge("unfinished" if p["failed"] else "running")}'
                            f'</td></tr>')
        head = ("<tr><th>When</th>" + ("<th>Who</th>" if viewer.admin else "")
                + '<th class="fb-hide">Through</th><th>Result</th></tr>')
        table = (f'<table class="fb-table">{head}{"".join(rows)}</table>' if rows
                 else '<p class="muted">No questions yet. Ask one above, or from ChatGPT or Claude.</p>')
        filt = ""
        if viewer.admin:
            links = [f'<a href="/activity"{" class=here" if not who else ""}>Everyone</a>']
            links += [f'<a href="/activity?who={esc(pid)}"{" class=here" if who == pid else ""}>{esc(p.display)}</a>'
                      for pid, p in sorted(cfg.people.items())]
            filt = f'<p class="fb-filter">{"".join(links)}</p>'
        intro = ("Every question anyone in the family asked the box, and how each one was checked. For other "
                 "people's questions you see the safety steps, not their answers or search words."
                 if viewer.admin else "Every question you asked the box, and how each one was checked.")
        body = (f'{assets()}<div class="fb-wide"><h1>Activity</h1>{ask_form(sess, msg, value)}'
                f'<h2>Questions</h2><p class="muted">{esc(intro)}</p>{filt}{table}</div>')
        return ctx.page(sess, "Activity", body, "/activity", status)

    @ctx.need_signin
    async def list_get(request: Request, sess):
        return list_page(sess, request)

    def state_of(sess, qid: str):
        """(owner, events, audit, status) or None when this viewer may not see qid."""
        found = act.find(cfg, sess.person, qid)
        if found:
            owner, path = found
            events = act.read_events(path)
            try:
                mtime = path.stat().st_mtime
            except OSError:
                mtime = time.time()
            status = act.status_of(events, mtime)
            if status == "running" and pending.get(qid, {}).get("failed"):
                status = "unfinished"
            audit = act.audit_entry(cfg, owner, qid) if status not in ("running", "unfinished") else None
            return owner, events, audit, status
        p = pending.get(qid)
        if p and p["owner"] == sess.person.id:
            return p["owner"], [], None, "unfinished" if p["failed"] else "running"
        return None

    def not_found(sess):
        return ctx.page(sess, "Not found", '<h1>Not found</h1><p>That question isn\'t in your activity.</p>'
                        '<p><a href="/activity">Back to activity</a></p>', "/activity", 404)

    @ctx.need_signin
    async def detail(request: Request, sess):
        qid = request.path_params["qid"]
        st = state_of(sess, qid)
        if st is None:
            return not_found(sess)
        owner, events, audit, status = st
        view = act.View(cfg, sess.person, owner, text_for(sess, owner, qid))
        live = act.render_detail(view, events, audit, status)
        who = "You" if view.full else esc(view.owner_name())
        from familybox.web import composer
        text = view.question_text
        asked = (f'<div class="fb-me">{esc(text)}</div>' if text is not None else
                 f'<p class="muted">{who} asked a question. The box does not keep question text.</p>')
        again = (f'<div class="fb-next">{composer(sess.csrf, "Ask another question", maxlength=MAX_QUESTION)}</div>'
                 if view.full else "")
        body = (f'{assets()}<div class="fb-wide fb-chat"><h1 class="sr">Question</h1>{asked}'
                f'<div id="fb-live" aria-live="polite" data-poll="/activity/{esc(qid)}/live" '
                f'data-status="{esc(status)}" data-version="{esc(act.version(events, audit, status))}">{live}</div>'
                f'<noscript><p class="muted">Reload the page to see new steps.</p></noscript>'
                f'<p class="fb-cap">{who}, {act.when_html(time.time() if not events else _started(events, owner, qid))}.'
                f' Each step was recorded by the box as it happened.</p>{again}</div>')
        return ctx.page(sess, "Activity", body, "/activity")

    def _started(events, owner, qid) -> float:
        path = cfg.runtime / "events" / owner / f"{qid}.jsonl"
        try:
            return path.stat().st_mtime - float(events[-1].get("t") or 0)
        except OSError:
            return time.time()

    async def live(request: Request):
        sess = ctx.session_of(request)
        if sess is None:
            return JSONResponse({"error": "signed out"}, status_code=401)
        qid = request.path_params["qid"]
        st = state_of(sess, qid)
        if st is None:
            return JSONResponse({"error": "not found"}, status_code=404)
        owner, events, audit, status = st
        view = act.View(cfg, sess.person, owner, text_for(sess, owner, qid))
        return JSONResponse({"status": status, "version": act.version(events, audit, status),
                             "html": act.render_detail(view, events, audit, status)})

    def mark_crashed(person_id: str, qid: str) -> None:
        """Store the crash on disk too, so the page says "Did not finish" after a restart. Only appended
        to a question that already wrote its first step; the message never carries the error itself."""
        path = cfg.runtime / "events" / person_id / f"{qid}.jsonl"
        if not path.is_file():
            return
        started = pending.get(qid, {}).get("started", time.time())
        try:
            with path.open("a") as f:
                f.write(json.dumps({"qid": qid, "t": round(time.time() - started, 3), "step": "crashed",
                                    "message": "the box hit an internal problem"}) + "\n")
        except OSError:
            log.exception("could not record the crash of %s", qid)

    async def run_question(person_id: str, question: str, qid: str) -> None:
        try:
            await ctx.box().ask_async(person_id, question, source="web", qid=qid)
        except Exception:  # noqa: BLE001 - shown on the page as "did not finish"
            log.exception("web question %s failed", qid)
            if qid in pending:
                pending[qid]["failed"] = True
            mark_crashed(person_id, qid)
            return
        finally:
            running.discard(person_id)
        pending.pop(qid, None)

    async def ask(request: Request):
        got = await ctx.guarded_form(request)
        if isinstance(got, Response):
            return got
        sess, form = got
        raw = form.get("question")
        question = raw.strip() if isinstance(raw, str) else ""
        pid = sess.person.id
        if not question:
            return list_page(sess, request, "Type a question first.", status=400)
        if len(question) > MAX_QUESTION:
            return list_page(sess, request, f"Keep questions under {MAX_QUESTION} characters.",
                             question[:MAX_QUESTION], 400)
        if pid in running:
            return list_page(sess, request, "Your last question is still running. Wait for it to finish.",
                             question, 429)
        now = time.time()
        times = recent.setdefault(pid, deque())
        while times and now - times[0] > 3600:
            times.popleft()
        if len(times) >= ASKS_PER_HOUR:
            return list_page(sess, request, "That's a lot of questions for one hour. Try again a little later.",
                             question, 429)
        times.append(now)
        qid = new_qid()
        texts[qid] = (pid, question)
        while len(texts) > KEEP_TEXT:
            texts.pop(next(iter(texts)))
        pending[qid] = {"owner": pid, "started": now, "failed": False}
        running.add(pid)
        # The page loads at once and polls; the question runs after the redirect is sent.
        return RedirectResponse(f"/activity/{qid}", status_code=303,
                                background=BackgroundTask(run_question, pid, question, qid))

    return [
        Route("/activity", list_get),
        Route("/activity/ask", ask, methods=["POST"]),
        Route("/activity/static/activity.css", css),
        Route("/activity/static/activity.js", js),
        Route("/activity/{qid}/live", live),
        Route("/activity/{qid}", detail),
    ]
