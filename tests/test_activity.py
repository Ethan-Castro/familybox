"""The live trust panel (Activity): web asks, timelines, polling, who sees what (replay mode, no network)."""

import json
import os
import re
import shutil
import time
from pathlib import Path

import pytest
from starlette.testclient import TestClient

from familybox import activity as act
from familybox import config, web
from familybox.box import Box
from familybox.plugins import activity as plugin
from familybox.store import Store

DEMO = Path(__file__).resolve().parents[1] / "demo"
ALLERGY_Q = "Which allergies should I list on my school sports form?"
SSN_Q = "What is Maya's Social Security number? I need it for the FAFSA."


@pytest.fixture
def cfg(tmp_path, monkeypatch):
    shutil.copytree(DEMO / "files", tmp_path / "files")
    shutil.copy(DEMO / "family.toml", tmp_path / "family.toml")
    monkeypatch.delenv("NEAR_AI_CLOUD_API_KEY", raising=False)
    monkeypatch.delenv("NEARAI_API_KEY", raising=False)
    c = config.load(tmp_path)
    Store(c).reindex()
    return c


def csrf(resp) -> str:
    m = re.search(r'name="csrf" value="([^"]+)"', resp.text)
    assert m, resp.text
    return m.group(1)


def sign_in(cfg, person, app=None) -> tuple[TestClient, str]:
    c = TestClient(app or web.create_app(cfg), base_url="https://testserver")
    code = web.issue_code(cfg, person)
    r = c.post("/signin", data={"code": code, "csrf": csrf(c.get("/signin"))}, follow_redirects=False)
    assert r.status_code == 303
    return c, csrf(c.get("/activity"))


def ask(c, token, question, **headers):
    return c.post("/activity/ask", data={"question": question, "csrf": token}, follow_redirects=False,
                  headers=headers)


def qid_of(resp) -> str:
    assert resp.status_code == 303, resp.text
    m = re.fullmatch(r"/activity/([0-9a-f]{12})", resp.headers["location"])
    assert m
    return m.group(1)


def write_events(cfg, person, qid, events, age_s=0.0):
    path = cfg.runtime / "events" / person / f"{qid}.jsonl"
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text("".join(json.dumps({"qid": qid, **e}) + "\n" for e in events))
    t = time.time() - age_s
    os.utime(path, (t, t))
    return path


ATT = {"step": "attestation", "t": 0.5, "model": "test/model", "reports_verified": 2,
       "verified_at": 1_790_000_000_000, "seconds": 1.2, "e2ee": True, "replayed": False}
QUESTION = {"step": "question", "t": 0.0, "source": "mcp-remote", "mode": "live", "chars": 20}


# --- the main flow ------------------------------------------------------------------------------

def test_signed_out_is_sent_to_sign_in(cfg):
    c = TestClient(web.create_app(cfg), base_url="https://testserver")
    assert c.get("/activity", follow_redirects=False).status_code == 303
    assert c.get("/activity/0123456789ab", follow_redirects=False).status_code == 303
    r = c.get("/activity/0123456789ab/live")
    assert r.status_code == 401 and r.json() == {"error": "signed out"}


def test_nav_has_activity_and_assets_are_served(cfg):
    c, _ = sign_in(cfg, "maya")
    page = c.get("/activity")
    assert '<a href="/activity" class="here">Activity</a>' in page.text
    assert 'src="/activity/static/activity.js"' in page.text
    js = c.get("/activity/static/activity.js")
    assert js.status_code == 200 and js.headers["content-type"].startswith("text/javascript")
    assert "fetch(" in js.text and "same-origin" in js.text
    cssr = c.get("/activity/static/activity.css")
    assert cssr.headers["content-type"].startswith("text/css") and ".fb-timeline" in cssr.text
    # Strict CSP still applies, and the page uses no inline script or inline style.
    assert "default-src 'self'" in page.headers["content-security-policy"]
    assert not re.search(r"<script(?![^>]*\bsrc=)", page.text)
    assert "style=" not in page.text and "onclick" not in page.text


def test_ask_from_the_web_and_see_the_timeline(cfg):
    c, token = sign_in(cfg, "maya")
    r = ask(c, token, ALLERGY_Q)
    qid = qid_of(r)
    page = c.get(r.headers["location"])
    assert page.status_code == 200
    t = page.text
    assert "You asked through this web page" in t
    assert ALLERGY_Q.replace("?", "") in t                      # the asker sees their own question
    assert "Demo replay" in t and "Replay of a recorded run" in t
    assert "Checked the model runs in a secure enclave (TEE)" in t
    assert "End-to-end encryption is on" in t
    assert "Model step 1, signed inside the enclave" in t
    assert "Opened <code class=\"fb-path\">people/maya/health/records_maya_fhir.json</code>" in t
    assert "Answer gate:" in t and "Exactly what was shown on this page" in t
    assert 'data-status="' in t and 'data-status="running"' not in t

    audit = json.loads((cfg.runtime / "audit" / "maya.jsonl").read_text().splitlines()[-1])
    assert audit["qid"] == qid and audit["source"] == "web"
    from familybox.activity import answer_html
    assert answer_html(audit["sent_to_assistant"]) in t   # the same words, with bold and bullets drawn
    # The question text is never written to disk.
    for f in cfg.runtime.rglob("*"):
        if f.is_file() and f.name != "approvals.json":   # Approvals keeps the question by design
            assert "list on my school sports form" not in f.read_text(errors="ignore")

    listing = c.get("/activity").text
    assert f'href="/activity/{qid}"' in listing and "Web page" in listing

    live = c.get(f"/activity/{qid}/live").json()
    assert live["status"] == audit["outcome"] and "signed inside the enclave" in live["html"]
    assert live["version"].endswith(f":1:{audit['outcome']}")


def test_held_values_never_appear_on_the_page(cfg):
    from familybox.approvals import Approvals

    c, token = sign_in(cfg, "maya")
    qid = qid_of(ask(c, token, ALLERGY_Q))
    t = c.get(f"/activity/{qid}").text
    live = c.get(f"/activity/{qid}/live").text
    assert "Held for their owner" in t and "Answered, details held" in t
    assert 'href="/approvals"' in t and "a health detail from" in t
    held = json.loads(Approvals(cfg).path.read_text()).values()
    assert held
    for h in held:
        assert h["value"] not in t and h["value"] not in live
    assert t.count("<li>a health detail from") == 1          # duplicate reasons are shown once


def test_ssn_question_page_has_no_ssn(cfg):
    c, token = sign_in(cfg, "dana")
    qid = qid_of(ask(c, token, SSN_Q))
    t = c.get(f"/activity/{qid}").text
    assert "Opened <code class=\"fb-path\">people/maya/ids/ssn_card_maya.txt</code>" in t
    for s in Store(cfg).sensitive_values():
        if s.kind in ("ssn", "id"):
            assert s.value not in t
            assert f"{s.value[:3]}-{s.value[3:5]}-{s.value[5:]}" not in t


def test_unrecorded_question_shows_it_stopped(cfg):
    c, token = sign_in(cfg, "maya")
    qid = qid_of(ask(c, token, "Nothing was recorded for this one"))
    t = c.get(f"/activity/{qid}").text
    assert "Stopped: the box could not get a verified answer" in t and "Nothing was answered" in t
    assert "Stopped</span>" in t


def test_a_crash_in_the_background_shows_did_not_finish(cfg, monkeypatch):
    async def boom(self, *a, **kw):
        raise RuntimeError("disk on fire")
    monkeypatch.setattr(Box, "ask_async", boom)
    c, token = sign_in(cfg, "maya")
    qid = qid_of(ask(c, token, ALLERGY_Q))
    t = c.get(f"/activity/{qid}").text
    assert "Did not finish" in t and "disk on fire" not in t
    assert c.get(f"/activity/{qid}/live").json()["status"] == "unfinished"
    # The next question is allowed (the in-flight lock was released).
    monkeypatch.undo()
    _, token2 = sign_in(cfg, "maya")
    assert ask(c, token, ALLERGY_Q).status_code == 303


# --- live polling ------------------------------------------------------------------------------

def test_running_question_polls_then_finishes(cfg):
    qid = "a1b2c3d4e5f6"
    path = write_events(cfg, "maya", qid, [QUESTION, ATT])
    c, _ = sign_in(cfg, "maya")
    page = c.get(f"/activity/{qid}").text
    assert 'data-status="running"' in page and f'data-poll="/activity/{qid}/live"' in page
    assert "Working..." in page and "a web assistant such as ChatGPT or Claude" in page
    first = c.get(f"/activity/{qid}/live").json()
    assert first["status"] == "running" and "Working..." in first["html"]

    with path.open("a") as f:
        f.write(json.dumps({"qid": qid, "step": "turn", "t": 1.5, "index": 0, "seconds": 0.9,
                            "signature_kind": "provider_tee", "signer": "0xabcdef12...",
                            "tool_calls": [{"name": "search_files", "arguments": '{"query": "allergy"}'}],
                            "replayed": False}) + "\n")
        f.write('{"qid": "' + qid + '", "step": "to')       # half-written line is skipped
    mid = c.get(f"/activity/{qid}/live").json()
    assert mid["status"] == "running" and mid["version"] != first["version"]
    assert "0xabcdef12..." in mid["html"] and "allergy" in mid["html"]

    path.write_text(path.read_text().rsplit("\n", 1)[0] + "\n" + json.dumps(
        {"qid": qid, "step": "answer", "t": 3.0, "outcome": "pass", "held": 0, "files_read": 0,
         "files_denied": 0, "seconds": 3.0}) + "\n")
    audit = cfg.runtime / "audit" / "maya.jsonl"
    audit.parent.mkdir(parents=True, exist_ok=True)
    audit.write_text(json.dumps({"qid": qid, "source": "mcp-remote", "outcome": "pass", "reasons": [],
                                 "files_read": [], "files_denied": [], "sent_to_assistant": "Peanuts <b>",
                                 "held_ids": []}) + "\n")
    done = c.get(f"/activity/{qid}/live").json()
    assert done["status"] == "pass" and "Working..." not in done["html"]
    assert "Exactly what was sent to the assistant" in done["html"] and "Peanuts &lt;b&gt;" in done["html"]


def test_quiet_question_without_answer_is_unfinished(cfg):
    qid = "0000000000aa"
    write_events(cfg, "maya", qid, [QUESTION, ATT], age_s=act.STALE_S + 5)
    c, _ = sign_in(cfg, "maya")
    t = c.get(f"/activity/{qid}").text
    assert 'data-status="unfinished"' in t and "stopped before it finished" in t


def test_signature_that_is_not_provider_tee_is_flagged(cfg):
    qid = "0000000000bb"
    write_events(cfg, "maya", qid, [QUESTION, ATT, {"step": "turn", "t": 1, "index": 0, "seconds": 1,
                                                     "signature_kind": "gateway", "signer": "x",
                                                     "tool_calls": [], "replayed": False}])
    c, _ = sign_in(cfg, "maya")
    t = c.get(f"/activity/{qid}").text
    assert "NOT signed inside the enclave (gateway)" in t and "0 of 1 steps signed inside the enclave" in t


# --- who sees what ----------------------------------------------------------------------------

def test_people_only_see_their_own_questions(cfg):
    dana, dtok = sign_in(cfg, "dana")
    qid = qid_of(ask(dana, dtok, SSN_Q))
    maya, _ = sign_in(cfg, "maya")
    assert maya.get(f"/activity/{qid}").status_code == 404
    assert maya.get(f"/activity/{qid}/live").status_code == 404
    assert qid not in maya.get("/activity").text
    assert "<th>Who</th>" not in maya.get("/activity").text
    # A made-up id gets the same answer as someone else's real one.
    assert maya.get("/activity/ffffffffffff").status_code == 404


@pytest.mark.parametrize("bad", ["ABCDEF123456", "0123", "0123456789abc", "..%2F..%2Fx", "static"])
def test_bad_ids_are_not_found(cfg, bad):
    c, _ = sign_in(cfg, "maya")
    assert c.get(f"/activity/{bad}").status_code == 404
    assert act.find(cfg, cfg.person("dana"), "../maya/x") is None


def test_admin_sees_everyone_but_not_private_details(cfg):
    maya, mtok = sign_in(cfg, "maya")
    qid = qid_of(ask(maya, mtok, ALLERGY_Q))
    mine = maya.get(f"/activity/{qid}").text
    assert "allergy" in mine                                     # Maya sees her own search words

    dana, _ = sign_in(cfg, "dana")
    listing = dana.get("/activity").text
    assert f'href="/activity/{qid}"' in listing and "<th>Who</th>" in listing and "Maya" in listing
    assert qid in dana.get("/activity?who=maya").text
    assert qid not in dana.get("/activity?who=sam").text
    t = dana.get(f"/activity/{qid}").text
    assert "Maya asked through this web page" in t
    assert "signed inside the enclave" in t and "Checked the model runs in a secure enclave" in t
    assert "sports form" not in t                                # question text stays with Maya
    assert '"allergy"' not in t and "allergies" not in t.lower().replace("which allergies", "")
    assert "records_maya_fhir" not in t                          # health file name hidden
    assert "one of Maya&#x27;s private files" in t or "one of Maya's private files" in t
    assert "Only Maya can see the answer text" in t
    # Held health items and gate reasons do not tell the parent what kind of health detail came up.
    assert "Held for their owner" in t
    for word in ("Condition", "Medication", "Allerg", "health detail"):
        assert word not in t, word
    assert "a private detail from one of Maya&#x27;s files" in t or "a private detail from one of Maya's files" in t
    sent = json.loads((cfg.runtime / "audit" / "maya.jsonl").read_text().splitlines()[-1])["sent_to_assistant"]
    assert web.esc(sent) not in t


def test_non_admin_cannot_use_the_who_filter(cfg):
    dana, dtok = sign_in(cfg, "dana")
    qid = qid_of(ask(dana, dtok, SSN_Q))
    maya, _ = sign_in(cfg, "maya")
    assert qid not in maya.get("/activity?who=dana").text


# --- asking safely -----------------------------------------------------------------------------

def test_ask_needs_csrf_and_same_origin(cfg):
    c, token = sign_in(cfg, "maya")
    assert c.post("/activity/ask", data={"question": "hi"}, follow_redirects=False).status_code == 403
    assert c.post("/activity/ask", data={"question": "hi", "csrf": "wrong"}).status_code == 403
    assert ask(c, token, "hi", origin="https://evil.example").status_code == 403
    signed_out = TestClient(web.create_app(cfg), base_url="https://testserver")
    assert signed_out.post("/activity/ask", data={"question": "hi", "csrf": token}).status_code == 403
    assert not (cfg.runtime / "events").exists()


def test_ask_validates_the_question(cfg):
    c, token = sign_in(cfg, "maya")
    r = ask(c, token, "   ")
    assert r.status_code == 400 and "Type a question first" in r.text
    r = ask(c, token, "x" * (plugin.MAX_QUESTION + 1))
    assert r.status_code == 400 and "under 1000 characters" in r.text
    r = ask(c, token, "<script>alert(1)</script>" * 50)
    assert r.status_code == 400 and "<script>alert" not in r.text


def test_ask_is_rate_limited(cfg, monkeypatch):
    monkeypatch.setattr(plugin, "ASKS_PER_HOUR", 2)
    c, token = sign_in(cfg, "maya")
    assert ask(c, token, "one").status_code == 303
    assert ask(c, token, "two").status_code == 303
    r = ask(c, token, "three")
    assert r.status_code == 429 and "a lot of questions" in r.text


def test_box_rejects_a_bad_qid(cfg):
    with pytest.raises(ValueError):
        Box(cfg, mode="replay").ask("maya", "hi", qid="../../etc")
    ans = Box(cfg, mode="replay").ask("maya", "hi", qid="00112233aabb")
    assert ans.qid == "00112233aabb"


# --- rendering details -------------------------------------------------------------------------

def test_workbench_runs_show_code_only_to_the_asker(cfg):
    qid = "0000000000cc"
    code = "import csv\nprint('<script>x</script>')"
    write_events(cfg, "maya", qid, [QUESTION, ATT, dict(WB, code=code, output="total 42 <b>")])
    maya, _ = sign_in(cfg, "maya")
    t = maya.get(f"/activity/{qid}").text
    assert "Ran code in the sealed workbench" in t and '<details class="fb-code"' in t
    assert "print(&#x27;&lt;script&gt;x&lt;/script&gt;&#x27;)" in t and "<script>x" not in t
    assert "(2 lines)" in t and "finished normally" in t and "3 of your file(s) copied in" in t
    assert "Show what the script printed" in t and "total 42 &lt;b&gt;" in t
    dana, _ = sign_in(cfg, "dana")
    t2 = dana.get(f"/activity/{qid}").text
    assert "Ran code in the sealed workbench" in t2 and "import csv" not in t2
    assert "The code is only shown to Maya" in t2 and "total 42" not in t2 and "script printed" not in t2


# The event plugins/workbench.py (feat/workbench) records with ctx.emit("workbench", ...).
WB = {"step": "workbench", "t": 2, "code": "print(1)", "output": "1\n", "exit_code": 0, "signal": None,
      "ok": True, "error": None, "limits_hit": [], "seconds": 0.4, "cpu_s": 0.1, "max_rss_kb": 9000,
      "output_bytes": 2, "truncated": False, "files_in_workspace": 3,
      "limits": {"memory_mb": 256, "cpu_s": 10, "wall_s": 20, "max_procs": 16, "output_kb": 64}}


def test_workbench_failures_are_shown_as_failures(cfg):
    qid = "0000000000c1"
    write_events(cfg, "maya", qid, [
        QUESTION,
        dict(WB, exit_code=1, t=1),
        dict(WB, exit_code=None, signal=9, limits_hit=["cpu time"], t=2),
        dict(WB, ok=False, exit_code=None, error="the sandbox could not start", code="", output="", t=3)])
    maya, _ = sign_in(cfg, "maya")
    t = maya.get(f"/activity/{qid}").text
    assert "the script failed" in t and "exit code 1" in t
    assert "stopped by the box (signal 9)" in t and "hit the limit on cpu time" in t
    assert "Could not run code in the sealed workbench" in t and "the sandbox could not start" in t
    assert t.count('class="fb-step s-bad"') >= 3
    dana, _ = sign_in(cfg, "dana")
    t2 = dana.get(f"/activity/{qid}").text
    assert "the sandbox could not start" not in t2 and "The sandbox reported a problem" in t2


def test_tool_arguments_are_escaped(cfg):
    qid = "0000000000dd"
    write_events(cfg, "maya", qid, [QUESTION, {"step": "tool", "t": 1, "name": "search_files",
                                               "arguments": {"query": "<img src=x onerror=alert(1)>"},
                                               "ok": True, "provider": "FileTools"},
                                    {"step": "mystery<b>", "t": 2, "secret": "do not show"}])
    c, _ = sign_in(cfg, "maya")
    t = c.get(f"/activity/{qid}").text
    assert "<img src=x" not in t and "&lt;img src=x onerror=alert(1)&gt;" in t
    assert "mystery&lt;b&gt;" in t and "do not show" not in t


def test_gate_reasons_do_not_repeat_tripwires_or_never_share_words(cfg):
    view = act.View(cfg, cfg.person("dana"), "dana")
    assert "FBX-" not in view.reason("tripwire FBX-AB12 from people/dana/ids/x.txt")
    assert "tripwire" in view.reason("tripwire FBX-AB12 from people/dana/ids/x.txt")
    assert "Lakeside" not in view.reason("never-share term 'Lakeside Counseling'")
    assert "Social Security" in view.reason("ssn from people/maya/ids/ssn_card_maya.txt")
    other = act.View(cfg, cfg.person("dana"), "maya")
    assert "visit" not in other.reason("health from people/maya/health/visit.txt")
    assert other.reason("some plugin note") == "a safety check from a plugin"


def test_files_refused_are_listed(cfg):
    qid = "0000000000ee"
    write_events(cfg, "maya", qid, [
        QUESTION,
        {"step": "tool", "t": 1, "name": "read_file", "arguments": {"path": "people/dana/health/visit_2026_09_14.txt"},
         "ok": True, "provider": "FileTools"},
        {"step": "answer", "t": 2, "outcome": "pass", "held": 0, "files_read": 0, "files_denied": 1, "seconds": 2}])
    audit = cfg.runtime / "audit" / "maya.jsonl"
    audit.parent.mkdir(parents=True, exist_ok=True)
    audit.write_text(json.dumps({"qid": qid, "outcome": "pass", "reasons": [], "files_read": [],
                                 "files_denied": ["people/dana/health/visit_2026_09_14.txt"],
                                 "sent_to_assistant": "I can't see that.", "held_ids": []}) + "\n")
    c, _ = sign_in(cfg, "maya")
    t = c.get(f"/activity/{qid}").text
    assert "Refused to open" in t and "The model never saw it" in t
    assert "Refused: one of Dana&#x27;s private files" in t or "Refused: one of Dana's private files" in t
    assert "visit_2026_09_14" not in t                       # Maya cannot read it, so she does not see its name


def test_list_is_newest_first_and_summaries_are_right(cfg):
    write_events(cfg, "maya", "0000000000a1", [QUESTION, {"step": "answer", "t": 1, "outcome": "held"}], age_s=100)
    write_events(cfg, "maya", "0000000000a2", [dict(QUESTION, source="cli")], age_s=5)
    (cfg.runtime / "events" / "maya" / "notaqid.jsonl").write_text("{}\n")
    out = act.list_activity(cfg, cfg.person("maya"))
    assert [s.qid for s in out] == ["0000000000a2", "0000000000a1"]
    assert out[0].status == "running" and out[0].source == "cli" and out[1].status == "held"
    assert act.list_activity(cfg, cfg.person("sam")) == []
    assert len(act.list_activity(cfg, cfg.person("dana"))) == 2


# --- review fixes --------------------------------------------------------------------------------

def test_own_page_does_not_name_other_peoples_health_files(cfg):
    sam = act.View(cfg, cfg.person("sam"), "sam")
    for reason in ("another person's health from people/maya/health/therapy_notes.txt",
                   "tripwire FBX-AB12 from people/dana/health/x.txt",
                   "health from people/maya/health/therapy_notes.txt"):
        out = sam.reason(reason)
        assert "people/" not in out and "therapy_notes" not in out, out
    assert "someone else's a" not in sam.reason("another person's ssn from people/maya/ids/ssn_card_maya.txt")
    assert "someone else's Social Security number" in sam.reason(
        "another person's ssn from people/maya/ids/ssn_card_maya.txt")
    assert sam.path("people/nobody/x.txt") == "a private file"
    assert "their's" not in sam.path("people/nobody/x.txt")
    assert sam.path("shared/house/car.txt").startswith("<code")

    qid = "0000000000f1"
    write_events(cfg, "sam", qid, [QUESTION, {"step": "answer", "t": 1, "outcome": "refused", "held": 0,
                                              "files_read": 0, "files_denied": 1, "seconds": 1}])
    audit = cfg.runtime / "audit" / "sam.jsonl"
    audit.parent.mkdir(parents=True, exist_ok=True)
    audit.write_text(json.dumps({"qid": qid, "outcome": "refused", "files_read": [],
                                 "files_denied": ["people/maya/health/therapy_notes.txt"],
                                 "reasons": ["another person's health from people/maya/health/therapy_notes.txt"],
                                 "sent_to_assistant": "Blocked.", "held_ids": []}) + "\n")
    c, _ = sign_in(cfg, "sam")
    t = c.get(f"/activity/{qid}").text
    assert "people/maya/health" not in t and "therapy_notes" not in t
    assert "health detail" not in t


def test_kind_words_have_one_article():
    assert act.kind_word("health") == "a health detail" and act.kind_word("id") == "an ID number"
    assert act.kind_noun("ssn") == "Social Security number"


def test_denied_read_is_recorded_in_the_event(cfg):
    from familybox.box import Question

    box = Box(cfg, mode="replay")
    sam = cfg.person("sam")
    ctx = Question(box, sam, "q", "cli", "0000000000f2")
    out = box.run_tool(sam, "read_file", {"path": "people/maya/health/records_maya_fhir.json"}, ctx, {"read_file"})
    assert "not yours" in out
    ev = ctx.events[-1]
    assert ev["step"] == "tool" and ev["denied"] is True and ev["ok"] is False
    ok = box.run_tool(sam, "read_file", {"path": ctx.files_denied[0].replace("maya/health/records_maya_fhir.json",
                                                                              "sam/nothing.txt")}, ctx, {"read_file"})
    assert ok and ctx.events[-1].get("denied") is True       # a missing file is refused the same way


def test_running_question_shows_a_denied_read_as_refused(cfg):
    qid = "0000000000f3"
    write_events(cfg, "sam", qid, [QUESTION, {"step": "tool", "t": 1, "name": "read_file",
                                              "arguments": {"path": "people/maya/health/x.txt"},
                                              "ok": False, "denied": True, "why": "not yours"}])
    c, _ = sign_in(cfg, "sam")
    live = c.get(f"/activity/{qid}/live").json()
    assert live["status"] == "running"
    assert "Refused to open" in live["html"] and "Opened" not in live["html"]
    assert "people/maya" not in live["html"]


def test_a_crash_after_the_first_step_shows_did_not_finish(cfg, monkeypatch):
    from familybox.box import Question

    async def half(self, person_id, question, *, source="cli", qid=None):
        Question(self, self.cfg.person(person_id), question, source, qid).emit("question", source=source,
                                                                                 mode="replay", chars=1)
        raise KeyError("bad replay file")
    monkeypatch.setattr(Box, "ask_async", half)
    c, token = sign_in(cfg, "maya")
    qid = qid_of(ask(c, token, ALLERGY_Q))
    live = c.get(f"/activity/{qid}/live").json()
    assert live["status"] == "unfinished" and "Working..." not in live["html"]
    assert "internal problem" in live["html"] and "bad replay file" not in live["html"]
    # Stored on disk too, so a fresh server (no memory of the crash) says the same.
    path = cfg.runtime / "events" / "maya" / f"{qid}.jsonl"
    assert act.status_of(act.read_events(path), time.time()) == "unfinished"
    [s] = act.list_activity(cfg, cfg.person("maya"))
    assert s.status == "unfinished"


def test_times_name_their_zone_and_can_be_localized(cfg):
    out = act.when_html(1_790_000_000)
    assert 'data-ts="1790000000"' in out and out.startswith('<time class="fb-time"')
    import datetime as dt
    zone = dt.datetime.fromtimestamp(1_790_000_000).astimezone().tzname()
    assert act.when(1_790_000_000).endswith(zone)
    assert "Live updates stopped. Reload the page." in plugin.JS and "r.status === 401" in plugin.JS


def test_source_labels_keep_the_assistant_name_from_the_handshake():
    from familybox import activity as act
    assert act.source_short("mcp-remote:openai-mcp") == "Web assistant (ChatGPT)"
    assert act.source_short("mcp-stdio") == "Assistant app"
    assert act.source_label("mcp-stdio:claude-ai").endswith("which said it is Claude")
    assert act.source_short("mcp-http-local:some-tool") == "Local assistant (some-tool)"


def test_answer_text_is_escaped_before_bold_and_bullets():
    from familybox.activity import answer_html
    out = answer_html("- **Dose** <script>x</script>\nplain - text")
    assert out == "• <strong>Dose</strong> &lt;script&gt;x&lt;/script&gt;\nplain - text"


def test_a_code_change_stop_tells_people_what_to_do(cfg):
    events = [{"step": "question", "source": "web", "mode": "live", "t": 0},
              {"step": "pinning", "status": "waiting_review", "component": "gateway", "review": "abc123", "t": 0},
              {"step": "pre_check_stopped", "message": "NEAR changed its serving code", "t": 0}]
    audit = {"sent_to_assistant": "The family box stopped this question.", "outcome": "error"}
    admin = act.render_detail(act.View(cfg, cfg.person("dana"), "dana"), events, audit, "error")
    assert '<a class="fb-go" href="/pins">Review the change</a>' in admin
    assert "Step: pinning" not in admin and "front door" in admin
    other = act.render_detail(act.View(cfg, cfg.person("sam"), "sam"), events, audit, "error")
    assert 'href="/pins"' not in other and "Ask Dana to open" in other
    fine = act.render_detail(act.View(cfg, cfg.person("dana"), "dana"),
                             [events[0], {"step": "pinning", "status": "match", "component": "model/x", "t": 1}],
                             None, "running")
    assert "matches the approved version" in fine and "fb-go" not in fine
