"""Fill forms on the box: references, access, the PDF, what the assistant sees, approvals, download."""

import asyncio
import dataclasses
import json
import re
import shutil
import stat
from io import BytesIO
from pathlib import Path

import pytest
from pypdf import PdfReader
from starlette.testclient import TestClient

from familybox import access, config, formfill, gate, web
from familybox.approvals import Approvals
from familybox.store import Store

DEMO = Path(__file__).resolve().parents[1] / "demo"
FULL_VALUES = ["987-65-4320", "987-65-4321", "987-65-4322", "X10483921", "X20577143", "2010-04-17", "1983-09-12",
               "BPF448812093", "MRN-5521907", "45,900.00", "96,410.00", "134,250.00", "Penicillin", "Peanuts",
               "asthma", "Albuterol", "sertraline", "77120"]

AID = {"student_name": "{{maya.name}}", "student_ssn": "{{maya.ssn}}", "student_date_of_birth": "{{maya.date_of_birth}}",
       "school_year": "2027-28", "parent1_name": "{{dana.name}}", "parent1_ssn": "{{dana.ssn}}",
       "parent1_wages": "{{dana.w2_wages}}", "parent2_name": "{{sam.name}}", "parent2_ssn": "{{sam.ssn}}",
       "parent2_wages": "{{sam.w2_wages}}", "household_agi": "{{dana.agi}}", "household_size": "3"}


@pytest.fixture
def cfg(tmp_path, monkeypatch):
    home = tmp_path / "home"
    shutil.copytree(DEMO / "files", home / "files")
    shutil.copytree(DEMO / "forms", home / "forms")
    shutil.copy(DEMO / "family.toml", home / "family.toml")
    monkeypatch.delenv("NEAR_AI_CLOUD_API_KEY", raising=False)
    monkeypatch.delenv("NEARAI_API_KEY", raising=False)
    monkeypatch.setenv("FAMILYBOX_HOME", str(home))
    c = config.load(home)
    Store(c).reindex()
    return c


def with_people(cfg, **changes) -> config.Config:
    people = dict(cfg.people)
    for pid, kw in changes.items():
        people[pid] = dataclasses.replace(people[pid], **kw)
    return dataclasses.replace(cfg, people=people)


def pdf_fields(data: bytes) -> dict:
    return PdfReader(BytesIO(data)).get_form_text_fields()


def gate_outcome(cfg, person_id: str, text: str) -> str:
    store = Store(cfg)
    person = cfg.person(person_id)
    return gate.check(text, sensitive=store.sensitive_values(),
                      readable_owners=set(access.readable_owners(cfg, person)), never_share=list(person.never_share),
                      display={p.id: p.display for p in cfg.people.values()},
                      common_words=store.nonhealth_words()).outcome


def no_full_values(text: str) -> None:
    norm = gate.normalize(text)
    for v in FULL_VALUES:
        assert gate.normalize(v) not in norm, v


def approve_all(cfg, res):
    for o in res.approvers:
        formfill.decide(cfg, o, res.form_id, True)


# --- templates ----------------------------------------------------------------------------------

def test_demo_templates_are_listed_with_fields_and_hints(cfg):
    ts = {t.slug: t for t in formfill.list_templates(cfg)}
    assert set(ts) == {"student_aid_info", "sports_medical"}
    assert "student_ssn" in ts["student_aid_info"].fields and "allergies" in ts["sports_medical"].fields
    assert ts["student_aid_info"].fields["student_ssn"]["hint"] == "{{<student>.ssn}}"
    text = formfill.describe_templates(cfg)
    assert "{{maya.ssn}}" in text and "practice form" in text and "\u2014" not in text
    assert formfill.find_template(cfg, "Student Aid Information (practice form)").slug == "student_aid_info"
    with pytest.raises(formfill.FormError, match="no form called"):
        formfill.find_template(cfg, "../files/people/dana/ids/ssn_card_dana")


def test_generator_script_makes_fillable_pdfs(tmp_path):
    import runpy
    mod = runpy.run_path(str(DEMO.parent / "scripts" / "make_demo_forms.py"))
    assert mod["main"]([str(tmp_path)]) == 0
    r = PdfReader(tmp_path / "sports_medical.pdf")
    assert "allergies" in r.get_fields() and "FICTIONAL" in r.pages[0].extract_text()


# --- resolving and filling ----------------------------------------------------------------------

def test_parent_fills_student_aid_form_with_real_values_in_pdf(cfg):
    res = formfill.fill(cfg, "dana", "student_aid_info", "maya", AID)
    assert res.approvers == ["dana", "maya", "sam"] and res.recipients == ["dana"]
    path = formfill.pdf_path(cfg, res.form_id)
    assert stat.S_IMODE(path.stat().st_mode) == 0o600
    assert stat.S_IMODE(path.parent.stat().st_mode) == 0o700
    got = pdf_fields(path.read_bytes())
    assert got["student_ssn"] == "987-65-4322" and got["parent1_ssn"] == "987-65-4320"
    assert got["parent2_ssn"] == "987-65-4321" and got["student_date_of_birth"] == "2010-04-17"
    assert got["student_name"] == "Maya Okafor" and got["parent2_name"] == "Sam Okafor"
    assert got["parent1_wages"] == "96,410.00" and got["parent2_wages"] == "45,900.00"
    assert got["household_agi"] == "134,250.00" and got["school_year"] == "2027-28"
    assert got["student_email"] is None


def test_assistant_only_sees_masked_summary_that_passes_the_gate(cfg):
    res = formfill.fill(cfg, "dana", "student_aid_info", "maya", AID)
    assert "SSN ending 4322" in res.text and "SSN ending 4320" in res.text and "SSN ending 4321" in res.text
    assert res.form_id in res.text and "Dana can download" in res.text
    no_full_values(res.text)
    assert gate_outcome(cfg, "dana", res.text) == "pass"
    assert "\u2014" not in res.text


def test_teen_fills_own_sports_form_with_health_and_family_insurance(cfg):
    fields = {"athlete_name": "{{maya.name}}", "athlete_date_of_birth": "{{Maya.dob}}",
              "allergies": "{{maya.allergies}}", "conditions": "{{maya.conditions}}",
              "medications": "{{maya.medications}}", "medical_record_number": "{{maya.mrn}}",
              "insurance_plan": "{{family.insurance_plan}}", "insurance_member_id": "{{family.insurance_member_id}}",
              "insurance_group_number": "{{ family.group_number }}", "sport": "Soccer (varsity) \\ fall",
              "emergency_contact_name": "{{dana.name}}"}
    with pytest.raises(formfill.FormError, match="emergency_contact_name"):
        formfill.fill(cfg, "maya", "sports_medical", "maya", fields)   # Maya can't read Dana's files
    fields["emergency_contact_name"] = "Dana Okafor (mom)"
    fields["emergency_contact_phone"] = "512-555-0142"
    res = formfill.fill(cfg, "maya", "sports_medical", "maya", fields)
    assert res.approvers == ["maya"] and res.recipients == ["maya"]
    got = pdf_fields(formfill.pdf_path(cfg, res.form_id).read_bytes())
    assert got["allergies"] == "Penicillin; Peanuts"
    assert got["conditions"] == "Exercise-induced asthma" and got["medications"] == "Albuterol inhaler"
    assert got["medical_record_number"] == "MRN-5521907" and got["athlete_date_of_birth"] == "2010-04-17"
    assert got["insurance_member_id"] == "BPF448812093" and got["insurance_group_number"] == "77120"
    assert got["insurance_plan"] == "Bluepoint Family PPO" and got["sport"] == "Soccer (varsity) \\ fall"
    no_full_values(res.text)
    assert gate_outcome(cfg, "maya", res.text) == "pass"
    assert "insurance member ID ending 093" in res.text


def test_references_can_be_mixed_with_text(cfg):
    res = formfill.fill(cfg, "dana", "student_aid_info", "maya",
                        {"parent1_name": "{{dana.name}} and {{sam.name}}"})
    assert pdf_fields(formfill.pdf_path(cfg, res.form_id).read_bytes())["parent1_name"] == "Dana Okafor and Sam Okafor"
    assert "your text with Dana's full name" in res.text


# --- access -------------------------------------------------------------------------------------

def test_teen_cannot_reference_a_parents_ssn(cfg):
    with pytest.raises(formfill.FormError) as e:
        formfill.fill(cfg, "maya", "student_aid_info", "maya",
                      {"student_ssn": "{{maya.ssn}}", "parent1_ssn": "{{dana.ssn}}"})
    assert "{{dana.ssn}}" in str(e.value) and "isn't in files Maya may read" in str(e.value)
    no_full_values(str(e.value))
    # Nothing was made: no PDF, no approval item.
    assert not list((cfg.runtime / "forms").glob("*.pdf"))
    assert Approvals(cfg).pending("dana") == [] and Approvals(cfg).pending("maya") == []


def test_parent_cannot_reference_a_teens_health_record(cfg):
    with pytest.raises(formfill.FormError, match=r"\{\{maya.allergies\}\}"):
        formfill.fill(cfg, "dana", "sports_medical", "maya", {"allergies": "{{maya.allergies}}"})


def test_allowed_when_the_household_grants_access(cfg):
    granted = with_people(cfg, maya={"also_reads": ("people/dana/ids",)})
    res = formfill.fill(granted, "maya", "student_aid_info", "maya", {"parent1_ssn": "{{dana.ssn}}"})
    assert pdf_fields(formfill.pdf_path(granted, res.form_id).read_bytes())["parent1_ssn"] == "987-65-4320"
    assert res.approvers == ["dana"]


def test_missing_and_forbidden_look_the_same(cfg):
    msg_forbidden = msg_missing = ""
    try:
        formfill.fill(cfg, "maya", "student_aid_info", "maya", {"parent1_ssn": "{{dana.ssn}}"})
    except formfill.FormError as e:
        msg_forbidden = str(e).replace("dana.ssn", "X")
    try:
        formfill.fill(cfg, "maya", "student_aid_info", "maya", {"parent1_ssn": "{{maya.w2_wages}}"})
    except formfill.FormError as e:
        msg_missing = str(e).replace("maya.w2_wages", "X")
    assert msg_forbidden and msg_forbidden == msg_missing


def test_typed_text_check_does_not_reveal_stored_values(cfg):
    # Typing a real allergy or a made-up one gives the same result, so typing can't test a guess.
    a = formfill.fill(cfg, "dana", "sports_medical", "maya", {"allergies": "Penicillin"})
    b = formfill.fill(cfg, "dana", "sports_medical", "maya", {"allergies": "Shellfish"})
    assert a.text.replace(a.form_id, "") == b.text.replace(b.form_id, "")
    # Real and made-up ID numbers are refused the same way.
    msgs = []
    for guess in ("X10483921", "X10483922"):
        with pytest.raises(formfill.FormError) as e:
            formfill.fill(cfg, "maya", "student_aid_info", "maya", {"student_email": guess})
        msgs.append(str(e.value))
    assert msgs[0] == msgs[1]
    ok = formfill.fill(cfg, "maya", "sports_medical", "maya",
                       {"emergency_contact_phone": "(512) 555-0142", "grade": "10th", "sport": "maya2010@example.com"})
    assert ok.filled == ["sport", "grade", "emergency_contact_phone"]


def test_nobody_could_receive_a_mixed_form(cfg):
    # Without Sam reading Maya's IDs, neither Maya nor Sam may see each other's details.
    c = with_people(cfg, sam={"also_reads": ("people/dana/taxes",)})
    with pytest.raises(formfill.FormError, match="separate parts"):
        formfill.fill(c, "dana", "student_aid_info", "maya",
                      {"student_ssn": "{{maya.ssn}}", "parent2_ssn": "{{sam.ssn}}"})


@pytest.mark.parametrize("fields,match", [
    ({"student_ssn": "987-65-4320"}, "typed-in text"),          # someone else's known SSN
    ({"student_ssn": "987 65 4322"}, "typed-in text"),          # the asker's own SSN, typed
    ({"student_ssn": "123-45-6789"}, "typed-in text"),          # any SSN-shaped number
    ({"student_ssn": "123456789"}, "typed-in text"),
    ({"student_email": "card 4111 1111 1111 1111"}, "typed-in text"),
    ({"student_email": "MRN-5521907"}, "typed-in text"),
    ({"student_email": "X10483921"}, "typed-in text"),          # a known passport number
    ({"nope": "x"}, "no such field"),
    ({"student_ssn": "{{maya.shoe_size}}"}, "unknown detail"),
    ({"student_ssn": "{{grandma.ssn}}"}, "nobody called"),
    ({"student_ssn": "{{maya.ssn"}, "must look like"),
    ({"student_ssn": "{{maya}}"}, "must look like"),
    ({"student_ssn": "x" * 301}, "too long"),
    ({"student_ssn": ["{{maya.ssn}}"]}, "must be text"),
    ({"student_ssn": "   "}, "Nothing to fill"),
    ({}, "at least one field"),
])
def test_bad_fields_are_refused_with_nothing_made(cfg, fields, match):
    with pytest.raises(formfill.FormError, match=match) as e:
        formfill.fill(cfg, "dana", "student_aid_info", "maya", fields)
    no_full_values(str(e.value))
    assert not list((cfg.runtime / "forms").glob("*.pdf"))


def test_unknown_for_person_and_form(cfg):
    with pytest.raises(formfill.FormError, match="nobody called"):
        formfill.fill(cfg, "dana", "student_aid_info", "grandma", {"school_year": "2027-28"})
    with pytest.raises(formfill.FormError, match="no form called"):
        formfill.fill(cfg, "dana", "w9", "maya", {"school_year": "2027-28"})


def test_only_owners_receive_the_pdf(cfg):
    # Dana filled it, but only Maya's details are in it: Maya approves and Maya downloads.
    res = formfill.fill(cfg, "dana", "student_aid_info", "maya", {"student_ssn": "{{maya.ssn}}"})
    assert res.approvers == ["maya"] and res.recipients == ["maya"] and "Maya can download" in res.text
    approve_all(cfg, res)
    with pytest.raises(PermissionError, match="isn't yours"):
        formfill.download(cfg, "dana", res.form_id)
    assert pdf_fields(formfill.download(cfg, "maya", res.form_id)[1])["student_ssn"] == "987-65-4322"


def test_text_only_form_needs_the_askers_own_approval(cfg):
    res = formfill.fill(cfg, "sam", "student_aid_info", "maya", {"school_year": "2027-28"})
    assert res.approvers == ["sam"] and res.recipients == ["sam"]


# --- approval before download -------------------------------------------------------------------

def test_download_needs_every_owner_to_approve(cfg):
    res = formfill.fill(cfg, "dana", "student_aid_info", "maya", AID)
    with pytest.raises(PermissionError, match="not approved"):
        formfill.download(cfg, "dana", res.form_id)
    formfill.decide(cfg, "dana", res.form_id, True)
    formfill.decide(cfg, "maya", res.form_id, True)
    with pytest.raises(PermissionError, match="not approved"):
        formfill.download(cfg, "dana", res.form_id)
    with pytest.raises(KeyError):
        formfill.decide(cfg, "maya", res.form_id, True)          # can't approve twice
    with pytest.raises(KeyError):
        formfill.decide(cfg, "maya", "nosuchform", True)
    formfill.decide(cfg, "sam", res.form_id, True)
    with pytest.raises(PermissionError, match="isn't yours"):
        formfill.download(cfg, "maya", res.form_id)               # Maya may not see her parents' SSNs
    name, data = formfill.download(cfg, "dana", res.form_id)
    assert name.endswith(".pdf") and pdf_fields(data)["student_ssn"] == "987-65-4322"
    log = (cfg.runtime / "audit" / "dana.jsonl").read_text()
    assert '"form_download"' in log and '"form_fill"' in log
    no_full_values(log)


def test_core_approvals_page_items_count_too(cfg):
    res = formfill.fill(cfg, "maya", "sports_medical", "maya", {"allergies": "{{maya.allergies}}"})
    items = Approvals(cfg).pending("maya")
    assert len(items) == 1 and items[0]["kind"] == "form" and "allergies" in items[0]["question"]
    out = Approvals(cfg).decide("maya", items[0]["id"], True)
    no_full_values(json.dumps(out))
    assert formfill.download(cfg, "maya", res.form_id)[1].startswith(b"%PDF")
    no_full_values((cfg.runtime / "approvals.json").read_text())
    no_full_values((cfg.runtime / "forms" / "index.json").read_text())


def test_deny_deletes_the_pdf_and_closes_the_others(cfg):
    res = formfill.fill(cfg, "dana", "student_aid_info", "maya", AID)
    formfill.decide(cfg, "dana", res.form_id, True)
    formfill.decide(cfg, "maya", res.form_id, False)
    assert not formfill.pdf_path(cfg, res.form_id).exists()
    assert Approvals(cfg).pending("sam") == []
    with pytest.raises(PermissionError, match="denied"):
        formfill.download(cfg, "dana", res.form_id)


def test_forms_expire_after_a_week(cfg, monkeypatch):
    res = formfill.fill(cfg, "maya", "sports_medical", "maya", {"allergies": "{{maya.allergies}}"})
    approve_all(cfg, res)
    real = formfill.time.time()
    monkeypatch.setattr(formfill.time, "time", lambda: real + formfill.FORM_TTL_S + 5)
    with pytest.raises(PermissionError, match="expired"):
        formfill.download(cfg, "maya", res.form_id)
    assert not formfill.pdf_path(cfg, res.form_id).exists()


def test_delete_and_revoked_access(cfg):
    res = formfill.fill(cfg, "dana", "student_aid_info", "maya", {"student_ssn": "{{maya.ssn}}",
                                                                  "parent1_ssn": "{{dana.ssn}}"})
    approve_all(cfg, res)
    revoked = with_people(cfg, dana={"also_reads": ()})
    with pytest.raises(PermissionError, match="no longer"):
        formfill.download(revoked, "dana", res.form_id)
    with pytest.raises(KeyError):
        formfill.delete(cfg, "sam", res.form_id)                  # not Sam's form
    formfill.delete(cfg, "maya", res.form_id)
    assert not formfill.pdf_path(cfg, res.form_id).exists()
    with pytest.raises(PermissionError, match="deleted"):
        formfill.download(cfg, "dana", res.form_id)


def test_form_ids_are_letters_only(cfg):
    with pytest.raises(KeyError):
        formfill.pdf_path(cfg, "../../files/people/dana/ids/x")
    res = formfill.fill(cfg, "maya", "sports_medical", "maya", {"sport": "soccer"})
    assert re.fullmatch(r"[a-z]{10}", res.form_id)


# --- MCP, CLI, web ------------------------------------------------------------------------------

def test_mcp_tools_return_only_masked_text(cfg):
    from familybox import mcp_server
    server = mcp_server.build_server("dana", "replay")

    async def go():
        names = [t.name for t in await server.list_tools()]
        listing = await server.call_tool("list_family_forms", {})
        ok = await server.call_tool("fill_family_form", {"form": "student_aid_info", "for_person": "Maya",
                                                         "fields": AID})
        bad = await server.call_tool("fill_family_form", {"form": "sports_medical", "for_person": "maya",
                                                          "fields": {"allergies": "{{maya.allergies}}"}})
        return names, listing, ok, bad
    names, listing, ok, bad = asyncio.run(go())
    assert {"list_family_forms", "fill_family_form"} <= set(names)
    text = ok.content[0].text
    assert "SSN ending 4322" in text and gate_outcome(cfg, "dana", text) == "pass"
    no_full_values(text)
    assert "not filled" in bad.content[0].text
    assert "sports_medical" in listing.content[0].text


def test_cli_list_fill_mine_approve_download(cfg, capsys, tmp_path):
    from familybox import cli
    assert cli.main(["forms", "list"]) == 0
    assert "student_aid_info" in capsys.readouterr().out
    assert cli.main(["forms", "fill", "--as", "dana", "--for", "maya", "student_aid_info",
                     json.dumps({"student_ssn": "{{maya.ssn}}", "parent1_ssn": "{{dana.ssn}}"})]) == 0
    out = capsys.readouterr().out
    assert "SSN ending 4322" in out
    no_full_values(out)
    fid = re.search(r"form id ([a-z]{10})", out).group(1)
    assert cli.main(["forms", "fill", "--as", "maya", "student_aid_info", '{"parent1_ssn": "{{dana.ssn}}"}']) == 1
    assert cli.main(["forms", "fill", "--as", "maya", "student_aid_info", "not json"]) == 2
    capsys.readouterr()
    assert cli.main(["forms", "download", "--as", "dana", fid, str(tmp_path / "a.pdf")]) == 1
    assert "not approved" in capsys.readouterr().err
    assert cli.main(["forms", "mine", "--as", "maya"]) == 0
    assert fid in capsys.readouterr().out
    assert cli.main(["forms", "approve", "--as", "maya", fid]) == 0
    assert "Still waiting" in capsys.readouterr().out
    assert cli.main(["forms", "approve", "--as", "dana", fid]) == 0
    assert "Everyone has approved" in capsys.readouterr().out
    out_pdf = tmp_path / "a.pdf"
    assert cli.main(["forms", "download", "--as", "dana", fid, str(out_pdf)]) == 0
    assert stat.S_IMODE(out_pdf.stat().st_mode) == 0o600
    assert pdf_fields(out_pdf.read_bytes())["student_ssn"] == "987-65-4322"
    assert cli.main(["forms", "download", "--as", "dana", fid, str(out_pdf)]) == 1   # never overwrites


def _web_sign_in(cfg, person):
    c = TestClient(web.create_app(cfg), base_url="https://testserver")
    code = web.issue_code(cfg, person)
    tok = re.search(r'name="csrf" value="([^"]+)"', c.get("/signin").text).group(1)
    assert c.post("/signin", data={"code": code, "csrf": tok}, follow_redirects=False).status_code == 303
    return c, re.search(r'name="csrf" value="([^"]+)"', c.get("/").text).group(1)


def test_web_forms_page_approve_then_download(cfg):
    res = formfill.fill(cfg, "dana", "student_aid_info", "maya", {"student_ssn": "{{maya.ssn}}",
                                                                  "parent1_ssn": "{{dana.ssn}}"})
    anon = TestClient(web.create_app(cfg), base_url="https://testserver")
    assert anon.get("/forms", follow_redirects=False).status_code == 303
    assert anon.post(f"/forms/{res.form_id}/download").status_code == 403

    dana, dtok = _web_sign_in(cfg, "dana")
    page = dana.get("/forms")
    assert page.status_code == 200 and 'href="/forms"' in page.text and res.form_id in page.text
    no_full_values(page.text)
    assert "SSN ending 4322" in page.text
    assert dana.post(f"/forms/{res.form_id}/download", data={"csrf": dtok}).status_code == 403   # not approved
    assert dana.post(f"/forms/{res.form_id}/approve", data={"csrf": "wrong"}).status_code == 403
    assert dana.post(f"/forms/{res.form_id}/approve", data={"csrf": dtok}).status_code == 200
    assert dana.get(f"/forms/{res.form_id}/download").status_code == 405

    maya, mtok = _web_sign_in(cfg, "maya")
    assert "Approvals (1)" in maya.get("/forms").text
    assert maya.post(f"/forms/{res.form_id}/approve", data={"csrf": mtok}).status_code == 200
    r = maya.post(f"/forms/{res.form_id}/download", data={"csrf": mtok})
    assert r.status_code == 403 and not r.content.startswith(b"%PDF")       # Maya isn't the recipient

    r = dana.post(f"/forms/{res.form_id}/download", data={"csrf": dtok},
                  headers={"origin": "https://evil.example"})
    assert r.status_code == 403
    r = dana.post(f"/forms/{res.form_id}/download", data={"csrf": dtok})
    assert r.status_code == 200 and r.headers["content-type"] == "application/pdf"
    assert "attachment" in r.headers["content-disposition"] and r.headers["cache-control"] == "no-store"
    assert pdf_fields(r.content)["parent1_ssn"] == "987-65-4320"
    assert dana.post(f"/forms/{res.form_id}/bogus", data={"csrf": dtok}).status_code == 404


# --- review fixes -------------------------------------------------------------------------------

def test_approvers_only_see_masks_of_files_they_may_read(cfg, capsys):
    from familybox import cli
    res = formfill.fill(cfg, "dana", "student_aid_info", "maya",
                        {"student_ssn": "{{maya.ssn}}", "parent1_ssn": "{{dana.ssn}}", "parent2_ssn": "{{sam.ssn}}",
                         "parent1_wages": "{{dana.w2_wages}}"})
    assert "maya" in res.approvers and res.recipients == ["dana"]
    rows = formfill.forms_for(cfg, "maya")
    text = json.dumps(rows)
    assert "4320" not in text and "4321" not in text and "refs" not in rows[0] and "sources" not in rows[0]
    assert "parent1_ssn: Dana's SSN (hidden)" in rows[0]["fields"]
    assert "student_ssn: your SSN ending 4322" in rows[0]["fields"]
    dana_lines = formfill.forms_for(cfg, "dana")[0]["fields"]
    assert "parent1_ssn: your SSN ending 4320" in dana_lines and "parent2_ssn: Sam's SSN ending 4321" in dana_lines

    maya, _ = _web_sign_in(cfg, "maya")
    page = maya.get("/forms").text
    assert res.form_id in page and "4320" not in page and "4321" not in page and "(hidden)" in page
    assert cli.main(["forms", "mine", "--as", "maya"]) == 0
    out = capsys.readouterr().out
    assert res.form_id in out and "4320" not in out and "4321" not in out


def test_approval_question_maps_fields_and_held_text_fits_the_owner(cfg, capsys):
    from familybox import cli
    res = formfill.fill(cfg, "dana", "student_aid_info", "maya",
                        {"student_ssn": "{{maya.ssn}}", "parent1_ssn": "{{dana.ssn}}"})
    item = Approvals(cfg).pending("maya")[0]
    assert "student_ssn gets your SSN ending 4322" in item["question"]
    assert "4320" not in item["question"] and "Dana can download it" in item["question"]
    data = Approvals(cfg)._load()
    assert data[f"form-{res.form_id}-maya"]["value"].startswith("Approved. Dana can download it")
    assert data[f"form-{res.form_id}-dana"]["value"].startswith("Approved. Download it")
    assert cli.main(["forms", "approve", "--as", "dana", res.form_id]) == 0
    capsys.readouterr()
    assert cli.main(["forms", "approve", "--as", "maya", res.form_id]) == 0
    out = capsys.readouterr().out
    assert "Dana can download" in out and "you can download" not in out


def test_reference_must_fit_the_field_kind(cfg):
    with pytest.raises(formfill.FormError, match="student_name: this field doesn't take a SSN"):
        formfill.fill(cfg, "maya", "student_aid_info", "maya", {"student_name": "{{maya.ssn}}"})
    with pytest.raises(formfill.FormError, match="school_year"):
        formfill.fill(cfg, "maya", "student_aid_info", "maya", {"school_year": "{{maya.date_of_birth}}"})
    assert not list((cfg.runtime / "forms").glob("*.pdf"))


def test_expired_and_orphaned_pdfs_are_swept_without_anyone_looking(cfg):
    from familybox import plugins
    from familybox.box import Box
    old = formfill.fill(cfg, "maya", "sports_medical", "maya", {"allergies": "{{maya.allergies}}"})
    new = formfill.fill(cfg, "maya", "sports_medical", "maya", {"allergies": "{{maya.allergies}}"})
    d = cfg.runtime / "forms"
    orphan = d / "orphanpdfx.pdf"
    orphan.write_bytes(b"%PDF-1.4 left over")
    with formfill._locked(cfg):
        data = formfill._load(cfg)
        data[old.form_id]["created"] -= formfill.FORM_TTL_S + 60
        formfill._save(cfg, data)
    Box(cfg)                                                   # box start runs the sweep
    assert not orphan.exists() and not formfill.pdf_path(cfg, old.form_id).exists()
    assert formfill.pdf_path(cfg, new.form_id).exists()
    assert Approvals(cfg)._load()[f"form-{old.form_id}-maya"]["status"] == "denied"
    assert plugins  # imported for the side effect of loading the forms plugin


def test_damaged_index_is_moved_aside_and_its_pdfs_removed(cfg):
    res = formfill.fill(cfg, "maya", "sports_medical", "maya", {"allergies": "{{maya.allergies}}"})
    idx = cfg.runtime / "forms" / "index.json"
    idx.write_text("{ not json")
    formfill.sweep(cfg)
    aside = list(idx.parent.glob("index.damaged-*.json"))
    assert len(aside) == 1 and aside[0].read_text() == "{ not json"
    assert stat.S_IMODE(aside[0].stat().st_mode) == 0o600
    assert not formfill.pdf_path(cfg, res.form_id).exists()
    assert Approvals(cfg).pending("maya") == []                # its approval can't lead anywhere: closed
    idx.write_text("[1, 2]")
    assert formfill.forms_for(cfg, "maya") == [] and len(list(idx.parent.glob("index.damaged-*.json"))) == 2


def test_too_many_waiting_forms_are_refused(cfg, monkeypatch):
    for _ in range(formfill.MAX_WAITING):
        formfill.fill(cfg, "maya", "sports_medical", "maya", {"allergies": "{{maya.allergies}}"})
    with pytest.raises(formfill.FormError, match="Too many forms are waiting"):
        formfill.fill(cfg, "maya", "sports_medical", "maya", {"allergies": "{{maya.allergies}}"})
    assert len(list((cfg.runtime / "forms").glob("*.pdf"))) == formfill.MAX_WAITING
    formfill.fill(cfg, "dana", "student_aid_info", "dana", {"parent1_ssn": "{{dana.ssn}}"})   # others unaffected
    more = formfill.MAX_FILLS_PER_HOUR - formfill.MAX_WAITING
    monkeypatch.setattr(formfill, "MAX_WAITING", 100)
    for _ in range(more):
        formfill.fill(cfg, "maya", "sports_medical", "maya", {"allergies": "{{maya.allergies}}"})
    with pytest.raises(formfill.FormError, match="in the last hour"):
        formfill.fill(cfg, "maya", "sports_medical", "maya", {"allergies": "{{maya.allergies}}"})


@pytest.mark.parametrize("side", ["[1, 2]", '{"fields": [1]}', '{"fields": {"allergies": "x"}}', "not json"])
def test_odd_sidecar_does_not_break_the_list(cfg, side):
    (cfg.home / "forms" / "sports_medical.json").write_text(side)
    ts = {t.slug: t for t in formfill.list_templates(cfg)}
    assert set(ts) == {"student_aid_info", "sports_medical"}
    assert ts["sports_medical"].fields["allergies"] == {"label": "allergies", "hint": "", "kinds": None}


def test_mcp_fill_hides_unexpected_errors(cfg, monkeypatch):
    from familybox import mcp_server

    def boom(*a, **k):
        raise OSError("disk path /secret/thing")
    monkeypatch.setattr(formfill, "fill", boom)
    server = mcp_server.build_server("dana", "replay")
    got = asyncio.run(server.call_tool("fill_family_form", {"form": "x", "for_person": "dana", "fields": {"a": "b"}}))
    assert got.content[0].text == "The box couldn't fill that form. Ask the person who runs the box to check it."


def test_approvals_and_audit_files_are_private(cfg):
    formfill.fill(cfg, "maya", "sports_medical", "maya", {"allergies": "{{maya.allergies}}"})
    assert stat.S_IMODE((cfg.runtime / "approvals.json").stat().st_mode) == 0o600
    assert stat.S_IMODE((cfg.runtime / "audit" / "maya.jsonl").stat().st_mode) == 0o600


def test_concurrent_approval_writers_lose_nothing(cfg):
    import threading
    appr = Approvals(cfg)

    def add(i):
        appr.add("maya", "q", [gate.Held(f"item-{i}", "ssn", "l", "v", "maya", "p")])
    ts = [threading.Thread(target=add, args=(i,)) for i in range(20)]
    for t in ts:
        t.start()
    for t in ts:
        t.join()
    assert len(appr._load()) == 20
