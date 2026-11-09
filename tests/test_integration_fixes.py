"""Regressions for problems found in the whole-system review after the ten features were merged."""

from __future__ import annotations

import json
import shutil
from pathlib import Path

import pytest

from familybox import config
from familybox.approvals import Approvals
from familybox.box import Box, Question
from familybox.gate import Held
from familybox.plugins import paraphrase, workbench
from familybox.store import Sensitive, Store

DEMO = Path(__file__).resolve().parents[1] / "demo"


@pytest.fixture
def cfg(tmp_path, monkeypatch):
    home = tmp_path / "home"
    shutil.copytree(DEMO / "files", home / "files")
    shutil.copy(DEMO / "family.toml", home / "family.toml")
    monkeypatch.setenv("FAMILYBOX_HOME", str(home))
    monkeypatch.delenv("NEAR_AI_CLOUD_API_KEY", raising=False)
    return config.load()


def fact(owner: str, path: str) -> Sensitive:
    return Sensitive("X20577143", "id", "passport number", path, owner)


def test_whole_hold_never_goes_to_someone_who_cannot_read_the_answer(cfg):
    box = Box(cfg, mode="replay")
    dana = cfg.person("dana")
    passport = fact("maya", "people/maya/ids/passport_maya.txt")
    # Dana's answer quoted her own W-2 and Maya's passport: Maya may not read Dana's taxes, so Dana holds it.
    paths = ["people/dana/taxes/w2_2025_dana.txt", "people/maya/ids/passport_maya.txt"]
    assert paraphrase._hold_owner(box, [passport], dana, paths) == "dana"
    # Only Maya's own file was touched: Maya can read everything in it, so it is hers to approve.
    assert paraphrase._hold_owner(box, [passport], dana, ["people/maya/ids/passport_maya.txt"]) == "maya"


def test_reading_a_photo_records_its_transcript_for_the_second_check(cfg):
    photo = cfg.files / "people/maya/health/rx.png"
    photo.write_bytes(b"\x89PNG fake")
    (cfg.files / "people/maya/health/rx.png.transcript.txt").write_text("Medication: Fluoxetine 10 mg\n")
    box = Box(cfg, mode="replay")
    box.store.reindex()
    maya = cfg.person("maya")
    ctx = Question(box, maya, "q", "test")
    from familybox.box import FileTools
    assert "Fluoxetine" in FileTools(box.store).run(maya, "read_file", {"path": "people/maya/health/rx.png"}, ctx)
    paths = paraphrase.touched_paths(box, maya, ctx)
    assert "people/maya/health/rx.png.transcript.txt" in paths
    assert any("Fluoxetine" in f.value for f in paraphrase.facts_for(box, paths))


def test_workbench_gets_originals_only_for_plain_text(cfg, tmp_path):
    (cfg.files / "people/maya/health/record.json").write_text(json.dumps({"resourceType": "Patient",
                                                                          "identifier": [{"value": "ZZ998877"}]}))
    store = Store(cfg)
    store.reindex()
    dest = tmp_path / "ws"
    index = workbench.stage_workspace(cfg, store, cfg.person("maya"), dest)
    raw = {p.relative_to(dest / "files").as_posix() for p in (dest / "files").rglob("*") if p.is_file()}
    assert raw and all(Path(p).suffix in workbench.RAW_COPY_SUFFIXES for p in raw)
    assert "people/maya/health/record.json" not in raw
    entry = next(e for e in index if e["path"] == "people/maya/health/record.json")
    assert "file" not in entry and (dest / "text/people/maya/health/record.json.txt").exists()


def test_cli_approve_only_decides_waiting_items(cfg, capsys):
    from familybox import cli
    held = Held("h1", "ssn", "SSN", "987-65-4322", "maya", "people/maya/ids/ssn_card_maya.txt")
    Approvals(cfg).add("maya", "q", [held])
    assert cli.main(["deny", "--as", "maya", "h1"]) in (0, None)
    capsys.readouterr()
    assert cli.main(["approve", "--as", "maya", "h1"]) == 1          # denied stays denied
    assert "987-65-4322" not in capsys.readouterr().out


def test_activity_list_skips_photo_reads(cfg):
    from familybox import activity
    folder = cfg.runtime / "events" / "maya"
    folder.mkdir(parents=True)
    (folder / ("b" * 12 + ".jsonl")).write_text(json.dumps({"step": "photo", "t": 0}) + "\n")
    assert activity.list_activity(cfg, cfg.person("maya")) == []


def test_other_person_named_only_in_the_question_counts(cfg):
    people = cfg.people.values()
    maya = cfg.person("maya")
    q = "What does the fridge note in the shared folder say about Mom?"
    a = "Her counseling sessions switched to every other Tuesday."
    assert not paraphrase.mentions_other_person(a, maya, people)
    assert paraphrase.mentions_other_person(f"{q}\n{a}", maya, people)
