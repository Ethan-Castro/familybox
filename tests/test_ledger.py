"""Tamper-evident audit logs (familybox.ledger) and the log verify command. No network."""

import json
import shutil
import stat
import threading
from pathlib import Path

import pytest

from familybox import cli, config, ledger
from familybox.box import Box
from familybox.store import Store

DEMO = Path(__file__).resolve().parents[1] / "demo"


@pytest.fixture
def rt(tmp_path):
    return tmp_path / "runtime"


@pytest.fixture
def cfg(tmp_path, monkeypatch):
    home = tmp_path / "home"
    shutil.copytree(DEMO / "files", home / "files")
    shutil.copy(DEMO / "family.toml", home / "family.toml")
    monkeypatch.delenv("NEAR_AI_CLOUD_API_KEY", raising=False)
    monkeypatch.delenv("NEARAI_API_KEY", raising=False)
    monkeypatch.setenv("FAMILYBOX_HOME", str(home))
    c = config.load(home)
    Store(c).reindex()
    return c


def fill(rt, person="maya", n=5):
    return [ledger.append(rt, person, {"time": 1700000000 + i, "outcome": "pass", "n": i}) for i in range(n)]


def lines(rt, person="maya"):
    return ledger.log_path(rt, person).read_text().splitlines()


def write_lines(rt, ls, person="maya"):
    ledger.log_path(rt, person).write_text("".join(x + "\n" for x in ls))


def rehash(line: str, **changes) -> str:
    """What a careful attacker does: change a field and recompute that entry's own hash."""
    e = json.loads(line) | changes
    e["entry_hash"] = ledger.entry_hash(e)
    return json.dumps(e)


# --- a good chain -----------------------------------------------------------------------------------

def test_chain_verifies_and_links(rt):
    written = fill(rt, n=5)
    assert [e["seq"] for e in written] == [0, 1, 2, 3, 4]
    assert written[0]["prev_hash"] == ledger.genesis_hash("maya")
    for a, b in zip(written, written[1:]):
        assert b["prev_hash"] == a["entry_hash"]
    rep = ledger.verify_all(rt, "maya")
    assert rep.ok and rep.count == 5 and rep.head == written[-1]["entry_hash"] and not rep.problems
    assert ledger.head(rt, "maya") == (5, written[-1]["entry_hash"])
    assert stat.S_IMODE(ledger.log_path(rt, "maya").stat().st_mode) == 0o600


def test_hash_ignores_on_disk_formatting(rt):
    fill(rt, n=3)
    reformatted = [json.dumps(json.loads(x), indent=None, separators=(",", ":"), sort_keys=True) for x in lines(rt)]
    write_lines(rt, reformatted)
    assert ledger.verify(rt, "maya").ok


def test_hash_known_value():
    e = {"time": 1, "outcome": "pass", "seq": 0, "prev_hash": ledger.genesis_hash("maya")}
    import hashlib
    body = json.dumps(e, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode()
    assert ledger.entry_hash(e) == hashlib.sha256(b"familybox-ledger-v1\n" + body).hexdigest()
    assert ledger.entry_hash(e | {"entry_hash": "x"}) == ledger.entry_hash(e)


def test_missing_log_is_fine_until_the_box_has_a_record(rt):
    assert ledger.verify(rt, "maya").ok
    fill(rt, n=2)
    ledger.log_path(rt, "maya").unlink()
    rep = ledger.verify(rt, "maya")
    assert not rep.ok and "missing" in rep.problems[0]


# --- tampering ----------------------------------------------------------------------------------

def test_edit_detected(rt):
    fill(rt)
    ls = lines(rt)
    e = json.loads(ls[2]); e["outcome"] = "refused"; ls[2] = json.dumps(e)
    write_lines(rt, ls)
    rep = ledger.verify(rt, "maya")
    assert not rep.ok and any("line 3" in p and "changed" in p for p in rep.problems)


def test_edit_with_recomputed_hash_detected(rt):
    fill(rt)
    ls = lines(rt)
    ls[1] = rehash(ls[1], outcome="refused")
    write_lines(rt, ls)
    rep = ledger.verify(rt, "maya")
    assert not rep.ok and any("line 3" in p and "does not follow" in p for p in rep.problems)


def test_edit_of_last_entry_with_recomputed_hash_caught_by_head(rt):
    fill(rt)
    ls = lines(rt)
    ls[-1] = rehash(ls[-1], sent_to_assistant="something else")
    write_lines(rt, ls)
    rep = ledger.verify(rt, "maya")
    assert not rep.ok and any("last recorded 5 entries" in p for p in rep.problems)


@pytest.mark.parametrize("drop", [0, 2, 4])
def test_deletion_detected(rt, drop):
    fill(rt)
    ls = lines(rt)
    del ls[drop]
    write_lines(rt, ls)
    assert not ledger.verify(rt, "maya").ok


def test_reorder_detected(rt):
    fill(rt)
    ls = lines(rt)
    ls[1], ls[2] = ls[2], ls[1]
    write_lines(rt, ls)
    rep = ledger.verify(rt, "maya")
    assert not rep.ok and any("expected 1" in p for p in rep.problems)


def test_duplicated_entry_detected(rt):
    fill(rt)
    ls = lines(rt)
    write_lines(rt, ls[:3] + [ls[2]] + ls[3:])
    assert not ledger.verify(rt, "maya").ok


def test_inserted_unchained_line_detected(rt):
    fill(rt)
    ls = lines(rt)
    write_lines(rt, ls[:2] + [json.dumps({"time": 1, "outcome": "pass"})] + ls[2:])
    rep = ledger.verify(rt, "maya")
    assert not rep.ok and any("without chain fields" in p for p in rep.problems)


def test_duplicate_keys_rejected(rt):
    fill(rt, n=2)
    ls = lines(rt)
    ls[1] = ls[1][:-1] + ', "outcome": "refused"}'
    write_lines(rt, ls)
    assert not ledger.verify(rt, "maya").ok


def test_truncation_caught_by_head_file(rt):
    fill(rt)
    write_lines(rt, lines(rt)[:3])
    rep = ledger.verify(rt, "maya")
    assert not rep.ok and any("last recorded 5" in p for p in rep.problems)


def test_truncation_with_rewritten_head_caught_by_checkpoint(rt):
    fill(rt, n=3)
    count, h = ledger.head(rt, "maya")
    ledger.add_checkpoint(rt, "maya", count, h, "NEAR anchor abc")
    fill(rt, n=2)
    assert ledger.verify_all(rt, "maya").ok
    # Attacker cuts back to 2 entries and rewrites the head file to match.
    ls = lines(rt)[:2]
    write_lines(rt, ls)
    last = json.loads(ls[-1])
    ledger._write_head(rt, "maya", last["seq"], last["entry_hash"])
    assert ledger.verify(rt, "maya").ok              # the log alone cannot see a clean cut ...
    rep = ledger.verify_all(rt, "maya")              # ... the checkpoint can
    assert not rep.ok and any("NEAR anchor abc says entry 3" in p for p in rep.problems)


def test_wiping_log_and_head_caught_by_checkpoint(rt):
    fill(rt, n=2)
    ledger.add_checkpoint(rt, "maya", *ledger.head(rt, "maya"), "local checkpoint")
    ledger.log_path(rt, "maya").unlink()
    ledger.head_path(rt, "maya").unlink()
    assert not ledger.verify_all(rt, "maya").ok


def test_another_persons_log_does_not_verify(rt):
    fill(rt, "dana", n=3)
    shutil.copy(ledger.log_path(rt, "dana"), ledger.log_path(rt, "maya"))
    shutil.copy(ledger.head_path(rt, "dana"), ledger.head_path(rt, "maya"))
    rep = ledger.verify(rt, "maya")
    assert not rep.ok and any("line 1" in p for p in rep.problems)


def test_damaged_checkpoint_reported(rt):
    fill(rt, n=1)
    p = ledger.checkpoints_path(rt, "maya")
    p.parent.mkdir(parents=True)
    p.write_text("not json\n")
    assert not ledger.verify_all(rt, "maya").ok


# --- old logs, damaged writes, concurrency --------------------------------------------------------

def test_old_unchained_log_is_sealed(rt):
    path = ledger.log_path(rt, "maya")
    path.parent.mkdir(parents=True)
    old = [json.dumps({"time": 1, "outcome": "pass"}), json.dumps({"time": 2, "outcome": "held"})]
    path.write_text("\n".join(old) + "\n")
    rep = ledger.verify(rt, "maya")
    assert rep.ok and rep.count == 0 and rep.unchained_lines == 2
    e = ledger.append(rt, "maya", {"time": 3, "outcome": "pass"})
    assert e["seq"] == 1
    start = json.loads(lines(rt)[2])
    assert start["event"] == "ledger_start" and start["unchained_lines"] == 2 and start["seq"] == 0
    rep = ledger.verify(rt, "maya")
    assert rep.ok and rep.count == 2 and rep.unchained_lines == 2
    # Changing an old line after it was sealed shows up.
    ls = lines(rt)
    ls[0] = json.dumps({"time": 1, "outcome": "refused"})
    write_lines(rt, ls)
    rep = ledger.verify(rt, "maya")
    assert not rep.ok and any("older lines" in p for p in rep.problems)


def test_removing_sealed_old_lines_detected(rt):
    path = ledger.log_path(rt, "maya")
    path.parent.mkdir(parents=True)
    path.write_text(json.dumps({"time": 1, "outcome": "pass"}) + "\n")
    ledger.append(rt, "maya", {"time": 3})
    write_lines(rt, lines(rt)[1:])
    assert not ledger.verify(rt, "maya").ok


def test_torn_last_line_is_sealed_as_a_warning(rt):
    fill(rt, n=2)
    with ledger.log_path(rt, "maya").open("a") as f:
        f.write('{"time": 9, "outcome": "pa')       # power cut in the middle of a write
    before = ledger.verify(rt, "maya")              # not sealed yet: a note, and the head file still matches
    assert before.ok and before.count == 2 and any("cut off" in w for w in before.warnings)
    e = ledger.append(rt, "maya", {"time": 10})
    assert e["seq"] == 3 and all(json.loads(x) for x in lines(rt)[-2:])   # our lines stay whole
    assert json.loads(lines(rt)[-2])["reason"] == "torn_write"
    rep = ledger.verify_all(rt, "maya")
    assert rep.count == 4 and rep.ok and not rep.problems and any("power cut" in w for w in rep.warnings)
    ledger.append(rt, "maya", {"time": 11})
    assert ledger.verify_all(rt, "maya").ok       # and it stays that way


def test_torn_line_bytes_still_pinned(rt):
    fill(rt, n=2)
    with ledger.log_path(rt, "maya").open("a") as f:
        f.write('{"time": 9, "outcome": "pa')
    ledger.append(rt, "maya", {"time": 10})
    ls = lines(rt)
    ls[2] = '{"time": 9, "outcome": "xx'          # the cut-off piece is edited afterwards
    write_lines(rt, ls)
    rep = ledger.verify(rt, "maya")
    assert not rep.ok and any("changed" in p for p in rep.problems)


def test_cutting_the_last_entry_short_is_not_a_power_cut(rt):
    fill(rt, n=3)
    data = ledger.log_path(rt, "maya").read_bytes()
    ledger.log_path(rt, "maya").write_bytes(data[:-20])    # head file still says 3 entries
    rep = ledger.verify(rt, "maya")
    assert not rep.ok and any("the box last recorded 3" in p for p in rep.problems)


def test_two_damaged_lines_are_still_a_failure(rt):
    fill(rt, n=2)
    with ledger.log_path(rt, "maya").open("a") as f:
        f.write('garbage one\n{"time": 9, "outcome": "pa')
    ledger.append(rt, "maya", {"time": 10})
    assert "reason" not in json.loads(lines(rt)[-2])
    rep = ledger.verify(rt, "maya")
    assert not rep.ok and any("damaged line" in p for p in rep.problems)


def test_stripping_chain_fields_from_last_entry_detected(rt):
    fill(rt, n=3)
    ls = lines(rt)
    e = json.loads(ls[-1])
    for k in ("seq", "prev_hash", "entry_hash"):
        e.pop(k)
    e["outcome"] = "refused"
    ls[-1] = json.dumps(e)
    write_lines(rt, ls)
    ledger.append(rt, "maya", {"time": 5})           # the box keeps going and seals the damage
    assert not ledger.verify(rt, "maya").ok


def test_concurrent_appends_keep_one_chain(rt):
    def worker(k):
        for i in range(40):
            ledger.append(rt, "maya", {"time": 1, "worker": k, "i": i})
    ts = [threading.Thread(target=worker, args=(k,)) for k in range(5)]
    for t in ts:
        t.start()
    for t in ts:
        t.join()
    rep = ledger.verify(rt, "maya")
    assert rep.ok and rep.count == 200


def _append_forever(runtime: str, stop, started):
    rt = Path(runtime)
    started.set()
    i = 0
    while not stop.is_set():
        ledger.append(rt, "maya", {"time": 1, "outcome": "pass", "i": i})
        i += 1


def _quick_fill(rt, person="maya", n=2000):
    """A long chain written in one go (append() fsyncs every entry, which is slow for thousands)."""
    prev, out = ledger.genesis_hash(person), []
    for i in range(n):
        e = {"time": 1700000000 + i, "outcome": "pass", "n": i, "seq": i, "prev_hash": prev}
        e["entry_hash"] = prev = ledger.entry_hash(e)
        out.append(json.dumps(e))
    ledger.log_path(rt, person).parent.mkdir(parents=True, exist_ok=True)
    write_lines(rt, out, person)
    ledger._write_head(rt, person, n - 1, prev)


def test_verify_never_fails_while_another_process_appends(rt):
    # A long log makes each verify slow enough that, without the lock, the writer lands an entry between
    # reading the log and reading the head file most of the time (the reviewer saw 610 of 797 fail).
    import multiprocessing as mp
    _quick_fill(rt)
    assert ledger.verify_all(rt, "maya").ok
    ctx = mp.get_context("spawn")
    stop, started = ctx.Event(), ctx.Event()
    proc = ctx.Process(target=_append_forever, args=(str(rt), stop, started))
    proc.start()
    try:
        assert started.wait(30)
        failures, runs, seen = [], 0, set()
        import time as _t
        deadline = _t.time() + 3
        while _t.time() < deadline:
            rep = ledger.verify_all(rt, "maya")
            runs += 1
            seen.add(rep.count)
            if not rep.ok:
                failures.append(rep.problems[:2])
    finally:
        stop.set()
        proc.join(30)
    assert proc.exitcode == 0
    assert runs > 5 and len(seen) > 3, (runs, len(seen))    # the writer really ran during the checks
    assert failures == []
    assert ledger.verify_all(rt, "maya").ok


def test_verify_of_nothing_creates_nothing(rt):
    assert ledger.verify(rt, "maya").ok
    assert not (rt / "audit").exists()


def test_bad_inputs(rt):
    with pytest.raises(ledger.LedgerError):
        ledger.append(rt, "../dana", {"time": 1})
    with pytest.raises(ledger.LedgerError):
        ledger.append(rt, "maya", {"time": 1, "seq": 7})
    with pytest.raises(ValueError):
        ledger.append(rt, "maya", {"x": float("nan")})


# --- the box and the CLI --------------------------------------------------------------------------

def test_box_answers_are_chained(cfg):
    box = Box(cfg, mode="replay")
    box.ask("maya", "What medications am I on?")
    box.ask("maya", "What medications am I on?")
    entries = [json.loads(x) for x in ledger.log_path(cfg.runtime, "maya").read_text().splitlines()]
    assert [e["seq"] for e in entries] == [0, 1] and entries[0]["qid"]
    assert ledger.verify_all(cfg.runtime, "maya").ok


def test_cli_log_verify(cfg, capsys):
    assert cli.main(["log", "verify", "--as", "maya"]) == 0
    assert "no linked entries yet" in capsys.readouterr().out
    fill(cfg.runtime, n=3)
    assert cli.main(["log", "verify", "--as", "maya"]) == 0
    out = capsys.readouterr().out
    assert "checks out: 3 entries" in out and ledger.head(cfg.runtime, "maya")[1] in out and "\u2014" not in out
    ls = lines(cfg.runtime)
    ls[0] = rehash(ls[0], outcome="refused")
    write_lines(cfg.runtime, ls)
    assert cli.main(["log", "verify", "--as", "maya"]) == 1
    assert "does NOT check out" in capsys.readouterr().out
    assert cli.main(["log", "verify", "--as", "maya", "--json"]) == 1
    assert json.loads(capsys.readouterr().out)["ok"] is False
    assert cli.main(["log", "verify", "--as", "nobody"]) == 2


def test_cli_log_show_still_works(cfg, capsys):
    fill(cfg.runtime, n=1)
    assert cli.main(["log", "--as", "maya"]) == 0
    assert '"entry_hash"' in capsys.readouterr().out


# --- approvals are in the chain ---------------------------------------------------------------------

def _held(cfg):
    from familybox.approvals import Approvals
    from familybox.gate import Held
    return Approvals(cfg).add("sam", "What is Dana's SSN?",
                              [Held("h1", "ssn", "SSN", "987-65-4321", "dana", "people/dana/ids/ssn_card_dana.txt"),
                               Held("h2", "ssn", "SSN", "987-65-4322", "dana", "people/dana/ids/ssn_card_dana.txt")])


@pytest.mark.parametrize("cmd,event", [("approve", "approved"), ("deny", "denied")])
def test_cli_approve_and_deny_are_logged_without_the_value(cfg, capsys, cmd, event):
    a, b = _held(cfg)
    before = ledger.verify_all(cfg.runtime, "dana").count
    assert cli.main([cmd, "--as", "dana", a]) == 0
    capsys.readouterr()
    rep = ledger.verify_all(cfg.runtime, "dana")
    assert rep.ok and rep.count == before + 1
    last = json.loads(lines(cfg.runtime, "dana")[-1])
    assert last["event"] == event and last["item_id"] == a and last["asker"] == "sam" and last["label"] == "SSN"
    assert last["seq"] == before
    text = ledger.log_path(cfg.runtime, "dana").read_text()
    assert "987-65-4321" not in text and "987-65-4322" not in text


def test_approve_then_deny_both_chained(cfg):
    from familybox.approvals import Approvals
    a, b = _held(cfg)
    Approvals(cfg).decide("dana", a, True)
    Approvals(cfg).decide("dana", b, False)
    rep = ledger.verify_all(cfg.runtime, "dana")
    assert rep.ok and [json.loads(x)["event"] for x in lines(cfg.runtime, "dana")[-2:]] == ["approved", "denied"]
    assert not ledger.log_path(cfg.runtime, "sam").exists() or "987-65-432" not in \
        ledger.log_path(cfg.runtime, "sam").read_text()
