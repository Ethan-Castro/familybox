"""Confidential analysis workbench: run_analysis tool provider and the namespace sandbox.

The first half runs anywhere (fake sandbox). The second half runs real scripts in the real
sandbox and is skipped unless unprivileged Linux namespaces work here (the Pi, most Linux boxes).
"""

import json
import os
import re
import shutil
import stat
import sys
import time
from pathlib import Path

import pytest

from familybox import config, enclave, sandbox
from familybox.box import Box, Question
from familybox.plugins import workbench
from familybox.store import Store

DEMO = Path(__file__).resolve().parents[1] / "demo"
MAYA_SSN = "987-65-4322"
DANA_SSN = "987-65-4320"


@pytest.fixture
def cfg(tmp_path, monkeypatch):
    home = tmp_path / "home"
    shutil.copytree(DEMO / "files", home / "files")
    shutil.copy(DEMO / "family.toml", home / "family.toml")
    monkeypatch.delenv("NEAR_AI_CLOUD_API_KEY", raising=False)
    monkeypatch.delenv("NEARAI_API_KEY", raising=False)
    monkeypatch.delenv("FAMILYBOX_WORKBENCH", raising=False)
    c = config.load(home)
    Store(c).reindex()
    return c


def enable(cfg, people=None, include_granted=None):
    extra = "\n[workbench]\nenabled = true\n"
    if people is not None:
        extra += f"people = {json.dumps(people)}\n"
    if include_granted is not None:
        extra += f"include_granted = {json.dumps(include_granted)}\n"
    with (cfg.home / "family.toml").open("a") as f:
        f.write(extra)


def write_replay(replay_dir: Path, person: str, question: str, answer: str, tool_calls: list) -> None:
    replay_dir.mkdir(parents=True, exist_ok=True)
    rec = {"answer": answer, "model": "test/model", "tokens_in": 1, "tokens_out": 1,
           "attestation": {"model_reports_verified": 1, "verified_at_ms": 1, "seconds": 0.1, "e2ee": True},
           "turns": [{"seconds": 0.1, "signature_kind": "provider_tee", "signer": "0xabc", "tool_calls": tool_calls,
                      "content": None},
                     {"seconds": 0.1, "signature_kind": "provider_tee", "signer": "0xabc", "tool_calls": [],
                      "content": answer}]}
    (replay_dir / f"{enclave.replay_key(person, question)}.json").write_text(json.dumps(rec))


def events(cfg, ans) -> list[dict]:
    return [json.loads(x) for x in (cfg.runtime / "events" / ans.person / f"{ans.qid}.jsonl").read_text().splitlines()]


def last_audit(cfg, person) -> dict:
    return json.loads((cfg.runtime / "audit" / f"{person}.jsonl").read_text().splitlines()[-1])


def tool_names(box, person_id):
    return [t["function"]["name"] for t in box.tools_for(box.cfg.person(person_id))]


class FakeSandbox:
    """Stands in for sandbox.run: records the workspace it was given and returns a fixed result."""

    def __init__(self, output="42\n", **kw):
        self.output, self.kw, self.calls = output, kw, []
        self.sleep = 0.0

    def __call__(self, code, *, data_dir, scratch, limits=sandbox.Limits(), slot_held=False):
        if self.sleep:
            time.sleep(self.sleep)
        listing = sorted(p.relative_to(data_dir).as_posix() for p in data_dir.rglob("*") if p.is_file())
        self.calls.append({"code": code, "files": listing, "index": json.loads((data_dir / "index.json").read_text())})
        return sandbox.Result(ok=True, exit_code=0, output=self.output, output_bytes=len(self.output),
                              seconds=0.05, **self.kw)


@pytest.fixture
def fake(monkeypatch):
    f = FakeSandbox()
    monkeypatch.setattr(sandbox, "available", lambda refresh=False: (True, ""))
    monkeypatch.setattr(sandbox, "run", f)
    return f


# --- switched off, unsupported ------------------------------------------------------------------

def test_off_by_default_and_not_offered(cfg):
    box = Box(cfg, mode="replay")
    assert tool_names(box, "maya") == ["search_files", "read_file"]
    st = workbench.status(cfg, cfg.person("maya"))
    assert not st["offered"] and "family.toml" in st["reason"]


def test_not_offered_where_the_sandbox_does_not_work(cfg, monkeypatch):
    enable(cfg)
    monkeypatch.setattr(sandbox, "available", lambda refresh=False: (False, "no namespaces here"))
    box = Box(cfg, mode="replay")
    assert "run_analysis" not in tool_names(box, "maya")
    wb = next(p for p in box.tool_providers if isinstance(p, workbench.Workbench))
    assert wb.status(cfg.person("maya")) == {"offered": False, "enabled": True, "available": False,
                                              "reason": "no namespaces here"}


@pytest.mark.skipif(sys.platform.startswith("linux"), reason="checks the non-Linux reason")
def test_real_reason_on_a_mac():
    ok, why = sandbox.available(refresh=True)
    assert not ok and "Linux" in why and "\u2014" not in why
    r = sandbox.run("print(1)", data_dir=None, scratch=Path("/nonexistent"))
    assert not r.ok and "Linux" in r.error


def test_people_list_and_env_override(cfg, fake, monkeypatch):
    enable(cfg, people=["dana"])
    box = Box(cfg, mode="replay")
    assert "run_analysis" in tool_names(box, "dana")
    assert "run_analysis" not in tool_names(box, "maya")
    assert "not switched on for Maya" in workbench.status(cfg, cfg.person("maya"))["reason"]
    monkeypatch.setenv("FAMILYBOX_WORKBENCH", "off")
    assert "run_analysis" not in tool_names(box, "dana")


def test_call_while_off_is_refused_by_the_box(cfg, tmp_path, fake):
    q = "add things up"
    write_replay(tmp_path / "rp", "maya", q, "ok", [["run_analysis", json.dumps({"code": "print(1)"})]])
    ans = Box(cfg, mode="replay", replay_dir=tmp_path / "rp").ask("maya", q)
    assert fake.calls == []
    assert any(e["step"] == "tool" and e["name"] == "run_analysis" and e["why"] == "not offered"
               for e in events(cfg, ans))


# --- the workspace holds only the asker's files ------------------------------------------------

def test_workspace_has_only_readable_files(cfg, tmp_path):
    store = Store(cfg)
    idx = workbench.stage_workspace(cfg, store, cfg.person("maya"), tmp_path / "maya")
    paths = {f["path"] for f in idx}
    assert paths and all(p.startswith(("people/maya/", "shared/")) for p in paths)
    assert "people/maya/health/records_maya_fhir.json" in paths
    on_disk = {p.relative_to(tmp_path / "maya").as_posix() for p in (tmp_path / "maya").rglob("*") if p.is_file()}
    assert not any("dana" in p or "sam" in p for p in on_disk)
    assert "text/people/maya/ids/ssn_card_maya.txt.txt" in on_disk
    # FHIR JSON arrives flattened to text as well as the original
    assert "Patient:" in (tmp_path / "maya/text/people/maya/health/records_maya_fhir.json.txt").read_text()

    # By default only Dana's own files and shared/, even though also_reads grants her more
    dana = {f["path"] for f in workbench.stage_workspace(cfg, store, cfg.person("dana"), tmp_path / "dana")}
    assert dana and all(p.startswith(("people/dana/", "shared/")) for p in dana)
    # include_granted adds the folders the owner granted her, and still never a health folder
    dana = {f["path"] for f in workbench.stage_workspace(cfg, store, cfg.person("dana"), tmp_path / "dana2",
                                                         include_granted=True)}
    assert "people/maya/ids/ssn_card_maya.txt" in dana            # also_reads
    assert not any(p.startswith("people/maya/health/") for p in dana)   # health stays owner only
    assert "people/sam/taxes/w2_2025_sam.txt" in dana and "people/sam/ids/ssn_card_sam.txt" not in dana


def test_workspace_skips_links_to_other_peoples_files(cfg, tmp_path):
    link = cfg.files / "people/maya/ids/not_really_mine.txt"
    link.symlink_to(cfg.files / "people/dana/ids/ssn_card_dana.txt")
    linked_dir = cfg.files / "people/maya/sneaky"
    linked_dir.symlink_to(cfg.files / "people/dana/taxes", target_is_directory=True)
    store = Store(cfg)
    store.reindex()
    idx = workbench.stage_workspace(cfg, store, cfg.person("maya"), tmp_path / "ws")
    assert not any(f["path"].endswith("not_really_mine.txt") or "sneaky" in f["path"] for f in idx)
    blob = "".join(p.read_text(errors="replace") for p in (tmp_path / "ws").rglob("*") if p.is_file())
    assert DANA_SSN not in blob and "96,410" not in blob
    skipped = json.loads((tmp_path / "ws/index.json").read_text())["skipped"]
    assert any(s["why"] == "link" for s in skipped)


# --- the tool through the box -------------------------------------------------------------------

def test_run_through_the_box_logs_code_output_and_limits(cfg, tmp_path, fake):
    enable(cfg)
    code = f"# looking for {MAYA_SSN}\nprint(open('/data/text/people/maya/ids/ssn_card_maya.txt.txt').read())"
    fake.output = f"SSN: {MAYA_SSN}\n"
    fake.kw = {"limits_hit": ["cpu"]}
    q = "Use a script to read my card"
    write_replay(tmp_path / "rp", "maya", q, "Your number ends in 4322.",
                 [["run_analysis", json.dumps({"code": code})]])
    box = Box(cfg, mode="replay", replay_dir=tmp_path / "rp")
    assert tool_names(box, "maya") == ["search_files", "read_file", "run_analysis"]
    ans = box.ask("maya", q, source="web")
    assert ans.outcome == "pass" and ans.text == "Your number ends in 4322."
    call = fake.calls[0]
    assert call["code"] == code
    assert all(f.startswith(("files/people/maya/", "text/people/maya/", "files/shared/", "text/shared/"))
               or f in ("index.json", "README.txt") for f in call["files"])
    # files the script could see are recorded apart from files read (none were read one by one),
    # and the gate still applies their owners' rules
    assert "people/maya/ids/ssn_card_maya.txt" in ans.files_visible and ans.files_read == []

    ev = [e for e in events(cfg, ans) if e["step"] == "workbench"]
    assert len(ev) == 1 and ev[0]["limits_hit"] == ["cpu"] and ev[0]["exit_code"] == 0
    assert "print(open(" in ev[0]["code"] and "[protected]" in ev[0]["output"]
    audit = last_audit(cfg, "maya")
    assert "people/maya/ids/ssn_card_maya.txt" in audit["files_visible"] and audit["files_read"] == []
    assert stat.S_IMODE((cfg.runtime / "audit" / "maya.jsonl").stat().st_mode) == 0o600
    assert stat.S_IMODE((cfg.runtime / "audit").stat().st_mode) == 0o700
    wb = audit["plugins"]["workbench"][0]
    assert "print(open(" in wb["code"] and wb["limits"]["memory_mb"] == 512
    own_log = cfg.runtime / "workbench" / "maya.jsonl"
    assert stat.S_IMODE(own_log.stat().st_mode) == 0o600
    for raw in (own_log.read_text(), json.dumps(audit),
                (cfg.runtime / "events" / "maya" / f"{ans.qid}.jsonl").read_text()):
        assert MAYA_SSN not in raw and "987654322" not in raw
    assert workbench.read_log(cfg, "maya")[0]["qid"] == ans.qid


def test_script_output_still_goes_through_the_gate(cfg, tmp_path, fake):
    """The model sees the script output; if it repeats a protected value, the gate holds it."""
    enable(cfg)
    fake.output = f"{MAYA_SSN}\n"
    q = "Print my SSN with a script"
    write_replay(tmp_path / "rp", "maya", q, f"Your SSN is {MAYA_SSN}.",
                 [["run_analysis", json.dumps({"code": "print(1)"})]])
    ans = Box(cfg, mode="replay", replay_dir=tmp_path / "rp").ask("maya", q)
    assert ans.outcome in ("held", "masked", "refused") and MAYA_SSN not in ans.text


def test_live_loop_gets_tool_and_result(cfg, fake, monkeypatch):
    enable(cfg)
    seen = {}

    async def fake_live(*, tools, run_tool, emit, **kw):
        seen["tools"] = [t["function"]["name"] for t in tools]
        seen["out"] = json.loads(run_tool("run_analysis", {"code": "print(6*7)"}))
        seen["bad"] = json.loads(run_tool("run_analysis", {"code": 7}))
        return enclave.Draft(answer="It is 42.", model="m")
    judged = []

    async def fake_classifier(**kw):   # the second privacy check (feat/paraphrase), never a real call here
        judged.append(kw["messages"][1]["content"])
        return {"content": json.dumps({"reveals": False, "categories": [], "spans": [], "facts": []}),
                "signature_kind": "provider_tee", "signer": "0xabcdef0123456789", "tokens": [1, 1], "seconds": 0.1}
    from familybox.plugins import paraphrase
    monkeypatch.setattr(paraphrase, "call_classifier", fake_classifier)
    monkeypatch.setenv("NEAR_AI_CLOUD_API_KEY", "test-not-a-key")
    monkeypatch.setattr(enclave, "ask_live", fake_live)
    ans = Box(cfg, mode="live").ask("dana", "what is six times seven")
    assert "run_analysis" in seen["tools"]
    assert seen["out"] == {"exit_code": 0, "output": "42\n", "seconds": 0.05}
    assert "error" in seen["bad"] and ans.outcome == "pass"
    # the files the script could see are judged by the second privacy check too
    assert judged and "It is 42." in judged[0] and ans.files_visible


def test_runs_per_question_are_capped(cfg, tmp_path, fake):
    enable(cfg)
    q = "loop forever"
    calls = [["run_analysis", json.dumps({"code": f"print({i})"})] for i in range(5)]
    write_replay(tmp_path / "rp", "maya", q, "done", calls)
    Box(cfg, mode="replay", replay_dir=tmp_path / "rp").ask("maya", q)
    assert len(fake.calls) == workbench.MAX_RUNS_PER_QUESTION


def test_a_slow_script_does_not_hold_up_other_questions(cfg, tmp_path, fake):
    """Tools run off the event loop: while one person's script sleeps, another question finishes."""
    import asyncio
    enable(cfg)
    fake.sleep = 1.5
    slow, quick = "Add up my bills with a script", "When does the car registration expire?"
    write_replay(tmp_path / "rp", "maya", slow, "done", [["run_analysis", json.dumps({"code": "print(1)"})]])
    write_replay(tmp_path / "rp", "dana", quick, "In March.", [])
    box = Box(cfg, mode="replay", replay_dir=tmp_path / "rp")
    done = {}

    async def timed(person, q, delay):
        await asyncio.sleep(delay)
        t = time.monotonic()
        await box.ask_async(person, q)
        done[person] = time.monotonic() - t

    async def both():
        await asyncio.gather(timed("maya", slow, 0), timed("dana", quick, 0.2))
    asyncio.run(both())
    assert done["maya"] >= 1.5 and done["dana"] < 1.0, done
    assert len(fake.calls) == 1


def test_enclave_runs_tools_off_the_event_loop():
    import asyncio
    import threading
    loop_thread = threading.get_ident()
    seen = {}

    def slow_tool(name, args):
        seen["thread"] = threading.get_ident()
        time.sleep(0.6)
        return "ok"

    async def main():
        ticks = 0

        async def ticker():
            nonlocal ticks
            for _ in range(5):
                await asyncio.sleep(0.05)
                ticks += 1
        out, _ = await asyncio.gather(enclave.run_tool_off_loop(slow_tool, "x", "{}"), ticker())
        return out, ticks
    out, ticks = asyncio.run(main())
    assert out == "ok" and ticks == 5 and seen["thread"] != loop_thread


def test_busy_returns_at_once_and_does_not_use_up_a_run(cfg, tmp_path, fake):
    enable(cfg)
    with sandbox.slot() as got:
        assert got
        t = time.monotonic()
        res, files = workbench.run_for(cfg, Store(cfg), cfg.person("maya"), "print(1)")
        assert res.busy and not res.ok and files == [] and time.monotonic() - t < 0.5
        assert workbench.model_view(res) == {"error": sandbox.BUSY, "busy": True}
        with sandbox.slot() as again:
            assert not again
        q = "count things while busy"
        calls = [["run_analysis", json.dumps({"code": "print(1)"})]] * 4
        write_replay(tmp_path / "rp", "maya", q, "done", calls)
        ans = Box(cfg, mode="replay", replay_dir=tmp_path / "rp").ask("maya", q)
    assert fake.calls == []
    assert sum(e["step"] == "workbench_busy" for e in events(cfg, ans)) == 4   # never hit the per-question cap
    with sandbox.slot() as got:
        assert got   # released


def test_settings_fail_closed_on_wrong_types(cfg, fake):
    toml = cfg.home / "family.toml"
    original = toml.read_text()
    for bad, word in (('enabled = "false"', "enabled"), ('enabled = "true"', "enabled"), ("enabled = 1", "enabled"),
                      ('enabled = true\npeople = "dana"', "people"), ("enabled = true\npeople = [1, 2]", "people"),
                      ('enabled = true\ninclude_granted = "yes"', "include_granted")):
        toml.write_text(original + f"\n[workbench]\n{bad}\n")
        st = workbench.status(cfg, cfg.person("dana"))
        assert not st["offered"] and not st["enabled"], bad
        assert "not valid" in st["reason"] and word in st["reason"] and "\u2014" not in st["reason"], st
        assert "run_analysis" not in tool_names(Box(cfg, mode="replay"), "dana")
    toml.write_text(original + '\n[workbench]\nenabled = true\npeople = ["dana"]\n')
    assert workbench.status(cfg, cfg.person("dana"))["offered"]


def test_staging_folder_is_private_in_ram_and_leftovers_are_removed(cfg, tmp_path, monkeypatch):
    xdg = tmp_path / "xdg"
    xdg.mkdir(mode=0o700)
    monkeypatch.setenv("XDG_RUNTIME_DIR", str(xdg))
    d = workbench.scratch_dir(cfg)
    assert d == xdg / "familybox-workbench" and stat.S_IMODE(d.stat().st_mode) == 0o700
    monkeypatch.setenv("XDG_RUNTIME_DIR", str(tmp_path / "missing"))
    d2 = workbench.scratch_dir(cfg)
    assert d2 == cfg.runtime / "workbench" / "tmp" and stat.S_IMODE(d2.stat().st_mode) == 0o700
    monkeypatch.setenv("XDG_RUNTIME_DIR", str(xdg))
    old_ws, old_run, fresh = d / "ws-crashed", d2 / "run-crashed", d / "ws-running-now"
    for p in (old_ws, old_run, fresh):
        (p / "data").mkdir(parents=True)
        (p / "data" / "copy.txt").write_text(MAYA_SSN)
    keep = d / "not-ours"
    keep.mkdir()
    long_ago = time.time() - 2 * workbench.LEFTOVER_AGE_S
    for p in (old_ws, old_run, keep):
        os.utime(p, (long_ago, long_ago))
    Box(cfg, mode="replay")   # register() cleans up
    assert not old_ws.exists() and not old_run.exists()
    assert fresh.exists() and keep.exists()   # a run in progress, and anything not ours, stay


def test_model_view_reports_errors_and_limits():
    assert workbench.model_view(sandbox.Result(ok=False, error="nope")) == {"error": "nope"}
    v = workbench.model_view(sandbox.Result(ok=True, exit_code=1, signal=24, output="x", output_bytes=99999,
                                            truncated=True, limits_hit=["cpu", "output"], seconds=1))
    assert v["killed_by_signal"] == 24 and v["limits_hit"] == ["cpu", "output"] and "99999" in v["output_truncated"]


def test_limits_hit_classification():
    lim = sandbox.Limits()
    r = sandbox.Result(ok=True, exit_code=1, output="Traceback...\nMemoryError\n")
    assert sandbox.limits_hit(r, timed_out=False, flooded=False, limits=lim) == []
    assert sandbox.script_reported(r.output, []) == ["memory"]          # said by the script, not measured
    r = sandbox.Result(ok=True, signal=24, cpu_s=20.01)
    assert sandbox.limits_hit(r, timed_out=False, flooded=False, limits=lim) == ["cpu"]
    r = sandbox.Result(ok=True, signal=9)
    assert sandbox.limits_hit(r, timed_out=True, flooded=False, limits=lim) == ["time"]
    r = sandbox.Result(ok=True, max_rss_kb=500 * 1024)
    assert sandbox.limits_hit(r, timed_out=False, flooded=False, limits=lim) == ["memory"]
    r = sandbox.Result(ok=True, exit_code=1, output="BlockingIOError: [Errno 11] Resource temporarily unavailable")
    assert sandbox.script_reported(r.output, []) == ["processes"]


def test_a_script_cannot_fake_measured_limits():
    """Printing the words, or sending itself SIGXCPU or SIGKILL, never shows up as a measured limit."""
    lim = sandbox.Limits()
    words = "MemoryError\nResource temporarily unavailable\nNo space left on device\n"
    for sig in (None, 24, 9):
        r = sandbox.Result(ok=True, signal=sig, output=words, cpu_s=0.05, max_rss_kb=9000)
        assert sandbox.limits_hit(r, timed_out=False, flooded=False, limits=lim) == []
    assert sandbox.script_reported(words, []) == ["memory", "processes", "disk"]
    e = {"limits_hit": [], "limits_reported_by_script": ["memory"]}
    assert workbench.limits_text(e) == ("limits hit: none; the script's output mentions: memory "
                                        "(not measured by the box)")
    v = workbench.model_view(sandbox.Result(ok=True, exit_code=1, script_reported=["memory"]))
    assert "limits_hit" not in v and v["output_mentions_limits"] == ["memory"]


def _bpf(prog, arch_id, nr, arg0=0):
    """A tiny interpreter for the seccomp program, enough to check its decisions anywhere."""
    from familybox import sandbox_launcher as L
    data = {0: nr, 4: arch_id, 16: arg0 & 0xFFFFFFFF}
    acc, pc = 0, 0
    while True:
        code, jt, jf, k = prog[pc]
        if code == L.LD_ABS:
            acc = data[k]
            pc += 1
        elif code == L.RET:
            return k
        else:
            hit = {L.JEQ: acc == k, L.JGE: acc >= k, L.JSET: bool(acc & k)}[code]
            pc += 1 + (jt if hit else jf)


@pytest.mark.parametrize("arch", ["aarch64", "x86_64"])
def test_seccomp_program_decisions(arch):
    from familybox import sandbox_launcher as L
    prog = L.seccomp_program(arch)
    aid = L.AUDIT_ARCH[arch]
    eperm, eagain = L.RET_ERRNO | L.EPERM, L.RET_ERRNO | L.EAGAIN
    for name, nr in L.DENY[arch].items():
        assert _bpf(prog, aid, nr) == eperm, name
    clone = L.CLONE[arch]
    assert _bpf(prog, aid, clone, 0x003D0F00) == L.RET_ALLOW              # glibc pthread_create flags
    assert _bpf(prog, aid, clone, 0x01200011) == eagain                   # glibc fork()
    assert _bpf(prog, aid, clone, 0x10000000 | 17) == eagain              # new user namespace
    assert _bpf(prog, aid, L.CLONE3) == L.RET_ERRNO | L.ENOSYS
    for nr in L.NEW_PROCESS[arch].values():
        assert _bpf(prog, aid, nr) == eagain
    for ok in (0, 1, 63, 64, 56 if arch == "aarch64" else 257, 221 if arch == "aarch64" else 59):  # read/write/openat/execve
        assert _bpf(prog, aid, ok) == L.RET_ALLOW
    assert _bpf(prog, 0x40000003, 0) == L.RET_KILL_PROCESS                # wrong architecture
    if arch == "x86_64":
        assert _bpf(prog, aid, 0x40000000 + 1) == eperm                   # x32 ABI


def test_cli_status_and_web_page(cfg, fake, monkeypatch, capsys):
    from starlette.testclient import TestClient

    from familybox import cli, web
    monkeypatch.setenv("FAMILYBOX_HOME", str(cfg.home))
    assert cli.main(["workbench", "status", "--as", "maya"]) == 1
    assert "family.toml" in capsys.readouterr().out
    enable(cfg)
    assert cli.main(["workbench", "status", "--as", "maya"]) == 0
    script = cfg.home / "s.py"
    script.write_text("print(6*7)")
    assert cli.main(["workbench", "run", "--as", "maya", str(script)]) == 0
    assert '"output": "42\\n"' in capsys.readouterr().out
    assert cli.main(["workbench", "log", "--as", "maya"]) == 0
    assert "print(6*7)" in capsys.readouterr().out

    c = TestClient(web.create_app(cfg), base_url="https://testserver")
    code = web.issue_code(cfg, "maya")
    tok = re.search(r'name="csrf" value="([^"]+)"', c.get("/signin").text).group(1)
    c.post("/signin", data={"code": code, "csrf": tok}, follow_redirects=False)
    r = c.get("/workbench")
    assert r.status_code == 200 and "print(6*7)" in r.text and 'href="/workbench" class="here"' in r.text
    assert "\u2014" not in r.text
    # Dana's page never shows Maya's scripts
    c2 = TestClient(web.create_app(cfg), base_url="https://testserver")
    code = web.issue_code(cfg, "dana")
    tok = re.search(r'name="csrf" value="([^"]+)"', c2.get("/signin").text).group(1)
    c2.post("/signin", data={"code": code, "csrf": tok}, follow_redirects=False)
    assert "print(6*7)" not in c2.get("/workbench").text


def test_fleet_exec_target_dir(monkeypatch):
    monkeypatch.syspath_prepend(str(Path(__file__).resolve().parents[1] / "scripts"))
    import fleet_exec
    monkeypatch.delenv("FAMILYBOX_PI_DIR", raising=False)
    assert fleet_exec.pi_dir() == "~/familybox"
    monkeypatch.setenv("FAMILYBOX_PI_DIR", "~/familybox-wb/")
    assert fleet_exec.pi_dir() == "~/familybox-wb"
    for bad in ("~/x; rm -rf ~", "~/../etc", "~", "/", "relative/path", "~/a b", "$(id)",
                "~/.", "~/familybox/.", "~/familybox/./.", "/.", "~/./familybox", "~/familybox/.."):
        monkeypatch.setenv("FAMILYBOX_PI_DIR", bad)
        with pytest.raises(SystemExit):
            fleet_exec.pi_dir()


# --- the real sandbox (Linux with unprivileged namespaces only) ---------------------------------

linux_sandbox = pytest.mark.skipif(not sandbox.available()[0],
                                   reason=f"sandbox not available here: {sandbox.available()[1]}")
FAST = sandbox.Limits(cpu_s=3, wall_s=6)


def run_as(cfg, person_id, code, limits=FAST):
    res, files = workbench.run_for(cfg, Store(cfg), cfg.person(person_id), code, limits)
    return res


@linux_sandbox
def test_real_runs_python_isolated(cfg):
    r = run_as(cfg, "maya", "import sys, os, socket\n"
                             "print(sys.flags.isolated, os.getcwd(), socket.gethostname())\n"
                             "print(sorted(os.environ))\nraise SystemExit(3)")
    assert r.ok and r.exit_code == 3, r
    first, envline = r.output.splitlines()[:2]
    assert first == "1 /work sandbox"
    assert "NEAR_AI_CLOUD_API_KEY" not in envline and "JFLEET_TOKEN" not in envline


@linux_sandbox
def test_real_no_secrets_from_the_parent_environment(cfg, monkeypatch):
    monkeypatch.setenv("NEAR_AI_CLOUD_API_KEY", "sk-test-should-never-be-seen")
    sandbox.available(refresh=True)
    r = run_as(cfg, "maya", "import os\nprint(dict(os.environ))\nprint(os.listdir('/proc'))")
    assert r.ok and "sk-test-should-never-be-seen" not in r.output
    assert r.output.splitlines()[1] == "[]"   # no /proc: no other process, no other environment


@linux_sandbox
def test_real_no_network(cfg):
    code = """
import socket
for host, port in [("1.1.1.1", 53), ("8.8.8.8", 443), ("127.0.0.1", 8080), ("192.168.1.1", 80)]:
    s = socket.socket()
    s.settimeout(2)
    try:
        s.connect((host, port))
        print("CONNECTED", host)
    except OSError as e:
        print("blocked", host, type(e).__name__)
try:
    socket.getaddrinfo("example.com", 443)
    print("DNS WORKED")
except OSError:
    print("dns blocked")
u = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
try:
    u.sendto(b"x", ("1.1.1.1", 53))
    print("UDP SENT")
except OSError:
    print("udp blocked")
print(sorted(i[1] for i in socket.if_nameindex()))
"""
    r = run_as(cfg, "maya", code)
    assert r.ok and r.exit_code == 0, r
    assert "CONNECTED" not in r.output and "WORKED" not in r.output and "UDP SENT" not in r.output
    assert r.output.count("blocked") == 6
    assert r.output.strip().splitlines()[-1] == "['lo']"


@linux_sandbox
def test_real_reads_own_files_only(cfg):
    code = f"""
import json, os
idx = json.load(open("/data/index.json"))
print("files", len(idx["files"]))
print(open("/data/text/people/maya/ids/ssn_card_maya.txt.txt").read().strip().splitlines()[-1])
print(open("/data/files/shared/home/car_registration.txt").read()[:5])
print("dana" in os.listdir("/data/files/people"), "sam" in os.listdir("/data/files/people"))
targets = {json.dumps([str(cfg.files / "people/dana/ids/ssn_card_dana.txt"), str(cfg.runtime / "index.sqlite3"),
                      str(cfg.home / "family.toml"), str(cfg.runtime), str(cfg.home),
                      "/home/offlinebase/familybox", "/home/offlinebase/familybox-wb", "/home", str(Path.home()),
                      str(Path(__file__).resolve().parents[1] / ".env"), "/etc/shadow", "/proc/1/environ",
                      "/run", "/var/run", "/root", "/mnt", "/media", "/srv", "/sys", "/dev/shm", "/var"])}
for t in targets:
    try:
        if os.path.isdir(t):
            print("LISTED", t, os.listdir(t))
        else:
            open(t).read(1)
            print("READ", t)
    except OSError:
        print("hidden", t)
print(sorted(os.listdir("/")))
"""
    r = run_as(cfg, "maya", code)
    assert r.ok and r.exit_code == 0, r
    lines = r.output.splitlines()
    assert lines[1] == f"SSN: {MAYA_SSN}" and lines[3] == "False False"
    assert "READ" not in r.output and "LISTED" not in r.output, r.output
    assert DANA_SSN not in r.output
    from familybox.sandbox_launcher import SYSTEM_DIRS
    assert lines[-1] == str(sorted(["code", "data", "dev", "etc", "proc", "tmp", "work"]
                                   + [d for d in SYSTEM_DIRS if os.path.lexists("/" + d)]))


@linux_sandbox
def test_real_writes_are_discarded_and_files_read_only(cfg):
    code = """
import os
for p in ["/data/new.txt", "/data/files/people/maya/ids/ssn_card_maya.txt", "/etc/passwd", "/usr/evil", "/x"]:
    try:
        open(p, "a").write("x")
        print("WROTE", p)
    except OSError as e:
        print("refused", p)
open("/work/scratch.txt", "w").write("hello")
open("/tmp/scratch.txt", "w").write("hello")
print(sorted(os.listdir("/work")), os.path.exists("/work/left_over.txt"))
open("/work/left_over.txt", "w").write("from the first run")
"""
    r = run_as(cfg, "maya", code)
    assert r.ok and "WROTE" not in r.output and r.output.count("refused") == 5, r.output
    assert "['scratch.txt'] False" in r.output
    r2 = run_as(cfg, "maya", "import os; print(os.listdir('/work'), os.listdir('/tmp'))")
    assert r2.output.strip() == "[] []"
    original = (cfg.files / "people/maya/ids/ssn_card_maya.txt").read_text()
    assert original.endswith(f"{MAYA_SSN}\n") or MAYA_SSN in original
    scratch = workbench.scratch_dir(cfg)
    assert not [d for d in scratch.iterdir() if d.name.startswith(("ws-", "run-"))]   # the staging copy is gone


@linux_sandbox
def test_real_no_privileges_inside(cfg):
    code = """
import ctypes, os
libc = ctypes.CDLL(None, use_errno=True)
print("mount", libc.mount(b"tmpfs", b"/work", b"tmpfs", 0, None), ctypes.get_errno())
print("umount", libc.umount2(b"/data", 2), ctypes.get_errno())
print("remount", libc.mount(None, b"/data", None, 32 | 4096, None), ctypes.get_errno())
try:
    os.chroot("/work"); print("CHROOT")
except OSError:
    print("no chroot")
try:
    os.setuid(1000); print("SETUID")
except OSError:
    print("no setuid")
"""
    r = run_as(cfg, "maya", code)
    assert r.ok, r
    for line in r.output.splitlines()[:3]:
        assert line.split()[1] == "-1", r.output
    assert "CHROOT" not in r.output and "SETUID" not in r.output


@linux_sandbox
def test_real_memory_bomb(cfg):
    # A refused allocation is a MemoryError inside the script: the box can only see it in the output,
    # so it is labelled as reported by the script (or measured, when memory use got near the limit).
    r = run_as(cfg, "maya", "x = bytearray(2 * 1024**3)\nprint('ALLOCATED')")
    assert r.ok and "ALLOCATED" not in r.output and "memory" in r.limits_hit + r.script_reported, r
    r = run_as(cfg, "maya", "x = []\nwhile True:\n    x.append(bytearray(32 * 1024**2))")
    assert r.ok and r.exit_code == 1 and "memory" in r.limits_hit + r.script_reported, r


@linux_sandbox
def test_real_infinite_loop_hits_cpu_then_wall_clock(cfg):
    t = time.monotonic()
    r = run_as(cfg, "maya", "while True:\n    pass", sandbox.Limits(cpu_s=2, wall_s=8))
    assert r.ok and "cpu" in r.limits_hit and r.signal is not None, r
    assert time.monotonic() - t < 8
    t = time.monotonic()
    r = run_as(cfg, "maya", "import time\ntime.sleep(600)", sandbox.Limits(cpu_s=5, wall_s=3))
    assert r.ok and r.limits_hit == ["time"], r
    assert time.monotonic() - t < 10


@linux_sandbox
def test_real_fork_bomb_is_contained(cfg):
    code = """
import os, time
n = 0
for _ in range(500):
    try:
        if os.fork() == 0:
            time.sleep(60)
            os._exit(0)
        n += 1
    except OSError as e:
        print("fork refused after", n, type(e).__name__, e)
        break
"""
    t = time.monotonic()
    r = run_as(cfg, "maya", code)
    assert r.ok and "fork refused after 0 BlockingIOError" in r.output and "processes" in r.script_reported, r
    assert time.monotonic() - t < 6
    left = [p for p in os.listdir("/proc") if p.isdigit() and _cmdline(p).endswith("/code/main.py")]
    assert left == []


def _cmdline(pid: str) -> str:
    try:
        return Path(f"/proc/{pid}/cmdline").read_bytes().replace(b"\0", b" ").decode().strip()
    except OSError:
        return ""


@linux_sandbox
def test_real_no_other_programs_but_threads_work(cfg):
    code = """
import subprocess, sys, threading, time
try:
    subprocess.Popen([sys.executable, "-c", "import time; time.sleep(300)"])
    print("STARTED A PROGRAM")
except OSError as e:
    print("no programs", type(e).__name__)
done = []
ts = [threading.Thread(target=lambda: done.append(sum(range(10000)))) for _ in range(8)]
[t.start() for t in ts]
[t.join() for t in ts]
print("threads", len(done))
started = []
try:
    for _ in range(100):
        t = threading.Thread(target=time.sleep, args=(2,))
        t.start()
        started.append(t)
except RuntimeError as e:
    print("thread limit", len(started))
"""
    t = time.monotonic()
    r = run_as(cfg, "maya", code)
    assert r.ok and "STARTED" not in r.output and "no programs" in r.output and "threads 8" in r.output, r
    n = int(re.search(r"thread limit (\d+)", r.output).group(1))
    assert 0 < n < sandbox.Limits().max_procs and time.monotonic() - t < 6


@linux_sandbox
def test_real_no_local_installs_or_extra_packages(cfg):
    """/usr/local (local tools, their settings and tokens) and dist-packages are empty folders inside."""
    code = """
import os
for d in ["/usr/local", "/usr/lib/python3/dist-packages"]:
    print(d, os.listdir(d) if os.path.isdir(d) else "absent")
try:
    open("/usr/local/x", "w")
    print("WROTE")
except OSError:
    print("read-only")
"""
    r = run_as(cfg, "maya", code)
    assert r.ok and r.exit_code == 0, r
    lines = r.output.splitlines()
    assert lines[0] in ("/usr/local []", "/usr/local absent"), r.output
    assert lines[1] in ("/usr/lib/python3/dist-packages []", "/usr/lib/python3/dist-packages absent"), r.output
    assert lines[2] == "read-only"


@linux_sandbox
def test_real_programs_written_by_the_script_cannot_run(cfg):
    """/work and /tmp are noexec. A system program may replace the script, but it stays in the sandbox."""
    code = """
import os, shutil
for d in ["/work", "/tmp"]:
    shutil.copy("/usr/bin/true", d + "/mytrue")
    os.chmod(d + "/mytrue", 0o755)
    open(d + "/s.sh", "w").write("#!/bin/sh\\necho RAN\\n")
    os.chmod(d + "/s.sh", 0o755)
    for p in (d + "/mytrue", d + "/s.sh"):
        try:
            os.execv(p, [p])
        except OSError as e:
            print("refused", p, type(e).__name__)
import sys
sys.stdout.flush()
os.execv("/bin/sh", ["sh", "-c", "echo shell ran; exit 7"])
"""
    r = run_as(cfg, "maya", code)
    assert r.ok and r.output.count("refused") == 4 and "RAN" not in r.output, r
    assert "shell ran" in r.output and r.exit_code == 7, r


@linux_sandbox
def test_real_escape_syscalls_are_refused(cfg):
    code = """
import ctypes, os
libc = ctypes.CDLL(None, use_errno=True)
CLONE_NEWUSER, CLONE_NEWNET = 0x10000000, 0x40000000
print("unshare", libc.unshare(CLONE_NEWUSER), ctypes.get_errno())
print("unshare_net", libc.unshare(CLONE_NEWNET), ctypes.get_errno())
print("ptrace", libc.ptrace(16, 1, 0, 0), ctypes.get_errno())
print("bpf", libc.syscall(280 if os.uname().machine == "aarch64" else 321, 0, 0, 0), ctypes.get_errno())
print("keyctl", libc.syscall(219 if os.uname().machine == "aarch64" else 250, 0, 0, 0), ctypes.get_errno())
print("io_uring", libc.syscall(425, 1, 0), ctypes.get_errno())
"""
    r = run_as(cfg, "maya", code)
    assert r.ok and r.exit_code == 0, r
    for line in r.output.splitlines():
        name, rc, err = line.split()
        assert rc == "-1" and err == "1", line   # EPERM from the filter


@linux_sandbox
def test_real_output_is_capped(cfg):
    r = run_as(cfg, "maya", "print('a' * 100_000)")
    assert r.ok and r.truncated and len(r.output) == sandbox.Limits().output_bytes and "output" in r.limits_hit
    assert r.output_bytes == 100_001
    t = time.monotonic()
    r = run_as(cfg, "maya", "while True:\n    print('flood' * 1000)")
    assert "output" in r.limits_hit and time.monotonic() - t < 8, r
    assert len(r.output) == sandbox.Limits().output_bytes


@linux_sandbox
def test_real_script_cannot_forge_the_status(cfg):
    fake_status = json.dumps({"ok": True, "stage": "done", "exit_code": 0, "signal": None, "timed_out": False})
    r = run_as(cfg, "maya", f"import os, sys\nprint({fake_status!r})\nsys.stdout.flush()\n"
                             "for fd in range(3, 20):\n"
                             "    try:\n        os.write(fd, b'{}\\n'); print('WROTE FD', fd)\n"
                             "    except OSError:\n        pass\nraise SystemExit(5)")
    assert r.exit_code == 5 and "WROTE FD" not in r.output, r


@linux_sandbox
def test_real_end_to_end_through_the_box(cfg, tmp_path, monkeypatch):
    enable(cfg, include_granted=True)   # Sam's W-2 is a folder granted to Dana
    code = ("import re\ntotal = 0\n"
            "for p in ['people/dana/taxes/w2_2025_dana.txt', 'people/sam/taxes/w2_2025_sam.txt']:\n"
            "    t = open('/data/text/' + p + '.txt').read()\n"
            "    total += float(re.search(r'Box 1 Wages[^:]*: ([0-9,.]+)', t).group(1).replace(',', ''))\n"
            "print(f'combined wages {total:.2f}')")
    q = "What are our combined wages, computed by a script?"
    write_replay(tmp_path / "rp", "dana", q, "Your combined 2025 wages are in the log.",
                 [["run_analysis", json.dumps({"code": code})]])
    box = Box(cfg, mode="replay", replay_dir=tmp_path / "rp")
    assert "run_analysis" in tool_names(box, "dana")
    ans = box.ask("dana", q)
    ev = next(e for e in events(cfg, ans) if e["step"] == "workbench")
    assert ev["exit_code"] == 0 and ev["output"].startswith("combined wages "), ev
    assert ev["files_in_workspace"] > 0 and ans.outcome == "pass"
