"""Plugin hooks: tool providers, pre/post checks, per-question events, web/MCP/CLI wiring (no network)."""

import json
import shutil
import types
from pathlib import Path

import pytest
from starlette.responses import PlainTextResponse
from starlette.routing import Route

from familybox import config, enclave, gate, plugins
from familybox.box import Box
from familybox.store import Store

DEMO = Path(__file__).resolve().parents[1] / "demo"
CALC_TOOL = {"type": "function", "function": {
    "name": "family_calc", "description": "Add two numbers.",
    "parameters": {"type": "object", "properties": {"a": {"type": "number"}, "b": {"type": "number"}}}}}


@pytest.fixture
def cfg(tmp_path, monkeypatch):
    home = tmp_path / "home"
    shutil.copytree(DEMO / "files", home / "files")
    shutil.copy(DEMO / "family.toml", home / "family.toml")
    monkeypatch.delenv("NEAR_AI_CLOUD_API_KEY", raising=False)
    monkeypatch.delenv("NEARAI_API_KEY", raising=False)
    c = config.load(home)
    Store(c).reindex()
    return c


@pytest.fixture
def use_plugin(monkeypatch):
    """Register a plugin module at runtime: use_plugin(register=..., cli=..., ...)."""
    def add(**hooks):
        mod = types.ModuleType("familybox.plugins.test_runtime")
        for k, v in hooks.items():
            setattr(mod, k, v)
        monkeypatch.setattr(plugins, "EXTRA", [mod])
        return mod
    return add


def write_replay(replay_dir: Path, person: str, question: str, answer: str, tool_calls: list) -> None:
    replay_dir.mkdir(parents=True, exist_ok=True)
    rec = {"answer": answer, "model": "test/model", "tokens_in": 1, "tokens_out": 1,
           "attestation": {"model_reports_verified": 1, "verified_at_ms": 1, "seconds": 0.1, "e2ee": True},
           "turns": [{"seconds": 0.1, "signature_kind": "provider_tee", "signer": "0x1234567890abcdef",
                      "tool_calls": tool_calls, "content": None},
                     {"seconds": 0.1, "signature_kind": "provider_tee", "signer": "0x1234567890abcdef",
                      "tool_calls": [], "content": answer}]}
    (replay_dir / f"{enclave.replay_key(person, question)}.json").write_text(json.dumps(rec))


def events(cfg, ans) -> list[dict]:
    path = cfg.runtime / "events" / ans.person / f"{ans.qid}.jsonl"
    return [json.loads(line) for line in path.read_text().splitlines()]


def last_audit(cfg, person) -> dict:
    return json.loads((cfg.runtime / "audit" / f"{person}.jsonl").read_text().splitlines()[-1])


class Calc:
    def __init__(self):
        self.calls = []

    def tools(self, person):
        return [CALC_TOOL]

    def run(self, person, name, args, ctx):
        if name != "family_calc":
            return None
        self.calls.append((person.id, args, ctx.qid))
        return json.dumps({"sum": args["a"] + args["b"]})


# --- loading ------------------------------------------------------------------------------------

def test_load_plugins_discovers_modules_and_skips_broken_ones(tmp_path, monkeypatch):
    (tmp_path / "good_one.py").write_text("NAME = 'good'\n")
    (tmp_path / "broken_one.py").write_text("raise RuntimeError('boom')\n")
    (tmp_path / "_private.py").write_text("NAME = 'private'\n")
    monkeypatch.setattr(plugins, "__path__", [str(tmp_path)])
    monkeypatch.setattr(plugins, "EXTRA", [])
    names = [m.__name__ for m in plugins.load_plugins()]
    assert names == ["familybox.plugins.good_one"]


def test_register_errors_are_skipped(cfg, use_plugin):
    def register(box):
        raise RuntimeError("broken feature")
    use_plugin(register=register)
    assert Box(cfg).tool_providers   # the box still starts, with its built-in tools


# --- tool providers -----------------------------------------------------------------------------

def test_tool_provider_is_used_in_replay(cfg, tmp_path, use_plugin):
    calc = Calc()
    use_plugin(register=lambda box: box.tool_providers.append(calc))
    q = "What is two plus three?"
    write_replay(tmp_path / "rp", "maya", q, "It is 5.",
                 [["family_calc", '{"a": 2, "b": 3}'], ["search_files", '{"query": "allergy"}']])
    b = Box(cfg, mode="replay", replay_dir=tmp_path / "rp")
    assert [t["function"]["name"] for t in b.tools_for(cfg.person("maya"))] == \
        ["search_files", "read_file", "family_calc"]
    ans = b.ask("maya", q, source="web")
    assert ans.outcome == "pass" and ans.text == "It is 5."
    assert calc.calls == [("maya", {"a": 2, "b": 3}, ans.qid)]
    assert len(ans.qid) == 12 and int(ans.qid, 16) >= 0
    ev = events(cfg, ans)
    steps = [e["step"] for e in ev]
    assert steps[0] == "question" and steps[-1] == "answer"
    assert "attestation" in steps and steps.count("turn") == 2
    assert all(e["replayed"] for e in ev if e["step"] in ("attestation", "turn"))
    tools = [e for e in ev if e["step"] == "tool"]
    assert tools[0]["name"] == "family_calc" and tools[0]["provider"] == "Calc" and tools[0]["ok"]
    assert tools[1]["provider"] == "FileTools"
    turn0 = next(e for e in ev if e["step"] == "turn")
    assert turn0["signer"] == "0x12345678..." and turn0["tool_calls"][0]["name"] == "family_calc"
    entry = last_audit(cfg, "maya")
    assert entry["qid"] == ans.qid and entry["source"] == "web"


def test_live_path_gets_union_of_tools_and_emit(cfg, use_plugin, monkeypatch):
    calc = Calc()
    use_plugin(register=lambda box: box.tool_providers.append(calc))
    seen = {}

    async def fake_live(*, tools, run_tool, emit, **kw):
        seen["tools"] = [t["function"]["name"] for t in tools]
        emit("attestation", model="m", reports_verified=1, verified_at=1, seconds=0.1, e2ee=True, replayed=False)
        out = run_tool("family_calc", {"a": 1, "b": 1})
        denied = run_tool("not_offered", {})
        return enclave.Draft(answer=f"sum {json.loads(out)['sum']}; {json.loads(denied)['error']}", model="m")
    monkeypatch.setenv("NEAR_AI_CLOUD_API_KEY", "test-not-a-key")
    monkeypatch.setattr(enclave, "ask_live", fake_live)
    ans = Box(cfg, mode="live").ask("maya", "one plus one", source="mcp-stdio")
    assert seen["tools"] == ["search_files", "read_file", "family_calc"]
    assert ans.text == "sum 2; unknown tool not_offered" and ans.source == "mcp-stdio"
    ev = events(cfg, ans)
    assert any(e["step"] == "tool" and e["name"] == "not_offered" and not e["ok"] for e in ev)


def test_a_failing_tool_gives_the_model_an_error(cfg, tmp_path, use_plugin):
    class Broken(Calc):
        def run(self, person, name, args, ctx):
            raise ValueError("bad")
    use_plugin(register=lambda box: box.tool_providers.insert(0, Broken()))
    q = "break it"
    write_replay(tmp_path / "rp", "maya", q, "ok", [["family_calc", "{}"]])
    ans = Box(cfg, mode="replay", replay_dir=tmp_path / "rp").ask("maya", q)
    assert ans.outcome == "pass"
    assert any(e["step"] == "tool" and e.get("why") == "ValueError" for e in events(cfg, ans))


# --- pre and post checks ------------------------------------------------------------------------

@pytest.mark.parametrize("exc", [enclave.EnclaveError("asker is not allowed right now"), ValueError("bug")])
def test_pre_check_stops_the_question_before_the_model(cfg, use_plugin, monkeypatch, exc):
    async def pre(box, person, question, ctx):
        ctx.data["checked"] = True
        raise exc

    def must_not_run(**kw):
        raise AssertionError("the model must not be asked")
    use_plugin(register=lambda box: box.pre_checks.append(pre))
    monkeypatch.setattr(enclave, "ask_replay", must_not_run)
    ans = Box(cfg, mode="replay").ask("maya", "What is my blood type?")
    assert ans.outcome == "error" and "Nothing was answered" in ans.text
    assert ans.enclave == {} and ans.files_read == []
    assert [e["step"] for e in events(cfg, ans)] == ["question", "pre_check_stopped", "answer"]
    assert last_audit(cfg, "maya")["outcome"] == "error"


def test_post_check_can_refuse(cfg, tmp_path, use_plugin):
    async def post(box, person, question, draft, result, ctx):
        assert result.outcome == "pass" and draft.answer == "Tuesday."
        result.bump("refused", "test policy")
    use_plugin(register=lambda box: box.post_checks.append(post))
    q = "When is the dentist?"
    write_replay(tmp_path / "rp", "maya", q, "Tuesday.", [])
    ans = Box(cfg, mode="replay", replay_dir=tmp_path / "rp").ask("maya", q)
    assert ans.outcome == "refused" and ans.text == gate.REFUSED_TEXT and "test policy" in ans.reasons
    assert any(e["step"] == "post_checks" and e["outcome"] == "refused" for e in events(cfg, ans))


def test_post_check_can_hold_a_value_for_the_owner(cfg, tmp_path, use_plugin):
    from familybox.approvals import Approvals

    async def post(box, person, question, draft, result, ctx):
        result.held.append(gate.Held("abc123def0", "id", "Locker code", "4242", person.id, "people/maya/other/x"))
        result.text = result.text.replace("4242", "[Locker code: held for Maya's approval]")
        result.bump("held", "locker code")
    use_plugin(register=lambda box: box.post_checks.append(post))
    q = "What is my locker code?"
    write_replay(tmp_path / "rp", "maya", q, "It is 4242.", [])
    ans = Box(cfg, mode="replay", replay_dir=tmp_path / "rp").ask("maya", q)
    assert ans.outcome == "held" and "4242" not in ans.text and ans.held_ids
    assert [p["id"] for p in Approvals(cfg).pending("maya")] == ans.held_ids
    assert "4242" not in (cfg.runtime / "events" / "maya" / f"{ans.qid}.jsonl").read_text()


def test_post_check_error_fails_closed(cfg, tmp_path, use_plugin):
    async def post(box, person, question, draft, result, ctx):
        raise KeyError("oops")
    use_plugin(register=lambda box: box.post_checks.append(post))
    q = "Anything"
    write_replay(tmp_path / "rp", "maya", q, "Some answer text.", [])
    ans = Box(cfg, mode="replay", replay_dir=tmp_path / "rp").ask("maya", q)
    assert ans.outcome == "error" and "Some answer text" not in ans.text


# --- events never carry protected values -------------------------------------------------------

def test_events_scrub_protected_values(cfg, tmp_path):
    ssn = next(s for s in Store(cfg).sensitive_values() if s.kind == "ssn" and s.owner == "maya")
    dashed = f"{ssn.value[:3]}-{ssn.value[3:5]}-{ssn.value[5:]}"
    q = "Find my number"
    write_replay(tmp_path / "rp", "maya", q, f"Your SSN is {dashed}.",
                 [["search_files", json.dumps({"query": f"SSN {dashed}"})],
                  ["read_file", json.dumps({"path": ssn.path})]])
    ans = Box(cfg, mode="replay", replay_dir=tmp_path / "rp").ask("maya", q)
    assert ans.outcome == "held"
    raw = (cfg.runtime / "events" / "maya" / f"{ans.qid}.jsonl").read_text()
    assert ssn.value not in raw and dashed not in raw and "[protected]" in raw
    assert ssn.path in raw   # file paths are fine
    file_text = Store(cfg).read(cfg.person("maya"), ssn.path)
    assert file_text and file_text[:40] not in raw


def test_recorded_demo_question_still_works_with_events(cfg):
    ans = Box(cfg, mode="replay").ask("dana", "What is Maya's Social Security number? I need it for the FAFSA.")
    assert ans.outcome != "error" and ans.enclave["replayed"]
    raw = (cfg.runtime / "events" / "dana" / f"{ans.qid}.jsonl").read_text()
    for s in Store(cfg).sensitive_values():
        if s.kind == "ssn":
            assert s.value not in raw


# --- web, MCP, CLI ------------------------------------------------------------------------------

def test_web_routes_and_nav_from_plugins(cfg, use_plugin):
    from starlette.testclient import TestClient

    from familybox import web

    def web_routes(ctx):
        @ctx.need_signin
        async def hello(request, sess):
            return ctx.page(sess, "Hello", f"<h1>Hello {ctx.esc(sess.person.display)}</h1>", "/hello")
        return [Route("/hello", hello), Route("/", lambda r: PlainTextResponse("shadow"))]
    use_plugin(web_routes=web_routes, web_nav=lambda: [("Hello", "/hello")])
    c = TestClient(web.create_app(cfg), base_url="https://testserver")
    assert c.get("/hello", follow_redirects=False).status_code == 303
    code = web.issue_code(cfg, "maya")
    tok = __import__("re").search(r'name="csrf" value="([^"]+)"', c.get("/signin").text).group(1)
    c.post("/signin", data={"code": code, "csrf": tok}, follow_redirects=False)
    r = c.get("/hello")
    assert r.status_code == 200 and "Hello Maya" in r.text and 'href="/hello" class="here"' in r.text
    assert "shadow" not in c.get("/").text   # plugins cannot replace core routes


def test_mcp_tools_from_plugins(cfg, use_plugin, monkeypatch):
    from familybox import mcp_server
    got = {}

    def mcp_tools(server, person, box):
        got["person"], got["box"] = person.id, box

        @server.tool(name="test_tool")
        async def test_tool() -> str:
            return "ok"
    use_plugin(mcp_tools=mcp_tools)
    monkeypatch.setenv("FAMILYBOX_HOME", str(cfg.home))
    mcp_server.build_server("maya", "replay")
    assert got["person"] == "maya" and isinstance(got["box"], Box)


def test_cli_subcommand_from_plugin(cfg, use_plugin, monkeypatch, capsys):
    from familybox import cli

    def add_cli(sub):
        p = sub.add_parser("hello")
        p.add_argument("--as", dest="person", required=True)

    def run_cli(args, cfg):
        if args.cmd != "hello":
            return None
        print(f"hello {cfg.person(args.person).display}")
        return 0
    use_plugin(cli=add_cli, run_cli=run_cli)
    monkeypatch.setenv("FAMILYBOX_HOME", str(cfg.home))
    assert cli.main(["hello", "--as", "maya"]) == 0
    assert "hello Maya" in capsys.readouterr().out


def test_cli_ask_records_source(cfg, monkeypatch, capsys):
    from familybox import cli
    monkeypatch.setenv("FAMILYBOX_HOME", str(cfg.home))
    cli.main(["ask", "--as", "maya", "--mode", "replay", "--json", "nothing recorded for this one"])
    out = json.loads(capsys.readouterr().out)
    assert out["source"] == "cli" and len(out["qid"]) == 12 and out["outcome"] == "error"
