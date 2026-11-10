"""Side-by-side log: the same question through familybox and through a plain chatbot that has the files.

Reads one results file written by eval/attacks.py and writes a readable log, one entry per question:
what the box did step by step (from the box's own event record), what the assistant received, and
what the plain-chatbot setup read and said.

"Plain chatbot" here is the eval's `open` arm: the same NEAR model with every family file readable
and nothing checking the reply. It stands in for pasting or uploading the files into a chatbot. It is
not a run against ChatGPT or Claude, and it does not measure what such a service stores afterwards.

Run:  uv run python eval/compare_log.py eval/results/<date>/attacks_<tag>.jsonl
Writes eval/reports/compare_<date>_<tag>.md
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from familybox import access, config  # noqa: E402

CFG = config.load(ROOT / "demo")
LABEL = {"box": "familybox", "no_gate": "Box tools, reply not checked", "open": "Plain chatbot with the files"}


def others_files(row: dict) -> list[str]:
    """Files read that the asker is not allowed to read under the family's own rules (demo/family.toml)."""
    person = CFG.person(row["asker"])
    return [p for p in row.get("files_read") or [] if not access.can_read(person, p)]


def quote(text: str, limit: int = 900) -> str:
    text = (text or "").strip() or "(nothing)"
    if len(text) > limit:
        text = text[:limit].rstrip() + " [...]"
    return "\n".join("> " + line for line in text.splitlines())


def steps(events: list[dict]) -> list[str]:
    """The box's event record as short lines. Events hold no file text or answer text."""
    out = []
    for e in events:
        s, t = e.get("step"), f"{e.get('t', 0):5.1f}s"
        if s == "attestation":
            out.append(f"{t}  enclave proof checked for `{e.get('model')}` "
                       f"({e.get('reports_verified')} report), encrypted end to end: {e.get('e2ee')}")
        elif s == "turn":
            calls = ", ".join(c.get("name", "") for c in e.get("tool_calls") or []) or "writes its reply"
            out.append(f"{t}  model turn {e.get('index')}, signed by the enclave (`{e.get('signature_kind')}`): {calls}")
        elif s == "tool":
            a = e.get("arguments") or {}
            what = a.get("path") or a.get("query") or ""
            if e.get("ok"):
                out.append(f"{t}  {e.get('name')} `{what}`")
            else:
                out.append(f"{t}  {e.get('name')} `{what}` BLOCKED ({e.get('why')})")
        elif s == "gate":
            held = e.get("held") or []
            out.append(f"{t}  answer gate: **{e.get('outcome')}**" + (f", held back: {json.dumps(held)}" if held else ""))
        elif s == "paraphrase_check":
            out.append(f"{t}  second check (`{e.get('model', '')}`): reveals a protected fact in other words: "
                       f"{e.get('reveals')}, action: {e.get('action')}")
        elif s == "post_checks":
            out.append(f"{t}  after all checks: **{e.get('outcome')}**")
        elif s == "answer":
            out.append(f"{t}  sent to the assistant: **{e.get('outcome')}** ({e.get('files_read')} files read, "
                       f"{e.get('files_denied')} denied)")
        elif s in ("error", "pre_check_stopped", "post_check_stopped"):
            out.append(f"{t}  stopped: {e.get('message')}")
    return out


def verdict(row: dict) -> str:
    if row["outcome"] == "error":
        return "no answer (stopped, nothing sent)"
    if row["kind"] == "utility":
        return "answered correctly" if row.get("useful") else "NOT answered correctly"
    return ("**LEAK**: " + ", ".join(f"`{x}`" for x in row["leaked"])) if row.get("leaked") else "no leak"


def main() -> int:
    if len(sys.argv) != 2:
        print(__doc__)
        return 2
    src = Path(sys.argv[1]).resolve()
    rows = [json.loads(line) for line in src.read_text().splitlines() if line.strip()]
    by = {(r["id"], r["arm"]): r for r in rows}
    ids = list(dict.fromkeys(r["id"] for r in sorted(rows, key=lambda r: (r["kind"], r["category"], r["id"]))))
    arms = [a for a in ("box", "no_gate", "open") if any(r["arm"] == a for r in rows)]
    attacks = [r for r in rows if r["kind"] == "attack"]
    n_att = len({r["id"] for r in attacks})
    n_ut = len({r["id"] for r in rows if r["kind"] == "utility"})

    L = [f"# Same questions, two ways: familybox and a plain chatbot ({src.parent.name})", "",
         f"Source rows: `{src.relative_to(ROOT)}`. Fictional family, live NEAR AI Cloud run.", "",
         "**familybox**: the assistant asks the box. An enclave model reads only the asker's files, and the box "
         "checks the reply against the real values before anything is sent.",
         "**Plain chatbot with the files**: the same model, every family file readable, the reply sent as written. "
         "This stands in for pasting or uploading the drawer into a chatbot. It is not a run against ChatGPT or "
         "Claude, and it does not count what such a service keeps afterwards (it would keep every file it was given).",
         "", "## Scoreboard", "",
         "| | " + " | ".join(LABEL[a] for a in arms) + " |", "|---|" + "---|" * len(arms)]

    def cell(fn):
        return " | ".join(str(fn(a)) for a in arms)
    L.append(f"| Attacks that leaked (of {n_att}) | " + cell(
        lambda a: sum(1 for r in attacks if r["arm"] == a and r.get("leaked"))) + " |")
    L.append("| Attacks that leaked, not counting reworded hints | " + cell(
        lambda a: sum(1 for r in attacks if r["arm"] == a and r.get("leaked") and r["category"] != "paraphrase")) + " |")
    L.append(f"| Normal questions answered correctly (of {n_ut}) | " + cell(
        lambda a: sum(1 for r in rows if r["arm"] == a and r["kind"] == "utility" and r.get("useful"))) + " |")
    L.append("| Questions where a file the asker may not read was read | " + cell(
        lambda a: sum(1 for r in rows if r["arm"] == a and others_files(r))) + " |")
    L.append("| Questions stopped with no answer | " + cell(
        lambda a: sum(1 for r in rows if r["arm"] == a and r["outcome"] == "error")) + " |")
    L.append("| Median seconds per question | " + cell(
        lambda a: sorted(r["seconds"] for r in rows if r["arm"] == a)[len([r for r in rows if r["arm"] == a]) // 2]) + " |")
    L += ["", "Leaks are judged by the checker in `eval/attacks.py`, not by the box. Reworded-hint attacks are "
          "judged by word stems and over-count on purpose. \"May not read\" follows the family's own rules: "
          "each person's files are theirs, parents can read a child's non-health files, health is owner-only.", ""]

    for jid in ids:
        any_row = next(r for r in rows if r["id"] == jid)
        L += [f"## {jid} ({any_row['category']}): {any_row['asker']} asks", "", quote(any_row["question"]), ""]
        for arm in arms:
            r = by.get((jid, arm))
            if not r:
                continue
            L += [f"### {LABEL[arm]}: {verdict(r)}", ""]
            if arm == "box" and r.get("events"):
                L += ["What the box did:", "", "```"] + steps(r["events"]) + ["```", ""]
            files = r.get("files_read") or []
            L.append(f"Files read ({len(files)}): " + (", ".join(f"`{p}`" for p in files) or "none"))
            if o := others_files(r):
                L.append("Of those, not the asker's to read: " + ", ".join(f"`{p}`" for p in o))
            L += ["", "What the assistant received:", "", quote(r.get("answer") or r.get("error", "")), ""]
    out = ROOT / "eval" / "reports" / f"compare_{src.parent.name}{src.stem.removeprefix('attacks')}.md"
    out.write_text("\n".join(L) + "\n")
    print(out)
    return 0


if __name__ == "__main__":
    sys.exit(main())
