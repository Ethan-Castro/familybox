"""How often the concept judge in eval/attacks.py agrees with hand labels on the committed paraphrase answers.

Run:  uv run python eval/judge_agreement.py
Prints, for the judge as committed now: agreement, false positives and misses, per answer.
"""

from __future__ import annotations

import importlib.util
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
RESULTS = {"run1": ROOT / "eval/results/2026-11-08/attacks_paraphrase_run1.jsonl",
           "run2": ROOT / "eval/results/2026-11-08/attacks_paraphrase_run2.jsonl"}
LABELS = ROOT / "eval/labels/paraphrase_2026-11-08.json"


def _attacks():
    spec = importlib.util.spec_from_file_location("fb_eval_attacks", ROOT / "eval" / "attacks.py")
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def agreement() -> dict:
    ev = _attacks()
    forbidden = {a[0]: a[4] for a in ev.ATTACKS}
    answers = {}
    for run, path in RESULTS.items():
        for line in path.read_text().splitlines():
            r = json.loads(line)
            answers[(run, r["arm"], r["id"])] = r["answer"]
    rows = []
    for lab in json.loads(LABELS.read_text())["labels"]:
        key = (lab["run"], lab["arm"], lab["id"])
        hits = ev.leaked(answers[key], forbidden[lab["id"]])
        rows.append({"key": key, "label": lab["leak"], "judge": bool(hits), "hits": hits, "note": lab["note"]})
    return {"rows": rows, "n": len(rows), "agree": sum(r["label"] == r["judge"] for r in rows),
            "false_positives": [r["key"] for r in rows if r["judge"] and not r["label"]],
            "misses": [r["key"] for r in rows if r["label"] and not r["judge"]]}


def main() -> int:
    a = agreement()
    print(f"judge agrees with hand labels on {a['agree']} of {a['n']} answers")
    for r in a["rows"]:
        mark = "ok  " if r["label"] == r["judge"] else "DIFF"
        print(f"{mark} {' '.join(r['key']):18s} label={'leak' if r['label'] else 'none':4s} "
              f"judge={'leak' if r['judge'] else 'none':4s} {r['hits']}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
