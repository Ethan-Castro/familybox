"""Recompute the pinning fingerprints from the raw keyless attestation captures (no network).

  uv run python spikes/pin_stability.py            # print per-capture fingerprints
  uv run python spikes/pin_stability.py --shipped  # also print the shipped pins file built from them

Captures (spikes/captures/2026-11-09/, public attestation data from verify() with no API key):
  att1.json, att2.json   model instance gpu02 (INSTANCE_LABEL=gpu02), two minutes apart
  att3.json              model instance gpu04
  samples.json           6 back-to-back samples; the only capture with TDX quote values (MRTD, RTMR0-2).
                         Every model sample there came from gpu04.
att*.json were captured before the box recorded quotes, so gpu02's TD values are unknown. The model
fingerprints printed for att1/att2 reuse gpu04's TD values and so only show that everything else matches.
"""

import json
import sys
import types
from pathlib import Path

from familybox import pinning

D = Path(__file__).resolve().parent / "captures" / "2026-11-09"
MODEL = "deepseek-ai/DeepSeek-V4.1-Flash-1017"


def dep(d):
    cm = d["compose_manager"]
    return types.SimpleNamespace(app_compose=d["app_compose"],
                                 runtime_measurements=types.SimpleNamespace(**d["runtime_measurements"]),
                                 compose_manager=types.SimpleNamespace(actions=cm["actions"]) if cm else None)


def main() -> None:
    samples = json.loads((D / "samples.json").read_text())
    td = {}
    for s in samples:
        for r in s:
            if r.get("c") and "td" in r["fields"]:
                td.setdefault(r["c"], set()).add(json.dumps(r["fields"]["td"]))
    print("distinct TD values per component across the samples:", {c: len(v) for c, v in td.items()})
    td = {c: json.loads(next(iter(v))) for c, v in td.items()}
    last = {}
    for n in (1, 2, 3):
        a = json.loads((D / f"att{n}.json").read_text())
        ms = (pinning.measure("gateway", None, dep(a["gateway"]["deployment"]), td["gateway"])
              + pinning.measure("model", MODEL, dep(a["models"][0]["deployment"]), td[f"model/{MODEL}"]))
        for m in ms:
            extra = ""
            if m.component.endswith("/workload"):
                extra = f"{len(m.fields['standing'])} compose files standing"
            elif "allowed_envs_per_instance" in m.info:
                extra = f"per-instance envs left out: {m.info['allowed_envs_per_instance']}"
            print(f"att{n}  {m.component:<55} {m.fp[:16]}  {extra}")
        last = {m.component: m for m in ms}
    if "--shipped" in sys.argv:
        comps = {c: [{"fp": m.fp, "fields": m.fields, "seen": "November 9, 2026", "instance": "gpu04"}]
                 for c, m in last.items() if not c.endswith("/workload")}
        print(json.dumps({"version": 1, "components": comps}, indent=1))


if __name__ == "__main__":
    main()
