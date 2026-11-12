"""Owner review of NEAR code changes, by the owner's rule (2026-11-12):

  "Use the normal model, accept abliterated neighbors."

NEAR runs abliterated models (refusal training removed) as separate models on the same sealed machines
as the normal ones, each behind its own service. familybox only ever asks for the normal model. So:

- **Deployment-list changes** (model/<id>/workload) are trusted when the normal model's own service is
  still deployed (for DeepSeek V4.1 Flash, `proxy-dsv41`), whatever runs next to it. When the list of
  services can't be seen, the change is trusted only if nothing in it mentions abliterated.
- **Every other change** (the gateway, the model machine's own code, its manager) is rejected if it
  mentions abliterated anywhere, and trusted otherwise.
- A model whose own name is abliterated is never trusted (the box also refuses to call one).

Re-checks reviews rejected earlier too. Every decision lands in the box's NEAR code history, like a review
on the /pins page. Run in the box's environment:

    FAMILYBOX_HOME=... uv run python scripts/pins_review_clean.py --as dana
"""
import argparse
import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))
from familybox import config  # noqa: E402
from familybox.pinning import PinStore  # noqa: E402

# The normal model's own service on NEAR's machines, from the compose manager's signed log.
OWN_SERVICE = {
    "deepseek-ai/DeepSeek-V4.1-Flash-1017": "proxy-dsv41",
    "z-ai/glm-5.3-flash": "proxy-glm53",
    "Qwen/Qwen3.6-35B-A3B-FP8": "proxy-qwen36-35b-a3b",
    "Qwen/Qwen3-VL-30B-A3B-Instruct": "proxy-qwen3vl-30b-a3b",
}


def services_for(store: PinStore, review_id: str) -> list[str]:
    for e in reversed(store.history()):
        if e.get("review") == review_id and e.get("event") == "changed":
            return sorted((e.get("info") or {}).get("service_updates") or {})
    return []


def judge(store: PinStore, r: dict) -> tuple[bool, str]:
    comp = r["component"]
    text = json.dumps(store.diff(r["id"]), default=str).lower()
    if "abliterat" in comp.lower():
        return False, "the model itself is abliterated"
    if comp.endswith("/workload"):
        model = comp[len("model/"):-len("/workload")]
        svcs = services_for(store, r["id"])
        own = OWN_SERVICE.get(model)
        if svcs and own:
            return (own in svcs, f"its own service {own} {'is' if own in svcs else 'is NOT'} still deployed"
                    + ("; abliterated neighbors next to it" if "abliterat" in " ".join(svcs) else ""))
        return ("abliterat" not in text, "services not visible; " + ("mentions abliterated" if "abliterat" in text
                                                                     else "nothing abliterated"))
    return ("abliterat" not in text, "mentions abliterated" if "abliterat" in text else "nothing abliterated")


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--as", dest="person", required=True)
    args = ap.parse_args()
    cfg = config.load()
    if not cfg.person(args.person).admin:
        print(f"{args.person} does not run the box")
        return 2
    store = PinStore(cfg)
    rejected = 0
    for r in store.reviews("waiting") + store.reviews("rejected"):
        ok, why = judge(store, r)
        if r["status"] == "rejected" and not ok:
            continue                                  # already rejected, and still should be
        store.decide(r["id"], ok, args.person)
        rejected += not ok
        changed = sorted({c.get("field", "?") for c in store.diff(r["id"]).get("changes", []) if isinstance(c, dict)})
        print(f"{'trusted ' if ok else 'REJECTED'} {r['id']} {r['component']} ({', '.join(changed) or 'n/a'}): {why}")
    return 1 if rejected else 0


if __name__ == "__main__":
    sys.exit(main())
