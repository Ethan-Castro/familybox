"""Pin what the box verified about NEAR AI Cloud, and stop questions when NEAR's serving code changes.

TEE attestation proves the model ran in an enclave. It does not say *which* code ran there, and NEAR
redeploys. So the box keeps a "measurement fingerprint" for each part of the path a question takes:

  gateway                 NEAR's API gateway CVM (TLS, routing, E2EE pass-through)
  model/<id>              the model CVM: firmware, kernel, OS, its compose file, container images and
                          the env var names the operator may set at runtime
  model/<id>/manager      the compose manager image: the program inside the model CVM that installs
                          and runs the model containers
  model/<id>/workload     the compose files that manager says are still deployed, by sha256

The first verified use is pinned (trust on first use), unless a shipped pins file in the repo already
names the expected values. Every later live question is checked inside the SDK's own verification
(the gateway deployment verifier and the model deployment_policy) before any prompt is sent. The check
covers the reports the box verified for this question. NEAR's model instances share one signing key,
so another instance running different code could still receive the prompt (see "Limits" in
docs/BUILD_LOG.md). If a fingerprint is new, the question stops before any prompt is sent, an owner
review item is created, and every question stops until the owner accepts or rejects it
(`familybox pins`, or the box page /pins).

Levels: "strict" stops for any change. "platform" still stops for the gateway, the model enclave and
the compose manager, and only logs which model compose files were deployed. "off" checks nothing.

What goes into a fingerprint is what was the same across instances in live runs (docs/BUILD_LOG.md):
MRTD and RTMR0-2 from the verified TDX quote, the dstack OS image hash, the app-compose settings,
container images and allowed env names (minus a short list seen to differ per instance), and the
compose text with the INSTANCE_LABEL line masked. The raw compose hash and MRCONFIGID are kept as
information only: they differ per model instance (INSTANCE_LABEL=gpu02 vs gpu04).

pins.json holds accepted fingerprints, review items and the head of the history. pins_history.jsonl
is append-only and hash chained, and pins.json records its newest hash and length, so removing or
editing any entry shows, unless someone rewrites both files together.
"""

from __future__ import annotations

import contextlib
import datetime as dt
import fcntl
import hashlib
import json
import os
import re
import secrets
import threading
import time
from collections.abc import Callable
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from .config import Config
from .enclave import EnclaveError

REPO_PINS = Path(__file__).resolve().parents[2] / "pins" / "near-ai-cloud.json"
LEVELS = ("strict", "platform", "off")   # same as box.PIN_LEVELS
GENESIS = "0" * 64

# Lines in a compose file that name the instance, not the code. Masked before hashing. Only keys seen
# to differ between instances in live data go here (docs/BUILD_LOG.md); add others only with evidence.
PER_INSTANCE_KEYS = ("INSTANCE_LABEL",)
_MASK = re.compile(r"(?m)^(\s*-?\s*[\"']?(?:" + "|".join(PER_INSTANCE_KEYS) + r")\s*[=:]).*$")
_IMAGE = re.compile(r"(?m)^\s*image:\s*[\"']?([^\s\"'#]+)")
# Env var names the operator may set on one model instance but not another, matched exactly. Seen in
# live data: model instance gpu02 allowed these 4 and gpu04 did not. Every other allowed env name is fingerprinted, because
# an allowed env is a value NEAR can inject at runtime without changing any measurement.
PER_INSTANCE_ENVS = frozenset({"AWS_REGION", "AWS_ACCESS_KEY_ID", "AWS_SECRET_ACCESS_KEY", "AWS_S3_BUCKET"})
# How often a matching check refreshes last_ok in pins.json (fewer SD card writes on the Pi).
SAVE_EVERY_S = 300
# app-compose settings that change what runs or who can reach it.
FLAG_KEYS = ("manifest_version", "name", "runner", "kms_enabled", "gateway_enabled", "local_key_provider_enabled",
             "key_provider_id", "public_logs", "public_sysinfo", "no_instance_id", "secure_time", "port_policy")
_HEX_ID = re.compile(r"^[0-9a-f]{12}$")


class PinError(EnclaveError):
    """A pinned measurement changed, or the pin files are unreadable. The question stops."""


def _sha(text: str | bytes) -> str:
    return hashlib.sha256(text.encode() if isinstance(text, str) else text).hexdigest()


def _canon(obj) -> str:
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), default=str)


def fingerprint_of(fields: dict) -> str:
    return _sha(_canon(fields))


def nice_date(ts: float | str | None) -> str:
    """'November 8, 2026' from epoch seconds or an RFC 3339 timestamp."""
    try:
        if isinstance(ts, str):
            d = dt.datetime.fromisoformat(ts[:19]).replace(tzinfo=dt.UTC)
        else:
            d = dt.datetime.fromtimestamp(float(ts if ts is not None else time.time()), dt.UTC)
    except (TypeError, ValueError):
        d = dt.datetime.now(dt.UTC)
    return f"{d:%B} {d.day}, {d.year}"


# ---------------------------------------------------------------- TDX quote measurements

# Offsets in an Intel TDX quote (v4 and v5, TD 1.0 report body). v5 adds a 6-byte body descriptor.
_TD_FIELDS = {"mrtd": (136, 48), "mrconfigid": (184, 48), "rtmr0": (328, 48), "rtmr1": (376, 48),
              "rtmr2": (424, 48), "rtmr3": (472, 48), "report_data": (520, 64)}


def td_measurements(quote: bytes) -> dict[str, str]:
    """Read MRTD, MRCONFIGID and RTMR0-3 from a quote the SDK has already verified."""
    if len(quote) < 48:
        raise ValueError("quote too short")
    version = int.from_bytes(quote[0:2], "little")
    if version == 4:
        body = 48
    elif version == 5:
        body = 54
    else:
        raise ValueError(f"unsupported quote version {version}")
    out = {}
    for name, (off, size) in _TD_FIELDS.items():
        chunk = quote[body + off: body + off + size]
        if len(chunk) != size:
            raise ValueError("quote too short")
        out[name] = chunk.hex()
    return out


class QuoteLog:
    """Wraps the SDK's TDX quote verifier and remembers each verified quote's measurements.

    Keyed by sha256(app_compose): the SDK checks that MRCONFIGID is 0x01 || sha256(app_compose)
    after the quote verifies, so a deployment callback can find its own quote's measurements. If
    several quotes share one app-compose, measure() fingerprints each quote on its own, so the result
    never depends on how many instances answered or in what order.
    """

    def __init__(self, inner: Callable | None = None):
        self._inner = inner
        self.by_compose: dict[str, list[dict]] = {}
        self._lock = threading.Lock()

    async def __call__(self, quote_hex: str):
        if self._inner is None:
            from nearai_inference_sdk.utils.intel import verify_dcap_quote
            inner = verify_dcap_quote
        else:
            inner = self._inner
        res = inner(quote_hex)
        if hasattr(res, "__await__"):
            res = await res
        m = td_measurements(bytes.fromhex(quote_hex.removeprefix("0x")))
        # Cross-check our parse against the SDK's own verified fields; a mismatch fails closed.
        if (m["mrconfigid"] != bytes(res.mr_config_id).hex() or m["rtmr3"] != bytes(res.rt_mr3).hex()
                or m["report_data"] != bytes(res.report_data).hex()):
            raise PinError("the box could not read the enclave measurements")
        key = m["mrconfigid"][2:66]
        with self._lock:
            entry = {k: m[k] for k in ("mrtd", "rtmr0", "rtmr1", "rtmr2")}
            lst = self.by_compose.setdefault(key, [])
            if entry not in lst:
                lst.append(entry)
        return res

    def lookup(self, app_compose: str) -> list[dict]:
        with self._lock:
            return list(self.by_compose.get(_sha(app_compose), []))


# ---------------------------------------------------------------- fingerprints

def running_workload(actions) -> dict:
    """What the compose manager's signed action log says is still deployed.

    Every compose file brought up and not fully taken down again counts, with the sha256 of its latest
    compose_up. A file whose only deployed services were all taken down again (for example a one-off
    token-rotation job) does not count, and a "dry" run is not a deployment. The latest
    compose_manager_started image is the manager. Tags, commits and per-service updates are
    information. This is recorded deployment intent, not proof that a container is healthy (the SDK
    says the same).
    """
    manager_image = None
    files: dict[str, dict] = {}   # file -> {"sha", "full", "services": {svc: sha | "down"}, "up"}
    for a in actions or ():
        kind, f = a.get("action"), a.get("file")
        svcs = [s for s in (a.get("services") or []) if isinstance(s, str)]
        if kind == "compose_manager_started":
            manager_image = a.get("image")
        elif kind == "compose_up" and f and svcs != ["dry"]:
            st = files.get(f)
            if st is None or st["gone"]:
                st = files[f] = {"full": False, "services": {}, "gone": False}
            st.update(sha=a.get("file_sha256") or "", up=a)
            if svcs:
                for s in svcs:
                    st["services"][s] = a.get("file_sha256") or ""
            else:
                st["full"] = True
        elif kind == "compose_down" and f and f in files:
            st = files[f]
            if svcs:
                for s in svcs:
                    st["services"][s] = "down"
            else:
                st["gone"] = True

    def standing(st) -> bool:
        return not st["gone"] and (st["full"] or any(v != "down" for v in st["services"].values()))

    live = {f: st for f, st in files.items() if standing(st)}
    latest = max(live.values(), key=lambda st: st["up"].get("timestamp") or "")["up"] if live else None
    current = latest.get("file") if latest else None
    return {"compose_manager_image": manager_image,
            "standing": sorted(f"{f} {st['sha']}" for f, st in live.items()),   # "file sha256"
            "file": current,
            "file_sha256": latest.get("file_sha256") if latest else None,
            "tag": latest.get("tag") if latest else None,
            "commit": latest.get("commit") if latest else None,
            "deployed_at": latest.get("timestamp") if latest else None,
            "service_updates": dict(sorted(live[current]["services"].items())) if current else {}}


def _app_compose(app_compose: str, per_instance_envs: frozenset = frozenset()) -> tuple[dict, dict]:
    """(fingerprinted fields, information) from the measured app-compose JSON."""
    try:
        ac = json.loads(app_compose)
    except (TypeError, ValueError) as e:
        raise PinError("NEAR's deployment description could not be read") from e
    if not isinstance(ac, dict):
        raise PinError("NEAR's deployment description could not be read")
    compose = str(ac.get("docker_compose_file") or "")
    envs = sorted({str(e) for e in (ac.get("allowed_envs") or [])})
    fields = {
        "settings": {k: ac.get(k) for k in FLAG_KEYS},
        "images": sorted(set(_IMAGE.findall(compose))),
        "compose_sha256_masked": _sha(_MASK.sub(r"\1<instance>", compose)),
        "pre_launch_script_sha256": _sha(ac["pre_launch_script"]) if ac.get("pre_launch_script") else None,
        "allowed_envs": [e for e in envs if e not in per_instance_envs],
    }
    info = {"allowed_envs_per_instance": [e for e in envs if e in per_instance_envs]}
    return fields, info


@dataclass
class Measured:
    """One component's fingerprint as seen in one verified report."""
    component: str
    fields: dict
    info: dict = field(default_factory=dict)
    deployed_at: str | None = None

    @property
    def fp(self) -> str:
        return fingerprint_of(self.fields)


def measure(kind: str, model: str | None, deployment, td: list[dict]) -> list[Measured]:
    """Fingerprints for one verified gateway or model report (an SDK MeasuredDeployment).

    td is every verified quote seen for this app-compose. Each one is fingerprinted on its own, so
    one report's fingerprint never mixes in another instance's quote.
    """
    # The per-instance env names were seen differing between model instances only; the gateway keeps all.
    fields, info = _app_compose(deployment.app_compose, PER_INSTANCE_ENVS if kind == "model" else frozenset())
    rm = deployment.runtime_measurements
    fields["os_image_hash"] = getattr(rm, "os_image_hash", None)
    info["compose_hash"] = getattr(rm, "compose_hash", None)
    if not td:
        raise PinError("the box could not read the enclave measurements")
    base = "gateway" if kind == "gateway" else f"model/{model}"
    unique = sorted({_canon(t): t for t in td}.values(), key=_canon)
    out = [Measured(base, fields | {"td": [t]}, dict(info)) for t in unique]
    if kind == "model":
        cm = deployment.compose_manager
        wl = running_workload(cm.actions) if cm is not None else running_workload(())
        out.append(Measured(f"{base}/manager", {"compose_manager_image": wl["compose_manager_image"]},
                            {"compose_manager": cm is not None}))
        winfo = {k: wl[k] for k in ("file", "file_sha256", "tag", "commit", "service_updates")}
        out.append(Measured(f"{base}/workload", {"standing": wl["standing"]},
                            winfo | {"compose_manager": cm is not None}, deployed_at=wl["deployed_at"]))
    return out


# ---------------------------------------------------------------- the pin store

def _level(cfg: Config) -> str:
    from .box import _pin_level
    return _pin_level(cfg)


class PinStore:
    """<runtime>/pins.json (accepted fingerprints, reviews) and <runtime>/pins_history.jsonl."""

    def __init__(self, cfg: Config, shipped: Path | None = None):
        self.cfg = cfg
        self.path = cfg.runtime / "pins.json"
        self.history_path = cfg.runtime / "pins_history.jsonl"
        self.lock_path = cfg.runtime / ".pins.lock"
        self.shipped_path = REPO_PINS if shipped is None else shipped
        self.level = _level(cfg)

    # ---- files

    @contextlib.contextmanager
    def locked(self):
        self.cfg.runtime.mkdir(parents=True, exist_ok=True)
        fd = os.open(self.lock_path, os.O_RDWR | os.O_CREAT, 0o600)
        try:
            fcntl.flock(fd, fcntl.LOCK_EX)
            yield
        finally:
            fcntl.flock(fd, fcntl.LOCK_UN)
            os.close(fd)

    def load(self) -> dict:
        if not self.path.exists():
            if self.history_path.exists() and self.history_path.stat().st_size > 0:
                # Someone removed the pins but not the history: never silently trust on first use again.
                raise PinError("the box's NEAR pin file is missing; the owner must check it")
            return {"version": 1, "components": {}, "fingerprints": {}, "reviews": {}}
        try:
            data = json.loads(self.path.read_text())
            if not isinstance(data, dict) or data.get("version") != 1:
                raise ValueError("bad pin file")
            for k in ("components", "fingerprints", "reviews"):
                if not isinstance(data.setdefault(k, {}), dict):
                    raise ValueError("bad pin file")
            head = data.get("history")
            if head is not None and not (isinstance(head, dict) and isinstance(head.get("head"), str)
                                         and isinstance(head.get("count"), int)):
                raise ValueError("bad pin file")
            return data
        except (OSError, ValueError) as e:
            raise PinError("the box's NEAR pin file is damaged; the owner must check it") from e

    def save(self, data: dict) -> None:
        tmp = self.path.with_name(f".pins.{secrets.token_hex(4)}.tmp")
        fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        with os.fdopen(fd, "w") as f:
            json.dump(data, f, indent=1, sort_keys=True)
            f.flush()
            os.fsync(f.fileno())
        os.replace(tmp, self.path)

    def shipped(self) -> dict:
        """Repo-shipped expected fingerprints: {component: [fields, ...]}. Missing file means none."""
        if not self.shipped_path or not self.shipped_path.exists():
            return {}
        try:
            data = json.loads(self.shipped_path.read_text())
            comps = data["components"]
            return {c: [e["fields"] for e in v] for c, v in comps.items()}
        except (OSError, ValueError, KeyError, TypeError) as e:
            raise PinError("the shipped NEAR pin file is damaged; the owner must check it") from e

    def _lines(self) -> list[str]:
        if not self.history_path.exists():
            return []
        return [ln for ln in self.history_path.read_text().splitlines() if ln.strip()]

    def history(self) -> list[dict]:
        """Every readable history entry. A damaged line is skipped here; verify_history() reports it."""
        out = []
        for line in self._lines():
            try:
                entry = json.loads(line)
            except ValueError:
                continue
            if isinstance(entry, dict):
                out.append(entry)
        return out

    def _append(self, data: dict, event: str, **fields) -> dict:
        """Append one hash-chained entry and record the new head in data. Callers hold the lock and
        save data right after, so pins.json always names the newest entry and the count."""
        head = data.get("history")
        if head is None:
            lines = self._lines()                     # a box from before heads were recorded
            head = {"head": _sha(lines[-1]) if lines else GENESIS, "count": len(lines)}
        entry = {"time": int(time.time()), "event": event, **fields, "prev": head["head"]}
        line = _canon(entry)
        fd = os.open(self.history_path, os.O_WRONLY | os.O_CREAT | os.O_APPEND, 0o600)
        with os.fdopen(fd, "a") as f:
            f.write(line + "\n")
            f.flush()
            os.fsync(f.fileno())
        data["history"] = {"head": _sha(line), "count": head["count"] + 1}
        return entry

    def verify_history(self) -> bool:
        """True if every line points at the one before it and the newest one is the head pins.json
        names, with the same count. So removing or editing any entry, the newest included, shows."""
        with self.locked():
            lines = self._lines()
            prev = GENESIS
            for line in lines:
                try:
                    if json.loads(line).get("prev") != prev:
                        return False
                except (ValueError, AttributeError):
                    return False
                prev = _sha(line)
            try:
                head = self.load().get("history")
            except PinError:
                return False
        if not lines:
            return head is None or head["count"] == 0
        return head is not None and head["head"] == prev and head["count"] == len(lines)

    # ---- checking

    def _remember(self, data: dict, m: Measured, now: int) -> bool:
        """Record what was seen. True if anything worth saving changed (not just the time)."""
        new = m.fp not in data["fingerprints"]
        rec = data["fingerprints"].setdefault(m.fp, {"component": m.component, "fields": m.fields,
                                                      "first_seen": now})
        changed = new or rec.get("info") != m.info or bool(m.deployed_at and rec.get("deployed_at") != m.deployed_at)
        rec["last_seen"] = now
        rec["info"] = m.info
        if m.deployed_at:
            rec["deployed_at"] = m.deployed_at
        return changed

    def check(self, m: Measured, run_id: str) -> dict:
        """Compare one measurement with the pins. Returns {"status": ...}; raises PinError to stop.

        status: first_use | shipped | match | same_run | changed_allowed
        run_id groups the reports of one verification (one question), so several instances seen on
        first use are all pinned together.
        """
        with self.locked():
            data = self.load()
            now = int(time.time())
            comp = data["components"].get(m.component)
            known = m.fp in data["fingerprints"]
            changed = self._remember(data, m, now)
            blocking = not (self.level == "off" or (self.level == "platform" and m.component.endswith("/workload")))

            if comp and m.fp in comp["accepted"]:
                # A match only rewrites pins.json when something new was seen or last_ok is stale.
                if changed or now - int(comp.get("last_ok") or 0) >= SAVE_EVERY_S:
                    comp["last_ok"] = now
                    self.save(data)
                return {"status": "match", "fp": m.fp}
            if comp is None:
                shipped = self.shipped().get(m.component)
                if shipped is None:
                    data["components"][m.component] = {"accepted": [m.fp], "pinned_at": now, "source": "first use",
                                                       "first_run": run_id, "last_ok": now}
                    self._append(data, "pinned", component=m.component, fp=m.fp, source="first use",
                                 fields=m.fields, info=m.info)
                    self.save(data)
                    return {"status": "first_use", "fp": m.fp}
                shipped_fps = [fingerprint_of(f) for f in shipped]
                if m.fp in shipped_fps:
                    data["components"][m.component] = {"accepted": shipped_fps, "pinned_at": now,
                                                       "source": "shipped", "first_run": run_id, "last_ok": now}
                    for f in shipped:
                        data["fingerprints"].setdefault(fingerprint_of(f), {"component": m.component, "fields": f,
                                                                            "first_seen": now})
                    self._append(data, "pinned", component=m.component, fp=m.fp, source="shipped",
                                 fields=m.fields, info=m.info)
                    self.save(data)
                    return {"status": "shipped", "fp": m.fp}
                # A shipped pin exists and NEAR serves something else: that is a change, not a first use.
                data["components"][m.component] = {"accepted": shipped_fps, "pinned_at": now, "source": "shipped"}
                for f in shipped:
                    data["fingerprints"].setdefault(fingerprint_of(f), {"component": m.component, "fields": f,
                                                                        "first_seen": now})
                comp = data["components"][m.component]
            elif comp.get("first_run") == run_id and comp.get("source") == "first use":
                # Same verification as the first use: another instance seen alongside it.
                comp["accepted"].append(m.fp)
                self._append(data, "pinned", component=m.component, fp=m.fp, source="first use",
                             fields=m.fields, info=m.info)
                self.save(data)
                return {"status": "same_run", "fp": m.fp}

            if not blocking:
                if not known:
                    self._append(data, "changed", component=m.component, fp=m.fp, blocking=False,
                                 level=self.level, fields=m.fields, info=m.info, deployed_at=m.deployed_at)
                self.save(data)
                return {"status": "changed_allowed", "fp": m.fp}

            rid = _sha(f"{m.component}\n{m.fp}")[:12]
            review = data["reviews"].get(rid)
            if review is not None and review["status"] == "accepted":
                review = None   # accepted once, dropped later (accept --only): it needs a fresh review
            if review is None:
                review = {"id": rid, "component": m.component, "fp": m.fp, "previous": list(comp["accepted"]),
                          "status": "waiting", "detected_at": now, "deployed_at": m.deployed_at}
                data["reviews"][rid] = review
                self._append(data, "changed", component=m.component, fp=m.fp, blocking=True, review=rid,
                             previous=list(comp["accepted"]), fields=m.fields, info=m.info,
                             deployed_at=m.deployed_at)
                self.save(data)
            else:
                self.save(data)
            raise PinError(self.blocked_message(review))

    @staticmethod
    def blocked_message(review: dict) -> str:
        when = nice_date(review.get("deployed_at") or review.get("detected_at"))
        if review.get("status") == "rejected":
            return (f"NEAR is serving code the owner rejected on {nice_date(review.get('decided'))}. "
                    f"The box will not answer until NEAR changes it back or the owner accepts it")
        return f"NEAR changed its serving code on {when}; the owner must review it before the box answers again"

    def blocking_review(self, components: list[str] | None = None) -> dict | None:
        """A waiting review that should stop questions now (the pre-check). No network needed."""
        data = self.load()
        for r in sorted(data["reviews"].values(), key=lambda r: r["detected_at"]):
            if r["status"] == "waiting" and (components is None or r["component"] in components
                                             or any(r["component"].startswith(c + "/") for c in components)):
                if self.level == "off" or (self.level == "platform" and r["component"].endswith("/workload")):
                    continue
                return r
        return None

    # ---- owner decisions

    def reviews(self, status: str | None = "waiting") -> list[dict]:
        data = self.load()
        out = [r for r in data["reviews"].values() if status is None or r["status"] == status]
        return sorted(out, key=lambda r: r["detected_at"])

    def diff(self, review_id: str) -> dict:
        """What changed: per field, the accepted values and the new ones."""
        data = self.load()
        r = data["reviews"].get(review_id)
        if r is None:
            raise KeyError("no such review")
        new = data["fingerprints"].get(r["fp"], {})
        prev = [data["fingerprints"].get(fp, {}) for fp in r["previous"]]
        old = prev[-1] if prev else {}
        return {"review": r, "changes": diff_fields(old.get("fields", {}), new.get("fields", {})),
                "info_changes": diff_fields(old.get("info", {}), new.get("info", {})),
                "new": new, "old": old}

    def decide(self, review_id: str, accept: bool, by: str, *, only: bool = False) -> dict:
        if not _HEX_ID.match(review_id or ""):
            raise KeyError("no such review")
        with self.locked():
            data = self.load()
            r = data["reviews"].get(review_id)
            if r is None or r["status"] not in ("waiting", "rejected"):
                raise KeyError("no such review waiting")
            now = int(time.time())
            r.update(status="accepted" if accept else "rejected", decided=now, by=by)
            if accept:
                comp = data["components"].setdefault(r["component"], {"accepted": [], "pinned_at": now})
                comp["accepted"] = [r["fp"]] if only else [*[f for f in comp["accepted"] if f != r["fp"]], r["fp"]]
                comp.update(source="owner", pinned_at=now)
                comp.pop("first_run", None)
            self._append(data, "accepted" if accept else "rejected", component=r["component"], fp=r["fp"],
                         review=review_id, by=by, only=only)
            self.save(data)
            return r


def diff_fields(old: Any, new: Any, path: str = "") -> list[dict]:
    """Flat list of {"field", "before", "after"} for values that differ."""
    if isinstance(old, dict) and isinstance(new, dict):
        out = []
        for k in sorted(set(old) | set(new)):
            out += diff_fields(old.get(k), new.get(k), f"{path}.{k}" if path else k)
        return out
    if isinstance(old, list) and isinstance(new, list) and all(isinstance(x, str) for x in old + new):
        removed = sorted(set(old) - set(new))
        added = sorted(set(new) - set(old))
        return [{"field": path, "removed": removed, "added": added}] if removed or added else []
    if old != new:
        return [{"field": path, "before": old, "after": new}]
    return []


# ---------------------------------------------------------------- SDK wiring

class Checker:
    """InferenceClient options that check every gateway and model report against the pins.

    The SDK calls these inside its own verification, before any prompt is sent, so the check covers
    the reports the box verified for this question. NEAR's model instances share a signing key, so an
    instance the box never saw could still receive the prompt (docs/BUILD_LOG.md, Limits). A PinError
    raised here stops the question with its message.
    """

    def __init__(self, store: PinStore, run_id: str, emit: Callable[..., Any] | None = None):
        self.store = store
        self.run_id = run_id
        self.emit = emit or (lambda *a, **k: None)
        self.quotes = QuoteLog()
        self.results: list[dict] = []

    def _check(self, kind: str, model: str | None, deployment) -> None:
        for m in measure(kind, model, deployment, self.quotes.lookup(deployment.app_compose)):
            try:
                r = self.store.check(m, self.run_id)
            except PinError as e:
                self.emit("pinning", component=m.component, status="changed", fp=m.fp[:12])
                self.results.append({"component": m.component, "status": "changed", "fp": m.fp, "error": str(e)})
                raise
            self.emit("pinning", component=m.component, status=r["status"], fp=m.fp[:12])
            self.results.append({"component": m.component, **r})

    async def gateway_deployment(self, deployment) -> None:
        self._check("gateway", None, deployment)

    async def model_deployment(self, model: str, deployment) -> None:
        self._check("model", model, deployment)

    def client_options(self) -> dict:
        from nearai_inference_sdk import (
            AttestationVerifiers,
            GatewayVerificationOptions,
            ModelAttestationVerifiers,
            ModelVerificationOptions,
        )
        return {
            "gateway_verification": GatewayVerificationOptions(
                verifiers=AttestationVerifiers(tdx_quote=self.quotes, deployment=self.gateway_deployment)),
            "model_verification": ModelVerificationOptions(
                verifiers=ModelAttestationVerifiers(tdx_quote=self.quotes)),
            "deployment_policy": self.model_deployment,
        }


async def check_now(cfg: Config, model: str | None = None, store: PinStore | None = None) -> list[dict]:
    """Attestation only (no prompt, no API key needed): verify NEAR now and compare with the pins."""
    from nearai_inference_sdk import InferenceClient
    store = store or PinStore(cfg)
    checker = Checker(store, "check-" + secrets.token_hex(6))
    try:
        async with InferenceClient(None, e2ee=False, attestation_cache_time_to_live_ms=0,
                                   **checker.client_options()) as c:
            await c.verify(model or cfg.model)
    except Exception as e:  # noqa: BLE001
        cause = e
        while cause is not None and not isinstance(cause, PinError):
            cause = cause.__cause__ or cause.__context__
        if cause is None:
            raise
        return checker.results
    return checker.results
