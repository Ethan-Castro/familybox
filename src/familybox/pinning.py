"""Pin what the box verified about NEAR AI Cloud, and stop questions when NEAR's serving code changes.

TEE attestation proves the model ran in an enclave. It does not say *which* code ran there, and NEAR
redeploys. So the box keeps a "measurement fingerprint" for each part of the path a question takes:

  gateway                 NEAR's API gateway CVM (TLS, routing, E2EE pass-through)
  model/<id>              the model CVM: firmware, kernel, OS, its compose file and container images
  model/<id>/workload     what that CVM's compose manager is running: compose files, by sha256

The first verified use is pinned (trust on first use), unless a shipped pins file in the repo already
names the expected values. Every later live question is checked inside the SDK's own verification
(the gateway deployment verifier and the model deployment_policy), against the same reports the
question is sent to, so there is no gap between "checked" and "used". If a fingerprint is new, the
question stops before any prompt is sent, an owner review item is created, and every question stops
until the owner accepts or rejects it (`familybox pins`, or the box page /pins).

What goes into a fingerprint is what was the same across instances in live runs (docs/BUILD_LOG.md):
MRTD and RTMR0-2 from the verified TDX quote, the dstack OS image hash, the app-compose settings and
container images, and the compose text with per-instance labels masked. The raw compose hash and
MRCONFIGID are kept as information only: they differ per model instance (INSTANCE_LABEL=gpu02 vs gpu04).

pins.json holds accepted fingerprints and review items. pins_history.jsonl is append-only and hash
chained, so the audit can show every fingerprint the box ever saw and every owner decision.
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
LEVELS = ("strict", "platform", "off")
GENESIS = "0" * 64

# Lines in a compose file that name the instance, not the code. Masked before hashing.
PER_INSTANCE_KEYS = ("INSTANCE_LABEL", "INSTANCE_ID", "INSTANCE_NAME", "NODE_NAME", "CVM_NAME", "CVM_HOST",
                     "HOSTNAME", "HOST_IP", "DD_HOSTNAME")
_MASK = re.compile(r"(?m)^(\s*-?\s*[\"']?(?:" + "|".join(PER_INSTANCE_KEYS) + r")\s*[=:]).*$")
_IMAGE = re.compile(r"(?m)^\s*image:\s*[\"']?([^\s\"'#]+)")
# app-compose settings that change what runs or who can reach it. allowed_envs differs per instance
# in live data, so it is shown in diffs but not fingerprinted.
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
    after the quote verifies, so a deployment callback can find its own quote's measurements.
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
    """What the compose manager's signed action log says it deployed last, read the way the SDK reads it
    (verify_compose_manager_deployment_image_provenance): the latest compose_up, and the latest
    compose_manager_started image.

    Two refinements from live logs: a compose file that was fully taken down again afterwards (for
    example a one-off token-rotation job) does not count, and a "dry" run is not a deployment.
    Per-service updates are listed as information. This is recorded deployment intent, not proof that
    a container is healthy (the SDK says the same).
    """
    manager_image = None
    current = None                       # the latest compose_up still standing
    ups: dict[str, dict] = {}            # file -> its latest compose_up
    downed: set[str] = set()
    services: dict[str, dict[str, str]] = {}   # file -> service -> file_sha256 (or "down")
    for a in actions or ():
        kind, f = a.get("action"), a.get("file")
        svcs = [s for s in (a.get("services") or []) if isinstance(s, str)]
        if kind == "compose_manager_started":
            manager_image = a.get("image")
        elif kind == "compose_up" and f and svcs != ["dry"]:
            ups[f] = a
            downed.discard(f)
            if svcs:
                for s in svcs:
                    services.setdefault(f, {})[s] = a.get("file_sha256") or ""
            else:
                services[f] = {}
            current = f
        elif kind == "compose_down" and f:
            if svcs:
                for s in svcs:
                    services.setdefault(f, {})[s] = "down"
            else:
                downed.add(f)
                services.pop(f, None)
    if current in downed:
        standing = [a for f, a in ups.items() if f not in downed]
        current = max(standing, key=lambda a: a.get("timestamp") or "")["file"] if standing else None
    up = ups.get(current) if current else None
    return {"compose_manager_image": manager_image,
            "file": up.get("file") if up else None,
            "file_sha256": up.get("file_sha256") if up else None,
            "tag": up.get("tag") if up else None,
            "commit": up.get("commit") if up else None,
            "deployed_at": up.get("timestamp") if up else None,
            "service_updates": dict(sorted(services.get(current, {}).items())) if current else {}}


def _app_compose(app_compose: str) -> tuple[dict, dict]:
    """(fingerprinted fields, information) from the measured app-compose JSON."""
    try:
        ac = json.loads(app_compose)
    except (TypeError, ValueError) as e:
        raise PinError("NEAR's deployment description could not be read") from e
    if not isinstance(ac, dict):
        raise PinError("NEAR's deployment description could not be read")
    compose = str(ac.get("docker_compose_file") or "")
    fields = {
        "settings": {k: ac.get(k) for k in FLAG_KEYS},
        "images": sorted(set(_IMAGE.findall(compose))),
        "compose_sha256_masked": _sha(_MASK.sub(r"\1<instance>", compose)),
        "pre_launch_script_sha256": _sha(ac["pre_launch_script"]) if ac.get("pre_launch_script") else None,
    }
    info = {"allowed_envs": sorted(ac.get("allowed_envs") or [])}
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
    """Fingerprints for one verified gateway or model report (an SDK MeasuredDeployment)."""
    fields, info = _app_compose(deployment.app_compose)
    rm = deployment.runtime_measurements
    fields["os_image_hash"] = getattr(rm, "os_image_hash", None)
    fields["td"] = sorted(td, key=_canon)
    info["compose_hash"] = getattr(rm, "compose_hash", None)
    if not td:
        raise PinError("the box could not read the enclave measurements")
    base = "gateway" if kind == "gateway" else f"model/{model}"
    out = [Measured(base, fields, info)]
    if kind == "model":
        cm = deployment.compose_manager
        wl = running_workload(cm.actions) if cm is not None else running_workload(())
        wfields = {k: wl[k] for k in ("compose_manager_image", "file", "file_sha256")}
        winfo = {k: wl[k] for k in ("tag", "commit", "service_updates")} | {"compose_manager": cm is not None}
        out.append(Measured(f"{base}/workload", wfields, winfo, deployed_at=wl["deployed_at"]))
    return out


# ---------------------------------------------------------------- the pin store

def _level(cfg: Config) -> str:
    env = os.environ.get("FAMILYBOX_PIN_LEVEL")
    if env:
        level = env
    else:
        import tomllib
        try:
            level = tomllib.loads((cfg.home / "family.toml").read_text()).get("pins", {}).get("level", "strict")
        except (OSError, ValueError):
            level = "strict"
    return level if level in LEVELS else "strict"


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

    def history(self) -> list[dict]:
        if not self.history_path.exists():
            return []
        return [json.loads(line) for line in self.history_path.read_text().splitlines() if line.strip()]

    def _append(self, event: str, **data) -> dict:
        """Append one hash-chained entry. Callers hold the lock."""
        prev = GENESIS
        if self.history_path.exists():
            lines = [ln for ln in self.history_path.read_text().splitlines() if ln.strip()]
            if lines:
                prev = _sha(lines[-1])
        entry = {"time": int(time.time()), "event": event, **data, "prev": prev}
        fd = os.open(self.history_path, os.O_WRONLY | os.O_CREAT | os.O_APPEND, 0o600)
        with os.fdopen(fd, "a") as f:
            f.write(_canon(entry) + "\n")
        return entry

    def verify_history(self) -> bool:
        """True if every history line points at the one before it (nothing removed or edited)."""
        prev = GENESIS
        if not self.history_path.exists():
            return True
        for line in self.history_path.read_text().splitlines():
            if not line.strip():
                continue
            try:
                if json.loads(line).get("prev") != prev:
                    return False
            except ValueError:
                return False
            prev = _sha(line)
        return True

    # ---- checking

    def _remember(self, data: dict, m: Measured, now: int) -> None:
        rec = data["fingerprints"].setdefault(m.fp, {"component": m.component, "fields": m.fields,
                                                      "first_seen": now})
        rec["last_seen"] = now
        rec["info"] = m.info
        if m.deployed_at:
            rec["deployed_at"] = m.deployed_at

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
            self._remember(data, m, now)
            blocking = not (self.level == "off" or (self.level == "platform" and m.component.endswith("/workload")))

            if comp and m.fp in comp["accepted"]:
                comp["last_ok"] = now
                self.save(data)
                return {"status": "match", "fp": m.fp}
            if comp is None:
                shipped = self.shipped().get(m.component)
                if shipped is None:
                    data["components"][m.component] = {"accepted": [m.fp], "pinned_at": now, "source": "first use",
                                                       "first_run": run_id, "last_ok": now}
                    self.save(data)
                    self._append("pinned", component=m.component, fp=m.fp, source="first use", fields=m.fields,
                                 info=m.info)
                    return {"status": "first_use", "fp": m.fp}
                shipped_fps = [fingerprint_of(f) for f in shipped]
                if m.fp in shipped_fps:
                    data["components"][m.component] = {"accepted": shipped_fps, "pinned_at": now,
                                                       "source": "shipped", "first_run": run_id, "last_ok": now}
                    for f in shipped:
                        data["fingerprints"].setdefault(fingerprint_of(f), {"component": m.component, "fields": f,
                                                                            "first_seen": now})
                    self.save(data)
                    self._append("pinned", component=m.component, fp=m.fp, source="shipped", fields=m.fields,
                                 info=m.info)
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
                self.save(data)
                self._append("pinned", component=m.component, fp=m.fp, source="first use", fields=m.fields,
                             info=m.info)
                return {"status": "same_run", "fp": m.fp}

            if not blocking:
                self.save(data)
                if not known:
                    self._append("changed", component=m.component, fp=m.fp, blocking=False, level=self.level,
                                 fields=m.fields, info=m.info, deployed_at=m.deployed_at)
                return {"status": "changed_allowed", "fp": m.fp}

            rid = _sha(f"{m.component}\n{m.fp}")[:12]
            review = data["reviews"].get(rid)
            if review is not None and review["status"] == "accepted":
                review = None   # accepted once, dropped later (accept --only): it needs a fresh review
            if review is None:
                review = {"id": rid, "component": m.component, "fp": m.fp, "previous": list(comp["accepted"]),
                          "status": "waiting", "detected_at": now, "deployed_at": m.deployed_at}
                data["reviews"][rid] = review
                self.save(data)
                self._append("changed", component=m.component, fp=m.fp, blocking=True, review=rid,
                             previous=list(comp["accepted"]), fields=m.fields, info=m.info, deployed_at=m.deployed_at)
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
            self.save(data)
            self._append("accepted" if accept else "rejected", component=r["component"], fp=r["fp"], review=review_id,
                         by=by, only=only)
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

    The SDK calls these inside its own verification, so the check covers exactly the reports the
    question's prompts are encrypted to. A PinError raised here stops the question with its message.
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
