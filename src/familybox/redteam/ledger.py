"""Spending guard, rate limits and the scoreboard for the red-team page.

Everything lives in <runtime>/redteam/ (folder 0700, files 0600):
  secret        random key; never leaves the box
  state.json    today's spend and tokens, open reservations, hit times per visitor, the scoreboard
  leaks.jsonl   one line per confirmed leak (the attack text and what the assistant would receive)

Visitors are never stored by IP address. A visitor is HMAC(day key, ip) cut to 20 hex characters,
where the day key is HMAC(secret, UTC date): the codes change every day, so they cannot be linked
across days, and hit times older than an hour are dropped.

Order of checks for one attempt (admit):
  1. Hard limits (attempts per visitor per hour, all visitors per hour, all visitors per day). Over
     any of them the attempt is refused outright (HTTP 429).
  2. Live limits. The attempt runs live on the enclave only if every one of these holds, otherwise it
     switches to replay only: a key is set, live is not turned off, fewer than max_live_in_flight live
     attempts are running, the visitor and global live-per-hour caps are not used up, and today's
     tokens and dollars plus every open reservation plus this attempt's worst case stay within
     max_tokens_per_day and daily_budget_usd.
A live attempt reserves its worst case (guard.worst_case_tokens) before the call. settle() swaps the
reservation for the real token count, or keeps the whole reservation as spent when the real count is
unknown (an error). Reservations older than RESERVATION_TTL_S are counted as spent.
"""

from __future__ import annotations

import contextlib
import datetime as dt
import fcntl
import hashlib
import hmac
import json
import os
import secrets
import time
from dataclasses import dataclass
from pathlib import Path

from ..config import Config
from ..web import _write_private
from . import guard
from .home import Settings

HOUR = 3600
RESERVATION_TTL_S = 15 * 60
SCORE_KEYS = ("attempts", "live", "replayed", "answered", "masked", "held", "blocked", "stopped", "leaks")
OUTCOME_KEY = {"pass": "answered", "masked": "masked", "held": "held", "refused": "blocked", "error": "stopped"}


def _today(now: float) -> str:
    return dt.datetime.fromtimestamp(now, dt.timezone.utc).strftime("%Y-%m-%d")


def _empty_score() -> dict:
    return {k: 0 for k in SCORE_KEYS} | {"leaked": {}}


@dataclass
class Admission:
    allowed: bool                 # False: refused outright (429)
    live: bool                    # True: run on the enclave; False: replay only
    reason: str = ""              # plain English, shown to the visitor
    reservation: str | None = None


class Ledger:
    def __init__(self, cfg: Config, settings: Settings):
        self.cfg = cfg
        self.s = settings
        self.dir = cfg.runtime / "redteam"
        self.dir.mkdir(parents=True, exist_ok=True, mode=0o700)
        os.chmod(self.dir, 0o700)
        self.worst_in, self.worst_out = guard.worst_case_tokens(settings.max_question_chars)
        self.worst_usd = guard.cost_usd(self.worst_in, self.worst_out, settings.price_in_per_m,
                                        settings.price_out_per_m)

    # ---- storage

    @contextlib.contextmanager
    def _locked(self, now: float, write: bool = True):
        fd = os.open(self.dir / ".lock", os.O_WRONLY | os.O_CREAT, 0o600)
        try:
            fcntl.flock(fd, fcntl.LOCK_EX)
            st = self._load()
            self._roll(st, now)
            yield st
            if write:
                _write_private(self.dir / "state.json", json.dumps(st).encode())
        finally:
            fcntl.flock(fd, fcntl.LOCK_UN)
            os.close(fd)

    def _load(self) -> dict:
        p = self.dir / "state.json"
        try:
            st = json.loads(p.read_text()) if p.exists() else {}
        except ValueError:
            st = {}
        st.setdefault("day", "")
        st.setdefault("spent_usd", 0.0)
        st.setdefault("tokens", 0)
        st.setdefault("reservations", {})
        st.setdefault("visitors", {})        # visitor code -> {"all": [times], "live": [times]}
        st.setdefault("global", {"all": [], "live": []})
        st.setdefault("day_attempts", 0)
        st.setdefault("score", {"today": _empty_score(), "all": _empty_score()})
        return st

    def _roll(self, st: dict, now: float) -> None:
        day = _today(now)
        if st["day"] != day:
            st.update(day=day, spent_usd=0.0, tokens=0, day_attempts=0, visitors={})
            st["score"]["today"] = _empty_score()
        for rid, r in list(st["reservations"].items()):
            if now - r["t"] > RESERVATION_TTL_S:
                st["spent_usd"] += r["usd"]
                st["tokens"] += r["tokens"]
                del st["reservations"][rid]
        for bucket in [st["global"], *st["visitors"].values()]:
            for k in ("all", "live"):
                bucket[k] = [t for t in bucket.get(k, []) if now - t < HOUR]
        st["visitors"] = {v: b for v, b in st["visitors"].items() if b["all"] or b["live"]}

    def _secret(self) -> bytes:
        p = self.dir / "secret"
        if not p.exists():
            _write_private(p, secrets.token_bytes(32))
        return p.read_bytes()

    def visitor(self, ip: str, now: float | None = None) -> str:
        """Daily-rotating keyed hash of the visitor's address. The address itself is never stored."""
        day_key = hmac.new(self._secret(), f"day:{_today(now or time.time())}".encode(), hashlib.sha256).digest()
        return hmac.new(day_key, (ip or "unknown").encode(), hashlib.sha256).hexdigest()[:20]

    def csrf_for(self, cookie: str) -> str:
        return hmac.new(self._secret(), f"csrf:{cookie}".encode(), hashlib.sha256).hexdigest()[:32]

    # ---- one attempt

    def admit(self, ip: str, *, key_present: bool, now: float | None = None) -> Admission:
        now = now or time.time()
        v = self.visitor(ip, now)
        s = self.s
        with self._locked(now) as st:
            mine = st["visitors"].setdefault(v, {"all": [], "live": []})
            g = st["global"]
            if len(mine["all"]) >= s.attempts_per_visitor_per_hour:
                return Admission(False, False, f"You have reached {s.attempts_per_visitor_per_hour} tries "
                                 "this hour. Please come back later.")
            if len(g["all"]) >= s.attempts_global_per_hour:
                return Admission(False, False, "The page is very busy right now. Please try again in a while.")
            if st["day_attempts"] >= s.attempts_global_per_day:
                return Admission(False, False, "The page has reached its limit for today. Please come back "
                                 "tomorrow.")
            mine["all"].append(now)
            g["all"].append(now)
            st["day_attempts"] += 1

            reserved_usd = sum(r["usd"] for r in st["reservations"].values())
            reserved_tok = sum(r["tokens"] for r in st["reservations"].values())
            worst_tok = self.worst_in + self.worst_out
            why = ""
            if not key_present:
                why = "Live mode is off on this box (no NEAR AI key is set)."
            elif s.replay_only:
                why = "This box is set to replay only."
            elif len(st["reservations"]) >= s.max_live_in_flight:
                why = "Other live tries are running right now."
            elif len(mine["live"]) >= s.live_per_visitor_per_hour:
                why = f"You have used your {s.live_per_visitor_per_hour} live tries for this hour."
            elif len(g["live"]) >= s.live_global_per_hour:
                why = "Everyone together has used this hour's live tries."
            elif st["tokens"] + reserved_tok + worst_tok > s.max_tokens_per_day:
                why = "Today's token limit for live tries is used up."
            elif st["spent_usd"] + reserved_usd + self.worst_usd > s.daily_budget_usd:
                why = "Today's spending limit for live tries is used up."
            if why:
                return Admission(True, False, why)
            rid = secrets.token_hex(8)
            st["reservations"][rid] = {"t": now, "usd": self.worst_usd, "tokens": worst_tok}
            mine["live"].append(now)
            g["live"].append(now)
            return Admission(True, True, "", rid)

    def settle(self, reservation: str | None, tokens: tuple[int, int] | None,
               now: float | None = None) -> float:
        """Replace the reservation with the real cost. Unknown tokens keep the whole reservation."""
        now = now or time.time()
        with self._locked(now) as st:
            r = st["reservations"].pop(reservation, None) if reservation else None
            if tokens is None:
                usd, tok = (r["usd"], r["tokens"]) if r else (self.worst_usd, self.worst_in + self.worst_out)
            else:
                tin, tout = int(tokens[0]), int(tokens[1])
                usd = guard.cost_usd(tin, tout, self.s.price_in_per_m, self.s.price_out_per_m)
                tok = tin + tout
            st["spent_usd"] += usd
            st["tokens"] += tok
            return usd

    def record(self, *, outcome: str, live: bool, leaked_labels: list[str], now: float | None = None) -> None:
        now = now or time.time()
        with self._locked(now) as st:
            for board in st["score"].values():
                board["attempts"] += 1
                board["live" if live else "replayed"] += 1
                board[OUTCOME_KEY.get(outcome, "stopped")] += 1
                if leaked_labels:
                    board["leaks"] += 1
                    for lab in leaked_labels:
                        board["leaked"][lab] = board["leaked"].get(lab, 0) + 1

    def record_leak(self, entry: dict) -> None:
        path = self.dir / "leaks.jsonl"
        fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_APPEND, 0o600)
        with os.fdopen(fd, "a") as f:
            f.write(json.dumps({"time": int(time.time())} | entry) + "\n")

    def snapshot(self, now: float | None = None) -> dict:
        """Scoreboard and spend for display. Never includes visitor codes. Read only (page views never write)."""
        now = now or time.time()
        with self._locked(now, write=False) as st:
            return {
                "day": st["day"],
                "score": json.loads(json.dumps(st["score"])),
                "spent_usd": round(st["spent_usd"], 6),
                "tokens": st["tokens"],
                "live_in_flight": len(st["reservations"]),
                "daily_budget_usd": self.s.daily_budget_usd,
                "max_tokens_per_day": self.s.max_tokens_per_day,
                "worst_case_usd_per_try": round(self.worst_usd, 6),
            }
