"""Dedicated demo homes and the on/off switch for the red-team page.

The page is enabled only for a home that (1) carries the marker file written by `familybox redteam
init`, (2) has the demo family (maya, sam, dana), and (3) holds only fictional SSNs (987-65-4320 to
987-65-4329). A real family's box can never be switched into red-team mode by accident.
"""

from __future__ import annotations

import re
import shutil
from dataclasses import dataclass, field
from pathlib import Path

from .. import config
from ..config import Config
from ..store import Store

REPO_ROOT = Path(__file__).resolve().parents[3]
DEMO_SOURCE = REPO_ROOT / "demo"
MARKER = "REDTEAM_DEMO_HOME"
DEMO_PEOPLE = ("dana", "sam", "maya")
FICTIONAL_SSNS = {f"98765432{i}" for i in range(10)}

MARKER_TEXT = ("This folder is a throwaway demo home for the familybox red-team page.\n"
               "Every person, number and record in it is made up. Do not put real documents here.\n")


class RedTeamError(RuntimeError):
    """The red-team page cannot be turned on for this home."""


@dataclass(frozen=True)
class Settings:
    """Spending and rate limits. Prices are US dollars per million tokens."""
    daily_budget_usd: float = 2.00
    price_in_per_m: float = 0.50        # placeholder, not NEAR's real price; live serve requires --price-in
    price_out_per_m: float = 2.00       # placeholder, not NEAR's real price; live serve requires --price-out
    max_tokens_per_day: int = 2_000_000
    live_per_visitor_per_hour: int = 5
    live_global_per_hour: int = 60
    attempts_per_visitor_per_hour: int = 30
    attempts_global_per_hour: int = 600
    attempts_global_per_day: int = 5000
    max_live_in_flight: int = 2
    max_question_chars: int = 500
    replay_only: bool = False
    trust_ip_header: str | None = None  # e.g. "cf-connecting-ip" when behind a tunnel you control
    replay_dir: Path | None = None      # default: the repo's replays/


@dataclass
class _Registry:
    enabled: dict[str, Settings] = field(default_factory=dict)


_REG = _Registry()


def _key(cfg: Config) -> str:
    return str(Path(cfg.home).resolve())


def check_demo_home(cfg: Config) -> None:
    """Raise RedTeamError unless cfg.home is a dedicated, fictional demo home."""
    home = Path(cfg.home).resolve()
    if not (home / MARKER).is_file():
        raise RedTeamError(f"{home} is not a red-team demo home (no {MARKER} file). "
                           "Make one with: familybox redteam init <folder>")
    if DEMO_SOURCE.exists() and home == DEMO_SOURCE.resolve():
        raise RedTeamError("use a copy of the demo home, not the repo's demo/ folder itself")
    missing = [p for p in DEMO_PEOPLE if p not in cfg.people]
    if missing:
        raise RedTeamError(f"the demo family is missing: {', '.join(missing)}")
    for s in Store(cfg).sensitive_values():
        if s.kind == "ssn" and re.sub(r"\D", "", s.value) not in FICTIONAL_SSNS:
            raise RedTeamError("this home holds an SSN outside the fictional 987-65-4320 to 4329 range; "
                               "it looks like a real family's box, so the red-team page stays off")
    from . import scoring
    scoring.checker()   # raises RedTeamError if the independent checker is missing


def enable(cfg: Config, settings: Settings | None = None) -> Settings:
    check_demo_home(cfg)
    s = settings or Settings()
    _REG.enabled[_key(cfg)] = s
    return s


def disable(cfg: Config) -> None:
    _REG.enabled.pop(_key(cfg), None)


def settings_for(cfg: Config) -> Settings | None:
    """The settings if the red-team page is on for this home, else None (the default)."""
    return _REG.enabled.get(_key(cfg))


def init_home(target: Path, source: Path = DEMO_SOURCE) -> Config:
    """Copy the fictional demo family into a new folder and mark it as a red-team demo home."""
    target = Path(target).expanduser().resolve()
    if target.exists() and any(target.iterdir()):
        raise RedTeamError(f"{target} is not empty; pick a new folder")
    if not (source / "family.toml").is_file():
        raise RedTeamError(f"demo family not found at {source}")
    target.mkdir(parents=True, exist_ok=True)
    shutil.copytree(source / "files", target / "files")
    shutil.copy(source / "family.toml", target / "family.toml")
    (target / MARKER).write_text(MARKER_TEXT)
    cfg = config.load(target)
    Store(cfg).reindex()
    check_demo_home(cfg)
    return cfg
