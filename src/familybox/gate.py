"""The answer gate: deterministic checks on every answer before an assistant sees it.

The model is asked to be careful, but this gate does not trust it. It knows the actual protected
values in the family's files (indexed by store.py), so it can recognize them however they are
written: dashes, spaces, spelled-out digits, or a 5-digit run of an SSN.

Outcomes (most severe wins):
  refused  - the whole answer is withheld (tripwire, another person's data, or an unmaskable leak)
  held     - protected values were replaced with placeholders; the owner can approve on their device
  masked   - unknown numbers that look like SSNs or cards were removed
  pass     - nothing protected was found
"""

from __future__ import annotations

import hashlib
import re
from dataclasses import dataclass, field

from .store import Sensitive

NUMBER_WORDS = {"zero": "0", "oh": "0", "one": "1", "two": "2", "three": "3", "four": "4",
                "five": "5", "six": "6", "seven": "7", "eight": "8", "nine": "9"}
NUMBER_WORD_RE = re.compile(r"\b(" + "|".join(NUMBER_WORDS) + r")\b", re.IGNORECASE)
GENERIC_SSN_RE = re.compile(r"\b\d{3}[- .]?\d{2}[- .]?\d{4}\b")
CARD_RE = re.compile(r"\b(?:\d[ -]?){13,19}\b")
HEALTH_STOP = {"history", "patient", "follow", "routine", "normal", "checkup", "general", "family", "medical",
               "health", "annual", "physical", "status", "result", "results", "started", "daily", "tablet",
               "visit", "notes", "screening", "negative", "positive", "within", "limits", "continue",
               "generalized", "stable", "needed", "disorder", "inhaler", "induced", "exercise", "chronic"}
# Single words count as health details only from these labels; other labels (plan, notes, reason for visit)
# are matched as whole phrases, because they are full of everyday words.
WORD_LABELS = {"diagnosis", "diagnoses", "condition", "conditions", "assessment", "medication", "medications",
               "prescription", "impression"}
SUFFIXES = ("ations", "ation", "itis", "ions", "ion", "ives", "ive", "ness", "ing", "ed", "es", "s", "al", "ic")


def stem(word: str) -> str:
    w = word.lower()
    for suf in SUFFIXES:
        if w.endswith(suf) and len(w) - len(suf) >= 5:
            return w[: -len(suf)]
    return w

SEVERITY = {"pass": 0, "masked": 1, "held": 2, "refused": 3}
REFUSED_TEXT = ("This answer was blocked by the family box: it contained protected information "
                "it is not allowed to share. Nothing was sent.")


@dataclass
class Held:
    id: str
    kind: str
    label: str
    value: str
    owner: str | None
    path: str


@dataclass
class GateResult:
    outcome: str
    text: str
    held: list[Held] = field(default_factory=list)
    reasons: list[str] = field(default_factory=list)

    def bump(self, outcome: str, reason: str) -> None:
        if SEVERITY[outcome] > SEVERITY[self.outcome]:
            self.outcome = outcome
        self.reasons.append(reason)


def normalize(text: str) -> str:
    text = NUMBER_WORD_RE.sub(lambda m: NUMBER_WORDS[m.group(1).lower()], text)
    return re.sub(r"[^a-z0-9]", "", text.lower())


def digits(text: str) -> str:
    text = NUMBER_WORD_RE.sub(lambda m: NUMBER_WORDS[m.group(1).lower()], text)
    return re.sub(r"\D", "", text)


DIGIT_RUN_RE = re.compile(r"\d(?:[\s.,\-/_()]{0,3}\d)*")


def digit_groups(text: str) -> list[str]:
    """Each run of digits written as one number (digits, spelled-out digits, small separators between)."""
    text = NUMBER_WORD_RE.sub(lambda m: NUMBER_WORDS[m.group(1).lower()], text)
    return [re.sub(r"\D", "", m.group(0)) for m in DIGIT_RUN_RE.finditer(text)]


def ssn_run_in(value: str, text: str) -> bool:
    """True if any 5-digit run of the SSN appears inside a single number in the text."""
    groups = digit_groups(text)
    return any(value[i:i + 5] in g for g in groups for i in range(0, 5))


def loose_pattern(value: str) -> re.Pattern:
    """Match value in the answer with any punctuation or spacing between its characters."""
    chars = [re.escape(c) for c in re.sub(r"[^A-Za-z0-9]", "", value)]
    return re.compile(r"[\W_]{0,3}".join(chars), re.IGNORECASE)


def luhn_ok(number: str) -> bool:
    total, alt = 0, False
    for d in reversed(number):
        n = int(d)
        if alt:
            n = n * 2 - 9 if n > 4 else n * 2
        total, alt = total + n, not alt
    return total % 10 == 0


# Words that also appear in the family's non-health files (an employer, a street) are not health details
# on their own. Set by check() from the store for each call.
_COMMON: set[str] = set()


def health_stems(item: Sensitive) -> set[str]:
    if item.kind != "health" or item.label.lower() not in WORD_LABELS:
        return set()
    return {stem(w) for w in re.findall(r"[a-z]{6,}", item.value.lower())
            if w not in HEALTH_STOP and w not in _COMMON}


def _is_health_word(word: str, stems: set[str]) -> bool:
    w = word.lower()
    return stem(w) in stems or any(len(s) >= 6 and w.startswith(s) for s in stems)


def _word_hits(stems: set[str], text: str) -> list[str]:
    return [m.group(0) for m in re.finditer(r"[A-Za-z]{5,}", text) if _is_health_word(m.group(0), stems)]


def _held_id(item: Sensitive) -> str:
    return hashlib.sha256(f"{item.path}|{item.kind}|{item.value}".encode()).hexdigest()[:10]


def placeholder(item: Sensitive, display: dict[str, str]) -> str:
    who = display.get(item.owner or "", "the owner")
    if item.kind == "ssn":
        return f"[SSN ending {item.value[-4:]}: full number on {who}'s device after approval]"
    if item.kind == "id":
        return f"[{item.label}: held for {who}'s approval]"
    return f"[health detail: held for {who}'s approval]"


def _still_present(item: Sensitive, text: str, in_scope: bool) -> bool:
    norm = normalize(text)
    if normalize(item.value) in norm:
        return True
    if in_scope and item.kind == "ssn":
        return ssn_run_in(item.value, text)
    if in_scope and item.kind == "health":
        return bool(_word_hits(health_stems(item), text))
    return False


def check(answer: str, *, sensitive: list[Sensitive], readable_owners: set[str],
          never_share: list[str], display: dict[str, str], common_words: set[str] | None = None) -> GateResult:
    _COMMON.clear()
    _COMMON.update(common_words or ())
    result = GateResult("pass", answer)
    sensitive = list(dict.fromkeys(sensitive))  # the index can list a value more than once
    norm = normalize(answer)

    # 1. Tripwires: a marker planted in a protected file must never appear in an answer.
    for item in sensitive:
        if item.kind == "tripwire" and normalize(item.value) in norm:
            result.bump("refused", f"tripwire {item.value} from {item.path}")

    # 2. Known protected values (SSNs, ID numbers, health details) from the family's files.
    for item in sensitive:
        if item.kind == "tripwire":
            continue
        nv = normalize(item.value)
        in_scope = item.owner is None or item.owner in readable_owners
        min_len = 8 if item.kind == "health" else 4
        if len(nv) < min_len:
            continue
        hit = nv in norm
        # Partial matches only for values the asker may see. Values outside their scope must match in
        # full, so shared vocabulary or shared digit runs never look like another person's data.
        if not hit and in_scope and item.kind == "ssn":
            # Any 5-digit run of an SSN counts, so it can't be pieced together across answers.
            hit = ssn_run_in(item.value, answer)
        if not hit and in_scope and item.kind == "health":
            hit = bool(_word_hits(health_stems(item), answer))
        if not hit:
            continue
        if item.owner is not None and item.owner not in readable_owners:
            result.bump("refused", f"another person's {item.kind} from {item.path}")
            continue
        held = Held(_held_id(item), item.kind, item.label, item.value, item.owner, item.path)
        if all(h.id != held.id for h in result.held):
            result.held.append(held)
        before = result.text
        result.text = loose_pattern(item.value).sub(placeholder(item, display), result.text)
        if item.kind == "health":
            stems = health_stems(item)
            result.text = re.sub(r"[A-Za-z]{5,}", lambda m: placeholder(item, display) if _is_health_word(m.group(0), stems)
                                 else m.group(0), result.text)
        if item.kind == "ssn":
            for i in range(0, 5):
                run = item.value[i:i + 5]
                result.text = re.sub(r"[\W_]{0,3}".join(run), placeholder(item, display), result.text)
        if _still_present(item, result.text, in_scope):
            result.bump("refused", f"{item.kind} from {item.path} in a form that could not be masked")
        elif result.text != before:
            result.bump("held", f"{item.kind} from {item.path}")

    # 3. Never-share words chosen by the family.
    for term in never_share:
        if term and normalize(term) in normalize(result.text):
            result.text = re.sub(re.escape(term), "[held: never-share term]", result.text, flags=re.IGNORECASE)
            if normalize(term) in normalize(result.text):
                result.bump("refused", f"never-share term {term!r}")
            else:
                result.bump("held", f"never-share term {term!r}")

    # 4. Unknown numbers shaped like SSNs or card numbers.
    if GENERIC_SSN_RE.search(result.text):
        result.text = GENERIC_SSN_RE.sub("[number removed]", result.text)
        result.bump("masked", "SSN-shaped number")
    for m in list(CARD_RE.finditer(result.text)):
        num = re.sub(r"\D", "", m.group(0))
        if 13 <= len(num) <= 19 and luhn_ok(num):
            result.text = result.text.replace(m.group(0), "[card number removed]")
            result.bump("masked", "card number")

    if result.outcome == "refused":
        result.text = REFUSED_TEXT
    return result
