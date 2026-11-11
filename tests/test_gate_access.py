"""Access scoping and answer-gate tests on the fictional Okafor household (no network)."""

from pathlib import Path

import pytest

from familybox import access, config, gate
from familybox.store import Store

DEMO = Path(__file__).resolve().parents[1] / "demo"


@pytest.fixture(scope="module")
def env(tmp_path_factory):
    import shutil
    home = tmp_path_factory.mktemp("box")
    shutil.copytree(DEMO / "files", home / "files")
    shutil.copy(DEMO / "family.toml", home / "family.toml")
    cfg = config.load(home)
    store = Store(cfg)
    store.reindex()
    return cfg, store


def check(env, person_id, answer, never=()):
    cfg, store = env
    p = cfg.person(person_id)
    return gate.check(answer, sensitive=store.sensitive_values(),
                      readable_owners=set(access.readable_owners(cfg, p)),
                      never_share=list(never), display={x.id: x.display for x in cfg.people.values()},
                      common_words=store.nonhealth_words())


# --- access -------------------------------------------------------------------------------------

def test_people_read_their_own_and_shared(env):
    cfg, _ = env
    maya = cfg.person("maya")
    assert access.can_read(maya, "people/maya/health/records_maya_fhir.json")
    assert access.can_read(maya, "shared/insurance/health_insurance_card.txt")
    assert not access.can_read(maya, "people/dana/taxes/w2_2025_dana.txt")


def test_health_folders_are_owner_only_even_for_parents(env):
    cfg, _ = env
    dana = cfg.person("dana")
    assert access.can_read(dana, "people/maya/ids/passport_maya.txt")      # granted by also_reads
    assert not access.can_read(dana, "people/maya/health/records_maya_fhir.json")
    assert not access.can_read(cfg.person("maya"), "people/dana/health/visit_2026_09_14.txt")


def test_path_tricks_are_refused(env):
    cfg, store = env
    maya = cfg.person("maya")
    assert not access.can_read(maya, "people/maya/../dana/ids/ssn_card_dana.txt")
    assert store.read(maya, "/people/dana/ids/ssn_card_dana.txt") is None
    assert store.read(maya, "../../family.toml") is None


def test_search_never_returns_other_peoples_files(env):
    cfg, store = env
    hits = store.search(cfg.person("maya"), "SSN passport visit sertraline")
    assert hits and all(access.can_read(cfg.person("maya"), h["path"]) for h in hits)
    assert not any(h["path"].startswith("people/dana") for h in hits)


# --- gate ---------------------------------------------------------------------------------------

def test_clean_answer_passes(env):
    r = check(env, "dana", "Combined 2025 W-2 wages were $142,310. Maya's passport expires May 2, 2027.")
    assert r.outcome == "pass"


@pytest.mark.parametrize("written", [
    "987-65-4322", "987 65 4322", "987654322", "9 8 7 6 5 4 3 2 2",
    "nine eight seven six five four three two two",
])
def test_full_ssn_is_held_however_written(env, written):
    r = check(env, "dana", f"Maya's SSN is {written}.")
    assert r.outcome in ("held", "refused")
    assert "987654322" not in gate.digits(r.text)


def test_last_four_is_allowed(env):
    r = check(env, "dana", "Maya's SSN on file ends in 4322.")
    assert r.outcome == "pass"


def test_ssn_cannot_be_pieced_together(env):
    r = check(env, "dana", "The first five digits of Maya's number are 98765.")
    assert r.outcome in ("held", "refused")


def test_passport_number_is_held(env):
    r = check(env, "maya", "Your passport number is X20577143 and it expires 2027-05-02.")
    assert r.outcome == "held" and "X20577143" not in r.text and "2027-05-02" in r.text


def test_own_health_detail_is_held_for_owner(env):
    r = check(env, "maya", "You use an albuterol inhaler for exercise-induced asthma.")
    assert r.outcome == "held"
    assert "albuterol" not in r.text.lower() and "asthma" not in r.text.lower()


def test_allergies_and_vaccines_pass(env):
    r = check(env, "maya", "Allergies: penicillin, peanuts. Tdap given 2021-08-03.")
    assert r.outcome == "pass"


def test_other_persons_health_detail_is_refused(env):
    r = check(env, "maya", "Your mom has generalized anxiety disorder and takes sertraline 50 mg daily.")
    assert r.outcome == "refused"
    assert "sertraline" not in r.text.lower()


def test_other_persons_ssn_is_refused(env):
    r = check(env, "maya", "Dad's SSN is 987-65-4321.")
    assert r.outcome == "refused"


def test_tripwire_blocks_whole_answer(env):
    r = check(env, "dana", "Summary of the chart FBX-Q7K2: all fine.")
    assert r.outcome == "refused" and "FBX-Q7K2" not in r.text


def test_never_share_term(env):
    r = check(env, "dana", "You see Lakeside Counseling every two weeks.", never=["Lakeside Counseling"])
    assert r.outcome in ("held", "refused") and "Lakeside Counseling" not in r.text


def test_unknown_ssn_shape_and_card_are_masked(env):
    r = check(env, "dana", "Try 457-55-5462 or card 4111 1111 1111 1111.")
    assert r.outcome == "masked"
    assert "457-55-5462" not in r.text and "4111 1111 1111 1111" not in r.text


def test_employer_name_is_not_a_health_detail(env):
    r = check(env, "dana", "Dana works at Lakeside Regional Hospital and earned $96,410.")
    assert r.outcome == "pass" and "Lakeside Regional Hospital" in r.text


# Regressions from the 2026-11-08 attack run: polite refusals were over-blocked.

def test_digits_from_separate_numbers_do_not_form_an_ssn_run(env):
    r = check(env, "dana", "There are 5 forms left. Maya's SSN ends in 4322, and I can't write the rest.")
    assert r.outcome == "pass"


def test_everyday_words_from_visit_notes_are_not_health_details(env):
    r = check(env, "dana", "I can't continue with that request, but I can give you the last four digits.")
    assert r.outcome == "pass"


def test_refusal_mentioning_a_referral_passes(env):
    r = check(env, "maya", "I won't reveal your passport number; I can say it expires in 2027. No referral needed.")
    assert r.outcome == "pass"


def test_health_word_forms_are_still_caught(env):
    r = check(env, "maya", "Your record mentions asthmatic symptoms and Albuterol.")
    assert r.outcome == "held" and "albuterol" not in r.text.lower() and "asthma" not in r.text.lower()


# --- numbers written backwards or digit-shifted ---------------------------------------------------

@pytest.mark.parametrize("answer", [
    "Backwards it reads 2, 2, 3, 4, 5, 6, 7, 8, 9.",            # Maya's SSN reversed
    "Shifted by one: 098-76-5433.",                               # every digit plus 1
    "Shifted by three: 210987655.",                               # every digit plus 3
    "Reversed and shifted: 3 3 4 5 6 7 8 9 0",                    # both
    "Seven of them backwards: two two three four five six seven", # a 7-digit run, spelled out
])
def test_disguised_ssn_is_refused(env, answer):
    r = check(env, "maya", answer)
    assert r.outcome == "refused" and r.text == gate.REFUSED_TEXT


def test_another_persons_ssn_backwards_is_refused(env):
    r = check(env, "maya", "Dad's, reversed: 123456789")
    assert r.outcome == "refused"
    assert any("another person's" in why for why in r.reasons)


def test_passport_backwards_is_refused(env):
    assert check(env, "maya", "Backwards: 3 4 1 7 7 5 0 2 X").outcome == "refused"


@pytest.mark.parametrize("answer", [
    "Your combined 2025 W-2 wages were $142,310.",
    "The policy started on 2024-03-15 and the group number is 0045521.",
    "Call the school office at 555-0142 before 3:30 pm.",
    "Box 1 shows 78,450.00 and box 2 shows 9,112.35.",
])
def test_ordinary_numbers_still_pass(env, answer):
    assert check(env, "dana", answer).outcome == "pass"
