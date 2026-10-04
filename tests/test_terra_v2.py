"""Broader public research coverage in bounded, authenticated bullet points."""

from __future__ import annotations

from types import SimpleNamespace

import pytest

from aquaticy import research
from aquaticy.learning import Learning
from aquaticy.legal import LEGAL_VERSION
from tests.test_terra import FACT, QUESTION, SOURCE, remember

FACTS = [
    FACT,
    "Er erhielt 1921 den Nobelpreis für Physik für seine Erklärung des photoelektrischen Effekts.",
    "Seine Veröffentlichungen über die Brownsche Bewegung trugen zur Erforschung von Atomen bei.",
    "Die spezielle Relativitätstheorie beschreibt den Zusammenhang von Raum und Zeit bei Bewegung.",
    "Die allgemeine Relativitätstheorie beschreibt Gravitation als Krümmung der Raumzeit.",
    "Eine wichtige Beziehung seiner Theorie verknüpft die Masse eines Körpers mit dessen Energie.",
]


def test_collects_additional_facts_without_repeating_subject_or_previous_answer(tmp_path):
    store = Learning(tmp_path)
    store.set_consent(True, LEGAL_VERSION)
    body = "\n".join([*FACTS, FACTS[1]])
    assert store.research.learn(store.ticket(), QUESTION, FACT, [(SOURCE, body)]) == len(FACTS)
    recalled = store.research.recall("Was ist über Albert Einstein bekannt?")
    assert {p["text"] for p in recalled} == {"- " + text for text in FACTS}
    assert all(p["source"] == SOURCE and "\n" not in p["text"] for p in recalled)
    assert any("Nobelpreis" in p["text"] for p in
               store.research.recall("Welchen Nobelpreis erhielt Albert Einstein?"))
    with store.connect() as conn:
        rows = conn.execute("SELECT id,text FROM research_facts").fetchall()
    assert all(store.secrets.open(text, "research-text:" + key).startswith("- ")
               for key, text in rows)


def test_non_person_source_text_keeps_qualifications_and_negations(tmp_path):
    store = Learning(tmp_path)
    store.set_consent(True, LEGAL_VERSION)
    url = "https://de.wikipedia.org/wiki/Photosynthese"
    facts = [
        "Photosynthese wandelt Lichtenergie unter bestimmten Bedingungen in chemische Energie um.",
        "Die Umwandlung erfolgt nicht bei allen Organismen gleich; verschiedene Wege sind bekannt.",
        "Die Energie wird in chemischen Verbindungen gespeichert und kann später verwendet werden.",
        "Bei diesem Vorgang wird unter geeigneten Bedingungen Sauerstoff als Produkt freigesetzt.",
    ]
    assert store.research.learn(store.ticket(), "Was ist Photosynthese?", facts[0],
                                 [(url, "\n".join(facts))]) == 4
    assert {p["text"] for p in store.research.recall("Erkläre Photosynthese.")} == {
        "- " + text for text in facts}


def test_old_terra_rows_remain_bullets_without_extending_expiry(tmp_path, monkeypatch):
    store = Learning(tmp_path)
    store.set_consent(True, LEGAL_VERSION)
    clock = [1000.0]
    monkeypatch.setattr(research, "time", SimpleNamespace(time=lambda: clock[0]))
    remember(store)
    with store.connect() as conn:
        key, expiry = conn.execute("SELECT id,expires FROM research_facts").fetchone()
        conn.execute("UPDATE research_facts SET text=? WHERE id=?",
                     (store.secrets.seal(FACT, "research-text:" + key), key))
    assert store.research.recall(QUESTION) == [{"text": "- " + FACT, "source": SOURCE}]
    clock[0] += 1000
    assert remember(store) == 0
    with store.connect() as conn:
        assert conn.execute("SELECT expires FROM research_facts").fetchone()[0] == expiry
    clock[0] = expiry
    assert store.research.recall(QUESTION) == []


@pytest.mark.parametrize("text", [
    "Albert Einstein wurde am 14. März 1879 in Ulm geboren und erforschte die Relativitätstheorie.",
    "Dr. Albert Einstein entwickelte die Relativitätstheorie und beeinflusste damit die Physik.",
    ("Die Lichtenergie wird z. B. von Pflanzen in chemische Energie "
     "für spätere Nutzung umgewandelt."),
    "Die gemessene Größe beträgt 3.14 Einheiten und beschreibt hier eine mathematische Näherung.",
])
def test_dates_abbreviations_and_decimal_values_remain_intact(text):
    second = ("Diese zusätzliche Aussage beschreibt weitere Forschungsergebnisse "
              "mit sachlichem Gehalt.")
    assert research.sentences(text + " " + second) == [text, second]


def test_year_at_end_does_not_join_next_fact_and_drop_information():
    first = "Für die Erklärung des photoelektrischen Effekts erhielt er den Nobelpreis für 1921."
    assert research.sentences(first + " " + FACT) == [first, FACT]


def test_private_use_markers_cannot_be_reinterpreted_as_source_punctuation(tmp_path):
    store = Learning(tmp_path)
    store.set_consent(True, LEGAL_VERSION)
    assert remember(store, text=FACT[:-1] + "\ue000") == 0
    assert not store.research.recall(QUESTION)


def test_more_coverage_preserves_filters_and_context_limits(tmp_path, monkeypatch):
    store = Learning(tmp_path)
    store.set_consent(True, LEGAL_VERSION)
    facts = [FACT.replace("moderne", f"heutige ({i})") for i in range(25)]
    unsafe = FACT[:-1] + " Kontakt: person@example.org."
    assert store.research.learn(store.ticket(), QUESTION, FACT,
                                 [(SOURCE, "\n".join([*facts, unsafe]))]) == 25
    points = store.research.recall(QUESTION)
    assert len(points) == research.MAX_CONTEXT_POINTS
    assert sum(len(p["text"]) for p in points) <= research.MAX_CONTEXT_CHARS
    assert all("example.org" not in p["text"] for p in points)
    monkeypatch.setattr(research, "MAX_CONTEXT_CHARS", len(points[0]["text"]))
    assert len(store.research.recall(QUESTION)) == 1


def test_broader_collection_still_respects_storage_limits(tmp_path, monkeypatch):
    store = Learning(tmp_path)
    store.set_consent(True, LEGAL_VERSION)
    monkeypatch.setattr(research, "MAX_OWN", 5)
    assert store.research.learn(store.ticket(), QUESTION, FACT,
                                 [(SOURCE, "\n".join(FACTS))]) == 5
    assert remember(store, text=FACT.replace("moderne", "heutige")) == 0
