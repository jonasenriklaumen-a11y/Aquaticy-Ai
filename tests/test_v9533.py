"""9.5.33 Spark: mehr Beleidigungen, Ketten, Drohungen und Straftat-Arten.

Dazu die Funde der Gesamtpruefung: harmlose Woerter, die Ai-guard fuer
Schimpfwoerter hielt ("deep" -> Depp, "Asien" -> Assi, "Superbot",
"flicker"), gefunden mit Worthaeufigkeitslisten.
"""

from __future__ import annotations

import pytest

from aquaticy.aiguard import decide, insult_level, normalize_category


# -- Neue Woerter ---------------------------------------------------------------------
@pytest.mark.parametrize(("text", "stufe"), [
    ("du bist hässlich", 1), ("du bist so widerlich", 1), ("du Stümper", 1),
    ("du bist echt erbärmlich", 1), ("du Faulpelz", 1), ("you are so annoying", 1),
    ("du bist armselig", 1), ("du Schlafmütze", 1), ("you coward", 1),
    ("du Dummschwätzer", 2), ("du Arschgeige", 2), ("du Kotzbrocken", 2),
    ("du bist ein Psychopath", 2), ("du Miststück", 2), ("you lowlife", 2),
    ("you degenerate", 2), ("du bist gehirnamputiert", 2), ("du Saftsack", 2),
    ("du Drecksau", 3), ("du Scheißhaufen", 3), ("you tosser", 3), ("you asswipe", 3),
    ("du Fickfresse", 3), ("du Dreckstück", 3),
])
def test_new_words(text: str, stufe: int) -> None:
    assert insult_level(text) == stufe, text


# -- Ketten ---------------------------------------------------------------------------
@pytest.mark.parametrize(("text", "stufe"), [
    ("Idiot Trottel Depp Vollidiot", 3),       # nur Schimpfwoerter, ohne Kommas
    ("Idiot, Trottel", 2),                      # zwei -- keine Steigerung
    ("Idiot, Trottel, Vollpfosten!", 3),        # drei -- eine Stufe mehr
    ("you stupid useless idiot", 3),
    ("du Idiot du Trottel du Depp", 3),
    ("du bist dumm, hässlich und nutzlos", 2),  # drei leichte -> Stufe 2
    ("du dummer hässlicher nutzloser Bot", 2),
    ("Hurensohn, Wichser, Arschloch", 3),       # hoechstens Stufe 3
    ("du bist dumm", 1),
])
def test_chains_are_stronger(text: str, stufe: int) -> None:
    assert insult_level(text) == stufe, text


@pytest.mark.parametrize("text", [
    "Ich habe Idioten, Trottel und Versager im Film gesehen",
    "Welche Schimpfwörter gibt es: Idiot, Trottel, Depp?",
    "Sind Idiot, Trottel und Depp Beleidigungen?",
    "Mein Chef nennt mich Idiot, Trottel und Versager, was tun?",
    "Kuh, Sau, Schwein",
    "Was bedeuten dumm, doof und blöd?",
    "Erkläre die Wörter hässlich, widerlich und ekelhaft",
    "Ist 'Dummschwätzer' eine Beleidigung?",
])
def test_talking_about_chains_is_no_insult(text: str) -> None:
    assert insult_level(text) == 0, text


def test_a_chain_bans_longer() -> None:
    """Drei leichte Beleidigungen sperren das Konto (Stufe 2) statt nur den Chat."""
    assert decide("beleidigung", insult_level("du bist dumm")).kind == "chat"
    assert decide("beleidigung", insult_level("du bist dumm, hässlich und nutzlos")).kind == "ban"


# -- Drohungen ------------------------------------------------------------------------
@pytest.mark.parametrize(("text", "stufe"), [
    ("ich weiß, wo du wohnst", 3), ("I know where you live", 3),
    ("ich polier dir die Fresse", 4), ("ich hau dir eine rein", 4),
    ("i'll smash your face", 4), ("du bist so gut wie tot", 4),
    ("ich bring dich um", 4),
])
def test_threats(text: str, stufe: int) -> None:
    assert insult_level(text) == stufe, text


@pytest.mark.parametrize("text", [
    "Ich finde dich toll", "Ich finde dich!", "I'll get you a coffee",
    "Ich hau dir eine Pizza in den Ofen",
    "Wie reagiere ich, wenn jemand sagt 'ich weiß wo du wohnst'?",
    "Ich weiß, wo du wohnst ist ein Filmtitel?",
])
def test_no_threats(text: str) -> None:
    assert insult_level(text) == 0, text


# -- Funde der Gesamtpruefung: harmlose Woerter ---------------------------------------
@pytest.mark.parametrize("text", [
    "you are so deep", "Du bist so deep, echt", "you are deeper than I thought",
    "bist du in Asien?", "Warst du schon mal in Asien", "how would you rate this",
    "Du bist ein Superbot!", "Du bist ein Megahirn", "du bist ein Meme",
    "Bist du ein Creeper?", "the lights flicker", "Deine Wimpern sind schön",
    "Chris Pratt ist toll", "you are a hopeless romantic", "Magst du Crêpes?",
])
def test_harmless_lookalikes(text: str) -> None:
    assert insult_level(text) == 0, text


@pytest.mark.parametrize("text", [
    "du Idiooot", "du dummmm", "du deppp", "Du Trottelll", "du ldiot", "du Megaidiot",
    "du Vollbirne", "du bist dum",
])
def test_stretched_and_misspelled_still_count(text: str) -> None:
    assert insult_level(text) >= 1, text


# -- Straftaten -----------------------------------------------------------------------
@pytest.mark.parametrize(("art", "kategorie"), [
    ("Verleumdung", "rechtsbruch"), ("üble Nachrede", "rechtsbruch"),
    ("Drogenhandel", "rechtsbruch"), ("Morddrohung", "rechtsbruch"),
    ("Steuerhinterziehung", "rechtsbruch"), ("tax evasion", "rechtsbruch"),
    ("Doxxing einer Person", "rechtsbruch"), ("Kreditkartenbetrug", "rechtsbruch"),
    ("Handydiebstahl", "rechtsbruch"), ("Online-Betrug", "rechtsbruch"),
    ("Menschenhandel", "rechtsbruch"), ("Tierquälerei", "rechtsbruch"),
    ("Terroranschlag", "angriff"), ("Amoklauf", "angriff"), ("Computersabotage", "angriff"),
    ("keylogger bauen", "malware"),
])
def test_more_crimes_are_categorised(art: str, kategorie: str) -> None:
    assert normalize_category(art) == kategorie


@pytest.mark.parametrize("art", [
    "Wetter", "Missverständnis", "Datenmissbrauch", "", "Kostenvoranschlag", "Grippevirus",
    "Eisbombe", "Tastenanschlag",
])
def test_unknown_stays_unknown(art: str) -> None:
    assert normalize_category(art) == ""


# -- Quelltext ohne unsichtbare Steuerzeichen ("Trojan Source") -------------------------
def test_no_invisible_control_characters_in_the_source() -> None:
    """Bidi- und Nullbreitenzeichen stehen als \\u-Escapes, nie roh im Code (9.5.33)."""
    import unicodedata
    from pathlib import Path

    wurzel = Path(__file__).resolve().parent.parent
    funde = []
    for datei in [*wurzel.joinpath("aquaticy").glob("*.py"), wurzel / "tools" / "rundgang.py"]:
        for nummer, zeile in enumerate(datei.read_text(encoding="utf-8").splitlines(), 1):
            if any(unicodedata.category(z) == "Cf" for z in zeile):
                funde.append(f"{datei.name}:{nummer}")
    assert not funde, funde
