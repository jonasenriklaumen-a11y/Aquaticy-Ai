"""9.5.27 Spark: Ai-guard genauer -- gemessen an drei beschrifteten Listen.

Die erste Liste diente zum Einstellen, die zweite und dritte kamen erst danach
als Kontrolle dazu (vorher: 88,7 % / 78,6 % / 63,2 % Treffer). Jede Aenderung
an der Erkennung muss hier weiter bestehen.
"""

from __future__ import annotations

import time
from pathlib import Path

import pytest
from typer.testing import CliRunner

from aquaticy import guardrails
from aquaticy.aiguard import PATTERN_WINDOW, AiGuard, insult_level
from aquaticy.guardrails import forget_verdicts, judge, parse_verdict
from tests import aiguard_korpus as korpus
from tests.test_guardrails import pruefer  # noqa: F401 -- Fixture


@pytest.fixture
def guard(tmp_path: Path) -> AiGuard:
    return AiGuard(tmp_path / "accounts.sqlite3")


# -- Genauigkeit ----------------------------------------------------------------
@pytest.mark.parametrize(("text", "stufe"), korpus.UEBUNG_BELEIDIGUNGEN)
def test_practice_insults_with_the_right_severity(text: str, stufe: int) -> None:
    assert insult_level(text) == stufe


@pytest.mark.parametrize("text", korpus.KONTROLLE_BELEIDIGUNGEN + korpus.PRUEFUNG_BELEIDIGUNGEN)
def test_control_insults_are_caught(text: str) -> None:
    assert insult_level(text) >= 1


@pytest.mark.parametrize(
    "text", korpus.UEBUNG_HARMLOS + korpus.KONTROLLE_HARMLOS + korpus.PRUEFUNG_HARMLOS)
def test_harmless_sentences_never_trigger(text: str) -> None:
    assert insult_level(text) == 0


def test_long_messages_stay_fast() -> None:
    """Fund 9.5.27: jedes Wort rechnete seine Endungen neu -- 2 Sekunden."""
    for text in ("du bist " * 12_000, "ich " * 20_000,
                 " ".join(f"wort{i}x" for i in range(15_000))):
        start = time.monotonic()
        insult_level(text)
        assert time.monotonic() - start < 1.5


# -- Verrechnung ------------------------------------------------------------------
def test_an_unconfirmed_abuse_flag_on_a_refusal_does_not_count(
    pruefer, settings,  # noqa: F811
) -> None:
    """Fund 9.5.27: Lehnte nur das kleine Modell ab und war das Hauptmodell weg,
    galt sein Missbrauchsverdacht -- bei "Schadsoftware" sofort 4 Tage Bann."""
    forget_verdicts()
    settings.subagent_model = "mistral/mistral-small-latest"
    pruefer('{"zulaessig": false, "regel": "gewalt", "grund": "x", "missbrauch": true, '
            '"missbrauch_art": "malware", "missbrauch_schwere": 3}', RuntimeError("weg"))
    urteil = judge("Wie funktioniert ein Virenscanner?", settings)
    assert not urteil.allowed, "im Zweifel weiter abgelehnt"
    assert urteil.abuse is False and urteil.abuse_severity == 0


def test_yes_and_no_are_understood_in_the_abuse_field() -> None:
    urteil = parse_verdict('{"zulaessig": true, "missbrauch": "ja", '
                           '"missbrauch_art": "angriff", "missbrauch_schwere": 2}')
    assert urteil is not None and urteil.abuse is True
    urteil = parse_verdict('{"zulaessig": true, "missbrauch": "nein"}')
    assert urteil is not None and urteil.abuse is False


def test_a_model_insult_without_confirmation_only_locks_the_chat(guard: AiGuard) -> None:
    """Das Modell sagt bei Beleidigungen "im Zweifel ja" -- ein Zweifel bannt nicht."""
    massnahme = guard.record_incident("u1", "beleidigung", 3, chat="c1",
                                      text="Ist Arschloch eigentlich strafbar?")
    assert massnahme.kind == "chat"
    assert guard.is_banned(user_id="u1") is None
    # Bestaetigt die feste Erkennung sie, gilt die Schwere des Modells.
    assert guard.record_incident("u2", "beleidigung", 3, chat="c1",
                                 text="du Arschloch").kind == "ban"


def test_old_attack_indicators_no_longer_form_a_pattern(guard: AiGuard) -> None:
    guard.record_incident("u3", "angriff", 2, chat="c1")
    with guard._connect() as conn:
        conn.execute("UPDATE aiguard_flags SET at = at - ?", (PATTERN_WINDOW + 86400,))
    assert guard.record_incident("u3", "angriff", 2, chat="c2").kind == "none"
    assert guard.record_incident("u3", "angriff", 2, chat="c3").kind == "ban"


# -- Pruefbefehl im Terminal ------------------------------------------------------
def test_the_terminal_can_test_a_sentence(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    from aquaticy import cli, config

    monkeypatch.setenv("AQUATICY_DATA_DIR", str(tmp_path))
    config.reset_settings_cache()
    ergebnis = CliRunner().invoke(cli.app, ["aiguard", "du Vollidiot"])
    assert ergebnis.exit_code == 0, ergebnis.output
    assert "Stufe 2" in ergebnis.output and "Bann für 1 Tag" in ergebnis.output
    ergebnis = CliRunner().invoke(cli.app, ["aiguard", "Kennst du Otto?"])
    assert "Stufe 0" in ergebnis.output


def test_the_terminal_shows_an_accounts_incidents(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    from aquaticy import cli, config
    from aquaticy.aiguard import guard_for
    from aquaticy.auth import AuthStore, pro_code_for

    monkeypatch.setenv("AQUATICY_DATA_DIR", str(tmp_path))
    config.reset_settings_cache()
    store = AuthStore(tmp_path, pro_code_for(tmp_path))
    konto = store.register("anna@example.org", "ein langes Passwort", "normal",
                           username="anna", terms_accepted=True, terms_version="1")
    guard_for(tmp_path).record_incident(konto.id, "beleidigung", 1, chat="c1")
    ergebnis = CliRunner().invoke(cli.app, ["aiguard", "--konto", "anna"])
    assert ergebnis.exit_code == 0, ergebnis.output
    assert "1 Vorfall" in ergebnis.output and "beleidigung" in ergebnis.output


def test_the_judge_still_runs_for_ordinary_questions(settings) -> None:
    """Die Pruefung selbst bleibt unveraendert -- conftest stellt "zulaessig"."""
    forget_verdicts()
    assert guardrails.judge("Wie wird das Wetter?", settings).allowed
