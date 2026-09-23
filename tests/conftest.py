"""Gemeinsame Test-Fixtures."""

from __future__ import annotations

from pathlib import Path

import pytest

FIXTURE_DIR = Path(__file__).parent / "fixtures"


@pytest.fixture
def fixture_html() -> callable:
    """Laedt eine HTML-Fixture nach Namen."""

    def _load(name: str) -> str:
        return (FIXTURE_DIR / name).read_text(encoding="utf-8")

    return _load


@pytest.fixture
def settings(tmp_path: Path):
    """Settings, die nichts ausserhalb von tmp_path anfassen."""
    from aquaticy.config import Settings

    return Settings(
        model="mistral/mistral-large-latest",
        data_dir=tmp_path / "data",
        request_delay_seconds=0.0,
        fetch_timeout=5.0,
        enable_playwright=False,
        # Die automatische Vorrecherche wird gezielt in eigenen Tests
        # geprueft -- sonst verbraucht sie hier ueberall einen LLM-Aufruf.
        subagents_auto=False,
    )


@pytest.fixture(autouse=True)
def _rechtspruefer_ohne_netz(monkeypatch):
    """Der Rechtspruefer fragt sonst bei jeder Frage ein echtes Modell.

    Er wird gezielt in tests/test_guardrails.py geprueft -- dort mit eigenen
    Antworten. Ueberall sonst sagt er "zulaessig", damit Tests fuer andere
    Dinge weder ins Netz gehen noch ihre Aufrufe falsch zaehlen.
    """
    from aquaticy import guardrails

    guardrails.forget_verdicts()
    monkeypatch.setattr(
        guardrails,
        "_ask_model",
        lambda prompt, model, settings: '{"zulaessig": true, "regel": "", "grund": ""}',
    )


@pytest.fixture(autouse=True)
def _keine_echte_env(monkeypatch, tmp_path_factory):
    """Kein Test schreibt in die echte `.env` -- und keiner erbt die eines anderen.

    Ohne Konto schreibt `save_values` in die erste gefundene `.env`, und das
    war bisher `~/.config/aquaticy/.env` des Menschen, der die Tests laufen
    laesst: sein Standard-Ort stand danach auf "Bremen", sein Kontextfenster
    auf 32000. Ausserdem laedt das Speichern die Datei mit `override` in die
    Prozessumgebung -- dort blieb der Wert fuer alle folgenden Tests stehen.
    """
    import os

    from aquaticy import cli, config, web

    ziel = tmp_path_factory.mktemp("env") / ".env"
    monkeypatch.setattr(config, "ENV_CANDIDATES", (ziel,))
    for modul in (config, web, cli):
        monkeypatch.setattr(modul, "DEFAULT_ENV_PATH", ziel)
    vorher = dict(os.environ)
    yield
    os.environ.clear()
    os.environ.update(vorher)
    config.reset_settings_cache()
