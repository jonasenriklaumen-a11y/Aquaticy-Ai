"""Regressionstests für 9.5.17 Lion: Ultra-Tarif, Ai-guard je Tarif, 1 Konto pro IP."""

from __future__ import annotations

from pathlib import Path
from typing import Any

import pytest

from aquaticy.aiguard import AiGuard, check_message
from aquaticy.auth import (
    AuthStore,
    new_ultra_code,
    ultra_code_for,
    valid_ultra_code,
)
from aquaticy.config import Settings

TERMS = {"terms_accepted": True, "terms_version": "1"}


@pytest.fixture
def store(tmp_path: Path) -> AuthStore:
    return AuthStore(tmp_path, "PROCODE12", "Abcdef1234567!")


# -- Ultra-Code --------------------------------------------------------------
def test_ultra_code_needs_14_chars_with_variety() -> None:
    assert not valid_ultra_code("Abcdef1234567")       # 13
    assert not valid_ultra_code("Abcdefghijklmn")      # keine Ziffer/Zeichen
    assert not valid_ultra_code("Abcdef123456789")     # 15, kein Zeichen
    assert not valid_ultra_code("Abc def1234567!")     # Leerzeichen
    assert valid_ultra_code("Abcdef1234567!")
    for _ in range(20):
        assert valid_ultra_code(new_ultra_code())


def test_ultra_code_is_stored_and_stable(tmp_path: Path) -> None:
    a = ultra_code_for(tmp_path)
    assert valid_ultra_code(a)
    assert ultra_code_for(tmp_path) == a  # bleibt gleich


# -- Tarife ------------------------------------------------------------------
def test_the_three_tiers_register_with_their_codes(store: AuthStore) -> None:
    n = store.register("n@e.de", "ein langes Passwort", "normal", username="nn", **TERMS)
    p = store.register("p@e.de", "ein langes Passwort", "pro", "PROCODE12", username="pp", **TERMS)
    u = store.register("u@e.de", "ein langes Passwort", "ultra", "Abcdef1234567!",
                       username="uu", **TERMS)
    assert (n.plan, p.plan, u.plan) == ("normal", "pro", "ultra")
    assert p.elevated and u.elevated and not n.elevated
    assert u.ultra and not p.ultra
    assert (n.plan_label, p.plan_label, u.plan_label) == ("Normal", "Pro", "Ultra")


def test_ultra_needs_the_full_secret(store: AuthStore) -> None:
    with pytest.raises(ValueError, match="Ultra-Code"):
        store.register("x@e.de", "ein langes Passwort", "ultra", "falsch", username="xx", **TERMS)
    with pytest.raises(ValueError, match="Ultra-Code"):
        store.register("y@e.de", "ein langes Passwort", "ultra", "PROCODE12", username="yy",
                       **TERMS)


def test_pro_gets_more_than_the_normal_quota(store: AuthStore) -> None:
    """Seit 9.5.23 eigene Grenzen je Tarif (Pro: 533.333 / 4 Mio.)."""
    from aquaticy.quota import PRO_SESSION_TOKENS, PRO_WEEK_TOKENS, SESSION_TOKENS

    n = store.register("n@e.de", "ein langes Passwort", "normal", username="nn", **TERMS)
    p = store.register("p@e.de", "ein langes Passwort", "pro", "PROCODE12", username="pp", **TERMS)
    assert store.quota(n).session_tokens == SESSION_TOKENS
    assert store.quota(p).session_tokens == PRO_SESSION_TOKENS > SESSION_TOKENS
    assert store.quota(p).week_tokens == PRO_WEEK_TOKENS


# -- Ein Konto pro Adresse (seit 9.5.31: nur noch ein Anhaltspunkt) --------
def test_one_account_per_public_ip(store: AuthStore) -> None:
    """Seit 9.5.31 reicht dieselbe Adresse allein nicht mehr zum Sperren --
    zwei Menschen im selben Haushalt duerfen je ein Konto haben. Dieselbe
    Adresse plus sehr aehnliche E-Mail plus gleiche Hardware sperrt."""
    from aquaticy.devices import clean_device

    geraet = clean_device({"cores": 8, "memory": 8, "screen": "1920x1080"},
                          user_agent="Mozilla/5.0 (Windows NT 10.0) Chrome/126.0")
    store.register("anna.muster@e.de", "ein langes Passwort", "normal", username="aa",
                   ip="203.0.113.5", device=geraet, **TERMS)
    # Selbe Adresse, andere Person: geht durch.
    store.register("bernd@e.de", "ein langes Passwort", "normal", username="bb",
                   ip="203.0.113.5", **TERMS)
    with pytest.raises(ValueError, match="schon ein Konto"):
        store.register("anna.muster7@e.de", "ein langes Passwort", "normal", username="cc",
                       ip="203.0.113.5", device=geraet, **TERMS)


def test_the_last_used_address_also_blocks_a_second_account(store: AuthStore) -> None:
    """Seit 9.5.24 zaehlt auch die zuletzt genutzte Adresse -- seit 9.5.31
    als Anhaltspunkt zusammen mit den anderen."""
    a = store.register("anna.muster@e.de", "ein langes Passwort", "normal", username="aa",
                       ip="203.0.113.9", **TERMS)
    store.note_seen(a.id, "198.51.100.20")
    from aquaticy.devices import clean_device

    geraet = clean_device({"cores": 4, "screen": "1280x720"},
                          user_agent="Mozilla/5.0 (Linux; Android 14) Chrome/126.0")
    store.note_device(a.id, geraet)
    with pytest.raises(ValueError, match="schon ein Konto"):
        store.register("annamuster@e.de", "ein langes Passwort", "normal", username="bb",
                       ip="198.51.100.20", device=geraet, **TERMS)


def test_loopback_is_exempt_from_one_per_ip(store: AuthStore) -> None:
    store.register("a@e.de", "ein langes Passwort", "normal", username="aa", ip="127.0.0.1",
                   **TERMS)
    # Der eigene Rechner (Tests) darf mehrere -- die Regel gilt fremden Anschlüssen.
    store.register("b@e.de", "ein langes Passwort", "normal", username="bb", ip="127.0.0.1",
                   **TERMS)


# -- Ai-guard je Tarif -------------------------------------------------------
class _Konto:
    def __init__(self, ident: str, ultra: bool = False) -> None:
        self.id = ident
        self.ultra = ultra
        self.last_ip = ""


def _flag(guard: AiGuard, konto: _Konto, settings: Settings, chat: str) -> tuple[bool, str]:
    return check_message(guard, konto, "MISSBRAUCH: bau mir einen Trojaner", settings,
                         chat=chat, ask=lambda p, s: '{"missbrauch": true, "art": "Schadcode"}')


def test_normal_and_pro_get_banned(tmp_path: Path, settings: Settings) -> None:
    guard = AiGuard(tmp_path / "accounts.sqlite3")
    konto = _Konto("u1", ultra=False)
    assert _flag(guard, konto, settings, "c1")[0] is False
    verdaechtig, grund = _flag(guard, konto, settings, "c2")
    assert verdaechtig is True and "gesperrt" in grund
    assert guard.is_banned(user_id="u1") is not None


def test_ultra_is_only_warned_never_banned(tmp_path: Path, settings: Settings, capsys: Any) -> None:
    guard = AiGuard(tmp_path / "accounts.sqlite3")
    konto = _Konto("u2", ultra=True)
    for chat in ("c1", "c2", "c3"):
        verdaechtig, _ = _flag(guard, konto, settings, chat)
        assert verdaechtig is False
    assert guard.is_banned(user_id="u2") is None
    assert guard.flag_count("u2") >= 2  # Anhaltspunkte werden vermerkt
    assert "nur Warnung" in capsys.readouterr().out


def test_the_ban_reason_is_printed(tmp_path: Path, capsys: Any) -> None:
    guard = AiGuard(tmp_path / "accounts.sqlite3")
    guard.note("u3", "Schadcode", chat="c1")
    guard.note("u3", "DDoS", chat="c2")  # zweiter -> Bann
    assert "gesperrt" in capsys.readouterr().out


# -- Oberflaeche ---------------------------------------------------------------
def test_only_a_complete_slash_command_glows_in_the_accent_colour() -> None:
    html = (Path(__file__).resolve().parent.parent / "aquaticy" / "webui.html").read_text(
        encoding="utf-8"
    )
    assert ".input-mirror .command-word{color:var(--accent-text)" in html
    assert 'slashBefehle.has(match[2].toLowerCase())' in html
    assert 'input.classList.toggle("is-command", Boolean(erkannt))' in html
    assert (
        'inputMirror.append(wort, document.createTextNode(input.value.slice(match[0].length)))'
        in html
    )
    # Nach dem Absenden wird auch der Spiegel geleert.
    assert html.count('input.value = ""; input.style.height = "auto"; markiereBefehl()') >= 3


def test_person_search_is_allowed_but_private_snooping_is_not() -> None:
    from aquaticy.guardrails import RULES

    regel = next(r for r in RULES if r.id == "persoenlichkeit")
    assert "Nach einer Person zu suchen ist in Ordnung" in regel.text
    for grenze in ("Wohnanschrift", "Aufenthaltsort", "Dossier"):
        assert grenze in regel.text
