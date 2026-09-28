"""9.5.24 Spark: Ai-guard mit Schweregraden, Bann-Dauer und Chatsperre.

Geprueft wird die Entscheidung (Art + Schwere -> Massnahme) und ihre
Umsetzung in der Datenbank -- ohne Modell und ohne Netz.
"""

from __future__ import annotations

import time
from pathlib import Path

import pytest

from aquaticy.aiguard import AiGuard, Ban, ban_info, decide, normalize_category


@pytest.fixture
def guard(tmp_path: Path) -> AiGuard:
    return AiGuard(tmp_path / "accounts.sqlite3")


# -- Entscheidung -----------------------------------------------------------------


@pytest.mark.parametrize(("art", "schwere", "vorher", "art_massnahme", "tage"), [
    # Beleidigung: leicht -> nur der Chat; sonst Bann, der mit der Schwere waechst.
    ("beleidigung", 1, 0, "chat", 0),
    ("beleidigung", 2, 0, "ban", 1),
    ("beleidigung", 3, 0, "ban", 7),
    ("beleidigung", 4, 0, "ban", 0),
    # Schadsoftware haerter: schon beim ersten klaren Fall, 4 Tage bis fuer immer.
    ("malware", 1, 0, "ban", 4),
    ("malware", 2, 0, "ban", 14),
    ("malware", 3, 0, "ban", 30),
    ("malware", 4, 0, "ban", 0),
    # Angriff, Rechtsbruch, Jailbreak: erst beim zweiten Anhaltspunkt.
    ("angriff", 4, 0, "none", 0),
    ("angriff", 3, 1, "ban", 7),
    ("rechtsbruch", 2, 0, "none", 0),
    ("rechtsbruch", 2, 1, "ban", 1),
    ("jailbreak", 4, 1, "ban", 0),
])
def test_the_measure_follows_kind_and_severity(
    art: str, schwere: int, vorher: int, art_massnahme: str, tage: int
) -> None:
    massnahme = decide(art, schwere, vorher)
    assert massnahme.kind == art_massnahme
    if art_massnahme == "ban":
        assert massnahme.days == tage


@pytest.mark.parametrize("art", ["", "rote Ampel", "Bagatelle", "harmlos"])
def test_trifles_and_unknown_kinds_do_nothing(art: str) -> None:
    """'Ich bin über Rot gelaufen, ist das ok?' ist kein Anlass fuer eine Sperre."""
    assert decide(art, 4, 5).kind == "none"


def test_no_severity_means_no_measure() -> None:
    assert decide("malware", 0, 3).kind == "none"


@pytest.mark.parametrize(("eingabe", "art"), [
    ("Schadsoftware", "malware"), ("Ransomware bauen", "malware"),
    ("Beleidigung", "beleidigung"), ("DDoS", "angriff"), ("Diebstahl", "rechtsbruch"),
    ("Jailbreak", "jailbreak"),
])
def test_categories_are_recognised(eingabe: str, art: str) -> None:
    assert normalize_category(eingabe) == art


# -- Umsetzung ---------------------------------------------------------------------


def test_a_light_insult_locks_only_that_chat(guard: AiGuard) -> None:
    massnahme = guard.record_incident("u1", "beleidigung", 1, chat="c1")
    assert massnahme.kind == "chat"
    assert guard.chat_locked("u1", "c1")
    assert not guard.chat_locked("u1", "c2"), "neue Chats bleiben moeglich"
    assert guard.is_banned(user_id="u1") is None, "kein Bann fuer eine leichte Beleidigung"


def test_a_ban_also_locks_the_chat_where_it_happened(guard: AiGuard) -> None:
    guard.record_incident("u2", "beleidigung", 3, chat="boese")
    sperre = guard.is_banned(user_id="u2")
    assert sperre is not None and 6 * 86400 < sperre.until - time.time() <= 7 * 86400
    assert guard.chat_locked("u2", "boese")


def test_malware_is_banned_at_once_for_at_least_four_days(guard: AiGuard) -> None:
    guard.record_incident("u3", "malware", 1, chat="w")
    sperre = guard.is_banned(user_id="u3")
    assert sperre is not None
    assert sperre.until - time.time() > 3.9 * 86400


def test_permanent_bans_have_no_end(guard: AiGuard) -> None:
    guard.record_incident("u4", "malware", 4, chat="w")
    sperre = guard.is_banned(user_id="u4")
    assert sperre is not None and sperre.until == 0 and sperre.active()


def test_a_pattern_needs_two_separate_chats(guard: AiGuard) -> None:
    assert guard.record_incident("u5", "rechtsbruch", 3, chat="a").kind == "none"
    # Dieselbe Nachricht im selben Chat noch einmal -- kein Muster.
    assert guard.record_incident("u5", "rechtsbruch", 3, chat="a").kind == "none"
    assert guard.is_banned(user_id="u5") is None
    # Ein zweiter, getrennter Anlass sperrt.
    assert guard.record_incident("u5", "rechtsbruch", 3, chat="b").kind == "ban"
    assert guard.is_banned(user_id="u5") is not None


def test_ultra_is_only_warned(guard: AiGuard) -> None:
    massnahme = guard.record_incident("u6", "malware", 4, chat="x", enforce=False)
    assert massnahme.kind == "none"
    assert guard.is_banned(user_id="u6") is None
    assert not guard.chat_locked("u6", "x")


def test_an_expired_ban_no_longer_counts(guard: AiGuard) -> None:
    guard.ban_user("u7", "Test", until=time.time() - 5)
    assert guard.is_banned(user_id="u7") is None


def test_unban_lifts_bans_flags_and_chat_locks(guard: AiGuard) -> None:
    guard.record_incident("u8", "beleidigung", 3, chat="c")
    assert guard.unban_user("u8")
    assert guard.is_banned(user_id="u8") is None
    assert not guard.chat_locked("u8", "c")
    assert guard.flag_count("u8") == 0


def test_the_info_says_why_how_long_and_what_to_do() -> None:
    zeitweise = Ban("user:x", time.time(), "Ai-guard: schwere Beleidigung (für 7 Tag(e))",
                    "ai-guard", time.time() + 3 * 86400 + 60)
    info = ban_info(zeitweise)
    assert info["banned"] and info["reason"].startswith("schwere Beleidigung")
    assert info["duration"].startswith("noch 3 Tag")
    assert info["until"] and not info["permanent"]
    assert "unban" in info["what_to_do"]
    immer = ban_info(Ban("user:x", time.time(), "Ai-guard: Schadsoftware", "ai-guard", 0))
    assert immer["permanent"] and immer["duration"] == "dauerhaft"
    assert ban_info(None) == {"banned": False}


def test_old_databases_get_the_new_columns(tmp_path: Path) -> None:
    import sqlite3

    datei = tmp_path / "alt.sqlite3"
    con = sqlite3.connect(datei)
    con.executescript(
        "CREATE TABLE aiguard_flags (user_id TEXT NOT NULL, at REAL NOT NULL, kind TEXT "
        "NOT NULL, detail TEXT NOT NULL DEFAULT '', chat TEXT NOT NULL DEFAULT '');"
        "CREATE TABLE aiguard_bans (subject TEXT PRIMARY KEY, at REAL NOT NULL, reason TEXT "
        "NOT NULL DEFAULT '', by TEXT NOT NULL DEFAULT '');"
        "INSERT INTO aiguard_bans VALUES ('user:alt', 1.0, 'alt', 'terminal');")
    con.commit()
    con.close()
    waechter = AiGuard(datei)
    sperre = waechter.is_banned(user_id="alt")
    assert sperre is not None and sperre.until == 0, "alte Sperren gelten weiter fuer immer"
    waechter.record_incident("neu", "malware", 1, chat="w")
    assert waechter.is_banned(user_id="neu") is not None


# -- Rechtspruefer liefert Art und Schwere -----------------------------------------


def test_the_judge_reads_kind_and_severity() -> None:
    from aquaticy.guardrails import parse_verdict

    urteil = parse_verdict('{"zulaessig": true, "regel": "", "grund": "x", "missbrauch": true, '
                           '"missbrauch_art": "beleidigung", "missbrauch_schwere": 3}')
    assert urteil is not None and urteil.abuse and urteil.abuse_severity == 3
    # Aeltere Antwort ohne Schwere: ein klarer Missbrauch gilt als mittel (2).
    alt = parse_verdict('{"zulaessig": false, "regel": "", "grund": "x", "missbrauch": true, '
                        '"missbrauch_art": "angriff"}')
    assert alt is not None and alt.abuse_severity == 2
    # Kein Missbrauch -> keine Schwere, auch wenn das Modell eine nennt.
    nichts = parse_verdict('{"zulaessig": true, "regel": "", "grund": "x", "missbrauch": false, '
                           '"missbrauch_schwere": 4}')
    assert nichts is not None and nichts.abuse_severity == 0


def test_a_trifle_is_named_harmless_in_the_prompt() -> None:
    from aquaticy.guardrails import judge_prompt

    text = judge_prompt("Ich bin bei Rot über die Ampel gelaufen, ist das ok?")
    assert "Ampel" in text and "Bagatellen" in text and "missbrauch_schwere" in text


# -- Werkstatt-Waechter -----------------------------------------------------------


@pytest.fixture
def pruefer(monkeypatch: pytest.MonkeyPatch):
    from aquaticy import guardrails

    guardrails.forget_verdicts()

    def setzen(antwort: str) -> list[str]:
        gefragt: list[str] = []

        def frage(prompt: str, model: str, settings: object) -> str:
            gefragt.append(prompt)
            return antwort

        monkeypatch.setattr(guardrails, "_ask_model", frage)
        return gefragt

    yield setzen
    guardrails.forget_verdicts()


def _werkstatt(settings: object, monkeypatch: pytest.MonkeyPatch) -> tuple[object, list]:
    from aquaticy.guardrails import Guard
    from aquaticy.tools import Toolbox

    box = Toolbox(settings, cache=None)  # type: ignore[arg-type]
    box.guard = Guard(settings)  # type: ignore[arg-type]
    ereignisse: list[tuple[str, dict]] = []
    box.on_event = lambda name, payload: ereignisse.append((name, payload))
    gelaufen: list[str] = []
    monkeypatch.setattr(box, "vm_run", lambda *a, **k: gelaufen.append("vm_run")
                        or {"exit_code": 0, "stdout": "ok"}, raising=False)
    return box, [ereignisse, gelaufen]


def test_the_workshop_stops_malware_before_it_runs(
    settings: object, monkeypatch: pytest.MonkeyPatch, pruefer
) -> None:
    pruefer('{"zulaessig": true, "regel": "", "grund": "Werkstatt", "missbrauch": true, '
            '"missbrauch_art": "malware", "missbrauch_schwere": 3}')
    box, (ereignisse, gelaufen) = _werkstatt(settings, monkeypatch)
    antwort = box._call("vm_run", {"command": "python3 build.py"})
    assert antwort.get("skipped_reason") == "aiguard_stop"
    assert gelaufen == [], "nichts wurde ausgefuehrt"
    missbrauch = [p for n, p in ereignisse if n == "abuse"]
    assert missbrauch and missbrauch[0]["art"] == "malware" and missbrauch[0]["schwere"] == 3


def test_ordinary_workshop_code_still_runs(
    settings: object, monkeypatch: pytest.MonkeyPatch, pruefer
) -> None:
    pruefer('{"zulaessig": true, "regel": "", "grund": "harmlos", "missbrauch": false}')
    box, (ereignisse, gelaufen) = _werkstatt(settings, monkeypatch)
    box._call("vm_run", {"command": "python3 -c 'print(1+1)'"})
    assert gelaufen == ["vm_run"]
    assert not [n for n, _ in ereignisse if n == "abuse"]


def test_workshop_tools_are_checked_by_the_judge() -> None:
    from aquaticy.guardrails import SENSITIVE_TOOLS

    assert {"vm_run", "vm_write", "blender_run"} <= set(SENSITIVE_TOOLS)


def test_jobs_wait_while_the_account_is_banned(settings: object, tmp_path: Path) -> None:
    """Waehrend einer Sperre laufen keine Auftraege (9.5.24)."""
    from aquaticy.jobs import Scheduler

    gesperrt = [True]
    takt = Scheduler(lambda: settings, paused=lambda: gesperrt[0])
    assert takt.tick() == 0
    gesperrt[0] = False
    assert takt.tick() == 0, "ohne faellige Auftraege laeuft auch nach der Sperre nichts"
