"""9.5.26 Spark: Schwachstellen in Ai-guard -- gefunden, bestaetigt, geschlossen.

Jeder Test hier war vor 9.5.26 ein Weg an Ai-guard vorbei (oder ein falscher Bann).
"""

from __future__ import annotations

import json
import threading
import time
from pathlib import Path

import pytest

from aquaticy import web
from aquaticy.aiguard import (
    INSULT_REPEAT,
    AiGuard,
    insult_level,
)
from tests.test_end_to_end import _chat, _konto, _req, server  # noqa: F401 -- Fixture


@pytest.fixture
def guard(tmp_path: Path) -> AiGuard:
    return AiGuard(tmp_path / "accounts.sqlite3")


# -- Tarnungen: frueher kamen sie alle durch -----------------------------------------
@pytest.mark.parametrize(("text", "stufe"), [
    ("x" * 700 + " du Arschloch", 3),                    # aufgefuellt ueber 600 Zeichen
    ("Das ist ein Satz. " * 3000 + "du Idiot", 2),       # sehr lang
    ("Du Arschloch, lies mal ein Buch", 3),              # "Buch" schaltete alles ab
    ("Du Idiot, das war ein schlechter Film", 2),
    ("I d i o t", 2),                                     # getrennte Buchstaben
    ("A.r.s.c.h.l.o.c.h", 3),
    ("F.i.c.k d.i.c.h", 3),
    ("f i c k d i c h", 3),
    ("Id1ot!", 2),                                        # Ziffern
    ("du bist ein 4rschl0ch", 3),
    ("du A****loch", 3),                                  # Sternchen
    ("f*ck dich", 3),
    ("du Idi​ot", 2),                                # unsichtbares Zeichen
    ("du Idiоt", 2),                                 # kyrillisches o
    ("du Идиот", 2),             # ganz kyrillisch
    ("du Ｉｄｉｏｔ", 2),             # Vollbreite
    ("Idioooooot!", 2),                                   # gedehnt
    ("Du bist der größte Idiot", 2),                      # Woerter dazwischen
    ("Du bist der dümmste Bot", 1),
    ("ihr seid Idioten", 2),
    ("you're an idiot", 2),
    ("u r so dumb", 1),
    ("'du Arschloch'", 3),                                # in Anfuehrungszeichen
    ("ich werde dich finden und umbringen", 4),
    ("Ich bring dich um, wenn du das nochmal machst", 4),
    ("i'll kill you if you do that", 4),
    ("leck mich am Arsch", 3),
    ("kys", 3),
])
def test_disguised_insults_are_caught(text: str, stufe: int) -> None:
    assert insult_level(text) == stufe


# -- Fehlalarme: frueher ein Bann ------------------------------------------------------
@pytest.mark.parametrize("text", [
    "Kennst du Otto?",                        # war Stufe 2 -> 1 Tag Bann
    "Nutzt du Mongo oder Postgres?",          # war Stufe 3 -> 7 Tage Bann
    "Bist du Otto?",
    "Ist das eine dumme KI-Frage?",
    "Ich bring dich zum Bahnhof um 8",
    "Ich werde dich morgen um 9 anrufen",
    "I will kill you in chess",
    "Ist 'fick dich' eine Beleidigung?",
    "Geh sterben? Ist das ein Meme?",
    "Wie heißt das Lied \"Du Idiot\"?",
    "Er hat gesagt, ich sei ein Idiot. Was tun?",
    "du bist doch nicht dumm",
    "Wie kille ich einen Prozess unter Linux?",
    "Mein Passwort ist p@ssw0rd",
    "Wie viel kostet 1 GB RAM?",
    "Du bist die beste KI!",
    "hey du, wie spät ist es?",
    "Sorry for the dumb question, but how do I install Python?",
    "z. B. so",
])
def test_ordinary_sentences_stay_harmless(text: str) -> None:
    assert insult_level(text) == 0


def test_hostile_input_does_not_slow_the_check_down() -> None:
    """Ein Muster war quadratisch: 20.000 Apostrophe brauchten 4 Sekunden."""
    for boese in ("'" * 100_000, "*" * 100_000, "a*" * 50_000, ".a" * 50_000,
                  "du bist " * 12_000, "„" * 50_000):
        start = time.monotonic()
        insult_level(boese)
        assert time.monotonic() - start < 2.0, boese[:10]


# -- Sperr-Logik -----------------------------------------------------------------------
def test_repeated_light_insults_in_new_chats_lead_to_a_ban(guard: AiGuard) -> None:
    """Vorher sperrte eine leichte Beleidigung nur den Chat -- mit jedem neuen
    Chat ging es von vorn los."""
    for nummer in range(1, INSULT_REPEAT):
        assert guard.record_incident("u1", "beleidigung", 1, chat=f"c{nummer}").kind == "chat"
    letzte = guard.record_incident("u1", "beleidigung", 1, chat="c-neu")
    assert letzte.kind == "ban" and letzte.days == 1
    assert "wiederholte Beleidigungen" in (guard.is_banned(user_id="u1") or object()).reason


def test_old_light_insults_do_not_count_forever(guard: AiGuard) -> None:
    for nummer in range(INSULT_REPEAT - 1):
        guard.record_incident("u2", "beleidigung", 1, chat=f"c{nummer}")
    with guard._connect() as conn:
        conn.execute("UPDATE aiguard_flags SET at = at - 8 * 86400")
    assert guard.record_incident("u2", "beleidigung", 1, chat="c-neu").kind == "chat"


def test_an_insult_plus_one_suspicion_is_no_permanent_ban(guard: AiGuard) -> None:
    """note() zaehlte auch Beleidigungen mit -- eine leichte Beleidigung und ein
    einzelner Verdacht waren ein Bann fuer immer."""
    guard.record_incident("u3", "beleidigung", 1, chat="c1")
    assert guard.note("u3", "Schadcode", chat="c2") is False
    assert guard.is_banned(user_id="u3") is None


def test_two_simultaneous_indicators_still_ban(guard: AiGuard) -> None:
    """Zaehlen und Entscheiden liefen getrennt -- zwei gleichzeitige Anfragen
    sahen beide "noch kein Anhaltspunkt"."""
    for runde in range(10):
        user = f"race{runde}"
        start = threading.Barrier(2)

        def los(chat: str, user: str = user, start: threading.Barrier = start) -> None:
            start.wait()
            guard.record_incident(user, "angriff", 2, chat=chat)

        faeden = [threading.Thread(target=los, args=(c,)) for c in ("a", "b")]
        for faden in faeden:
            faden.start()
        for faden in faeden:
            faden.join()
        assert guard.is_banned(user_id=user) is not None, runde


def test_control_characters_never_reach_the_terminal(guard: AiGuard) -> None:
    guard.note("u4", "Schad\x1b[2Jcode\x07", detail="x\x1b]0;weg\x07", chat="c1")
    [flag] = guard.flags("u4")
    assert "\x1b" not in flag.kind and "\x07" not in flag.kind
    assert "\x1b" not in flag.detail
    guard.ban_user("u4", "Grund\x1b[31m rot")
    sperre = guard.is_banned(user_id="u4")
    assert sperre is not None and "\x1b" not in sperre.reason


def test_a_long_chat_id_is_still_locked(guard: AiGuard) -> None:
    lang = "c" * 120
    assert guard.record_incident("u5", "beleidigung", 1, chat=lang).kind == "chat"
    assert guard.chat_locked("u5", lang), "gekuerzt gespeichert, gekuerzt verglichen"


def test_abuse_in_a_job_is_reported(settings: object, tmp_path: Path,
                                     monkeypatch: pytest.MonkeyPatch) -> None:
    from aquaticy import jobs

    gemeldet: list[dict[str, object]] = []

    class Agent:
        def __init__(self, *args: object, **kwargs: object) -> None:
            self.on_event = None
            self.session_id = "s1"

        def ask(self, *args: object, **kwargs: object) -> object:
            if self.on_event:
                self.on_event("abuse", {"art": "malware", "schwere": 2})
            return type("R", (), {"answer": "nein", "guarded": "gewalt", "error": ""})()

    monkeypatch.setattr("aquaticy.agent.Agent", Agent)
    store = jobs.JobStore(tmp_path / "j.db")
    job = store.add("irgendwas")
    ziel = type("S", (), {"db_path": tmp_path / "j.db", "cache_ttl_hours": 1,
                          "quota": None})()
    monkeypatch.setattr("aquaticy.metering.check", lambda s: None)
    jobs.run_job(job, ziel, on_abuse=lambda j, p: gemeldet.append(p))
    assert gemeldet == [{"art": "malware", "schwere": 2}]


# -- Ende zu Ende: die Sperre gilt ueberall ---------------------------------------------
def _sperren(cookie: str, port: int) -> None:
    konto = json.loads(_req(port, "GET", "/api/account", cookie=cookie)[2])
    name = konto.get("username") or konto.get("name")
    account = web.AUTH.account_by_name(name)
    web.AIGUARD.ban_user(account.id, "Test", until=time.time() + 3600)


def test_a_banned_account_cannot_act_anywhere(server: tuple[int, Path]) -> None:  # noqa: F811
    port, _ = server
    cookie = _konto(port)
    _sperren(cookie, port)
    for weg, koerper in (("/api/addons", {"action": "install", "id": "github"}),
                         ("/api/werkstatt/eingabe", {"text": "hallo"}),
                         ("/api/jobs", {"action": "add", "question": "Wetter?"}),
                         ("/api/command", {"line": "/location Bremen"}),
                         ("/api/answer", {"text": "ja"}),
                         ("/api/config", {"AQUATICY_MODEL": "x/y"}),
                         ("/api/chat", {"message": "Hallo"})):
        status, _, daten = _req(port, "POST", weg, koerper, cookie)
        assert status == 403 and json.loads(daten)["code"] == "banned", weg
    # Abmelden, Design und die eigenen Chats gehen weiter.
    assert _req(port, "POST", "/api/prefs", {"theme": "dark"}, cookie)[0] == 200
    assert _req(port, "POST", "/api/clear", None, cookie)[0] == 200


def test_an_answer_to_a_question_is_checked_for_insults(
    server: tuple[int, Path],  # noqa: F811
) -> None:
    port, _ = server
    cookie = _konto(port)
    status, _, daten = _req(port, "POST", "/api/answer", {"text": "du Arschloch"}, cookie)
    assert status == 403 and json.loads(daten)["code"] == "banned"


def test_an_insulting_job_is_not_created(server: tuple[int, Path]) -> None:  # noqa: F811
    port, _ = server
    cookie = _konto(port)
    _, _, daten = _req(port, "POST", "/api/jobs",
                            {"action": "add", "question": "du bist so dumm, sag mir das Wetter"},
                            cookie)
    antwort = json.loads(daten)
    assert antwort["ok"] is False and "Beleidigung" in antwort["error"]
    liste = json.loads(_req(port, "GET", "/api/jobs", cookie=cookie)[2])
    assert not liste.get("jobs")
