"""9.5.18 Sunflower: Tempo im Pro- und Code-Modus -- und die Funde der Fehlersuche.

Die Rechtspruefung und die Master-Planung laufen gleichzeitig; losgeschickt
wird trotzdem erst nach dem OK. Die Suche nach dem staerksten Modell laeuft
neben der Pruefung. Dazu: der Umbau der Kontentabelle ohne Datenverlust,
getarnte PHP/JSP-Uploads, die Bildart aus den Bytes, robuste Add-ons, die
Kontingent-Meldung je Tarif und offene Rueckfragen. Alles mit gestellten
Aufrufen -- kein Netz, kein Modell.
"""

from __future__ import annotations

import threading
import time
from typing import Any

import pytest

from aquaticy import master
from aquaticy.agent import Agent, AgentResult
from aquaticy.config import Settings
from aquaticy.tools import Toolbox


@pytest.fixture
def agent(settings: Settings, monkeypatch: pytest.MonkeyPatch) -> Agent:
    monkeypatch.setattr(Agent, "_auto_subagents_wanted", lambda self: True)
    monkeypatch.setattr(Agent, "_strongest_model", lambda self, purpose="": "")
    a = Agent(settings, cache=None, toolbox=Toolbox(settings, cache=None))
    a.mode, a.structured, a.online = "pro", True, True
    return a


def test_the_master_plans_while_the_legal_check_runs(
    agent: Agent, monkeypatch: pytest.MonkeyPatch
) -> None:
    zeiten: dict[str, float] = {}
    geplant: list[str] = []

    def planen(question: str, settings: Any, **kw: Any) -> Any:
        zeiten["plan_start"] = time.monotonic()
        geplant.append(question)
        return master.Mission(tasks=[], plan="", fallback=True)

    def pruefen(self: Agent, question: str) -> None:
        zeiten["pruefung_start"] = time.monotonic()
        time.sleep(0.3)
        zeiten["pruefung_ende"] = time.monotonic()
        return None

    monkeypatch.setattr(master, "plan_mission", planen)
    monkeypatch.setattr(Agent, "_legal_check", pruefen)
    agent._prefetch_plan("Vergleiche drei Lastenräder")
    Agent._legal_check(agent, "Vergleiche drei Lastenräder")
    mission = agent._take_prefetched_plan("Vergleiche drei Lastenräder",
                                          max(1, agent.agent_limit), agent.strong_count)
    assert mission is not None and mission.fallback
    assert zeiten["plan_start"] < zeiten["pruefung_ende"], "die Planung wartet nicht mehr"
    assert geplant == ["Vergleiche drei Lastenräder"], "und laeuft nur einmal"


def test_a_refused_request_starts_no_agents(
    agent: Agent, monkeypatch: pytest.MonkeyPatch
) -> None:
    losgeschickt: list[Any] = []
    monkeypatch.setattr(master, "plan_mission",
                        lambda q, s, **kw: master.Mission(tasks=[], plan="", fallback=True))
    monkeypatch.setattr(Agent, "_legal_check",
                        lambda self, q: AgentResult(answer="abgelehnt", guarded="name"))
    monkeypatch.setattr(Agent, "_run_subagents", lambda self, tasks: losgeschickt.append(tasks))
    ergebnis = agent.ask("Finde die Adresse von Max Mustermann", stream=False)
    assert ergebnis.answer == "abgelehnt"
    assert losgeschickt == [], "abgelehnt heisst: kein Agent laeuft los"


def test_a_plan_for_another_question_is_not_reused(agent: Agent,
                                                  monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(master, "plan_mission",
                        lambda q, s, **kw: master.Mission(tasks=[], plan="", fallback=True))
    agent._prefetch_plan("Frage A")
    assert agent._take_prefetched_plan("Frage B", max(1, agent.agent_limit),
                                       agent.strong_count) is None


def test_no_prefetch_outside_the_pro_mode(agent: Agent) -> None:
    agent.mode = "normal"
    agent._prefetch_plan("Vergleiche drei Lastenräder")
    assert agent._vorplan is None


def test_the_strongest_model_is_looked_up_once_even_in_parallel(
    settings: Settings, monkeypatch: pytest.MonkeyPatch
) -> None:
    aufrufe: list[int] = []

    def langsam(settings: Any, purpose: str = "work") -> str:
        aufrufe.append(1)
        time.sleep(0.2)
        return "mistral/mistral-large-latest"

    monkeypatch.setattr("aquaticy.system.strongest_model", langsam)
    a = Agent(settings, cache=None, toolbox=Toolbox(settings, cache=None))
    a.mode = "code"
    faeden = [threading.Thread(target=a._strongest_model) for _ in range(4)]
    for f in faeden:
        f.start()
    for f in faeden:
        f.join()
    assert len(aufrufe) == 1


def test_the_workshop_is_not_warmed_without_isolation(
    settings: Settings, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr("aquaticy.sandbox.find_runtime", lambda: None)
    a = Agent(settings, cache=None, toolbox=Toolbox(settings, cache=None))
    faden = a._warm_workshop()      # ohne Podman/Docker: nichts, kein Fehler
    assert faden is not None
    faden.join(5)
    assert a.toolbox._sandbox_box is None


def test_looking_for_docker_never_blocks_the_turn(
    settings: Settings, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Fund 9.5.18: `docker info` lief im Haupt-Faden -- bei jeder Code-Nachricht."""
    gestartet = threading.Event()

    def langsam() -> None:
        gestartet.set()
        time.sleep(0.5)

    monkeypatch.setattr("aquaticy.sandbox.find_runtime", langsam)
    a = Agent(settings, cache=None, toolbox=Toolbox(settings, cache=None))
    vorher = time.monotonic()
    faden = a._warm_workshop()
    assert time.monotonic() - vorher < 0.2, "der Turn wartet nicht auf docker info"
    assert faden is not None and gestartet.wait(2)
    faden.join(5)


def test_a_hanging_model_lookup_does_not_block_a_second_caller(
    settings: Settings, monkeypatch: pytest.MonkeyPatch
) -> None:
    freigabe = threading.Event()

    def haengt(settings: Any, purpose: str = "work") -> str:
        freigabe.wait(5)
        return "mistral/mistral-large-latest"

    monkeypatch.setattr("aquaticy.system.strongest_model", haengt)
    monkeypatch.setattr("aquaticy.agent.STRONG_LOOKUP_WAIT", 0.2)
    a = Agent(settings, cache=None, toolbox=Toolbox(settings, cache=None))
    a.mode = "code"
    erster = threading.Thread(target=a._strongest_model)
    erster.start()
    time.sleep(0.05)
    vorher = time.monotonic()
    assert a._strongest_model() == ""
    assert time.monotonic() - vorher < 1.0
    freigabe.set()
    erster.join(5)
    assert a._strongest_model() == "mistral/mistral-large-latest"


# --- Fehlersuche 9.5.18: Umbau der Kontentabelle ---------------------------

_ALTE_KONTEN = """
CREATE TABLE users (
    id TEXT PRIMARY KEY, email TEXT NOT NULL UNIQUE, username TEXT NOT NULL,
    password_hash BLOB NOT NULL, password_salt BLOB NOT NULL,
    plan TEXT NOT NULL CHECK(plan IN ('normal','pro')), created_at REAL NOT NULL,
    terms_version TEXT NOT NULL, terms_accepted_at REAL NOT NULL,
    last_ip TEXT NOT NULL DEFAULT '', last_seen REAL NOT NULL DEFAULT 0
);
CREATE TABLE sessions (
    token_hash TEXT PRIMARY KEY,
    user_id TEXT NOT NULL REFERENCES {ziel}(id) ON DELETE CASCADE,
    device_hash TEXT NOT NULL, ip_hash TEXT NOT NULL,
    created_at REAL NOT NULL, expires_at REAL NOT NULL
);
"""


def _alte_datenbank(tmp_path: Any, *, ziel: str = "users") -> str:
    """Legt mit dem heutigen Code ein Konto samt Sitzung an und setzt dann die
    Tabellen auf den Stand vor 9.5.17 (bzw. den kaputten Stand von 9.5.17)."""
    import sqlite3

    from aquaticy.auth import AuthStore

    store = AuthStore(tmp_path, "PROCODE12", "Abcdef1234567!")
    konto = store.register("a@example.org", "ein langes Passwort", "normal",
                           username="anna", terms_accepted=True, terms_version="1")
    token = store.create_session(konto, "dev", "203.0.113.9")
    con = sqlite3.connect(tmp_path / "accounts.sqlite3")
    zeilen_u = con.execute(
        "SELECT id, email, username, password_hash, password_salt, plan, created_at, "
        "terms_version, terms_accepted_at FROM users").fetchall()
    zeilen_s = con.execute("SELECT * FROM sessions").fetchall()
    con.executescript("PRAGMA foreign_keys=OFF; DROP TABLE sessions; DROP TABLE users;"
                      + _ALTE_KONTEN.format(ziel=ziel))
    con.executemany("INSERT INTO users VALUES (?,?,?,?,?,?,?,?,?,'203.0.113.9',123)", zeilen_u)
    con.executemany("INSERT INTO sessions VALUES (?,?,?,?,?,?)", zeilen_s)
    con.commit()
    con.close()
    return token


def test_the_ultra_migration_keeps_sessions_and_addresses(tmp_path: Any) -> None:
    import sqlite3

    from aquaticy.auth import AuthStore

    token = _alte_datenbank(tmp_path)
    store = AuthStore(tmp_path, "PROCODE12", "Abcdef1234567!")
    assert store.session_account(token, "dev", "203.0.113.9") is not None, \
        "der Umbau darf keine Sitzung per CASCADE loeschen"
    con = sqlite3.connect(tmp_path / "accounts.sqlite3")
    sql = con.execute("SELECT sql FROM sqlite_master WHERE name='sessions'").fetchone()[0]
    assert "users_alt" not in sql
    assert con.execute("SELECT last_ip, last_seen FROM users").fetchone() == ("203.0.113.9", 123)
    con.close()
    konto = store.authenticate("a@example.org", "ein langes Passwort")
    assert konto is not None and store.create_session(konto, "dev", "203.0.113.9")
    ultra = store.register("u@example.org", "ein langes Passwort", "ultra", "Abcdef1234567!",
                           username="uu", terms_accepted=True, terms_version="1",
                           ip="198.51.100.4")
    assert ultra.plan == "ultra"


def test_a_database_broken_by_9517_is_repaired(tmp_path: Any) -> None:
    import sqlite3

    from aquaticy.auth import AuthStore

    token = _alte_datenbank(tmp_path, ziel='"users_alt"')
    store = AuthStore(tmp_path, "PROCODE12", "Abcdef1234567!")
    con = sqlite3.connect(tmp_path / "accounts.sqlite3")
    sql = con.execute("SELECT sql FROM sqlite_master WHERE name='sessions'").fetchone()[0]
    assert "users_alt" not in sql and "REFERENCES users(id)" in sql
    indizes = {r[0] for r in con.execute(
        "SELECT name FROM sqlite_master WHERE type='index' AND tbl_name='sessions'")}
    assert {"sessions_user_idx", "sessions_expiry_idx"} <= indizes
    con.close()
    assert store.session_account(token, "dev", "203.0.113.9") is not None
    konto = store.authenticate("a@example.org", "ein langes Passwort")
    assert konto is not None and store.create_session(konto, "dev", "203.0.113.9")
    # Zweiter Start: nichts mehr zu tun, nichts geht verloren.
    AuthStore(tmp_path, "PROCODE12", "Abcdef1234567!")
    assert store.session_account(token, "dev", "203.0.113.9") is not None


# --- Fehlersuche 9.5.18: Uploads ---------------------------------------------

@pytest.mark.parametrize("name", [
    "shell.php\x00.jpg", "shell.php .png", "shell.php.", "ｓｈｅｌｌ.ｐｈｐ", "x.jsp;.png",
    "a.php%00.jpg", "C:\\temp\\y.PHTML", "a.jsp/", "bild.png.Php5", "a.php::$DATA",
])
def test_disguised_scripts_are_still_blocked(name: str) -> None:
    from aquaticy.web import blocked_upload

    assert blocked_upload(name)


@pytest.mark.parametrize("name", [
    "foto.png", "notizen.txt", "php", "my.phpdoc.txt", "a.jspx1", "jsp-vs-php.pdf", "php_notes.md",
])
def test_harmless_names_pass(name: str) -> None:
    from aquaticy.web import blocked_upload

    assert not blocked_upload(name)


def test_the_image_type_comes_from_the_bytes_not_the_browser() -> None:
    from aquaticy.web import image_mime

    assert image_mime(b"\x89PNG\r\n\x1a\n" + b"0" * 8) == "image/png"
    assert image_mime(b"RIFF\x00\x00\x00\x00WEBPVP8 ") == "image/webp"
    assert image_mime(b"\xff\xd8\xff\xe0") == "image/jpeg"
    assert image_mime(b"<?php echo 1; ?>") == ""


# --- Fehlersuche 9.5.18: Add-ons mit unerwarteten Antworten ------------------

def _liste_statt_objekt() -> Any:
    import httpx

    return httpx.Client(transport=httpx.MockTransport(
        lambda request: httpx.Response(200, json=["unerwartet"])))


def test_the_new_addons_survive_a_list_instead_of_an_object(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from aquaticy import addons

    monkeypatch.setattr(addons, "_takt", lambda host: None)
    assert addons.news(client=_liste_statt_objekt())["meldungen"] == []
    assert "error" in addons.wikipedia("Berlin", client=_liste_statt_objekt())
    assert addons.currency(1, "EUR", "USD", client=_liste_statt_objekt())["ergebnis"] == {}
    assert addons.holidays("DE", 2026, client=_liste_statt_objekt())["feiertage"] == []


def test_the_quota_message_fits_the_plan(tmp_path: Any) -> None:
    """Seit 9.5.17 hat auch Pro ein Limit -- die Meldung darf nichts anderes sagen."""
    from aquaticy.quota import Quota, QuotaExceeded

    for faktor, erwartet in ((1.0, "Ein Pro-Konto hat mehr"),
                             (2.0, "Mit einem Ultra-Konto gibt es kein Limit")):
        quota = Quota(tmp_path / f"q{faktor}.sqlite3", "konto", 0.0, factor=faktor)
        with pytest.raises(QuotaExceeded) as fehler:
            quota.check(need=quota.week_tokens + 1)
        assert erwartet in str(fehler.value)
        assert "Pro-Konto gibt es kein Limit" not in str(fehler.value)


@pytest.mark.parametrize(("letzte", "offen"), [
    ("Soll ich weitersuchen?", True),
    ("Soll ich weitersuchen? 🙂", True),
    ("**Passt das?** Sonst suche ich weiter.", True),
    ("Hier die Liste.\n\nSoll ich noch Preise vergleichen?)", True),
    ("Soll ich suchen?\n\nHier ist die Liste.", False),
    ("Fertig. Quelle: https://example.org/?id=1", False),
    ("Das war's.", False),
])
def test_an_open_question_is_found_on_the_last_line(
    settings: Settings, letzte: str, offen: bool
) -> None:
    a = Agent(settings, cache=None, toolbox=Toolbox(settings, cache=None))
    a.messages = [{"role": "user", "content": "such"},
                  {"role": "assistant", "content": letzte}]
    assert a._last_reply_asks() is offen
