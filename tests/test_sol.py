"""9.6.8 Sol: allgemeine Fehlermeldungen, Fehlerseiten, Ersatz-Port, Ausweichmodell,
Anfragelimit je Konto und Selbstheilung im Browser."""

from __future__ import annotations

import socket
import threading
from http.client import HTTPConnection
from http.server import ThreadingHTTPServer
from pathlib import Path

import pytest

from aquaticy import web


def _ui() -> str:
    return web.UI_FILE.read_text(encoding="utf-8")


def test_version_label() -> None:
    import aquaticy

    assert aquaticy.VERSION_LABEL == "10.0 Luna"


@pytest.mark.parametrize("text", [
    "TimeoutError: read timed out", "litellm.APIConnectionError: boom", "Fehler 502",
    "HTTP 500", "Traceback (most recent call last)", "[Errno 28] No space left",
    "Weiterleitung abgelehnt (403)", "", "   ",
])
def test_technical_errors_become_generic(text: str) -> None:
    assert web.public_error(text) == web.GENERIC_ERROR


@pytest.mark.parametrize("text", [
    "Das Passwort braucht mindestens 12 Zeichen.",
    "Dein Limit ist erreicht. Es setzt sich um 14:00 Uhr zurück.",
    "Bitte melde dich an.",
])
def test_hints_for_people_stay(text: str) -> None:
    assert web.public_error(text) == text


@pytest.fixture
def port():
    server = ThreadingHTTPServer(("127.0.0.1", 0), web.Handler)
    faden = threading.Thread(target=server.serve_forever, daemon=True)
    faden.start()
    try:
        yield server.server_address[1]
    finally:
        server.shutdown()
        server.server_close()


def _get(port: int, path: str, accept: str = "") -> tuple[int, str, bytes]:
    conn = HTTPConnection("127.0.0.1", port, timeout=10)
    conn.request("GET", path, headers={"Accept": accept} if accept else {})
    antwort = conn.getresponse()
    daten = antwort.read()
    conn.close()
    return antwort.status, antwort.getheader("Content-Type") or "", daten


def test_unknown_page_shows_an_error_page_in_the_browser(port: int) -> None:
    status, art, body = _get(port, "/gibt-es-nicht", "text/html,application/xhtml+xml")
    assert status == 404 and art.startswith("text/html")
    assert "Diese Seite gibt es nicht." in body.decode() and 'href="/"' in body.decode()
    # Fuer die Oberflaeche (fetch, JSON) bleibt es JSON.
    status, art, _ = _get(port, "/gibt-es-nicht")
    assert status == 404 and art.startswith("application/json")


def test_a_crashing_page_shows_a_generic_error_page(port: int, monkeypatch) -> None:
    def kaputt(self) -> None:
        raise RuntimeError("geheimes Innenleben /home/user/x.py")

    monkeypatch.setattr(web.Handler, "_send_ui", kaputt)
    status, art, body = _get(port, "/", "text/html")
    assert status == 500 and art.startswith("text/html")
    assert "geheimes" not in body.decode() and "Da ist etwas schiefgelaufen." in body.decode()


def test_server_errors_never_carry_details(port: int, monkeypatch) -> None:
    def kaputt(self) -> None:
        raise OSError("Platte voll unter /data")

    monkeypatch.setattr(web.Handler, "_send_ui", kaputt)
    status, _, body = _get(port, "/")
    assert status == 500 and b"Platte" not in body


def test_rate_limit_counts_per_account_not_per_address(monkeypatch) -> None:
    """Zwei Konten hinter derselben Adresse sperren sich nicht gegenseitig aus."""
    monkeypatch.setattr(web, "REQUEST_LIMIT", web.RateLimiter(attempts=2, window_seconds=60))
    monkeypatch.setattr(web, "ADDRESS_LIMIT", web.RateLimiter(attempts=100, window_seconds=60))
    assert web.REQUEST_LIMIT.allow("konto:a") and web.REQUEST_LIMIT.allow("konto:a")
    assert not web.REQUEST_LIMIT.allow("konto:a")
    assert web.REQUEST_LIMIT.allow("konto:b")
    source = Path(web.__file__).read_text(encoding="utf-8")
    assert 'f"konto:{account.id}" if account is not None else f"ip:{client}"' in source
    assert "ADDRESS_LIMIT.allow(client)" in source


def test_backup_ports_skip_the_cluster_port() -> None:
    kandidaten = web.port_candidates(8765)
    assert kandidaten[0] == 8765 and web.cluster.DISCOVERY_PORT not in kandidaten
    assert len(kandidaten) == web.BACKUP_PORTS + 1
    assert web.port_candidates(0) == [0]


def test_busy_port_falls_back_to_the_next_free_one() -> None:
    besetzt = socket.socket()
    besetzt.bind(("127.0.0.1", 0))
    besetzt.listen()
    port = besetzt.getsockname()[1]
    try:
        assert web.free_port("127.0.0.1", port) != port
        server = web.bind_server("127.0.0.1", port)
        try:
            assert server.server_address[1] != port
        finally:
            server.server_close()
    finally:
        besetzt.close()


def test_backup_model_takes_over_when_the_provider_is_down(settings, monkeypatch) -> None:
    """Der Anbieter streikt: das schnelle Modell desselben Anbieters uebernimmt."""
    from aquaticy.agent import Agent

    settings.model = "mistral/mistral-large-latest"
    settings.llm_retries = 2
    agent = Agent(settings)
    monkeypatch.setattr("aquaticy.agent.time.sleep", lambda s: None)
    gesehen: list[str] = []
    ereignisse: list[tuple[str, dict]] = []
    agent.on_event = lambda art, daten: ereignisse.append((art, daten))

    def completion(messages, *, stream):
        gesehen.append(agent.active_model)
        if agent.active_model == "mistral/mistral-large-latest":
            raise RuntimeError("503 Service Unavailable: overloaded")
        return {"role": "assistant", "content": "ok"}

    monkeypatch.setattr(agent, "_completion", completion)
    antwort = agent._completion_with_retry([{"role": "user", "content": "x"}], stream=False)
    assert antwort["content"] == "ok"
    assert gesehen[0] == "mistral/mistral-large-latest"
    assert gesehen[-1] != "mistral/mistral-large-latest"
    assert gesehen[-1].startswith("mistral/")
    assert any(d.get("reason") == "Ausweichmodell" for a, d in ereignisse if a == "retry")
    agent.close()


def test_a_real_error_is_not_hidden_behind_a_backup_model(settings, monkeypatch) -> None:
    from aquaticy.agent import Agent

    settings.model = "mistral/mistral-large-latest"
    agent = Agent(settings)
    monkeypatch.setattr("aquaticy.agent.time.sleep", lambda s: None)
    monkeypatch.setattr(agent, "_completion", lambda m, stream: (_ for _ in ()).throw(
        RuntimeError("401 invalid api key")))
    with pytest.raises(RuntimeError):
        agent._completion_with_retry([{"role": "user", "content": "x"}], stream=False)
    assert not getattr(agent, "_ausweich_model", "")
    agent.close()


def test_browser_side_self_healing() -> None:
    html = _ui()
    assert 'id="errorbox"' in html and "function zeigeFehler(" in html
    assert 'id="offline-hinweis"' in html and 'addEventListener("offline", zeigeOffline)' in html
    # Nur Lesen wird von selbst wiederholt -- nie Senden, Speichern, Loeschen.
    assert 'const lesen = !options.method || options.method.toUpperCase() === "GET";' in html
    assert "async function wiederAnhaengen(" in html
    assert "if (versuch >= 3) return false;" in html
    # Technische Fehler kommen in der Oberflaeche nie an.
    assert "String(err)" not in html and "HTTP ${res.status}" not in html


def test_chat_errors_stay_generic_but_hints_pass() -> None:
    quelle = Path(web.__file__).read_text(encoding="utf-8")
    assert 'payload = {**payload, "message": public_error(str(payload.get("message", "")))}' \
        in quelle
    assert web.public_error("Bild.png ist kein Bild (.png, .jpg).") \
        == "Bild.png ist kein Bild (.png, .jpg)."
