"""9.6.8 Ultra: Fehlerkorrekturen zu Sol -- Start, Offline-Hinweis, Abgabe im
Verbund und technische Fehlertexte im Chat."""

from __future__ import annotations

import json
import socket
import time
from typing import Any

import pytest

from aquaticy import cluster, web
from tests.test_cluster import _verbinden, _warte, verbund  # noqa: F401


def test_version_label() -> None:
    import aquaticy

    assert aquaticy.VERSION_LABEL == "10.0.1 Luna"


def _fehler(art: type[BaseException], text: str) -> BaseException:
    try:
        raise art(text)
    except BaseException as exc:
        return exc


def test_library_errors_never_reach_the_chat() -> None:
    try:
        int("abc")
    except ValueError as exc:
        assert web.user_hint(exc) == web.GENERIC_ERROR
    try:
        b"\xff".decode("utf-8")
    except UnicodeDecodeError as exc:
        assert web.user_hint(exc) == web.GENERIC_ERROR
    try:
        json.loads("nicht json")
    except ValueError as exc:
        assert web.user_hint(exc) == web.GENERIC_ERROR
    assert web.user_hint(_fehler(RuntimeError, "Das sieht aus wie ein Satz.")) \
        == web.GENERIC_ERROR
    assert web.user_hint(_fehler(ValueError, "Antwort 500")) == web.GENERIC_ERROR
    assert web.user_hint(_fehler(ValueError, "could not convert string to float: 'x'")) \
        == web.GENERIC_ERROR


def test_intended_hints_still_reach_the_chat() -> None:
    satz = "Nutzung: /image pfad/zum/bild.jpg (oder .png)"
    assert web.user_hint(_fehler(ValueError, satz)) == satz
    assert web.user_hint(_fehler(FileNotFoundError, "Bild nicht gefunden: x.png")) \
        == "Bild nicht gefunden: x.png"
    # Ein Hinweis darf mit einem Dateinamen anfangen ...
    assert web.user_hint(_fehler(ValueError, ".env ist kein Bild (.png).")) \
        == ".env ist kein Bild (.png)."
    # ... und eigene Fehlerklassen von Aquaticy sind ebenfalls Hinweise.
    from aquaticy.calc import CalcError

    assert web.user_hint(_fehler(CalcError, "Durch null teilen geht nicht.")) \
        == "Durch null teilen geht nicht."


def test_a_failed_start_frees_the_port_and_stops_the_planner(settings, monkeypatch) -> None:
    """Scheitert der Start nach dem Binden, bleibt weder Port noch Planer zurueck."""
    for name in ("AUTH", "TOKEN", "AIGUARD", "SCHEDULER", "SERVER", "CLUSTER"):
        monkeypatch.setattr(web, name, getattr(web, name))
    monkeypatch.setattr(web, "USER_SCHEDULERS", {})
    monkeypatch.setattr(web, "get_settings", lambda: settings)
    monkeypatch.setattr("aquaticy.sandbox.sweep", lambda: None)

    def gesperrt(data_dir: Any) -> Any:
        raise OSError("database is locked")

    monkeypatch.setattr("aquaticy.learning.Learning", gesperrt)
    probe = socket.socket()
    probe.bind(("127.0.0.1", 0))
    port = probe.getsockname()[1]
    probe.close()
    with pytest.raises(OSError, match="locked"):
        web.serve("127.0.0.1", port, open_browser=False)
    assert web.SCHEDULER is None and not web.USER_SCHEDULERS
    wieder = socket.socket()
    try:
        wieder.bind(("127.0.0.1", port))  # der Port ist wieder frei
    finally:
        wieder.close()


def test_a_refused_release_is_tried_again(verbund, monkeypatch) -> None:  # noqa: F811
    """Laeuft beim Abgeben noch ein Chat, gibt der Server das Konto spaeter ab."""
    monkeypatch.setattr(cluster, "RELEASE_RETRY_FIRST", 0.05)
    a, b, _, _, gefragt, neustarts = verbund
    _verbinden(a, b, gefragt, neustarts)
    b.homes["konto1"] = b.node_id
    a.homes["konto1"] = a.node_id
    versuche: list[float] = []

    def erst_beim_dritten(user: str) -> bool:
        versuche.append(time.time())
        return len(versuche) >= 3

    b.hooks.release = erst_beim_dritten
    b._take_members(a.public_info(), a.homes)
    _warte(lambda: len(versuche) >= 3)
    time.sleep(0.3)
    assert len(versuche) == 3  # danach ist Ruhe


def test_a_release_stops_when_the_account_comes_back(verbund, monkeypatch) -> None:  # noqa: F811
    monkeypatch.setattr(cluster, "RELEASE_RETRY_FIRST", 0.05)
    a, b, _, _, gefragt, neustarts = verbund
    _verbinden(a, b, gefragt, neustarts)
    b.homes["konto1"] = b.node_id
    a.homes["konto1"] = a.node_id
    versuche: list[str] = []
    b.hooks.release = lambda user: versuche.append(user) and False
    b._take_members(a.public_info(), a.homes)
    _warte(lambda: versuche)
    with b._lock:
        b.state["homes"]["konto1"] = b.node_id  # der Master legt es zurueck
    time.sleep(0.4)
    anzahl = len(versuche)
    time.sleep(0.4)
    assert len(versuche) == anzahl


def test_offline_shows_the_banner_not_the_error_window() -> None:
    html = web.UI_FILE.read_text(encoding="utf-8")
    assert "grund.gezeigt || grund.netz" in html
    assert "if (!navigator.onLine) return;  // das zeigt schon der Offline-Hinweis" in html
    assert 'err.netz = true; } catch {}\n        $("#offline-hinweis").hidden = false;' in html
