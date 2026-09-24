"""Tests fuer die Feststellung, ob Aquaticy selbst eingeschlossen laeuft.

Ein Container laesst sich hier nicht starten -- geprueft wird deshalb die
Entscheidung, nicht die Laufzeit: was gilt als Kiste, was als Oeffnung, und
was als Loch.
"""

from __future__ import annotations

import pytest

from aquaticy import boxed


@pytest.fixture(autouse=True)
def _nichts_echtes(monkeypatch: pytest.MonkeyPatch) -> None:
    """Standardlage: kein Container, keine Laufzeit, keine Sockel."""
    monkeypatch.setattr(boxed.Path, "exists", lambda self: False)
    monkeypatch.setattr(boxed.shutil, "which", lambda name: None)
    monkeypatch.setattr(boxed.Path, "read_text", lambda self, **k: "")
    monkeypatch.setattr(boxed.os, "geteuid", lambda: 1000)
    monkeypatch.setattr(boxed.os, "access", lambda pfad, modus: False)


def _existiert(*pfade: str):
    wanted = set(pfade)
    return lambda self: str(self) in wanted


def test_outside_a_box_it_says_so() -> None:
    stand = boxed.posture()
    assert stand.boxed is False
    assert "nicht in einer Kiste" in " ".join(boxed.describe(stand))


def test_podman_marks_the_outer_box(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(boxed.Path, "exists", _existiert("/run/.containerenv"))
    stand = boxed.posture()
    assert stand.boxed is True
    assert stand.kind == "podman"
    assert any("Netz nach draussen" in eintrag for eintrag in stand.openings)


def test_docker_marks_it_too(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(boxed.Path, "exists", _existiert("/.dockerenv"))
    assert boxed.posture().kind == "docker"


def test_a_box_without_a_marker_is_found_in_the_control_group(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(boxed.Path, "read_text", lambda self, **k: "12:pids:/docker/abc123\n")
    stand = boxed.posture()
    assert stand.boxed is True
    assert stand.kind == "unbekannt"


def test_the_inner_box_needs_a_runtime(monkeypatch: pytest.MonkeyPatch) -> None:
    """Ohne Laufzeit drinnen gibt es keine Werkstatt -- und das wird gesagt."""
    monkeypatch.setattr(boxed.Path, "exists", _existiert("/run/.containerenv"))
    ohne = boxed.posture()
    assert ohne.workshop_possible is False
    assert any("keine Laufzeit" in zeile for zeile in boxed.describe(ohne))

    monkeypatch.setattr(boxed.shutil, "which", lambda name: "/usr/bin/podman"
                        if name == "podman" else None)
    mit = boxed.posture()
    assert mit.nested == "podman" and mit.workshop_possible is True


def test_podman_is_preferred_over_docker_inside(monkeypatch: pytest.MonkeyPatch) -> None:
    """Wurzellos ist drinnen die bessere Wahl -- kein Dienst mit Wurzelrechten."""
    monkeypatch.setattr(boxed.shutil, "which", lambda name: f"/usr/bin/{name}")
    assert boxed.nested_runtime() == "podman"


def test_the_host_socket_is_reported_as_a_hole(monkeypatch: pytest.MonkeyPatch) -> None:
    """Der Sockel des Wirts hebt die ganze aeussere Wand auf.

    Wer ihn erreicht, startet auf dem Wirt einen Container mit dessen
    Wurzelverzeichnis und ist damit root. Er darf nie hineingereicht werden
    -- und wenn doch, muss es jemand sehen.
    """
    monkeypatch.setattr(
        boxed.Path, "exists", _existiert("/run/.containerenv", "/var/run/docker.sock")
    )
    stand = boxed.posture()
    assert stand.holes, "ein erreichbarer Sockel ist ein Loch"
    assert any("docker.sock" in eintrag for eintrag in stand.holes)
    assert any(zeile.startswith("LOCH:") for zeile in boxed.describe(stand))


def test_root_inside_the_box_is_a_hole(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(boxed.Path, "exists", _existiert("/run/.containerenv"))
    monkeypatch.setattr(boxed.os, "geteuid", lambda: 0)
    assert any("als root" in eintrag for eintrag in boxed.posture().holes)


def test_a_writable_root_filesystem_is_a_hole(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(boxed.Path, "exists", _existiert("/run/.containerenv"))
    monkeypatch.setattr(boxed.os, "access", lambda pfad, modus: True)
    assert any("Wurzeldateisystem" in eintrag for eintrag in boxed.posture().holes)


def test_outside_a_box_none_of_that_counts_as_a_hole(monkeypatch: pytest.MonkeyPatch) -> None:
    """Auf dem eigenen Rechner ist root oder ein Sockel keine Meldung wert.

    Gemeldet wird nur, was die Kiste undicht macht -- sonst waere die
    Ausgabe ausserhalb der Kiste ein Alarm ohne Anlass.
    """
    monkeypatch.setattr(boxed.Path, "exists", _existiert("/var/run/docker.sock"))
    monkeypatch.setattr(boxed.os, "geteuid", lambda: 0)
    monkeypatch.setattr(boxed.os, "access", lambda pfad, modus: True)
    assert boxed.posture().holes == ()
    assert not any(zeile.startswith("LOCH:") for zeile in boxed.describe(boxed.posture()))


@pytest.mark.parametrize("modul,name", [
    ("Path", "exists"), ("Path", "read_text"),
    ("shutil", "which"), ("os", "access"),
])
def test_a_broken_filesystem_never_stops_the_start(
    monkeypatch: pytest.MonkeyPatch, modul: str, name: str
) -> None:
    """Das hier laeuft beim Start -- es darf nie abbrechen.

    Auf einem eigenartigen Dateisystem kann schon `exists()` mit einem
    Rechtefehler aussteigen. Dann soll "keine Kiste" dastehen, kein Absturz.
    """
    def wirf(*args: object, **kwargs: object) -> object:
        raise PermissionError("kaputt")

    monkeypatch.setattr(getattr(boxed, modul), name, wirf)
    zeilen = boxed.describe(boxed.posture())
    assert zeilen and isinstance(zeilen[0], str)
