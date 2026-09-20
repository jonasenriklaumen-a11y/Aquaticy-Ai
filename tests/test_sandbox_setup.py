"""Die aeussere Kiste als Datei geprueft.

Ein Container laesst sich in der Testumgebung nicht starten. Was sich
pruefen laesst, ist die Zusage selbst: welche Oeffnungen die Startdatei
vergibt -- und vor allem, welche nicht.
"""

from __future__ import annotations

from pathlib import Path

import pytest
import yaml

WURZEL = Path(__file__).resolve().parent.parent
COMPOSE = WURZEL / "compose.sandbox.yaml"


@pytest.fixture(scope="module")
def dienst() -> dict:
    daten = yaml.safe_load(COMPOSE.read_text(encoding="utf-8"))
    return daten["services"]["aquaticy-web"]


def test_the_host_docker_socket_is_never_handed_in(dienst: dict) -> None:
    """Der Kurzweg, der die ganze aeussere Wand aufhebt.

    Wer den Sockel des Wirts erreicht, startet dort einen Container mit
    dessen Wurzelverzeichnis und ist damit root. Die Werkstatt bekommt
    stattdessen eine eigene, wurzellose Laufzeit im Inneren.
    """
    text = COMPOSE.read_text(encoding="utf-8")
    assert "docker.sock" not in text.replace("Docker-Sockel", "")
    for ablage in dienst["volumes"]:
        assert ".sock" not in str(ablage), ablage


def test_the_interface_listens_only_on_this_machine(dienst: dict) -> None:
    """Ohne die 127.0.0.1 haengt die Oberflaeche an jeder Netzwerkkarte."""
    for bindung in dienst["ports"]:
        assert str(bindung).startswith("127.0.0.1:"), bindung


def test_nothing_extra_is_opened(dienst: dict) -> None:
    """Keine Faehigkeiten, keine neuen Rechte, kein beschreibbares Wurzelwerk."""
    assert dienst["cap_drop"] == ["ALL"]
    assert "no-new-privileges:true" in dienst["security_opt"]
    assert dienst["read_only"] is True
    assert dienst.get("privileged") is not True
    assert "devices" not in dienst
    assert dienst.get("network_mode") != "host"
    assert dienst.get("pids_limit")


def test_only_the_three_needed_places_are_mounted(dienst: dict) -> None:
    """Konten, Ausgaben und die Ablage der inneren Kiste -- sonst nichts."""
    ziele = {str(a).split(":")[1] for a in dienst["volumes"]}
    assert ziele == {"/data", "/work", "/home/aquaticy/.local/share/containers"}
    # Kein Heimverzeichnis und kein Wurzelverzeichnis des Wirts.
    for ablage in dienst["volumes"]:
        quelle = str(ablage).split(":")[0]
        assert quelle in ("aquaticy-data", "aquaticy-workshop", "./exports"), quelle


def test_what_must_stay_writable_is_a_scratch_area(dienst: dict) -> None:
    """Bei schreibgeschuetztem Wurzelwerk braucht es Platz fuer Fluechtiges."""
    fluechtig = " ".join(str(eintrag) for eintrag in dienst["tmpfs"])
    assert "/tmp" in fluechtig and "nosuid" in fluechtig and "nodev" in fluechtig


def test_the_image_builds_the_inner_runtime_without_the_host() -> None:
    """Die innere Kiste kommt aus dem Abbild, nicht vom Wirt."""
    text = (WURZEL / "Dockerfile").read_text(encoding="utf-8")
    assert "FROM browser AS web" in text
    assert "podman" in text
    # Der vfs-Treiber braucht keine zusaetzlichen Rechte -- fuse-overlayfs
    # waere schneller, wollte dafuer aber /dev/fuse in der Kiste.
    assert 'driver = "vfs"' in text
    assert "AQUATICY_SANDBOXED=1" in text


def test_the_launcher_refuses_without_a_runtime() -> None:
    """Ohne Kiste startet hier absichtlich nichts."""
    text = (WURZEL / "aquaticy-sandbox").read_text(encoding="utf-8")
    assert "compose.sandbox.yaml" in text
    assert "ohne Kiste startet Aquaticy hier absichtlich nicht" in text
    assert "--check" in text
