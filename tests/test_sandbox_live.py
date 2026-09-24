"""Die Werkstatt des Code-Modus in einem echten Behaelter -- nur, wo es Docker gibt.

Bis 9.5.12 gab es dafuer keinen echten Lauf, nur Befehlszeilen-Tests. Genau
dadurch fiel nicht auf, dass Docker 29 den Arbeitsordner beim ersten
Einhaengen wieder root gab: die Werkstatt startete, rechnete, antwortete --
und konnte keine einzige Datei schreiben. Dieser Test startet wirklich und
schreibt wirklich.
"""

from __future__ import annotations

import shutil
import subprocess

import pytest

from aquaticy import sandbox as werkstatt


def _bereit() -> bool:
    if not shutil.which("docker"):
        return False
    try:
        dienst = subprocess.run(["docker", "info"], capture_output=True, timeout=10, check=False)
        abbild = subprocess.run(
            ["docker", "image", "inspect", werkstatt.DEFAULT_IMAGE],
            capture_output=True, timeout=10, check=False,
        )
    except (OSError, subprocess.SubprocessError):
        return False
    return dienst.returncode == 0 and abbild.returncode == 0


pytestmark = pytest.mark.skipif(
    not _bereit(), reason="kein Docker-Dienst oder kein Werkstatt-Abbild vorhanden"
)


@pytest.fixture
def box():
    kiste = werkstatt.Sandbox(image=werkstatt.DEFAULT_IMAGE)
    yield kiste
    kiste.stop()


def test_the_workshop_can_write_its_own_folder(box: werkstatt.Sandbox) -> None:
    assert box.put_bytes("ergebnis/bild.png", b"\x89PNG\r\n\x1a\n") == {
        "written": "/work/ergebnis/bild.png", "bytes": 8}
    assert box.write("notiz.txt", "hallo")["written"] == "/work/notiz.txt"
    lauf = box.run("id -u; stat -c '%u' /work; echo x > datei.txt && cat datei.txt; "
                   "python3 -c \"print(2 ** 10)\"")
    assert lauf.exit_code == 0, lauf
    assert lauf.stdout.split() == ["1000", "1000", "x", "1024"]
    assert box.read("notiz.txt")["text"] == "hallo"
    assert box.get_bytes("ergebnis/bild.png") == b"\x89PNG\r\n\x1a\n"
    pfade = {eintrag["path"] for eintrag in box.list_files()}
    assert {"/work/notiz.txt", "/work/datei.txt", "/work/ergebnis/bild.png"} <= pfade


def test_the_workshop_stays_locked_down(box: werkstatt.Sandbox) -> None:
    lauf = box.run(
        "python3 - <<'EOF'\n"
        "import socket\n"
        "try:\n"
        "    socket.create_connection(('1.1.1.1', 53), timeout=3)\n"
        "    print('netz-offen')\n"
        "except OSError:\n"
        "    print('kein-netz')\n"
        "for pfad in ('/etc/x', '/usr/x'):\n"
        "    try:\n"
        "        open(pfad, 'w')\n"
        "        print('schreibbar', pfad)\n"
        "    except OSError:\n"
        "        print('gesperrt')\n"
        "EOF"
    )
    assert lauf.stdout.split() == ["kein-netz", "gesperrt", "gesperrt"], lauf
    with pytest.raises(ValueError):
        box.get_bytes("../etc/passwd")
