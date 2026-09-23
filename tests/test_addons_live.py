"""Add-ons in einer echten Werkstatt -- nur, wo es Docker und das Desktop-Abbild gibt.

Die Hersteller-Server sind hier nicht erreichbar, also spielt ein Server IN
der Installations-Werkstatt Blender.org (127.0.0.1 ist dort der Behaelter
selbst -- das Heimnetz bleibt gesperrt). Geprueft wird der ganze Weg:
Datentraeger anlegen, abgesperrt installieren, Wegwerf-Werkstatt weg,
Datentraeger bleibt, im Desktop starten, deinstallieren.
"""

from __future__ import annotations

import hashlib
import io
import subprocess
import tarfile
import time
import uuid

import pytest

from aquaticy import sandbox as werkstatt
from tests.test_desktop_live import _bereit

pytestmark = pytest.mark.skipif(
    not _bereit(), reason="kein Docker-Dienst oder kein Desktop-Abbild gebaut"
)

#: Ein "Blender", das nur ein Fenster aufmacht.
FAKE_BLENDER = b"#!/bin/sh\nxterm -T FakeBlender -e sleep 600\n"


def _archiv() -> bytes:
    puffer = io.BytesIO()
    with tarfile.open(fileobj=puffer, mode="w:xz") as tar:
        info = tarfile.TarInfo("blender-4.5.3-linux-x64/blender")
        info.size, info.mode = len(FAKE_BLENDER), 0o755
        tar.addfile(info, io.BytesIO(FAKE_BLENDER))
    return puffer.getvalue()


def _docker(*args: str) -> subprocess.CompletedProcess[str]:
    return subprocess.run(["docker", *args], capture_output=True, text=True, check=False,
                          timeout=120)


@pytest.fixture(scope="module")
def volume() -> str:
    name = f"aquaticy-addon-{uuid.uuid4().hex[:12]}-blender"
    runtime = werkstatt.find_runtime()
    assert runtime is not None
    werkstatt.ensure_addon_volume(runtime, name, werkstatt.DESKTOP_IMAGE)
    yield name
    werkstatt.remove_addon_volume(runtime, name)


def test_the_volume_is_labelled_and_belongs_to_the_worker(volume: str) -> None:
    info = _docker("volume", "inspect", "--format", "{{json .Labels}}", volume).stdout
    assert '"aquaticy-addon":"1"' in info
    besitzer = _docker("run", "--rm", "--network", "none", "-v", f"{volume}:/a",
                       werkstatt.DESKTOP_IMAGE, "stat", "-c", "%u", "/a").stdout.strip()
    assert besitzer == "1000"


def test_install_runs_locked_and_leaves_only_the_volume(volume: str) -> None:
    archiv = _archiv()
    box = werkstatt.Sandbox(user_mode=True, headless=True,
                            addon_mounts={volume: "/addons/blender"})
    box.runtime = werkstatt.find_runtime()
    box.ensure()
    name = box.name
    try:
        regeln = _docker("exec", "--user", "0:0", "--env", f"PATH={werkstatt.ROOT_PATH}",
                         name, "iptables", "-S", "OUTPUT").stdout
        for bereich in werkstatt.BLOCKED_RANGES:
            assert f"-d {bereich} -j REJECT" in regeln, "auch beim Installieren kein Heimnetz"
        box.put_bytes("quelle/release/Blender4.5/blender-4.5.3-linux-x64.tar.xz", archiv)
        box.write("quelle/release/Blender4.5/index.html",
                  '<a href="blender-4.5.3-linux-x64.tar.xz">x</a>')
        box.write("quelle/release/Blender4.5/blender-4.5.3.sha256",
                  f"{hashlib.sha256(archiv).hexdigest()}  blender-4.5.3-linux-x64.tar.xz\n")
        box.run("cd /work/quelle && nohup python3 -m http.server 8000 --bind 127.0.0.1 "
                "> /dev/null 2>&1 &", timeout=10)
        time.sleep(1)
        fertig = box.addon_helper("install", "blender", "/addons/blender",
                                  "--quelle", "http://127.0.0.1:8000", timeout=120)
        assert '"ok": true' in fertig.stdout, fertig.stdout + fertig.stderr
        assert '"version": "4.5.3"' in fertig.stdout
        # Nichts landet ausserhalb des Datentraegers: das Wurzeldateisystem ist fest.
        versuch = box.run("touch /usr/local/bin/x 2>&1; echo rc=$?")
        assert "rc=0" not in versuch.stdout
    finally:
        box.stop("Test")
    assert _docker("ps", "-a", "--filter", f"name={name}", "--format", "{{.Names}}"
                   ).stdout.strip() == "", "die Wegwerf-Werkstatt ist weg"
    werkstatt.sweep()
    assert _docker("volume", "inspect", volume).returncode == 0, "der Datentraeger bleibt"


def test_the_desktop_starts_the_installed_program(volume: str) -> None:
    box = werkstatt.Sandbox(user_mode=True, browser_agent=werkstatt.browser_agent(),
                            addon_mounts={volume: "/addons/blender"})
    box.runtime = werkstatt.find_runtime()
    box.ensure()
    try:
        geoeffnet = box.desktop("open", "blender", timeout=60)
        assert geoeffnet.returncode == 0, geoeffnet.stderr
        assert b"FakeBlender" in geoeffnet.stdout, geoeffnet.stdout
        # Ein zweites Mal startet es nicht noch einmal, es kommt nach vorn.
        nochmal = box.desktop("open", "blender", timeout=60)
        assert b"nach vorn" in nochmal.stdout
        # WhatsApp ist nicht eingehaengt -- also gibt es das hier auch nicht.
        fehlt = box.desktop("open", "whatsapp", timeout=30)
        assert fehlt.returncode == 2 and b"nicht installiert" in fehlt.stderr + fehlt.stdout
        # Blender-Skripte finden das Programm aus dem Add-on.
        from aquaticy.addons import werkstatt_command_for_blender

        vorn, _, _ = werkstatt_command_for_blender().rpartition('"$B"')
        lauf = box.run(vorn + 'echo "$B"')
        assert lauf.stdout.strip() == "/addons/blender/app/blender-4.5.3-linux-x64/blender"
        assert box.status()["addons"] == ["blender"]
    finally:
        box.stop("Test")


def test_uninstall_deletes_the_volume(volume: str) -> None:
    runtime = werkstatt.find_runtime()
    assert runtime is not None
    assert werkstatt.remove_addon_volume(runtime, volume)
    assert _docker("volume", "inspect", volume).returncode != 0
    assert werkstatt.remove_addon_volume(runtime, volume), "zweimal loeschen ist kein Fehler"
