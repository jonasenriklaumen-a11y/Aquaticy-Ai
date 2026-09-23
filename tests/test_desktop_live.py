"""Der User mode in einer echten Werkstatt -- nur, wo es Docker und das Abbild gibt.

Alle anderen Tests pruefen Befehlszeilen und Entscheidungen. Dieser hier
startet wirklich: Behaelter, Netzsperre, Desktop, Browser. Er laeuft nur, wenn
der Docker-Dienst antwortet und das Desktop-Abbild gebaut ist
(docker/workshop-desktop.Dockerfile) -- sonst wird er uebersprungen, denn ein
Test, der erst ein Gigabyte aus dem Netz holt, waere eine Wette.

Das Bildmodell ist auch hier gestellt: geprueft wird der Weg von Aquaticys
Pruefung bis zum Tastendruck im Browser, nicht die Sehkraft eines Modells.
"""

from __future__ import annotations

import json
import shutil
import subprocess
import time
import urllib.parse

import pytest

from aquaticy import sandbox as werkstatt
from aquaticy.config import Settings
from aquaticy.desktop import Desktop


def _bereit() -> bool:
    if not shutil.which("docker"):
        return False
    try:
        dienst = subprocess.run(["docker", "info"], capture_output=True, timeout=10, check=False)
        abbild = subprocess.run(
            ["docker", "image", "inspect", werkstatt.DESKTOP_IMAGE],
            capture_output=True, timeout=10, check=False,
        )
    except (OSError, subprocess.SubprocessError):
        return False
    return dienst.returncode == 0 and abbild.returncode == 0


pytestmark = pytest.mark.skipif(
    not _bereit(), reason="kein Docker-Dienst oder kein Desktop-Abbild gebaut"
)

SEITE = """<!doctype html><meta charset=utf-8><title>Werkstatt-Test</title>
<form action=/senden><input name=q autofocus style='font:20px sans-serif;width:600px'></form>"""

SERVER = """import http.server, json, os
class H(http.server.SimpleHTTPRequestHandler):
    def do_GET(self):
        eintrag = {'pfad': self.path, 'ua': self.headers.get('User-Agent', '')}
        with open('/work/log.jsonl', 'a') as f:
            f.write(json.dumps(eintrag) + chr(10))
        return super().do_GET()
    def log_message(self, *args):
        pass
os.chdir('/work/seite')
http.server.ThreadingHTTPServer(('127.0.0.1', 8000), H).serve_forever()
"""


@pytest.fixture(scope="module")
def box():
    sandkasten = werkstatt.Sandbox(user_mode=True, browser_agent=werkstatt.browser_agent())
    sandkasten.runtime = werkstatt.find_runtime()
    sandkasten.ensure()
    yield sandkasten
    name = sandkasten.name
    sandkasten.stop("Test fertig")
    rest = subprocess.run(
        ["docker", "ps", "-a", "--filter", f"name={name}", "--format", "{{.Names}}"],
        capture_output=True, text=True, check=False,
    )
    assert rest.stdout.strip() == "", "nach dem Test bleibt nichts liegen"


def test_the_lock_is_in_place_and_cannot_be_lifted_from_inside(box) -> None:
    regeln = subprocess.run(
        ["docker", "exec", "--user", "0:0", "--env", f"PATH={werkstatt.ROOT_PATH}",
         box.name, "iptables", "-S", "OUTPUT"],
        capture_output=True, text=True, check=False,
    ).stdout
    for bereich in werkstatt.BLOCKED_RANGES:
        assert f"-d {bereich} -j REJECT" in regeln, bereich
    versuch = box.run("/usr/sbin/iptables -F OUTPUT 2>&1; echo rc=$?")
    assert "rc=0" not in versuch.stdout and "Permission denied" in versuch.stdout


def test_the_home_network_is_refused(box) -> None:
    probe = box.run(
        "python3 -c \"import socket\n"
        "for host in ('192.168.1.1', '10.0.0.1', '169.254.169.254'):\n"
        "    s = socket.socket(); s.settimeout(4)\n"
        "    try:\n"
        "        s.connect((host, 80)); print(host, 'OFFEN')\n"
        "    except ConnectionRefusedError:\n"
        "        print(host, 'abgewiesen')\n"
        "    except OSError as e:\n"
        "        print(host, type(e).__name__)\"",
        timeout=40,
    )
    zeilen = dict(zeile.split(" ", 1) for zeile in probe.stdout.strip().splitlines())
    assert zeilen and all(wert == "abgewiesen" for wert in zeilen.values()), zeilen


def test_typing_and_sending_through_the_checks_arrives_intact(box) -> None:
    box.write("seite/index.html", SEITE)
    box.write("server.py", SERVER)
    box.run("nohup python3 /work/server.py > /dev/null 2>&1 &", timeout=10)
    time.sleep(1)

    arten = iter([
        '{"feld": "suche", "art": "harmlos"}',          # vor dem Tippen
        '{"was": "sucht", "art": "harmlos"}',           # vor dem Enter
    ])
    gefragt: list[str] = []
    desktop = Desktop(
        box, Settings(), vision=lambda bild, prompt: next(arten),
        ask=lambda frage, optionen: gefragt.append(frage) or "nein",
    )
    geoeffnet = desktop.open("browser", "http://127.0.0.1:8000/")
    assert geoeffnet["neue_fenster"], geoeffnet
    time.sleep(3)
    text = "Grüße aus Köln: äöüß ÄÖÜ € @ {1}"
    assert desktop.type(text)["getippt"] == len(text)
    assert desktop.key("Return")["gedrueckt"] == ["Return"]
    time.sleep(2)

    eintraege = [json.loads(z) for z in box.read("log.jsonl")["text"].splitlines() if z]
    gesendet = [e for e in eintraege if e["pfad"].startswith("/senden?q=")]
    assert gesendet, eintraege
    assert urllib.parse.unquote_plus(gesendet[-1]["pfad"][len("/senden?q="):]) == text
    assert "KI-gesteuert" in gesendet[-1]["ua"], "der Browser gibt sich zu erkennen"
    assert gefragt == []


def test_a_refused_submit_really_sends_nothing(box) -> None:
    vorher = box.read("log.jsonl")["text"].count("/senden?")
    desktop = Desktop(
        box, Settings(),
        vision=lambda bild, prompt: '{"was": "schickt das Formular ab", "art": "senden"}',
        ask=lambda frage, optionen: "nein",
    )
    desktop.key("ctrl+l")
    antwort = desktop.key("Return")
    assert antwort["done"] is False
    time.sleep(1.5)
    assert box.read("log.jsonl")["text"].count("/senden?") == vorher


def test_screenshots_are_real_pictures(box) -> None:
    bild = box.screenshot()
    raster = box.screenshot(grid=True)
    assert bild[:2] == b"\xff\xd8" and raster[:2] == b"\xff\xd8"
    assert len(bild) > 5_000 and bild != raster


def test_a_restart_after_a_timeout_keeps_the_lock(box) -> None:
    """Ein zu langer Befehl startet den Behaelter neu -- und ein Neustart baut
    das Netz neu auf. Frueher war die Sperre danach weg und das Heimnetz offen."""
    lauf = box.run("sleep 30", timeout=1)
    assert lauf.timed_out
    regeln = subprocess.run(
        ["docker", "exec", "--user", "0:0", "--env", f"PATH={werkstatt.ROOT_PATH}",
         box.name, "iptables", "-S", "OUTPUT"],
        capture_output=True, text=True, check=False,
    ).stdout
    for bereich in werkstatt.BLOCKED_RANGES:
        assert f"-d {bereich} -j REJECT" in regeln, bereich
    probe = box.run(
        "python3 -c \"import socket;s=socket.socket();s.settimeout(4)\n"
        "try:\n s.connect(('192.168.1.1',80));print('OFFEN')\n"
        "except ConnectionRefusedError:\n print('abgewiesen')\n"
        "except OSError as e:\n print(type(e).__name__)\"",
        timeout=30,
    )
    assert probe.stdout.strip() == "abgewiesen"
    assert box.screenshot()[:2] == b"\xff\xd8", "und der Desktop ist wieder da"
