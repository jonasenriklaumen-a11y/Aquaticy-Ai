"""Tests fuer den Add-on-Installer im Desktop-Abbild (docker/desktop/aquaticy-addons).

Die echten Server (mozilla.org, signal.org, blender.org) sind hier nicht
erreichbar -- und ein Test, der Hunderte Megabyte laedt, waere eine Wette.
Also spielt ein kleiner Server auf 127.0.0.1 die Hersteller: gleiche Pfade,
gleiche Formate (Umleitung, SHA256SUMS, Paketliste, .sha256-Datei), winzige
Dateien. Geprueft wird, was zaehlt: dass nur mit passender Pruefsumme etwas
ausgepackt wird, dass nichts aus dem Zielordner ausbricht und dass eine
gescheiterte Installation nichts Halbes hinterlaesst.
"""

from __future__ import annotations

import gzip
import hashlib
import importlib.machinery
import importlib.util
import io
import json
import shutil
import subprocess
import tarfile
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from types import ModuleType

import pytest

ORDNER = Path(__file__).resolve().parent.parent / "docker" / "desktop"


@pytest.fixture(scope="module")
def helfer() -> ModuleType:
    loader = importlib.machinery.SourceFileLoader(
        "aquaticy_addons_helfer", str(ORDNER / "aquaticy-addons")
    )
    spec = importlib.util.spec_from_loader(loader.name, loader)
    assert spec is not None
    modul = importlib.util.module_from_spec(spec)
    loader.exec_module(modul)
    return modul


def _tar_xz(dateien: dict[str, bytes]) -> bytes:
    puffer = io.BytesIO()
    with tarfile.open(fileobj=puffer, mode="w:xz") as tar:
        for name, inhalt in dateien.items():
            info = tarfile.TarInfo(name)
            info.size = len(inhalt)
            info.mode = 0o755
            tar.addfile(info, io.BytesIO(inhalt))
    return puffer.getvalue()


def _deb(tmp: Path, version: str) -> bytes:
    bau = tmp / "debbau"
    (bau / "DEBIAN").mkdir(parents=True)
    (bau / "DEBIAN" / "control").write_text(
        f"Package: signal-desktop\nVersion: {version}\nArchitecture: amd64\n"
        "Maintainer: Test <t@example.org>\nDescription: Test\n", encoding="utf-8"
    )
    programm = bau / "opt" / "Signal" / "signal-desktop"
    programm.parent.mkdir(parents=True)
    programm.write_text("#!/bin/sh\necho signal\n", encoding="utf-8")
    programm.chmod(0o755)
    subprocess.run(["dpkg-deb", "--build", "--root-owner-group", str(bau), str(tmp / "s.deb")],
                   check=True, capture_output=True)
    return (tmp / "s.deb").read_bytes()


class Hersteller:
    """Ein Server, der sich wie die drei Hersteller verhaelt."""

    def __init__(self, tmp: Path) -> None:
        tmp.mkdir(parents=True, exist_ok=True)
        self.dateien: dict[str, bytes] = {}
        self.umleitungen: dict[str, str] = {}
        self.abrufe: list[str] = []
        blender = _tar_xz({"blender-4.5.10-linux-x64/blender": b"#!/bin/sh\necho blender\n"})
        self.dateien["/release/Blender4.5/"] = (
            b'<a href="blender-4.5.1-linux-x64.tar.xz">x</a>'
            b'<a href="blender-4.5.10-linux-x64.tar.xz">y</a>'
            b'<a href="blender-4.5.9-windows-x64.zip">z</a>'
        )
        self.dateien["/release/Blender4.5/blender-4.5.10-linux-x64.tar.xz"] = blender
        self.dateien["/release/Blender4.5/blender-4.5.10.sha256"] = (
            f"{hashlib.sha256(b'anders').hexdigest()}  blender-4.5.10-windows-x64.zip\n"
            f"{hashlib.sha256(blender).hexdigest()}  blender-4.5.10-linux-x64.tar.xz\n"
        ).encode()
        firefox = _tar_xz({"firefox/firefox": b"#!/bin/sh\necho firefox\n"})
        pfad = "/pub/firefox/releases/140.3.0esr/linux-x86_64/de/firefox-140.3.0esr.tar.xz"
        self.umleitungen["/"] = pfad
        self.dateien[pfad] = firefox
        self.dateien["/pub/firefox/releases/140.3.0esr/SHA256SUMS"] = (
            f"{hashlib.sha256(firefox).hexdigest()}  "
            "linux-x86_64/de/firefox-140.3.0esr.tar.xz\n"
        ).encode()
        paket = _deb(tmp, "7.70.0")
        (tmp / "alt").mkdir(parents=True)
        alt = _deb(tmp / "alt", "7.9.0")
        liste = (
            "Package: signal-desktop-beta\nVersion: 9.0.0\nFilename: pool/b.deb\n"
            f"SHA256: {'0' * 64}\n\n"
            f"Package: signal-desktop\nVersion: 7.9.0\nFilename: pool/s/alt.deb\n"
            f"SHA256: {hashlib.sha256(alt).hexdigest()}\n\n"
            f"Package: signal-desktop\nVersion: 7.70.0\nFilename: pool/s/neu.deb\n"
            f"SHA256: {hashlib.sha256(paket).hexdigest()}\n"
        )
        self.dateien["/desktop/apt/dists/xenial/main/binary-amd64/Packages.gz"] = gzip.compress(
            liste.encode()
        )
        self.dateien["/desktop/apt/pool/s/neu.deb"] = paket
        self.dateien["/desktop/apt/pool/s/alt.deb"] = alt

        hersteller = self

        class Handler(BaseHTTPRequestHandler):
            def do_GET(self) -> None:
                pfad = self.path.split("?", 1)[0]
                hersteller.abrufe.append(self.path)
                if pfad in hersteller.umleitungen and "product=" in self.path:
                    self.send_response(302)
                    self.send_header("Location", hersteller.umleitungen[pfad])
                    self.end_headers()
                    return
                daten = hersteller.dateien.get(pfad)
                if daten is None:
                    self.send_response(404)
                    self.end_headers()
                    return
                self.send_response(200)
                self.send_header("Content-Length", str(len(daten)))
                self.end_headers()
                self.wfile.write(daten)

            def log_message(self, *args: object) -> None:
                pass

        self.server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        threading.Thread(target=self.server.serve_forever, daemon=True).start()
        self.quelle = f"http://127.0.0.1:{self.server.server_address[1]}"


@pytest.fixture
def hersteller(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Hersteller:
    if not shutil.which("dpkg-deb"):
        pytest.skip("dpkg-deb fehlt")
    monkeypatch.setenv("AQUATICY_ADDONS_TEST", "1")
    server = Hersteller(tmp_path / "server")
    yield server
    server.server.shutdown()


def _aufruf(helfer: ModuleType, capsys: pytest.CaptureFixture[str], *args: str) -> tuple[int, dict]:
    code = helfer.main(list(args))
    zeilen = capsys.readouterr().out.strip().splitlines()
    return code, json.loads(zeilen[-1])


def test_blender_is_installed_from_the_newest_linux_build(
    helfer: ModuleType, hersteller: Hersteller, tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    ziel = tmp_path / "blender"
    code, antwort = _aufruf(helfer, capsys, "install", "blender", str(ziel),
                            "--quelle", hersteller.quelle)
    assert code == 0, antwort
    assert antwort["version"] == "4.5.10", "4.5.10 ist neuer als 4.5.9 -- Zahlen, nicht Text"
    assert (ziel / antwort["start"]).is_file()
    assert not (ziel / ".arbeit").exists(), "nichts Halbes bleibt liegen"
    info = json.loads((ziel / "aquaticy.json").read_text())
    assert info["programm"] == "blender" and info["start"] == "app/blender-4.5.10-linux-x64/blender"
    code, status = _aufruf(helfer, capsys, "status", str(ziel))
    assert status["installiert"] is True


def test_a_wrong_checksum_installs_nothing(
    helfer: ModuleType, hersteller: Hersteller, tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    hersteller.dateien["/release/Blender4.5/blender-4.5.10-linux-x64.tar.xz"] += b"manipuliert"
    ziel = tmp_path / "blender"
    code, antwort = _aufruf(helfer, capsys, "install", "blender", str(ziel),
                            "--quelle", hersteller.quelle)
    assert code == 1 and "Pruefsumme" in antwort["fehler"]
    assert not (ziel / "app").exists() and not (ziel / "aquaticy.json").exists()
    assert not (ziel / ".arbeit").exists()


def test_a_failed_update_keeps_the_working_install(
    helfer: ModuleType, hersteller: Hersteller, tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    ziel = tmp_path / "blender"
    assert _aufruf(helfer, capsys, "install", "blender", str(ziel),
                   "--quelle", hersteller.quelle)[0] == 0
    hersteller.dateien["/release/Blender4.5/blender-4.5.10.sha256"] = b"kaputt\n"
    code, _antwort = _aufruf(helfer, capsys, "install", "blender", str(ziel),
                            "--quelle", hersteller.quelle)
    assert code == 1
    assert (ziel / "app" / "blender-4.5.10-linux-x64" / "blender").is_file(), "altes bleibt"


def test_firefox_follows_the_redirect_and_checks_the_published_sums(
    helfer: ModuleType, hersteller: Hersteller, tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    ziel = tmp_path / "_firefox"
    code, antwort = _aufruf(helfer, capsys, "install", "firefox", str(ziel),
                            "--quelle", hersteller.quelle)
    assert code == 0, antwort
    assert antwort["version"] == "140.3.0esr"
    assert (ziel / "app" / "firefox" / "firefox").is_file()
    assert any("product=firefox-esr-latest" in abruf for abruf in hersteller.abrufe)


def test_signal_takes_the_newest_stable_package_only(
    helfer: ModuleType, hersteller: Hersteller, tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    ziel = tmp_path / "signal"
    code, antwort = _aufruf(helfer, capsys, "install", "signal", str(ziel),
                            "--quelle", hersteller.quelle)
    assert code == 0, antwort
    assert antwort["version"] == "7.70.0", "nicht die Beta, und 7.70 > 7.9"
    assert (ziel / "app" / "opt" / "Signal" / "signal-desktop").is_file()
    assert not any("b.deb" in abruf for abruf in hersteller.abrufe)


def test_a_web_app_gets_its_own_honest_profile(
    helfer: ModuleType, hersteller: Hersteller, tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    firefox = tmp_path / "_firefox"
    _aufruf(helfer, capsys, "install", "firefox", str(firefox), "--quelle", hersteller.quelle)
    ziel = tmp_path / "whatsapp"
    code, antwort = _aufruf(
        helfer, capsys, "webapp", str(ziel), "--firefox", str(firefox),
        "--adresse", "https://web.whatsapp.com/",
        "--zusatz", "aquaticy-usermode/9.5.9 (KI-gesteuert; +https://x.y)",
    )
    assert code == 0, antwort
    assert "Firefox/140.0" in antwort["kennung"] and "KI-gesteuert" in antwort["kennung"]
    prefs = (ziel / "profil" / "user.js").read_text()
    assert '"general.useragent.override"' in prefs and "KI-gesteuert" in prefs
    assert 'user_pref("signon.rememberSignons", false);' in prefs, "keine Passwoerter merken"
    assert 'user_pref("permissions.default.camera", 2);' in prefs
    code, _ = _aufruf(helfer, capsys, "reset", str(ziel), "profil")
    assert code == 0 and not (ziel / "profil").exists()


def test_web_apps_need_https(helfer: ModuleType, tmp_path: Path,
                             monkeypatch: pytest.MonkeyPatch,
                             capsys: pytest.CaptureFixture[str]) -> None:
    monkeypatch.setenv("AQUATICY_ADDONS_TEST", "1")
    code, antwort = _aufruf(helfer, capsys, "webapp", str(tmp_path / "x"),
                            "--adresse", "http://web.whatsapp.com/")
    assert code == 1 and "https" in antwort["fehler"]


def test_archives_cannot_break_out(helfer: ModuleType, tmp_path: Path) -> None:
    archiv = tmp_path / "boese.tar"
    archiv.write_bytes(_tar_xz({"../ausbruch": b"x"}))
    with pytest.raises(tarfile.TarError):
        helfer.tar_auspacken(archiv, tmp_path / "ziel")
    assert not (tmp_path / "ausbruch").exists()
    # Ein absoluter Pfad landet IM Ziel -- der Schraegstrich vorn faellt weg.
    archiv.write_bytes(_tar_xz({"/tmp/aquaticy-ausbruch-test": b"x"}))
    helfer.tar_auspacken(archiv, tmp_path / "ziel")
    assert (tmp_path / "ziel" / "tmp" / "aquaticy-ausbruch-test").is_file()
    assert not Path("/tmp/aquaticy-ausbruch-test").exists()


def test_archives_have_a_size_limit(helfer: ModuleType, tmp_path: Path,
                                    monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(helfer, "MAX_ENTPACKT", 10)
    archiv = tmp_path / "gross.tar"
    archiv.write_bytes(_tar_xz({"a": b"x" * 11}))
    with pytest.raises(helfer.Fehler):
        helfer.tar_auspacken(archiv, tmp_path / "ziel")


def test_gzip_bombs_are_stopped(helfer: ModuleType) -> None:
    with pytest.raises(helfer.Fehler):
        helfer.entpacke_gz(gzip.compress(b"0" * 5000), grenze=1000)


@pytest.mark.parametrize(
    ("url", "hosts", "quelle"),
    [
        ("https://evil.example/x", ("download.blender.org",), ""),
        ("http://download.blender.org/x", ("download.blender.org",), ""),
        ("http://127.0.0.1:9/x", (), "http://127.0.0.1:8000"),
    ],
)
def test_only_the_makers_servers_are_asked(helfer: ModuleType, url: str, hosts: tuple,
                                           quelle: str) -> None:
    with pytest.raises(helfer.Fehler):
        helfer.erlaubt(url, hosts, quelle)


@pytest.mark.parametrize("quelle", ["http://example.org", "ftp://127.0.0.1", "file:///etc"])
def test_a_test_source_must_be_local_or_https(helfer: ModuleType, quelle: str) -> None:
    with pytest.raises(helfer.Fehler):
        helfer.quelle_ok(quelle)


def test_targets_are_only_addon_volumes(
    helfer: ModuleType, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.delenv("AQUATICY_ADDONS_TEST", raising=False)
    for ziel in ("/work", "/addons/../etc", "/addons/X", "/addons/whatsapp/profil", "/etc"):
        with pytest.raises(helfer.Fehler):
            helfer.ziel_frei(ziel)


def test_checksum_lists_are_matched_by_name(helfer: ModuleType) -> None:
    liste = f"{'a' * 64}  linux-x86_64/de/firefox-1esr.tar.xz\n{'b' * 64} *other.tar.xz\n"
    assert helfer.summe_aus_liste(liste, "linux-x86_64/de/firefox-1esr.tar.xz") == "a" * 64
    assert helfer.summe_aus_liste(liste, "other.tar.xz") == "b" * 64
    with pytest.raises(helfer.Fehler):
        helfer.summe_aus_liste(liste, "fehlt.tar.xz")


def test_the_installer_is_in_the_image() -> None:
    dockerfile = (ORDNER.parent / "workshop-desktop.Dockerfile").read_text()
    assert "COPY docker/desktop/aquaticy-addons /usr/local/bin/aquaticy-addons" in dockerfile
    for paket in ("libnss3", "libgtk-3-0t64", "libgl1-mesa-dri", "dpkg"):
        assert paket in dockerfile, paket
