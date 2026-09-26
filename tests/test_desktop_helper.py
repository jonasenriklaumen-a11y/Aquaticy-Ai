"""Tests fuer die Hilfsprogramme im Desktop-Abbild (docker/desktop/).

Sie laufen sonst nur in der Werkstatt. Hier wird geprueft, was ohne Bildschirm
pruefbar ist: dass aus Argumenten nie etwas anderes wird als das Erwartete,
dass Sonderzeichen vorab eine Taste bekommen und dass der Browser sich ehrlich
zu erkennen gibt.
"""

from __future__ import annotations

import importlib.machinery
import importlib.util
import shutil
import subprocess
import sys
from pathlib import Path
from types import ModuleType

import pytest

ORDNER = Path(__file__).resolve().parent.parent / "docker" / "desktop"


@pytest.fixture(scope="module")
def helfer() -> ModuleType:
    loader = importlib.machinery.SourceFileLoader(
        "aquaticy_desktop_helfer", str(ORDNER / "aquaticy-desktop")
    )
    spec = importlib.util.spec_from_loader(loader.name, loader)
    assert spec is not None
    modul = importlib.util.module_from_spec(spec)
    loader.exec_module(modul)
    return modul


@pytest.fixture
def kein_rufen(helfer: ModuleType, monkeypatch: pytest.MonkeyPatch) -> list[tuple]:
    """Merkt sich, was aufgerufen wuerde -- ausgefuehrt wird nichts."""
    gerufen: list[tuple] = []

    def rufe(*args: str, eingabe: bytes | None = None, zeit: float = 30):
        gerufen.append((args, eingabe))
        return subprocess.CompletedProcess(args, 0, b"", b"")

    monkeypatch.setattr(helfer, "rufe", rufe)
    monkeypatch.setattr(helfer.time, "sleep", lambda sekunden: None)
    return gerufen


@pytest.mark.parametrize(
    "argumente",
    [
        [], ["loeschen"], ["click", "x", "5"], ["click", "5000", "5"], ["click", "5", "5",
        "--button", "9"], ["key", "ctrl+l; rm"], ["key"], ["scroll", "5", "5", "quer", "3"],
        ["scroll", "5", "5", "down", "99"], ["open", "rm"], ["open", "browser", "-evil"],
        ["focus", "abc"], ["shot", "--mark", "9999", "1"], ["shot", "--quality", "5"],
    ],
)
def test_wrong_calls_are_refused_before_anything_runs(
    helfer: ModuleType, kein_rufen: list[tuple], argumente: list[str]
) -> None:
    assert helfer.main(argumente) == 2
    assert kein_rufen == [], "nichts ausgefuehrt"


def test_a_click_is_exactly_a_click(helfer: ModuleType, kein_rufen: list[tuple]) -> None:
    assert helfer.main(["click", "12", "34", "--double"]) == 0
    assert kein_rufen[0][0] == (
        "xdotool", "mousemove", "--sync", "12", "34", "click", "--repeat", "2", "--delay",
        "120", "1",
    )


def test_keys_are_passed_as_names(helfer: ModuleType, kein_rufen: list[tuple]) -> None:
    assert helfer.main(["key", "ctrl+l", "Return"]) == 0
    assert kein_rufen[0][0][-2:] == ("ctrl+l", "Return")


def test_the_grid_has_labels_every_hundred_pixels(helfer: ModuleType) -> None:
    befehle = helfer.raster_befehle()
    linien = [b for b in befehle if b.startswith("line ")]
    assert len(linien) == (1280 // 100) + (800 // 100 - 1)
    assert "+302+12" in befehle and "300" in befehle


def test_the_mark_sits_where_the_click_goes(helfer: ModuleType) -> None:
    assert "circle 640,400 658,400" in helfer.marken_befehle(640, 400)


@pytest.mark.parametrize(
    ("zeichen", "name"), [("ä", "0xe4"), ("ß", "0xdf"), ("Ä", "0xc4"), ("€", "0x10020ac"),
                          ("„", "0x100201e")],
)
def test_keysyms_match_what_xdotool_looks_for(helfer: ModuleType, zeichen: str, name: str) -> None:
    assert helfer.keysym_fuer(zeichen) == name


def test_free_keys_are_found_in_the_keymap(helfer: ModuleType) -> None:
    belegung = "\n".join([
        "keycode  38 = a A a A",
        "keycode 200 =",
        "keycode 201 = ",
        "keycode  90 =",  # zu weit unten -- echte Tasten bleiben in Ruhe
        "keycode 202 = adiaeresis",
    ])
    frei, belegt = helfer.freie_tasten(belegung)
    assert frei == [200, 201]
    assert "adiaeresis" in belegt


def test_special_characters_get_a_key_before_typing(
    helfer: ModuleType, monkeypatch: pytest.MonkeyPatch
) -> None:
    gerufen: list[tuple] = []

    def rufe(*args: str, eingabe: bytes | None = None, zeit: float = 30):
        gerufen.append(args)
        ausgabe = b"keycode 200 =\nkeycode 201 =\nkeycode 202 =\n" if args[:2] == (
            "xmodmap", "-pke") else b""
        return subprocess.CompletedProcess(args, 0, ausgabe, b"")

    monkeypatch.setattr(helfer, "rufe", rufe)
    monkeypatch.setattr(helfer.time, "sleep", lambda sekunden: None)
    helfer.sonderzeichen_belegen("Grüße, Köln")
    belegt = [args for args in gerufen if args[0] == "xmodmap" and "-e" in args]
    assert belegt, "vorab belegt"
    zuordnungen = [teil for teil in belegt[0] if teil.startswith("keycode")]
    assert {z.split("=")[1].split()[0] for z in zuordnungen} == {"0xfc", "0xdf", "0xf6"}


def test_plain_ascii_needs_no_remapping(helfer: ModuleType, kein_rufen: list[tuple]) -> None:
    helfer.sonderzeichen_belegen("Hello, world! jonas@example.org {x:[1]}")
    assert kein_rufen == []


def test_emoji_are_refused_instead_of_typed_wrong(
    helfer: ModuleType, kein_rufen: list[tuple], monkeypatch: pytest.MonkeyPatch
) -> None:
    class Eingabe:
        buffer = type("B", (), {"read": staticmethod(lambda: "Hallo 😀".encode())})()

    monkeypatch.setattr(helfer.sys, "stdin", Eingabe())
    assert helfer.main(["type"]) == 2
    assert kein_rufen == []


def test_the_browser_says_who_is_driving(
    helfer: ModuleType, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv("HOME", str(tmp_path))
    kennung = 'Mozilla/5.0 (X11; Linux x86_64) aquaticy-usermode/9 (KI-gesteuert; +https://x.y)'
    helfer.profil_anlegen(kennung)
    ini = (tmp_path / ".config/falkon/profiles/default/settings.ini").read_text()
    assert f'UserAgent="{kennung}"' in ini, "in Anfuehrungszeichen -- sonst endet sie am ;"
    office = (tmp_path / ".config/libreoffice/4/user/registrymodifications.xcu").read_text()
    assert "ShowTipOfTheDay" in office
    for ordner in ("Downloads", "Dokumente"):
        assert (tmp_path / ordner).is_dir()


def test_a_broken_identity_cannot_break_the_file(
    helfer: ModuleType, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv("HOME", str(tmp_path))
    helfer.profil_anlegen('boese"\n[Web-Browser-Settings]\nUserAgent=nackt')
    zeilen = (tmp_path / ".config/falkon/profiles/default/settings.ini").read_text().splitlines()
    assert sum(z.startswith("[Web-Browser-Settings]") for z in zeilen) == 1
    assert sum(z.startswith("UserAgent=") for z in zeilen) == 1, "keine zweite Zeile erschlichen"


@pytest.mark.skipif(shutil.which("sh") is None, reason="keine Shell")
def test_the_lock_script_is_valid_shell() -> None:
    fertig = subprocess.run(["sh", "-n", str(ORDNER / "aquaticy-netz")], check=False)
    assert fertig.returncode == 0
    text = (ORDNER / "aquaticy-netz").read_text()
    for bereich in ("10.0.0.0/8", "100.64.0.0/10", "127.0.0.0/8", "169.254.0.0/16",
                    "172.16.0.0/12", "192.168.0.0/16"):
        assert bereich in text, bereich
    assert "set -eu" in text, "eine gescheiterte Zeile bricht ab -- keine halbe Sperre"


def test_the_helpers_are_in_the_image() -> None:
    dockerfile = (ORDNER.parent / "workshop-desktop.Dockerfile").read_text()
    assert "COPY docker/desktop/aquaticy-desktop /usr/local/bin/aquaticy-desktop" in dockerfile
    assert "COPY docker/desktop/aquaticy-netz /usr/local/sbin/aquaticy-netz" in dockerfile
    assert "chmod 0700 /usr/local/sbin/aquaticy-netz" in dockerfile
    assert "USER 1000" in dockerfile
    for paket in ("tini", "iptables", "xvfb", "xdotool", "falkon", "libreoffice-writer"):
        assert paket in dockerfile, paket


def test_helper_and_host_agree_on_the_apps(helfer: ModuleType) -> None:
    from aquaticy import desktop

    assert set(helfer.APPS) == set(desktop.APPS)
    assert (helfer.BREITE, helfer.HOEHE) == (desktop.WIDTH, desktop.HEIGHT)
    assert helfer.TASTE.pattern == desktop.KEY_RE.pattern


def test_the_helper_runs_under_the_python_of_the_image(helfer: ModuleType) -> None:
    """Das Abbild hat Python 3.12; der Test laeuft ab 3.11 -- beides muss gehen."""
    assert sys.version_info >= (3, 11)
    assert helfer.VERSION


def test_window_titles_do_not_swallow_the_host(helfer: ModuleType) -> None:
    """Falkon nennt seine Klasse "Falkon Browser.Falkon" -- mit Leerzeichen."""
    ausgabe = (
        "0x0060001c  0 Falkon Browser.Falkon  95a19ec59497 Index of /ubuntu - Falkon\n"
        "0x00200008 -1 tint2.Tint2                    N/A tint2\n"
        "0x00c00003  0 mousepad.Mousepad     95a19ec59497 Unbenannt 1 - Mousepad\n"
        "0x00c00009  0 libreoffice.LibreOffice  N/A \n"
    )
    fenster = helfer.fenster_zeilen(ausgabe, "95a19ec59497")
    assert fenster == [
        {"id": "0x0060001c", "klasse": "Falkon Browser.Falkon",
         "titel": "Index of /ubuntu - Falkon"},
        {"id": "0x00c00003", "klasse": "mousepad.Mousepad", "titel": "Unbenannt 1 - Mousepad"},
        {"id": "0x00c00009", "klasse": "libreoffice.LibreOffice", "titel": ""},
    ]


def test_the_window_list_stays_small(helfer: ModuleType) -> None:
    ausgabe = "".join(
        f"0x{i:08x}  0 x.X  host {'T' * 500}\n" for i in range(500)
    )
    fenster = helfer.fenster_zeilen(ausgabe, "host")
    assert len(fenster) == helfer.MAX_FENSTER
    assert all(len(f["titel"]) <= 200 for f in fenster)


def test_an_addon_start_path_stays_in_its_folder(helfer: ModuleType, tmp_path: Path) -> None:
    """Seit 9.5.16: ein absoluter Pfad oder ein Symlink nach draussen startet nichts."""
    ordner = tmp_path / "blender"
    (ordner / "app").mkdir(parents=True)
    (ordner / "app" / "blender").write_text("#!/bin/sh\n")
    (ordner / "raus").symlink_to("/bin/sh")
    assert helfer.innerhalb(ordner, "app/blender") == (ordner / "app" / "blender").resolve()
    for start in ("/bin/sh", "../../bin/sh", "raus", "", "app"):
        assert helfer.innerhalb(ordner, start) is None, start
