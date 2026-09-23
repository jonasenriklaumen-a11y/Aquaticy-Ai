"""Tests fuer die Werkstatt.

Ein echter Behaelter laeuft hier nicht -- in der Pruefkette gibt es weder
Docker noch Podman, und ein Test, der ein Abbild aus dem Netz zieht, waere
kein Test mehr, sondern eine Wette. Geprueft wird deshalb genau das, was man
ohne Laufzeit pruefen kann und was zaehlt: **welche Befehlszeile gebaut wird**.
Dort steht die Sicherheit. Faellt eine Haertung heraus, faellt hier ein Test.
"""

from __future__ import annotations

import subprocess
import sys
from types import SimpleNamespace
from typing import Any

import pytest

from aquaticy import sandbox as werkstatt


class FakeRun:
    """Merkt sich jede Befehlszeile und antwortet, wie man es ihr sagt."""

    def __init__(self, antworten: dict[str, tuple[int, str, str]] | None = None) -> None:
        self.aufrufe: list[list[str]] = []
        self.antworten = antworten or {}

    def __call__(self, args: list[str], **kwargs: Any) -> subprocess.CompletedProcess[str]:
        self.aufrufe.append(list(args))
        for schluessel, (code, out, err) in self.antworten.items():
            if schluessel in args:
                return subprocess.CompletedProcess(args, code, out, err)
        return subprocess.CompletedProcess(args, 0, "", "")

    def zeile(self, enthaelt: str) -> list[str]:
        """Die erste Zeile, in der *enthaelt* vorkommt."""
        for aufruf in self.aufrufe:
            if enthaelt in aufruf:
                return aufruf
        raise AssertionError(f"keine Zeile mit {enthaelt!r} in {self.aufrufe}")


@pytest.fixture
def box(monkeypatch: pytest.MonkeyPatch) -> tuple[werkstatt.Sandbox, FakeRun]:
    fake = FakeRun({"inspect": (0, "true\n", "")})
    monkeypatch.setattr(subprocess, "run", fake)
    monkeypatch.setattr(
        werkstatt,
        "_runs_capped",
        lambda binary, *args, **kwargs: fake([binary, *args], **kwargs),
    )
    sandkasten = werkstatt.Sandbox(image="python:3.12-slim")
    sandkasten.runtime = werkstatt.Runtime("docker", "docker", "Docker (gehaertet)")
    return sandkasten, fake


# ---------------------------------------------------------------------------
# Die Wand
# ---------------------------------------------------------------------------
def test_the_container_is_locked_down(box: tuple[werkstatt.Sandbox, FakeRun]) -> None:
    """Jede dieser Zeilen hat einen Grund -- keine darf verschwinden."""
    sandkasten, fake = box
    sandkasten.ensure()
    zeile = fake.zeile("--detach")

    def paar(flagge: str) -> str:
        return zeile[zeile.index(flagge) + 1]

    assert paar("--network") == "none", "kein Netz -- weder hinaus noch ins Heimnetz"
    assert paar("--cap-drop") == "ALL", "keine Linux-Faehigkeiten"
    assert paar("--security-opt") == "no-new-privileges"
    assert "--read-only" in zeile, "unveraenderliches Wurzeldateisystem"
    assert paar("--user") == werkstatt.RUN_AS, "nicht als root"
    assert paar("--memory") == "1024m"
    assert paar("--memory-swap") == "1024m", "kein Auslagern -- sonst waere das Limit keins"
    assert paar("--cpus") == "1"
    assert paar("--pids-limit") == str(werkstatt.PID_LIMIT), "gegen die Gabelbombe"
    assert "/tmp:rw,noexec,nosuid,size=64m" in zeile


def test_nothing_of_the_computer_goes_in(box: tuple[werkstatt.Sandbox, FakeRun]) -> None:
    """Kein Verzeichnis, keine Umgebungsvariable, kein Schluessel."""
    sandkasten, fake = box
    sandkasten.ensure()
    zeile = fake.zeile("--detach")

    mounts = [zeile[i + 1] for i, teil in enumerate(zeile) if teil == "-v"]
    assert mounts, "ein Arbeitsverzeichnis braucht es"
    for mount in mounts:
        quelle = mount.split(":")[0]
        assert not quelle.startswith("/"), f"{mount} reicht ein Verzeichnis des Rechners hinein"
        assert quelle.startswith("aquaticy-werkstatt-"), mount

    umgebung = [zeile[i + 1] for i, teil in enumerate(zeile) if teil == "--env"]
    erlaubt = {"HOME", "PATH", "LANG", "PYTHONDONTWRITEBYTECODE"}
    for eintrag in umgebung:
        name = eintrag.split("=", 1)[0]
        assert name in erlaubt, f"{name} hat in der Werkstatt nichts zu suchen"


def test_the_strongest_runtime_wins(monkeypatch: pytest.MonkeyPatch) -> None:
    """gVisor vor Podman vor Docker -- und niemals der Rechner selbst."""
    vorhanden: set[str] = set()
    monkeypatch.setattr(
        werkstatt.shutil, "which", lambda name: f"/usr/bin/{name}" if name in vorhanden else None
    )
    monkeypatch.setattr(werkstatt, "_works", lambda binary: binary in vorhanden)
    monkeypatch.setattr(werkstatt, "_has_gvisor", lambda binary: "gvisor" in vorhanden)

    assert werkstatt.find_runtime() is None, "ohne Laufzeit gibt es keine Werkstatt"

    vorhanden = {"docker"}
    gefunden = werkstatt.find_runtime()
    assert gefunden is not None and gefunden.kind == "docker"

    vorhanden = {"docker", "podman"}
    gefunden = werkstatt.find_runtime()
    assert gefunden is not None and gefunden.kind == "podman", "ohne Wurzelrechte ist besser"

    vorhanden = {"docker", "podman", "gvisor"}
    gefunden = werkstatt.find_runtime()
    assert gefunden is not None and gefunden.kind == "gvisor"
    assert "--runtime" in gefunden.extra and "runsc" in gefunden.extra


def test_without_a_runtime_nothing_runs_on_the_computer(monkeypatch: pytest.MonkeyPatch) -> None:
    """Der wichtigste Test der Datei: es gibt keinen Rueckfall."""
    monkeypatch.setattr(werkstatt, "find_runtime", lambda: None)
    sandkasten = werkstatt.Sandbox()
    with pytest.raises(werkstatt.SandboxUnavailable) as gescheitert:
        sandkasten.ensure()
    assert "fuehre ich nichts aus" in str(gescheitert.value)


# ---------------------------------------------------------------------------
# Arbeiten darin
# ---------------------------------------------------------------------------
def test_a_command_never_touches_a_shell_of_this_computer(
    box: tuple[werkstatt.Sandbox, FakeRun]
) -> None:
    """Der Befehl geht als Argument an die Laufzeit -- interpretiert wird er
    erst drinnen. Sonst waere ein `; rm -rf ~` aus dem Modell ein Problem."""
    sandkasten, fake = box
    sandkasten.run("echo hallo; rm -rf /")
    zeile = fake.zeile("exec")
    assert zeile[-1] == "echo hallo; rm -rf /", "der Befehl steht unzerlegt am Ende"
    assert zeile[-2] == "-c" and zeile[-3] == "sh"
    assert "--user" in zeile and zeile[zeile.index("--user") + 1] == werkstatt.RUN_AS


def test_paths_stay_inside_the_workshop() -> None:
    assert werkstatt.safe_path("loesung.py") == "/work/loesung.py"
    assert werkstatt.safe_path("/work/unter/a.txt") == "/work/unter/a.txt"
    for boese in ("../../etc/passwd", "/etc/passwd", "/work/../etc/shadow", ""):
        with pytest.raises(ValueError):
            werkstatt.safe_path(boese)


def test_long_output_is_cut(box: tuple[werkstatt.Sandbox, FakeRun]) -> None:
    """Ein `yes` ohne Deckel wuerde das Kontextfenster fuellen."""
    sandkasten, fake = box
    fake.antworten = {"exec": (0, "x" * 50_000, ""), "inspect": (0, "true\n", "")}
    ergebnis = sandkasten.run("yes")
    assert len(ergebnis.stdout) < werkstatt.MAX_OUTPUT + 100
    assert ergebnis.truncated
    assert "gekuerzt" in ergebnis.stdout


def test_host_output_is_buffered_with_a_hard_limit() -> None:
    done = werkstatt._runs_capped(
        sys.executable, "-c", "print('x' * 1000000)", timeout=5
    )
    assert len(done.stdout) <= werkstatt.MAX_OUTPUT * 2


def test_a_hanging_command_is_ended(
    box: tuple[werkstatt.Sandbox, FakeRun], monkeypatch: pytest.MonkeyPatch
) -> None:
    sandkasten, fake = box

    def haengt(args: list[str], **kwargs: Any) -> subprocess.CompletedProcess[str]:
        fake.aufrufe.append(list(args))
        if "exec" in args:
            raise subprocess.TimeoutExpired(args, 5)
        return subprocess.CompletedProcess(args, 0, "true\n", "")

    sandkasten.runtime = werkstatt.Runtime("docker", "docker", "Docker")
    monkeypatch.setattr(
        werkstatt,
        "_runs_capped",
        lambda binary, *args, **kwargs: haengt([binary, *args], **kwargs),
    )
    ergebnis = sandkasten.run("sleep 999", timeout=1)
    assert ergebnis.timed_out and ergebnis.exit_code == 124
    assert "Abgebrochen" in ergebnis.as_dict()["note"]


def test_the_timeout_has_an_upper_bound(
    box: tuple[werkstatt.Sandbox, FakeRun], monkeypatch: pytest.MonkeyPatch
) -> None:
    """Wer 10000 Sekunden verlangt, bekommt trotzdem hoechstens das Maximum."""
    sandkasten, fake = box
    aufgezeichnet: dict[str, Any] = {}

    def merke(args: list[str], **kwargs: Any) -> subprocess.CompletedProcess[str]:
        fake.aufrufe.append(list(args))
        if "exec" in args:
            aufgezeichnet["timeout"] = kwargs.get("timeout")
        return subprocess.CompletedProcess(args, 0, "true\n", "")

    monkeypatch.setattr(
        werkstatt,
        "_runs_capped",
        lambda binary, *args, **kwargs: merke([binary, *args], **kwargs),
    )
    sandkasten.run("echo", timeout=10_000)
    assert aufgezeichnet["timeout"] <= werkstatt.MAX_TIMEOUT + 5


# ---------------------------------------------------------------------------
# Und wieder weg
# ---------------------------------------------------------------------------
def test_stopping_removes_container_and_volume(box: tuple[werkstatt.Sandbox, FakeRun]) -> None:
    """"Nach zwanzig Minuten sind alle Spuren weg" ist genau das hier."""
    sandkasten, fake = box
    sandkasten.ensure()
    name, volume = sandkasten.name, sandkasten._volume
    sandkasten.stop("Test")

    entfernt = fake.zeile("rm")
    assert name in entfernt and "--force" in entfernt and "--volumes" in entfernt
    aufgeraeumt = [zeile for zeile in fake.aufrufe if "volume" in zeile and "rm" in zeile]
    assert aufgeraeumt and volume in aufgeraeumt[0]
    assert not sandkasten.alive


def test_the_clock_starts_over_with_every_use(box: tuple[werkstatt.Sandbox, FakeRun]) -> None:
    """Zwanzig Minuten ab der letzten Nachricht, nicht ab dem Start."""
    sandkasten, _ = box
    sandkasten.ensure()
    erster = sandkasten._timer
    assert erster is not None
    sandkasten.touch()
    assert sandkasten._timer is not erster, "die Uhr wird neu gestellt"
    assert sandkasten._timer is not None
    sandkasten.stop("Test")
    assert sandkasten._timer is None, "ohne Werkstatt keine Uhr"


def test_a_failed_start_leaves_nothing_standing(monkeypatch: pytest.MonkeyPatch) -> None:
    """Halbe Werkstatt ist schlimmer als keine."""
    fake = FakeRun({"run": (1, "", "kein Abbild")})
    monkeypatch.setattr(subprocess, "run", fake)
    sandkasten = werkstatt.Sandbox()
    sandkasten.runtime = werkstatt.Runtime("docker", "docker", "Docker")
    with pytest.raises(werkstatt.SandboxUnavailable):
        sandkasten.ensure()
    assert not sandkasten.alive
    assert any("rm" in zeile for zeile in fake.aufrufe), "der Rest wird weggeraeumt"


def test_forgotten_workshops_are_swept(monkeypatch: pytest.MonkeyPatch) -> None:
    """Nach einem Absturz soll beim naechsten Start nichts liegen bleiben."""
    fake = FakeRun(
        {"ps": (0, "abc123\ndef456\n", ""), "ls": (0, "aquaticy-werkstatt-x\nandere\n", "")}
    )
    monkeypatch.setattr(subprocess, "run", fake)
    entfernt = werkstatt.sweep(werkstatt.Runtime("docker", "docker", "Docker"))
    assert entfernt == 2
    geloescht = [zeile for zeile in fake.aufrufe if "volume" in zeile and "rm" in zeile]
    assert any("aquaticy-werkstatt-x" in zeile for zeile in geloescht)
    assert not any("andere" in zeile for zeile in geloescht), "fremde Datentraeger bleiben"


# ---------------------------------------------------------------------------
# Dateien hinein und heraus
# ---------------------------------------------------------------------------
def _laufende(monkeypatch: pytest.MonkeyPatch) -> werkstatt.Sandbox:
    """Eine Werkstatt, die sich fuer laufend haelt -- ohne echten Behaelter."""
    sandkasten = werkstatt.Sandbox(image="python:3.12-slim")
    sandkasten.runtime = werkstatt.Runtime("docker", "docker", "Docker (gehaertet)")
    sandkasten._name = "aquaticy-werkstatt-test"
    monkeypatch.setattr(sandkasten, "ensure", lambda: sandkasten._name)
    return sandkasten


def test_hineinlegen_geht_durch_die_werkstatt(monkeypatch: pytest.MonkeyPatch) -> None:
    """Auch ein Bild -- write() nimmt nur Text und wuerde daran scheitern."""
    box = _laufende(monkeypatch)
    aufrufe: list[list[str]] = []

    def fake(args: list[str], **kwargs: Any) -> subprocess.CompletedProcess[bytes]:
        aufrufe.append(list(args))
        return subprocess.CompletedProcess(args, 0, b"", b"")

    monkeypatch.setattr(werkstatt.subprocess, "run", fake)
    antwort = box.put_bytes("eingang/bild.png", b"\x89PNG\r\n")
    assert antwort["written"] == "/work/eingang/bild.png"
    assert antwort["bytes"] == 6
    zeile = " ".join(aufrufe[-1])
    assert "exec" in zeile
    assert "--user 1000:1000" in zeile
    assert "/work/eingang/bild.png" in zeile


def test_zu_grosse_dateien_gehen_nicht_hinein(monkeypatch: pytest.MonkeyPatch) -> None:
    box = _laufende(monkeypatch)
    with pytest.raises(ValueError, match="zu gross"):
        box.put_bytes("gross.bin", b"x" * (werkstatt.MAX_FILE_BYTES + 1))


def test_hinauslegen_kennt_nur_pfade_unter_work(monkeypatch: pytest.MonkeyPatch) -> None:
    box = _laufende(monkeypatch)
    with pytest.raises(ValueError):
        box.get_bytes("../../etc/passwd")
    with pytest.raises(ValueError):
        box.put_bytes("/etc/passwd", b"x")


def test_eine_fehlende_datei_ist_kein_leerer_download(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    box = _laufende(monkeypatch)
    monkeypatch.setattr(
        werkstatt.subprocess,
        "run",
        lambda args, **kwargs: subprocess.CompletedProcess(args, 1, b"", b""),
    )
    with pytest.raises(FileNotFoundError):
        box.get_bytes("gibtsnicht.txt")


def test_zu_grosse_datei_kommt_nicht_heraus(monkeypatch: pytest.MonkeyPatch) -> None:
    """head -c limit+1: ist mehr da als erlaubt, wird nichts geliefert."""
    box = _laufende(monkeypatch)
    zuviel = b"x" * (werkstatt.MAX_FILE_BYTES + 1)
    monkeypatch.setattr(
        werkstatt.subprocess,
        "run",
        lambda args, **kwargs: subprocess.CompletedProcess(args, 0, zuviel, b""),
    )
    with pytest.raises(ValueError, match="groesser"):
        box.get_bytes("gross.bin")


def test_dateiliste_nennt_pfad_und_groesse(monkeypatch: pytest.MonkeyPatch) -> None:
    box = _laufende(monkeypatch)
    ausgabe = "1234 /work/loesung.py\n99 /work/eingang/daten.csv\n"
    monkeypatch.setattr(
        werkstatt,
        "_runs",
        lambda *args, **kwargs: subprocess.CompletedProcess(list(args), 0, ausgabe, ""),
    )
    dateien = box.list_files()
    assert dateien == [
        {"path": "/work/eingang/daten.csv", "bytes": 99},
        {"path": "/work/loesung.py", "bytes": 1234},
    ]


def test_ohne_laufende_werkstatt_ist_die_liste_leer(monkeypatch: pytest.MonkeyPatch) -> None:
    box = werkstatt.Sandbox()
    assert box.list_files() == []


def test_each_account_gets_its_own_workshop(tmp_path) -> None:
    werkstatt.forget_shared()
    one = SimpleNamespace(data_dir=tmp_path / "one")
    two = SimpleNamespace(data_dir=tmp_path / "two")
    assert werkstatt.shared(one) is werkstatt.shared(one)
    assert werkstatt.shared(one) is not werkstatt.shared(two)
    werkstatt.forget_shared()



def test_vm_sizes_cover_normal_and_plus() -> None:
    """normal entspricht den alten festen Zahlen, plus gibt deutlich mehr."""
    assert werkstatt.VM_SIZES["normal"] == {
        "cpus": werkstatt.CPUS,
        "memory_mb": werkstatt.MEMORY_MB,
        "disk_gb": werkstatt.DISK_GB,
    }
    plus = werkstatt.VM_SIZES["plus"]
    normal = werkstatt.VM_SIZES["normal"]
    assert plus["cpus"] > normal["cpus"]
    assert plus["memory_mb"] > normal["memory_mb"]
    assert plus["disk_gb"] > normal["disk_gb"]


def test_blender_timeout_is_longer_than_a_normal_command() -> None:
    """Ein Rendering braucht laenger als ein gewoehnlicher Befehl -- aber
    bleibt trotzdem innerhalb der harten Obergrenze."""
    assert werkstatt.COMMAND_TIMEOUT < werkstatt.BLENDER_TIMEOUT <= werkstatt.MAX_TIMEOUT


# ---------------------------------------------------------------------------
# User mode: Desktop mit Internet -- aber mit Netzsperre fuers Heimnetz
# ---------------------------------------------------------------------------
_ALLE_REGELN = "\n".join(
    f"-A OUTPUT -d {bereich} -j REJECT --reject-with icmp-port-unreachable"
    for bereich in werkstatt.BLOCKED_RANGES
)


class UserModeRun:
    """Wie FakeRun, kennt aber Sperre, Regelliste und Desktop-Start."""

    def __init__(self, regeln: str = _ALLE_REGELN, sperre: tuple[int, str] = (0, "gesperrt\n"),
                 desktop: tuple[int, str] = (0, '{"bereit": true}\n')) -> None:
        self.aufrufe: list[list[str]] = []
        self.regeln, self.sperre, self.desktop = regeln, sperre, desktop

    def __call__(self, args: list[str], **kwargs: Any) -> subprocess.CompletedProcess[str]:
        self.aufrufe.append(list(args))
        if "inspect" in args:
            return subprocess.CompletedProcess(args, 0, "true\n", "")
        if werkstatt.NETWORK_SCRIPT in args:
            return subprocess.CompletedProcess(args, self.sperre[0], self.sperre[1], "kaputt")
        if "iptables" in args:
            return subprocess.CompletedProcess(args, 0, self.regeln, "")
        if werkstatt.DESKTOP_HELPER in args and "start" in args:
            return subprocess.CompletedProcess(args, self.desktop[0], self.desktop[1], "")
        return subprocess.CompletedProcess(args, 0, "", "")

    def zeile(self, enthaelt: str) -> list[str]:
        for aufruf in self.aufrufe:
            if enthaelt in aufruf:
                return aufruf
        raise AssertionError(f"keine Zeile mit {enthaelt!r}")


def _user_box(monkeypatch: pytest.MonkeyPatch, fake: UserModeRun) -> werkstatt.Sandbox:
    monkeypatch.setattr(subprocess, "run", fake)
    sandkasten = werkstatt.Sandbox(user_mode=True, browser_agent="Kennung (KI-gesteuert)")
    sandkasten.runtime = werkstatt.Runtime("docker", "docker", "Docker (gehaertet)")
    return sandkasten


def test_user_mode_opens_the_internet_and_nothing_else(monkeypatch: pytest.MonkeyPatch) -> None:
    fake = UserModeRun()
    sandkasten = _user_box(monkeypatch, fake)
    sandkasten.ensure()
    zeile = fake.zeile("--detach")

    def paar(flagge: str) -> str:
        return zeile[zeile.index(flagge) + 1]

    assert "--network" not in zeile, "das uebliche Netz der Laufzeit -- gesperrt wird drinnen"
    assert paar("--cap-drop") == "ALL"
    assert zeile.count("--cap-add") == 1 and paar("--cap-add") == "NET_ADMIN", (
        "genau eine Faehigkeit, nur fuer die Sperre"
    )
    assert paar("--security-opt") == "no-new-privileges"
    assert "--read-only" in zeile
    assert paar("--user") == werkstatt.RUN_AS, "gearbeitet wird nie als root"
    assert paar("--pids-limit") == str(werkstatt.DESKTOP_PID_LIMIT)
    assert "/run:rw,nosuid,nodev,size=8m" in zeile
    assert f"DISPLAY={werkstatt.DISPLAY}" in zeile
    assert zeile[-4:] == [werkstatt.DESKTOP_IMAGE, "tini", "--", "sleep", "infinity"][-4:]
    assert werkstatt.DESKTOP_IMAGE in zeile, "ohne Angabe das Desktop-Abbild"
    assert not any(teil.startswith("/home") or teil.startswith("/Users") for teil in zeile)


def test_the_lock_runs_as_root_and_everything_else_does_not(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    fake = UserModeRun()
    _user_box(monkeypatch, fake).ensure()
    als_root = [aufruf for aufruf in fake.aufrufe if "exec" in aufruf and "0:0" in aufruf]
    assert {werkstatt.NETWORK_SCRIPT, "iptables"} == {
        teil for aufruf in als_root for teil in aufruf
        if teil in (werkstatt.NETWORK_SCRIPT, "iptables")
    }, "als root laufen genau die Sperre und das Nachlesen der Regeln"
    start = fake.zeile(werkstatt.DESKTOP_HELPER)
    assert start[start.index("--user") + 1] == werkstatt.RUN_AS
    assert "Kennung (KI-gesteuert)" in start, "der Browser bekommt seine ehrliche Kennung"


@pytest.mark.parametrize("fehlt", werkstatt.BLOCKED_RANGES)
def test_an_incomplete_lock_means_no_user_mode(monkeypatch: pytest.MonkeyPatch, fehlt: str) -> None:
    regeln = "\n".join(z for z in _ALLE_REGELN.splitlines() if f" {fehlt} " not in z)
    fake = UserModeRun(regeln=regeln)
    sandkasten = _user_box(monkeypatch, fake)
    with pytest.raises(werkstatt.SandboxUnavailable, match=fehlt.replace(".", r"\.")):
        sandkasten.ensure()
    assert not sandkasten.alive
    assert any("rm" in aufruf and "--force" in aufruf for aufruf in fake.aufrufe), (
        "die offene Werkstatt wird sofort wieder abgebaut"
    )


def test_a_failing_lock_script_means_no_user_mode(monkeypatch: pytest.MonkeyPatch) -> None:
    fake = UserModeRun(sperre=(1, ""))
    sandkasten = _user_box(monkeypatch, fake)
    with pytest.raises(werkstatt.SandboxUnavailable, match="Netzsperre"):
        sandkasten.ensure()
    assert not sandkasten.alive


def test_the_script_saying_locked_is_not_enough(monkeypatch: pytest.MonkeyPatch) -> None:
    """Das Skript meldet "gesperrt" -- nachgelesen wird trotzdem."""
    fake = UserModeRun(regeln="-P OUTPUT ACCEPT\n")
    with pytest.raises(werkstatt.SandboxUnavailable, match="unvollstaendig"):
        _user_box(monkeypatch, fake).ensure()


def test_a_desktop_that_does_not_start_takes_the_workshop_with_it(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    fake = UserModeRun(desktop=(1, ""))
    sandkasten = _user_box(monkeypatch, fake)
    with pytest.raises(werkstatt.SandboxUnavailable, match="Desktop"):
        sandkasten.ensure()
    assert not sandkasten.alive


def test_without_user_mode_there_is_no_desktop(box: tuple[werkstatt.Sandbox, FakeRun]) -> None:
    sandkasten, fake = box
    with pytest.raises(werkstatt.SandboxUnavailable, match="User mode"):
        sandkasten.desktop("windows")
    zeile = fake.zeile("--detach") if any("--detach" in a for a in fake.aufrufe) else []
    assert "NET_ADMIN" not in zeile


def test_a_screenshot_must_be_a_jpeg(monkeypatch: pytest.MonkeyPatch) -> None:
    fake = UserModeRun()
    sandkasten = _user_box(monkeypatch, fake)
    sandkasten.ensure()

    def antwort(args: list[str], **kwargs: Any) -> Any:
        if "shot" in args:
            return subprocess.CompletedProcess(args, 0, b"<html>kein Bild</html>", b"")
        return fake(args, **kwargs)

    monkeypatch.setattr(subprocess, "run", antwort)
    with pytest.raises(werkstatt.SandboxUnavailable, match="Bildschirmfoto"):
        sandkasten.screenshot()


def test_typed_text_travels_through_stdin(monkeypatch: pytest.MonkeyPatch) -> None:
    fake = UserModeRun()
    sandkasten = _user_box(monkeypatch, fake)
    sandkasten.ensure()
    gesehen: list[dict[str, Any]] = []

    def antwort(args: list[str], **kwargs: Any) -> Any:
        if werkstatt.DESKTOP_HELPER not in args:
            return fake(args, **kwargs)
        gesehen.append({"args": list(args), "input": kwargs.get("input")})
        return subprocess.CompletedProcess(args, 0, b"{}", b"")

    monkeypatch.setattr(subprocess, "run", antwort)
    sandkasten.desktop("type", stdin=b"; rm -rf / $(boese)")
    assert gesehen[-1]["input"] == b"; rm -rf / $(boese)"
    assert "; rm -rf / $(boese)" not in " ".join(gesehen[-1]["args"])
    assert "--interactive" in gesehen[-1]["args"]


def test_shared_picks_the_desktop_image_in_user_mode(monkeypatch: pytest.MonkeyPatch) -> None:
    settings = SimpleNamespace(data_dir="/tmp/aquaticy-test-usermode", vm_user_mode=True,
                               vm_desktop_image="", vm_image="python:3.12-slim")
    werkstatt.forget_shared(settings)
    try:
        sandkasten = werkstatt.shared(settings)
        assert sandkasten.user_mode is True
        assert sandkasten.image == werkstatt.DESKTOP_IMAGE
        assert "KI-gesteuert" in sandkasten.browser_agent
    finally:
        werkstatt.forget_shared(settings)


def _zu_lang(fake: UserModeRun):
    def capped(binary: str, *args: str, **kwargs: Any):
        fake([binary, *args], **kwargs)
        raise subprocess.TimeoutExpired([binary, *args], 1)

    return capped


def test_a_timeout_restart_puts_the_lock_back_first(monkeypatch: pytest.MonkeyPatch) -> None:
    """Ein Neustart baut das Netz neu auf -- die Sperre muss sofort wieder hin."""
    fake = UserModeRun()
    sandkasten = _user_box(monkeypatch, fake)
    sandkasten.ensure()
    monkeypatch.setattr(werkstatt, "_runs_capped", _zu_lang(fake))
    fake.aufrufe.clear()
    assert sandkasten.run("sleep 999", timeout=1).timed_out
    reihenfolge = [
        "restart" if "restart" in aufruf else
        "sperre" if werkstatt.NETWORK_SCRIPT in aufruf else
        "nachlesen" if "iptables" in aufruf else
        "desktop" if werkstatt.DESKTOP_HELPER in aufruf else None
        for aufruf in fake.aufrufe
    ]
    schritte = [schritt for schritt in reihenfolge if schritt]
    assert schritte[:4] == ["restart", "sperre", "nachlesen", "desktop"], schritte
    assert sandkasten.alive


def test_a_restart_without_the_lock_takes_the_workshop_down(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    fake = UserModeRun()
    sandkasten = _user_box(monkeypatch, fake)
    sandkasten.ensure()
    fake.regeln = "-P OUTPUT ACCEPT\n"  # nach dem Neustart fehlt die Sperre
    monkeypatch.setattr(werkstatt, "_runs_capped", _zu_lang(fake))
    sandkasten.run("sleep 999", timeout=1)
    assert not sandkasten.alive, "eine offene Werkstatt ist schlimmer als keine"


def test_a_look_from_outside_starts_no_workshop(monkeypatch: pytest.MonkeyPatch) -> None:
    fake = UserModeRun()
    sandkasten = _user_box(monkeypatch, fake)
    with pytest.raises(werkstatt.SandboxUnavailable, match="laeuft gerade nicht"):
        sandkasten.screenshot(start=False)
    assert not any("--detach" in aufruf for aufruf in fake.aufrufe), "nichts gestartet"
