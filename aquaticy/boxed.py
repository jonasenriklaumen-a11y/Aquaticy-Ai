"""Laeuft Aquaticy selbst in einer Kiste -- und was steht daran offen?

Zwei Waende uebereinander:

1. **Die aeussere Kiste.** Das ganze Programm laeuft in einem Container:
   Oberflaeche, Agent, Browser-Rueckfall. Vom Wirt sieht es nur, was
   ausdruecklich hineingereicht wurde -- der Datenordner, der Ausgabeordner
   und der Weg nach draussen ins Netz. Kein Heimverzeichnis, keine Geraete,
   keine Wurzelrechte.

2. **Die innere Kiste.** Die Werkstatt, in der der Code-Modus fremden Code
   ausfuehrt, laeuft noch einmal in einem eigenen Container INNERHALB der
   aeusseren. Ein Ausbruch von dort landet also nicht auf dem Rechner,
   sondern in der aeusseren Kiste -- und die hat selbst kaum etwas.

Dieses Modul stellt nur fest, was der Fall ist. Es aendert nichts: eine
Kiste, die sich selbst einsperrt, waere ein Widerspruch. Was hier als
`Loch` gemeldet wird, gehoert in die Startdatei, nicht in den Programmlauf.

**Warum der Docker-Socket des Wirts nie hineingereicht wird.** Das ist der
uebliche Kurzweg, damit die Werkstatt drinnen Container starten kann -- und
er hebt die ganze aeussere Wand auf: wer den Socket erreicht, startet auf
dem Wirt einen Container mit dessen Wurzelverzeichnis und ist damit root.
Die Werkstatt bekommt deshalb eine eigene, wurzellose Laufzeit im Inneren.
"""

from __future__ import annotations

import os
import shutil
from dataclasses import dataclass
from pathlib import Path

#: Woran ein Container sich zu erkennen gibt. Podman legt die erste Datei
#: an, Docker die zweite; beide sind seit Jahren stabil.
BOX_MARKERS: tuple[tuple[str, str], ...] = (
    ("/run/.containerenv", "podman"),
    ("/.dockerenv", "docker"),
)

#: Der Socket, ueber den man den Wirt steuern koennte. Er hat in der Kiste
#: nichts zu suchen -- siehe Modulkopf.
HOST_SOCKETS: tuple[str, ...] = (
    "/var/run/docker.sock",
    "/run/docker.sock",
    "/run/podman/podman.sock",
)

#: Laufzeiten fuer die innere Kiste, stark zuerst. Wurzellos ist Podman hier
#: die erste Wahl: es braucht keinen Dienst mit Wurzelrechten im Ruecken.
NESTED_RUNTIMES: tuple[str, ...] = ("podman", "docker")


@dataclass(frozen=True, slots=True)
class Posture:
    """Der Stand der Dinge -- eine Zeile je Frage, die man stellen wuerde."""

    boxed: bool
    #: Woran die aeussere Kiste erkannt wurde ("podman", "docker", "" ).
    kind: str
    #: Die Laufzeit fuer die innere Kiste, oder "" wenn es keine gibt.
    nested: str
    #: Was offen steht und offen stehen soll.
    openings: tuple[str, ...]
    #: Was offen steht und NICHT offen stehen sollte.
    holes: tuple[str, ...]

    @property
    def workshop_possible(self) -> bool:
        """Kann der Code-Modus ueberhaupt eine Werkstatt aufmachen?"""
        return bool(self.nested)


def _da(pfad: str) -> bool:
    """Gibt es diese Datei? Ein kaputter Pfad ist keine Antwort wert.

    Das hier laeuft beim Start. Auf einem eigenartigen Dateisystem kann
    schon `exists()` mit einem Rechtefehler abbrechen -- und dann stuende
    nicht "keine Kiste" da, sondern ein Absturz.
    """
    try:
        return Path(pfad).exists()
    except OSError:
        return False


def _first_marker() -> str:
    for pfad, name in BOX_MARKERS:
        if _da(pfad):
            return name
    return ""


def in_a_box() -> bool:
    """Laeuft dieser Prozess in einem Container?"""
    if _first_marker():
        return True
    # Ein Container ohne Markierung ist selten, aber moeglich. Dann verraet
    # ihn die Steuergruppe: auf einem gewoehnlichen System steht dort nicht
    # der Name einer Container-Laufzeit.
    try:
        gruppen = Path("/proc/self/cgroup").read_text(encoding="utf-8", errors="replace")
    except OSError:
        return False
    return any(wort in gruppen for wort in ("/docker/", "/podman/", "libpod", "kubepods"))


def nested_runtime() -> str:
    """Die Laufzeit, mit der drinnen eine Werkstatt aufgemacht werden kann."""
    for name in NESTED_RUNTIMES:
        try:
            gefunden = shutil.which(name)
        except OSError:  # kaputter PATH -- dann eben keine Laufzeit
            return ""
        if gefunden:
            return name
    return ""


def reachable_host_sockets() -> tuple[str, ...]:
    """Steuersockel des Wirts, die von hier aus erreichbar sind."""
    return tuple(pfad for pfad in HOST_SOCKETS if _da(pfad))


def _root_is_writable() -> bool:
    """Ist das Wurzeldateisystem beschreibbar?

    In der Kiste soll es das nicht sein: alles Veraenderliche liegt in
    eigenen Ablagen. Ein beschreibbares Wurzelverzeichnis heisst, dass
    jemand darin etwas ablegen und beim naechsten Start ausfuehren kann.
    """
    try:
        return os.access("/", os.W_OK)
    except OSError:
        return False


def posture() -> Posture:
    """Stellt fest, wie Aquaticy gerade steht."""
    kind = _first_marker()
    boxed = bool(kind) or in_a_box()
    offen: list[str] = []
    loecher: list[str] = []

    if boxed:
        offen.append("Netz nach draussen (Recherche, Modelle, Ollama auf dem Wirt)")
        offen.append("Datenordner und Ausgabeordner")
    innen = nested_runtime()
    if innen:
        offen.append(f"innere Kiste fuer die Werkstatt ({innen})")

    for pfad in reachable_host_sockets():
        loecher.append(
            f"{pfad} ist erreichbar -- darueber laesst sich der Wirt steuern. "
            "Diesen Sockel nicht in die Kiste reichen."
        )
    if boxed and os.geteuid() == 0:
        loecher.append("Aquaticy laeuft in der Kiste als root -- ein eigener Benutzer ist besser.")
    if boxed and _root_is_writable():
        loecher.append(
            "Das Wurzeldateisystem der Kiste ist beschreibbar -- "
            "mit `read_only: true` bleibt nur das Noetige schreibbar."
        )
    return Posture(
        boxed=boxed,
        kind=kind or ("unbekannt" if boxed else ""),
        nested=innen,
        openings=tuple(offen),
        holes=tuple(loecher),
    )


def describe(stand: Posture | None = None) -> list[str]:
    """Der Stand als lesbare Zeilen -- fuer die Kommandozeile."""
    stand = stand if stand is not None else posture()
    zeilen: list[str] = []
    if stand.boxed:
        zeilen.append(f"Aquaticy laeuft in einer Kiste ({stand.kind}).")
    else:
        zeilen.append(
            "Aquaticy laeuft direkt auf dem Rechner, nicht in einer Kiste. "
            "Mit ./aquaticy-sandbox startet es eingeschlossen."
        )
    if stand.nested:
        zeilen.append(f"Werkstatt: innere Kiste ueber {stand.nested} moeglich.")
    else:
        zeilen.append(
            "Werkstatt: keine Laufzeit fuer die innere Kiste gefunden -- "
            "der Code-Modus fuehrt dann nichts aus."
        )
    zeilen.extend(f"offen: {eintrag}" for eintrag in stand.openings)
    zeilen.extend(f"LOCH: {eintrag}" for eintrag in stand.holes)
    return zeilen
