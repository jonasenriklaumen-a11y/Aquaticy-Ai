"""Die Werkstatt: eine Wegwerf-Maschine, in der Aquaticy Code ausfuehren darf.

Im Code-Modus laesst sich eine abgeschottete Umgebung zuschalten. Darin darf
Aquaticy alles -- Dateien anlegen, Programme starten, Tests laufen lassen --,
nur eines nicht: heraus. Diese Datei ist die Wand.

**Warum ueberhaupt eine Wand.** Code, den ein Sprachmodell schreibt, ist
fremder Code. Er kann falsch sein, er kann bei einem praeparierten Prompt
boesartig sein, und er kann beides sein, ohne dass man es ihm ansieht. Er
darf deshalb nie auf dem Rechner des Nutzers laufen -- auch nicht "nur kurz"
und auch nicht "nur zum Testen".

**Was die Wand ist.** Nach dem Stand der Technik (Stand 2026) reicht ein
gewoehnlicher Container fuer fremden Code nicht mehr: Kernel und Container
teilen sich denselben Kern, und eine Kernel-Luecke fuehrt aus jedem Container
heraus. Die drei belastbaren Stufen sind, von stark nach schwach:

1. **MicroVM** (Firecracker, Kata) -- eigener Kernel auf Hardware-
   Virtualisierung. Was drinnen passiert, bleibt hinter der CPU-Grenze.
2. **gVisor** (`runsc`) -- ein Kern im Nutzerraum faengt die Systemaufrufe ab
   und beantwortet sie selbst; das Programm sieht den echten Kernel nie.
3. **Container ohne Wurzelrechte** (rootless Podman) -- ein Ausbruch landet in
   einem unprivilegierten Nutzernamensraum, nicht bei root.

Aquaticy nimmt, was da ist, in genau dieser Reihenfolge, und faellt niemals auf
"dann eben direkt auf dem Rechner" zurueck. Ist keine der Stufen vorhanden,
gibt es die Werkstatt nicht, und das Werkzeug sagt, was zu installieren ist.

**Womit die Wand zusaetzlich gehaertet wird** -- jede Zeile hat einen Grund:

* `--network none` -- kein Netz. Weder hinaus noch ins Heimnetz. Damit ist der
  haeufigste Missbrauch (Daten abfliessen lassen, Nachladen von Schadcode) an
  der Wurzel erledigt.
* `--cap-drop ALL` -- keine Linux-Faehigkeiten. Kein Mounten, keine rohen
  Sockets, keine Kernelmodule.
* `--security-opt no-new-privileges` -- ein setuid-Programm kann drinnen keine
  Rechte mehr hinzugewinnen.
* `--read-only` -- das Wurzeldateisystem ist unveraenderlich. Geschrieben wird
  nur in `/work` und in ein kleines `/tmp` im Arbeitsspeicher.
* `--user` auf eine unprivilegierte Kennung -- niemand arbeitet als root.
* `--memory`, `--cpus`, `--pids-limit`, `--ulimit` -- eine Endlosschleife, eine
  Gabelbombe oder ein Speicherfresser bringt den Rechner nicht in die Knie.
* Keine Umgebungsvariablen von aussen. Die Schluessel des Nutzers haben in der
  Werkstatt nichts zu suchen, und sie kommen auch nicht hinein.
* Kein Verzeichnis des Rechners wird hineingereicht. Dateien gehen nur durch
  das Werkzeug hinein und heraus, ueber die Standardeingabe des Prozesses.

**Was danach uebrig bleibt: nichts.** Zwanzig Minuten nach der letzten Nutzung
werden Behaelter und Datentraeger geloescht. Beim naechsten Mal entsteht eine
neue, leere Werkstatt. Auch beim Beenden des Programms wird aufgeraeumt.

**User mode.** Auf Wunsch (Einstellungen -> Werkstatt) wird die Werkstatt ein
kleiner Desktop, den Aquaticy bedient wie ein Mensch: Bildschirm ansehen,
klicken, tippen, Programme oeffnen (siehe aquaticy/desktop.py). Dafuer
aendert sich genau zweierlei, und beides ist hier begruendet:

* Es gibt **Internet** -- aber **kein Heimnetz**. Beim Start setzt ein Skript
  im Abbild (docker/desktop/aquaticy-netz) als root eine Sperre fuer alle
  privaten und lokalen Bereiche; dafuer bekommt der Behaelter als einzige
  Faehigkeit `NET_ADMIN`. Alles andere laeuft weiter als unprivilegierter
  Nutzer ohne jede Faehigkeit -- die Sperre kann von drinnen niemand aendern.
  Aquaticy liest die Regeln danach selbst nach. Fehlt auch nur ein Bereich,
  wird die Werkstatt sofort wieder abgebaut: ohne Sperre kein User mode.
* Mehr Prozesse und offene Dateien, ein Aufraeumer (`tini`) als erster
  Prozess und ein beschreibbares `/run` -- ein Browser ist kein Skript.

Alles andere bleibt: kein root, unveraenderliches Wurzeldateisystem, keine
Verzeichnisse und keine Umgebungsvariablen vom Rechner, feste Grenzen fuer
Speicher und Prozessor, Loeschen nach zwanzig Minuten Ruhe.
"""

from __future__ import annotations

import atexit
import contextlib
import os
import re
import shutil
import subprocess
import threading
import time
import uuid
from dataclasses import dataclass
from pathlib import Path
from typing import Any

#: Wie lange die Werkstatt nach der letzten Nutzung stehen bleibt.
IDLE_MINUTES = 20

#: Grenzen. Ein Kern, ein Gigabyte Arbeitsspeicher, vier Gigabyte Platte.
CPUS = 1
MEMORY_MB = 1024
DISK_GB = 4

#: Zwei Groessen fuer die Werkstatt, waehlbar in den Einstellungen
#: (AQUATICY_VM_SIZE). "normal" ist der Alltag -- ein Skript schreiben,
#: ausfuehren, die Ausgabe lesen. "plus" gibt es fuer alles, was mehr
#: Rechenleistung braucht: ein Blender-Rendering zum Beispiel bringt mit
#: einem Kern und einem Gigabyte kaum ein Bild zustande, bevor die Zeit
#: ablaeuft.
VM_SIZES: dict[str, dict[str, int]] = {
    "normal": {"cpus": CPUS, "memory_mb": MEMORY_MB, "disk_gb": DISK_GB},
    "plus": {"cpus": 4, "memory_mb": 6144, "disk_gb": 20},
}

#: Wie lange ein Blender-Rendering laufen darf. Laenger als ein gewoehnlicher
#: Befehl (COMMAND_TIMEOUT) -- schon eine einfache Szene braucht mehrere
#: Sekunden je Bild --, aber wie jeder Befehl durch MAX_TIMEOUT gedeckelt.
BLENDER_TIMEOUT = 90

#: Prozesse und offene Dateien. Beides deckelt eine Gabelbombe.
PID_LIMIT = 256
FILE_LIMIT = 512

#: Wie lange ein einzelner Befehl laufen darf, und wie lange hoechstens.
COMMAND_TIMEOUT = 30
MAX_TIMEOUT = 120

#: Wie viel Ausgabe zurueckkommt. Der Rest wird abgeschnitten -- ein `yes`
#: ohne Deckel wuerde sonst das Kontextfenster fuellen.
MAX_OUTPUT = 8000

#: Wie viel eine einzelne Datei beim Lesen liefern darf.
MAX_READ_BYTES = 200_000

#: Wie gross eine Datei sein darf, die hinein- oder herausgereicht wird.
#: Der Weg fuehrt durch den Arbeitsspeicher des Servers -- 20 MB sind
#: genug fuer alles, was man von Hand hin- und hertraegt, und wenig genug,
#: dass zehn davon nebeneinander niemandem den Rechner fuellen.
MAX_FILE_BYTES = 20 * 1024 * 1024

#: Wie viele Dateien die Liste hoechstens zeigt.
MAX_LIST = 500

#: Das Abbild. Klein, mit Python und den ueblichen Werkzeugen.
DEFAULT_IMAGE = "python:3.12-slim"

#: Das Arbeitsverzeichnis in der Werkstatt. Nur hier darf geschrieben werden.
WORKDIR = "/work"

#: Die Kennung, unter der drinnen gearbeitet wird -- nicht root.
RUN_AS = "1000:1000"

#: Das Abbild fuer den User mode (siehe docker/workshop-desktop.Dockerfile).
DESKTOP_IMAGE = "aquaticy-werkstatt-desktop:local"

#: Im User mode laufen Browser und Office. Die brauchen mehr Prozesse --
#: jeder Thread zaehlt mit -- und mehr offene Dateien als ein Skript. Gegen
#: eine Gabelbombe hilft die Grenze trotzdem noch.
DESKTOP_PID_LIMIT = 1024
DESKTOP_FILE_LIMIT = 4096

#: Der Bildschirm in der Werkstatt.
DISPLAY = ":1"

#: Die Hilfsprogramme im Desktop-Abbild.
DESKTOP_HELPER = "aquaticy-desktop"
NETWORK_SCRIPT = "/usr/local/sbin/aquaticy-netz"

#: Diese Bereiche muessen in der Netzsperre stehen, sonst gilt sie als nicht
#: eingerichtet: das Heimnetz (RFC 1918), Tailscale/CGNAT, Loopback und
#: Link-Local. Die Werkstatt kaeme sonst an Router, Home Assistant und Lager.
BLOCKED_RANGES = (
    "10.0.0.0/8",
    "100.64.0.0/10",
    "127.0.0.0/8",
    "169.254.0.0/16",
    "172.16.0.0/12",
    "192.168.0.0/16",
)

#: Der Suchpfad fuer die beiden Aufrufe als root (Sperre setzen, Sperre lesen).
#: Drinnen gilt sonst der knappe PATH der Werkstatt -- ohne /usr/sbin, wo
#: iptables liegt.
ROOT_PATH = "/usr/sbin:/sbin:/usr/bin:/bin"

#: So viel darf ein Bildschirmfoto hoechstens wiegen. Ein JPEG von 1280x800
#: hat gut 100 kB; was deutlich groesser ist, ist kein Bildschirmfoto.
MAX_SHOT_BYTES = 5 * 1024 * 1024


class SandboxUnavailable(RuntimeError):
    """Es gibt keine belastbare Abschottung auf diesem Rechner."""


@dataclass(frozen=True)
class Runtime:
    """Womit die Werkstatt betrieben wird."""

    binary: str
    #: "gvisor", "podman" oder "docker" -- absteigend nach Staerke.
    kind: str
    label: str
    #: Zusaetzliche Argumente fuer `run`, etwa die gVisor-Laufzeit.
    extra: tuple[str, ...] = ()

    @property
    def strength(self) -> str:
        """Ein Satz darueber, wie stark die Wand hier ist."""
        return {
            "gvisor": (
                "gVisor: die Systemaufrufe beantwortet ein Kern im Nutzerraum, "
                "der echte Kernel wird nicht angefasst."
            ),
            "podman": (
                "Podman ohne Wurzelrechte: ein Ausbruch landet in einem "
                "unprivilegierten Nutzernamensraum, nicht bei root."
            ),
            "docker": (
                "Docker mit gehaertetem Profil: kein Netz, keine Faehigkeiten, "
                "unveraenderliches Wurzeldateisystem. Der Kernel ist geteilt -- "
                "fuer noch mehr Abstand waere gVisor oder eine MicroVM noetig."
            ),
        }[self.kind]


def _runs(binary: str, *args: str, timeout: float = 8.0) -> subprocess.CompletedProcess[str]:
    """Ruft die Laufzeit auf -- ohne Shell, damit nichts interpretiert wird."""
    return subprocess.run(
        [binary, *args],
        capture_output=True,
        text=True,
        timeout=timeout,
        check=False,
    )


#: Befehle, die ueber der Grenze noch laufen duerfen -- einzeln, ohne Verkettung.
_CLEANUP_RE = re.compile(r"^\s*(rm|rmdir|truncate|du|ls|df)(\s[^;&|`$<>(){}\n]*)?$")


def cleanup_command(command: str) -> bool:
    """Ist das ein reiner Aufraeumbefehl -- ohne Verkettung, Umleitung oder Ersetzung?"""
    return bool(_CLEANUP_RE.fullmatch(command or ""))


def _runs_capped(
    binary: str, *args: str, timeout: float = 8.0
) -> subprocess.CompletedProcess[str]:
    """Fuehrt einen Werkstatt-Befehl mit begrenzten Empfangspuffern aus.

    Die Begrenzung muss hier am Host-Rohr liegen: ein Container-Speicherlimit
    verhindert nicht, dass sein Client beliebig viel Ausgabe in Aquaticys
    Hauptprozess puffert.
    """
    command = [binary, *args]
    stdout = bytearray()
    stderr = bytearray()

    def drain(pipe: Any, target: bytearray, limit: int) -> None:
        while chunk := pipe.read(8192):
            remaining = limit - len(target)
            if remaining > 0:
                target.extend(chunk[:remaining])

    process = subprocess.Popen(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    assert process.stdout is not None and process.stderr is not None
    # `_cut()` braucht etwas mehr als seine Anzeigegrenze, um den Hinweis auf
    # die Kuerzung einzublenden. Der Host behaelt trotzdem nur kleine Puffer.
    readers = [
        threading.Thread(target=drain, args=(process.stdout, stdout, MAX_OUTPUT * 2)),
        threading.Thread(target=drain, args=(process.stderr, stderr, MAX_OUTPUT)),
    ]
    for reader in readers:
        reader.start()
    try:
        process.wait(timeout=timeout)
    except subprocess.TimeoutExpired:
        process.kill()
        process.wait()
        raise
    finally:
        for reader in readers:
            reader.join()
    return subprocess.CompletedProcess(
        command,
        process.returncode,
        stdout.decode("utf-8", errors="replace"),
        stderr.decode("utf-8", errors="replace"),
    )


def _works(binary: str) -> bool:
    """Antwortet die Laufzeit ueberhaupt? Ein installierter Client ohne
    laufenden Dienst ist so gut wie keiner."""
    try:
        return _runs(binary, "info", "--format", "{{.ServerVersion}}").returncode == 0
    except (OSError, subprocess.SubprocessError):
        return False


def _has_gvisor(binary: str) -> bool:
    """Kennt diese Laufzeit `runsc`?"""
    try:
        found = _runs(binary, "info", "--format", "{{.Runtimes}}")
    except (OSError, subprocess.SubprocessError):
        return False
    return found.returncode == 0 and "runsc" in found.stdout


def find_runtime() -> Runtime | None:
    """Sucht die staerkste verfuegbare Abschottung.

    Returns:
        Die Laufzeit, oder `None`, wenn es keine gibt. Dann gibt es auch keine
        Werkstatt -- ein Rueckfall auf den Rechner selbst waere genau das, was
        diese Datei verhindern soll.
    """
    for binary in ("podman", "docker"):
        if not shutil.which(binary) or not _works(binary):
            continue
        if _has_gvisor(binary):
            return Runtime(binary, "gvisor", f"{binary} + gVisor", ("--runtime", "runsc"))
    if shutil.which("podman") and _works("podman"):
        return Runtime("podman", "podman", "Podman (ohne Wurzelrechte)")
    if shutil.which("docker") and _works("docker"):
        return Runtime("docker", "docker", "Docker (gehaertet)")
    return None


@dataclass
class RunResult:
    """Was ein Befehl in der Werkstatt hinterlassen hat."""

    exit_code: int
    stdout: str
    stderr: str
    seconds: float
    timed_out: bool = False
    truncated: bool = False

    def as_dict(self) -> dict[str, Any]:
        payload: dict[str, Any] = {
            "exit_code": self.exit_code,
            "stdout": self.stdout,
            "stderr": self.stderr,
            "seconds": round(self.seconds, 2),
        }
        if self.timed_out:
            payload["note"] = (
                "Abgebrochen: der Befehl lief laenger als erlaubt. Lass ihn "
                "kuerzer laufen oder teile ihn auf."
            )
        if self.truncated:
            payload["truncated"] = True
        return payload


def _cut(text: str, limit: int = MAX_OUTPUT) -> tuple[str, bool]:
    """Kuerzt lange Ausgaben und sagt, ob gekuerzt wurde."""
    if len(text) <= limit:
        return text, False
    half = limit // 2
    return text[:half] + "\n… [gekuerzt] …\n" + text[-half:], True


#: Was in einem Pfad vorkommen darf. Alles andere waere entweder ein Versuch,
#: die Anfuehrungszeichen im `sh -c` zu verlassen, oder ein Tippfehler -- beides
#: will man nicht durchlassen.
PATH_CHARS = re.compile(r"^[A-Za-z0-9._/\- ]+$")


def safe_path(path: str) -> str:
    """Prueft einen Pfad in der Werkstatt.

    Erlaubt ist alles unterhalb von `/work`. Das ist keine Sicherheitsgrenze --
    die ist die Werkstatt selbst --, sondern Ordnung: Dateien, die ausserhalb
    liegen, waeren beim naechsten Start weg und wuerden nur verwirren.

    Raises:
        ValueError: Wenn der Pfad hinausfuehrt.
    """
    import posixpath

    raw = (path or "").strip()
    if not raw:
        raise ValueError("Ohne Pfad geht es nicht.")
    if not PATH_CHARS.match(raw):
        raise ValueError(
            "Im Pfad sind nur Buchstaben, Ziffern, Punkt, Strich, Unterstrich und "
            f"Schraegstrich erlaubt -- '{raw}' hat anderes darin."
        )
    full = raw if raw.startswith("/") else posixpath.join(WORKDIR, raw)
    full = posixpath.normpath(full)
    if full != WORKDIR and not full.startswith(WORKDIR + "/"):
        raise ValueError(f"Nur Pfade unterhalb von {WORKDIR} -- '{raw}' liegt ausserhalb.")
    return full


#: So heissen die Datentraeger der Add-ons: je Konto und Add-on einer.
ADDON_VOLUME_RE = re.compile(r"^aquaticy-addon-[0-9a-f]{12}-[a-z_]{2,20}$")
#: Und dort haengen sie in der Werkstatt.
ADDON_PATH_RE = re.compile(r"^/addons/[a-z_]{2,20}$")
#: Beschriftung, an der man sie erkennt -- sweep() laesst sie in Ruhe.
ADDON_LABEL = "aquaticy-addon=1"


def ensure_addon_volume(runtime: Runtime, volume: str, image: str) -> None:
    """Legt den Datentraeger eines Add-ons an (falls noetig) und gibt ihn 1000.

    Raises:
        SandboxUnavailable: Wenn das nicht geht.
    """
    if not ADDON_VOLUME_RE.fullmatch(volume):
        raise SandboxUnavailable(f"Ungueltiger Name fuer einen Add-on-Datentraeger: {volume}")
    da = _runs(runtime.binary, "volume", "inspect", volume, timeout=20)
    if da.returncode != 0:
        made = _runs(
            runtime.binary, "volume", "create", "--label", ADDON_LABEL, volume, timeout=20
        )
        if made.returncode != 0:
            raise SandboxUnavailable(
                "Datentraeger fuers Add-on liess sich nicht anlegen: " + made.stderr.strip()[:300]
            )
    prepared = _runs(
        runtime.binary,
        "run", "--rm",
        "--network", "none",
        "--cap-drop", "ALL",
        "--cap-add", "CHOWN",
        "--security-opt", "no-new-privileges",
        "--user", "0:0",
        "-v", f"{volume}:/addon",
        image,
        "chown", RUN_AS, "/addon",
        timeout=120,
    )
    if prepared.returncode != 0:
        raise SandboxUnavailable(
            "Datentraeger fuers Add-on liess sich nicht vorbereiten: "
            + prepared.stderr.strip()[:300]
        )


def remove_addon_volume(runtime: Runtime, volume: str) -> bool:
    """Loescht den Datentraeger eines Add-ons samt Programm und Anmeldung."""
    if not ADDON_VOLUME_RE.fullmatch(volume):
        return False
    weg = _runs(runtime.binary, "volume", "rm", "--force", volume, timeout=60)
    if weg.returncode == 0:
        return True
    return "no such volume" in weg.stderr.lower()


def addon_volumes(runtime: Runtime, prefix: str) -> list[str]:
    """Welche Add-on-Datentraeger es fuer ein Konto gibt."""
    gefunden = _runs(
        runtime.binary, "volume", "ls", "--quiet", "--filter", f"label={ADDON_LABEL}",
        timeout=30,
    )
    return [
        zeile.strip()
        for zeile in gefunden.stdout.splitlines()
        if zeile.strip().startswith(prefix) and ADDON_VOLUME_RE.fullmatch(zeile.strip())
    ]


class Sandbox:
    """Eine Werkstatt: startet auf Bedarf, raeumt sich selbst weg."""

    def __init__(
        self,
        *,
        image: str = "",
        idle_minutes: int = IDLE_MINUTES,
        memory_mb: int = MEMORY_MB,
        disk_gb: int = DISK_GB,
        cpus: int = CPUS,
        on_event: Any = None,
        user_mode: bool = False,
        browser_agent: str = "",
        addon_mounts: dict[str, str] | None = None,
        headless: bool = False,
    ) -> None:
        #: Desktop mit Internet statt Maschine ohne Netz (siehe Kopf der Datei).
        self.user_mode = bool(user_mode)
        #: Womit sich der Browser im User mode bei Webseiten meldet.
        self.browser_agent = browser_agent
        #: Datentraeger der eingeschalteten Add-ons -> wo sie haengen
        #: (/addons/<name>). Sie gehoeren nicht der Werkstatt und bleiben,
        #: wenn sie abgebaut wird -- dort liegen Programme und Anmeldungen.
        self.addon_mounts = {
            volume: ziel
            for volume, ziel in (addon_mounts or {}).items()
            if ADDON_VOLUME_RE.fullmatch(volume) and ADDON_PATH_RE.fullmatch(ziel)
        }
        #: Ohne Bildschirm: fuer den Installer, der nur laedt und auspackt.
        self.headless = bool(headless)
        # Ohne ausdrueckliches Abbild entscheidet die Betriebsart: der User mode
        # braucht den Desktop, alles andere kommt mit dem kleinen Abbild aus.
        self.image = image or (DESKTOP_IMAGE if self.user_mode else DEFAULT_IMAGE)
        self.idle_seconds = max(60, int(idle_minutes) * 60)
        self.memory_mb = max(128, int(memory_mb))
        self.disk_gb = max(1, int(disk_gb))
        self.cpus = max(1, int(cpus))
        self.on_event = on_event
        self.runtime: Runtime | None = None
        self._name = ""
        self._volume = ""
        self._lock = threading.RLock()
        self._timer: threading.Timer | None = None
        self._quota_warned = False
        #: Ueber der Grenze (nur wo die Laufzeit keine Quote kann): dann laufen
        #: nur noch Aufraeumbefehle (seit 9.5.15).
        self._over_quota = False
        #: Kann die Laufzeit eine Platzquote? Wird beim ersten Start geklaert.
        self._quota_ok = True
        #: Wann zuletzt nachgemessen wurde (nur ohne Quote noetig).
        self._last_quota_check = 0.0
        #: Wann zuletzt gearbeitet wurde -- fuer die Anzeige.
        self.last_used = 0.0

    # -- Zustand ----------------------------------------------------------
    @property
    def name(self) -> str:
        return self._name

    @property
    def alive(self) -> bool:
        return bool(self._name)

    def _emit(self, event: str, **payload: Any) -> None:
        # Das Aufraeumen laeuft in einem eigenen Thread und meldet sich unter
        # Umstaenden, wenn die Anfrage laengst vorbei ist. Ein Fehler im
        # Empfaenger darf die Werkstatt nicht stehen lassen.
        if not self.on_event:
            return
        with contextlib.suppress(Exception):  # nur Anzeige, nie kritisch
            self.on_event(event, payload)

    # -- Aufbau -----------------------------------------------------------
    def ensure(self) -> str:
        """Startet die Werkstatt, falls sie nicht schon laeuft.

        Returns:
            Der Name des Behaelters.

        Raises:
            SandboxUnavailable: Wenn es keine belastbare Abschottung gibt oder
                der Start scheitert.
        """
        with self._lock:
            if self._name and self._running():
                self._touch_locked()
                return self._name
            self._name = ""
            runtime = self.runtime or find_runtime()
            if runtime is None:
                raise SandboxUnavailable(
                    "Auf diesem Rechner gibt es keine Abschottung, der ich fremden "
                    "Code anvertrauen wuerde. Installiere Podman (ohne Wurzelrechte) "
                    "oder Docker; am besten zusaetzlich gVisor. Auf dem Rechner "
                    "selbst fuehre ich nichts aus."
                )
            self.runtime = runtime
            self._check_nested_network()
            token = uuid.uuid4().hex[:12]
            self._name = f"aquaticy-werkstatt-{token}"
            self._volume = f"aquaticy-werkstatt-{token}"
            self._quota_warned = False
            self._emit(
                "vm_start", runtime=runtime.label, image=self.image, user_mode=self.user_mode
            )
            try:
                self._create_volume()
                self._start_container()
                if self.user_mode:
                    self._lock_network()
                    if not self.headless:
                        self._start_desktop()
            except Exception:
                # Halbe Werkstatt ist schlimmer als keine: alles wieder weg.
                self._destroy_locked("Start fehlgeschlagen")
                raise
            self._touch_locked()
            return self._name

    def _check_nested_network(self) -> None:
        """Im eingeschlossenen Start (Kiste in der Kiste) braucht Netz ein Geraet.

        Die innere Werkstatt laeuft dort mit Podman ohne Wurzelrechte, und das
        baut sein Netz ueber /dev/net/tun. Die aeussere Kiste reicht dieses
        Geraet bewusst nicht von selbst herein (compose.sandbox.yaml). Ohne
        diese Pruefung kaeme eine Fehlermeldung von Podman, die niemand
        versteht -- so steht da, was fehlt und wo man es freigibt.
        """
        if not self.user_mode or os.environ.get("AQUATICY_SANDBOXED") != "1":
            return
        if not Path("/dev/net/tun").exists():
            raise SandboxUnavailable(
                "Im eingeschlossenen Start braucht der User mode das Geraet /dev/net/tun, "
                "damit die Werkstatt ins Internet kann. Freigeben in compose.sandbox.yaml "
                "(Abschnitt 'devices', dort erklaert) und neu starten -- oder den User "
                "mode ausschalten."
            )

    def _create_volume(self) -> None:
        """Legt den Datentraeger an und macht ihn fuer die Kennung schreibbar.

        Der Datentraeger gehoert dieser Werkstatt allein und verschwindet mit
        ihr. Bind-Mounts vom Rechner gibt es bewusst nicht: was drinnen
        passiert, soll drinnen bleiben.
        """
        runtime = self.runtime
        assert runtime is not None
        made = _runs(runtime.binary, "volume", "create", self._volume, timeout=20)
        if made.returncode != 0:
            raise SandboxUnavailable(
                "Datentraeger liess sich nicht anlegen: " + made.stderr.strip()[:300]
            )
        # Einmal kurz als root hinein, nur um die Rechte zu setzen. Dieser
        # Behaelter hat kein Netz, keine Faehigkeiten ausser CHOWN und lebt
        # einen Sekundenbruchteil.
        prepared = _runs(
            runtime.binary,
            "run", "--rm",
            "--network", "none",
            "--cap-drop", "ALL",
            "--cap-add", "CHOWN",
            "--security-opt", "no-new-privileges",
            "--user", "0:0",
            "-v", f"{self._volume}:{WORKDIR}",
            self.image,
            "chown", RUN_AS, WORKDIR,
            timeout=120,
        )
        if prepared.returncode != 0:
            raise SandboxUnavailable(
                "Die Werkstatt liess sich nicht vorbereiten: " + prepared.stderr.strip()[:300]
            )

    def _run_flags(self) -> list[str]:
        """Die Haertung. Jede Zeile steht im Kopf der Datei begruendet."""
        runtime = self.runtime
        assert runtime is not None
        desktop = self.user_mode
        # Ohne User mode: gar kein Netz. Mit: das uebliche Netz der Laufzeit --
        # die Sperre fuers Heimnetz setzt _lock_network gleich nach dem Start.
        netz = [] if desktop else ["--network", "none"]
        # NET_ADMIN ist die eine Faehigkeit, die die Sperre braucht. Sie steht
        # nur root zur Verfuegung, und root arbeitet drinnen nie -- ausser fuer
        # genau dieses eine Skript beim Start.
        faehigkeiten = ["--cap-drop", "ALL", *(("--cap-add", "NET_ADMIN") if desktop else ())]
        prozesse = DESKTOP_PID_LIMIT if desktop else PID_LIMIT
        dateien = DESKTOP_FILE_LIMIT if desktop else FILE_LIMIT
        flags = [
            "run", "--detach",
            "--name", self._name,
            *runtime.extra,
            # -- Abschottung --
            *netz,
            *faehigkeiten,
            "--security-opt", "no-new-privileges",
            "--read-only",
            "--user", RUN_AS,
            # -- Grenzen --
            "--memory", f"{self.memory_mb}m",
            "--memory-swap", f"{self.memory_mb}m",
            "--cpus", str(self.cpus),
            "--pids-limit", str(prozesse),
            "--ulimit", f"nofile={dateien}:{dateien}",
            "--ulimit", f"fsize={self.disk_gb * 1024 * 1024 * 1024}",
            # -- Platz zum Arbeiten --
            # `nocopy`: Neuere Docker-Versionen (29.x) legen wegen --workdir
            # den Ordner zuerst im Abbild an -- als root -- und kopieren das
            # beim ersten Einhaengen in den noch leeren Datentraeger. Das
            # machte das chown aus _create_volume zunichte, und die Werkstatt
            # konnte in /work nichts schreiben (bis 9.5.12).
            "-v", f"{self._volume}:{WORKDIR}:nocopy",
            *(
                flag
                for volume, ziel in sorted(self.addon_mounts.items())
                for flag in ("-v", f"{volume}:{ziel}:nocopy")
            ),
            "--tmpfs", "/tmp:rw,noexec,nosuid,size=64m",
            # Nicht jede Laufzeit kennt diese Quote (sie braucht xfs mit
            # Projektquoten). Wo sie fehlt, faellt der Start damit aus -- dann
            # startet _start_container ohne sie und wir messen stattdessen nach.
            *(("--storage-opt", f"size={self.disk_gb}G") if self._quota_ok else ()),
            "--workdir", WORKDIR,
            # -- Umgebung: nur das Noetigste, nichts vom Rechner --
            "--env", "HOME=" + WORKDIR,
            "--env", "PATH=/usr/local/bin:/usr/bin:/bin",
            "--env", "LANG=C.UTF-8",
            "--env", "PYTHONDONTWRITEBYTECODE=1",
            "--label", "aquaticy-werkstatt=1",
        ]
        if desktop:
            flags += [
                # iptables braucht ein beschreibbares /run fuer seine Sperrdatei,
                # der Browser ein groesseres /dev/shm als die 64 MB ab Werk.
                "--tmpfs", "/run:rw,nosuid,nodev,size=8m",
                "--shm-size", "256m",
                "--env", f"DISPLAY={DISPLAY}",
                "--label", "aquaticy-werkstatt-user=1",
            ]
        return flags

    def _command(self) -> list[str]:
        """Was im Behaelter als erster Prozess laeuft.

        Im User mode startet und beendet der Desktop Programme. Deren
        Ueberbleibsel raeumt nur ein echter erster Prozess weg -- `sleep` tut
        das nicht, und jeder nicht abgeholte Prozess zaehlt gegen die Grenze.
        """
        if self.user_mode:
            return ["tini", "--", "sleep", "infinity"]
        return ["sleep", "infinity"]

    def _start_container(self) -> None:
        runtime = self.runtime
        assert runtime is not None
        args = [
            *self._run_flags(),
            self.image,
            # Nichts tun, aber am Leben bleiben. `sleep infinity` haelt genau
            # einen Prozess und kostet nichts.
            *self._command(),
        ]
        started = _runs(runtime.binary, *args, timeout=300)
        if started.returncode != 0 and "storage-opt" in started.stderr:
            # Die Laufzeit kann keine Quote -- dann eben ohne, und der Platz
            # wird nach jedem Befehl nachgemessen.
            self._quota_ok = False
            args = [*self._run_flags(), self.image, *self._command()]
            started = _runs(runtime.binary, *args, timeout=300)
        if started.returncode != 0:
            if self.user_mode:
                hilfe = (
                    " (Fuer den User mode braucht es das Desktop-Abbild. Bauen mit: "
                    f"'{runtime.binary} build -f docker/workshop-desktop.Dockerfile "
                    f"-t {DESKTOP_IMAGE} .')"
                )
            else:
                hilfe = (
                    f" (Fehlt das Abbild? '{runtime.binary} pull {self.image}' holt es einmalig.)"
                )
            raise SandboxUnavailable(
                "Die Werkstatt liess sich nicht starten: " + started.stderr.strip()[:300] + hilfe
            )

    def _lock_network(self) -> None:
        """Setzt die Sperre fuers Heimnetz -- und prueft sie selbst nach.

        Das Skript im Abbild laeuft als root, weil nur root mit NET_ADMIN die
        Regeln setzen kann. Danach liest Aquaticy die Regeln aus und verlaesst
        sich nicht auf das "gesperrt" des Skripts: steht auch nur ein Bereich
        nicht darin, gilt die Werkstatt als offen -- und wird abgebaut.

        Raises:
            SandboxUnavailable: Wenn die Sperre fehlt oder unvollstaendig ist.
        """
        runtime = self.runtime
        assert runtime is not None
        gesetzt = _runs(
            runtime.binary, "exec", "--user", "0:0", "--env", f"PATH={ROOT_PATH}",
            self._name, NETWORK_SCRIPT,
            timeout=60,
        )
        if gesetzt.returncode != 0 or "gesperrt" not in gesetzt.stdout:
            raise SandboxUnavailable(
                "Die Netzsperre fuers Heimnetz liess sich nicht einrichten -- ohne sie "
                "startet der User mode nicht. " + gesetzt.stderr.strip()[:300]
            )
        regeln = _runs(
            runtime.binary, "exec", "--user", "0:0", "--env", f"PATH={ROOT_PATH}",
            self._name, "iptables", "-S", "OUTPUT",
            timeout=30,
        )
        fehlt = [
            bereich
            for bereich in BLOCKED_RANGES
            if f"-d {bereich} -j REJECT" not in regeln.stdout
        ]
        if regeln.returncode != 0 or fehlt:
            raise SandboxUnavailable(
                "Die Netzsperre fuers Heimnetz ist unvollstaendig (es fehlt: "
                + (", ".join(fehlt) or "die Regelliste")
                + ") -- ohne sie startet der User mode nicht."
            )
        self._emit("vm_net", locked=True, ranges=len(BLOCKED_RANGES))

    def _start_desktop(self) -> None:
        """Startet Bildschirm, Fenstermanager und Leiste in der Werkstatt."""
        runtime = self.runtime
        assert runtime is not None
        gestartet = _runs(
            runtime.binary,
            "exec", "--user", RUN_AS, "--workdir", WORKDIR, self._name,
            DESKTOP_HELPER, "start", self.browser_agent,
            timeout=90,
        )
        if gestartet.returncode != 0 or "bereit" not in gestartet.stdout:
            raise SandboxUnavailable(
                "Der Desktop in der Werkstatt ist nicht hochgekommen: "
                + (gestartet.stderr.strip() or gestartet.stdout.strip())[:300]
            )
        self._emit("vm_desktop", ready=True)

    def desktop(
        self, *args: str, stdin: bytes | None = None, timeout: float = 60, start: bool = True
    ) -> subprocess.CompletedProcess[bytes]:
        """Ruft das Hilfsprogramm des Desktops auf -- mit festen Argumenten.

        Keine Shell, kein Text, der als Befehl gelesen werden koennte: die
        Argumente gehen als Liste an die Laufzeit, getippter Text ueber die
        Standardeingabe.

        Args:
            start: Darf dafuer eine Werkstatt entstehen? Ein Blick von aussen
                (die Oberflaeche) soll keine hochfahren -- auch keine, deren
                Behaelter inzwischen verschwunden ist.

        Raises:
            SandboxUnavailable: Wenn die Werkstatt nicht im User mode laeuft.
        """
        if not self.user_mode:
            raise SandboxUnavailable(
                "Die Werkstatt laeuft nicht im User mode -- den schaltet der Nutzer in "
                "den Einstellungen unter 'Werkstatt' ein."
            )
        if start:
            name = self.ensure()
        elif self._name and self._running():
            name = self._name
        else:
            raise SandboxUnavailable("Die Werkstatt laeuft gerade nicht.")
        runtime = self.runtime
        assert runtime is not None
        done = subprocess.run(
            [
                runtime.binary, "exec", *(("--interactive",) if stdin is not None else ()),
                "--user", RUN_AS, "--workdir", WORKDIR, name,
                DESKTOP_HELPER, *args,
            ],
            input=stdin,
            capture_output=True,
            timeout=timeout,
            check=False,
        )
        self.touch()
        return done

    def addon_helper(
        self, *args: str, timeout: int = 1800
    ) -> subprocess.CompletedProcess[str]:
        """Ruft den Add-on-Installer in der Werkstatt auf -- feste Argumente, keine Shell.

        Laenger als ein gewoehnlicher Befehl darf er: Blender ist gut 350 MB gross.
        """
        name = self.ensure()
        runtime = self.runtime
        assert runtime is not None
        return _runs(
            runtime.binary,
            "exec", "--user", RUN_AS, "--workdir", WORKDIR, name,
            "aquaticy-addons", *args,
            timeout=max(10, int(timeout)),
        )

    def screenshot(
        self, *, grid: bool = False, mark: tuple[int, int] | None = None, start: bool = True
    ) -> bytes:
        """Ein Bildschirmfoto als JPEG.

        Raises:
            SandboxUnavailable: Ohne User mode oder wenn kein Bild kommt.
        """
        extra: list[str] = []
        if grid:
            extra.append("--grid")
        if mark is not None:
            extra += ["--mark", str(int(mark[0])), str(int(mark[1]))]
        done = self.desktop("shot", *extra, timeout=40, start=start)
        bild = done.stdout or b""
        if done.returncode != 0 or not bild.startswith(b"\xff\xd8"):
            grund = (done.stderr or b"").decode("utf-8", "replace").strip()[:300]
            raise SandboxUnavailable("Kein Bildschirmfoto bekommen. " + grund)
        if len(bild) > MAX_SHOT_BYTES:
            raise SandboxUnavailable("Das Bildschirmfoto ist unplausibel gross.")
        return bild

    def _running(self) -> bool:
        runtime = self.runtime
        if runtime is None or not self._name:
            return False
        found = _runs(runtime.binary, "inspect", "--format", "{{.State.Running}}", self._name)
        return found.returncode == 0 and found.stdout.strip() == "true"

    # -- Arbeiten ---------------------------------------------------------
    def run(self, command: str, timeout: int = COMMAND_TIMEOUT) -> RunResult:
        """Fuehrt *command* in der Werkstatt aus.

        Der Befehl geht als Argument an die Laufzeit, nie durch eine Shell auf
        diesem Rechner -- interpretiert wird er erst drinnen.
        """
        command = (command or "").strip()
        if not command:
            raise ValueError("Ohne Befehl gibt es nichts zu tun.")
        limit = max(1, min(int(timeout or COMMAND_TIMEOUT), MAX_TIMEOUT))
        name = self.ensure()
        runtime = self.runtime
        assert runtime is not None
        if self._over_quota and not cleanup_command(command):
            # Hart (9.5.15): ueber der Grenze laeuft nur noch Aufraeumen.
            return RunResult(
                exit_code=125, stdout="",
                stderr=(f"[Werkstatt] Voll: mehr als {self.disk_gb} GB belegt. Erst aufräumen "
                        "-- erlaubt sind jetzt nur rm, rmdir, truncate, du, ls und df, "
                        "jeweils einzeln."),
                seconds=0.0,
            )
        self._emit("vm_run", command=command[:200])
        started = time.monotonic()
        # Kann die Laufzeit keine echte Quote, wacht ein Aufpasser waehrend des
        # Befehls: ueber der Grenze wird er abgebrochen, nicht erst hinterher
        # gewarnt (bis 9.5.14).
        stop = threading.Event()
        waechter = None
        if not self._quota_ok:
            waechter = threading.Thread(target=self._watch_disk, args=(stop,), daemon=True)
            waechter.start()
        try:
            done = _runs_capped(
                runtime.binary,
                "exec", "--user", RUN_AS, "--workdir", WORKDIR, name,
                "sh", "-c", command,
                # Etwas Luft, damit die Laufzeit selbst antworten kann, bevor
                # wir sie abwuergen.
                timeout=limit + 5,
            )
            out, cut_out = _cut(done.stdout)
            err, cut_err = _cut(done.stderr, MAX_OUTPUT // 2)
            result = RunResult(
                exit_code=done.returncode,
                stdout=out,
                stderr=err,
                seconds=time.monotonic() - started,
                truncated=cut_out or cut_err,
            )
        except subprocess.TimeoutExpired:
            # Der Prozess drinnen laeuft womoeglich weiter -- also weg damit.
            self._kill_processes()
            result = RunResult(
                exit_code=124,
                stdout="",
                stderr="",
                seconds=time.monotonic() - started,
                timed_out=True,
            )
        finally:
            stop.set()
            if waechter is not None:
                waechter.join(timeout=5)
        self.touch()
        self._check_quota(result)
        self._emit("vm_done", exit_code=result.exit_code, seconds=round(result.seconds, 2))
        return result

    def _refuse_if_full(self) -> None:
        """Ueber der Grenze wird nichts mehr hineingeschrieben (9.5.15)."""
        if self._over_quota:
            raise ValueError(f"Die Werkstatt ist voll (mehr als {self.disk_gb} GB) -- "
                             "erst aufräumen.")

    #: So oft misst der Aufpasser waehrend eines Befehls (Sekunden).
    WATCH_SECONDS = 3.0

    def _watch_disk(self, stop: threading.Event) -> None:
        """Misst waehrend eines Befehls -- ueber der Grenze wird abgebrochen."""
        while not stop.wait(self.WATCH_SECONDS):
            if self.usage_gb() > self.disk_gb:
                self._over_quota = True
                self._kill_processes()
                return

    def _check_quota(self, result: RunResult) -> None:
        """Misst den Platz nach jedem Befehl, wo die Laufzeit keine Quote kann.

        Ueber der Grenze ist die Werkstatt gesperrt -- bis aufgeraeumt ist,
        laufen nur noch Aufraeumbefehle (``cleanup_command``). Bis 9.5.14 gab
        es hier nur eine Warnung.
        """
        if self._quota_ok:
            return
        self._last_quota_check = time.monotonic()
        voll = self.usage_gb()
        if voll <= self.disk_gb:
            self._over_quota = False
            self._quota_warned = False
            return
        self._over_quota = True
        self._quota_warned = True
        result.stderr = (
            f"[Werkstatt] {voll} GB belegt, erlaubt sind {self.disk_gb} GB. Der Befehl wurde "
            "abgebrochen bzw. ist gesperrt, bis aufgeräumt ist (rm, einzeln).\n" + result.stderr
        )

    def _kill_processes(self) -> None:
        """Beendet, was nach einer Zeitueberschreitung noch laeuft.

        Im User mode baut ein Neustart das Netz des Behaelters neu auf -- ohne
        die Sperre von vorher. Die wird deshalb sofort neu gesetzt und
        nachgelesen, bevor irgendetwas anderes darin laeuft, und der Desktop
        kommt wieder hoch. Klappt eins davon nicht, wird die Werkstatt
        abgebaut: eine offene Werkstatt ist schlimmer als keine.
        """
        runtime = self.runtime
        if runtime is None or not self._name:
            return
        with self._lock:
            with contextlib.suppress(OSError, subprocess.SubprocessError):
                _runs(runtime.binary, "restart", "--time", "1", self._name, timeout=60)
            if not self.user_mode or not self._name:
                return
            try:
                self._lock_network()
                if not self.headless:
                    self._start_desktop()
            except Exception:
                self._destroy_locked("Netzsperre nach dem Neustart nicht wiederhergestellt")

    def write(self, path: str, text: str) -> dict[str, Any]:
        """Legt eine Datei in der Werkstatt an."""
        full = safe_path(path)
        name = self.ensure()
        runtime = self.runtime
        assert runtime is not None
        self._refuse_if_full()
        data = (text or "").encode("utf-8")
        if len(data) > 4 * 1024 * 1024:
            raise ValueError("Die Datei ist zu gross fuer den Weg durch das Werkzeug (4 MB).")
        parent = full.rsplit("/", 1)[0] or WORKDIR
        done = subprocess.run(
            [
                runtime.binary, "exec", "--interactive",
                "--user", RUN_AS, "--workdir", WORKDIR, name,
                "sh", "-c", f'mkdir -p "{parent}" && cat > "{full}"',
            ],
            input=data,
            capture_output=True,
            timeout=60,
            check=False,
        )
        self.touch()
        if done.returncode != 0:
            grund = done.stderr.decode("utf-8", "replace")[:300]
            return {"error": grund or "Schreiben ging nicht."}
        self._emit("vm_write", path=full, bytes=len(data))
        return {"written": full, "bytes": len(data)}

    def read(self, path: str, max_bytes: int = MAX_READ_BYTES) -> dict[str, Any]:
        """Liest eine Datei aus der Werkstatt."""
        full = safe_path(path)
        name = self.ensure()
        runtime = self.runtime
        assert runtime is not None
        limit = max(1, min(int(max_bytes or MAX_READ_BYTES), MAX_READ_BYTES))
        done = _runs(
            runtime.binary,
            "exec", "--user", RUN_AS, "--workdir", WORKDIR, name,
            "sh", "-c", f'head -c {limit + 1} "{full}"',
            timeout=60,
        )
        self.touch()
        if done.returncode != 0:
            return {"error": done.stderr.strip()[:300] or "Datei nicht lesbar."}
        text = done.stdout
        cut = len(text.encode("utf-8", "ignore")) > limit
        if cut:
            text = text[:limit]
        return {"path": full, "text": text, "truncated": cut}

    def put_bytes(self, path: str, data: bytes) -> dict[str, Any]:
        """Legt eine Datei unveraendert in die Werkstatt -- auch ein Bild.

        `write` nimmt Text und wuerde an einem PNG scheitern. Hierueber geht
        alles, was der Nutzer anhaengt, unangetastet hinein.
        """
        full = safe_path(path)
        if len(data) > MAX_FILE_BYTES:
            raise ValueError(
                f"Die Datei ist zu gross fuer die Werkstatt "
                f"({MAX_FILE_BYTES // (1024 * 1024)} MB sind das Hoechste)."
            )
        name = self.ensure()
        self._refuse_if_full()
        runtime = self.runtime
        assert runtime is not None
        parent = full.rsplit("/", 1)[0] or WORKDIR
        done = subprocess.run(
            [
                runtime.binary, "exec", "--interactive",
                "--user", RUN_AS, "--workdir", WORKDIR, name,
                "sh", "-c", f'mkdir -p "{parent}" && cat > "{full}"',
            ],
            input=data,
            capture_output=True,
            timeout=120,
            check=False,
        )
        self.touch()
        if done.returncode != 0:
            grund = done.stderr.decode("utf-8", "replace")[:300]
            return {"error": grund or "Hineinlegen ging nicht."}
        self._emit("vm_write", path=full, bytes=len(data))
        return {"written": full, "bytes": len(data)}

    def get_bytes(self, path: str, max_bytes: int = MAX_FILE_BYTES) -> bytes:
        """Holt eine Datei unveraendert heraus.

        Raises:
            ValueError: Wenn der Pfad hinausfuehrt oder die Datei zu gross ist.
            FileNotFoundError: Wenn es sie nicht gibt.
        """
        full = safe_path(path)
        limit = max(1, min(int(max_bytes or MAX_FILE_BYTES), MAX_FILE_BYTES))
        name = self.ensure()
        runtime = self.runtime
        assert runtime is not None
        done = subprocess.run(
            [
                runtime.binary, "exec", "--user", RUN_AS, "--workdir", WORKDIR, name,
                "sh", "-c", f'test -f "{full}" && head -c {limit + 1} "{full}"',
            ],
            capture_output=True,
            timeout=120,
            check=False,
        )
        self.touch()
        if done.returncode != 0:
            raise FileNotFoundError(f"In der Werkstatt liegt keine Datei '{full}'.")
        if len(done.stdout) > limit:
            raise ValueError(
                f"Die Datei ist groesser als {limit // (1024 * 1024)} MB -- "
                "so viel geht nicht durch."
            )
        return done.stdout

    def list_files(self, path: str = WORKDIR) -> list[dict[str, Any]]:
        """Was in der Werkstatt liegt -- Pfad und Groesse, flach aufgelistet.

        Ohne diese Liste muesste man raten, wie eine erzeugte Datei heisst,
        um sie herauszuholen.
        """
        full = safe_path(path)
        if not self.alive or self.runtime is None:
            return []
        # `find -printf` gibt es in busybox nicht; `stat -c` ueberall.
        done = _runs(
            self.runtime.binary,
            "exec", "--user", RUN_AS, "--workdir", WORKDIR, self._name,
            "sh", "-c",
            f'find "{full}" -type f -not -path "*/.git/*" 2>/dev/null '
            f"| head -n {MAX_LIST} | xargs -r stat -c '%s %n' 2>/dev/null",
            timeout=30,
        )
        self.touch()
        dateien: list[dict[str, Any]] = []
        for zeile in done.stdout.splitlines():
            groesse, _, pfad = zeile.strip().partition(" ")
            if not pfad:
                continue
            try:
                dateien.append({"path": pfad, "bytes": int(groesse)})
            except ValueError:
                continue
        dateien.sort(key=lambda eintrag: eintrag["path"])
        return dateien

    def usage_gb(self) -> float:
        """Wie voll die Werkstatt ist -- in Gigabyte."""
        if not self.alive or self.runtime is None:
            return 0.0
        done = _runs(
            self.runtime.binary,
            "exec", "--user", RUN_AS, self._name,
            "sh", "-c", f"du -sk {WORKDIR} 2>/dev/null | cut -f1",
            timeout=30,
        )
        try:
            return round(int(done.stdout.strip() or 0) / (1024 * 1024), 2)
        except ValueError:
            return 0.0

    # -- Abbau ------------------------------------------------------------
    def touch(self) -> None:
        """Setzt die Uhr zurueck: erst zwanzig Minuten Ruhe raeumen auf."""
        with self._lock:
            self._touch_locked()

    def _touch_locked(self) -> None:
        self.last_used = time.time()
        if self._timer is not None:
            self._timer.cancel()
        if not self._name:
            self._timer = None
            return
        self._timer = threading.Timer(self.idle_seconds, self._idle_out)
        self._timer.daemon = True
        self._timer.start()

    def _idle_out(self) -> None:
        self.stop("seit 20 Minuten unbenutzt")

    def stop(self, reason: str = "aufgeraeumt") -> None:
        """Loescht Behaelter und Datentraeger -- ohne Rueckstand."""
        with self._lock:
            if not self._name and not self._volume:
                return
            self._destroy_locked(reason)

    def _destroy_locked(self, reason: str) -> None:
        runtime = self.runtime
        name, volume = self._name, self._volume
        self._name, self._volume = "", ""
        if self._timer is not None:
            self._timer.cancel()
            self._timer = None
        if runtime is None:
            return
        with contextlib.suppress(OSError, subprocess.SubprocessError):
            if name:
                _runs(runtime.binary, "rm", "--force", "--volumes", name, timeout=60)
        with contextlib.suppress(OSError, subprocess.SubprocessError):
            if volume:
                _runs(runtime.binary, "volume", "rm", "--force", volume, timeout=60)
        if name:
            self._emit("vm_stop", reason=reason)

    def status(self) -> dict[str, Any]:
        """Kurzer Zustandsbericht fuer Anzeige und Werkzeug."""
        if not self.alive:
            return {"running": False}
        ruhe = max(0, int(self.idle_seconds - (time.time() - self.last_used)))
        return {
            "running": True,
            "user_mode": self.user_mode,
            "addons": sorted(ziel.rsplit("/", 1)[-1] for ziel in self.addon_mounts.values()),
            "runtime": self.runtime.label if self.runtime else "",
            "image": self.image,
            "cpus": self.cpus,
            "memory_mb": self.memory_mb,
            "disk_gb": self.disk_gb,
            "idle_left_seconds": ruhe,
        }


def sweep(runtime: Runtime | None = None) -> int:
    """Raeumt vergessene Werkstaetten weg -- etwa nach einem Absturz.

    Erkannt werden sie an ihrer Beschriftung. Beim Start des Servers einmal
    aufgerufen, bleibt von einem harten Abbruch nichts liegen.

    Returns:
        Wie viele Behaelter entfernt wurden.
    """
    runtime = runtime or find_runtime()
    if runtime is None:
        return 0
    found = _runs(
        runtime.binary, "ps", "--all", "--quiet", "--filter", "label=aquaticy-werkstatt=1",
        timeout=30,
    )
    ids = [line.strip() for line in found.stdout.splitlines() if line.strip()]
    for container in ids:
        with contextlib.suppress(OSError, subprocess.SubprocessError):
            _runs(runtime.binary, "rm", "--force", "--volumes", container, timeout=60)
    volumes = _runs(
        runtime.binary, "volume", "ls", "--quiet", timeout=30
    )
    for volume in volumes.stdout.splitlines():
        volume = volume.strip()
        if volume.startswith("aquaticy-werkstatt-"):
            with contextlib.suppress(OSError, subprocess.SubprocessError):
                _runs(runtime.binary, "volume", "rm", "--force", volume, timeout=60)
    return len(ids)


#: Eine Werkstatt je Kontoprofil. So koennen mehrere Nutzer gleichzeitig
#: arbeiten, ohne Dateien, Prozesse oder Ereignisse miteinander zu teilen.
_shared: dict[str, Sandbox] = {}
_shared_lock = threading.Lock()
_shared_registered = False


#: Kein Empfaenger uebergeben ist etwas anderes als "ab jetzt niemand".
_KEEP = object()


def shared(settings: Any = None, on_event: Any = _KEEP) -> Sandbox:
    """Die Werkstatt des aktuellen Kontoprofils.

    Wer keinen Empfaenger uebergibt, laesst den bestehenden stehen: sonst
    haette ein Blick auf die Dateiliste mitten in einer Anfrage die
    Live-Anzeige stumm geschaltet.
    """
    global _shared_registered
    data_dir = getattr(settings, "data_dir", None)
    key = str(Path(data_dir).resolve()) if data_dir else "__default__"
    with _shared_lock:
        if not _shared_registered:
            atexit.register(_stop_shared)
            _shared_registered = True
        box = _shared.get(key)
        if box is None:
            user_mode = bool(getattr(settings, "vm_user_mode", False))
            box = Sandbox(
                image=(
                    getattr(settings, "vm_desktop_image", "") or DESKTOP_IMAGE
                    if user_mode
                    else getattr(settings, "vm_image", "") or DEFAULT_IMAGE
                ),
                user_mode=user_mode,
                browser_agent=browser_agent(settings) if user_mode else "",
                addon_mounts=_addon_mounts(settings) if user_mode else None,
                idle_minutes=int(
                    getattr(settings, "vm_idle_minutes", IDLE_MINUTES) or IDLE_MINUTES
                ),
                memory_mb=int(getattr(settings, "vm_memory_mb", MEMORY_MB) or MEMORY_MB),
                disk_gb=int(getattr(settings, "vm_disk_gb", DISK_GB) or DISK_GB),
                cpus=int(getattr(settings, "vm_cpus", CPUS) or CPUS),
            )
            _shared[key] = box
        if on_event is not _KEEP:
            box.on_event = on_event
        return box


def _addon_mounts(settings: Any) -> dict[str, str]:
    """Die Datentraeger der eingeschalteten Add-ons dieses Kontos."""
    if settings is None:
        return {}
    try:
        from aquaticy import addons

        return addons.mounts(settings)
    except Exception:
        return {}


def browser_agent(settings: Any = None) -> str:
    """Die Kennung des Browsers im User mode -- ehrlich, mit Kontaktweg.

    Der Anfang ist der uebliche Browser-Teil, damit Seiten nicht nur eine
    Fehlerseite ausliefern. Der Schluss sagt, wer hier wirklich bedient: eine
    KI, und wo man sich beschweren kann.
    """
    from aquaticy import __version__

    return (
        "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) "
        "Chrome/87.0 Safari/537.36 Falkon/3.2 "
        f"aquaticy-usermode/{__version__} (KI-gesteuert; "
        "+https://github.com/jonasenriklaumen-a11y/Aquaticy-Ai)"
    )


def _stop_shared() -> None:
    """Beim Beenden des Programms: alle Werkstaetten gehen mit."""
    for box in list(_shared.values()):
        box.stop("Programm beendet")


def forget_shared(settings: Any = None) -> None:
    """Vergisst eine Kontowerkstatt oder, ohne Konto, alle Werkstaetten."""
    data_dir = getattr(settings, "data_dir", None)
    key = str(Path(data_dir).resolve()) if data_dir else ""
    with _shared_lock:
        boxes = [_shared.pop(key)] if key and key in _shared else []
        if not key:
            boxes = list(_shared.values())
            _shared.clear()
        for box in boxes:
            box.stop("neu aufgebaut")
