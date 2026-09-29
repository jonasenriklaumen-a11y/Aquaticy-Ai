"""Geraete, Browser und Anhaltspunkte fuer Mehrfachkonten (seit 9.5.31).

Bis 9.5.30 galt: eine IP-Adresse, ein Konto. Das sperrte zwei Menschen im
selben Haushalt aus -- hinter einem Router teilen sich alle dieselbe Adresse.
Jetzt zaehlen **Anhaltspunkte**, und erst viele oder gewichtige sperren die
Kontoerstellung:

========================================  ========
Anhaltspunkt                              Punkte
========================================  ========
dieselbe Geraete-Kennung (Cookie)          3
gleiche Hardware UND gleicher Browser      1,5
gleiche Hardware                           1
gleicher Browser                           0,5
dieselbe IP-Adresse                        1
sehr aehnliche E-Mail-Adresse              1
========================================  ========

Ab :data:`BLOCK_POINTS` (3) wird kein neues Konto angelegt, ab
:data:`SUSPICIOUS_POINTS` (1,5) steht ein Hinweis im Terminal. Beispiele:
selbe Adresse und selber Browser (1,5) -- geht durch, zwei Menschen im
selben Haushalt mit demselben Browser sind normal. Dasselbe Handy (die
Geraete-Kennung aus dem Cookie, 3) -- gesperrt. Selbe Adresse, aehnliche
E-Mail und gleiche Hardware (1 + 1 + 1) -- gesperrt.

**Was gespeichert wird.** Je Konto und Geraet: eine zufaellige Geraete-
Kennung (nur als Hash), eine kurze lesbare Zusammenfassung von Hardware und
Browser ("Windows · 8 Kerne · 8 GB · 1920x1080 · NVIDIA …", "Chrome 126,
de-DE") fuer `aquaticy list`, und je ein Hash davon zum Vergleichen. Kein
Canvas- oder Audio-Fingerabdruck, keine Seitenverlaeufe. Das steht so im
Datenschutzhinweis.
"""

from __future__ import annotations

import difflib
import hashlib
import re
import secrets
from dataclasses import dataclass
from typing import Any

#: Ab so vielen Punkten wird kein weiteres Konto angelegt.
BLOCK_POINTS = 3.0
#: Ab so vielen Punkten steht ein Hinweis im Terminal.
SUSPICIOUS_POINTS = 1.5

#: Das Cookie mit der Geraete-Kennung. Zufaellig, zwei Jahre gueltig.
DEVICE_COOKIE = "aquaticy_device"
DEVICE_COOKIE_AGE = 2 * 365 * 86400

POINTS_COOKIE = 3.0
POINTS_HARDWARE_AND_BROWSER = 1.5
POINTS_HARDWARE = 1.0
POINTS_BROWSER = 0.5
POINTS_IP = 1.0
POINTS_EMAIL = 1.0

_TOKEN_RE = re.compile(r"^[A-Za-z0-9_-]{16,64}$")


def new_device_token() -> str:
    """Eine neue, zufaellige Geraete-Kennung fuer das Cookie."""
    return secrets.token_urlsafe(24)


def token_hash(token: str) -> str:
    """Die Geraete-Kennung als Hash -- im Klartext wird sie nie gespeichert."""
    token = str(token or "").strip()
    if not _TOKEN_RE.fullmatch(token):
        return ""
    return hashlib.sha256(("aquaticy-device\x1f" + token).encode()).hexdigest()


def _text(value: Any, laenge: int) -> str:
    """Nur druckbare Zeichen, gekuerzt -- was der Browser schickt, ist ein Vorschlag."""
    roh = "".join(z for z in str(value if value is not None else "") if z.isprintable())
    return " ".join(roh.split())[:laenge]


def _zahl(value: Any, hoechstens: float) -> float:
    try:
        zahl = float(value)
    except (TypeError, ValueError):
        return 0.0
    if zahl != zahl or zahl < 0:  # NaN oder negativ
        return 0.0
    return min(zahl, hoechstens)


# ---------------------------------------------------------------------------
# Browser aus der Kennung (User-Agent) -- serverseitig, nicht vom Skript
# ---------------------------------------------------------------------------
_BROWSER = (
    ("Edge", re.compile(r"Edg(?:e|A|iOS)?/(\d+)")),
    ("Opera", re.compile(r"(?:OPR|Opera)/(\d+)")),
    ("Samsung Internet", re.compile(r"SamsungBrowser/(\d+)")),
    ("Firefox", re.compile(r"(?:Firefox|FxiOS)/(\d+)")),
    ("Chrome", re.compile(r"(?:Chrome|CriOS)/(\d+)")),
    ("Safari", re.compile(r"Version/(\d+)[.\d]* .*Safari/")),
)
_SYSTEM = (
    ("iPhone", re.compile(r"iPhone")),
    ("iPad", re.compile(r"iPad")),
    ("Android", re.compile(r"Android")),
    ("Windows", re.compile(r"Windows")),
    ("macOS", re.compile(r"Macintosh|Mac OS X")),
    ("ChromeOS", re.compile(r"CrOS")),
    ("Linux", re.compile(r"Linux")),
)


def browser_name(user_agent: str) -> str:
    """ "Chrome 126" aus dem User-Agent -- oder "unbekannt"."""
    ua = str(user_agent or "")
    for name, muster in _BROWSER:
        treffer = muster.search(ua)
        if treffer:
            return f"{name} {treffer.group(1)}"
    return _text(ua, 40) or "unbekannt"


def system_name(user_agent: str, platform: str = "") -> str:
    """Betriebssystem aus User-Agent (oder der Angabe des Browsers)."""
    for name, muster in _SYSTEM:
        if muster.search(str(user_agent or "")):
            return name
    return _text(platform, 30)


@dataclass(frozen=True, slots=True)
class DeviceInfo:
    """Was ueber das Geraet bekannt ist -- bereinigt."""

    cookie_hash: str = ""
    hardware: str = ""
    browser: str = ""
    hardware_hash: str = ""
    browser_hash: str = ""


def clean_device(raw: Any, *, user_agent: str = "", accept_language: str = "",
                 cookie: str = "") -> DeviceInfo:
    """Macht aus den Angaben des Browsers eine :class:`DeviceInfo`.

    Alles wird gekuerzt und auf Zahlen/Text geprueft. Der Browser selbst kommt
    aus dem User-Agent der Anfrage, nicht aus dem Skript.
    """
    daten = raw if isinstance(raw, dict) else {}
    system = system_name(user_agent, str(daten.get("platform") or ""))
    kerne = int(_zahl(daten.get("cores"), 512))
    speicher = _zahl(daten.get("memory"), 1024)
    bildschirm = _text(daten.get("screen"), 20)
    if not re.fullmatch(r"\d{2,5}x\d{2,5}", bildschirm):
        bildschirm = ""
    pixel = round(_zahl(daten.get("dpr"), 10), 2)
    beruehrung = int(_zahl(daten.get("touch"), 64))
    zone = _text(daten.get("tz"), 40)
    gpu = _text(daten.get("gpu"), 120)
    sprache = _text(daten.get("lang") or accept_language.split(";")[0], 40)

    teile = [system or "unbekanntes System"]
    if kerne:
        teile.append(f"{kerne} Kerne")
    if speicher:
        teile.append(f"{speicher:g} GB")
    if bildschirm:
        teile.append(bildschirm + (f"@{pixel:g}x" if pixel and pixel != 1 else ""))
    if beruehrung:
        teile.append("Touch")
    if gpu:
        teile.append(gpu)
    hardware = " · ".join(teile)
    browser = browser_name(user_agent) + (f", {sprache}" if sprache else "")

    # Vergleichswerte: nur, wenn es wirklich etwas zu vergleichen gibt. Ohne
    # jede Hardware-Angabe (Skript aus, altes Formular, Tests) bleibt der Hash
    # leer -- leere Hashes treffen nie.
    hat_hardware = bool(kerne or speicher or bildschirm or gpu)
    hardware_hash = hashlib.sha256(
        "\x1f".join((system, str(kerne), f"{speicher:g}", bildschirm, f"{pixel:g}",
                     str(beruehrung), zone, gpu)).encode()
    ).hexdigest() if hat_hardware else ""
    browser_hash = hashlib.sha256(
        "\x1f".join((str(user_agent or "")[:400], sprache)).encode()
    ).hexdigest() if user_agent else ""
    return DeviceInfo(
        cookie_hash=token_hash(cookie),
        hardware=hardware[:200],
        browser=browser[:80],
        hardware_hash=hardware_hash,
        browser_hash=browser_hash,
    )


# ---------------------------------------------------------------------------
# E-Mail-Adressen, die sich sehr aehneln
# ---------------------------------------------------------------------------
def _kern(email: str) -> str:
    """ "max.muster+test7@gmail.com" -> "maxmuster": ohne Punkte, Zusatz, Ziffern."""
    lokal = str(email or "").strip().lower().split("@", 1)[0]
    lokal = lokal.split("+", 1)[0]
    return re.sub(r"[^a-zäöüß]", "", lokal)


def emails_similar(a: str, b: str) -> bool:
    """Sehen zwei E-Mail-Adressen aus wie Varianten derselben Person?"""
    ka, kb = _kern(a), _kern(b)
    if len(ka) < 4 or len(kb) < 4:
        return False
    if ka == kb:
        return True
    return difflib.SequenceMatcher(None, ka, kb).ratio() >= 0.88


# ---------------------------------------------------------------------------
# Punkte gegen ein vorhandenes Konto
# ---------------------------------------------------------------------------
@dataclass(frozen=True, slots=True)
class Assessment:
    """Das Ergebnis der Pruefung bei einer Registrierung."""

    points: float = 0.0
    reasons: tuple[str, ...] = ()
    #: Das Konto, dem die neue Registrierung am meisten aehnelt.
    closest: str = ""

    @property
    def blocked(self) -> bool:
        return self.points >= BLOCK_POINTS

    @property
    def suspicious(self) -> bool:
        return self.points >= SUSPICIOUS_POINTS


def score(
    *, email: str, ip: str, device: DeviceInfo, other_email: str, other_ips: set[str],
    other_devices: list[tuple[str, str, str]],
) -> tuple[float, list[str]]:
    """Punkte der neuen Registrierung gegen EIN vorhandenes Konto.

    *other_devices*: (cookie_hash, hardware_hash, browser_hash) je bekanntem
    Geraet des Kontos.
    """
    punkte = 0.0
    gruende: list[str] = []
    geraet = 0.0
    geraet_grund = ""
    for keks, hardware, browser in other_devices:
        if device.cookie_hash and keks and device.cookie_hash == keks:
            wert, grund = POINTS_COOKIE, "dasselbe Gerät (Geräte-Kennung)"
        elif (device.hardware_hash and device.hardware_hash == hardware
              and device.browser_hash and device.browser_hash == browser):
            wert, grund = POINTS_HARDWARE_AND_BROWSER, "gleiche Hardware und gleicher Browser"
        elif device.hardware_hash and device.hardware_hash == hardware:
            wert, grund = POINTS_HARDWARE, "gleiche Hardware"
        elif device.browser_hash and device.browser_hash == browser:
            wert, grund = POINTS_BROWSER, "gleicher Browser"
        else:
            continue
        if wert > geraet:
            geraet, geraet_grund = wert, grund
    if geraet:
        punkte += geraet
        gruende.append(geraet_grund)
    if ip and ip in other_ips:
        punkte += POINTS_IP
        gruende.append("dieselbe IP-Adresse")
    if emails_similar(email, other_email):
        punkte += POINTS_EMAIL
        gruende.append("sehr ähnliche E-Mail-Adresse")
    return punkte, gruende
