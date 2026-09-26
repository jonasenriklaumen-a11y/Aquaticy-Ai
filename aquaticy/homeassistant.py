"""Home Assistant anbinden -- ueber die REST-Schnittstelle, ohne Zusatzpaket.

Home Assistant bringt eine schlichte REST-Schnittstelle mit, die alles kann,
was aquaticy braucht: Zustaende lesen und Dienste aufrufen. Angemeldet wird sich
mit einem langlebigen Zugriffstoken, das man sich im eigenen Profil anlegt.

Zwei Vorsichtsmassnahmen sind eingebaut:

* **Lesen ist frei, Schalten nicht.** Ohne `AQUATICY_HA_CONTROL=true` beantwortet
  aquaticy Fragen ueber das Haus, aber schaltet nichts.
* **Empfindliches immer mit Rueckfrage.** Schloesser, Alarmanlagen, Tore und
  Heizungen bleiben auch mit erlaubtem Schalten bestaetigungspflichtig. Ein
  falsch verstandener Satz soll nicht die Haustuer aufschliessen.
"""

from __future__ import annotations

import re
import time
from dataclasses import dataclass
from typing import Any

import httpx

#: Uebliche Adressen, unter denen eine Instanz im Heimnetz zu finden ist.
COMMON_URLS: tuple[str, ...] = (
    "http://homeassistant.local:8123",
    "http://homeassistant:8123",
    "http://hassio.local:8123",
    "http://localhost:8123",
)

#: Der Port, auf dem Home Assistant lauscht.
HA_PORT = 8123

#: Bereiche, die auch bei erlaubtem Schalten eine ausdrueckliche Bestaetigung
#: brauchen. Licht wieder auszuschalten ist harmlos; eine Tuer aufzuschliessen,
#: eine Alarmanlage scharfzustellen oder das Garagentor zu oeffnen nicht.
PROTECTED_DOMAINS: frozenset[str] = frozenset(
    {"lock", "alarm_control_panel", "cover", "water_heater", "climate", "vacuum",
     # Skripte, Szenen und Knoepfe tun, was in ihnen steht -- und darin kann
     # "Haustuer aufschliessen" stehen. Seit 9.5.16 fragen sie deshalb
     # genauso nach wie das Schloss selbst.
     "script", "scene", "button"}
)

#: So sehen Bereich und Dienst aus: Kleinbuchstaben, Ziffern, Unterstrich.
#: Alles andere (``../lock/unlock``, ``%2e%2e``, ``/``) wuerde aus
#: ``services/light/<dienst>`` einen anderen Pfad machen -- bis 9.5.15 wurde
#: so aus "Licht" ein Tuerschloss, ohne Rueckfrage (seit 9.5.16 zu).
NAME_RE = re.compile(r"^[a-z0-9_]{1,64}$")

#: Eine Entitaet: ``bereich.name``.
ENTITY_RE = re.compile(r"^[a-z0-9_]{1,64}\.[a-z0-9_]{1,128}$")

#: Womit Home Assistant ausser ``entity_id`` noch Ziele annimmt. Ein Bereich
#: oder Geraet schaltet alles darin -- auch das Schloss.
TARGET_KEYS: frozenset[str] = frozenset({"area_id", "device_id", "floor_id", "label_id",
                                         "target"})

#: Bereiche, in denen aquaticy ueberhaupt schalten darf. Alles andere lehnt er
#: ab -- lieber eine Absage als ein unerwarteter Eingriff.
ALLOWED_DOMAINS: frozenset[str] = frozenset(
    {
        "light",
        "switch",
        "fan",
        "media_player",
        "scene",
        "script",
        "input_boolean",
        "climate",
        "cover",
        "lock",
        "alarm_control_panel",
        "vacuum",
        "humidifier",
        "water_heater",
        "button",
    }
)

#: So lange gilt eine einmal geholte Zustandsliste als frisch. Der Agent
#: fragt in einer Runde gern dreimal -- erst die Uebersicht, dann einen
#: Bereich, dann gezielt. Bei tausend Entitaeten waeren das drei volle
#: Uebertragungen fuer denselben Augenblick. Laenger halten wollen wir sie
#: nicht: ein Licht kann in zehn Sekunden ausgehen.
STATES_TTL = 10.0

#: (Adresse, Token) -> (Zeitpunkt, Zustaende)
_states_cache: dict[tuple[str, str], tuple[float, list[Entity]]] = {}

#: So viele Entitaeten gibt aquaticy hoechstens an das Modell weiter. Eine
#: gewachsene Installation hat schnell tausend -- die wuerden das
#: Kontextfenster sprengen, bevor die eigentliche Frage drankommt.
MAX_ENTITIES = 60


class HomeAssistantError(RuntimeError):
    """Etwas an der Verbindung oder der Anfrage stimmt nicht."""


@dataclass
class Entity:
    """Ein Geraet oder Wert aus Home Assistant."""

    entity_id: str
    state: str
    name: str = ""
    unit: str = ""
    changed: str = ""

    @property
    def domain(self) -> str:
        return self.entity_id.split(".", 1)[0]

    def as_dict(self) -> dict[str, str]:
        out = {"entity_id": self.entity_id, "name": self.name, "state": self.state}
        if self.unit:
            out["unit"] = self.unit
        if self.changed:
            out["changed"] = self.changed
        return out

    def __str__(self) -> str:
        value = f"{self.state} {self.unit}".strip()
        return f"{self.name or self.entity_id}: {value}"


def normalize_url(url: str) -> str:
    """Macht aus "192.168.1.5" oder "ha.local" eine benutzbare Adresse."""
    url = (url or "").strip().rstrip("/")
    if not url:
        return ""
    if "://" not in url:
        url = f"http://{url}"
    # Ohne Portangabe den Standardport ergaenzen -- niemand tippt ihn gern mit.
    from urllib.parse import urlparse

    parsed = urlparse(url)
    if parsed.port is None and parsed.scheme == "http":
        url = f"{url}:{HA_PORT}"
    return url


class HomeAssistant:
    """Schmaler Client fuer die REST-Schnittstelle."""

    def __init__(self, url: str, token: str, timeout: float = 10.0) -> None:
        self.url = normalize_url(url)
        self.token = (token or "").strip()
        self.timeout = timeout

    @property
    def configured(self) -> bool:
        return bool(self.url and self.token)

    def _request(self, method: str, path: str, payload: Any = None) -> Any:
        if not self.configured:
            raise HomeAssistantError(
                "Home Assistant ist nicht eingerichtet. `aquaticy connect-ha` verbindet dich."
            )
        try:
            response = httpx.request(
                method,
                f"{self.url}/api/{path.lstrip('/')}",
                headers={"Authorization": f"Bearer {self.token}"},
                json=payload,
                timeout=self.timeout,
            )
        except httpx.HTTPError as exc:
            raise HomeAssistantError(f"{self.url} nicht erreichbar: {exc}") from exc
        if response.status_code == 401:
            raise HomeAssistantError(
                "Das Zugriffstoken wird abgelehnt. Ein neues gibt es in Home Assistant "
                "unter Profil - Sicherheit - Langlebige Zugriffstokens."
            )
        if response.status_code == 404:
            raise HomeAssistantError(f"Unbekannter Aufruf: {path}")
        if response.status_code >= 400:
            raise HomeAssistantError(f"Home Assistant antwortet mit {response.status_code}.")
        try:
            return response.json()
        except ValueError:
            return response.text

    # -- Lesen ------------------------------------------------------------
    def ping(self) -> str:
        """Prueft die Verbindung und gibt die Version zurueck."""
        self._request("GET", "/")
        config = self._request("GET", "config")
        if isinstance(config, dict):
            name = str(config.get("location_name") or "")
            version = str(config.get("version") or "")
            return f"{name} {version}".strip() or "verbunden"
        return "verbunden"

    def states(self, *, fresh: bool = False) -> list[Entity]:
        """Alle Entitaeten mit ihrem aktuellen Zustand.

        Kurz zwischengespeichert -- siehe :data:`STATES_TTL`.
        """
        key = (self.url, self.token)
        if not fresh:
            cached = _states_cache.get(key)
            if cached and time.monotonic() - cached[0] < STATES_TTL:
                return cached[1]
        raw = self._request("GET", "states")
        if not isinstance(raw, list):
            raise HomeAssistantError("Unerwartete Antwort auf die Zustandsabfrage.")
        entities = [_entity(item) for item in raw if isinstance(item, dict)]
        _states_cache[key] = (time.monotonic(), entities)
        return entities

    def find(self, search: str = "", domain: str = "", limit: int = MAX_ENTITIES) -> list[Entity]:
        """Sucht Entitaeten nach Name, Kennung oder Bereich."""
        needle = (search or "").strip().lower()
        wanted = (domain or "").strip().lower()
        found = []
        for entity in self.states():
            if wanted and entity.domain != wanted:
                continue
            if needle and needle not in f"{entity.entity_id} {entity.name}".lower():
                continue
            found.append(entity)
        return found[: max(1, limit)]

    def domains(self) -> dict[str, int]:
        """Welche Bereiche gibt es, und wie viele Entitaeten je Bereich?"""
        counts: dict[str, int] = {}
        for entity in self.states():
            counts[entity.domain] = counts.get(entity.domain, 0) + 1
        return dict(sorted(counts.items(), key=lambda item: (-item[1], item[0])))

    # -- Schalten ---------------------------------------------------------
    def call(self, domain: str, service: str, entity_id: str = "", data: Any = None) -> list[Any]:
        """Ruft einen Dienst auf, etwa `light.turn_on`.

        Raises:
            HomeAssistantError: Wenn Bereich, Dienst oder Ziel nicht zusammenpassen
                (siehe :func:`check_call`).
        """
        payload = check_call(domain, service, entity_id, data)
        result = self._request("POST", f"services/{domain}/{service}", payload)
        # Nach dem Schalten stimmt der zwischengespeicherte Zustand nicht mehr.
        _states_cache.pop((self.url, self.token), None)
        return result if isinstance(result, list) else []


def _entities(value: Any) -> list[str]:
    if isinstance(value, str):
        return [teil.strip() for teil in value.split(",") if teil.strip()]
    if isinstance(value, list | tuple):
        return [str(teil).strip() for teil in value]
    return [str(value)]


def check_call(domain: str, service: str, entity_id: str = "", data: Any = None) -> dict[str, Any]:
    """Prueft einen Dienstaufruf und gibt die Nutzlast zurueck.

    Bereich und Dienst muessen reine Namen sein, und jedes Ziel muss im
    selben Bereich liegen: ``light.turn_on`` schaltet Lichter, nie ein
    Schloss. Ziele ueber Raum, Geraet oder Etikett gibt es nicht -- sie
    wuerden alles darin schalten.

    Raises:
        HomeAssistantError: Bei allem, was nicht genau so aussieht.
    """
    if not NAME_RE.match(domain or "") or not NAME_RE.match(service or ""):
        raise HomeAssistantError(
            "Bereich und Dienst duerfen nur aus Kleinbuchstaben, Ziffern und _ bestehen.")
    payload: dict[str, Any] = dict(data) if isinstance(data, dict) else {}
    verboten = sorted(TARGET_KEYS & set(payload))
    if verboten:
        raise HomeAssistantError(
            f"Ziele ueber {', '.join(verboten)} gibt es nicht -- bitte einzelne Entitaeten nennen.")
    ziele = _entities(entity_id) if entity_id else []
    if "entity_id" in payload:
        ziele += _entities(payload["entity_id"])
    for ziel in ziele:
        if not ENTITY_RE.match(ziel):
            raise HomeAssistantError(f"'{ziel[:80]}' ist keine Entitaet (bereich.name).")
        if ziel.split(".", 1)[0] != domain:
            raise HomeAssistantError(
                f"'{ziel}' liegt nicht im Bereich '{domain}' -- {domain}.{service} "
                "schaltet nur Entitaeten aus diesem Bereich.")
    if ziele:
        payload["entity_id"] = ziele[0] if len(ziele) == 1 else ziele
    return payload


def _entity(raw: dict[str, Any]) -> Entity:
    attributes = raw.get("attributes") or {}
    return Entity(
        entity_id=str(raw.get("entity_id") or ""),
        state=str(raw.get("state") or ""),
        name=str(attributes.get("friendly_name") or ""),
        unit=str(attributes.get("unit_of_measurement") or ""),
        changed=str(raw.get("last_changed") or "")[:19].replace("T", " "),
    )


def from_settings(settings: Any) -> HomeAssistant:
    """Baut den Client aus den Einstellungen."""
    return HomeAssistant(getattr(settings, "ha_url", ""), getattr(settings, "ha_token", ""))


def discover(subnet: str = "", timeout: float = 1.0) -> list[str]:
    """Sucht erreichbare Instanzen -- erst die ueblichen Namen, dann das Netz.

    Der Namensweg kostet Millisekunden und trifft in den meisten Haushalten;
    der Netzdurchlauf ist der Rueckfall fuer alle anderen.
    """
    found: list[str] = []
    for url in COMMON_URLS:
        host = url.split("://", 1)[1].split(":")[0]
        try:
            import socket

            address = socket.gethostbyname(host)
        except OSError:
            continue
        from aquaticy.lan import port_open

        if port_open(address, HA_PORT, timeout=timeout):
            found.append(url)

    from aquaticy.lan import NotPrivate, find_port

    try:
        for address in find_port(HA_PORT, subnet):
            candidate = f"http://{address}:{HA_PORT}"
            if candidate not in found:
                found.append(candidate)
    except (NotPrivate, ValueError):
        pass  # Kein erkennbares Netz -- die Namensfunde bleiben trotzdem gueltig
    return found
