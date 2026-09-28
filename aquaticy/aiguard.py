"""Ai-guard: erkennt, wenn jemand Aquaticy fuer Angriffe missbrauchen will (9.5.16 Lion).

Aquaticy hilft bei Recherche, Schreiben und -- fuer Fachleute -- bei
Verteidigung: Schadcode verstehen, eine Lücke absichern, einen Angriff
erkennen. Was es **nicht** tut, ist jemandem beim Angreifen helfen: eine
Schaddatei bauen, eine Anleitung für einen DDoS-Angriff schreiben, in fremde
Systeme einbrechen, Zugangsdaten stehlen. Der Rechtsrahmen
(:mod:`aquaticy.guardrails`) lehnt das schon je Anfrage ab. Ai-guard sieht
eine Stufe darueber: **über mehrere Chats hinweg** -- versucht dieselbe Person
das immer wieder?

**Wie es entscheidet.** Jede Nachricht eines angemeldeten Kontos wird
eingeschaetzt (dasselbe schnelle Modell wie der Rechtsprüfer). Ist sie ein
Anhaltspunkt -- eine klare Bitte um Schadcode, eine Angriffsanleitung, einen
Einbruch --, wird sie am Konto vermerkt. Ein Anhaltspunkt allein sperrt
niemanden: ein Fachbegriff, eine Frage aus Neugier, ein missverstandener Satz
soll kein Bann sein. Erst **zwei** Anhaltspunkte -- zwei getrennte Nachrichten
mit klarer Missbrauchsabsicht -- sperren das Konto. Auch eine Ablehnung durch
den Rechtsrahmen (Grundgesetz, BGB) zählt als Anhaltspunkt.

**Was gespeichert wird.** Nur der Anlass: Zeitpunkt, Art (etwa "Schadcode"),
ein kurzer Vermerk und der Chat. Nie der ganze Nachrichtentext. Die Daten
dienen allein dieser Prüfung -- das steht so in den Nutzungsbedingungen und
klein unten in den Einstellungen.

**Wer sperrt und entsperrt.** Automatisch bei zwei Anhaltspunkten. Von Hand
über das Terminal:

    aquaticy ban "name"        # Konto sperren
    aquaticy ban 203.0.113.7   # Adresse sperren
    aquaticy unban "name"      # wieder freigeben

Aus dem Chat lässt sich daran nichts ändern -- wie bei allen Schutzgrenzen.
"""

from __future__ import annotations

import hashlib
import ipaddress
import json
import logging
import math
import re
import sqlite3
import threading
import time
from collections import OrderedDict
from collections.abc import Callable
from contextlib import closing, contextmanager
from dataclasses import dataclass
from pathlib import Path
from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    from collections.abc import Iterator

    from aquaticy.config import Settings

#: So viele Anhaltspunkte sperren ein Konto. Einer ist ein Verdacht -- der
#: darf ein Fachwort oder eine missverstandene Frage sein; zwei ist ein Muster.
NEEDED = 2

LOG = logging.getLogger("aquaticy.aiguard")

#: So lange gilt ein einmal gefaelltes Urteil ueber einen Text (Stunden), damit
#: dasselbe nicht zweimal ein Modell kostet.
DECISION_TTL = 3600.0

#: Kürzer als das schaut sich Ai-guard gar nicht erst an -- ein Gruss ist kein
#: Angriff, und jede Prüfung kostet.
MIN_LENGTH = 12

#: Version der Regeln. Ändert sie sich, gelten alte Urteile nicht mehr.
GUARD_VERSION = "2026-09-26"


@dataclass(frozen=True, slots=True)
class Flag:
    """Ein Anhaltspunkt -- der Anlass, nicht der Text."""

    at: float
    kind: str
    detail: str
    chat: str


@dataclass(frozen=True, slots=True)
class Ban:
    """Eine Sperre -- für ein Konto oder eine Adresse."""

    subject: str
    at: float
    reason: str
    by: str
    #: Wann die Sperre endet (Unix-Zeit). 0 heisst: fuer immer (seit 9.5.24).
    until: float = 0.0

    def active(self, now: float | None = None) -> bool:
        """Gilt die Sperre gerade noch?"""
        return self.until <= 0 or self.until > (time.time() if now is None else now)

    def remaining_text(self, now: float | None = None) -> str:
        """Wie lange noch -- fuer den Hinweis an den Nutzer."""
        if self.until <= 0:
            return "dauerhaft"
        rest = self.until - (time.time() if now is None else now)
        if rest <= 0:
            return "abgelaufen"
        if rest < 3600:
            return f"noch {max(1, math.ceil(rest / 60))} Min."
        # Auf die volle Stunde aufgerundet: direkt nach einem 7-Tage-Bann soll
        # "noch 7 Tag(e)" stehen, nicht "noch 6 Tag(e), 23 Std.".
        stunden_gesamt = math.ceil(rest / 3600)
        tage, stunden = divmod(stunden_gesamt, 24)
        if tage >= 1:
            return f"noch {tage} Tag(e)" + (f", {stunden} Std." if stunden else "")
        return f"noch {stunden} Std."


# ---------------------------------------------------------------------------
# Schweregrad -> Massnahme (seit 9.5.24)
# ---------------------------------------------------------------------------
#: Die Arten von Fehlverhalten, die Ai-guard unterscheidet. Alles andere ist
#: harmlos und fuehrt zu nichts.
#:  * ``beleidigung``  -- Beschimpfungen gegen Aquaticy oder andere.
#:  * ``jailbreak``    -- wiederholte Versuche, die Regeln auszuhebeln oder
#:                        Aquaticy etwas sagen zu lassen, was es nicht soll.
#:  * ``malware``      -- Schadsoftware bauen, installieren oder ausfuehren.
#:  * ``angriff``      -- andere Angriffshilfe (DDoS, Einbruch, Datendiebstahl,
#:                        Waffen).
#:  * ``rechtsbruch``  -- schwerer Verstoss gegen Grundgesetz/BGB, der einer
#:                        realen Person oder Sache wirklich schadet (Diebstahl,
#:                        Betrug). NICHT: Bagatellen wie "bei Rot gelaufen".
KATEGORIEN = ("beleidigung", "jailbreak", "malware", "angriff", "rechtsbruch")

#: Arten, die erst bei Wiederholung (``NEEDED`` Anhaltspunkte) sperren -- ein
#: einzelner Anhaltspunkt kann ein Missverstaendnis sein.
_MUSTER_ARTEN = frozenset({"jailbreak", "angriff", "rechtsbruch"})

#: Arten, die sofort greifen -- schon ein klarer Fall reicht.
_SOFORT_ARTEN = frozenset({"beleidigung", "malware"})

_SYNONYME = {
    "insult": "beleidigung", "beleidigung": "beleidigung", "beschimpfung": "beleidigung",
    "hate": "beleidigung", "harassment": "beleidigung",
    "jailbreak": "jailbreak", "prompt-injection": "jailbreak", "manipulation": "jailbreak",
    "malware": "malware", "schadsoftware": "malware", "virus": "malware",
    "schadcode": "malware", "schadprogramm": "malware",
    "ransomware": "malware", "trojaner": "malware",
    "angriff": "angriff", "attack": "angriff", "ddos": "angriff", "exploit": "angriff",
    "phishing": "angriff", "einbruch": "angriff", "waffen": "angriff",
    "rechtsbruch": "rechtsbruch", "diebstahl": "rechtsbruch", "betrug": "rechtsbruch",
    "straftat": "rechtsbruch",
}


def normalize_category(art: str) -> str:
    """Ordnet die Beschreibung des Modells einer bekannten Art zu -- oder ""."""
    wort = str(art or "").strip().lower()
    if wort in _SYNONYME:
        return _SYNONYME[wort]
    for teil in re.split(r"[^a-zäöüß]+", wort):
        if teil in _SYNONYME:
            return _SYNONYME[teil]
    return ""


@dataclass(frozen=True, slots=True)
class Action:
    """Was Ai-guard mit einem Vorfall tut."""

    #: "none" (nur vermerken), "chat" (nur diesen Chat sperren), "ban" (Konto).
    kind: str
    #: Dauer eines Banns in Tagen. 0 = fuer immer. Bei "chat"/"none" ohne Belang.
    days: int = 0
    category: str = ""
    reason: str = ""

    @property
    def until(self) -> float:
        """Endzeit fuer einen zeitlich begrenzten Bann -- 0 bei "fuer immer"."""
        return time.time() + self.days * 86400 if self.days > 0 else 0.0


def decide(category: str, severity: int, prior: int = 0) -> Action:
    """Entscheidet die Massnahme aus Art, Schwere (1-4) und bisherigen Mustern.

    Args:
        category: eine der :data:`KATEGORIEN` (oder etwas Unbekanntes -> nichts).
        severity: 1 (leicht) bis 4 (sehr schwer). 0 oder weniger -> nichts.
        prior: wie viele Muster-Anhaltspunkte das Konto schon hat (fuer die
            Arten, die erst bei Wiederholung sperren).

    Returns:
        Die :class:`Action`. Die Dauer waechst mit der Schwere:
        Beleidigung leicht -> Chatsperre, sonst 1/7 Tage bis fuer immer;
        Malware haerter -> 4/14/30 Tage bis fuer immer; Angriff, Rechtsbruch
        und Jailbreak erst ab dem zweiten Anhaltspunkt (1/7 Tage bis immer).
    """
    art = normalize_category(category)
    stufe = max(0, min(4, int(severity or 0)))
    if not art or stufe <= 0:
        return Action("none", category=art)

    if art == "beleidigung":
        # Leicht: nur der Chat, in dem beleidigt wurde. Sonst Konto-Bann, der
        # mit der Schwere waechst -- bei einem Bann wird der Chat mitgesperrt.
        return {
            1: Action("chat", category=art, reason="unangemessene Sprache"),
            2: Action("ban", 1, art, "schwere Beleidigung"),
            3: Action("ban", 7, art, "schwere Beleidigung"),
            4: Action("ban", 0, art, "wiederholte schwere Beleidigung"),
        }[stufe]

    if art == "malware":
        # Haerter gesehen (Wunsch des Betreibers): schon ein klarer Fall sperrt,
        # 4 Tage bis fuer immer.
        return {
            1: Action("ban", 4, art, "Versuch, Schadsoftware zu erstellen"),
            2: Action("ban", 14, art, "Versuch, Schadsoftware zu erstellen"),
            3: Action("ban", 30, art, "Versuch, Schadsoftware zu bauen und auszuführen"),
            4: Action("ban", 0, art, "wiederholter Bau von Schadsoftware"),
        }[stufe]

    # angriff / rechtsbruch / jailbreak: erst das Muster (zwei Anhaltspunkte).
    if prior + 1 < NEEDED:
        return Action("none", category=art, reason="einzelner Anhaltspunkt")
    dauer = {1: 1, 2: 1, 3: 7, 4: 0}[stufe]
    grund = {"angriff": "wiederholte Angriffsversuche",
             "rechtsbruch": "wiederholte schwere Rechtsverstöße",
             "jailbreak": "wiederholte Versuche, die Schutzregeln auszuhebeln"}[art]
    return Action("ban", dauer, art, grund)


# ---------------------------------------------------------------------------
# Die Einschätzung durch das Modell
# ---------------------------------------------------------------------------
JUDGE_SCHEMA: dict[str, Any] = {
    "type": "object",
    "properties": {
        "missbrauch": {"type": "boolean"},
        "art": {"type": "string"},
        "grund": {"type": "string"},
    },
    "required": ["missbrauch"],
    "additionalProperties": False,
}


def judge_prompt(text: str, context: str = "") -> str:
    """Der Text, mit dem das Modell eine Nachricht einschätzt."""
    davor = f"\nWas vorher im Chat stand:\n{context.strip()[:1500]}\n" if context.strip() else ""
    return (
        "Du bist ein Sicherheitsfilter. Entscheide, ob die folgende Nachricht eines "
        "Nutzers Aquaticy für einen ANGRIFF missbrauchen will. Das ist der Fall bei:\n"
        "- der Bitte, Schadsoftware zu schreiben oder zu bauen (Viren, Ransomware, "
        "Trojaner, Keylogger, Stealer);\n"
        "- einer Anleitung für einen Angriff auf fremde Systeme (DDoS, Einbruch, "
        "Exploit gegen ein System, das dem Nutzer nicht gehört);\n"
        "- dem Stehlen von Zugangsdaten, Phishing, dem Umgehen von Anmeldungen;\n"
        "- Anleitungen für Waffen, Sprengstoff oder andere Mittel, um Menschen zu schaden.\n\n"
        "KEIN Missbrauch ist: Verteidigung und Bildung -- Schadcode verstehen, eine "
        "eigene Lücke absichern, einen Angriff erkennen, ein Pentest mit Auftrag, eine "
        "CTF-Aufgabe, allgemeine Sicherheitsfragen. Im Zweifel: kein Missbrauch.\n"
        f"{davor}\n"
        f"Nachricht:\n{text.strip()[:2000]}\n\n"
        'Antworte NUR mit JSON: {"missbrauch": true|false, "art": "<zwei bis vier Wörter>", '
        '"grund": "<kurz>"}'
    )


def _ask_model(prompt: str, settings: Settings) -> str:
    """Ein Aufruf beim schnellen Modell -- die einzige Stelle mit Netz."""
    import litellm

    from aquaticy import metering
    from aquaticy.pace import key_of as pace_key_of
    from aquaticy.pace import paced

    model = _fast_model(settings)
    litellm.suppress_debug_info = True
    with paced(model, pace_key_of(settings, model)):
        response = metering.completion(
            settings,
            enforce=False,
            model=model,
            messages=[{"role": "user", "content": prompt}],
            max_tokens=120,
            timeout=max(15.0, float(getattr(settings, "planner_timeout", 20)) * 2),
            response_format={
                "type": "json_schema",
                "json_schema": {"name": "aiguard", "schema": JUDGE_SCHEMA},
            },
            **settings.fast_kwargs_for(model),
        )
    return str(response.choices[0].message.content or "").strip()


def _fast_model(settings: Settings) -> str:
    from aquaticy.system import fast_model

    return fast_model(settings) or str(getattr(settings, "model", "") or "")


def parse_judgement(raw: str) -> tuple[bool, str] | None:
    """Liest die Antwort des Modells. `None` = keine klare Antwort."""
    raw = (raw or "").strip()
    start, end = raw.find("{"), raw.rfind("}")
    if start == -1 or end <= start:
        return None
    try:
        payload = json.loads(raw[start : end + 1])
    except json.JSONDecodeError:
        return None
    if not isinstance(payload, dict):
        return None
    flag = payload.get("missbrauch")
    if isinstance(flag, str) and flag.strip().lower() in ("true", "false"):
        flag = flag.strip().lower() == "true"
    if not isinstance(flag, bool):
        return None
    art = " ".join(str(payload.get("art") or "").split())[:60] or "Missbrauch"
    return flag, art


_cache: OrderedDict[str, tuple[float, tuple[bool, str] | None]] = OrderedDict()
_cache_lock = threading.Lock()


def forget_judgements() -> None:
    """Leert den Urteilsspeicher -- für Tests."""
    with _cache_lock:
        _cache.clear()


def classify(
    text: str,
    settings: Settings,
    *,
    context: str = "",
    ask: Callable[[str, Settings], str] | None = None,
) -> tuple[bool, str] | None:
    """Ist *text* ein Anhaltspunkt? Returns: (True/False, Art) -- oder None (unklar).

    Kurze Nachrichten und ein leerer Text sind nie ein Anhaltspunkt. Fällt die
    Einschätzung aus (kein Modell, kein Urteil), ist das ausdrücklich KEIN
    Anhaltspunkt: Ai-guard sperrt nur, was es sicher erkennt -- der Rechtsrahmen
    ist die Stelle, die im Zweifel ablehnt.
    """
    text = (text or "").strip()
    if len(text) < MIN_LENGTH:
        return False, ""
    from aquaticy import smalltalk

    if smalltalk.art_von(text) is not None:
        # "Wer hat dich erschaffen?" -- eine Standardantwort, kein Anlass zur Pruefung.
        return False, ""
    schluessel = hashlib.sha256(
        "\x1f".join((GUARD_VERSION, context, text)).encode("utf-8", "replace")
    ).hexdigest()
    jetzt = time.monotonic()
    with _cache_lock:
        bekannt = _cache.get(schluessel)
        if bekannt is not None and bekannt[0] > jetzt:
            _cache.move_to_end(schluessel)
            return bekannt[1]
    frage = ask or _ask_model
    try:
        roh = frage(judge_prompt(text, context), settings)
        urteil = parse_judgement(roh)
    except Exception:
        urteil = None
    with _cache_lock:
        if len(_cache) > 2048:
            _cache.clear()
        _cache[schluessel] = (jetzt + DECISION_TTL, urteil)
    return urteil


# ---------------------------------------------------------------------------
# Der Speicher: Anhaltspunkte und Sperren, im Konto-Ordner
# ---------------------------------------------------------------------------
def _norm_ip(ip: str) -> str:
    """Eine Adresse in einheitlicher Schreibweise -- oder "" wenn keine."""
    try:
        adresse = ipaddress.ip_address(str(ip or "").split("%", 1)[0].strip())
    except ValueError:
        return ""
    if isinstance(adresse, ipaddress.IPv6Address) and adresse.ipv4_mapped is not None:
        adresse = adresse.ipv4_mapped
    return str(adresse)


def _ban_of(row: Any) -> Ban:
    """Eine Zeile aus ``aiguard_bans`` als :class:`Ban`."""
    return Ban(str(row["subject"]), float(row["at"]), str(row["reason"]), str(row["by"]),
               float(row["until"] or 0.0))


class AiGuard:
    """Anhaltspunkte und Sperren, in derselben Datenbank wie die Konten."""

    def __init__(self, db_path: Path | str) -> None:
        self.db_path = Path(db_path)
        self._lock = threading.Lock()
        self._setup()

    @contextmanager
    def _connect(self) -> Iterator[sqlite3.Connection]:
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        conn = sqlite3.connect(self.db_path, timeout=10)
        conn.row_factory = sqlite3.Row
        try:
            yield conn
            conn.commit()
        finally:
            conn.close()

    def _setup(self) -> None:
        with self._lock, self._connect() as conn:
            conn.executescript(
                """
                CREATE TABLE IF NOT EXISTS aiguard_flags (
                    user_id  TEXT NOT NULL,
                    at       REAL NOT NULL,
                    kind     TEXT NOT NULL,
                    detail   TEXT NOT NULL DEFAULT '',
                    chat     TEXT NOT NULL DEFAULT '',
                    category TEXT NOT NULL DEFAULT '',
                    severity INTEGER NOT NULL DEFAULT 0
                );
                CREATE INDEX IF NOT EXISTS aiguard_flags_user ON aiguard_flags(user_id);
                CREATE TABLE IF NOT EXISTS aiguard_bans (
                    subject TEXT PRIMARY KEY,
                    at      REAL NOT NULL,
                    reason  TEXT NOT NULL DEFAULT '',
                    by      TEXT NOT NULL DEFAULT '',
                    until   REAL NOT NULL DEFAULT 0
                );
                CREATE TABLE IF NOT EXISTS aiguard_chat_locks (
                    user_id TEXT NOT NULL,
                    chat    TEXT NOT NULL,
                    at      REAL NOT NULL,
                    reason  TEXT NOT NULL DEFAULT '',
                    PRIMARY KEY (user_id, chat)
                );
                """
            )
            # Aeltere Datenbanken (vor 9.5.24) kennen die neuen Spalten noch
            # nicht -- fehlt eine, wird sie ergaenzt.
            spalten_bans = {str(r["name"]) for r in conn.execute("PRAGMA table_info(aiguard_bans)")}
            if "until" not in spalten_bans:
                conn.execute("ALTER TABLE aiguard_bans ADD COLUMN until REAL NOT NULL DEFAULT 0")
            spalten_flags = {str(r["name"])
                             for r in conn.execute("PRAGMA table_info(aiguard_flags)")}
            if "category" not in spalten_flags:
                conn.execute("ALTER TABLE aiguard_flags ADD COLUMN category TEXT NOT NULL "
                             "DEFAULT ''")
            if "severity" not in spalten_flags:
                conn.execute("ALTER TABLE aiguard_flags ADD COLUMN severity INTEGER NOT NULL "
                             "DEFAULT 0")

    # -- Anhaltspunkte ----------------------------------------------------
    def note(self, user_id: str, kind: str, detail: str = "", chat: str = "",
             *, enforce: bool = True) -> bool:
        """Vermerkt einen Anhaltspunkt. Returns: ob das Konto jetzt gesperrt ist.

        Innerhalb eines Chats zählt derselbe Anlass nur einmal -- sonst wäre
        eine einzige Nachricht, mehrfach geschickt, schon ein Bann. Zwei
        getrennte Anlässe (:data:`NEEDED`) lösen aus.

        Args:
            enforce: Ob bei Erreichen der Schwelle wirklich gesperrt wird.
                Für Ultra-Konten ``False`` (seit 9.5.17): dann nur eine Warnung
                im Terminal, kein Bann. Für Pro/Normal ``True`` -- gesperrt, und
                der Grund steht im Terminal.
        """
        user_id = str(user_id or "")
        if not user_id:
            return False
        with self._lock, self._connect() as conn, closing(conn.cursor()) as cur:
            schon = cur.execute(
                "SELECT 1 FROM aiguard_flags WHERE user_id=? AND kind=? AND chat=? AND chat!=''",
                (user_id, str(kind), str(chat)),
            ).fetchone()
            neu = schon is None
            if neu:
                cur.execute(
                    "INSERT INTO aiguard_flags (user_id, at, kind, detail, chat) "
                    "VALUES (?, ?, ?, ?, ?)",
                    (user_id, time.time(), str(kind)[:60], str(detail)[:200], str(chat)[:80]),
                )
            (anzahl,) = cur.execute(
                "SELECT COUNT(*) FROM aiguard_flags WHERE user_id=?", (user_id,)
            ).fetchone()
            erreicht = int(anzahl) >= NEEDED
            gesperrt = erreicht and enforce
            if gesperrt:
                grund = f"{int(anzahl)} Anhaltspunkte für Missbrauch (zuletzt: {kind})"
                cur.execute(
                    "INSERT INTO aiguard_bans (subject, at, reason, by) VALUES (?, ?, ?, ?) "
                    "ON CONFLICT(subject) DO NOTHING",
                    (f"user:{user_id}", time.time(), "Ai-guard: " + grund, "ai-guard"),
                )
        # Ins Terminal (seit 9.5.17): bei Pro/Normal der Grund der Sperre, bei
        # Ultra nur eine Warnung.
        if gesperrt:
            LOG.warning("Ai-guard: Konto %s gesperrt — %s", user_id, kind)
            print(f"[Ai-guard] Konto {user_id} gesperrt — Grund: {kind}", flush=True)
        elif erreicht and not enforce and neu:
            LOG.warning("Ai-guard: Ultra-Konto %s auffällig (%d) — nur Warnung, kein Bann",
                        user_id, int(anzahl))
            print(f"[Ai-guard] Ultra-Konto {user_id} auffällig ({int(anzahl)} Anhaltspunkte, "
                  f"zuletzt: {kind}) — nur Warnung, kein Bann.", flush=True)
        return gesperrt

    def record_incident(self, user_id: str, category: str, severity: int, *,
                        chat: str = "", detail: str = "", enforce: bool = True) -> Action:
        """Vermerkt einen Vorfall mit Art und Schwere und setzt die Massnahme um.

        Die Massnahme entscheidet :func:`decide` (seit 9.5.24): Chatsperre,
        Bann fuer Tage oder fuer immer -- je nach Art und Schwere. Bei einem
        Bann wird der Chat, in dem es passiert ist, zusaetzlich gesperrt.

        Args:
            enforce: ``False`` fuer Ultra-Konten -- dann nur eine Warnung im
                Terminal, keine Sperre (wie seit 9.5.17).

        Returns:
            Die Massnahme, die tatsaechlich gilt (bei Ultra immer "none").
        """
        user_id = str(user_id or "")
        art = normalize_category(category)
        stufe = max(0, min(4, int(severity or 0)))
        if not user_id or not art or stufe <= 0:
            return Action("none", category=art)
        with self._lock, self._connect() as conn:
            schon = conn.execute(
                "SELECT 1 FROM aiguard_flags WHERE user_id=? AND category=? AND chat=? "
                "AND chat!=''", (user_id, art, str(chat)),
            ).fetchone()
            platz = ",".join("?" for _ in _MUSTER_ARTEN)
            (vorher,) = conn.execute(
                f"SELECT COUNT(*) FROM aiguard_flags WHERE user_id=? AND category IN ({platz})",
                (user_id, *_MUSTER_ARTEN),
            ).fetchone()
            if schon is None or art in _SOFORT_ARTEN:
                conn.execute(
                    "INSERT INTO aiguard_flags (user_id, at, kind, detail, chat, category, "
                    "severity) VALUES (?, ?, ?, ?, ?, ?, ?)",
                    (user_id, time.time(), art, str(detail or art)[:200], str(chat)[:80],
                     art, stufe),
                )
        # Dasselbe Muster im selben Chat zaehlt nur einmal -- sonst waere eine
        # einzige, mehrfach geschickte Nachricht schon ein Bann.
        if schon is not None and art in _MUSTER_ARTEN:
            return Action("none", category=art, reason="schon vermerkt")
        massnahme = decide(art, stufe, int(vorher))
        if massnahme.kind == "none":
            return massnahme
        if not enforce:
            LOG.warning("Ai-guard: Ultra-Konto %s — %s (%s), nur Warnung", user_id,
                        massnahme.reason, art)
            print(f"[Ai-guard] Ultra-Konto {user_id}: {massnahme.reason} ({art}, Stufe "
                  f"{stufe}) — nur Warnung, keine Sperre.", flush=True)
            return Action("none", category=art, reason=massnahme.reason)
        if massnahme.kind == "chat":
            self.lock_chat(user_id, chat, massnahme.reason)
            print(f"[Ai-guard] Konto {user_id}: Chat gesperrt — {massnahme.reason}",
                  flush=True)
            return massnahme
        # Bann -- und der Chat, in dem es passiert ist, bleibt fuer immer zu.
        dauer = "für immer" if massnahme.days <= 0 else f"für {massnahme.days} Tag(e)"
        self.ban_user(user_id, f"Ai-guard: {massnahme.reason} ({dauer})", "ai-guard",
                      until=massnahme.until)
        self.lock_chat(user_id, chat, massnahme.reason)
        LOG.warning("Ai-guard: Konto %s gesperrt %s — %s", user_id, dauer, massnahme.reason)
        print(f"[Ai-guard] Konto {user_id} gesperrt {dauer} — Grund: {massnahme.reason}",
              flush=True)
        return massnahme

    def flags(self, user_id: str) -> list[Flag]:
        with self._connect() as conn:
            rows = conn.execute(
                "SELECT at, kind, detail, chat FROM aiguard_flags WHERE user_id=? ORDER BY at",
                (str(user_id),),
            ).fetchall()
        return [Flag(float(r["at"]), str(r["kind"]), str(r["detail"]), str(r["chat"]))
                for r in rows]

    def flag_count(self, user_id: str) -> int:
        with self._connect() as conn:
            (anzahl,) = conn.execute(
                "SELECT COUNT(*) FROM aiguard_flags WHERE user_id=?", (str(user_id),)
            ).fetchone()
        return int(anzahl)

    def pattern_count(self, user_id: str) -> int:
        """Anhaltspunkte der Muster-Arten (angriff/rechtsbruch/jailbreak, 9.5.24)."""
        platz = ",".join("?" for _ in _MUSTER_ARTEN)
        with self._connect() as conn:
            (anzahl,) = conn.execute(
                f"SELECT COUNT(*) FROM aiguard_flags WHERE user_id=? AND category IN ({platz})",
                (str(user_id), *_MUSTER_ARTEN),
            ).fetchone()
        return int(anzahl)

    # -- Sperren ----------------------------------------------------------
    def ban_user(self, user_id: str, reason: str = "", by: str = "terminal",
                 until: float = 0.0) -> None:
        self._ban(f"user:{user_id!s}", reason or "Von Hand gesperrt", by, until)

    def ban_ip(self, ip: str, reason: str = "", by: str = "terminal", until: float = 0.0) -> str:
        """Sperrt eine Adresse. Returns: die normalisierte Adresse, oder "" wenn ungültig."""
        adresse = _norm_ip(ip)
        if adresse:
            self._ban(f"ip:{adresse}", reason or "Von Hand gesperrt", by, until)
        return adresse

    def _ban(self, subject: str, reason: str, by: str, until: float = 0.0) -> None:
        with self._lock, self._connect() as conn:
            conn.execute(
                "INSERT INTO aiguard_bans (subject, at, reason, by, until) VALUES (?, ?, ?, ?, ?) "
                "ON CONFLICT(subject) DO UPDATE SET at=excluded.at, reason=excluded.reason, "
                "by=excluded.by, until=excluded.until",
                (subject, time.time(), str(reason)[:200], str(by)[:60], float(until or 0.0)),
            )

    # -- Chatsperre (9.5.24) ----------------------------------------------
    def lock_chat(self, user_id: str, chat: str, reason: str = "") -> None:
        """Sperrt genau einen Chat -- neue Chats bleiben moeglich."""
        if not user_id or not chat:
            return
        with self._lock, self._connect() as conn:
            conn.execute(
                "INSERT INTO aiguard_chat_locks (user_id, chat, at, reason) VALUES (?, ?, ?, ?) "
                "ON CONFLICT(user_id, chat) DO UPDATE SET at=excluded.at, reason=excluded.reason",
                (str(user_id), str(chat)[:80], time.time(), str(reason)[:200]),
            )

    def chat_locked(self, user_id: str, chat: str) -> str:
        """Grund, wenn dieser Chat gesperrt ist -- sonst ""."""
        if not user_id or not chat:
            return ""
        with self._connect() as conn:
            row = conn.execute(
                "SELECT reason FROM aiguard_chat_locks WHERE user_id=? AND chat=?",
                (str(user_id), str(chat)),
            ).fetchone()
        return str(row["reason"] or "unangemessene Sprache") if row else ""

    def unlock_chat(self, user_id: str, chat: str = "") -> int:
        """Hebt eine Chatsperre auf (leerer Chat: alle des Kontos)."""
        with self._lock, self._connect() as conn:
            if chat:
                weg = conn.execute("DELETE FROM aiguard_chat_locks WHERE user_id=? AND chat=?",
                                   (str(user_id), str(chat))).rowcount
            else:
                weg = conn.execute("DELETE FROM aiguard_chat_locks WHERE user_id=?",
                                   (str(user_id),)).rowcount
        return int(weg)

    def unban_user(self, user_id: str) -> bool:
        """Gibt ein Konto frei -- samt Anhaltspunkten und Chatsperren, sonst
        sperrt es sich sofort neu."""
        with self._lock, self._connect() as conn:
            weg = conn.execute("DELETE FROM aiguard_bans WHERE subject=?",
                               (f"user:{user_id!s}",)).rowcount
            conn.execute("DELETE FROM aiguard_flags WHERE user_id=?", (str(user_id),))
            conn.execute("DELETE FROM aiguard_chat_locks WHERE user_id=?", (str(user_id),))
        return bool(weg)

    def unban_ip(self, ip: str) -> bool:
        adresse = _norm_ip(ip)
        if not adresse:
            return False
        with self._lock, self._connect() as conn:
            weg = conn.execute("DELETE FROM aiguard_bans WHERE subject=?",
                               (f"ip:{adresse}",)).rowcount
        return bool(weg)

    def is_banned(self, user_id: str = "", ip: str = "") -> Ban | None:
        """Ist dieses Konto oder diese Adresse gesperrt? Returns: die Sperre oder None."""
        subjects = []
        if user_id:
            subjects.append(f"user:{user_id!s}")
        adresse = _norm_ip(ip)
        if adresse:
            subjects.append(f"ip:{adresse}")
        if not subjects:
            return None
        platz = ",".join("?" for _ in subjects)
        with self._connect() as conn:
            rows = conn.execute(
                f"SELECT subject, at, reason, by, until FROM aiguard_bans "
                f"WHERE subject IN ({platz}) ORDER BY at",
                subjects,
            ).fetchall()
        # Eine abgelaufene Sperre (9.5.24, zeitlich begrenzt) zaehlt nicht mehr.
        jetzt = time.time()
        for row in rows:
            ban = _ban_of(row)
            if ban.active(jetzt):
                return ban
        return None

    def bans(self) -> list[Ban]:
        with self._connect() as conn:
            rows = conn.execute(
                "SELECT subject, at, reason, by, until FROM aiguard_bans ORDER BY at"
            ).fetchall()
        return [_ban_of(r) for r in rows]


#: Der Satz, den ein gesperrtes Konto zu sehen bekommt.
BANNED_MESSAGE = (
    "Dieses Konto ist gesperrt. Ai-guard hat einen schweren Verstoß gegen die "
    "Nutzungsregeln erkannt. Oben links unter der Versionsnummer steht unter „Info“, "
    "warum und wie lange. Wenn du das für einen Irrtum hältst, wende dich an den "
    "Betreiber dieser Installation."
)

#: Der Satz fuer einen gesperrten Chat (9.5.24).
CHAT_LOCKED_MESSAGE = (
    "In diesem Chat kannst du nicht mehr schreiben — Ai-guard hat ihn wegen "
    "unangemessener Sprache gesperrt. Du kannst einen neuen Chat beginnen."
)

#: Was ein gesperrter Nutzer tun kann -- steht im Info-Fenster.
WHAT_TO_DO = (
    "Warte, bis die Sperre abläuft — danach geht alles wieder wie vorher. Hältst du die "
    "Sperre für einen Irrtum, wende dich an den Betreiber dieser Installation; er kann "
    "sie im Terminal aufheben (aquaticy unban)."
)


def ban_info(ban: Ban | None, now: float | None = None) -> dict[str, Any]:
    """Was die Oberflaeche ueber eine Sperre zeigt (9.5.24). Leer, wenn keine."""
    if ban is None or not ban.active(now):
        return {"banned": False}
    grund = ban.reason.removeprefix("Ai-guard: ").strip() or "Verstoß gegen die Nutzungsregeln"
    if ban.until <= 0:
        dauer, bis = "dauerhaft", ""
    else:
        dauer = ban.remaining_text(now)
        bis = time.strftime("%d.%m.%Y, %H:%M Uhr", time.localtime(ban.until))
    return {"banned": True, "reason": grund, "duration": dauer, "until": bis,
            "permanent": ban.until <= 0, "what_to_do": WHAT_TO_DO}


def guard_for(data_dir: Path | str) -> AiGuard:
    """Ai-guard für die Kontendatenbank eines Datenordners."""
    return AiGuard(Path(data_dir) / "accounts.sqlite3")


def check_message(
    guard: AiGuard,
    account: Any,
    text: str,
    settings: Settings,
    *,
    chat: str = "",
    context: str = "",
    ask: Callable[[str, Settings], str] | None = None,
) -> tuple[bool, str]:
    """Prüft eine Nachricht eines angemeldeten Kontos. Returns: (gesperrt, Grund).

    Ist das Konto schon gesperrt, kommt sofort (True, Grund). Sonst wird die
    Nachricht eingeschätzt; ein Anhaltspunkt wird vermerkt und sperrt beim
    zweiten Mal.
    """
    if account is None:
        return False, ""
    user_id = str(getattr(account, "id", "") or "")
    laufend = guard.is_banned(user_id=user_id, ip=str(getattr(account, "last_ip", "") or ""))
    if laufend is not None:
        return True, BANNED_MESSAGE
    urteil = classify(text, settings, context=context, ask=ask)
    if not urteil or not urteil[0]:
        return False, ""
    darf_bannen = not bool(getattr(account, "ultra", False))
    gesperrt = guard.note(user_id, urteil[1], detail=urteil[1], chat=chat, enforce=darf_bannen)
    return (True, BANNED_MESSAGE) if gesperrt else (False, "")
