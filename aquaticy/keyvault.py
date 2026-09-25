"""Der Schluesselbund eines Kontos: eigene API-Schluessel, nur fuer dieses Konto.

Seit 9.5.14 Seashell kann jedes Konto -- normal oder Pro -- eigene
API-Schluessel hinterlegen. Was dafuer gilt:

* **Nur dieses Konto.** Ein Schluessel haengt an der Kennung des Kontos. Er
  steht nicht in der ``.env`` des Servers, nicht in der Prozessumgebung
  (``os.environ`` gilt fuer alle Konten zugleich!) und nicht in einem
  anderen Profil. Kein Endpunkt nimmt eine fremde Kontokennung entgegen.
* **Verschluesselt.** Gespeichert wird mit Fernet (AES plus HMAC), mit einem
  Schluessel je Konto, abgeleitet aus einem Geheimnis des Servers
  (``vault.key``) und der Kontokennung. Eine Zeile, die jemand in ein anderes
  Konto umkopiert, laesst sich dort nicht entschluesseln. Wer nur die
  Datenbank hat, hat nichts.
* **Nie zurueck in den Browser.** Die Oberflaeche bekommt den Anbieter, die
  letzten vier Zeichen und das Datum -- nie den Schluessel selbst, auch nicht
  dem Besitzer.
* **Nur an den Anbieter.** Ein eigener Schluessel geht an die Schnittstelle
  des Anbieters -- nie an eine Adresse, die der Betreiber eingetragen hat
  (siehe ``Settings.llm_kwargs_for``).

Was ehrlich dazugehoert: Der Server muss den Schluessel entschluesseln, um in
deinem Namen beim Anbieter anzufragen. Wer den Server betreibt, koennte das
also auch. Gegen andere Konten, Datensicherungen der Datenbank und neugierige
Blicke in den Browser schuetzt der Schluesselbund; gegen den Betreiber selbst
schuetzt nur, dem Betreiber zu trauen -- oder Aquaticy selbst zu betreiben.
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import re
import secrets
import sqlite3
import threading
import time
from collections.abc import Iterator
from contextlib import contextmanager
from dataclasses import dataclass
from pathlib import Path
from typing import Any


@dataclass(frozen=True)
class Slot:
    """Ein Platz im Schluesselbund: welcher Schluessel, wofuer, wie er aussieht."""

    name: str
    label: str
    art: str  # "modell" oder "suche"
    form: str
    note: str


#: Welche Schluessel es gibt -- und nur diese.
SLOTS: tuple[Slot, ...] = (
    Slot("NVIDIA_NIM_API_KEY", "NVIDIA NIM", "modell", "nvapi-…",
         "Für die NVIDIA-Modelle (nvidia_nim/…), zum Beispiel Llama 3.3 70B."),
    Slot("MISTRAL_API_KEY", "Mistral", "modell", "",
         "Für die Mistral-Modelle (mistral/…), zum Beispiel Mistral Large und Codestral."),
    Slot("AQUATICY_API_KEY", "Anderer Anbieter", "modell", "",
         "Für ein Modell eines anderen Anbieters, den LiteLLM kennt (zum Beispiel "
         "openai/…, anthropic/…, groq/…) — trag die Modell-ID oben unter Hauptmodell ein."),
    Slot("BRAVE_API_KEY", "Brave Search", "suche", "",
         "Für die Suchmaschine Brave (Abschnitt Suche)."),
    Slot("TAVILY_API_KEY", "Tavily", "suche", "tvly-…",
         "Für die Suchmaschine Tavily (Abschnitt Suche)."),
)
SLOT_BY_NAME: dict[str, Slot] = {slot.name: slot for slot in SLOTS}
MODEL_KEY_NAMES = frozenset(s.name for s in SLOTS if s.art == "modell")
SEARCH_KEY_NAMES = frozenset(s.name for s in SLOTS if s.art == "suche")

#: Ein Schluessel: druckbare Zeichen ohne Leerzeichen, vernuenftig lang.
KEY_RE = re.compile(r"[\x21-\x7e]{8,400}")

_LOCKS: dict[str, threading.Lock] = {}
_LOCKS_LOCK = threading.Lock()


def _lock_for(path: Path) -> threading.Lock:
    with _LOCKS_LOCK:
        return _LOCKS.setdefault(str(path), threading.Lock())


class VaultError(ValueError):
    """Ein Schluessel, der so nicht angenommen wird -- mit einem Satz dazu."""


def check_key(name: str, value: str) -> str:
    """Prueft Name und Form. Returns: der bereinigte Schluessel.

    Raises:
        VaultError: unbekannter Name oder keine Schluesselform.
    """
    if name not in SLOT_BY_NAME:
        raise VaultError("Diesen Schlüssel gibt es hier nicht.")
    wert = str(value or "").strip()
    if not wert:
        raise VaultError("Bitte einen Schlüssel einfügen.")
    if not KEY_RE.fullmatch(wert):
        raise VaultError(
            "Das sieht nicht nach einem API-Schlüssel aus (8 bis 400 Zeichen, ohne Leerzeichen)."
        )
    return wert


def masked(value: str) -> str:
    """"••••ab12" -- genug, um den eigenen Schluessel wiederzuerkennen."""
    return "••••" + (value[-4:] if len(value) >= 12 else "")


def load_secret(path: Path) -> bytes:
    """Das Geheimnis des Servers fuer den Schluesselbund -- einmal angelegt, geschuetzt."""
    from aquaticy.memory import secure_file

    if path.is_file():
        wert = path.read_bytes()
        if len(wert) >= 32:
            return wert
    wert = secrets.token_bytes(32)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(wert)
    secure_file(path)
    return wert


class KeyVault:
    """Die eigenen API-Schluessel eines Kontos."""

    def __init__(self, db_path: Path | str, account_id: str, secret: bytes) -> None:
        if not account_id:
            raise ValueError("Ein Schlüsselbund braucht ein Konto.")
        self.db_path = Path(db_path)
        self.account_id = str(account_id)
        # Ein Schluessel je Konto: HMAC(Servergeheimnis, Kontokennung).
        abgeleitet = hmac.new(secret, b"aquaticy-keyvault-v1:" + self.account_id.encode(),
                              hashlib.sha256).digest()
        from cryptography.fernet import Fernet

        self._fernet = Fernet(base64.urlsafe_b64encode(abgeleitet))
        self._lock = _lock_for(self.db_path)
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
            conn.execute(
                """
                CREATE TABLE IF NOT EXISTS api_keys (
                    account_id TEXT NOT NULL,
                    name       TEXT NOT NULL,
                    token      TEXT NOT NULL,
                    hint       TEXT NOT NULL DEFAULT '',
                    added_at   REAL NOT NULL,
                    PRIMARY KEY (account_id, name)
                )
                """
            )

    # -- Schreiben ------------------------------------------------------------
    def set(self, name: str, value: str) -> None:
        """Legt einen Schluessel ab (oder ersetzt ihn)."""
        wert = check_key(name, value)
        token = self._fernet.encrypt(wert.encode("utf-8")).decode("ascii")
        with self._lock, self._connect() as conn:
            conn.execute(
                "INSERT INTO api_keys (account_id, name, token, hint, added_at) "
                "VALUES (?, ?, ?, ?, ?) ON CONFLICT(account_id, name) DO UPDATE SET "
                "token = excluded.token, hint = excluded.hint, added_at = excluded.added_at",
                (self.account_id, name, token, masked(wert), time.time()),
            )

    def remove(self, name: str) -> bool:
        """Entfernt einen Schluessel. Returns: ob einer da war."""
        with self._lock, self._connect() as conn:
            weg = conn.execute(
                "DELETE FROM api_keys WHERE account_id = ? AND name = ?",
                (self.account_id, str(name)),
            ).rowcount
        return bool(weg)

    # -- Lesen ----------------------------------------------------------------
    def _rows(self) -> list[sqlite3.Row]:
        with self._lock, self._connect() as conn:
            return conn.execute(
                "SELECT name, token, hint, added_at FROM api_keys WHERE account_id = ? "
                "ORDER BY name", (self.account_id,)
            ).fetchall()

    def keys(self) -> dict[str, str]:
        """Die Schluessel im Klartext -- nur fuer die Einstellungen des Kontos.

        Was sich nicht entschluesseln laesst (umkopiert, beschaedigt), fehlt
        einfach: lieber kein Schluessel als ein kaputter, der beim Anbieter
        als "falscher Schluessel" ankommt.
        """
        from cryptography.fernet import InvalidToken

        gefunden: dict[str, str] = {}
        for zeile in self._rows():
            if zeile["name"] not in SLOT_BY_NAME:
                continue
            try:
                gefunden[zeile["name"]] = self._fernet.decrypt(
                    str(zeile["token"]).encode("ascii")).decode("utf-8")
            except (InvalidToken, ValueError, UnicodeError):
                continue
        return gefunden

    def names(self) -> list[str]:
        return sorted(self.keys())

    def count(self) -> int:
        """Wie viele Schluessel dieses Konto wirklich benutzen kann.

        Gezaehlt wird, was sich entschluesseln laesst: eine umkopierte oder
        beschaedigte Zeile ist kein Schluessel.
        """
        return len(self.keys())

    def public(self) -> list[dict[str, Any]]:
        """Was der Browser sehen darf: Anbieter, letzte Zeichen, Datum -- nie den Schluessel."""
        lesbar = self.keys()
        return [
            {"name": zeile["name"], "hint": str(zeile["hint"] or "••••"),
             "added_at": float(zeile["added_at"] or 0.0)}
            for zeile in self._rows() if zeile["name"] in lesbar
        ]


def summary(names: list[str] | set[str] | frozenset[str]) -> str:
    """"Du hast keinen / einen / 3 API-Schluessel hinzugefuegt" -- mit Namen."""
    liste = [SLOT_BY_NAME[n].label for n in sorted(names, key=_ordnung) if n in SLOT_BY_NAME]
    if not liste:
        return "Du hast keinen API-Schlüssel hinzugefügt."
    if len(liste) == 1:
        return f"Du hast einen API-Schlüssel hinzugefügt: {liste[0]}."
    return f"Du hast {len(liste)} API-Schlüssel hinzugefügt: {', '.join(liste)}."


def _ordnung(name: str) -> int:
    return next((i for i, slot in enumerate(SLOTS) if slot.name == name), 99)


def scrub(text: str, secrets_: list[str] | set[str]) -> str:
    """Entfernt Schluessel aus einem Text -- Fehlermeldungen der Anbieter zitieren sie gern."""
    ergebnis = str(text or "")
    for geheim in sorted({s for s in secrets_ if s and len(s) >= 8}, key=len, reverse=True):
        ergebnis = ergebnis.replace(geheim, "••••")
    return ergebnis
