"""Verschluesselung persoenlicher Daten (seit 9.5.32).

Was damit verschluesselt liegt:

* **Chats** -- Fragen, Antworten, Zusatzdaten und eigene Chatnamen in der
  Verlaufsdatenbank jedes Kontos (``aquaticy/cache.py``).
* **Fotos und Bilder** -- Hochgeladenes (``uploads/``), Schnappschuesse und
  KI-Bilder (``media/``).
* **IP-Adressen, Geraete und Browser** -- in der Kontendatenbank. Zum
  Abgleichen gibt es je Wert einen *Schluessel-Hash* (HMAC): der Server kann
  pruefen, ob zwei Adressen gleich sind, ohne sie lesbar zu speichern. Der
  Betreiber sieht in ``aquaticy list`` nur ``#`` und die ersten Zeichen davon.
* **E-Mail-Adressen** -- verschluesselt; gesucht wird ueber den Schluessel-Hash.

Wie: AES-256-GCM (authentifiziert -- wer ein Byte aendert, bekommt einen
Fehler statt falscher Daten). Jedes Konto hat einen eigenen Schluessel,
abgeleitet (HKDF) aus dem Hauptschluessel ``data.key`` neben der
Kontendatenbank und der Kennung des Kontos. Eine Datei oder Zeile, die jemand
in ein anderes Konto kopiert, laesst sich dort nicht oeffnen; die
"Zusatzdaten" (AAD) binden jeden Wert an seine Spalte bzw. seinen Dateinamen.

Was ehrlich dazugehoert: Der Server muss Chats lesen, um mit ihnen zu
arbeiten, und Adressen vergleichen, um Konten zu schuetzen. ``data.key`` liegt
deshalb auf dem Server. Die Verschluesselung schuetzt gegen gestohlene oder
kopierte Datenbanken und Sicherungen, gegen andere Konten und gegen das
beilaeufige Hineinsehen in Dateien -- wer den Server selbst uebernimmt und den
Schluessel liest, koennte entschluesseln. Deshalb gehoert ``data.key`` nie in
eine Sicherung zusammen mit den Daten.
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import re
import secrets
import threading
from pathlib import Path

from aquaticy.memory import CipherError, load_secret_file

#: Die Datei mit dem Hauptschluessel -- neben der Kontendatenbank.
KEY_FILE = "data.key"
#: So beginnt ein verschluesselter Text (Datenbankspalten).
TEXT_PREFIX = "enc2:"
#: So beginnt eine verschluesselte Datei.
FILE_MAGIC = b"AQENC2\x00"
_NONCE = 12

_lock = threading.Lock()
_masters: dict[str, bytes] = {}


def key_root(folder: Path | str) -> tuple[Path, str]:
    """Wo der Hauptschluessel liegt und wie das Profil heisst.

    Ein Kontoprofil liegt unter ``<daten>/users/<kennung>`` -- dann liegt der
    Schluessel in ``<daten>``. Sonst (Terminal ohne Konten) im Ordner selbst.
    """
    ordner = Path(folder).resolve()
    # Nur eine echte Kontokennung (32 Hexzeichen) unter "users" -- ein
    # Datenordner, der zufaellig /srv/users/aquaticy heisst, ist kein Profil.
    if ordner.parent.name == "users" and re.fullmatch(r"[0-9a-f]{32}", ordner.name):
        return ordner.parent.parent, ordner.name
    return ordner, "lokal"


def master_key(root: Path | str) -> bytes:
    """Der Hauptschluessel einer Installation -- beim ersten Mal zufaellig angelegt."""
    wurzel = Path(root).resolve()
    schluessel = str(wurzel)
    with _lock:
        if schluessel in _masters:
            return _masters[schluessel]
        pfad = wurzel / KEY_FILE
        wert = load_secret_file(pfad, lambda: secrets.token_bytes(32), 32)
        _masters[schluessel] = wert
        return wert


def _derive(master: bytes, info: str) -> bytes:
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.kdf.hkdf import HKDF

    return HKDF(algorithm=hashes.SHA256(), length=32, salt=None,
                info=("aquaticy/" + info).encode("utf-8")).derive(master)


class Sealer:
    """AES-256-GCM mit einem abgeleiteten Schluessel."""

    def __init__(self, key: bytes) -> None:
        from cryptography.hazmat.primitives.ciphers.aead import AESGCM

        self._aead = AESGCM(key)

    # -- Bytes --------------------------------------------------------------
    def seal_bytes(self, data: bytes, aad: str) -> bytes:
        nonce = secrets.token_bytes(_NONCE)
        return FILE_MAGIC + nonce + self._aead.encrypt(nonce, bytes(data), aad.encode("utf-8"))

    def open_bytes(self, blob: bytes, aad: str) -> bytes:
        """Entschluesselt -- unverschluesselte (alte) Daten kommen unveraendert zurueck.

        Raises:
            CipherError: verschluesselt, aber nicht zu oeffnen (falscher
                Schluessel, beschaedigt, in ein anderes Konto kopiert).
        """
        if not blob.startswith(FILE_MAGIC):
            return blob
        from cryptography.exceptions import InvalidTag

        roh = blob[len(FILE_MAGIC):]
        try:
            return self._aead.decrypt(roh[:_NONCE], roh[_NONCE:], aad.encode("utf-8"))
        except (InvalidTag, ValueError) as exc:
            raise CipherError("Verschlüsselte Daten lassen sich nicht öffnen.") from exc

    # -- Text ---------------------------------------------------------------
    def seal_text(self, text: str, aad: str) -> str:
        if not text:
            return ""
        roh = self.seal_bytes(text.encode("utf-8"), aad)[len(FILE_MAGIC):]
        return TEXT_PREFIX + base64.urlsafe_b64encode(roh).decode("ascii")

    def open_text(self, value: str, aad: str) -> str:
        wert = str(value or "")
        if not wert.startswith(TEXT_PREFIX):
            return wert  # Klartext aus der Zeit vor 9.5.32
        try:
            roh = base64.urlsafe_b64decode(wert[len(TEXT_PREFIX):].encode("ascii"))
        except (ValueError, UnicodeEncodeError) as exc:
            raise CipherError("Verschlüsselter Text ist beschädigt.") from exc
        return self.open_bytes(FILE_MAGIC + roh, aad).decode("utf-8")


def profile_sealer(folder: Path | str) -> Sealer:
    """Der Schluessel eines Kontoprofils (oder der lokalen Installation)."""
    wurzel, name = key_root(folder)
    return Sealer(_derive(master_key(wurzel), f"profil/{name}"))


def is_sealed_file(data: bytes) -> bool:
    return bytes(data[: len(FILE_MAGIC)]) == FILE_MAGIC


def write_private(path: Path | str, data: bytes, profile: Path | str) -> None:
    """Schreibt eine Datei eines Profils verschluesselt (Name als Zusatzdaten)."""
    ziel = Path(path)
    ziel.write_bytes(profile_sealer(profile).seal_bytes(data, "datei:" + ziel.name))


def read_private(path: Path | str, profile: Path | str | None = None) -> bytes:
    """Liest eine (vielleicht) verschluesselte Datei eines Profils.

    Ohne *profile* gilt: die Datei liegt in ``<profil>/<ordner>/<name>``.
    """
    quelle = Path(path)
    daten = quelle.read_bytes()
    if not is_sealed_file(daten):
        return daten
    profil = Path(profile) if profile is not None else quelle.resolve().parent.parent
    return profile_sealer(profil).open_bytes(daten, "datei:" + quelle.name)


# ---------------------------------------------------------------------------
# Kontendatenbank: Schluessel-Hashes und verschluesselte Spalten
# ---------------------------------------------------------------------------
class ServerSecrets:
    """Werkzeuge fuer die Kontendatenbank einer Installation."""

    def __init__(self, root: Path | str) -> None:
        master = master_key(root)
        self._blind_key = _derive(master, "blind")
        self._sealer = Sealer(_derive(master, "konten"))

    def blind(self, purpose: str, value: str) -> str:
        """Schluessel-Hash: gleich fuer gleiche Werte, aber ohne Schluessel nicht umkehrbar."""
        wert = str(value or "")
        if not wert:
            return ""
        return hmac.new(self._blind_key, f"{purpose}\x1f{wert}".encode(),
                        hashlib.sha256).hexdigest()

    def seal(self, value: str, aad: str) -> str:
        return self._sealer.seal_text(str(value or ""), aad)

    def open(self, value: str, aad: str) -> str:
        """Entschluesselt; bei Fehlern leer statt Absturz (Anzeige, kein Abgleich)."""
        try:
            return self._sealer.open_text(value, aad)
        except (CipherError, UnicodeDecodeError):
            return ""


def short_tag(digest: str) -> str:
    """Was der Betreiber sieht: ``#`` und die ersten acht Zeichen des Hashs."""
    wert = str(digest or "")
    return "#" + wert[:8] if wert else "—"
