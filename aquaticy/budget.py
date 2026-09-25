"""Ein gemeinsamer Speicherdeckel je Profil: 400 MB fuer alles (seit 9.5.15).

Bis 9.5.14 pruefte nur der Speicher (aquaticy/memory.py) die 400-MB-Grenze --
Zwischenspeicher, Chatverlauf und Bilder wuchsen daran vorbei, und die
Anzeige nannte eine Zahl, die nicht alles umfasste. Jetzt zaehlt hier ALLES,
was im Ordner eines Profils liegt: die Datenbank (Speicher, Verlauf,
Zwischenspeicher, Merkzettel, Auftraege), hochgeladene Dateien, Bilder aus
Recherchen, KI-Bilder und festgehaltene Bilder von Auftraegen.

Wird es eng (90 %), raeumt ``make_room`` auf -- in dieser Reihenfolge, vom
Ersetzbaren zum Eigenen:

1. abgelaufene und danach alle Eintraege im Zwischenspeicher (kommen beim
   naechsten Abruf wieder),
2. Momentaufnahmen aus Recherchen (die aeltesten zuerst),
3. hochgeladene Dateien (die aeltesten zuerst),
4. KI-Bilder (die aeltesten zuerst).

Notizen, Verlauf und die Bilder von Auftraegen loescht niemand still. Reicht
das Aufraeumen nicht, wird NICHTS Neues mehr angelegt (``StorageFull``) --
mit einem Satz, was man loeschen kann.
"""

from __future__ import annotations

import contextlib
import sqlite3
import threading
import time
from pathlib import Path

#: Mehr als das darf ein Profil nie belegen. Bewusst 400 Millionen Byte und
#: nicht 400 MiB: die Anzeige soll dieselbe Zahl nennen, die hier steht.
MAX_BYTES = 400_000_000

#: Ab hier wird aufgeraeumt, statt bis zum Anschlag zu warten.
CLEANUP_AT = 0.9

#: Aufgeraeumt wird bis hierher -- sonst stuende man gleich wieder davor.
CLEANUP_TO = 0.7

#: Wie lange eine Messung gilt. Das Durchzaehlen eines Ordners mit ein paar
#: hundert Bildern kostet Millisekunden; bei jedem Zwischenspeicher-Eintrag
#: waere es trotzdem zu oft.
MEASURE_SECONDS = 3.0

_messungen: dict[str, tuple[float, int]] = {}
_lock = threading.Lock()


class StorageFull(OSError):
    """Das Profil hat seine 400 MB erreicht -- auch nach dem Aufraeumen."""


def _dateien(data_dir: Path) -> list[Path]:
    """Alle Dateien eines Profils. Der Ordner ``users`` gehoert anderen Konten."""
    if not data_dir.is_dir():
        return []
    gefunden: list[Path] = []
    for eintrag in data_dir.iterdir():
        if eintrag.is_dir():
            if eintrag.name == "users" and eintrag.parent == data_dir:
                continue
            gefunden.extend(p for p in eintrag.rglob("*") if p.is_file())
        elif eintrag.is_file():
            gefunden.append(eintrag)
    return gefunden


def used_bytes(data_dir: Path | str, *, fresh: bool = False) -> int:
    """Wie viel das Profil belegt -- alles zusammen."""
    ordner = Path(data_dir)
    schluessel = str(ordner.resolve()) if ordner.exists() else str(ordner)
    jetzt = time.monotonic()
    if not fresh:
        with _lock:
            bekannt = _messungen.get(schluessel)
        if bekannt and bekannt[0] > jetzt:
            return bekannt[1]
    summe = 0
    for datei in _dateien(ordner):
        with contextlib.suppress(OSError):
            summe += datei.stat().st_size
    with _lock:
        _messungen[schluessel] = (jetzt + MEASURE_SECONDS, summe)
    return summe


def forget(data_dir: Path | str | None = None) -> None:
    """Messungen vergessen -- nach dem Loeschen, und fuer Tests."""
    with _lock:
        if data_dir is None:
            _messungen.clear()
        else:
            ordner = Path(data_dir)
            _messungen.pop(str(ordner.resolve()) if ordner.exists() else str(ordner), None)


def _datenbank(data_dir: Path) -> Path:
    return data_dir / "aquaticy.sqlite3"


def _zwischenspeicher_leeren(data_dir: Path, alles: bool) -> None:
    datei = _datenbank(data_dir)
    if not datei.is_file():
        return
    with contextlib.suppress(sqlite3.Error):
        conn = sqlite3.connect(datei, timeout=10)
        try:
            if alles:
                conn.execute("DELETE FROM cache")
            else:
                conn.execute("DELETE FROM cache WHERE expires_at < ?", (time.time(),))
            conn.commit()
            conn.execute("VACUUM")
        finally:
            conn.close()


def _aelteste_zuerst(ordner: Path, passt: object) -> list[Path]:
    if not ordner.is_dir():
        return []
    dateien = [p for p in ordner.iterdir() if p.is_file() and passt(p.name)]  # type: ignore[operator]

    def alter(datei: Path) -> float:
        try:
            return datei.stat().st_mtime
        except OSError:
            return 0.0

    return sorted(dateien, key=alter)


def make_room(data_dir: Path | str) -> int:
    """Raeumt auf, bis hoechstens 70 % belegt sind. Returns: frei gewordene Bytes."""
    from aquaticy.media import AI_MARK, KEEP_MARK

    ordner = Path(data_dir)
    vorher = used_bytes(ordner, fresh=True)
    ziel = MAX_BYTES * CLEANUP_TO

    def genug() -> bool:
        forget(ordner)
        return used_bytes(ordner, fresh=True) <= ziel

    _zwischenspeicher_leeren(ordner, alles=False)
    if not genug():
        _zwischenspeicher_leeren(ordner, alles=True)
    stufen = (
        _aelteste_zuerst(ordner / "media",
                         lambda n: KEEP_MARK not in n and AI_MARK not in n),
        _aelteste_zuerst(ordner / "uploads", lambda n: True),
        _aelteste_zuerst(ordner / "media", lambda n: AI_MARK in n),
    )
    for dateien in stufen:
        for datei in dateien:
            if genug():
                break
            with contextlib.suppress(OSError):
                datei.unlink()
    forget(ordner)
    return max(0, vorher - used_bytes(ordner, fresh=True))


def has_room(data_dir: Path | str, incoming: int = 0) -> bool:
    """Passt *incoming* noch hinein -- notfalls nach dem Aufraeumen?"""
    ordner = Path(data_dir)
    if used_bytes(ordner) + max(0, incoming) <= MAX_BYTES * CLEANUP_AT:
        return True
    make_room(ordner)
    return used_bytes(ordner, fresh=True) + max(0, incoming) <= MAX_BYTES


def ensure_room(data_dir: Path | str, incoming: int = 0) -> None:
    """Wie ``has_room`` -- nur dass es ``StorageFull`` wirft, statt False zu sagen."""
    if not has_room(data_dir, incoming):
        raise StorageFull(
            f"Dein Speicher ist voll ({MAX_BYTES // 1_000_000} MB). Lösche alte Chats, "
            "Notizen oder hochgeladene Dateien in den Einstellungen unter Speicher."
        )
