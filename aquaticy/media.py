"""Private, user-scoped snapshots used by visual research and monitoring."""

from __future__ import annotations

import hashlib
import re
import time
from contextlib import suppress
from pathlib import Path

MIME_EXTENSIONS = {
    "image/jpeg": ".jpg",
    "image/png": ".png",
    "image/webp": ".webp",
    "image/gif": ".gif",
}
MEDIA_ID = re.compile(r"^[0-9]{13}-[0-9a-f]{16}(?:-fest|-ki)?\.(?:jpg|png|webp|gif)$")
MAX_SNAPSHOTS = 200

#: KI-Bilder (seit 9.5.15): gehoeren zu einem Chat und gehen mit ihm. Bis
#: 9.5.14 wurden sie "fest" abgelegt -- fuer immer, auch nach dem Loeschen
#: des Chats. Mehr als so viele bleiben nicht; die aeltesten gehen zuerst.
AI_MARK = "-ki"
MAX_AI_IMAGES = 300

#: Festgehaltene Bilder (Auftraege) werden nie still geloescht -- dafuer gibt
#: es eine Obergrenze. Wer mehr will, loescht erst alte Auftraege.
MAX_KEPT = 200

#: Marke im Dateinamen fuer Bilder, die bleiben muessen. Ein Schnappschuss aus
#: einer Recherche ist eine Momentaufnahme und darf altern; das Foto, das
#: jemand fuer einen Auftrag hochgeladen hat, ist die Frage selbst -- waere es
#: nach zweihundert Webcam-Bildern weg, suchte der Auftrag nach nichts mehr.
KEEP_MARK = "-fest"


def _directory(data_dir: Path | str) -> Path:
    path = Path(data_dir) / "media"
    path.mkdir(parents=True, exist_ok=True)
    return path


def save_snapshot(
    data_dir: Path | str, content: bytes, content_type: str, *, keep: bool = False,
    ai: bool = False,
) -> str:
    """Store the exact inspected frame and return an opaque media id.

    Mit *keep* bleibt das Bild vom Aufraeumen verschont -- fuer alles, worauf
    sich spaeter noch etwas beruft (Auftraege; hoechstens ``MAX_KEPT``).
    Mit *ai* ist es ein KI-Bild: es gehoert zu seinem Chat, geht mit ihm und
    zaehlt zu hoechstens ``MAX_AI_IMAGES``.

    Raises:
        ValueError: kein unterstuetztes Bild, oder zu viele festgehaltene.
        StorageFull: der gemeinsame 400-MB-Deckel ist erreicht (aquaticy/budget.py).
    """
    from aquaticy.budget import ensure_room, forget

    mime = str(content_type or "").split(";", 1)[0].lower()
    extension = MIME_EXTENSIONS.get(mime)
    if not extension or not content:
        raise ValueError("Nicht unterstütztes oder leeres Bild.")
    directory = _directory(data_dir)
    if keep and sum(1 for n in _names(directory) if KEEP_MARK in n) >= MAX_KEPT:
        raise ValueError(
            f"Es sind schon {MAX_KEPT} Bilder für Aufträge abgelegt -- lösche erst alte Aufträge."
        )
    ensure_room(data_dir, len(content))
    digest = hashlib.sha256(content).hexdigest()[:16]
    marke = KEEP_MARK if keep else AI_MARK if ai else ""
    media_id = f"{int(time.time() * 1000):013d}-{digest}{marke}{extension}"
    target = directory / media_id
    if not target.exists():
        target.write_bytes(content)
    forget(data_dir)
    _rotate(directory, lambda n: KEEP_MARK not in n and AI_MARK not in n, MAX_SNAPSHOTS)
    _rotate(directory, lambda n: AI_MARK in n, MAX_AI_IMAGES)
    return media_id


def _names(directory: Path) -> list[str]:
    return [item.name for item in directory.iterdir()
            if item.is_file() and MEDIA_ID.fullmatch(item.name)]


def _rotate(directory: Path, passt: object, behalten: int) -> None:
    """Loescht die aeltesten Bilder einer Art ueber *behalten* hinaus."""
    def alter(item: Path) -> float:
        try:
            return item.stat().st_mtime
        except OSError:
            return 0.0

    bilder = sorted((directory / n for n in _names(directory) if passt(n)),  # type: ignore[operator]
                    key=alter, reverse=True)
    for old in bilder[behalten:]:
        with suppress(OSError):
            old.unlink()


def media_ids_in(value: object) -> set[str]:
    """Alle Bildkennungen in einem Verlaufseintrag (meta) -- fuer das Loeschen mit dem Chat."""
    gefunden: set[str] = set()
    if isinstance(value, dict):
        for inhalt in value.values():
            gefunden |= media_ids_in(inhalt)
    elif isinstance(value, list):
        for inhalt in value:
            gefunden |= media_ids_in(inhalt)
    elif isinstance(value, str) and MEDIA_ID.fullmatch(value.strip()):
        gefunden.add(value.strip())
    return gefunden


def snapshot_path(data_dir: Path | str, media_id: str) -> Path | None:
    """Der Dateipfad eines Schnappschusses -- oder `None`.

    Gebraucht dort, wo nicht die Bytes, sondern eine Datei erwartet wird:
    ein Bildauftrag reicht sein Vergleichsbild an das Vision-Modell weiter.
    Dieselbe strenge Pruefung wie beim Lesen -- ein Name mit Schraegstrichen
    oder Punkten kommt hier gar nicht erst durch.
    """
    wanted = str(media_id or "").strip()
    if not MEDIA_ID.fullmatch(wanted):
        return None
    path = Path(data_dir) / "media" / wanted
    return path if path.is_file() else None


def delete_snapshot(data_dir: Path | str, media_id: str) -> bool:
    """Loescht einen Schnappschuss. `False`, wenn es ihn nicht gab.

    Gedacht fuer den Fall, dass das, was sich darauf berief, verschwindet --
    ein geloeschter Auftrag zum Beispiel. Ein festgehaltenes Bild wird sonst
    nie wieder aufgeraeumt.
    """
    path = snapshot_path(data_dir, media_id)
    if path is None:
        return False
    with suppress(OSError):
        path.unlink()
        return True
    return False


def load_snapshot(data_dir: Path | str, media_id: str) -> tuple[bytes, str] | None:
    """Read one snapshot without accepting paths or cross-user locations."""
    wanted = str(media_id or "").strip()
    if not MEDIA_ID.fullmatch(wanted):
        return None
    path = Path(data_dir) / "media" / wanted
    try:
        data = path.read_bytes()
    except OSError:
        return None
    extension = path.suffix.lower()
    mime = next((kind for kind, ext in MIME_EXTENSIONS.items() if ext == extension), "")
    return (data, mime) if data and mime else None
