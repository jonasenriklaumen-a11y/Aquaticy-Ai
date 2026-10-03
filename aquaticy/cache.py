"""SQLite-Persistenz: Response-Cache (TTL) und Recherche-Verlauf.

Bewusst klein gehalten -- zwei Tabellen, keine ORM-Schicht.
"""

from __future__ import annotations

import contextlib
import hashlib
import json
import sqlite3
import threading
import time
import weakref
from collections.abc import Iterator
from contextlib import closing, contextmanager
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from aquaticy.media import KEEP_MARK, delete_snapshot, media_ids_in

SCHEMA = """
CREATE TABLE IF NOT EXISTS cache (
    key        TEXT PRIMARY KEY,
    kind       TEXT NOT NULL,
    label      TEXT NOT NULL,
    payload    TEXT NOT NULL,
    created_at REAL NOT NULL,
    expires_at REAL NOT NULL
);
CREATE INDEX IF NOT EXISTS cache_expires_idx ON cache(expires_at);

CREATE TABLE IF NOT EXISTS history (
    id         INTEGER PRIMARY KEY AUTOINCREMENT,
    session_id TEXT NOT NULL,
    created_at REAL NOT NULL,
    question   TEXT NOT NULL,
    answer     TEXT NOT NULL,
    meta       TEXT NOT NULL DEFAULT '{}'
);
CREATE INDEX IF NOT EXISTS history_session_idx ON history(session_id);

-- Ein Chat heisst normalerweise nach seiner ersten Frage. Wer ihn umbenennt,
-- bekommt hier einen Eintrag; die erste Frage bleibt unangetastet.
CREATE TABLE IF NOT EXISTS chat_titles (
    session_id TEXT PRIMARY KEY,
    title      TEXT NOT NULL
);

-- Ein Chat, in dem etwas steht, das noch niemand gelesen hat. Angelegt wird
-- der Eintrag von den Auftraegen: die stellen ihre Frage von selbst, oft
-- nachts, und die Antwort soll auffallen, ohne dass jemand danach sucht.
-- Beim Oeffnen faellt der Eintrag weg -- danach sieht der Chat aus wie jeder
-- andere.
CREATE TABLE IF NOT EXISTS chat_unread (
    session_id TEXT PRIMARY KEY,
    since      REAL NOT NULL,
    reason     TEXT NOT NULL DEFAULT ''
);

CREATE TABLE IF NOT EXISTS notes (
    id         INTEGER PRIMARY KEY AUTOINCREMENT,
    created_at REAL NOT NULL,
    text       TEXT NOT NULL
);

-- Seit 9.5.32 liegen Chats verschluesselt (aquaticy/privacy.py). Steht hier
-- eine 1, sind auch die alten Zeilen umgeschrieben.
CREATE TABLE IF NOT EXISTS privacy_state (
    name  TEXT PRIMARY KEY,
    value TEXT NOT NULL
);
"""

#: Welche Spalten verschluesselt liegen (Tabelle, Spalte) -- die Zusatzdaten
#: (AAD) binden jeden Wert an genau diese Spalte.
SEALED_COLUMNS = (("history", "question"), ("history", "answer"), ("history", "meta"),
                  ("chat_titles", "title"), ("notes", "text"))

# Nur Kennungen und Zeitangaben werden in SQL gruppiert; die Texte bleiben
# verschluesselt. Ein JOIN ersetzt die bisherigen zwei Abfragen je Chat.
CHAT_SUMMARIES = """
    SELECT h.session_id, h.turns, h.touched, first.question, title.title,
           unread.session_id IS NOT NULL AS unread
    FROM (
        SELECT session_id, MIN(id) AS first_id, MAX(id) AS last_id,
               COUNT(*) AS turns, MAX(created_at) AS touched
        FROM history GROUP BY session_id
    ) AS h
    JOIN history AS first ON first.id = h.first_id
    LEFT JOIN chat_titles AS title ON title.session_id = h.session_id
    LEFT JOIN chat_unread AS unread ON unread.session_id = h.session_id
    ORDER BY h.last_id DESC
"""


def cache_key(kind: str, *parts: Any) -> str:
    """Stabiler Schluessel aus Art und beliebigen Bestandteilen."""
    raw = "\x1f".join([kind, *(str(part) for part in parts)])
    return f"{kind}:{hashlib.sha256(raw.encode('utf-8')).hexdigest()[:32]}"


def _snippet(row: Any, needle: str, width: int = 110) -> str:
    """Die Stelle um den Treffer herum -- Frage bevorzugt, sonst Antwort.

    Die Frage steht vorn, weil sie kuerzer ist und man den eigenen Wortlaut
    schneller wiedererkennt als den der Antwort.
    """
    # casefold kann Zeichen erweitern (Straße -> strasse). Die Fundstelle
    # deshalb auf die Position im Originaltext zurueckfuehren.
    klein = needle.casefold()
    for feld in ("question", "answer"):
        text = " ".join(str(row[feld] or "").split())
        stelle = text.casefold().find(klein)
        if stelle < 0:
            continue
        offset = 0
        for index, char in enumerate(text):
            offset += len(char.casefold())
            if offset > stelle:
                stelle = index
                break
        von = max(0, stelle - width // 3)
        bis = min(len(text), stelle + len(needle) + width)
        return ("… " if von else "") + text[von:bis] + (" …" if bis < len(text) else "")
    return ""


@dataclass(slots=True)
class Note:
    """Ein Eintrag auf dem Merkzettel des Nutzers."""

    id: int
    created_at: float
    text: str


@dataclass(slots=True)
class HistoryEntry:
    """Ein abgeschlossener Frage/Antwort-Durchlauf."""

    id: int
    session_id: str
    created_at: float
    question: str
    answer: str
    meta: dict[str, Any]


#: Wie oft Abgelaufenes weggeraeumt wird (je Datenbank).
PURGE_EVERY = 600.0
_LAST_PURGE: dict[str, float] = {}
_PURGE_LOCK = threading.Lock()


_INIT_LOCK = threading.Lock()
_INIT_LOCKS: weakref.WeakValueDictionary[str, threading.Lock] = weakref.WeakValueDictionary()


@contextmanager
def _initializing(path: Path) -> Iterator[None]:
    # Auch journal_mode und VACUUM brauchen dieselbe Start-Sperre. Schwache
    # Referenzen behalten keine laengst geschlossenen Profile im Speicher.
    key = str(path.resolve())
    with _INIT_LOCK:
        lock = _INIT_LOCKS.get(key)
        if lock is None:
            lock = threading.Lock()
            _INIT_LOCKS[key] = lock
    with lock:
        yield


class Cache:
    """Schmaler Wrapper um eine SQLite-Datei."""

    def __init__(self, db_path: Path | str, ttl_hours: int = 24) -> None:
        self.db_path = Path(db_path)
        self.ttl_seconds = max(0, int(ttl_hours)) * 3600
        self._fill_lock = threading.Lock()
        self._fills: dict[str, tuple[threading.Lock, int]] = {}
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        from aquaticy.privacy import profile_sealer

        #: Der Schluessel dieses Profils (seit 9.5.32): Chats liegen verschluesselt.
        self._sealer = profile_sealer(self.db_path.parent)
        with _initializing(self.db_path):
            with self._connect() as conn:
                conn.executescript(SCHEMA)
                self._seal_old_rows(conn)
                clean_cache = self._seal_old_cache(conn)
            if clean_cache:
                # Auch Overflow-Seiten und schon frueher freigewordene Seiten
                # koennen Alttexte tragen. Einmalig verdichten und den WAL leeren.
                # Marker 1 bleibt bei einem Abbruch stehen: dann wird dies beim
                # naechsten Oeffnen erneut versucht; 2 bedeutet fertig bereinigt.
                with self._connect() as conn:
                    conn.execute("VACUUM")
                    busy, _, _ = conn.execute("PRAGMA wal_checkpoint(TRUNCATE)").fetchone()
                    if not busy:
                        conn.execute("INSERT OR REPLACE INTO privacy_state VALUES ('cache', '2')")
        self._maybe_purge()

    # -- Verschluesselung (9.5.32) ------------------------------------------
    def _seal(self, text: str, spalte: str) -> str:
        return self._sealer.seal_text(str(text or ""), spalte)

    def _open(self, text: Any, spalte: str) -> str:
        """Entschluesselt eine Spalte. Eine einzelne kaputte Zeile ergibt ""
        statt einer Ausnahme (9.5.34) -- sonst liess sich die ganze Chatliste
        nicht mehr oeffnen."""
        from aquaticy.memory import CipherError

        try:
            return self._sealer.open_text(str(text or ""), spalte)
        except (CipherError, UnicodeDecodeError):
            return ""

    def _seal_old_rows(self, conn: sqlite3.Connection) -> None:
        """Verschluesselt einmalig, was noch aus der Zeit vor 9.5.32 im Klartext liegt."""
        from aquaticy.privacy import TEXT_PREFIX

        fertig = conn.execute(
            "SELECT value FROM privacy_state WHERE name='chats'").fetchone()
        if fertig is not None and str(fertig[0]) == "1":
            return
        for tabelle, spalte in SEALED_COLUMNS:
            schluessel = "id" if tabelle != "chat_titles" else "session_id"
            zeilen = conn.execute(
                f"SELECT {schluessel}, {spalte} FROM {tabelle} "
                f"WHERE {spalte} != '' AND substr({spalte}, 1, ?) != ?",
                (len(TEXT_PREFIX), TEXT_PREFIX),
            ).fetchall()
            for zeile in zeilen:
                conn.execute(
                    f"UPDATE {tabelle} SET {spalte}=? WHERE {schluessel}=?",
                    (self._seal(str(zeile[1]), f"{tabelle}.{spalte}"), zeile[0]),
                )
        conn.execute("INSERT OR REPLACE INTO privacy_state (name, value) VALUES ('chats', '1')")

    def _seal_old_cache(self, conn: sqlite3.Connection) -> bool:
        """Alte Suchbegriffe und Rechercheergebnisse einmalig verschluesseln."""
        from aquaticy.budget import fits, note_written
        from aquaticy.privacy import TEXT_PREFIX

        state = conn.execute("SELECT value FROM privacy_state WHERE name='cache'").fetchone()
        if state is not None:
            return str(state[0]) != "2"
        # Zwei neu geoeffnete Chats koennen dasselbe Profil zugleich
        # migrieren. Vor dem ersten Lesen der Altwerte den Schreiber reservieren.
        if not conn.in_transaction:
            conn.execute("BEGIN IMMEDIATE")
        state = conn.execute("SELECT value FROM privacy_state WHERE name='cache'").fetchone()
        if state is not None:
            return str(state[0]) != "2"
        # Beim Ersetzen groesserer Klartexte auch freigewordene SQLite-Bytes
        # ueberschreiben; sonst blieben die Altwerte im Datenbankfile lesbar.
        conn.execute("PRAGMA secure_delete=ON")
        while True:
            rows = conn.execute(
                "SELECT * FROM cache WHERE (payload != '' AND substr(payload, 1, ?) != ?) OR "
                "(label != '' AND substr(label, 1, ?) != ?) LIMIT 32",
                (len(TEXT_PREFIX), TEXT_PREFIX, len(TEXT_PREFIX), TEXT_PREFIX),
            ).fetchall()
            if not rows:
                break
            for row in rows:
                payload = row["payload"]
                label = row["label"]
                sealed = (payload if payload.startswith(TEXT_PREFIX)
                          and self._open(payload, "cache.payload")
                          else self._seal(payload, "cache.payload"))
                # Ein alter Suchbegriff kann selbst mit "enc2:" anfangen.
                # Nur ein authentifizierter Wert ist bereits verschluesselt.
                title = (label if label.startswith(TEXT_PREFIX) and self._open(label, "cache.label")
                         else self._seal(label, "cache.label"))
                growth = max(0, len(sealed.encode()) + len(title.encode())
                             - len(payload.encode()) - len(label.encode()))
                keep = fits(self.db_path.parent, growth)
                # DELETE statt UPDATE: SQLite laesst bei einem wachsenden
                # UPDATE trotz secure_delete Reste in alten Overflow-Seiten.
                conn.execute("DELETE FROM cache WHERE key=?", (row["key"],))
                if keep:
                    conn.execute("INSERT INTO cache VALUES (?, ?, ?, ?, ?, ?)",
                                 (row["key"], row["kind"], title, sealed,
                                  row["created_at"], row["expires_at"]))
                    note_written(self.db_path.parent, growth)
                # Ohne Platz entfaellt nur der Cache-Eintrag, nie ein Upload.
        conn.execute("INSERT OR REPLACE INTO privacy_state VALUES ('cache', '1')")
        return True

    @contextmanager
    def filling(self, key: str) -> Iterator[None]:
        """Gleiche Cache-Misses teilen einen Abruf, verschiedene bleiben parallel.

        Gilt fuer die Werkzeugkaesten, die diesen Profil-Cache teilen. Es
        werden weder Ergebnisse noch Schluessel anderer Profile geteilt.
        Nach dem Warten muss der Aufrufer den Cache erneut pruefen.
        """
        with self._fill_lock:
            lock, users = self._fills.get(key, (threading.Lock(), 0))
            self._fills[key] = (lock, users + 1)
        try:
            with lock:
                yield
        finally:
            with self._fill_lock:
                _, users = self._fills[key]
                if users == 1:
                    del self._fills[key]
                else:
                    self._fills[key] = (lock, users - 1)

    def _maybe_purge(self) -> None:
        """Raeumt Abgelaufenes weg -- hoechstens alle zehn Minuten je Datei (9.5.15).

        ``purge_expired`` gab es schon, nur rief es niemand regelmaessig auf:
        abgelaufene Eintraege blieben liegen, bis jemand genau sie las.
        """
        jetzt = time.monotonic()
        schluessel = str(self.db_path)
        with _PURGE_LOCK:
            if _LAST_PURGE.get(schluessel, -PURGE_EVERY) + PURGE_EVERY > jetzt:
                return
            _LAST_PURGE[schluessel] = jetzt
        with contextlib.suppress(sqlite3.Error):
            self.purge_expired()

    @contextmanager
    def _connect(self) -> Iterator[sqlite3.Connection]:
        conn = sqlite3.connect(self.db_path, timeout=10)
        conn.row_factory = sqlite3.Row
        try:
            conn.execute("PRAGMA journal_mode=WAL")
            yield conn
            conn.commit()
        finally:
            conn.close()

    # -- Cache ------------------------------------------------------------
    def get(self, key: str) -> Any | None:
        """Gibt den gecachten Wert zurueck oder `None`, wenn abgelaufen/unbekannt."""
        now = time.time()
        with self._connect() as conn, closing(conn.cursor()) as cur:
            cur.execute("SELECT payload, expires_at FROM cache WHERE key = ?", (key,))
            row = cur.fetchone()
            if row is None:
                return None
            if row["expires_at"] < now:
                cur.execute("DELETE FROM cache WHERE key = ?", (key,))
                return None
            try:
                return json.loads(self._open(row["payload"], "cache.payload"))
            except json.JSONDecodeError:
                return None

    def set(
        self,
        key: str,
        value: Any,
        *,
        kind: str = "",
        label: str = "",
        ttl: int | None = None,
    ) -> None:
        """Legt *value* (JSON-serialisierbar) unter *key* ab."""
        now = time.time()
        ttl_seconds = self.ttl_seconds if ttl is None else max(0, ttl)
        payload = self._seal(json.dumps(value, ensure_ascii=False), "cache.payload")
        label = self._seal(label, "cache.label")
        # Der Zwischenspeicher zaehlt zum 400-MB-Deckel (aquaticy/budget.py).
        # Ist kein Platz, wird eben nicht zwischengespeichert -- das kostet
        # nur einen spaeteren zweiten Abruf, nie eine Antwort.
        from aquaticy.budget import fits, note_written

        self._maybe_purge()
        groesse = len(payload.encode("utf-8")) + len(label.encode("utf-8"))
        # Seit 9.5.34 ohne Aufraeumen: ein Zwischenspeicher-Eintrag ist es nicht
        # wert, Uploads zu loeschen. Passt er nicht, entfaellt er einfach.
        if not fits(self.db_path.parent, groesse):
            return
        with self._connect() as conn:
            conn.execute(
                "INSERT OR REPLACE INTO cache (key, kind, label, payload, created_at, expires_at)"
                " VALUES (?, ?, ?, ?, ?, ?)",
                (key, kind or key.split(":", 1)[0], label, payload, now, now + ttl_seconds),
            )
        note_written(self.db_path.parent, groesse)

    def purge_expired(self) -> int:
        """Loescht abgelaufene Eintraege, gibt deren Anzahl zurueck."""
        with self._connect() as conn, closing(conn.cursor()) as cur:
            cur.execute("DELETE FROM cache WHERE expires_at < ?", (time.time(),))
            return cur.rowcount

    def clear(self, kind: str | None = None) -> int:
        """Leert den Cache (optional nur eine Art)."""
        with self._connect() as conn, closing(conn.cursor()) as cur:
            if kind:
                cur.execute("DELETE FROM cache WHERE kind = ?", (kind,))
            else:
                cur.execute("DELETE FROM cache")
            return cur.rowcount

    def stats(self) -> dict[str, int]:
        """Anzahl gueltiger Eintraege je Art."""
        with self._connect() as conn, closing(conn.cursor()) as cur:
            cur.execute(
                "SELECT kind, COUNT(*) AS n FROM cache WHERE expires_at >= ? GROUP BY kind",
                (time.time(),),
            )
            return {row["kind"]: row["n"] for row in cur.fetchall()}

    # -- Verlauf ----------------------------------------------------------
    def add_history(
        self,
        session_id: str,
        question: str,
        answer: str,
        meta: dict[str, Any] | None = None,
    ) -> int:
        """Legt einen Austausch ab.

        Raises:
            StorageFull: Das Profil hat seine 400 MB erreicht (aquaticy/budget.py).
        """
        from aquaticy.budget import ensure_room, note_written

        daten = json.dumps(meta or {}, ensure_ascii=False)
        # Verschluesselt waechst der Text um gut ein Drittel (Base64) -- mit
        # eingerechnet (9.5.34).
        groesse = (len(question.encode()) + len(answer.encode()) + len(daten.encode())) * 4 // 3
        ensure_room(self.db_path.parent, groesse)
        with self._connect() as conn, closing(conn.cursor()) as cur:
            cur.execute(
                "INSERT INTO history (session_id, created_at, question, answer, meta)"
                " VALUES (?, ?, ?, ?, ?)",
                (
                    session_id,
                    time.time(),
                    self._seal(question, "history.question"),
                    self._seal(answer, "history.answer"),
                    self._seal(daten, "history.meta"),
                ),
            )
            nummer = int(cur.lastrowid or 0)
        note_written(self.db_path.parent, groesse)
        return nummer

    def recent_history(self, limit: int = 20, session_id: str | None = None) -> list[HistoryEntry]:
        query = "SELECT * FROM history"
        params: list[Any] = []
        if session_id:
            query += " WHERE session_id = ?"
            params.append(session_id)
        query += " ORDER BY id DESC LIMIT ?"
        # "LIMIT -1" hiesse in SQLite: alles (9.5.34, "export -n -1").
        params.append(max(1, int(limit)))
        with self._connect() as conn, closing(conn.cursor()) as cur:
            cur.execute(query, params)
            rows = cur.fetchall()
        return [
            HistoryEntry(
                id=row["id"],
                session_id=row["session_id"],
                created_at=row["created_at"],
                question=self._open(row["question"], "history.question"),
                answer=self._open(row["answer"], "history.answer"),
                meta=json.loads(self._open(row["meta"], "history.meta") or "{}"),
            )
            for row in reversed(rows)
        ]

    # -- Merkzettel -------------------------------------------------------
    MAX_NOTE_LENGTH = 500

    # -- Ungelesenes ------------------------------------------------------
    def mark_unread(self, session_id: str, reason: str = "auftrag") -> None:
        """Merkt vor, dass in diesem Chat etwas Ungelesenes steht."""
        session_id = str(session_id or "").strip()
        if not session_id:
            return
        with self._connect() as conn:
            conn.execute(
                "INSERT INTO chat_unread (session_id, since, reason) VALUES (?, ?, ?) "
                "ON CONFLICT(session_id) DO UPDATE SET since = excluded.since, "
                "reason = excluded.reason",
                (session_id, time.time(), str(reason or "")[:40]),
            )

    def clear_unread(self, session_id: str) -> None:
        """Gelesen. Ab jetzt ist es ein Chat wie jeder andere."""
        session_id = str(session_id or "").strip()
        if not session_id:
            return
        with self._connect() as conn:
            conn.execute("DELETE FROM chat_unread WHERE session_id = ?", (session_id,))

    def unread_chats(self) -> set[str]:
        """Alle Chats, in denen etwas Ungelesenes steht."""
        with self._connect() as conn, closing(conn.cursor()) as cur:
            rows = cur.execute("SELECT session_id FROM chat_unread").fetchall()
        return {str(row["session_id"]) for row in rows}

    def recent_chats(self, limit: int = 30) -> list[dict[str, Any]]:
        """Die letzten Chats, juengster zuerst.

        Ein Chat ist eine Sitzung, kein einzelner Austausch. Benannt wird er
        nach der ERSTEN Frage darin -- so wie man einen Ordner nach dem
        benennt, weswegen man ihn angelegt hat.
        """
        with self._connect() as conn, closing(conn.execute(
            CHAT_SUMMARIES + " LIMIT ?", (max(0, int(limit)),),
        )) as rows:
            return [self._chat_summary(row) for row in rows]

    def _chat_summary(self, row: sqlite3.Row) -> dict[str, Any]:
        title = self._open(row["title"], "chat_titles.title").strip()
        return {
            "session_id": row["session_id"],
            "title": title or self._open(row["question"], "history.question").strip(),
            "renamed": bool(title),
            "turns": int(row["turns"]),
            "touched": float(row["touched"] or 0.0),
            "unread": bool(row["unread"]),
        }

    def search_chats(self, needle: str, limit: int = 30) -> list[dict[str, Any]]:
        """Chats, in denen *needle* vorkommt -- im Namen oder im Gespraech.

        Gesucht wird ueber beides: den Titel und den Wortlaut der Fragen und
        Antworten. Wer nach "Mietvertrag" sucht, will den Chat auch dann
        finden, wenn er "Frage zur Wohnung" heisst.

        Zurueck kommt dieselbe Form wie bei `recent_chats`, ergaenzt um
        `snippet` -- die Stelle, an der es passt. Ohne die Stelle muesste man
        jeden Treffer oeffnen, um zu sehen, warum er einer ist.
        """
        needle = " ".join(str(needle).split())
        limit = max(0, int(limit))
        if not needle or not limit:
            return []
        # Neueste Chats zuerst pruefen und nach dem Trefferlimit aufhoeren.
        # Cursor statt fetchall: weder Klartext noch verschluesselte Antworten
        # des gesamten Profils muessen auf einmal im Arbeitsspeicher liegen.
        klein = needle.casefold()
        matches: list[dict[str, Any]] = []
        with self._connect() as conn, closing(conn.execute(CHAT_SUMMARIES)) as chats:
            for row in chats:
                snippet = ""
                matched = False
                title = self._open(row["title"], "chat_titles.title").strip()
                with closing(conn.execute(
                    "SELECT question, answer FROM history WHERE session_id=? ORDER BY id",
                    (row["session_id"],),
                )) as turns:
                    for turn in turns:
                        question = self._open(turn["question"], "history.question")
                        answer = self._open(turn["answer"], "history.answer")
                        if klein in question.casefold() or klein in answer.casefold():
                            snippet = _snippet({"question": question, "answer": answer}, needle)
                            matched = True
                            break
                if matched or klein in title.casefold():
                    chat = self._chat_summary(row)
                    matches.append({**chat, "snippet": snippet})
                    if len(matches) >= limit:
                        break
        return matches

    def rename_chat(self, session_id: str, title: str) -> str:
        """Gibt einem Chat einen eigenen Namen. Leer = zurueck zur ersten Frage."""
        session_id = (session_id or "").strip()
        title = " ".join((title or "").split())[:120]
        if not session_id:
            return ""
        with self._connect() as conn, closing(conn.cursor()) as cur:
            if title:
                cur.execute(
                    "INSERT INTO chat_titles (session_id, title) VALUES (?, ?) "
                    "ON CONFLICT(session_id) DO UPDATE SET title = excluded.title",
                    (session_id, self._seal(title, "chat_titles.title")),
                )
            else:
                cur.execute("DELETE FROM chat_titles WHERE session_id = ?", (session_id,))
            conn.commit()
        return title

    def delete_chat(self, session_id: str) -> int:
        """Loescht einen Chat samt seinem eigenen Namen.

        Returns:
            Wie viele Austausche geloescht wurden.
        """
        session_id = (session_id or "").strip()
        if not session_id:
            return 0
        with self._connect() as conn, closing(conn.cursor()) as cur:
            # Die KI-Bilder und Momentaufnahmen dieses Chats gehen mit ihm
            # (9.5.15) -- bis 9.5.14 blieben die Dateien liegen. Bilder von
            # Auftraegen ("fest") gehoeren dem Auftrag und bleiben.
            cur.execute("SELECT meta FROM history WHERE session_id = ?", (session_id,))
            bilder: set[str] = set()
            for zeile in cur.fetchall():
                with contextlib.suppress(json.JSONDecodeError, TypeError, ValueError):
                    bilder |= media_ids_in(
                        json.loads(self._open(zeile["meta"], "history.meta") or "{}"))
            cur.execute("DELETE FROM history WHERE session_id = ?", (session_id,))
            removed = cur.rowcount
            cur.execute("DELETE FROM chat_titles WHERE session_id = ?", (session_id,))
            # Auch der Ungelesen-Vermerk geht mit (seit 9.5.16).
            cur.execute("DELETE FROM chat_unread WHERE session_id = ?", (session_id,))
            conn.commit()
        for media_id in bilder:
            if KEEP_MARK not in media_id:
                delete_snapshot(self.db_path.parent, media_id)
        return max(0, removed)

    def chat_history(self, session_id: str, limit: int = 100) -> list[HistoryEntry]:
        """Alle Fragen und Antworten eines Chats, aelteste zuerst.

        `recent_history` liefert schon in dieser Reihenfolge -- ein zweites
        Umdrehen wuerde den Chat rueckwaerts anzeigen.
        """
        return self.recent_history(limit=limit, session_id=session_id)

    def add_note(self, text: str) -> int:
        """Merkt sich *text* dauerhaft -- ueber Sitzungen hinweg."""
        text = " ".join(str(text).split())[: self.MAX_NOTE_LENGTH]
        if not text:
            return 0
        with self._connect() as conn, closing(conn.cursor()) as cur:
            cur.execute(
                "INSERT INTO notes (created_at, text) VALUES (?, ?)",
                (time.time(), self._seal(text, "notes.text")),
            )
            return int(cur.lastrowid or 0)

    def list_notes(self, limit: int = 50) -> list[Note]:
        """Alle Notizen, neueste zuletzt."""
        with self._connect() as conn, closing(conn.cursor()) as cur:
            cur.execute("SELECT * FROM notes ORDER BY id DESC LIMIT ?", (limit,))
            rows = cur.fetchall()
        return [
            Note(id=row["id"], created_at=row["created_at"],
                 text=self._open(row["text"], "notes.text"))
            for row in reversed(rows)
        ]

    def delete_note(self, note_id: int) -> bool:
        with self._connect() as conn, closing(conn.cursor()) as cur:
            cur.execute("DELETE FROM notes WHERE id = ?", (note_id,))
            return cur.rowcount > 0

    def clear_notes(self) -> int:
        with self._connect() as conn, closing(conn.cursor()) as cur:
            cur.execute("DELETE FROM notes")
            return cur.rowcount
