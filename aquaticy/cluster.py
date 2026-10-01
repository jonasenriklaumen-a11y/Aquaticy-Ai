"""Server-Verbund (seit 9.6.1): bis zu zehn Aquaticy-Server arbeiten zusammen.

**Was der Verbund tut.**

* **Eine Datenbank.** Die Kontendatenbank (``accounts.sqlite3``: Konten,
  Sitzungen, Geraete, Ai-guard) wird Zeile fuer Zeile auf alle Server
  gespiegelt. Jede Aenderung landet ueber Trigger in einem Protokoll
  (``_cluster_log``); die anderen Server holen es ab und spielen es ein. Die
  Profilordner der Konten (Chats, Speicher, Auftraege, Schluessel) spiegelt der
  jeweils zustaendige Server auf alle anderen -- jeder Server hat jeden
  Eintrag.
* **Lastausgleich.** Jedes Konto hat einen Heimserver. Den teilt der Master
  zu: neue und laenger untaetige Konten gehen an den Server mit der geringsten
  Auslastung. Kommt eine Anfrage an einem anderen Server an, reicht der sie
  verschluesselt an den Heimserver weiter. So schreibt immer genau ein Server
  in einen Profilordner -- es gibt keine widerspruechlichen Staende.
* **Master** ist der Server, der eingeladen hat. Er nimmt Server auf, teilt
  Konten zu und verteilt die Mitgliederliste.

**Sicherheit.**

* Gefunden wird nur im eigenen Netz (UDP-Rundruf) und nur, wenn der Schalter
  in den Dev settings an ist.
* Verbunden wird nur mit Zustimmung: Auf dem eingeladenen Server fragt das
  Terminal ``yes/no``. Danach zeigt er einen sechsstelligen Code, der auf dem
  Master eingegeben werden muss. Der Code stammt aus einem Schluesseltausch
  (X25519) -- wer sich dazwischenschaltet, bekommt einen anderen Code, und die
  Verbindung kommt nicht zustande.
* Alles, was zwischen den Servern laeuft, ist mit AES-GCM verschluesselt und
  gegen Wiederholung geschuetzt. Wer den Verbundschluessel nicht hat, kann
  weder mitlesen noch etwas einspielen.

**Ehrliche Grenzen.** Der eingeladene Server uebernimmt die Daten des Masters;
seine bisherigen Daten werden nicht vermischt, sondern unter
``cluster/backup-<Zeit>`` gesichert (Passwoerter sind mit einem Schluessel je
Installation gesalzen, zwei Kontenbestaende lassen sich nicht verlustfrei
zusammenlegen). Faellt der Master aus, arbeiten die anderen mit der letzten
Zuteilung weiter.
"""

from __future__ import annotations

import base64
import contextlib
import hashlib
import hmac
import http.client
import io
import ipaddress
import json
import os
import re
import secrets
import shutil
import socket
import sqlite3
import sys
import threading
import time
from collections.abc import Callable, Iterable, Iterator
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

#: Hoechstens so viele Server in einem Verbund.
MAX_NODES = 10
#: UDP-Port fuer das Finden im lokalen Netz.
DISCOVERY_PORT = int(os.environ.get("AQUATICY_CLUSTER_PORT", "8766") or 8766)
BEACON_SECONDS = 5.0
#: So lange bleibt ein gefundener Server in der Liste, ohne sich zu melden.
DISCOVERY_TTL = 20.0
#: Takt fuer Lebenszeichen und Abgleich.
SYNC_SECONDS = 3.0
#: Ohne Antwort so lange gilt ein Server als weg.
DEAD_AFTER = 15.0
#: Erst nach so langer Pause darf ein Konto auf einen anderen Server wandern.
IDLE_SECONDS = 600.0
#: Wie lange eine Einladung gilt.
INVITE_SECONDS = 300.0
#: Wie weit die Uhren zweier Server auseinanderliegen duerfen.
CLOCK_SKEW = 120.0
#: Stueckgroesse beim Kopieren von Dateien.
CHUNK = 1 << 20
#: Eintraege je Abruf aus dem Aenderungsprotokoll.
LOG_BATCH = 500
#: So lange bleiben Protokolleintraege liegen.
LOG_KEEP_SECONDS = 3 * 86400.0
#: Falsche Codes, bevor eine Einladung verfaellt.
CODE_TRIES = 3

#: Die Datenbank, die alle Server gemeinsam haben.
SHARED_DB = "accounts.sqlite3"
#: Dateien im Datenordner, die nie in den Verbund gehen: der Zwischenspeicher
#: des lokalen Profils und alles, was zur Datenbank gehoert (die laeuft ueber
#: das Protokoll).
_ROOT_SKIP = re.compile(r"^(aquaticy\.sqlite3|accounts\.sqlite3)(-wal|-shm|-journal)?$|\.tmp$"
                        r"|^addons\.json$")
#: Gehoert zu diesem Rechner, nicht zum Verbund: was hier installiert ist.
_NODE_LOCAL = frozenset({"cluster", "addons.json"})
_USER_RE = re.compile(r"^[A-Za-z0-9_-]{1,64}$")
_NODE_RE = re.compile(r"^[0-9a-f]{16,64}$")
_SQLITE_SUFFIXES = (".sqlite3", ".sqlite", ".db")
_SIDE_FILES = ("-wal", "-shm", "-journal")
_TMP_PREFIX = ".sync-"
#: Kopfzeilen, die nicht weitergereicht werden (gelten nur fuer eine Verbindung).
_HOP = frozenset({"connection", "keep-alive", "transfer-encoding", "content-length",
                  "proxy-connection", "te", "upgrade", "trailer"})
#: Woran der Eingang erkennt, dass das Konto inzwischen woanders zuhause ist.
MOVED_HEADER = "X-Aquaticy-Cluster"


class ClusterError(RuntimeError):
    """Ein anderer Server war nicht erreichbar oder lehnte ab."""


# -- Verschluesselung --------------------------------------------------------
def _hkdf(key: bytes, salt: bytes, info: str, length: int = 32) -> bytes:
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.kdf.hkdf import HKDF

    return HKDF(algorithm=hashes.SHA256(), length=length, salt=salt,
                info=info.encode()).derive(key)


def seal(key: bytes, data: bytes, label: str) -> bytes:
    """Verschluesselt *data*. Jeder Aufruf bekommt einen eigenen Schluessel
    (HKDF mit frischem Salz) -- so wiederholt sich keine Nonce, egal wie viele
    Nachrichten ein Verbund in seinem Leben verschickt."""
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM

    salt = os.urandom(16)
    return salt + AESGCM(_hkdf(key, salt, label)).encrypt(bytes(12), data, label.encode())


def unseal(key: bytes, blob: bytes, label: str) -> bytes:
    """Gegenstueck zu `seal`. Wirft ClusterError, wenn etwas nicht stimmt."""
    from cryptography.exceptions import InvalidTag
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM

    if len(blob) < 16 + 16:
        raise ClusterError("Nachricht zu kurz.")
    try:
        return AESGCM(_hkdf(key, blob[:16], label)).decrypt(bytes(12), blob[16:],
                                                            label.encode())
    except InvalidTag as exc:
        raise ClusterError("Nachricht ist nicht vom Verbund.") from exc


def _b64(data: bytes) -> str:
    return base64.b64encode(data).decode("ascii")


def _unb64(text: Any) -> bytes:
    try:
        return base64.b64decode(str(text or ""), validate=True)
    except (ValueError, TypeError) as exc:
        raise ClusterError("Ungueltige Daten.") from exc


class FrameWriter(io.RawIOBase):
    """Ein Datenstrom in verschluesselten, nummerierten Stuecken.

    Der Heimserver schreibt seine ganze HTTP-Antwort hier hinein -- Kopf,
    Inhalt, auch einen laufenden Ereignisstrom. Jedes ``write`` wird sofort
    ein Stueck: so kommt ein laufender Chat genauso fluessig beim Browser an
    wie ohne Verbund. Die Nummer steckt in der Nonce; vertauschte, doppelte
    oder fehlende Stuecke fallen beim Entschluesseln auf.
    """

    def __init__(self, raw: Any, key: bytes, salt: bytes, label: str) -> None:
        from cryptography.hazmat.primitives.ciphers.aead import AESGCM

        super().__init__()
        self._raw = raw
        self._aead = AESGCM(_hkdf(key, salt, label))
        self._label = label.encode()
        self._n = 0
        self._ended = False

    def writable(self) -> bool:
        return True

    def _frame(self, data: bytes, last: bool) -> None:
        nonce = self._n.to_bytes(12, "big")
        self._n += 1
        ct = self._aead.encrypt(nonce, data, self._label + (b"|end" if last else b""))
        self._raw.write(len(ct).to_bytes(4, "big") + ct)
        self._raw.flush()

    def write(self, data: Any) -> int:
        stueck = bytes(data)
        if stueck and not self._ended:
            self._frame(stueck, last=False)
        return len(stueck)

    def flush(self) -> None:
        return None

    def end(self) -> None:
        if not self._ended:
            self._ended = True
            with contextlib.suppress(OSError):
                self._frame(b"", last=True)


def read_frames(chunks: Iterable[bytes], key: bytes, salt: bytes,
                label: str) -> Iterator[bytes]:
    """Entschluesselt einen Strom aus `FrameWriter`. Endet er ohne
    Schlussstueck, wirft der Leser ClusterError (abgeschnitten)."""
    from cryptography.exceptions import InvalidTag
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM

    aead = AESGCM(_hkdf(key, salt, label))
    marke = label.encode()
    puffer = bytearray()
    n = 0
    for chunk in chunks:
        puffer.extend(chunk)
        while len(puffer) >= 4:
            laenge = int.from_bytes(puffer[:4], "big")
            if laenge > 64 * CHUNK:
                raise ClusterError("Stueck zu gross.")
            if len(puffer) < 4 + laenge:
                break
            ct = bytes(puffer[4:4 + laenge])
            del puffer[:4 + laenge]
            nonce = n.to_bytes(12, "big")
            n += 1
            try:
                yield aead.decrypt(nonce, ct, marke)
                continue
            except InvalidTag:
                pass
            try:
                aead.decrypt(nonce, ct, marke + b"|end")
            except InvalidTag as exc:
                raise ClusterError("Stueck ist nicht vom Verbund.") from exc
            return
    raise ClusterError("Antwort abgeschnitten.")


def pairing_secrets(shared: bytes, invite_id: str, pub_a: bytes, pub_b: bytes
                    ) -> tuple[bytes, str]:
    """Aus dem Schluesseltausch: der Verbindungsschluessel und der Code."""
    salt = hashlib.sha256(invite_id.encode() + pub_a + pub_b).digest()
    key = _hkdf(shared, salt, "aquaticy-pair-key")
    zahl = int.from_bytes(_hkdf(shared, salt, "aquaticy-pair-code", 8), "big") % 1_000_000
    return key, f"{zahl:06d}"


def format_code(code: str) -> str:
    return f"{code[:3]} {code[3:]}"


def lan_ip_ok(address: str) -> bool:
    """Nur das eigene Netz: privat, Tailscale (100.64/10), Link-local, lokal."""
    try:
        ip = ipaddress.ip_address(str(address).split("%", 1)[0])
    except ValueError:
        return False
    if isinstance(ip, ipaddress.IPv6Address) and ip.ipv4_mapped:
        ip = ip.ipv4_mapped
    return (ip.is_private or ip.is_loopback or ip.is_link_local
            or ip in ipaddress.ip_network("100.64.0.0/10"))


# -- Die gemeinsame Datenbank -----------------------------------------------
def _unquote(text: Any) -> Any:
    """Liest ein Literal aus SQLites ``quote()`` -- ohne es je als SQL auszufuehren."""
    if text is None:
        return None
    s = str(text)
    if s == "NULL":
        return None
    if s.startswith("'") and s.endswith("'") and len(s) >= 2:
        return s[1:-1].replace("''", "'")
    if s[:2] in ("X'", "x'") and s.endswith("'"):
        return bytes.fromhex(s[2:-1])
    try:
        return int(s)
    except ValueError:
        return float(s)


def _ident(name: str) -> str:
    return '"' + str(name).replace('"', '""') + '"'


_NOW_SQL = "((julianday('now') - 2440587.5) * 86400.0)"


class SharedDb:
    """Spiegelt eine SQLite-Datenbank Zeile fuer Zeile (siehe Moduldoku).

    Jede Tabelle bekommt drei Trigger, die jede Aenderung samt alter und
    neuer Zeile ins Protokoll schreiben. Werte stehen dort als Ergebnis von
    ``quote()``: verlustfrei auch fuer Bytes und Kommazahlen. Eingespielt wird
    mit gebundenen Parametern -- ein Wert aus dem Protokoll wird nie zu SQL.
    Waehrend des Einspielens steht ``_cluster_flag`` auf 1; die Trigger
    schweigen dann, sonst liefe jede Aenderung endlos im Kreis.
    """

    def __init__(self, path: Path) -> None:
        self.path = Path(path)
        self._lock = threading.Lock()

    def _connect(self) -> sqlite3.Connection:
        conn = sqlite3.connect(self.path, timeout=15, isolation_level=None)
        conn.execute("PRAGMA journal_mode=WAL")
        return conn

    def _tables(self, conn: sqlite3.Connection) -> dict[str, tuple[list[str], list[str]]]:
        """Tabelle -> (Spalten, Schluesselspalten)."""
        out: dict[str, tuple[list[str], list[str]]] = {}
        for (name,) in conn.execute("SELECT name FROM sqlite_master WHERE type='table'"):
            if name.startswith(("sqlite_", "_cluster_")):
                continue
            info = conn.execute(f"PRAGMA table_info({_ident(name)})").fetchall()
            cols = [str(r[1]) for r in info]
            pk = [str(r[1]) for r in sorted(info, key=lambda r: r[5]) if r[5]]
            out[str(name)] = (cols, pk)
        return out

    def _wanted(self, conn: sqlite3.Connection) -> dict[str, tuple[str, list[str], str]]:
        """Triggername -> (Tabelle, Spalten, Art) fuer den heutigen Stand."""
        out: dict[str, tuple[str, list[str], str]] = {}
        for tabelle, (cols, _) in self._tables(conn).items():
            sig = hashlib.sha1("|".join(cols).encode()).hexdigest()[:10]
            stamm = "_cl_" + hashlib.sha1(tabelle.encode()).hexdigest()[:10]
            for op in ("i", "u", "d"):
                out[f"{stamm}_{op}_{sig}"] = (tabelle, cols, op)
        return out

    def _installed(self) -> bool:
        """Schnelle Pruefung ohne Schreibsperre: steht alles schon?"""
        try:
            conn = sqlite3.connect(self.path, timeout=15)
        except sqlite3.Error:
            return False
        try:
            namen = {str(r[0]) for r in conn.execute(
                "SELECT name FROM sqlite_master WHERE type IN ('table','trigger') AND "
                "name LIKE '\\_cl%' ESCAPE '\\'")}
            if not {"_cluster_log", "_cluster_flag", "_cluster_cursor"} <= namen:
                return False
            return {n for n in namen if n.startswith("_cl_")} == set(self._wanted(conn))
        except sqlite3.Error:
            return False
        finally:
            conn.close()

    def install(self) -> None:
        """Legt Protokoll und Trigger an -- und erneuert Trigger, deren Tabelle
        sich geaendert hat. Mehrfach aufrufbar, kostet dann nur eine Abfrage."""
        if self._installed():
            return
        with self._lock:
            conn = self._connect()
            try:
                conn.execute("BEGIN IMMEDIATE")
                conn.execute("CREATE TABLE IF NOT EXISTS _cluster_log (seq INTEGER PRIMARY KEY "
                             "AUTOINCREMENT, tbl TEXT NOT NULL, op TEXT NOT NULL, old TEXT, "
                             "new TEXT, at REAL NOT NULL)")
                conn.execute("CREATE TABLE IF NOT EXISTS _cluster_flag (v INTEGER NOT NULL)")
                conn.execute("CREATE TABLE IF NOT EXISTS _cluster_cursor (node TEXT PRIMARY "
                             "KEY, seq INTEGER NOT NULL)")
                if conn.execute("SELECT COUNT(*) FROM _cluster_flag").fetchone()[0] == 0:
                    conn.execute("INSERT INTO _cluster_flag (v) VALUES (0)")
                else:
                    conn.execute("UPDATE _cluster_flag SET v=0")
                vorhanden = {str(r[0]) for r in conn.execute(
                    "SELECT name FROM sqlite_master WHERE type='trigger' AND name LIKE '_cl_%'")}
                gewollt = self._wanted(conn)
                arten = {"i": ("INSERT", None, "NEW"), "u": ("UPDATE", "OLD", "NEW"),
                         "d": ("DELETE", "OLD", None)}
                for name, (tabelle, cols, op) in gewollt.items():
                    if name in vorhanden:
                        continue
                    wann, alt, neu = arten[op]

                    def obj(prefix: str | None, cols: list[str] = cols) -> str:
                        if prefix is None:
                            return "NULL"
                        return "json_object(" + ",".join(
                            f"'{c.replace(chr(39), chr(39) * 2)}',quote({prefix}.{_ident(c)})"
                            for c in cols) + ")"

                    conn.execute(
                        f"CREATE TRIGGER {_ident(name)} AFTER {wann} ON {_ident(tabelle)} "
                        "WHEN (SELECT v FROM _cluster_flag LIMIT 1)=0 BEGIN "
                        "INSERT INTO _cluster_log (tbl, op, old, new, at) VALUES ("
                        f"'{tabelle.replace(chr(39), chr(39) * 2)}', '{op}', {obj(alt)}, "
                        f"{obj(neu)}, {_NOW_SQL}); END")
                for alt in vorhanden - set(gewollt):
                    conn.execute(f"DROP TRIGGER IF EXISTS {_ident(alt)}")
                conn.execute("COMMIT")
            except Exception:
                with contextlib.suppress(sqlite3.Error):
                    conn.execute("ROLLBACK")
                raise
            finally:
                conn.close()

    def uninstall(self) -> None:
        """Nimmt Trigger und Protokoll wieder heraus (Verbund verlassen)."""
        with self._lock:
            conn = self._connect()
            try:
                for (name,) in conn.execute(
                        "SELECT name FROM sqlite_master WHERE type='trigger' AND name LIKE "
                        "'_cl_%'").fetchall():
                    conn.execute(f"DROP TRIGGER IF EXISTS {_ident(name)}")
                for tabelle in ("_cluster_log", "_cluster_flag", "_cluster_cursor"):
                    conn.execute(f"DROP TABLE IF EXISTS {tabelle}")
            finally:
                conn.close()

    def last_seq(self) -> int:
        conn = self._connect()
        try:
            row = conn.execute("SELECT MAX(seq) FROM _cluster_log").fetchone()
            return int(row[0] or 0)
        finally:
            conn.close()

    def changes(self, since: int, limit: int = LOG_BATCH) -> dict[str, Any]:
        conn = self._connect()
        try:
            oldest = conn.execute("SELECT MIN(seq) FROM _cluster_log").fetchone()[0]
            rows = conn.execute(
                "SELECT seq, tbl, op, old, new FROM _cluster_log WHERE seq>? ORDER BY seq "
                "LIMIT ?", (int(since), int(limit))).fetchall()
            last = conn.execute("SELECT MAX(seq) FROM _cluster_log").fetchone()[0]
        finally:
            conn.close()
        return {"entries": [list(r) for r in rows], "oldest": int(oldest or 0),
                "last": int(last or 0)}

    def cursor(self, node: str) -> int:
        conn = self._connect()
        try:
            row = conn.execute("SELECT seq FROM _cluster_cursor WHERE node=?",
                               (node,)).fetchone()
            return int(row[0]) if row else 0
        finally:
            conn.close()

    def cursors(self) -> dict[str, int]:
        conn = self._connect()
        try:
            return {str(n): int(s) for n, s in conn.execute(
                "SELECT node, seq FROM _cluster_cursor")}
        finally:
            conn.close()

    def set_cursors(self, values: dict[str, int], *, clear_log: bool = False) -> None:
        conn = self._connect()
        try:
            conn.execute("BEGIN IMMEDIATE")
            conn.execute("DELETE FROM _cluster_cursor")
            for node, seq in values.items():
                conn.execute("INSERT INTO _cluster_cursor (node, seq) VALUES (?, ?)",
                             (str(node), int(seq)))
            if clear_log:
                conn.execute("DELETE FROM _cluster_log")
            conn.execute("COMMIT")
        finally:
            conn.close()

    def apply(self, origin: str, entries: list[list[Any]]) -> int:
        """Spielt Eintraege eines anderen Servers ein. Returns: wie viele."""
        if not entries:
            return 0
        with self._lock:
            conn = self._connect()
            try:
                conn.execute("BEGIN IMMEDIATE")
                conn.execute("UPDATE _cluster_flag SET v=1")
                tabellen = self._tables(conn)
                letzte = 0
                for seq, tbl, op, alt, neu in entries:
                    letzte = max(letzte, int(seq))
                    if tbl not in tabellen:
                        continue
                    cols, pk = tabellen[tbl]
                    self._apply_one(conn, tbl, cols, pk, str(op),
                                    json.loads(alt) if alt else None,
                                    json.loads(neu) if neu else None)
                conn.execute("INSERT INTO _cluster_cursor (node, seq) VALUES (?, ?) "
                             "ON CONFLICT(node) DO UPDATE SET seq=MAX(seq, excluded.seq)",
                             (origin, letzte))
                conn.execute("UPDATE _cluster_flag SET v=0")
                conn.execute("COMMIT")
                return len(entries)
            except Exception:
                with contextlib.suppress(sqlite3.Error):
                    conn.execute("ROLLBACK")
                raise
            finally:
                conn.close()

    @staticmethod
    def _apply_one(conn: sqlite3.Connection, tbl: str, cols: list[str], pk: list[str],
                   op: str, alt: dict[str, Any] | None, neu: dict[str, Any] | None) -> None:
        t = _ident(tbl)

        def werte(row: dict[str, Any]) -> tuple[list[str], list[Any]]:
            namen = [c for c in cols if c in row]
            return namen, [_unquote(row[c]) for c in namen]

        def wo(row: dict[str, Any], schluessel: list[str]) -> tuple[str, list[Any]]:
            namen = [c for c in schluessel if c in row]
            return (" AND ".join(f"{_ident(c)} IS ?" for c in namen) or "0",
                    [_unquote(row[c]) for c in namen])

        def einfuegen(row: dict[str, Any]) -> None:
            namen, vals = werte(row)
            if not namen:
                return
            art = "INSERT OR REPLACE" if pk else "INSERT"
            conn.execute(f"{art} INTO {t} ({','.join(map(_ident, namen))}) VALUES "
                         f"({','.join('?' * len(namen))})", vals)

        if op == "i" and neu:
            einfuegen(neu)
        elif op == "u" and alt and neu:
            namen, vals = werte(neu)
            setze = ",".join(f"{_ident(c)}=?" for c in namen)
            if pk:
                bedingung, params = wo(alt, pk)
                treffer = conn.execute(f"UPDATE OR REPLACE {t} SET {setze} WHERE {bedingung}",
                                       vals + params).rowcount
            else:
                bedingung, params = wo(alt, cols)
                treffer = conn.execute(
                    f"UPDATE {t} SET {setze} WHERE rowid=(SELECT rowid FROM {t} WHERE "
                    f"{bedingung} LIMIT 1)", vals + params).rowcount
            if not treffer:
                einfuegen(neu)
        elif op == "d" and alt:
            if pk:
                bedingung, params = wo(alt, pk)
                conn.execute(f"DELETE FROM {t} WHERE {bedingung}", params)
            else:
                bedingung, params = wo(alt, cols)
                conn.execute(f"DELETE FROM {t} WHERE rowid=(SELECT rowid FROM {t} WHERE "
                             f"{bedingung} LIMIT 1)", params)

    def prune(self, keep_seconds: float = LOG_KEEP_SECONDS) -> None:
        conn = self._connect()
        try:
            conn.execute("DELETE FROM _cluster_log WHERE at < ?", (time.time() - keep_seconds,))
        finally:
            conn.close()

    def user_ids(self) -> set[str]:
        conn = self._connect()
        try:
            return {str(r[0]) for r in conn.execute("SELECT id FROM users")}
        except sqlite3.Error:
            return set()
        finally:
            conn.close()


def snapshot_sqlite(path: Path, target: Path) -> None:
    """Ein in sich stimmiger Abzug einer laufenden Datenbank (Backup-API)."""
    target.parent.mkdir(parents=True, exist_ok=True)
    with contextlib.suppress(FileNotFoundError):
        target.unlink()
    quelle = sqlite3.connect(path, timeout=15)
    ziel = sqlite3.connect(target)
    try:
        quelle.backup(ziel)
    finally:
        ziel.close()
        quelle.close()


# -- Dateien -----------------------------------------------------------------
def _is_sqlite(path: Path) -> bool:
    if not path.name.endswith(_SQLITE_SUFFIXES):
        return False
    try:
        with path.open("rb") as datei:
            return datei.read(16) == b"SQLite format 3\x00"
    except OSError:
        return False


def _skip_name(name: str) -> bool:
    return name.startswith(_TMP_PREFIX) or name.endswith(_SIDE_FILES)


def manifest(folder: Path) -> dict[str, str]:
    """Relativer Pfad -> Kennung des Stands (Groesse und Zeit, bei SQLite samt WAL)."""
    out: dict[str, str] = {}
    if not folder.is_dir():
        return out
    for wurzel, ordner, dateien in os.walk(folder, followlinks=False):
        ordner[:] = [o for o in ordner if not o.startswith(_TMP_PREFIX)]
        for name in dateien:
            if _skip_name(name):
                continue
            pfad = Path(wurzel) / name
            try:
                st = pfad.lstat()
            except OSError:
                continue
            if not os.path.isfile(pfad) or os.path.islink(pfad):
                continue
            sig = f"{st.st_size}:{st.st_mtime_ns}"
            if name.endswith(_SQLITE_SUFFIXES):
                with contextlib.suppress(OSError):
                    wal = Path(str(pfad) + "-wal").stat()
                    sig += f"+{wal.st_size}:{wal.st_mtime_ns}"
            out[pfad.relative_to(folder).as_posix()] = sig
    return out


def generation(entries: dict[str, str]) -> str:
    return hashlib.sha256(json.dumps(entries, sort_keys=True).encode()).hexdigest()[:24]


def safe_rel(base: Path, rel: str) -> Path:
    """*rel* unterhalb von *base* -- sonst ClusterError (kein ``..``, kein ``/``)."""
    rel = str(rel or "")
    teile = Path(rel).parts
    if (not rel or rel.startswith(("/", "\\")) or "\\" in rel or ".." in teile
            or any(t in ("", ".") for t in rel.split("/"))):
        raise ClusterError("Ungueltiger Pfad.")
    ziel = (base / rel).resolve()
    if base.resolve() not in ziel.parents:
        raise ClusterError("Ungueltiger Pfad.")
    return ziel


def write_atomic(target: Path, data: bytes) -> None:
    """Schreibt erst daneben und tauscht dann -- nie eine halbe Datei."""
    from aquaticy.memory import secure_file

    target.parent.mkdir(parents=True, exist_ok=True)
    tmp = target.parent / f"{_TMP_PREFIX}{secrets.token_hex(6)}"
    tmp.write_bytes(data)
    secure_file(tmp)
    if target.name.endswith(_SQLITE_SUFFIXES):
        # Ein altes WAL wuerde sonst auf die neue Datenbank angewandt.
        for endung in _SIDE_FILES:
            with contextlib.suppress(FileNotFoundError):
                Path(str(target) + endung).unlink()
    os.replace(tmp, target)


# -- Zustand -----------------------------------------------------------------
@dataclass
class Hooks:
    """Was der Verbund von der Weboberflaeche braucht."""

    #: {"runs": laufende Antworten, "sessions": offene Sitzungen}
    load: Callable[[], dict[str, Any]] = lambda: {}
    #: Gibt ein Konto ab. False = es laeuft noch etwas, bleibt hier.
    release: Callable[[str], bool] = lambda user: True
    #: Dieser Server ist jetzt Heimserver des Kontos.
    adopt: Callable[[str], None] = lambda user: None
    #: Startet den Server mit den Daten des Verbunds neu.
    restart: Callable[[], None] = lambda: None
    #: Eine neue Anfrage zum Verbinden (Terminal).
    ask: Callable[[dict[str, Any]], None] | None = None


@dataclass
class Invite:
    """Eine Einladung -- je eine Seite beim Master und beim Eingeladenen."""

    id: str
    peer: dict[str, Any]
    key: bytes = b""
    code: str = ""
    status: str = "pending"  # pending, accepted, denied, joined, failed, expired
    created: float = field(default_factory=time.time)
    tries: int = 0
    message: str = ""
    #: Beim Eingeladenen: die Adresse, von der die Einladung kam.
    source: str = ""

    def public(self) -> dict[str, Any]:
        return {"id": self.id, "peer": {k: self.peer.get(k) for k in
                                        ("node", "name", "address", "port", "version")},
                "status": self.status, "message": self.message,
                "needs_code": self.status == "accepted"}


def _now() -> float:
    return time.time()


class Cluster:
    """Der Verbund aus Sicht eines Servers."""

    def __init__(self, data_dir: Path | str, host: str = "0.0.0.0", port: int = 8765,
                 hooks: Hooks | None = None, version: str = "",
                 transport: Callable[[dict[str, Any], str, bytes, float], bytes] | None = None,
                 ) -> None:
        self.data_dir = Path(data_dir)
        self.dir = self.data_dir / "cluster"
        self.host = host
        self.port = int(port)
        self.hooks = hooks or Hooks()
        self.version = version
        self._transport = transport or _http_post
        self._lock = threading.RLock()
        self._stop = threading.Event()
        self._threads: list[threading.Thread] = []
        self.dir.mkdir(parents=True, exist_ok=True)
        with contextlib.suppress(OSError):
            self.dir.chmod(0o700)
        self.node = self._load_node()
        self.state = self._load_json("state.json", {"enabled": False, "cluster": None,
                                                    "homes": {}})
        self.synced: dict[str, dict[str, str]] = self._load_json("sync.json", {})
        self.db = SharedDb(self.data_dir / SHARED_DB)
        self.discovered: dict[str, dict[str, Any]] = {}
        self.last_ok: dict[str, float] = {}
        self.loads: dict[str, dict[str, Any]] = {}
        self.invites_out: dict[str, Invite] = {}
        self.invites_in: dict[str, Invite] = {}
        self._nonces: dict[str, float] = {}
        self._activity: dict[str, float] = {}   # Master: zuletzt aktiv (verbundweit)
        self._local_seen: dict[str, float] = {}  # Eingang: zuletzt hier gesehen
        self._seen_batch: set[str] = set()
        self._gens_done: dict[str, str] = {}
        self._orphans: dict[str, float] = {}
        self._moving: set[str] = set()
        self._assign_locks: dict[str, threading.Lock] = {}
        self._snapshots: dict[str, tuple[Path, str]] = {}
        self.notice = ""

    # -- Dateien des Verbunds ---------------------------------------------
    def _load_json(self, name: str, default: Any) -> Any:
        with contextlib.suppress(OSError, ValueError):
            daten = json.loads((self.dir / name).read_text(encoding="utf-8"))
            if isinstance(daten, type(default)):
                return daten
        return default

    def _save_json(self, name: str, data: Any) -> None:
        write_atomic(self.dir / name, json.dumps(data, ensure_ascii=False).encode())

    def _save(self) -> None:
        with self._lock:
            self._save_json("state.json", self.state)

    def _load_node(self) -> dict[str, str]:
        knoten = self._load_json("node.json", {})
        if not _NODE_RE.match(str(knoten.get("id", ""))):
            knoten = {"id": secrets.token_hex(16)}
        knoten["name"] = (socket.gethostname() or "aquaticy")[:60]
        self._save_json("node.json", knoten)
        return knoten

    # -- Eigenschaften -----------------------------------------------------
    @property
    def node_id(self) -> str:
        return str(self.node["id"])

    @property
    def enabled(self) -> bool:
        return bool(self.state.get("enabled"))

    @property
    def info(self) -> dict[str, Any] | None:
        return self.state.get("cluster") or None

    @property
    def joined(self) -> bool:
        return self.info is not None and not self.info.get("joining")

    @property
    def is_master(self) -> bool:
        return self.joined and self.info.get("master") == self.node_id

    @property
    def key(self) -> bytes:
        return _unb64(self.info["secret"]) if self.info else b""

    def members(self) -> list[dict[str, Any]]:
        return list(self.info.get("members", [])) if self.info else []

    def member(self, node: str) -> dict[str, Any] | None:
        return next((m for m in self.members() if m.get("node") == node), None)

    def peers(self) -> list[dict[str, Any]]:
        return [m for m in self.members() if m.get("node") != self.node_id]

    def alive(self, node: str) -> bool:
        if node == self.node_id:
            return True
        return _now() - self.last_ok.get(node, 0.0) < DEAD_AFTER

    def master_node(self) -> str:
        return str(self.info.get("master", "")) if self.info else ""

    @property
    def homes(self) -> dict[str, str]:
        return self.state.setdefault("homes", {})

    def lan_ready(self) -> bool:
        """Hoert der Server ueberhaupt auf das Netz (``--lan``)?"""
        return self.host not in ("127.0.0.1", "localhost", "::1")

    # -- Start und Stopp ---------------------------------------------------
    def start(self) -> None:
        """Startet Finden und Abgleich -- nur, wenn der Schalter an ist."""
        if not self.enabled or self._threads:
            return
        self._stop.clear()
        if self.joined:
            with contextlib.suppress(Exception):
                self.db.install()
        for ziel, name in ((self._beacon_loop, "aquaticy-cluster-beacon"),
                           (self._listen_loop, "aquaticy-cluster-listen"),
                           (self._sync_loop, "aquaticy-cluster-sync")):
            faden = threading.Thread(target=ziel, name=name, daemon=True)
            faden.start()
            self._threads.append(faden)

    def stop(self) -> None:
        self._stop.set()
        self._threads = []

    def set_enabled(self, on: bool) -> None:
        with self._lock:
            self.state["enabled"] = bool(on)
            self._save()
        if on:
            self.start()
        else:
            self.stop()
            self.discovered.clear()

    # -- Finden im lokalen Netz -------------------------------------------
    def beacon(self) -> dict[str, Any]:
        return {"app": "aquaticy", "v": 1, "node": self.node_id, "name": self.node["name"],
                "port": self.port, "version": self.version,
                "cluster": (self.info or {}).get("id", "") if self.joined else "",
                "master": self.is_master}

    def _beacon_loop(self) -> None:
        sock = None
        while not self._stop.is_set():
            with contextlib.suppress(Exception):
                self.poll_answers()
            try:
                if sock is None:
                    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                    sock.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
                if self.lan_ready():
                    sock.sendto(json.dumps(self.beacon()).encode(),
                                ("255.255.255.255", DISCOVERY_PORT))
            except OSError:
                if sock is not None:
                    sock.close()
                sock = None
            self._stop.wait(BEACON_SECONDS)
        if sock is not None:
            sock.close()

    def _listen_loop(self) -> None:
        sock = None
        while not self._stop.is_set():
            try:
                if sock is None:
                    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
                    with contextlib.suppress(AttributeError, OSError):
                        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEPORT, 1)
                    sock.bind(("", DISCOVERY_PORT))
                    sock.settimeout(1.0)
                daten, (adresse, _) = sock.recvfrom(2048)
            except TimeoutError:
                continue
            except OSError:
                if sock is not None:
                    sock.close()
                sock = None
                self._stop.wait(5.0)
                continue
            self.note_beacon(daten, adresse)
        if sock is not None:
            sock.close()

    def note_beacon(self, daten: bytes, adresse: str) -> None:
        """Merkt sich einen gefundenen Server. Fremdes und Kaputtes faellt raus."""
        if not lan_ip_ok(adresse):
            return
        try:
            b = json.loads(daten[:2048])
        except ValueError:
            return
        if not isinstance(b, dict) or b.get("app") != "aquaticy":
            return
        knoten = str(b.get("node", ""))
        if not _NODE_RE.match(knoten) or knoten == self.node_id:
            return
        try:
            port = int(b.get("port", 0))
        except (TypeError, ValueError):
            return
        if not 0 < port < 65536:
            return
        with self._lock:
            self.discovered[knoten] = {
                "node": knoten, "name": str(b.get("name", ""))[:60], "address": adresse,
                "port": port, "version": str(b.get("version", ""))[:40],
                "cluster": str(b.get("cluster", ""))[:64], "seen": _now()}

    def found(self) -> list[dict[str, Any]]:
        jetzt = _now()
        mitglieder = {m.get("node") for m in self.members()}
        with self._lock:
            for knoten in [k for k, v in self.discovered.items()
                           if jetzt - v["seen"] > DISCOVERY_TTL]:
                self.discovered.pop(knoten, None)
            return [dict(v, member=v["node"] in mitglieder)
                    for v in sorted(self.discovered.values(), key=lambda v: v["name"])]

    # -- Nachrichten zwischen Servern -------------------------------------
    def _seen_nonce(self, nonce: str) -> bool:
        jetzt = _now()
        with self._lock:
            for alt in [n for n, t in self._nonces.items() if jetzt - t > 2 * CLOCK_SKEW]:
                self._nonces.pop(alt, None)
            if nonce in self._nonces:
                return True
            self._nonces[nonce] = jetzt
            return False

    def _wrap(self, key: bytes, op: str, args: dict[str, Any]) -> tuple[bytes, str]:
        nonce = secrets.token_hex(12)
        innen = json.dumps({"op": op, "ts": _now(), "n": nonce, "a": args}).encode()
        return json.dumps({"from": self.node_id,
                           "box": _b64(seal(key, innen, "rpc"))}).encode(), nonce

    def _unwrap(self, raw: bytes, key_for: Callable[[str], list[bytes]]
                ) -> tuple[str, str, dict, str, bytes]:
        try:
            aussen = json.loads(raw)
            absender = str(aussen["from"])
            box = _unb64(aussen["box"])
        except (ValueError, KeyError, TypeError) as exc:
            raise ClusterError("Ungueltige Nachricht.") from exc
        schluessel = key_for(absender)
        if not schluessel:
            raise ClusterError("Unbekannter Server.")
        innen: Any = None
        for key in schluessel:
            with contextlib.suppress(ClusterError):
                innen = json.loads(unseal(key, box, "rpc"))
                break
        if not isinstance(innen, dict):
            raise ClusterError("Nachricht ist nicht vom Verbund.")
        if abs(_now() - float(innen.get("ts", 0))) > CLOCK_SKEW:
            raise ClusterError("Die Uhren der Server gehen zu weit auseinander.")
        nonce = str(innen.get("n", ""))
        if not nonce or self._seen_nonce(nonce):
            raise ClusterError("Nachricht wiederholt.")
        args = innen.get("a")
        return (absender, str(innen.get("op", "")), args if isinstance(args, dict) else {},
                nonce, key)

    def _member_keys(self, node: str) -> list[bytes]:
        """Der Verbundschluessel -- kurz nach einem Wechsel auch noch der alte."""
        if not self.info or self.member(node) is None:
            return []
        keys = [self.key]
        alt = self.info.get("previous") or {}
        if alt.get("secret") and _now() - float(alt.get("until", 0)) < 0:
            keys.append(_unb64(alt["secret"]))
        return keys

    def call(self, node: str, op: str, args: dict[str, Any] | None = None,
             timeout: float = 10.0, key: bytes = b"") -> dict[str, Any]:
        """Ein verschluesselter Aufruf bei einem anderen Mitglied."""
        ziel = self.member(node)
        if ziel is None:
            raise ClusterError("Kein Mitglied.")
        schluessel = key or self.key
        body, nonce = self._wrap(schluessel, op, args or {})
        antwort = self._transport(ziel, "/cluster/rpc", body, timeout)
        daten = json.loads(unseal(schluessel, antwort, f"reply:{nonce}"))
        if isinstance(daten, dict) and daten.get("error"):
            raise ClusterError(str(daten["error"]))
        self.last_ok[node] = _now()
        return daten if isinstance(daten, dict) else {}

    # -- Eingang fuer /cluster/... ----------------------------------------
    def handle_rpc(self, raw: bytes, source_ip: str) -> bytes:
        """Beantwortet einen verschluesselten Aufruf. Antwort: verschluesselt."""
        if not self.joined or not lan_ip_ok(source_ip):
            raise ClusterError("Kein Verbund.")
        absender, op, args, nonce, key = self._unwrap(raw, self._member_keys)
        self.last_ok[absender] = _now()
        try:
            ergebnis = self._dispatch(absender, op, args)
        except ClusterError as exc:
            ergebnis = {"error": str(exc)}
        except (OSError, ValueError, KeyError, TypeError, sqlite3.Error) as exc:
            # Auch ein Platten- oder Datenbankfehler geht als Antwort zurueck --
            # sonst riss die Verbindung ab, und der andere sah nur "weg".
            ergebnis = {"error": f"{type(exc).__name__} beim Bearbeiten von „{op}“."}
        return seal(key, json.dumps(ergebnis).encode(), f"reply:{nonce}")

    def _dispatch(self, absender: str, op: str, args: dict[str, Any]) -> dict[str, Any]:
        vom_master = absender == self.master_node()
        if op == "ping":
            if self.is_master:
                jetzt = _now()
                for user in args.get("seen", [])[:5000]:
                    if _USER_RE.match(str(user)):
                        self._activity[str(user)] = jetzt
            if isinstance(args.get("load"), dict):
                self.loads[absender] = args["load"]
            antwort = {"load": self.my_load(), "version": self.version}
            if self.is_master:
                antwort["members"] = self.public_info()
                antwort["homes"] = dict(self.homes)
            return antwort
        if op == "members" and vom_master:
            self._take_members(args.get("cluster"), args.get("homes"))
            return {"ok": True}
        if op == "assign" and self.is_master:
            user = str(args.get("user", ""))
            if not _USER_RE.match(user):
                raise ClusterError("Ungueltiges Konto.")
            return {"node": self.assign(user)}
        if op == "dblog":
            return self.db.changes(int(args.get("since", 0)))
        if op == "gens":
            return {"gens": self.my_generations()}
        if op == "manifest":
            return {"files": manifest(self._user_dir(args.get("user")))}
        if op == "file":
            return self._serve_file(args)
        if op == "release" and vom_master:
            user = str(args.get("user", ""))
            return {"ok": self._release(user)}
        if op == "pull" and vom_master:
            user, von = str(args.get("user", "")), str(args.get("from", ""))
            self.sync_user(user, von, force=True)
            return {"ok": True}
        if op == "adopt" and vom_master:
            with contextlib.suppress(Exception):
                self.hooks.adopt(str(args.get("user", "")))
            return {"ok": True}
        if op == "rootlist" and self.is_master:
            return {"files": self._root_files()}
        if op == "rootfile" and self.is_master:
            return self._serve_root(args)
        if op == "leave" and self.is_master:
            self.remove(absender, notify=False)
            return {"ok": True}
        if op == "rekey" and vom_master:
            self._take_rekey(args)
            return {"ok": True}
        if op == "kick" and vom_master:
            threading.Thread(target=self._leave_local, daemon=True).start()
            return {"ok": True}
        raise ClusterError("Unbekannter Aufruf.")

    # -- Last und Zuteilung ------------------------------------------------
    def my_load(self) -> dict[str, Any]:
        try:
            last = dict(self.hooks.load() or {})
        except Exception:
            last = {}
        with contextlib.suppress(OSError, AttributeError):
            last["cpu"] = round(os.getloadavg()[0] / max(1, os.cpu_count() or 1), 3)
        return last

    def score(self, node: str) -> float:
        """Je kleiner, desto freier. Laufende Antworten zaehlen am meisten."""
        last = self.my_load() if node == self.node_id else self.loads.get(node, {})
        jetzt = _now()
        aktiv = sum(1 for u, n in list(self.homes.items())
                    if n == node and jetzt - self._activity.get(u, 0) < IDLE_SECONDS)
        return (2.0 * float(last.get("runs", 0) or 0) + aktiv
                + 2.0 * float(last.get("cpu", 0) or 0))

    def least_loaded(self) -> str:
        lebendig = [m["node"] for m in self.members() if self.alive(m["node"])]
        if not lebendig:
            return self.node_id
        # Bei Gleichstand der Master -- dort liegen die Daten ohnehin schon.
        return min(lebendig, key=lambda n: (self.score(n), n != self.master_node(), n))

    def assign(self, user: str) -> str:
        """Der Heimserver eines Kontos (nur der Master entscheidet)."""
        with self._lock:
            schloss = self._assign_locks.setdefault(user, threading.Lock())
        with schloss:
            jetzt = _now()
            zuletzt = self._activity.get(user, 0.0)
            self._activity[user] = jetzt
            jetzt_heim = self.homes.get(user, "")
            if jetzt_heim and self.alive(jetzt_heim):
                if jetzt - zuletzt < IDLE_SECONDS:
                    return jetzt_heim
                bester = self.least_loaded()
                if bester == jetzt_heim or self.score(jetzt_heim) - self.score(bester) < 1.0:
                    return jetzt_heim
                return self._move(user, jetzt_heim, bester)
            bester = self.least_loaded()
            # Ohne Heimserver liegen die Daten beim Master (dort war das Konto,
            # bevor es den Verbund gab).
            quelle = jetzt_heim or self.master_node()
            if quelle and quelle != bester and self.alive(quelle):
                return self._move(user, quelle, bester)
            self._set_home(user, bester)
            return bester

    def _move(self, user: str, alt: str, neu: str) -> str:
        """Gibt ein Konto von *alt* an *neu*: abgeben, nachziehen, umschreiben."""
        try:
            if alt == self.node_id:
                if not self._release(user):
                    return alt
            elif not self.call(alt, "release", {"user": user}).get("ok"):
                return alt
            if neu == self.node_id:
                self.sync_user(user, alt, force=True)
            else:
                self.call(neu, "pull", {"user": user, "from": alt}, timeout=300.0)
        except (ClusterError, OSError, ValueError):
            with self._lock:
                self._moving.discard(user)
            return alt if self.alive(alt) else neu
        self._set_home(user, neu)
        return neu

    def _set_home(self, user: str, node: str) -> None:
        with self._lock:
            self.homes[user] = node
            self._moving.discard(user)
            self._save()
        if node == self.node_id:
            with contextlib.suppress(Exception):
                self.hooks.adopt(user)
        self.broadcast()
        if node != self.node_id:
            with contextlib.suppress(ClusterError, OSError, ValueError):
                self.call(node, "adopt", {"user": user})

    def _release(self, user: str) -> bool:
        if not _USER_RE.match(user):
            return False
        with self._lock:
            self._moving.add(user)
        try:
            frei = bool(self.hooks.release(user))
        except Exception:
            frei = False
        if not frei:
            with self._lock:
                self._moving.discard(user)
        return frei

    def is_home(self, user: str) -> bool:
        """Darf dieser Server das Konto gerade bedienen?"""
        if not self.joined:
            return True
        if user in self._moving:
            return False
        heim = self.homes.get(user, "")
        if heim:
            return heim == self.node_id or not self.alive(heim)
        return self.is_master or not self.alive(self.master_node())

    def home_for(self, user: str) -> str:
        """Wo ein Konto bedient wird -- aus Sicht des Eingangs."""
        jetzt = _now()
        zuletzt = self._local_seen.get(user, 0.0)
        self._local_seen[user] = jetzt
        with self._lock:
            self._seen_batch.add(user)
        heim = self.homes.get(user, "")
        if heim and self.alive(heim) and jetzt - zuletzt < IDLE_SECONDS / 2:
            return heim
        if self.is_master:
            return self.assign(user)
        try:
            heim = str(self.call(self.master_node(), "assign", {"user": user},
                                 timeout=320.0).get("node", ""))
        except (ClusterError, OSError, ValueError):
            return heim if heim and self.alive(heim) else self.node_id
        if self.member(heim) is None:
            return self.node_id
        with self._lock:
            self.homes[user] = heim
        return heim

    def forget_home(self, user: str) -> None:
        self._local_seen.pop(user, None)

    # -- Mitgliederliste ---------------------------------------------------
    def public_info(self) -> dict[str, Any]:
        """Die Mitgliederliste ohne Schluessel -- die gehen nur ueber "rekey"."""
        info = dict(self.info or {})
        info.pop("secret", None)
        info.pop("previous", None)
        return info

    def broadcast(self) -> None:
        """Der Master verteilt Mitglieder und Zuteilung an alle."""
        if not self.is_master:
            return
        for m in self.peers():
            with contextlib.suppress(ClusterError, OSError, ValueError):
                self.call(m["node"], "members", {"cluster": self.public_info(),
                                                 "homes": dict(self.homes)}, timeout=5.0)

    def _take_members(self, info: Any, homes: Any) -> None:
        if not isinstance(info, dict) or not self.info:
            return
        if info.get("id") != self.info.get("id"):
            return
        if int(info.get("version", 0)) < int(self.info.get("version", 0)):
            return
        if not any(m.get("node") == self.node_id for m in info.get("members", [])):
            threading.Thread(target=self._leave_local, daemon=True).start()
            return
        with self._lock:
            neu = dict(info)
            neu.pop("joining", None)
            # Schluessel kommen nie ueber diesen Weg -- nur ueber "rekey".
            neu["secret"] = self.info["secret"]
            if self.info.get("previous"):
                neu["previous"] = self.info["previous"]
            else:
                neu.pop("previous", None)
            self.state["cluster"] = neu
            if isinstance(homes, dict):
                self.state["homes"] = {str(u): str(n) for u, n in homes.items()
                                       if _USER_RE.match(str(u))}
            self._save()

    def remove(self, node: str, notify: bool = True) -> None:
        """Master: nimmt einen Server aus dem Verbund."""
        if not self.is_master or node == self.node_id:
            return
        if notify:
            with contextlib.suppress(ClusterError, OSError, ValueError):
                self.call(node, "kick", {}, timeout=5.0)
        with self._lock:
            info = self.state["cluster"]
            info["members"] = [m for m in info["members"] if m.get("node") != node]
            info["version"] = int(info.get("version", 0)) + 1
            for user in [u for u, n in self.homes.items() if n == node]:
                self.homes.pop(user, None)
            self.state.get("links", {}).pop(node, None)
            self._save()
        self.broadcast()
        self._rekey()

    def _rekey(self) -> None:
        """Master: neuer Verbundschluessel, nachdem ein Server gegangen ist.

        Jedes verbliebene Mitglied bekommt ihn verschluesselt mit seinem eigenen
        Verbindungsschluessel aus dem Schluesseltausch -- den kennt der
        entfernte Server nicht, auch wenn er den alten Verbundschluessel hat.
        """
        neu = secrets.token_bytes(32)
        links = self.state.get("links", {})
        for m in self.peers():
            link = links.get(m["node"])
            if not link:
                continue
            with contextlib.suppress(ClusterError, OSError, ValueError):
                self.call(m["node"], "rekey",
                          {"box": _b64(seal(_unb64(link), neu, "rekey"))}, timeout=5.0)
        with self._lock:
            info = self.state["cluster"]
            info["previous"] = {"secret": info["secret"], "until": _now() + CLOCK_SKEW}
            info["secret"] = _b64(neu)
            self._save()

    def _take_rekey(self, args: dict[str, Any]) -> None:
        link = self.state.get("link")
        if not link or not self.info:
            raise ClusterError("Kein Verbindungsschluessel.")
        neu = unseal(_unb64(link), _unb64(args.get("box")), "rekey")
        if len(neu) != 32:
            raise ClusterError("Ungueltiger Schluessel.")
        with self._lock:
            info = self.state["cluster"]
            info["previous"] = {"secret": info["secret"], "until": _now() + CLOCK_SKEW}
            info["secret"] = _b64(neu)
            self._save()

    def leave(self) -> None:
        """Verlaesst den Verbund. Die Daten bleiben als eigener Bestand hier."""
        if not self.info:
            return
        if self.is_master:
            for m in self.peers():
                with contextlib.suppress(ClusterError, OSError, ValueError):
                    self.call(m["node"], "kick", {}, timeout=5.0)
        else:
            with contextlib.suppress(ClusterError, OSError, ValueError):
                self.call(self.master_node(), "leave", {}, timeout=5.0)
        self._leave_local()

    def _leave_local(self) -> None:
        with self._lock:
            self.state["cluster"] = None
            self.state["homes"] = {}
            self.state.pop("links", None)
            self.state.pop("link", None)
            self._save()
            self.synced = {}
            self._save_json("sync.json", {})
        with contextlib.suppress(Exception):
            self.db.uninstall()
        self.notice = "Dieser Server arbeitet wieder allein."
        print("  [Verbund] Dieser Server ist nicht mehr im Verbund und arbeitet allein.")

    # -- Abgleich ----------------------------------------------------------
    def _sync_loop(self) -> None:
        runde = 0
        while not self._stop.wait(SYNC_SECONDS):
            if not self.joined:
                continue
            runde += 1
            try:
                self.sync_once(full=runde % 3 == 0)
            except Exception as exc:  # pragma: no cover - der Takt darf nie sterben
                print(f"  [Verbund] Abgleich: {type(exc).__name__}: {exc}")
            if runde % 1200 == 0:
                with contextlib.suppress(Exception):
                    self.db.prune()

    def sync_once(self, full: bool = True) -> None:
        """Ein Durchgang: Lebenszeichen, Datenbank, Profilordner."""
        with contextlib.suppress(Exception):
            self.db.install()
        with self._lock:
            gesehen, self._seen_batch = list(self._seen_batch), set()
        for m in self.peers():
            knoten = m["node"]
            try:
                antwort = self.call(knoten, "ping", {"load": self.my_load(),
                                                     "seen": gesehen}, timeout=5.0)
            except (ClusterError, OSError, ValueError):
                continue
            if isinstance(antwort.get("load"), dict):
                self.loads[knoten] = antwort["load"]
            if knoten == self.master_node() and antwort.get("members"):
                self._take_members(antwort.get("members"), antwort.get("homes"))
            if not self.joined:
                return
            try:
                self.pull_db(knoten)
            except (ClusterError, OSError, ValueError, sqlite3.Error) as exc:
                self.notice = f"Abgleich mit {m.get('name') or knoten[:8]}: {exc}"
        if full:
            for m in self.peers():
                if self.alive(m["node"]):
                    self.pull_files(m["node"])
            self._sweep_orphans()

    def pull_db(self, node: str) -> int:
        gesamt = 0
        for _ in range(200):
            seit = self.db.cursor(node)
            daten = self.call(node, "dblog", {"since": seit}, timeout=15.0)
            eintraege = daten.get("entries") or []
            if seit and daten.get("oldest") and int(daten["oldest"]) > seit + 1 and eintraege:
                self.notice = ("Ein Server war zu lange weg; ältere Änderungen fehlen. "
                               "Am sichersten: neu verbinden.")
            if not eintraege:
                break
            gesamt += self.db.apply(node, eintraege)
            if len(eintraege) < LOG_BATCH:
                break
        return gesamt

    def my_generations(self) -> dict[str, str]:
        """Stand der Konten, fuer die dieser Server zustaendig ist.

        Kurz zwischengespeichert: bei zehn Servern fragen neun im selben Takt.
        """
        with self._lock:
            alt = getattr(self, "_gens_cache", None)
            if alt is not None and _now() - alt[0] < 2.0:
                return dict(alt[1])
        out = self._generations()
        with self._lock:
            self._gens_cache = (_now(), out)
        return dict(out)

    def _generations(self) -> dict[str, str]:
        out: dict[str, str] = {}
        users = self.data_dir / "users"
        if not users.is_dir():
            return out
        for ordner in users.iterdir():
            user = ordner.name
            if not ordner.is_dir() or not _USER_RE.match(user):
                continue
            heim = self.homes.get(user, "")
            if heim == self.node_id or (not heim and self.is_master):
                out[user] = generation(manifest(ordner))
        return out

    def pull_files(self, node: str) -> None:
        try:
            stände = self.call(node, "gens", {}, timeout=30.0).get("gens") or {}
        except (ClusterError, OSError, ValueError):
            return
        for user, gen in stände.items():
            if not _USER_RE.match(str(user)) or self.homes.get(user) == self.node_id:
                continue
            if self._gens_done.get(user) == gen:
                continue
            with contextlib.suppress(ClusterError, OSError, ValueError):
                self.sync_user(user, node)
                self._gens_done[user] = gen

    def _user_dir(self, user: Any) -> Path:
        user = str(user or "")
        if not _USER_RE.match(user):
            raise ClusterError("Ungueltiges Konto.")
        return self.data_dir / "users" / user

    def sync_user(self, user: str, node: str, force: bool = False) -> None:
        """Holt den Profilordner eines Kontos vom zustaendigen Server."""
        if node == self.node_id or (self.homes.get(user) == self.node_id and not force):
            return
        ordner = self._user_dir(user)
        fern = self.call(node, "manifest", {"user": user}, timeout=30.0).get("files") or {}
        bekannt = dict(self.synced.get(user, {}))
        for rel, sig in fern.items():
            if bekannt.get(rel) == sig and (ordner / rel).exists():
                continue
            ziel = safe_rel(ordner, rel)
            daten = self._fetch(node, {"user": user, "rel": rel, "sig": sig})
            if daten is None:
                continue  # hat sich gerade geaendert -- naechste Runde
            write_atomic(ziel, daten)
            bekannt[rel] = sig
        if ordner.is_dir():
            for rel in list(manifest(ordner)):
                if rel not in fern:
                    with contextlib.suppress(OSError):
                        safe_rel(ordner, rel).unlink()
                    bekannt.pop(rel, None)
        with self._lock:
            self.synced[user] = {r: s for r, s in bekannt.items() if r in fern}
            self._save_json("sync.json", self.synced)

    def _fetch(self, node: str, args: dict[str, Any], op: str = "file") -> bytes | None:
        teile: list[bytes] = []
        versatz = 0
        while True:
            antwort = self.call(node, op, dict(args, offset=versatz), timeout=60.0)
            if antwort.get("changed"):
                return None
            stueck = _unb64(antwort.get("data", ""))
            teile.append(stueck)
            versatz += len(stueck)
            if antwort.get("eof") or not stueck:
                return b"".join(teile)

    def _serve_file(self, args: dict[str, Any]) -> dict[str, Any]:
        ordner = self._user_dir(args.get("user"))
        rel = str(args.get("rel", ""))
        pfad = safe_rel(ordner, rel)
        sig = manifest(ordner).get(rel)
        if sig is None or (args.get("sig") and sig != args.get("sig")):
            return {"changed": True}
        return self._chunk(pfad, f"{args.get('user')}/{rel}", sig, int(args.get("offset", 0)))

    def _chunk(self, pfad: Path, schluessel: str, sig: str, versatz: int) -> dict[str, Any]:
        quelle = pfad
        if _is_sqlite(pfad):
            # Eine laufende Datenbank wird nie roh kopiert, sondern als Abzug.
            with self._lock:
                abzug = self._snapshots.get(schluessel)
            if abzug is None or abzug[1] != sig or not abzug[0].exists():
                ziel = self.dir / "tmp" / f"{hashlib.sha1(schluessel.encode()).hexdigest()}.db"
                snapshot_sqlite(pfad, ziel)
                abzug = (ziel, sig)
                with self._lock:
                    self._snapshots[schluessel] = abzug
            quelle = abzug[0]
        with quelle.open("rb") as datei:
            datei.seek(max(0, versatz))
            daten = datei.read(CHUNK)
            eof = datei.tell() >= os.fstat(datei.fileno()).st_size
        if eof and quelle != pfad:
            with self._lock:
                self._snapshots.pop(schluessel, None)
            with contextlib.suppress(OSError):
                quelle.unlink()
        return {"data": _b64(daten), "eof": eof}

    def _sweep_orphans(self) -> None:
        """Profilordner geloeschter Konten verschwinden auch auf den Kopien."""
        users = self.data_dir / "users"
        if not users.is_dir():
            return
        bekannt = self.db.user_ids()
        jetzt = _now()
        for ordner in users.iterdir():
            user = ordner.name
            if (not ordner.is_dir() or not _USER_RE.match(user) or user in bekannt
                    or self.homes.get(user) == self.node_id or self.is_master):
                self._orphans.pop(user, None)
                continue
            seit = self._orphans.setdefault(user, jetzt)
            if jetzt - seit > 60.0:
                shutil.rmtree(ordner, ignore_errors=True)
                self._orphans.pop(user, None)
                self.synced.pop(user, None)

    # -- Beitritt: Daten des Masters uebernehmen --------------------------
    def _root_files(self) -> list[str]:
        out = []
        for eintrag in self.data_dir.iterdir():
            if eintrag.is_file() and not eintrag.is_symlink() and not _ROOT_SKIP.search(
                    eintrag.name) and not _skip_name(eintrag.name):
                out.append(eintrag.name)
        return [*sorted(out), SHARED_DB]

    def _serve_root(self, args: dict[str, Any]) -> dict[str, Any]:
        name = str(args.get("name", ""))
        if name not in self._root_files():
            raise ClusterError("Unbekannte Datei.")
        pfad = self.data_dir / name
        if name == SHARED_DB:
            return self._chunk(pfad, "@" + name, str(args.get("sig") or "join"),
                               int(args.get("offset", 0)))
        return self._chunk(pfad, "@" + name, "", int(args.get("offset", 0)))

    def complete_join(self) -> None:
        """Holt beim Beitritt alle gemeinsamen Daten und startet neu.

        Die bisherigen Daten dieses Servers wandern unter cluster/backup-<Zeit>
        -- geloescht wird nichts.
        """
        master = self.master_node()
        staging = self.dir / "staging"
        shutil.rmtree(staging, ignore_errors=True)
        staging.mkdir(parents=True)
        kennung = secrets.token_hex(4)
        for name in self.call(master, "rootlist", {}, timeout=30.0, key=self.key).get(
                "files", []):
            name = str(name)
            if "/" in name or "\\" in name or name.startswith("."):
                continue
            daten = self._fetch(master, {"name": name, "sig": kennung}, op="rootfile")
            if daten is not None:
                (staging / name).write_bytes(daten)
        db = SharedDb(staging / SHARED_DB)
        db.install()
        # Was der Master schon von den anderen eingespielt hat, steht in seinem
        # Abzug -- seine Zeiger gelten damit auch hier. Fuer ihn selbst: bis zu
        # seinem letzten eigenen Eintrag im Abzug. Sein Protokoll ist seins.
        zeiger = db.cursors()
        zeiger.pop(self.node_id, None)
        zeiger[master] = db.last_seq()
        db.set_cursors(zeiger, clear_log=True)
        sicherung = self.dir / f"backup-{time.strftime('%Y%m%d-%H%M%S')}"
        sicherung.mkdir(parents=True)
        for eintrag in list(self.data_dir.iterdir()):
            if eintrag.name in _NODE_LOCAL:
                continue
            shutil.move(str(eintrag), str(sicherung / eintrag.name))
        for eintrag in staging.iterdir():
            shutil.move(str(eintrag), str(self.data_dir / eintrag.name))
        shutil.rmtree(staging, ignore_errors=True)
        (self.data_dir / "users").mkdir(exist_ok=True)
        with self._lock:
            self.state["cluster"].pop("joining", None)
            self.state["enabled"] = True
            self._save()
            self.synced = {}
            self._save_json("sync.json", {})
        print(f"  [Verbund] Beigetreten. Die bisherigen Daten liegen unter {sicherung}.")
        self.hooks.restart()

    # -- Einladen (Master-Seite) ------------------------------------------
    def invite(self, address: str, port: int) -> Invite:
        """Schickt eine Einladung an einen anderen Server."""
        from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey
        from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

        if self.joined and not self.is_master:
            raise ClusterError("Einladen kann nur der Master des Verbunds.")
        if len(self.members()) >= MAX_NODES:
            raise ClusterError(f"Ein Verbund hat höchstens {MAX_NODES} Server.")
        if not lan_ip_ok(address):
            raise ClusterError("Nur Server im eigenen Netz lassen sich verbinden.")
        if not self.lan_ready():
            raise ClusterError("Dieser Server ist nur lokal erreichbar. Starte ihn mit "
                               "„aquaticy web --lan“.")
        privat = X25519PrivateKey.generate()
        oeffentlich = privat.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)
        einladung = Invite(id=secrets.token_hex(16),
                           peer={"address": address, "port": int(port)})
        ziel = {"address": address, "port": int(port)}
        antwort = json.loads(self._transport(ziel, "/cluster/hello", json.dumps({
            "id": einladung.id, "node": self.node_id, "name": self.node["name"],
            "port": self.port, "version": self.version, "pub": _b64(oeffentlich)}).encode(),
            10.0))
        if antwort.get("error"):
            raise ClusterError(str(antwort["error"]))
        fremd = _unb64(antwort.get("pub"))
        knoten = str(antwort.get("node", ""))
        if not _NODE_RE.match(knoten) or len(fremd) != 32:
            raise ClusterError("Der andere Server hat ungültig geantwortet.")
        if self.member(knoten) is not None:
            raise ClusterError("Dieser Server ist schon im Verbund.")
        from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PublicKey

        geteilt = privat.exchange(X25519PublicKey.from_public_bytes(fremd))
        einladung.key, einladung.code = pairing_secrets(geteilt, einladung.id, oeffentlich,
                                                        fremd)
        einladung.peer.update(node=knoten, name=str(antwort.get("name", ""))[:60],
                              version=str(antwort.get("version", ""))[:40])
        with self._lock:
            self.invites_out[einladung.id] = einladung
        threading.Thread(target=self._watch_invite, args=(einladung,), daemon=True).start()
        return einladung

    def _watch_invite(self, einladung: Invite) -> None:
        """Fragt nach, bis der andere Server im Terminal geantwortet hat."""
        ziel = {"address": einladung.peer["address"], "port": einladung.peer["port"]}
        while einladung.status == "pending" and not self._stop.is_set():
            if _now() - einladung.created > INVITE_SECONDS:
                einladung.status = "expired"
                einladung.message = "Keine Antwort — die Einladung ist abgelaufen."
                return
            time.sleep(2.0)
            try:
                antwort = json.loads(self._transport(ziel, "/cluster/hello-status",
                                                     json.dumps({"id": einladung.id}).encode(),
                                                     10.0))
            except (OSError, ValueError, ClusterError):
                continue
            status = str(antwort.get("status", ""))
            if status == "accepted":
                einladung.status = "accepted"
                einladung.message = ("Angenommen. Gib jetzt den Code ein, den der andere "
                                     "Server im Terminal zeigt.")
            elif status in ("denied", "expired"):
                einladung.status = "denied" if status == "denied" else "expired"
                einladung.message = ("Der andere Server hat abgelehnt." if status == "denied"
                                     else "Die Einladung ist abgelaufen.")

    def confirm(self, invite_id: str, code: str) -> Invite:
        """Master: Code vom anderen Server pruefen -- und erst dann Daten freigeben."""
        with self._lock:
            einladung = self.invites_out.get(str(invite_id))
        if einladung is None:
            raise ClusterError("Diese Einladung gibt es nicht mehr.")
        if einladung.status != "accepted":
            raise ClusterError("Der andere Server hat noch nicht angenommen.")
        eingabe = re.sub(r"\D", "", str(code or ""))
        if not hmac.compare_digest(eingabe, einladung.code):
            einladung.tries += 1
            if einladung.tries >= CODE_TRIES:
                einladung.status = "failed"
                einladung.message = "Dreimal ein falscher Code — die Einladung ist verfallen."
            raise ClusterError("Der Code stimmt nicht.")
        with self._lock:
            if not self.info:
                self.state["cluster"] = {
                    "id": secrets.token_hex(12), "master": self.node_id,
                    "secret": _b64(secrets.token_bytes(32)), "version": 1,
                    "members": [{"node": self.node_id, "name": self.node["name"],
                                 "address": "", "port": self.port}]}
                self.state["homes"] = {}
                self._save()
            if len(self.members()) >= MAX_NODES:
                raise ClusterError(f"Ein Verbund hat höchstens {MAX_NODES} Server.")
        self.db.install()
        neu = {"node": einladung.peer["node"], "name": einladung.peer.get("name", ""),
               "address": einladung.peer["address"], "port": einladung.peer["port"]}
        info = dict(self.info)
        info.pop("previous", None)
        info["members"] = [*info["members"], neu]
        info["version"] = int(info.get("version", 0)) + 1
        paket = seal(einladung.key, json.dumps({"cluster": info}).encode(), "join")
        ziel = {"address": einladung.peer["address"], "port": einladung.peer["port"]}
        antwort = json.loads(self._transport(ziel, "/cluster/hello-join", json.dumps({
            "id": einladung.id, "box": _b64(paket)}).encode(), 15.0))
        if not antwort.get("box"):
            einladung.status = "failed"
            einladung.message = str(antwort.get("error") or "Der Beitritt ist gescheitert.")
            raise ClusterError(einladung.message)
        bestaetigt = json.loads(unseal(einladung.key, _unb64(antwort["box"]), "joined"))
        with self._lock:
            info = self.state["cluster"]
            for m in info["members"]:
                if m["node"] == self.node_id and bestaetigt.get("you"):
                    m["address"] = str(bestaetigt["you"])[:64]
            info["members"] = [*info["members"], neu]
            info["version"] = int(info.get("version", 0)) + 1
            self.state.setdefault("links", {})[neu["node"]] = _b64(einladung.key)
            self._save()
        self.last_ok[neu["node"]] = _now()
        einladung.status = "joined"
        einladung.message = "Verbunden. Der andere Server übernimmt jetzt die Daten."
        self.start()
        threading.Thread(target=self.broadcast, daemon=True).start()
        return einladung

    # -- Eingeladen werden (Seite des anderen Servers) --------------------
    def handle_hello(self, payload: dict[str, Any], source_ip: str) -> dict[str, Any]:
        from cryptography.hazmat.primitives.asymmetric.x25519 import (
            X25519PrivateKey,
            X25519PublicKey,
        )
        from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

        if not self.enabled:
            return {"error": "Auf diesem Server ist der Verbund ausgeschaltet."}
        if self.info:
            return {"error": "Dieser Server ist schon in einem Verbund."}
        if not lan_ip_ok(source_ip):
            return {"error": "Nur aus dem eigenen Netz."}
        einladung_id = str(payload.get("id", ""))
        knoten = str(payload.get("node", ""))
        fremd = _unb64(payload.get("pub"))
        if not re.fullmatch(r"[0-9a-f]{32}", einladung_id) or not _NODE_RE.match(knoten) \
                or len(fremd) != 32:
            return {"error": "Ungültige Einladung."}
        with self._lock:
            offen = [e for e in self.invites_in.values() if e.status == "pending"
                     and _now() - e.created < INVITE_SECONDS]
            if len(offen) >= 3:
                return {"error": "Zu viele offene Anfragen."}
            if einladung_id in self.invites_in:
                return {"error": "Diese Einladung ist schon da."}
        privat = X25519PrivateKey.generate()
        oeffentlich = privat.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)
        geteilt = privat.exchange(X25519PublicKey.from_public_bytes(fremd))
        key, code = pairing_secrets(geteilt, einladung_id, fremd, oeffentlich)
        try:
            port = int(payload.get("port", 0))
        except (TypeError, ValueError):
            port = 0
        einladung = Invite(id=einladung_id, key=key, code=code, source=source_ip, peer={
            "node": knoten, "name": str(payload.get("name", ""))[:60], "address": source_ip,
            "port": port if 0 < port < 65536 else 0,
            "version": str(payload.get("version", ""))[:40]})
        with self._lock:
            self.invites_in[einladung_id] = einladung
        self._write_pending()
        if self.hooks.ask is not None:
            with contextlib.suppress(Exception):
                self.hooks.ask(einladung.public())
        return {"node": self.node_id, "name": self.node["name"], "version": self.version,
                "pub": _b64(oeffentlich)}

    def answer(self, invite_id: str, yes: bool) -> Invite | None:
        """Antwort aus dem Terminal: yes oder no."""
        with self._lock:
            einladung = self.invites_in.get(str(invite_id))
        if einladung is None or einladung.status != "pending":
            return einladung
        if _now() - einladung.created > INVITE_SECONDS:
            einladung.status = "expired"
        else:
            einladung.status = "accepted" if yes else "denied"
        self._write_pending()
        return einladung

    def hello_status(self, payload: dict[str, Any], source_ip: str) -> dict[str, Any]:
        with self._lock:
            einladung = self.invites_in.get(str(payload.get("id", "")))
        if einladung is None or einladung.source != source_ip:
            return {"status": "unknown"}
        if einladung.status == "pending" and _now() - einladung.created > INVITE_SECONDS:
            einladung.status = "expired"
        return {"status": einladung.status}

    def hello_join(self, payload: dict[str, Any], source_ip: str) -> dict[str, Any]:
        with self._lock:
            einladung = self.invites_in.get(str(payload.get("id", "")))
        if einladung is None or einladung.source != source_ip \
                or einladung.status != "accepted" or self.info:
            return {"error": "Keine angenommene Einladung."}
        try:
            paket = json.loads(unseal(einladung.key, _unb64(payload.get("box")), "join"))
        except (ClusterError, ValueError):
            einladung.status = "failed"
            return {"error": "Der Schlüssel passt nicht."}
        info = paket.get("cluster") if isinstance(paket, dict) else None
        if (not isinstance(info, dict) or not _NODE_RE.match(str(info.get("master", "")))
                or len(_unb64(info.get("secret"))) != 32
                or not any(m.get("node") == self.node_id for m in info.get("members", []))):
            einladung.status = "failed"
            return {"error": "Ungültige Verbunddaten."}
        for m in info["members"]:
            if m.get("node") == info["master"]:
                m["address"] = source_ip
                m["port"] = einladung.peer.get("port") or m.get("port")
        info["joining"] = True
        info.pop("previous", None)
        with self._lock:
            self.state["cluster"] = info
            self.state["homes"] = {}
            self.state["link"] = _b64(einladung.key)
            self._save()
        einladung.status = "joined"
        self._write_pending()
        self.last_ok[info["master"]] = _now()
        threading.Thread(target=self._join_worker, daemon=True).start()
        return {"box": _b64(seal(einladung.key, json.dumps({"ok": True, "you": source_ip})
                                 .encode(), "joined"))}

    def _join_worker(self) -> None:
        time.sleep(1.0)  # der Master traegt uns erst nach unserer Antwort ein
        for versuch in range(5):
            try:
                self.complete_join()
                return
            except (ClusterError, OSError, ValueError, sqlite3.Error) as exc:
                print(f"  [Verbund] Daten holen ({versuch + 1}/5): {exc}")
                time.sleep(3.0 * (versuch + 1))
        with self._lock:
            self.state["cluster"] = None
            self._save()
        print("  [Verbund] Beitritt gescheitert -- dieser Server arbeitet weiter allein.")

    def _write_pending(self) -> None:
        """Offene Anfragen fuer `aquaticy cluster` (wenn kein Terminal offen ist)."""
        with self._lock:
            offen = [dict(e.public(), code=format_code(e.code) if e.status == "accepted"
                          else "") for e in self.invites_in.values()
                     if e.status in ("pending", "accepted")
                     and _now() - e.created < INVITE_SECONDS]
        with contextlib.suppress(OSError):
            self._save_json("pending.json", offen)

    def poll_answers(self) -> None:
        """Antworten, die `aquaticy cluster` in den Ordner gelegt hat."""
        ordner = self.dir / "answers"
        if not ordner.is_dir():
            return
        for datei in ordner.glob("*.json"):
            with contextlib.suppress(OSError, ValueError):
                daten = json.loads(datei.read_text(encoding="utf-8"))
                einladung = self.answer(str(daten.get("id", "")), daten.get("answer") == "yes")
                if einladung is not None and einladung.status == "accepted":
                    print(f"  [Verbund] Angenommen. Code für den Master: "
                          f"{format_code(einladung.code)}")
            with contextlib.suppress(OSError):
                datei.unlink()

    # -- Weiterleiten an den Heimserver -----------------------------------
    def forward(self, handler: Any, user: str, body: bytes, https: bool,
                client_ip: str) -> bool:
        """Reicht eine Anfrage an den Heimserver weiter. False = selbst bedienen."""
        for _ in range(2):
            heim = self.home_for(user)
            if not heim or heim == self.node_id:
                return False
            ziel = self.member(heim)
            if ziel is None:
                return False
            try:
                ergebnis = self._proxy_once(handler, ziel, user, body, https, client_ip)
            except (ClusterError, OSError, ValueError):
                self.last_ok.pop(heim, None)
                self.forget_home(user)
                continue
            if ergebnis == "moved":
                self.forget_home(user)
                with self._lock:
                    self.homes.pop(user, None)
                continue
            return True
        return False

    def _proxy_once(self, handler: Any, ziel: dict[str, Any], user: str, body: bytes,
                    https: bool, client_ip: str) -> str:
        import httpx

        kopf = [(k, v) for k, v in handler.headers.items() if k.lower() not in _HOP]
        nonce = secrets.token_hex(12)
        innen = json.dumps({"op": "proxy", "ts": _now(), "n": nonce, "a": {
            "m": handler.command, "p": handler.path, "h": kopf, "b": _b64(body), "u": user,
            "ip": client_ip, "https": bool(https)}}).encode()
        anfrage = json.dumps({"from": self.node_id, "box": _b64(seal(self.key, innen, "rpc"))})
        url = f"http://{_host(ziel)}:{int(ziel['port'])}/cluster/proxy"
        geschrieben = False
        with httpx.Client(timeout=httpx.Timeout(10.0, read=90.0)) as client, \
                client.stream("POST", url, content=anfrage.encode()) as antwort:
            if antwort.status_code != 200:
                raise ClusterError(f"Weiterleitung abgelehnt ({antwort.status_code}).")
            salz = _unb64(antwort.headers.get("X-Aquaticy-Salt", ""))
            try:
                for stueck in read_frames(antwort.iter_bytes(), self.key, salz,
                                          f"stream:{nonce}"):
                    if not geschrieben:
                        if f"\r\n{MOVED_HEADER}: moved\r\n".encode() in stueck:
                            return "moved"
                        geschrieben = True
                    handler.wfile.write(stueck)
                    handler.wfile.flush()
            except (ClusterError, httpx.HTTPError):
                if not geschrieben:
                    raise
        handler.responded = True
        handler.close_connection = True
        return "ok"

    def open_proxy(self, raw: bytes, source_ip: str) -> tuple[dict[str, Any], str, bytes]:
        """Heimserver: prueft eine weitergeleitete Anfrage. Returns (Anfrage, Nonce,
        Schluessel fuer die Antwort)."""
        if not self.joined or not lan_ip_ok(source_ip):
            raise ClusterError("Kein Verbund.")
        _, op, args, nonce, key = self._unwrap(raw, self._member_keys)
        if op != "proxy" or not _USER_RE.match(str(args.get("u", ""))):
            raise ClusterError("Ungueltige Weiterleitung.")
        return args, nonce, key

    # -- Oberflaeche -------------------------------------------------------
    def view(self) -> dict[str, Any]:
        self.poll_answers()
        mitglieder = []
        for m in self.members():
            last = self.my_load() if m["node"] == self.node_id else self.loads.get(m["node"], {})
            mitglieder.append({
                "node": m["node"], "name": m.get("name", ""), "address": m.get("address", ""),
                "port": m.get("port"), "self": m["node"] == self.node_id,
                "master": m["node"] == self.master_node(), "alive": self.alive(m["node"]),
                "runs": int(last.get("runs", 0) or 0),
                "accounts": sum(1 for n in list(self.homes.values()) if n == m["node"]),
                "cpu": last.get("cpu")})
        with self._lock:
            einladungen = [e.public() for e in self.invites_out.values()
                           if _now() - e.created < INVITE_SECONDS * 2]
        return {"enabled": self.enabled, "joined": self.joined,
                "joining": bool(self.info and self.info.get("joining")),
                "master": self.is_master, "node": self.node_id, "name": self.node["name"],
                "lan": self.lan_ready(), "max": MAX_NODES, "members": mitglieder,
                "found": self.found() if self.enabled else [], "invites": einladungen,
                "notice": self.notice}


def _host(ziel: dict[str, Any]) -> str:
    adresse = str(ziel.get("address", ""))
    return f"[{adresse}]" if ":" in adresse else adresse


def _http_post(ziel: dict[str, Any], pfad: str, body: bytes, timeout: float) -> bytes:
    """Ein Aufruf ueber das Netz -- schlicht, ohne Umleitungen, ohne Proxy."""
    adresse = str(ziel.get("address", ""))
    if not adresse or not lan_ip_ok(adresse):
        raise ClusterError("Keine Adresse im eigenen Netz.")
    verbindung = http.client.HTTPConnection(adresse, int(ziel.get("port", 0)), timeout=timeout)
    try:
        verbindung.request("POST", pfad, body=body,
                           headers={"Content-Type": "application/json"})
        antwort = verbindung.getresponse()
        daten = antwort.read(64 * CHUNK)
    finally:
        verbindung.close()
    if antwort.status != 200:
        raise ClusterError(f"Der andere Server antwortet mit {antwort.status}.")
    return daten


class TerminalPrompt:
    """Fragt im Terminal nach: Verbinden, ja oder nein?

    Laeuft der Server ohne Terminal (Container im Hintergrund), steht die
    Anfrage in cluster/pending.json -- beantworten mit ``aquaticy cluster``.
    """

    def __init__(self) -> None:
        self.cluster: Cluster | None = None
        self._queue: list[dict[str, Any]] = []
        self._cond = threading.Condition()
        self._thread: threading.Thread | None = None

    def __call__(self, invite: dict[str, Any]) -> None:
        with self._cond:
            self._queue.append(invite)
            self._cond.notify()
        if self._thread is None:
            self._thread = threading.Thread(target=self._loop, name="aquaticy-cluster-ask",
                                            daemon=True)
            self._thread.start()

    def _loop(self) -> None:
        while True:
            with self._cond:
                while not self._queue:
                    self._cond.wait()
                invite = self._queue.pop(0)
            self._ask(invite)

    def _ask(self, invite: dict[str, Any]) -> None:
        peer = invite.get("peer", {})
        print("\n" + "=" * 64)
        print("  [Verbund] Anfrage zum Verbinden")
        print(f"  Server „{peer.get('name') or '?'}“ ({peer.get('address')}, "
              f"Aquaticy {peer.get('version') or '?'}) möchte diesen Server in seinen")
        print("  Verbund aufnehmen. Er wird dann Master. Die bisherigen Daten dieses")
        print("  Servers werden gesichert (cluster/backup-…) und durch die des Verbunds")
        print("  ersetzt.")
        tty = bool(sys.stdin and sys.stdin.isatty())
        if not tty:
            print("  Kein Terminal zum Antworten -- antworte mit:  aquaticy cluster")
            print("=" * 64)
            return
        while True:
            try:
                antwort = input("  Annehmen? [yes/no]: ").strip().lower()
            except (EOFError, OSError):
                print("  Kein Terminal zum Antworten -- antworte mit:  aquaticy cluster")
                return
            if antwort in ("yes", "y", "ja", "j", "no", "n", "nein"):
                break
            print("  Bitte „yes“ oder „no“ eingeben.")
        if self.cluster is None:
            return
        einladung = self.cluster.answer(str(invite.get("id", "")),
                                        antwort in ("yes", "y", "ja", "j"))
        if einladung is None or einladung.status == "expired":
            print("  Die Anfrage ist inzwischen abgelaufen.")
        elif einladung.status == "accepted":
            print(f"  Angenommen. Gib auf dem einladenden Server diesen Code ein: "
                  f"{format_code(einladung.code)}")
        else:
            print("  Abgelehnt. Die Server werden nicht verbunden.")
        print("=" * 64)
