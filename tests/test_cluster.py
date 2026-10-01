"""Server-Verbund (9.6.1): zwei Server in einem Prozess, verbunden ueber den Speicher."""

from __future__ import annotations

import json
import sqlite3
import time
from pathlib import Path
from typing import Any

import pytest

from aquaticy import cluster
from aquaticy.auth import AuthStore


class Netz:
    """Statt HTTP: jeder Aufruf geht direkt an den richtigen Server."""

    def __init__(self) -> None:
        self.knoten: dict[int, cluster.Cluster] = {}

    def __call__(self, ziel: dict[str, Any], pfad: str, body: bytes, timeout: float) -> bytes:
        c = self.knoten[int(ziel["port"])]
        quelle = "127.0.0.1"
        if pfad == "/cluster/rpc":
            return c.handle_rpc(body, quelle)
        handler = {"/cluster/hello": c.handle_hello, "/cluster/hello-status": c.hello_status,
                   "/cluster/hello-join": c.hello_join}[pfad]
        return json.dumps(handler(json.loads(body), quelle)).encode()


def _store(ordner: Path) -> AuthStore:
    return AuthStore(ordner, "ABCDEFGH1", "Abcdefgh1234!x")


def _konto(store: AuthStore, email: str) -> Any:
    return store.register(email, "ein-sicheres-passwort", "normal", terms_accepted=True,
                          terms_version="1")


def _warte(bedingung: Any, sekunden: float = 10.0) -> None:
    ende = time.time() + sekunden
    while time.time() < ende:
        if bedingung():
            return
        time.sleep(0.1)
    raise AssertionError("Zeit abgelaufen")


@pytest.fixture
def verbund(tmp_path: Path) -> Any:
    netz = Netz()
    neustarts: list[str] = []
    gefragt: list[dict[str, Any]] = []
    a_dir, b_dir = tmp_path / "a", tmp_path / "b"
    store_a, store_b = _store(a_dir), _store(b_dir)
    alt_a = _konto(store_a, "anna@example.org")
    _konto(store_b, "bert@example.org")
    a = cluster.Cluster(a_dir, port=1001, transport=netz,
                        hooks=cluster.Hooks(restart=lambda: neustarts.append("a")))
    b = cluster.Cluster(b_dir, port=1002, transport=netz,
                        hooks=cluster.Hooks(restart=lambda: neustarts.append("b"),
                                            ask=gefragt.append))
    netz.knoten = {1001: a, 1002: b}
    for c in (a, b):
        c.state["enabled"] = True
    return a, b, store_a, alt_a, gefragt, neustarts


def _verbinden(a: cluster.Cluster, b: cluster.Cluster, gefragt: list, neustarts: list) -> None:
    einladung = a.invite("127.0.0.1", 1002)
    assert gefragt and gefragt[0]["peer"]["node"] == a.node_id
    eingeladen = b.invites_in[einladung.id]
    assert eingeladen.code == einladung.code, "beide Seiten kommen auf denselben Code"
    b.answer(einladung.id, True)
    _warte(lambda: einladung.status == "accepted")
    with pytest.raises(cluster.ClusterError):
        a.confirm(einladung.id, "000000" if einladung.code != "000000" else "111111")
    a.confirm(einladung.id, einladung.code)
    _warte(lambda: "b" in neustarts, 20.0)
    # Im echten Betrieb startet B jetzt neu -- hier reicht es, den Schluessel-
    # Zwischenspeicher zu leeren.
    from aquaticy import privacy

    privacy._masters.clear()


def test_crypto_roundtrip_and_tamper() -> None:
    key = b"k" * 32
    box = cluster.seal(key, b"hallo", "rpc")
    assert cluster.unseal(key, box, "rpc") == b"hallo"
    with pytest.raises(cluster.ClusterError):
        cluster.unseal(key, box, "anders")
    kaputt = bytearray(box)
    kaputt[-1] ^= 1
    with pytest.raises(cluster.ClusterError):
        cluster.unseal(key, bytes(kaputt), "rpc")


def test_frames_detect_truncation() -> None:
    class Puffer:
        def __init__(self) -> None:
            self.daten = bytearray()

        def write(self, d: bytes) -> None:
            self.daten.extend(d)

        def flush(self) -> None:
            pass

    roh = Puffer()
    w = cluster.FrameWriter(roh, b"x" * 32, b"s" * 16, "stream:1")
    w.write(b"eins")
    w.write(b"zwei")
    ganz = bytes(roh.daten)
    w.end()
    assert list(cluster.read_frames([bytes(roh.daten)], b"x" * 32, b"s" * 16,
                                    "stream:1")) == [b"eins", b"zwei"]
    with pytest.raises(cluster.ClusterError):
        list(cluster.read_frames([ganz], b"x" * 32, b"s" * 16, "stream:1"))


def test_unquote_reads_sqlite_literals_without_sql() -> None:
    conn = sqlite3.connect(":memory:")
    for wert in (None, 7, 1790864833.581814, "it's", b"\x00\xff"):
        assert cluster._unquote(conn.execute("SELECT quote(?)", (wert,)).fetchone()[0]) == wert


def test_safe_rel_blocks_escapes(tmp_path: Path) -> None:
    for boese in ("../x", "/etc/passwd", "a/../../x", "", "a\\b"):
        with pytest.raises(cluster.ClusterError):
            cluster.safe_rel(tmp_path, boese)
    assert cluster.safe_rel(tmp_path, "a/b.txt") == (tmp_path / "a/b.txt").resolve()


def test_lan_only() -> None:
    assert cluster.lan_ip_ok("192.168.1.5")
    assert cluster.lan_ip_ok("100.101.1.2")  # Tailscale
    assert not cluster.lan_ip_ok("8.8.8.8")
    assert not cluster.lan_ip_ok("kaputt")


def test_shared_db_replicates_rows_both_ways(tmp_path: Path) -> None:
    for name in ("a.db", "b.db"):
        conn = sqlite3.connect(tmp_path / name)
        conn.execute("CREATE TABLE users (id TEXT PRIMARY KEY, name TEXT, pw BLOB, t REAL)")
        conn.execute("CREATE TABLE ev (user_id TEXT, at REAL)")  # ohne Schluessel
        conn.commit()
        conn.close()
    a, b = cluster.SharedDb(tmp_path / "a.db"), cluster.SharedDb(tmp_path / "b.db")
    a.install()
    b.install()
    conn = sqlite3.connect(tmp_path / "a.db")
    conn.execute("INSERT INTO users VALUES ('u1', 'Anna', x'00ff', 1.5)")
    conn.execute("INSERT INTO ev VALUES ('u1', 2.25)")
    conn.execute("INSERT INTO ev VALUES ('u1', 3.5)")
    conn.execute("UPDATE users SET name='Anna B' WHERE id='u1'")
    conn.execute("DELETE FROM ev WHERE at=2.25")
    conn.commit()
    conn.close()
    b.apply("A", a.changes(0)["entries"])
    conn = sqlite3.connect(tmp_path / "b.db")
    assert conn.execute("SELECT * FROM users").fetchall() == [("u1", "Anna B", b"\x00\xff", 1.5)]
    assert conn.execute("SELECT at FROM ev").fetchall() == [(3.5,)]
    conn.close()
    # Eingespieltes landet nicht im eigenen Protokoll -- sonst liefe es im Kreis.
    assert b.changes(0)["entries"] == []
    assert b.cursor("A") == a.last_seq()


def test_join_sync_and_files(verbund: Any) -> None:
    a, b, store_a, alt_a, gefragt, neustarts = verbund
    _verbinden(a, b, gefragt, neustarts)
    assert a.is_master and b.joined and not b.is_master
    # B hat die Daten des Masters -- und seine eigenen gesichert.
    store_b = _store(b.data_dir)
    assert {k.email for k in store_b.accounts()} == {"anna@example.org"}
    assert list((b.dir).glob("backup-*/accounts.sqlite3"))
    assert (b.data_dir / "auth.key").read_bytes() == (a.data_dir / "auth.key").read_bytes()
    # Ein neues Konto auf B kommt bei A an, und umgekehrt.
    _konto(store_b, "clara@example.org")
    a.sync_once()
    assert "clara@example.org" in {k.email for k in store_a.accounts()}
    _konto(store_a, "dora@example.org")
    b.sync_once()
    assert "dora@example.org" in {k.email for k in store_b.accounts()}
    # Anmeldung auf B gilt auch auf A (Sitzung repliziert), Abmelden ebenso.
    konto = store_b.authenticate("anna@example.org", "ein-sicheres-passwort")
    assert konto is not None
    token = store_b.create_session(konto, "geraet", "192.168.1.9")
    a.sync_once()
    assert store_a.session_account(token, "geraet", "192.168.1.9") is not None
    store_b.logout(token)
    a.sync_once()
    assert store_a.session_account(token, "geraet", "192.168.1.9") is None
    # Profilordner: A ist zustaendig, B bekommt die Kopie -- auch Datenbanken.
    ordner = a.data_dir / "users" / alt_a.id
    ordner.mkdir(parents=True, exist_ok=True)
    (ordner / "notiz.txt").write_text("hallo", encoding="utf-8")
    db = sqlite3.connect(ordner / "chat.sqlite3")
    db.execute("PRAGMA journal_mode=WAL")
    db.execute("CREATE TABLE t (x)")
    db.execute("INSERT INTO t VALUES (42)")
    db.commit()
    a._gens_cache = None  # der Stand ist 2 s zwischengespeichert
    b.sync_once(full=True)
    kopie = b.data_dir / "users" / alt_a.id
    assert (kopie / "notiz.txt").read_text(encoding="utf-8") == "hallo"
    assert sqlite3.connect(kopie / "chat.sqlite3").execute("SELECT x FROM t").fetchall() == [
        (42,)]
    db.close()
    (ordner / "notiz.txt").unlink()
    a._gens_cache = None
    b.sync_once(full=True)
    assert not (kopie / "notiz.txt").exists()


def test_assign_balances_and_remove_rekeys(verbund: Any) -> None:
    a, b, _store_a, _alt_a, gefragt, neustarts = verbund
    _verbinden(a, b, gefragt, neustarts)
    b.sync_once()
    a.sync_once()
    # A traegt schon ein aktives Konto -- das naechste geht an B.
    a.homes["schon-da"] = a.node_id
    a._activity["schon-da"] = time.time()
    a.last_ok[b.node_id] = time.time()
    assert a.assign("neu1") == b.node_id
    assert b.homes.get("neu1") == b.node_id, "der Master verteilt die Zuteilung"
    assert b.is_home("neu1") and not a.is_home("neu1")
    alter_schluessel = b.key
    a.remove(b.node_id)
    assert a.key != alter_schluessel
    assert len(a.members()) == 1


def test_invite_needs_feature_on(verbund: Any) -> None:
    a, b, *_ = verbund
    b.state["enabled"] = False
    with pytest.raises(cluster.ClusterError, match="ausgeschaltet"):
        a.invite("127.0.0.1", 1002)


def test_denied_invite_does_not_join(verbund: Any) -> None:
    a, b, _, _, _gefragt, neustarts = verbund
    einladung = a.invite("127.0.0.1", 1002)
    b.answer(einladung.id, False)
    _warte(lambda: einladung.status == "denied")
    with pytest.raises(cluster.ClusterError):
        a.confirm(einladung.id, einladung.code)
    assert not a.joined and not b.joined and not neustarts


def _paar(tmp_path: Path, port: int) -> tuple[cluster.Cluster, cluster.Cluster]:
    """Heimserver (echtes HTTP auf *port*) und ein Eingang mit gemeinsamem Schluessel."""
    heim = cluster.Cluster(tmp_path / "heim", host="0.0.0.0", port=port)
    eingang = cluster.Cluster(tmp_path / "eingang", host="0.0.0.0", port=1)
    info = {"id": "c1", "master": heim.node_id, "version": 1,
            "secret": cluster._b64(b"s" * 32),
            "members": [{"node": heim.node_id, "name": "heim", "address": "127.0.0.1",
                         "port": port},
                        {"node": eingang.node_id, "name": "eingang", "address": "127.0.0.1",
                         "port": 1}]}
    for c in (heim, eingang):
        c.state.update(enabled=True, cluster=json.loads(json.dumps(info)), homes={})
    return heim, eingang


class _Handler:
    """Was der Eingang von seinem eigenen Handler braucht."""

    def __init__(self, path: str) -> None:
        import io
        from http.client import HTTPMessage

        self.command, self.path = "GET", path
        self.headers = HTTPMessage()
        self.headers["Host"] = "aquaticy.local"
        self.headers["User-Agent"] = "Test"
        self.wfile = io.BytesIO()
        self.responded = False
        self.close_connection = False


def test_proxy_serves_on_home_server(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    import threading
    from http.server import ThreadingHTTPServer

    from aquaticy import web

    store = _store(tmp_path / "konten")
    konto = _konto(store, "erika@example.org")
    monkeypatch.setattr(web, "AUTH", store)
    monkeypatch.setattr(web, "SESSIONS", web.SessionRegistry())
    monkeypatch.setattr(web, "SESSION", web.SessionProxy())
    monkeypatch.setattr(web, "start_user_scheduler", lambda account: None)
    server = ThreadingHTTPServer(("127.0.0.1", 0), web.Handler)
    faden = threading.Thread(target=server.serve_forever, daemon=True)
    faden.start()
    try:
        heim, eingang = _paar(tmp_path, server.server_address[1])
        monkeypatch.setattr(web, "CLUSTER", heim)
        heim.homes[konto.id] = heim.node_id
        ziel = eingang.member(heim.node_id)

        h = _Handler("/api/account")
        assert eingang._proxy_once(h, ziel, konto.id, b"", False, "192.168.1.20") == "ok"
        antwort = h.wfile.getvalue()
        assert antwort.startswith(b"HTTP/1.0 200")
        assert b"erika@example.org" in antwort
        assert b"Content-Security-Policy" in antwort, "die Kopfzeilen des Heimservers"

        # Inzwischen woanders zuhause: der Heimserver sagt "moved", nichts geht raus.
        heim.homes[konto.id] = eingang.node_id
        heim.last_ok[eingang.node_id] = time.time()
        h = _Handler("/api/account")
        assert eingang._proxy_once(h, ziel, konto.id, b"", False, "192.168.1.20") == "moved"
        assert h.wfile.getvalue() == b""

        # Ohne den Verbundschluessel kommt nichts durch.
        heim.homes[konto.id] = heim.node_id
        eingang.state["cluster"]["secret"] = cluster._b64(b"f" * 32)
        h = _Handler("/api/account")
        with pytest.raises(cluster.ClusterError):
            eingang._proxy_once(h, ziel, konto.id, b"", False, "192.168.1.20")
        assert h.wfile.getvalue() == b""
    finally:
        server.shutdown()
        server.server_close()


def test_member_list_never_carries_the_secret(verbund: Any) -> None:
    a, b, _, _, gefragt, neustarts = verbund
    _verbinden(a, b, gefragt, neustarts)
    antwort = a._dispatch(b.node_id, "ping", {})
    assert "secret" not in antwort["members"] and "previous" not in antwort["members"]
    assert "secret" not in a.public_info()
    # Und trotzdem behaelt B seinen Schluessel, wenn die Liste ankommt.
    vorher = b.key
    b._take_members(a.public_info(), a.homes)
    assert b.key == vorher


def test_unexpected_errors_come_back_as_answer(verbund: Any, monkeypatch) -> None:
    """9.6.2.5: ein Plattenfehler auf der anderen Seite reisst die Verbindung nicht ab."""
    a, b, _, _, gefragt, neustarts = verbund
    _verbinden(a, b, gefragt, neustarts)

    def kaputt(*args: Any, **kwargs: Any) -> Any:
        raise OSError("Platte voll")

    monkeypatch.setattr(a, "my_generations", kaputt)
    with pytest.raises(cluster.ClusterError, match="OSError"):
        b.call(a.node_id, "gens", {})
