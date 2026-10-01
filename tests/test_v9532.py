"""9.5.32 Spark: Verschluesselung, Konto loeschen, Design und Ai-guard.

* Chats, Fotos, IP-Adressen, Geraete und E-Mail-Adressen liegen verschluesselt
  (aquaticy/privacy.py); der Betreiber sieht Adressen nur als "#".
* Passwoerter mit Argon2id und Pfeffer; alte scrypt-Hashes werden umgeschrieben.
* Konto loeschen, alle Daten loeschen, Passwort aendern, ueberall abmelden.
* Schriftgroesse, sofort wirkende Schalter, eigene Dialoge statt alert/confirm.
* Ai-guard erkennt getarnte Beleidigungen zu mindestens 99 %.
"""

from __future__ import annotations

import json
import re
import sqlite3
from pathlib import Path
from typing import Any

import pytest

from aquaticy import privacy
from aquaticy.auth import ARGON_PREFIX, AuthStore, _argon_params, _password_hash
from aquaticy.devices import clean_device
from aquaticy.memory import CipherError
from tests.test_end_to_end import _req, server  # noqa: F401 -- Fixture

TERMS = {"terms_accepted": True, "terms_version": "1"}
PC_UA = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/126.0.0.0 Safari/537.36"
PC = {"cores": 16, "memory": 8, "screen": "2560x1440", "gpu": "NVIDIA GeForce RTX 4070"}


@pytest.fixture
def store(tmp_path: Path) -> AuthStore:
    return AuthStore(tmp_path, "PROCODE12", "Abcdef1234567!")


def _roh(pfad: Path) -> str:
    """Die ganze Datenbank als Text -- so, wie jemand sie auf der Platte sieht."""
    with sqlite3.connect(pfad) as conn:
        return "\n".join(str(zeile) for zeile in conn.iterdump())


# -- privacy.py ---------------------------------------------------------------------
def test_sealing_is_authenticated_and_bound(tmp_path: Path) -> None:
    sealer = privacy.profile_sealer(tmp_path / "users" / ("a" * 32))
    text = sealer.seal_text("geheimer Chat", "history.question")
    assert text.startswith(privacy.TEXT_PREFIX) and "geheim" not in text
    assert sealer.open_text(text, "history.question") == "geheimer Chat"
    # An eine andere Spalte gebunden -> nicht zu oeffnen.
    with pytest.raises(CipherError):
        sealer.open_text(text, "history.answer")
    # Ein veraendertes Zeichen -> Fehler statt falscher Daten.
    kaputt = text[:-3] + ("A" if text[-3] != "A" else "B") + text[-2:]
    with pytest.raises(CipherError):
        sealer.open_text(kaputt, "history.question")
    # Alter Klartext bleibt lesbar.
    assert sealer.open_text("alter Klartext", "history.question") == "alter Klartext"


def test_every_account_has_its_own_key(tmp_path: Path) -> None:
    a = privacy.profile_sealer(tmp_path / "users" / ("a" * 32))
    b = privacy.profile_sealer(tmp_path / "users" / ("b" * 32))
    text = a.seal_text("nur für a", "x")
    with pytest.raises(CipherError):
        b.open_text(text, "x")
    schluessel = tmp_path / privacy.KEY_FILE
    assert schluessel.is_file() and len(schluessel.read_bytes()) == 32
    assert (schluessel.stat().st_mode & 0o077) == 0, "nur der Besitzer darf den Schlüssel lesen"


def test_only_real_profiles_use_the_shared_key(tmp_path: Path) -> None:
    """Ein Datenordner, der zufaellig unter "users" liegt, ist kein Kontoprofil."""
    assert privacy.key_root(tmp_path / "users" / ("a" * 32)) == (tmp_path.resolve(), "a" * 32)
    assert privacy.key_root(tmp_path / "users" / "aquaticy") == (
        (tmp_path / "users" / "aquaticy").resolve(), "lokal")


def test_private_files(tmp_path: Path) -> None:
    profil = tmp_path / "users" / ("c" * 32)
    (profil / "uploads").mkdir(parents=True)
    datei = profil / "uploads" / "1-foto.png"
    privacy.write_private(datei, b"\x89PNG echtes Foto", profil)
    assert b"echtes Foto" not in datei.read_bytes()
    assert privacy.read_private(datei) == b"\x89PNG echtes Foto"
    # Umbenannt (in eine andere Datei kopiert) -> nicht zu oeffnen.
    kopie = profil / "uploads" / "2-anderes.png"
    kopie.write_bytes(datei.read_bytes())
    with pytest.raises(CipherError):
        privacy.read_private(kopie)
    # Unverschluesselte Dateien (Terminal, alte Uploads) bleiben lesbar.
    alt = profil / "uploads" / "alt.png"
    alt.write_bytes(b"alt")
    assert privacy.read_private(alt) == b"alt"


# -- Chats verschluesselt -------------------------------------------------------------
def test_chats_are_encrypted_on_disk(tmp_path: Path) -> None:
    from aquaticy.cache import Cache

    profil = tmp_path / "users" / ("d" * 32)
    cache = Cache(profil / "aquaticy.sqlite3")
    cache.add_history("chat1", "Wie heißt mein Arzt Dr. Geheimnis?", "Er heißt Dr. Geheimnis.",
                      {"sources": ["https://example.org/geheim"]})
    cache.rename_chat("chat1", "Arztbesuch Geheimnis")
    cache.add_note("Ich wohne in der Geheimstraße")
    roh = _roh(profil / "aquaticy.sqlite3")
    assert "Geheimnis" not in roh and "Geheimstraße" not in roh and "example.org" not in roh
    # Lesen, Suchen, Liste -- wie vorher.
    eintrag = cache.chat_history("chat1")[0]
    assert eintrag.question.startswith("Wie heißt") and eintrag.meta["sources"]
    assert cache.recent_chats()[0]["title"] == "Arztbesuch Geheimnis"
    treffer = cache.search_chats("geheimnis")
    assert treffer and treffer[0]["session_id"] == "chat1" and "Geheimnis" in treffer[0]["snippet"]
    assert cache.search_chats("GEHEIMNIS"), "ohne Unterschied zwischen Groß und klein"
    assert not cache.search_chats("gibt es nicht")
    assert cache.list_notes()[0].text == "Ich wohne in der Geheimstraße"


def test_old_plaintext_chats_are_encrypted_once(tmp_path: Path) -> None:
    from aquaticy.cache import SCHEMA, Cache

    profil = tmp_path / "users" / ("e" * 32)
    profil.mkdir(parents=True)
    pfad = profil / "aquaticy.sqlite3"
    with sqlite3.connect(pfad) as conn:
        conn.executescript(SCHEMA)
        conn.execute("DELETE FROM privacy_state")
        conn.execute("INSERT INTO history (session_id, created_at, question, answer, meta) "
                     "VALUES ('alt', 1, 'Alte Frage Klartext', 'Alte Antwort', '{}')")
        conn.execute("INSERT INTO notes (created_at, text) VALUES (1, 'alte Notiz Klartext')")
    cache = Cache(pfad)
    assert "Klartext" not in _roh(pfad)
    assert cache.chat_history("alt")[0].question == "Alte Frage Klartext"
    assert cache.list_notes()[0].text == "alte Notiz Klartext"


def test_pictures_are_encrypted(tmp_path: Path) -> None:
    from aquaticy.media import load_snapshot, save_snapshot, snapshot_path

    profil = tmp_path / "users" / ("f" * 32)
    profil.mkdir(parents=True)
    kennung = save_snapshot(profil, b"\xff\xd8\xff echtes Bild", "image/jpeg")
    datei = snapshot_path(profil, kennung)
    assert datei is not None and b"echtes Bild" not in datei.read_bytes()
    assert load_snapshot(profil, kennung) == (b"\xff\xd8\xff echtes Bild", "image/jpeg")
    # Ein fremdes Profil kann das Bild nicht oeffnen.
    fremd = tmp_path / "users" / ("0" * 32)
    (fremd / "media").mkdir(parents=True)
    (fremd / "media" / kennung).write_bytes(datei.read_bytes())
    assert load_snapshot(fremd, kennung) is None


def test_uploads_are_encrypted_and_the_vision_model_can_read_them(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    from aquaticy import web
    from aquaticy.config import Settings

    profil = tmp_path / "users" / ("1" * 32)
    sitzung = web.ChatSession()
    sitzung._settings = Settings(data_dir=profil, env_path=tmp_path / ".env")
    pfad = sitzung._store("foto.png", b"\x89PNG privates Foto")
    assert b"privates Foto" not in pfad.read_bytes()
    assert privacy.read_private(pfad) == b"\x89PNG privates Foto"


# -- Passwoerter ----------------------------------------------------------------------
def test_passwords_use_argon2id_with_pepper(store: AuthStore) -> None:
    konto = store.register("a@example.org", "ein langes Passwort", "normal", username="aa",
                           **TERMS)
    with sqlite3.connect(store.db_path) as conn:
        gespeichert = conn.execute("SELECT password_hash FROM users").fetchone()[0]
    assert bytes(gespeichert).startswith(ARGON_PREFIX)
    assert store.authenticate("a@example.org", "ein langes Passwort") == konto
    assert store.authenticate("a@example.org", "falsches Passwort!!") is None
    # Ohne den Pfeffer (auth.key) passt das Passwort nicht -- die Datenbank allein reicht nicht.
    store._pepper = b"x" * 32
    assert store.authenticate("a@example.org", "ein langes Passwort") is None


def test_the_real_argon_settings_are_strong(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("AQUATICY_KDF", raising=False)
    speicher, durchlaeufe, spuren = _argon_params()
    assert speicher >= 64 * 1024 and durchlaeufe >= 3 and spuren >= 1


def test_old_scrypt_hashes_are_upgraded_at_login(store: AuthStore) -> None:
    store.register("alt@example.org", "ein langes Passwort", "normal", username="alt", **TERMS)
    salz = b"s" * 16
    with sqlite3.connect(store.db_path) as conn:
        conn.execute("UPDATE users SET password_hash=?, password_salt=?",
                     (_password_hash("ein langes Passwort", salz), salz))
    assert store.authenticate("alt@example.org", "ein langes Passwort") is not None
    with sqlite3.connect(store.db_path) as conn:
        neu, neues_salz = conn.execute("SELECT password_hash, password_salt FROM users").fetchone()
    assert bytes(neu).startswith(ARGON_PREFIX) and bytes(neues_salz) != salz
    assert store.authenticate("alt@example.org", "ein langes Passwort") is not None


def test_a_forged_hash_cannot_make_the_server_work_forever(store: AuthStore) -> None:
    from aquaticy.auth import _argon_verify

    riesig = ARGON_PREFIX + b"m=99999999,t=99,p=99$" + b"00" * 32
    assert _argon_verify("x", b"s" * 16, b"p" * 32, riesig) is False
    assert _argon_verify("x", b"s" * 16, b"p" * 32, ARGON_PREFIX + b"kaputt") is False


# -- Konten verschluesselt ------------------------------------------------------------
def test_emails_ips_and_devices_are_not_readable_on_disk(store: AuthStore) -> None:
    geraet = clean_device(PC, user_agent=PC_UA, cookie="K" * 32)
    konto = store.register("anna.geheim@example.org", "ein langes Passwort", "normal",
                           username="anna", ip="203.0.113.77", device=geraet, **TERMS)
    store.note_seen(konto.id, "198.51.100.66")
    roh = _roh(store.db_path)
    for klartext in ("anna.geheim", "203.0.113.77", "198.51.100.66", "RTX 4070", "Chrome"):
        assert klartext not in roh, klartext
    # Der Server arbeitet trotzdem damit.
    assert store.authenticate("anna.geheim@example.org", "ein langes Passwort") is not None
    assert store.account_by_name("anna.geheim@example.org") == konto or \
        store.account_by_name("anna.geheim@example.org").id == konto.id
    assert store.account(konto.id).email == "anna.geheim@example.org"
    assert store.last_address(konto.id) == "198.51.100.66"
    hardware, browser = store.last_device(konto.id)
    assert "RTX 4070" in hardware and browser.startswith("Chrome")
    # Die Adresse steht nur als Schluessel-Hash am Konto.
    assert re.fullmatch(r"[0-9a-f]{64}", store.account(konto.id).last_ip)


def test_same_ip_still_counts_as_an_indicator(store: AuthStore) -> None:
    """Die Anhaltspunkte (9.5.31) arbeiten mit den Hashes weiter."""
    geraet = clean_device(PC, user_agent=PC_UA)
    store.register("max.muster@web.de", "ein langes Passwort", "normal", username="max",
                   ip="203.0.113.5", device=geraet, **TERMS)
    store.register("oma@web.de", "ein langes Passwort", "normal", username="oma",
                   ip="203.0.113.5", **TERMS)
    with pytest.raises(ValueError, match="schon ein Konto"):
        store.register("maxmuster@gmx.de", "ein langes Passwort", "normal", username="max2",
                       ip="203.0.113.5", device=geraet, **TERMS)


def test_plaintext_from_9531_is_migrated(tmp_path: Path) -> None:
    store = AuthStore(tmp_path, "PROCODE12", "Abcdef1234567!")
    konto = store.register("mig@example.org", "ein langes Passwort", "normal", username="mig",
                           **TERMS)
    with sqlite3.connect(tmp_path / "accounts.sqlite3") as conn:
        conn.execute("UPDATE users SET email='mig@example.org', email_enc='', "
                     "last_ip='203.0.113.9', last_ip_enc='', created_ip='203.0.113.9'")
        conn.execute("INSERT INTO account_devices VALUES (?, '', 'hw-alt', 'br-alt', "
                     "'Windows · 8 Kerne', 'Chrome 120, de-DE', 1, 1)", (konto.id,))
        conn.execute("DELETE FROM privacy_state")
    neu = AuthStore(tmp_path, "PROCODE12", "Abcdef1234567!")
    roh = _roh(tmp_path / "accounts.sqlite3")
    assert "mig@example.org" not in roh and "203.0.113.9" not in roh and "8 Kerne" not in roh
    assert neu.authenticate("mig@example.org", "ein langes Passwort") is not None
    assert neu.last_address(konto.id) == "203.0.113.9"
    assert neu.last_device(konto.id)[0] == "Windows · 8 Kerne"


def test_ip_bans_work_with_hashes_only(tmp_path: Path) -> None:
    from aquaticy.aiguard import AiGuard

    guard = AiGuard(tmp_path / "accounts.sqlite3")
    kuerzel = guard.ban_ip("203.0.113.7")
    assert kuerzel.startswith("#") and len(kuerzel) == 9
    assert guard.is_banned(ip="203.0.113.7") is not None
    assert "203.0.113.7" not in _roh(tmp_path / "accounts.sqlite3")
    # Alte Klartext-Sperren (vor 9.5.32) werden beim Start umgeschrieben.
    with sqlite3.connect(tmp_path / "accounts.sqlite3") as conn:
        conn.execute("INSERT INTO aiguard_bans (subject, at, reason, by) "
                     "VALUES ('ip:198.51.100.3', 1, 'alt', 'terminal')")
    neu = AiGuard(tmp_path / "accounts.sqlite3")
    assert neu.is_banned(ip="198.51.100.3") is not None
    assert "198.51.100.3" not in _roh(tmp_path / "accounts.sqlite3")


def test_the_operator_sees_only_a_tag_and_can_ban_by_it(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    from typer.testing import CliRunner

    from aquaticy import cli, config
    from aquaticy.aiguard import guard_for
    from aquaticy.auth import pro_code_for
    from aquaticy.privacy import short_tag

    monkeypatch.setenv("AQUATICY_DATA_DIR", str(tmp_path))
    config.reset_settings_cache()
    try:
        store = AuthStore(tmp_path, pro_code_for(tmp_path))
        konto = store.register("liste@example.org", "ein langes Passwort", "normal",
                               username="Liste", ip="203.0.113.44",
                               device=clean_device(PC, user_agent=PC_UA), **TERMS)
        runner = CliRunner()
        ausgabe = runner.invoke(cli.app, ["list"], env={"COLUMNS": "400"}).output
        tag = short_tag(store.account(konto.id).last_ip)
        assert tag in ausgabe and "203.0.113.44" not in ausgabe
        assert "RTX" not in ausgabe and "Chrome" not in ausgabe
        ergebnis = runner.invoke(cli.app, ["ban", tag])
        assert ergebnis.exit_code == 0, ergebnis.output
        assert guard_for(tmp_path).is_banned(ip="203.0.113.44") is not None
        assert runner.invoke(cli.app, ["unban", tag]).exit_code == 0
        assert guard_for(tmp_path).is_banned(ip="203.0.113.44") is None
        assert runner.invoke(cli.app, ["ban", "#zz"]).exit_code == 1
    finally:
        config.reset_settings_cache()


# -- Konto verwalten ------------------------------------------------------------------
def test_change_password_ends_other_sessions(store: AuthStore) -> None:
    konto = store.register("pw@example.org", "ein langes Passwort", "normal", username="pw",
                           **TERMS)
    hier = store.create_session(konto, "gerät-a", "203.0.113.1")
    dort = store.create_session(konto, "gerät-b", "203.0.113.1")
    with pytest.raises(ValueError, match="bisherige"):
        store.change_password(konto, "falsch falsch falsch", "ein neues Passwort", hier)
    with pytest.raises(ValueError):
        store.change_password(konto, "ein langes Passwort", "kurz", hier)
    store.change_password(konto, "ein langes Passwort", "ein neues langes Passwort", hier)
    assert store.authenticate("pw@example.org", "ein neues langes Passwort") is not None
    assert store.authenticate("pw@example.org", "ein langes Passwort") is None
    assert store.session_account(hier, "gerät-a", "203.0.113.1") is not None
    assert store.session_account(dort, "gerät-b", "203.0.113.1") is None


def test_a_new_device_leaves_a_notice(store: AuthStore) -> None:
    konto = store.register("neu@example.org", "ein langes Passwort", "normal", username="neu",
                           device=clean_device(PC, user_agent=PC_UA, cookie="A" * 32), **TERMS)
    assert store.is_known_device(konto.id, clean_device(PC, user_agent=PC_UA,
                                                        cookie="A" * 32))
    fremd = clean_device({"cores": 2}, user_agent="Mozilla/5.0 (Linux; Android 14) Chrome/120",
                         cookie="Z" * 32)
    assert not store.is_known_device(konto.id, fremd)
    store.add_event(konto.id, "neues-geraet", "Anmeldung mit Chrome 120 auf Android")
    ereignisse = store.events(konto.id, unseen_only=True)
    assert ereignisse and "Android" in ereignisse[0]["detail"]
    assert "Android" not in _roh(store.db_path)
    store.mark_events_seen(konto.id)
    assert not store.events(konto.id, unseen_only=True)


def test_wipe_keeps_the_account_but_removes_the_data(store: AuthStore) -> None:
    from aquaticy.cache import Cache

    konto = store.register("wipe@example.org", "ein langes Passwort", "normal",
                           username="wipe", device=clean_device(PC, user_agent=PC_UA), **TERMS)
    profil = store.profile_dir(konto.id)
    Cache(profil / "aquaticy.sqlite3").add_history("c", "frage", "antwort")
    store.vault(konto).set("TAVILY_API_KEY", "tvly-geheim-1234")
    store.wipe_data(konto)
    assert store.account(konto.id) is not None
    assert not (profil / "aquaticy.sqlite3").exists() and profil.is_dir()
    assert store.vault(konto).count() == 0
    assert store.device_count(konto.id) == 0


# -- Ende zu Ende ---------------------------------------------------------------------
def _registrieren(port: int, name: str, geraet: str = "") -> str:
    _, kopf, _ = _req(port, "POST", "/api/consent", {"accepted": True})
    zustimmung = kopf["Set-Cookie"].split(";", 1)[0]
    status, kopf, daten = _req(port, "POST", "/api/auth/register", {
        "email": f"{name}@example.org", "username": name, "password": "ein langes Passwort",
        "plan": "normal", "terms_accepted": True, "device": PC},
        zustimmung + (f"; aquaticy_device={geraet}" if geraet else ""))
    assert status == 200, daten
    return zustimmung + "; " + kopf["Set-Cookie"].split(";", 1)[0]


def _post(port: int, pfad: str, body: Any, keks: str) -> tuple[int, dict[str, Any]]:
    status, _, daten = _req(port, "POST", pfad, body, keks)
    return status, json.loads(daten or b"{}")


def test_the_security_page_shows_only_my_own_data(server: tuple[int, Path]) -> None:  # noqa: F811
    port, _ = server
    keks = _registrieren(port, "sicher1")
    status, _, daten = _req(port, "GET", "/api/account/security", None, keks)
    sicht = json.loads(daten)
    assert status == 200 and sicht["sessions"] >= 1
    assert sicht["devices"] and "RTX 4070" in sicht["devices"][0]["hardware"]
    assert sicht["last_address"] in ("127.0.0.1", "")


def test_deleting_the_account_needs_password_and_word(server: tuple[int, Path]) -> None:  # noqa: F811
    port, _ = server
    keks = _registrieren(port, "loesch1")
    status, antwort = _post(port, "/api/account/delete",
                            {"password": "falsches Passwort!!", "confirm": "LÖSCHEN"}, keks)
    assert status == 403 and not antwort["ok"]
    status, antwort = _post(port, "/api/account/delete",
                            {"password": "ein langes Passwort", "confirm": "ja"}, keks)
    assert status == 400 and "LÖSCHEN" in antwort["error"]
    status, antwort = _post(port, "/api/account/delete",
                            {"password": "ein langes Passwort", "confirm": "löschen"}, keks)
    assert status == 200 and antwort["deleted"]
    # Danach ist die Sitzung weg und die Anmeldung geht nicht mehr.
    status, _, _ = _req(port, "GET", "/api/account", None, keks)
    assert status == 401
    _, kopf, _ = _req(port, "POST", "/api/consent", {"accepted": True})
    status, _, _ = _req(port, "POST", "/api/auth/login", {
        "email": "loesch1@example.org", "password": "ein langes Passwort"},
        kopf["Set-Cookie"].split(";", 1)[0])
    assert status == 401


def test_a_banned_account_can_delete_itself_but_not_come_back_from_that_device(
    server: tuple[int, Path],  # noqa: F811
) -> None:
    from aquaticy import web

    port, _ = server
    kennung = "G" * 32
    keks = _registrieren(port, "gesperrt1", kennung)
    konto = web.AUTH.account_by_name("gesperrt1")
    web.AIGUARD.ban_user(konto.id, reason="Test")
    status, antwort = _post(port, "/api/account/delete",
                            {"password": "ein langes Passwort", "confirm": "LÖSCHEN"}, keks)
    assert status == 200, antwort
    _, kopf, _ = _req(port, "POST", "/api/consent", {"accepted": True})
    status, _, daten = _req(port, "POST", "/api/auth/register", {
        "email": "ganzneu@example.org", "username": "ganzneu",
        "password": "ein langes Passwort", "plan": "normal", "terms_accepted": True},
        kopf["Set-Cookie"].split(";", 1)[0] + f"; aquaticy_device={kennung}")
    assert status == 403 and b"gesperrt" in daten


def test_wipe_and_password_over_http(server: tuple[int, Path]) -> None:  # noqa: F811
    port, _ = server
    keks = _registrieren(port, "wipe2")
    status, antwort = _post(port, "/api/account/wipe", {"password": "nein nein nein"}, keks)
    assert status == 403
    status, antwort = _post(port, "/api/account/wipe", {"password": "ein langes Passwort"},
                            keks)
    assert status == 200 and antwort["ok"]
    status, _, _ = _req(port, "GET", "/api/account", None, keks)
    assert status == 200, "das Konto bleibt"
    status, antwort = _post(port, "/api/account/password", {
        "password": "ein langes Passwort", "new_password": "ein ganz neues Passwort"}, keks)
    assert status == 200 and antwort["ok"]
    status, antwort = _post(port, "/api/account/logout-all", {}, keks)
    assert status == 200 and antwort["ok"]


def test_wrong_passwords_are_limited(server: tuple[int, Path]) -> None:  # noqa: F811
    port, _ = server
    keks = _registrieren(port, "rate1")
    codes = [_post(port, "/api/account/wipe", {"password": f"falsch {i} xxxxxxxx"}, keks)[0]
             for i in range(12)]
    assert codes[-1] == 429 and 403 in codes


# -- Oberflaeche ----------------------------------------------------------------------
def _seite() -> str:
    from aquaticy import web

    return web.UI_FILE.read_text(encoding="utf-8")


def test_font_size_is_part_of_the_state_and_page() -> None:
    from aquaticy import web
    from aquaticy.uistate import clean, defaults

    assert defaults()["fontsize"] == "normal"
    assert clean({"fontsize": "large"})["fontsize"] == "large"
    assert clean({"fontsize": "riesig"})["fontsize"] == "normal"
    html = _seite()
    for stufe in ("small", "normal", "large"):
        assert f'data-fsize="{stufe}"' in html
    assert ':root[data-fontsize="small"]{--fs:.9}' in html
    assert ':root[data-fontsize="large"]{--fs:1.15}' in html
    # Alle Schriftgroessen im Stil folgen der Einstellung.
    stil = html[html.index("<style>"):html.index("</style>")]
    # Ausnahmen: das Eingabefeld am Handy (unter 16 px zoomt iOS) und die drei
    # "A" im Design-Fenster, die die Stufen zeigen.
    for fest in ("textarea{font-size:16px}", ".fs-glyph-s{font-size:12px!important}",
                 ".fs-glyph-l{font-size:19px!important}"):
        stil = stil.replace(fest, "")
    assert not re.search(r"font-size:\s*\d+(?:\.\d+)?px", stil), "eine feste Schriftgröße"
    assert "data-fontsize" in Path(web.__file__).read_text(encoding="utf-8")


def test_the_page_arrives_with_the_font_size(tmp_path: Path, monkeypatch: pytest.MonkeyPatch
                                              ) -> None:
    from aquaticy import web

    class Zustand:
        def read(self) -> dict[str, Any]:
            from aquaticy.uistate import defaults

            return {**defaults(), "fontsize": "large"}

    monkeypatch.setattr(web, "ui_state", lambda: Zustand())
    monkeypatch.setattr(web, "AUTH", None)
    html = web.with_state('<html lang="de"><body></body></html>')
    assert 'data-fontsize="large"' in html


def test_switches_save_at_once_and_forms_use_checkboxes() -> None:
    html = _seite()
    assert "async function sofortSpeichern(schalter)" in html
    assert 'feld.matches("input.schalter[name]")' in html
    assert '<input type="checkbox" id="job-struktur" checked>' in html


def test_no_browser_alert_or_confirm_is_left() -> None:
    skript = "\n".join(re.findall(r"<script>(.*?)</script>", _seite(), re.S))
    ohne_kommentare = re.sub(r"//[^\n]*", "", skript)
    assert not re.search(r"\b(?:alert|confirm)\(", ohne_kommentare)
    assert "function hinweis(" in skript and "function frage(" in skript


def test_ultra_only_switches_show_a_lock() -> None:
    html = _seite()
    assert html.count('<span class="lock-tag" data-lock hidden>🔒 Mit Ultra verfügbar</span>') == 3
    assert "kontoPro" not in html and "pro-tag" not in html
    assert ".schalter.gesperrt" in html


def test_switches_do_not_rely_on_colour_alone() -> None:
    html = _seite()
    # Seit 9.6.0 ohne "I/O": Rand (aus) gegen Fuellung (an) -- nicht nur die Farbe.
    assert ".schalter{box-shadow:inset 0 0 0 2px var(--switch-off)}" in html
    assert 'content:"O"' not in html and 'content:"I"' not in html
    assert "--switch-off:" in html


def test_dark_mode_avoids_pure_black() -> None:
    html = _seite()
    block = re.search(r':root\[data-palette="mono"\]\[data-theme="dark"\]\{(.*?)\}', html, re.S)
    assert block and "--bg:#000000" not in block.group(1) and "--bg:#121212" in block.group(1)


def test_retry_capabilities_and_account_controls_are_there() -> None:
    html = _seite()
    for teil in ("function wiederholenKnopf(", 'id="account-delete"',
                 'id="account-wipe"', 'id="account-password"', 'id="account-logout-all"',
                 'id="security-banner"', 'id="device-list"'):
        assert teil in html, teil
    assert ".send{width:44px;height:44px}" in html


# -- Ai-guard: getarnte Beleidigungen -------------------------------------------------
@pytest.mark.parametrize("text", [
    "du d🙂u🙂m🙂m🙂e🙂r Bot", "du bíst dúmm", "yooouuu are useless", "du biiist dumm",
    "y o u ' r e so stupid", "I.d.1.o.t!", "du A****l0ch", "du_1d10t", "du Kn*llkopf",
    "halt die klaaappe", "verpiiiss dich", "son of a b i t c h", "i*d*i*o*t",
    "y0u'r3 so stupid", "du Fl*chzange", "w45 für ein Idiot du bist",
])
def test_disguised_insults_are_found(text: str) -> None:
    from aquaticy.aiguard import insult_level

    assert insult_level(text) >= 1, text


def test_disguise_lookalikes_are_not_insults() -> None:
    from aquaticy.aiguard import insult_level
    from tests.aiguard_tarnung_korpus import TARNUNG_HARMLOS

    falsch = [t for t in TARNUNG_HARMLOS if insult_level(t)]
    assert not falsch, falsch


def _getarnt(text: str) -> list[str]:
    """Jede Tarnung einmal -- am Wort, ohne das die Beleidigung nicht mehr erkannt wird."""
    from aquaticy.aiguard import insult_level

    woerter = text.split()
    ziel = next((w for i, w in enumerate(woerter)
                 if not insult_level(" ".join(woerter[:i] + woerter[i + 1:]))), "")
    kern = ziel.strip("!?.,;:")
    if len(kern) < 3:
        return []
    leet = {"i": "1", "o": "0", "e": "3", "a": "4", "s": "5"}
    homo = {"a": "а", "e": "е", "o": "о", "i": "і", "c": "с", "p": "р"}
    akzent = {"a": "á", "e": "é", "i": "í", "o": "ó", "u": "ú"}
    varianten = [
        " ".join(kern), ".".join(kern), "-".join(kern), "​".join(kern), "🙂".join(kern),
        "".join(leet.get(z, z) for z in kern), "".join(homo.get(z, z) for z in kern),
        "".join(akzent.get(z, z) for z in kern),
        "".join(z * 3 if z in "aeiou" else z for z in kern), kern + kern[-1],
    ]
    if len(kern) >= 5:
        varianten.append(kern[:2] + "*" + kern[3:])
    return [text.replace(kern, v, 1) for v in varianten]


def test_at_least_99_percent_of_disguised_insults_are_found() -> None:
    """Das Ziel aus 9.5.32: mindestens 99 % -- bei null Fehlalarmen (Test oben).

    Gemessen an den Beleidigungen aus dem Korpus ohne eigene Tarnung, jede mit
    elf Tarnungen. Ein komplett ausgesterntes Wort ("d****r") zaehlt nicht mit:
    das ist ohne Zusammenhang mehrdeutig und geht an das Modell.
    """
    from aquaticy.aiguard import insult_level
    from tests import aiguard_korpus as korpus

    saetze = ([t for t, _ in korpus.UEBUNG_BELEIDIGUNGEN] + korpus.KONTROLLE_BELEIDIGUNGEN
              + korpus.PRUEFUNG_BELEIDIGUNGEN)
    rein = [t for t in saetze if re.fullmatch(r"[\w\s'’!?,.äöüßÄÖÜ-]+", t)
            and not re.search(r"\d|\w[.\-*]\w[.\-*]", t)]
    varianten = [v for t in rein for v in _getarnt(t)]
    gefunden = sum(1 for v in varianten if insult_level(v))
    quote = gefunden / len(varianten)
    assert len(varianten) > 1500
    assert quote >= 0.99, f"{quote:.2%}"


# -- Parallele Suchen in Aufruf-Reihenfolge -------------------------------------------
def test_parallel_searches_keep_the_call_order() -> None:
    """Unter Last trugen sich parallele Suchen in Start-Reihenfolge ein ("b, a")."""
    from aquaticy.agent import _in_call_order

    aufrufe = [{"function": {"name": "web_search", "arguments": json.dumps({"query": q})}}
               for q in ("a", "b", "c")]
    suchen = ["frueher", "c", "a", "b"]
    _in_call_order(suchen, 1, aufrufe)
    assert suchen == ["frueher", "a", "b", "c"]
    # Kaputte Argumente oder fremde Werkzeuge stoeren nicht.
    suchen = ["x", "y"]
    _in_call_order(suchen, 0, [{"function": {"name": "web_search", "arguments": "{kaputt"}},
                               {"function": {"name": "fetch_page", "arguments": "{}"}}])
    assert suchen == ["x", "y"]
