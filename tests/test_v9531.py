"""9.5.31 Spark: Internet fuer die virtual machine (Ultra) und Anhaltspunkte
statt "ein Konto pro IP-Adresse".
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import pytest

from aquaticy import devices
from aquaticy.auth import AuthStore
from aquaticy.config import Settings
from aquaticy.devices import clean_device, emails_similar, new_device_token, score, token_hash
from tests.test_end_to_end import _req, server  # noqa: F401 -- Fixture

TERMS = {"terms_accepted": True, "terms_version": "1"}
HANDY_UA = ("Mozilla/5.0 (Linux; Android 14; Pixel 8) AppleWebKit/537.36 "
            "(KHTML, like Gecko) Chrome/126.0.0.0 Mobile Safari/537.36")
PC_UA = ("Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
         "(KHTML, like Gecko) Chrome/126.0.0.0 Safari/537.36")
HANDY = {"platform": "Linux armv8l", "cores": 8, "memory": 8, "screen": "412x915",
         "dpr": 2.625, "touch": 5, "tz": "Europe/Berlin", "lang": "de-DE",
         "gpu": "Mali-G715"}
PC = {"platform": "Win32", "cores": 16, "memory": 8, "screen": "2560x1440", "dpr": 1,
      "touch": 0, "tz": "Europe/Berlin", "lang": "de-DE", "gpu": "NVIDIA GeForce RTX 4070"}


@pytest.fixture
def store(tmp_path: Path) -> AuthStore:
    return AuthStore(tmp_path, "PROCODE12", "Abcdef1234567!")


# -- Geraete-Angaben ------------------------------------------------------------------
def test_the_device_summary_is_readable() -> None:
    geraet = clean_device(PC, user_agent=PC_UA, accept_language="de-DE,de;q=0.9")
    assert geraet.hardware.startswith("Windows · 16 Kerne · 8 GB · 2560x1440")
    assert "NVIDIA GeForce RTX 4070" in geraet.hardware
    assert geraet.browser == "Chrome 126, de-DE"
    assert geraet.hardware_hash and geraet.browser_hash
    assert not geraet.cookie_hash


@pytest.mark.parametrize(("ua", "name"), [
    ("Mozilla/5.0 (Windows NT 10.0) Chrome/126.0 Safari/537.36 Edg/126.0", "Edge 126"),
    ("Mozilla/5.0 (X11; Linux x86_64; rv:128.0) Gecko/20100101 Firefox/128.0", "Firefox 128"),
    ("Mozilla/5.0 (iPhone; CPU iPhone OS 17_5 like Mac OS X) Version/17.5 Mobile/15E148 "
     "Safari/604.1", "Safari 17"),
    ("Mozilla/5.0 (Linux; Android 14) SamsungBrowser/25.0 Chrome/121.0", "Samsung Internet 25"),
    ("", "unbekannt"),
])
def test_browser_names(ua: str, name: str) -> None:
    assert devices.browser_name(ua) == name


def test_what_the_browser_sends_is_cleaned() -> None:
    """Die Angaben kommen vom Browser -- also von jedem, der eine Anfrage baut."""
    roh = {"cores": "viele", "memory": float("nan"), "screen": "<script>", "dpr": -3,
           "touch": 10**9, "gpu": "A\x00B‮" + "x" * 500, "tz": ["Liste"]}
    geraet = clean_device(roh, user_agent="curl/8")
    assert "<" not in geraet.hardware and "\x00" not in geraet.hardware
    assert "‮" not in geraet.hardware
    assert len(geraet.hardware) <= 200 and len(geraet.browser) <= 80
    # Kaputtes Nicht-Woerterbuch geht auch.
    assert clean_device("Unsinn", user_agent="").hardware_hash == ""
    assert clean_device(None).browser_hash == ""


def test_without_hardware_data_nothing_matches() -> None:
    """Skript aus oder altes Formular: leere Hashes treffen nie."""
    a = clean_device({}, user_agent=PC_UA)
    punkte, _ = score(email="a@x.de", ip="", device=a, other_email="zzz@y.de", other_ips=set(),
                      other_devices=[("", "", "")])
    assert punkte == 0


def test_device_tokens() -> None:
    kennung = new_device_token()
    assert token_hash(kennung) and token_hash(kennung) == token_hash(kennung)
    assert token_hash(kennung) != kennung
    for kaputt in ("", "kurz", "a" * 65, "abc def ghi jkl mno", "ä" * 20, "x;y=z" * 5):
        assert token_hash(kaputt) == ""


@pytest.mark.parametrize(("a", "b", "gleich"), [
    ("max.muster@gmail.com", "maxmuster@gmail.com", True),
    ("max.muster+test@gmail.com", "max.muster@web.de", True),
    ("maxmuster1@gmail.com", "maxmuster2@gmail.com", True),
    ("anna.schmidt@web.de", "anna.schmitt@web.de", True),
    ("anna@web.de", "bernd@web.de", False),
    ("mama.meier@web.de", "papa.meier@web.de", False),
    ("a1@x.de", "a2@x.de", False),  # zu kurz, um etwas zu sagen
])
def test_similar_emails(a: str, b: str, gleich: bool) -> None:
    assert emails_similar(a, b) is gleich


# -- Punkte ---------------------------------------------------------------------------
def _punkte(**mehr: Any) -> float:
    werte: dict[str, Any] = {"email": "neu@x.de", "ip": "", "device": clean_device({}),
                             "other_email": "alt@y.de", "other_ips": set(), "other_devices": []}
    werte.update(mehr)
    return score(**werte)[0]


def test_the_examples_from_the_request() -> None:
    handy = clean_device(HANDY, user_agent=HANDY_UA, cookie="A" * 32)
    fremd = clean_device(PC, user_agent=PC_UA, cookie="B" * 32)
    zeile = (handy.cookie_hash, handy.hardware_hash, handy.browser_hash)
    # Dieselbe IP-Adresse allein ist nur merkwuerdig.
    assert _punkte(ip="203.0.113.1", other_ips={"203.0.113.1"}) == devices.POINTS_IP
    # Selbe Adresse und selber Browser: geht durch.
    browser_gleich = clean_device({"lang": "de-DE"}, user_agent=HANDY_UA)
    p = _punkte(ip="203.0.113.1", other_ips={"203.0.113.1"}, device=browser_gleich,
                other_devices=[zeile])
    assert p == 1.5 and p < devices.BLOCK_POINTS
    # Dasselbe Handy (Geraete-Kennung): Sperre.
    assert _punkte(device=handy, other_devices=[zeile]) >= devices.BLOCK_POINTS
    # Adresse + aehnliche E-Mail + gleiche Hardware: Sperre.
    gleiche_hw = clean_device(HANDY, user_agent=HANDY_UA.replace("126", "125"))
    assert _punkte(email="max.muster@x.de", other_email="maxmuster@y.de", ip="1.2.3.4",
                   other_ips={"1.2.3.4"}, device=gleiche_hw,
                   other_devices=[zeile]) >= devices.BLOCK_POINTS
    # Ein fremdes Geraet zaehlt nichts.
    assert _punkte(device=fremd, other_devices=[zeile]) == 0


def test_two_identical_phones_in_one_household_pass() -> None:
    """Zwei gleiche Handys hinter demselben Router: 1,5 + 1 = 2,5 -- geht durch."""
    erstes = clean_device(HANDY, user_agent=HANDY_UA, cookie="A" * 32)
    zweites = clean_device(HANDY, user_agent=HANDY_UA, cookie="C" * 32)
    p = _punkte(device=zweites, ip="1.2.3.4", other_ips={"1.2.3.4"},
                other_devices=[(erstes.cookie_hash, erstes.hardware_hash, erstes.browser_hash)])
    assert p == 2.5 and p < devices.BLOCK_POINTS


def test_only_the_strongest_device_match_counts() -> None:
    """Mehrere Geraete desselben Kontos addieren sich nicht auf."""
    handy = clean_device(HANDY, user_agent=HANDY_UA)
    zeile = ("", handy.hardware_hash, handy.browser_hash)
    assert _punkte(device=handy, other_devices=[zeile] * 5) == 1.5


# -- Registrierung --------------------------------------------------------------------
def _reg(store: AuthStore, mail: str, name: str, ip: str = "", device: Any = None) -> Any:
    return store.register(mail, "ein langes Passwort", "normal", username=name, ip=ip,
                          device=device, **TERMS)


def test_a_household_can_have_two_accounts(store: AuthStore) -> None:
    mama = clean_device(PC, user_agent=PC_UA, cookie="M" * 32)
    kind = clean_device(HANDY, user_agent=HANDY_UA, cookie="K" * 32)
    _reg(store, "petra.meier@web.de", "petra", "203.0.113.7", mama)
    _reg(store, "lena2010@gmx.de", "lena", "203.0.113.7", kind)
    # Selber Browser auf einem anderen Geraet geht auch.
    _reg(store, "opa@t-online.de", "opa", "203.0.113.7", clean_device({}, user_agent=PC_UA))


def test_the_same_device_cannot_make_a_second_account(store: AuthStore) -> None:
    handy = clean_device(HANDY, user_agent=HANDY_UA, cookie="H" * 32)
    _reg(store, "eins@web.de", "eins", "203.0.113.8", handy)
    # Anderes Netz (Mobilfunk), andere Mail -- aber dasselbe Handy.
    with pytest.raises(ValueError, match="schon ein Konto"):
        _reg(store, "zweiundzwanzig@gmx.de", "zwei", "198.51.100.3", handy)


def test_a_device_seen_at_login_counts_too(store: AuthStore) -> None:
    konto = _reg(store, "eins@web.de", "eins", "203.0.113.8")
    handy = clean_device(HANDY, user_agent=HANDY_UA, cookie="L" * 32)
    store.note_device(konto.id, handy)
    with pytest.raises(ValueError, match="schon ein Konto"):
        _reg(store, "ganz.anders@gmx.de", "zwei", "", handy)


def test_loopback_does_not_count_as_same_address(store: AuthStore) -> None:
    geraet = clean_device(PC, user_agent=PC_UA)
    _reg(store, "max.muster@web.de", "aa", "127.0.0.1", geraet)
    # Aehnliche Mail + Hardware/Browser = 2,5; die Loopback-Adresse zaehlt nicht.
    _reg(store, "maxmuster@gmx.de", "bb", "127.0.0.1", geraet)


def test_suspicious_registrations_are_logged(store: AuthStore,
                                             capsys: pytest.CaptureFixture[str]) -> None:
    _reg(store, "anna@web.de", "anna", "203.0.113.9", clean_device({}, user_agent=PC_UA))
    _reg(store, "bernd@web.de", "bernd", "203.0.113.9", clean_device({}, user_agent=PC_UA))
    ausgabe = capsys.readouterr().out
    assert "1.5 Punkte" in ausgabe and "dieselbe IP-Adresse" in ausgabe
    assert "abgelehnt" not in ausgabe


def test_devices_are_listed_and_deleted_with_the_account(store: AuthStore) -> None:
    konto = _reg(store, "eins@web.de", "eins", "", clean_device(PC, user_agent=PC_UA))
    hardware, browser = store.last_device(konto.id)
    assert hardware.startswith("Windows") and browser.startswith("Chrome 126")
    store.note_device(konto.id, clean_device(HANDY, user_agent=HANDY_UA))
    assert store.last_device(konto.id)[0].startswith("Android")
    # Hoechstens 20 Geraete je Konto.
    for nummer in range(30):
        store.note_device(konto.id, clean_device({"cores": nummer + 1}, user_agent=PC_UA))
    import sqlite3

    with sqlite3.connect(store.db_path) as conn:
        anzahl = conn.execute("SELECT COUNT(*) FROM account_devices WHERE user_id=?",
                              (konto.id,)).fetchone()[0]
    assert anzahl == 20
    store.remove_account(konto)
    assert store.last_device(konto.id) == ("", "")


def test_note_device_ignores_nonsense(store: AuthStore) -> None:
    konto = _reg(store, "eins@web.de", "eins")
    store.note_device(konto.id, None)
    store.note_device(konto.id, {"hardware": "x"})
    store.note_device(konto.id, clean_device(None))
    assert store.last_device(konto.id) == ("", "")


# -- aquaticy list --------------------------------------------------------------------
def test_the_list_shows_only_how_many_devices(tmp_path: Path,
                                           monkeypatch: pytest.MonkeyPatch) -> None:
    from typer.testing import CliRunner

    from aquaticy import cli, config
    from aquaticy.auth import pro_code_for

    monkeypatch.setenv("AQUATICY_DATA_DIR", str(tmp_path))
    config.reset_settings_cache()
    try:
        store = AuthStore(tmp_path, pro_code_for(tmp_path))
        _reg(store, "liste@example.org", "Liste", "",
             clean_device(PC, user_agent=PC_UA, accept_language="de-DE"))
        # Rich-Markup aus dem Browser darf die Tabelle nicht umfaerben.
        _reg(store, "markup@example.org", "Markup", "",
             clean_device({"cores": 2, "gpu": "[red]rot[/red]"}, user_agent=PC_UA))
        _reg(store, "ohne@example.org", "Ohne")
        ausgabe = CliRunner().invoke(cli.app, ["list"], env={"COLUMNS": "400"}).output
        # Seit 9.5.32 sieht der Betreiber Hardware und Browser nicht mehr --
        # nur wie viele Geraete ein Konto hat (tests/test_v9532.py).
        assert "Geräte" in ausgabe
        assert "Windows" not in ausgabe and "RTX 4070" not in ausgabe
        assert "Chrome" not in ausgabe and "[red]rot" not in ausgabe
        zeile = next(z for z in ausgabe.splitlines() if z.startswith("Liste"))
        assert " 1 " in zeile
    finally:
        config.reset_settings_cache()


# -- Internet fuer die virtual machine (nur Ultra) -----------------------------------
def _sitzung(tmp_path: Path, monkeypatch: pytest.MonkeyPatch, plan: str) -> Path:
    from aquaticy import web

    konto = type("Konto", (), {"plan": plan, "username": plan})()
    profil = tmp_path / "konto"
    profil.mkdir(exist_ok=True)
    monkeypatch.setattr(web, "SESSION", web.ChatSession(account=konto, profile=profil))
    return profil


@pytest.mark.parametrize("plan", ["normal", "pro"])
def test_normal_and_pro_cannot_switch_the_vm_lan_on(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, plan: str
) -> None:
    from aquaticy import web

    profil = _sitzung(tmp_path, monkeypatch, plan)
    # Seit 9.5.34: Internet haben Normal und Pro immer -- das lokale Netz nie.
    for wert in ("true", "1", "on", "ja", "TRUE "):
        with pytest.raises(ValueError, match="Ultra"):
            web.save_values({"AQUATICY_VM_LAN": wert})
    assert not (profil / ".env").exists() or "VM_LAN=true" not in (
        profil / ".env").read_text()
    # Ausschalten geht immer.
    web.save_values({"AQUATICY_VM_LAN": "false"})


def test_ultra_can_switch_vm_internet_on(tmp_path: Path,
                                         monkeypatch: pytest.MonkeyPatch) -> None:
    from aquaticy import web

    profil = _sitzung(tmp_path, monkeypatch, "ultra")
    web.save_values({"AQUATICY_VM_INTERNET": "true"})
    assert "AQUATICY_VM_INTERNET=true" in (profil / ".env").read_text()
    assert web.current_values()["AQUATICY_VM_INTERNET"] == "true"


def test_the_env_switch_only_counts_for_ultra(tmp_path: Path) -> None:
    from aquaticy import web

    profil = tmp_path / "konto"
    profil.mkdir()
    (profil / ".env").write_text("AQUATICY_VM_INTERNET=true\nAQUATICY_VM_LAN=true\n",
                                 encoding="utf-8")
    assert web._profile_settings(profil, "ultra").vm_internet is True
    assert web._profile_settings(profil, "ultra").vm_lan is True
    # Normal und Pro: immer Internet (9.5.34), nie das lokale Netz.
    for plan in ("pro", "normal"):
        einstellungen = web._profile_settings(profil, plan)
        assert einstellungen.vm_internet is True and einstellungen.vm_lan is False


def test_the_model_cannot_switch_vm_internet() -> None:
    from aquaticy import preferences
    from aquaticy.tools import Toolbox

    assert "AQUATICY_VM_INTERNET" in preferences.PROTECTED
    werkzeuge = Toolbox(Settings(), cache=None)
    for name in ("vm_internet", "AQUATICY_VM_INTERNET", "werkstatt_internet", "vm_netz"):
        assert "error" in werkzeuge.change_setting(name, "an"), name


def test_the_form_carries_the_ultra_switch() -> None:
    from aquaticy import web

    html = web.UI_FILE.read_text(encoding="utf-8")
    assert 'id="vminternet"' in html and 'name="AQUATICY_VM_INTERNET"' in html
    stelle = html.index('id="vminternet"')
    assert "Ultra" in html[stelle:stelle + 400]
    assert '$("#vminternet").addEventListener' in html
    assert '"Internet für die virtual machine": "Internet for the virtual machine"' in html


def _flags(box: Any) -> list[str]:
    from aquaticy import sandbox

    box.runtime = sandbox.Runtime("docker", "docker", "Docker (gehaertet)")
    box._name, box._volume = "aquaticy-test", "aquaticy-test-vol"
    return box._run_flags()


def test_the_vm_without_internet_has_no_network() -> None:
    from aquaticy import sandbox

    box = sandbox.Sandbox()
    flags = _flags(box)
    assert flags[flags.index("--network"):flags.index("--network") + 2] == ["--network", "none"]
    assert "NET_ADMIN" not in flags
    assert box.image == sandbox.DEFAULT_IMAGE and not box.netz_offen
    assert not any(f.startswith("/run:") for f in flags)


def test_the_vm_with_internet_is_locked_like_user_mode() -> None:
    from aquaticy import sandbox

    box = sandbox.Sandbox(internet=True, headless=True)
    flags = _flags(box)
    assert "--network" not in flags
    assert "NET_ADMIN" in flags and "ALL" in flags  # nur diese eine Faehigkeit
    assert "no-new-privileges" in flags and "--read-only" in flags
    # iptables-legacy braucht ein beschreibbares /run fuer die Sperre.
    assert "/run:rw,nosuid,nodev,size=8m" in flags
    # Kein Desktop: kein DISPLAY, kein grosses /dev/shm.
    assert "--shm-size" not in flags
    assert not any(f.startswith("DISPLAY=") for f in flags)
    assert box.image == sandbox.DESKTOP_IMAGE and box.netz_offen
    assert box.status()["internet"] is True


def test_the_home_network_lock_is_fail_closed_for_internet() -> None:
    """Ohne Heimnetz-Sperre startet die Maschine mit Internet nicht: start()
    sperrt, sobald das Netz offen ist, und _lock_network bricht sonst ab."""
    import inspect

    from aquaticy import sandbox

    quelle = inspect.getsource(sandbox.Sandbox)
    assert "if self.netz_offen:\n" in quelle and "self._lock_network()" in quelle
    assert "BLOCKED_RANGES" in inspect.getsource(sandbox.Sandbox._lock_network)


def test_user_mode_wins_over_internet() -> None:
    from aquaticy import sandbox

    box = sandbox.Sandbox(user_mode=True, internet=True)
    assert box.user_mode and not box.internet and box.netz_offen


def test_shared_builds_the_internet_vm(tmp_path: Path) -> None:
    from aquaticy import sandbox

    einstellungen = Settings(data_dir=tmp_path / "d", env_path=tmp_path / ".env")
    einstellungen.vm_internet = True
    try:
        box = sandbox.shared(einstellungen)
        assert box.internet and box.headless and not box.user_mode
        assert box.image == sandbox.DESKTOP_IMAGE
    finally:
        sandbox.forget_shared(einstellungen)


def test_the_model_is_told_about_the_internet() -> None:
    from aquaticy.tools import VM_NET_INTERNET, VM_NET_OFF, vm_schemas_for

    def text(**mehr: Any) -> str:
        einstellungen = Settings()
        for key, wert in mehr.items():
            setattr(einstellungen, key, wert)
        return next(s for s in vm_schemas_for(einstellungen)
                    if s["function"]["name"] == "vm_run")["function"]["description"]

    assert VM_NET_OFF in text()
    assert VM_NET_INTERNET in text(vm_internet=True)
    assert "Heimnetz" in VM_NET_INTERNET


# -- Ende zu Ende: Geraete-Kennung ---------------------------------------------------
def _registrieren(port: int, mail: str, name: str, cookie: str = "",
                  geraet: dict[str, Any] | None = None) -> tuple[int, dict[str, str], bytes]:
    _, kopf, _ = _req(port, "POST", "/api/consent", {"accepted": True})
    zustimmung = kopf["Set-Cookie"].split(";", 1)[0]
    return _req(port, "POST", "/api/auth/register", {
        "email": mail, "username": name, "password": "ein langes Passwort", "plan": "normal",
        "terms_accepted": True, "device": geraet or {}},
        zustimmung + (f"; {cookie}" if cookie else ""))


def test_registration_sets_the_device_cookie(server: tuple[int, Path]) -> None:  # noqa: F811
    from http.client import HTTPConnection

    port, _ = server
    _, kopf, _ = _req(port, "POST", "/api/consent", {"accepted": True})
    zustimmung = kopf["Set-Cookie"].split(";", 1)[0]
    conn = HTTPConnection("127.0.0.1", port, timeout=60)
    conn.request("POST", "/api/auth/register", body=json.dumps({
        "email": "geraet1@example.org", "username": "geraet1",
        "password": "ein langes Passwort", "plan": "normal", "terms_accepted": True,
        "device": HANDY}), headers={"Content-Type": "application/json",
                                    "User-Agent": HANDY_UA, "Cookie": zustimmung})
    antwort = conn.getresponse()
    antwort.read()
    kekse = antwort.headers.get_all("Set-Cookie") or []
    conn.close()
    assert antwort.status == 200
    geraet = [k for k in kekse if k.startswith(devices.DEVICE_COOKIE + "=")]
    assert geraet, kekse
    assert "HttpOnly" in geraet[0] and "SameSite" in geraet[0]
    kennung = geraet[0].split(";", 1)[0]
    # Dasselbe Geraet (Cookie) kann kein zweites Konto anlegen -- auch nicht von
    # der Loopback-Adresse, denn die Kennung wiegt allein 3 Punkte.
    status, _, daten = _registrieren(port, "voellig.anders@example.org", "geraet2", kennung)
    assert status == 400 and "schon ein Konto" in daten.decode(), daten
    # Ein anderes Geraet (ohne Cookie) schon.
    status, _, daten = _registrieren(port, "noch.jemand@example.org", "geraet3")
    assert status == 200, daten


def test_a_forged_device_cookie_is_replaced(server: tuple[int, Path]) -> None:  # noqa: F811
    from http.client import HTTPConnection

    port, _ = server
    _, kopf, _ = _req(port, "POST", "/api/consent", {"accepted": True})
    zustimmung = kopf["Set-Cookie"].split(";", 1)[0]
    conn = HTTPConnection("127.0.0.1", port, timeout=60)
    conn.request("POST", "/api/auth/register", body=json.dumps({
        "email": "falsch@example.org", "username": "falsch",
        "password": "ein langes Passwort", "plan": "normal", "terms_accepted": True}),
        headers={"Content-Type": "application/json", "User-Agent": PC_UA,
                 "Cookie": f"{zustimmung}; {devices.DEVICE_COOKIE}=<kaputt>"})
    antwort = conn.getresponse()
    antwort.read()
    kekse = antwort.headers.get_all("Set-Cookie") or []
    conn.close()
    assert antwort.status == 200
    neu = [k for k in kekse if k.startswith(devices.DEVICE_COOKIE + "=")]
    assert neu and "<kaputt>" not in neu[0]
    # Die Sitzung kommt zuletzt -- einfache Clients behalten nur das letzte.
    assert kekse[-1].startswith("aquaticy_session=")
