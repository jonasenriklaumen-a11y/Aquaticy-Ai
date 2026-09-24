"""Rechte je Add-on (9.5.10) -- einfach einzustellen, im Code durchgesetzt.

Geprueft wird nicht, ob die Einstellung gespeichert wird, sondern ob sie
WIRKT: ein Messenger auf "Nur lesen" tippt und sendet nichts, auch wenn das
Bildmodell "harmlos" sagt; "Nur Einzelchats" schreibt in keine Gruppe, auch
nicht in eine, die nicht sicher als Einzelchat zu erkennen ist; GitHub auf
"Nur öffentliche" liest kein privates Repo -- geprueft bei GitHub.
"""

from __future__ import annotations

import json
import subprocess
from pathlib import Path
from types import SimpleNamespace
from typing import Any

import httpx
import pytest

from aquaticy import addons
from aquaticy.config import Settings
from aquaticy.desktop import Desktop


@pytest.fixture
def konto(tmp_path: Path) -> Settings:
    ordner = tmp_path / "konto"
    ordner.mkdir()
    return Settings(data_dir=ordner, env_path=ordner / ".env", vm_user_mode=True)


def _an(konto: Settings, *ids: str) -> None:
    for addon_id in ids:
        addons._update(konto, addon_id, installed=True, enabled=True)


# -- Katalog und Speicher ----------------------------------------------------------
def test_every_addon_has_simple_rights() -> None:
    for addon_id in addons.CATALOG:
        rechte = addons.RIGHTS[addon_id]
        assert 1 <= len(rechte) <= 2, "einfach: ein, zwei Fragen je Add-on"
        for recht in rechte:
            assert 2 <= len(recht.options) <= 3
            assert recht.default in dict(recht.options)


def test_messengers_start_read_only(konto: Settings) -> None:
    _an(konto, "signal")
    assert addons.rights_of(konto, "signal") == {"zugriff": "lesen", "wo": "einzeln"}


def test_rights_are_checked_before_saving(konto: Settings) -> None:
    with pytest.raises(addons.AddOnError, match="nicht installiert"):
        addons.set_rights(konto, "signal", {"zugriff": "schreiben"})
    _an(konto, "signal")
    for falsch in ({"zugriff": "alles"}, {"root": "ja"}, {}, "schreiben", None):
        with pytest.raises(addons.AddOnError):
            addons.set_rights(konto, "signal", falsch)
    assert addons.set_rights(konto, "signal", {"zugriff": "schreiben"}) == {
        "zugriff": "schreiben", "wo": "einzeln"}


def test_a_broken_state_falls_back_to_the_default(konto: Settings) -> None:
    _an(konto, "whatsapp")
    addons._update(konto, "whatsapp", rechte={"zugriff": "ALLES", "wo": 5})
    assert addons.rights_of(konto, "whatsapp") == {"zugriff": "lesen", "wo": "einzeln"}


def test_the_window_shows_rights_with_their_dependency(konto: Settings) -> None:
    _an(konto, "telegram")
    ansicht = next(a for a in addons.public_view(konto, pro=True)["addons"]
                   if a["id"] == "telegram")
    assert ansicht["rechte"] == {"zugriff": "lesen", "wo": "einzeln"}
    wo = next(r for r in ansicht["rechte_katalog"] if r["key"] == "wo")
    assert wo["nur_wenn"] == ["zugriff", "schreiben"]
    assert [o["label"] for o in wo["options"]] == ["Nur Einzelchats", "Einzelchats und Gruppen"]


def test_the_prompt_knows_the_rights(konto: Settings) -> None:
    _an(konto, "whatsapp", "github")
    text = addons.prompt_for(konto)
    assert "WhatsApp Web: Was Aquaticy darf: Nur lesen" in text
    assert "Schreiben in" not in text.split("WhatsApp Web:")[1].split("\n")[0], (
        "ein Recht, das nicht gilt, steht nicht da")
    addons.set_rights(konto, "whatsapp", {"zugriff": "schreiben"})
    assert "Lesen und schreiben; Schreiben in: Nur Einzelchats" in addons.prompt_for(konto)


# -- GitHub -------------------------------------------------------------------------
def _github(antworten: dict[str, Any], gefragt: list[httpx.Request]) -> httpx.Client:
    def handler(anfrage: httpx.Request) -> httpx.Response:
        gefragt.append(anfrage)
        pfad = anfrage.url.path
        for anfang, antwort in antworten.items():
            if pfad == anfang:
                return httpx.Response(200, json=antwort)
        return httpx.Response(404, json={})

    return httpx.Client(transport=httpx.MockTransport(handler))


TOKEN = "ghp_" + "r" * 36


def test_public_only_hides_private_repos_everywhere() -> None:
    gefragt: list[httpx.Request] = []
    client = _github({
        "/user/repos": [{"full_name": "a/offen", "private": False},
                        {"full_name": "a/geheim", "private": True}],
        "/repos/a/geheim": {"private": True},
        "/repos/a/offen": {"private": False, "full_name": "a/offen"},
        "/search/issues": {"items": []},
    }, gefragt)
    repos = addons.github_call(TOKEN, "repos", client=client, nur_oeffentlich=True)
    assert [r["name"] for r in repos["repos"]] == ["a/offen"]
    assert gefragt[-1].url.params["visibility"] == "public"
    antwort = addons.github_call(TOKEN, "issues", repo="a/geheim", client=client,
                                 nur_oeffentlich=True)
    assert "privat" in antwort["error"]
    assert gefragt[-1].url.path == "/repos/a/geheim", "nach der Pruefung nichts mehr gelesen"
    assert addons.github_call(TOKEN, "repo", repo="a/offen", client=client,
                              nur_oeffentlich=True)["name"] == "a/offen"
    addons.github_call(TOKEN, "suche", query="bug", client=client, nur_oeffentlich=True)
    assert gefragt[-1].url.params["q"].endswith("is:public")


def test_overview_only_reads_no_file_contents() -> None:
    import base64

    gefragt: list[httpx.Request] = []
    client = _github({
        "/repos/a/b/contents/src": [{"name": "x.py", "type": "file", "size": 3}],
        "/repos/a/b/contents/src/x.py": {"encoding": "base64", "size": 3,
                                          "content": base64.b64encode(b"geheim").decode()},
    }, gefragt)
    ordner = addons.github_call(TOKEN, "datei", repo="a/b", path="src", client=client,
                                inhalte=False)
    assert ordner["eintraege"][0]["name"] == "x.py"
    datei = addons.github_call(TOKEN, "datei", repo="a/b", path="src/x.py", client=client,
                               inhalte=False)
    assert "text" not in datei and "geheim" not in json.dumps(datei)


def test_the_toolbox_passes_the_github_rights(konto: Settings,
                                              monkeypatch: pytest.MonkeyPatch) -> None:
    from aquaticy.tools import Toolbox

    _an(konto, "github")
    konto.github_token = TOKEN
    addons.set_rights(konto, "github", {"repos": "oeffentlich", "inhalte": "nein"})
    gesehen: dict[str, Any] = {}
    monkeypatch.setattr(addons, "github_call",
                        lambda token, action, **kw: gesehen.update(kw) or {"ok": True})
    box = Toolbox.__new__(Toolbox)
    box.settings, box.guard = konto, None
    box.stats = SimpleNamespace(addon_calls=0)
    box.call("github", {"action": "repos"})
    assert gesehen["nur_oeffentlich"] is True and gesehen["inhalte"] is False


# -- Wetter und Feeds ------------------------------------------------------------------
def test_weather_can_be_limited_to_my_place(konto: Settings,
                                            monkeypatch: pytest.MonkeyPatch) -> None:
    from aquaticy.tools import Toolbox

    _an(konto, "wetter")
    addons.set_rights(konto, "wetter", {"orte": "meiner"})
    orte: list[str] = []
    monkeypatch.setattr(addons, "weather", lambda ort, tage: orte.append(ort) or {"ok": 1})
    box = Toolbox.__new__(Toolbox)
    box.settings, box.guard = konto, None
    box.stats = SimpleNamespace(addon_calls=0)
    assert "keinen Ort" in box.call("weather", {"place": "Paris"})["error"]
    konto.location = "Bremen"
    box.call("weather", {"place": "Paris"})
    assert orte == ["Bremen"], "Nur mein Ort: Paris wird nicht gefragt"


def test_feeds_never_return_more_than_allowed(konto: Settings,
                                              monkeypatch: pytest.MonkeyPatch) -> None:
    from aquaticy.tools import Toolbox

    addons.install(konto, "feeds", pro=False)
    addons.set_feeds(konto, ["https://a.example/rss"])
    addons.set_rights(konto, "feeds", {"menge": "10"})
    grenzen: list[int] = []
    monkeypatch.setattr(addons, "read_feeds", lambda f, q, n: grenzen.append(n) or {})
    box = Toolbox.__new__(Toolbox)
    box.settings, box.guard = konto, None
    box.stats = SimpleNamespace(addon_calls=0)
    box.call("read_feeds", {"limit": 40})
    box.call("read_feeds", {"limit": "drei"})
    assert grenzen == [10, 10]


# -- Blender -----------------------------------------------------------------------
def test_blender_scripts_only_keeps_the_window_closed(konto: Settings) -> None:
    _an(konto, "blender")
    assert "blender" in addons.desktop_apps(konto)
    addons.set_rights(konto, "blender", {"nutzung": "skripte"})
    assert "blender" not in addons.desktop_apps(konto)
    desktop = Desktop(Box(), konto, vision=lambda bild, prompt: "{}")
    assert "nicht installiert oder ausgeschaltet" in desktop.open("blender")["error"]
    from aquaticy.tools import vm_schemas_for

    assert "blender_run" in [s["function"]["name"] for s in vm_schemas_for(konto)]


# -- Messenger im Desktop --------------------------------------------------------------
class Box:
    """Die Werkstatt: vorn ist das Fenster, das der Test will."""

    def __init__(self, klasse: str = "Navigator.aquaticy-whatsapp",
                 titel: str = "WhatsApp") -> None:
        self.klasse, self.titel = klasse, titel
        self.aufrufe: list[tuple[str, ...]] = []

    def screenshot(self, **kwargs: Any) -> bytes:
        return b"\xff\xd8JPEG"

    def desktop(self, *args: str, stdin: bytes | None = None, timeout: float = 60):
        self.aufrufe.append(args)
        antwort: dict[str, Any] = {"ok": True, "fenster": self.titel}
        if args[0] == "windows":
            antwort = {"fenster": [{"id": "0x1", "klasse": self.klasse, "titel": self.titel}],
                       "aktiv": self.titel, "aktiv_klasse": self.klasse}
        return subprocess.CompletedProcess(args, 0, json.dumps(antwort).encode(), b"")

    def handgriffe(self) -> list[str]:
        return [a[0] for a in self.aufrufe if a[0] != "windows"]


class Auge:
    """Das Bildmodell: sagt, was der Test will -- auch fuer den Chat."""

    def __init__(self, art: str = "harmlos", gruppe: Any = False, chat: str = "Mama") -> None:
        self.art, self.gruppe, self.chat = art, gruppe, chat
        self.fragen: list[str] = []

    def __call__(self, bild: bytes, prompt: str) -> str:
        self.fragen.append(prompt)
        if "Messenger" in prompt:
            return json.dumps({"chat": self.chat, "gruppe": self.gruppe})
        if "Eingabefeld" in prompt:
            return json.dumps({"feld": "sonstiges", "art": "harmlos"})
        if "Finde dieses Element" in prompt:
            return json.dumps({"gefunden": True, "x": 900, "y": 700, "was": "Senden-Knopf",
                               "art": self.art})
        return json.dumps({"was": "Nachricht abschicken", "art": self.art})


def _desktop(konto: Settings, box: Box, auge: Auge, antworten: list[str] | None = None):
    gefragt: list[str] = []
    antworten = list(antworten or ["ja"])

    def ask(frage: str, optionen: list[str]) -> str:
        gefragt.append(frage)
        return antworten.pop(0) if antworten else "nein"

    return Desktop(box, konto, vision=auge, ask=ask), gefragt


def test_read_only_types_and_sends_nothing(konto: Settings) -> None:
    _an(konto, "whatsapp")
    box, auge = Box(), Auge(art="harmlos")
    desktop, gefragt = _desktop(konto, box, auge)
    assert desktop.type("Hallo Mama")["skipped_reason"] == "messenger_read_only"
    assert desktop.key("Return")["skipped_reason"] == "messenger_read_only"
    assert desktop.key("ctrl+v")["skipped_reason"] == "messenger_read_only"
    auge.art = "senden"
    assert desktop.click(target="Senden")["skipped_reason"] == "messenger_read_only"
    assert box.handgriffe() == [] and gefragt == [], "weder gehandelt noch gefragt"
    # Lesen geht: blaettern und harmlose Klicks.
    assert desktop.key("Page_Down")["gedrueckt"] == ["Page_Down"]
    auge.art = "harmlos"
    assert desktop.click(target="Chat Mama")["geklickt"] == [900, 700]
    assert box.handgriffe() == ["key", "click"]


def test_single_chats_only_refuses_groups_and_unclear_chats(konto: Settings) -> None:
    _an(konto, "signal")
    addons.set_rights(konto, "signal", {"zugriff": "schreiben", "wo": "einzeln"})
    for gruppe in (True, None, "vielleicht"):
        box = Box(klasse="signal.Signal", titel="Signal")
        desktop, gefragt = _desktop(konto, box, Auge(gruppe=gruppe, chat="Familie"))
        assert desktop.type("Hallo")["skipped_reason"] == "messenger_no_groups", gruppe
        assert box.handgriffe() == []
    box = Box(klasse="signal.Signal", titel="Signal")
    desktop, gefragt = _desktop(konto, box, Auge(gruppe=False, chat="Mama"))
    assert desktop.type("Hallo Mama")["getippt"] == 10
    desktop._vision.art = "senden"
    antwort = desktop.key("Return")
    assert antwort["gedrueckt"] == ["Return"]
    assert "Einzelchat: Mama" in gefragt[0], "die Rueckfrage nennt den Chat"


def test_groups_allowed_still_asks_before_sending(konto: Settings) -> None:
    _an(konto, "telegram")
    addons.set_rights(konto, "telegram", {"zugriff": "schreiben", "wo": "alle"})
    box = Box(klasse="Navigator.aquaticy-telegram", titel="Telegram Web")
    desktop, gefragt = _desktop(konto, box, Auge(art="senden", gruppe=True), ["nein"])
    assert desktop.type("Hallo zusammen")["getippt"] == 14
    assert desktop.key("Return")["done"] is False
    assert len(gefragt) == 1 and box.handgriffe() == ["type"]


def test_a_messenger_outside_its_addon_gets_the_strictest_rights(konto: Settings) -> None:
    _an(konto, "whatsapp")
    addons.set_rights(konto, "whatsapp", {"zugriff": "schreiben", "wo": "alle"})
    # Telegram ist nicht eingeschaltet -- sein Fenster (etwa im Browser) gilt als "Nur lesen".
    box = Box(klasse="Falkon Browser.Falkon", titel="Telegram Web - Falkon")
    desktop, _ = _desktop(konto, box, Auge())
    assert desktop.type("x")["skipped_reason"] == "messenger_read_only"


def test_the_ordinary_browser_does_not_open_messengers(konto: Settings) -> None:
    box = Box(klasse="x", titel="x")
    desktop, _ = _desktop(konto, box, Auge())
    for adresse in ("https://web.whatsapp.com/", "https://WEB.TELEGRAM.ORG/a/"):
        assert desktop.open("browser", adresse)["skipped_reason"] == "messenger_via_addon"
    assert box.aufrufe == []


def test_other_windows_are_not_affected(konto: Settings) -> None:
    box = Box(klasse="libreoffice.LibreOffice", titel="Brief - LibreOffice Writer")
    desktop, _ = _desktop(konto, box, Auge())
    assert desktop.type("Sehr geehrte Damen und Herren")["getippt"] == 29


@pytest.mark.parametrize(
    ("klasse", "titel", "erwartet"),
    [
        ("Navigator.aquaticy-whatsapp", "(3) WhatsApp", "whatsapp"),
        ("signal.Signal", "Signal", "signal"),
        ("Navigator.aquaticy-telegram", "Telegram", "telegram"),
        ("Falkon Browser.Falkon", "WhatsApp - Falkon", "whatsapp"),
        ("xterm.XTerm", "bash", ""),
        ("libreoffice.LibreOffice", "Signalverarbeitung.odt", "signal"),
    ],
)
def test_messenger_windows_are_recognised(klasse: str, titel: str, erwartet: str) -> None:
    # Im Zweifel eher als Messenger erkannt -- das ist die strengere Seite.
    assert addons.messenger_of(klasse, titel) == erwartet


# -- Das Fenster im Web -----------------------------------------------------------------
def test_changing_rights_keeps_the_workshop_running(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    from aquaticy import web

    profil = tmp_path / "p"
    profil.mkdir()
    (profil / ".env").write_text("AQUATICY_VM_USER_MODE=true\n", encoding="utf-8")
    sitzung = web.ChatSession(account=SimpleNamespace(plan="pro", username="p"), profile=profil)
    monkeypatch.setattr(web, "SESSION", sitzung)
    neu_gebaut: list[bool] = []
    monkeypatch.setattr(sitzung, "reload", lambda: neu_gebaut.append(True))
    _an(sitzung.settings(), "whatsapp")
    antwort, status = web.addon_action(
        {"action": "rights", "id": "whatsapp", "rechte": {"zugriff": "schreiben"}})
    assert status == 200 and "Lesen und schreiben" in antwort["message"]
    assert neu_gebaut == [], "die Werkstatt (und die Anmeldung darin) bleibt"
    whatsapp = next(a for a in antwort["addons"] if a["id"] == "whatsapp")
    assert whatsapp["rechte"]["zugriff"] == "schreiben"
    antwort, status = web.addon_action(
        {"action": "rights", "id": "whatsapp", "rechte": {"zugriff": "root"}})
    assert status == 400


def test_the_agent_prompt_follows_the_rights(settings: Settings,
                                             monkeypatch: pytest.MonkeyPatch) -> None:
    from aquaticy.agent import Agent

    settings.vm_user_mode = True
    _an(settings, "whatsapp")
    agent = Agent(settings, cache=None)
    assert "Nur lesen" in agent.messages[0]["content"]
    addons.set_rights(settings, "whatsapp", {"zugriff": "schreiben"})
    monkeypatch.setattr("litellm.completion", lambda **kw: SimpleNamespace(
        choices=[SimpleNamespace(message=SimpleNamespace(content="ok", tool_calls=None))]))
    agent.ask("Wie spät ist es?", stream=False)
    assert "Lesen und schreiben" in agent.messages[0]["content"]


def test_the_ui_has_simple_rights() -> None:
    from aquaticy import web

    html = web.UI_FILE.read_text(encoding="utf-8")
    for teil in ("function addonRechte", 'action: "rights"', "role\", \"radiogroup",
                 ".seg button.on"):
        assert teil in html, teil
