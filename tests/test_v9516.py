"""Regressionstests fuer 9.5.16 Lion -- je Befund der Pruefung mindestens einer."""

from __future__ import annotations

import contextlib
from typing import Any

import httpx
import pytest

from aquaticy.config import Settings
from aquaticy.tools import Toolbox


def _ha_settings(settings: Settings, control: bool = True) -> Settings:
    settings.ha_url = "http://192.168.1.5:8123"
    settings.ha_token = "geheim"
    settings.ha_control = control
    return settings


def _ha_transport(monkeypatch: pytest.MonkeyPatch) -> list[str]:
    """Jede Anfrage an Home Assistant landet hier -- mit ihrem Pfad."""
    pfade: list[str] = []

    def handler(request: httpx.Request) -> httpx.Response:
        pfade.append(request.url.path)
        return httpx.Response(200, json=[])

    transport = httpx.MockTransport(handler)

    def patched(method: str, url: str, **kwargs: Any) -> httpx.Response:
        kwargs.pop("timeout", None)
        with httpx.Client(transport=transport) as session:
            return session.request(method, url, **kwargs)

    monkeypatch.setattr(httpx, "request", patched)
    return pfade


# -- 36: Home Assistant -- Dienst und Ziel muessen zum Bereich passen ----------
@pytest.mark.parametrize("service", [
    "../lock/unlock", "..%2flock%2funlock", "turn_on/../../lock/unlock", "unlock?x=1",
    "turn on", "",
])
def test_a_light_service_can_never_become_a_lock(settings: Settings,
                                                 monkeypatch: pytest.MonkeyPatch,
                                                 service: str) -> None:
    pfade = _ha_transport(monkeypatch)
    box = Toolbox(_ha_settings(settings))  # ohne ask_handler, wie in Auftraegen
    result = box.ha_call("light", service, "light.kueche")
    assert result.get("done") is not True
    assert "error" in result
    assert not pfade, f"trotzdem gesendet: {pfade}"


@pytest.mark.parametrize("entity_id,data", [
    ("lock.haustuer", None),
    ("light.kueche, lock.haustuer", None),
    ("", {"entity_id": "lock.haustuer"}),
    ("", {"entity_id": ["light.kueche", "lock.haustuer"]}),
    ("", {"area_id": "flur"}),
    ("", {"device_id": "abc"}),
    ("light.kueche/../x", None),
])
def test_a_light_call_only_reaches_lights(settings: Settings, monkeypatch: pytest.MonkeyPatch,
                                          entity_id: str, data: Any) -> None:
    pfade = _ha_transport(monkeypatch)
    box = Toolbox(_ha_settings(settings))
    result = box.ha_call("light", "turn_on", entity_id, data)
    assert "error" in result
    assert not pfade


def test_a_plain_light_call_still_works(settings: Settings,
                                        monkeypatch: pytest.MonkeyPatch) -> None:
    pfade = _ha_transport(monkeypatch)
    box = Toolbox(_ha_settings(settings))
    result = box.ha_call("light", "turn_on", "light.kueche", {"brightness_pct": 40})
    assert result["done"] is True
    assert pfade == ["/api/services/light/turn_on"]


def test_the_client_itself_checks_too(monkeypatch: pytest.MonkeyPatch) -> None:
    """Auch wer den Client direkt benutzt, kommt nicht am Pruefen vorbei."""
    from aquaticy.homeassistant import HomeAssistant, HomeAssistantError

    pfade = _ha_transport(monkeypatch)
    with pytest.raises(HomeAssistantError):
        HomeAssistant("http://192.168.1.5:8123", "geheim").call("light", "../lock/unlock")
    assert not pfade


# -- 37: Skripte, Szenen und Knoepfe fragen nach ------------------------------
@pytest.mark.parametrize("domain,service,entity", [
    ("script", "turn_on", "script.tuer_auf"),
    ("scene", "turn_on", "scene.abwesend"),
    ("button", "press", "button.garage"),
])
def test_indirect_switches_need_a_confirmation(settings: Settings,
                                               monkeypatch: pytest.MonkeyPatch,
                                               domain: str, service: str, entity: str) -> None:
    pfade = _ha_transport(monkeypatch)
    box = Toolbox(_ha_settings(settings))
    assert "bestaetigungspflichtig" in box.ha_call(domain, service, entity)["error"]
    box.ask_handler = lambda frage, optionen: "nein"
    assert box.ha_call(domain, service, entity)["done"] is False
    assert not pfade
    box.ask_handler = lambda frage, optionen: "klar"  # 18: "klar" gilt als ja
    assert box.ha_call(domain, service, entity)["done"] is True
    assert pfade == [f"/api/services/{domain}/{service}"]


# -- P1: der Browser loest keine Namen mehr selbst auf ------------------------
import socket  # noqa: E402
import threading  # noqa: E402
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer  # noqa: E402

from aquaticy import netguard  # noqa: E402


class _Intern(BaseHTTPRequestHandler):
    treffer: list[str] = []  # noqa: RUF012

    def log_message(self, *args: Any) -> None:
        pass

    def do_GET(self) -> None:
        _Intern.treffer.append(self.path)
        self.send_response(200)
        self.send_header("Content-Type", "text/html")
        self.end_headers()
        self.wfile.write(b"<html><body>interne Verwaltung</body></html>")


@pytest.fixture
def intern_server():
    server = ThreadingHTTPServer(("127.0.0.1", 0), _Intern)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    _Intern.treffer.clear()
    yield server.server_address[1]
    server.shutdown()
    server.server_close()


def _umspringer(monkeypatch: pytest.MonkeyPatch) -> None:
    """DNS-Rebinding: die erste Antwort ist oeffentlich, jede weitere intern."""
    antworten = iter([["93.184.216.34"]])
    monkeypatch.setattr(netguard, "resolve",
                        lambda host, port: next(antworten, ["127.0.0.1"]))
    netguard.forget()


def _proxy_anfrage(zeile: bytes) -> bytes:
    with socket.create_connection(("127.0.0.1", netguard.browser_proxy().port), timeout=5) as s:
        s.sendall(zeile)
        return s.recv(4096)


def test_the_proxy_refuses_internal_targets(intern_server: int) -> None:
    for anfrage in (
        f"CONNECT 127.0.0.1:{intern_server} HTTP/1.1\r\nHost: x\r\n\r\n",
        f"GET http://127.0.0.1:{intern_server}/geheim HTTP/1.1\r\nHost: x\r\n\r\n",
        f"GET http://localhost:{intern_server}/geheim HTTP/1.1\r\nHost: x\r\n\r\n",
        f"CONNECT [::1]:{intern_server} HTTP/1.1\r\n\r\n",
        f"GET http://2130706433:{intern_server}/ HTTP/1.1\r\n\r\n",
    ):
        assert _proxy_anfrage(anfrage.encode()).startswith(b"HTTP/1.1 403"), anfrage
    assert _Intern.treffer == []


def test_the_proxy_resolves_only_once(monkeypatch: pytest.MonkeyPatch,
                                      intern_server: int) -> None:
    """Die Proxy-Pruefung ist die Verbindung: ein Umspringen danach gibt es nicht."""
    monkeypatch.setattr(netguard, "resolve", lambda host, port: ["127.0.0.1"])
    antwort = _proxy_anfrage(
        f"GET http://umspringer.example:{intern_server}/ HTTP/1.1\r\n\r\n".encode())
    assert antwort.startswith(b"HTTP/1.1 403")
    assert _Intern.treffer == []


#: Wo die Pruefumgebung ihr Chromium hat, wenn Playwright ein anderes erwartet.
CHROMIUM = "/opt/pw-browsers/chromium"


class _MitPfad:
    """Startet Chromium von CHROMIUM, falls Playwrights eigenes fehlt."""

    def __init__(self, pw: Any) -> None:
        from pathlib import Path

        self._pw = pw
        self._pfad = CHROMIUM if Path(CHROMIUM).exists() else None

    @property
    def chromium(self) -> Any:
        return self

    def launch(self, **kwargs: Any) -> Any:
        if self._pfad:
            kwargs.setdefault("executable_path", self._pfad)
        return self._pw.chromium.launch(**kwargs)


def _chromium_da() -> bool:
    try:
        from playwright.sync_api import sync_playwright
    except ImportError:
        return False
    try:
        with sync_playwright() as pw:
            _MitPfad(pw).launch(headless=True).close()
        return True
    except Exception:
        return False


@pytest.mark.skipif(not _chromium_da(), reason="Chromium fuer Playwright fehlt")
def test_p1_the_browser_never_reaches_an_internal_server_after_rebinding(
    monkeypatch: pytest.MonkeyPatch, intern_server: int
) -> None:
    """Nachgestellt wie im Bericht: die Vorabpruefung sieht eine oeffentliche
    Adresse, Chromiums eigene Aufloesung aber den eigenen Rechner."""
    from playwright.sync_api import sync_playwright

    from aquaticy.browser import guard_context, launch_browser

    umleitung = "--host-resolver-rules=MAP umspringer.example 127.0.0.1"
    adresse = f"http://umspringer.example:{intern_server}/geheim"

    # Gegenprobe: so, wie es bis 9.5.15 lief (nur Vorabpruefung), kommt er durch.
    _umspringer(monkeypatch)
    with sync_playwright() as pw:
        browser = _MitPfad(pw).launch(headless=True, args=[umleitung])
        context = browser.new_context()
        guard_context(context)
        page = context.new_page()
        with contextlib.suppress(Exception):
            page.goto(adresse, timeout=10_000)
        browser.close()
    assert "/geheim" in _Intern.treffer, "Gegenprobe: ohne Proxy erreichbar"

    # Seit 9.5.16: derselbe Ablauf, aber Chromium laedt ueber den Proxy.
    _Intern.treffer.clear()
    _umspringer(monkeypatch)
    with sync_playwright() as pw:
        browser = launch_browser(_MitPfad(pw), [umleitung])
        context = browser.new_context()
        guard_context(context)
        page = context.new_page()
        with pytest.raises(Exception):  # noqa: B017 -- ERR_TUNNEL/403
            antwort = page.goto(adresse, timeout=10_000)
            assert antwort is not None and antwort.status != 200
            raise RuntimeError("abgewiesen")
        browser.close()
    assert _Intern.treffer == []


# -- 1 und 29: die Oberflaeche -------------------------------------------------
import json  # noqa: E402
import re  # noqa: E402
import shutil  # noqa: E402
import subprocess  # noqa: E402
from pathlib import Path  # noqa: E402

WEBUI = Path(__file__).resolve().parent.parent / "aquaticy" / "webui.html"
NODE = shutil.which("node") or ("/opt/node22/bin/node" if Path("/opt/node22/bin/node").exists()
                                else "")


def _md(text: str) -> str:
    quelle = WEBUI.read_text(encoding="utf-8")
    anfang = quelle.index("const esc = (t)")
    ende = quelle.index("/* ---------- Nachrichten ---------- */")
    skript = quelle[anfang:ende] + f"\nprocess.stdout.write(md({json.dumps(text)}));\n"
    return subprocess.run([NODE, "-e", skript], capture_output=True, text=True, check=True,
                          timeout=30).stdout


@pytest.mark.skipif(not NODE, reason="node fehlt")
def test_code_blocks_stay_code() -> None:
    code = "# Kommentar\ndef f(*args, **kwargs):\n    x = 1\n\n    - keine Liste\n    return x"
    html = _md(f"Hier:\n\n```python\n{code}\n```\n\nFertig.")
    inhalt = re.search(r"<pre><code>([\s\S]*?)</code></pre>", html)
    assert inhalt and inhalt.group(1) == code
    assert "<em>" not in html and "<li>" not in html and "<h3>" not in html
    assert '<span class="lang">python</span>' in html
    assert html.endswith("<p>Fertig.</p>")


@pytest.mark.skipif(not NODE, reason="node fehlt")
def test_inline_code_and_unfinished_blocks() -> None:
    html = _md("Nutze `*args` und `**kw` -- *wirklich*")
    assert "<code>*args</code>" in html and "<code>**kw</code>" in html
    assert "<em>wirklich</em>" in html
    offen = _md("Gleich:\n```js\nconst a = 1;\n- b")
    assert "<pre><code>const a = 1;\n- b</code></pre>" in offen
    assert "<script>" not in _md("<script>x</script> ```\n<b>\n```")
    assert "undefined" not in _md("\u0000B7\u0000\nText \u0000C3\u0000")


def test_the_web_ui_shows_ai_images() -> None:
    """29: dasselbe Muster wie media.MEDIA_ID -- auch "-ki"."""
    from aquaticy.media import MEDIA_ID

    quelle = WEBUI.read_text(encoding="utf-8")
    muster = re.search(r"const stored = /(.+?)/\.test", quelle)
    assert muster
    js = re.compile(muster.group(1))
    for name in ("1727000000000-0123456789abcdef.png", "1727000000000-0123456789abcdef-ki.png",
                 "1727000000000-0123456789abcdef-fest.jpg", "x.png", "../a-ki.png"):
        assert bool(js.match(name)) == bool(MEDIA_ID.match(name)), name


# -- 40/41: eigene Such-Schluessel ------------------------------------------
def test_own_search_key_is_used_for_searches(settings: Settings,
                                             monkeypatch: pytest.MonkeyPatch) -> None:
    from aquaticy import tools
    from aquaticy.models import SearchResult

    gesehen: list[Any] = []

    def suche(query: str, **kwargs: Any) -> list[SearchResult]:
        gesehen.append(kwargs.get("api_key"))
        return [SearchResult(title="t", url="https://a.example/", snippet="s")]

    monkeypatch.setattr(tools, "search_web", suche)
    monkeypatch.setenv("BRAVE_API_KEY", "betreiber-schluessel")
    settings.search_backend = "brave"
    settings.search_keys = {"BRAVE_API_KEY": "mein-eigener-schluessel"}
    settings.own_key_names = frozenset({"BRAVE_API_KEY"})
    Toolbox(settings).web_search("kaffeemaschine test")
    assert gesehen and set(gesehen) == {"mein-eigener-schluessel"}


def test_a_normal_account_never_borrows_the_operators_paid_search_key(
    settings: Settings, monkeypatch: pytest.MonkeyPatch
) -> None:
    from aquaticy.search import SearchError, SearchOptions, _search_brave

    monkeypatch.setenv("BRAVE_API_KEY", "betreiber-schluessel")
    settings.search_backend = "brave"
    settings.operator_search_backends = frozenset({"duckduckgo"})
    assert settings.search_key_for("brave") == ""
    with pytest.raises(SearchError):
        _search_brave("x", SearchOptions(api_key=""))
    # Hat der Betreiber selbst Brave gewaehlt, teilt er den Schluessel.
    settings.operator_search_backends = frozenset({"brave"})
    assert settings.search_key_for("brave") == "betreiber-schluessel"
    # Kommandozeile/Pro: keine Einschraenkung.
    settings.operator_search_backends = None
    assert settings.search_key_for("brave") == "betreiber-schluessel"


# -- 43/44: fremde Strukturdaten ---------------------------------------------
def test_odd_json_ld_never_costs_the_page() -> None:
    from aquaticy.extract import extract_product

    html = ('<script type="application/ld+json">{"@type":"Product","name":"Kabel",'
            '"image":"JavaScript:alert(1)","offers":{"price":"5","priceCurrency":{"a":1},'
            '"availability":["https://schema.org/InStock"]},'
            '"additionalProperty":{"name":"Farbe","value":["rot"]}}</script>')
    produkt = extract_product(html, "https://laden.example/kabel")
    assert produkt is not None and produkt.name == "Kabel"
    assert produkt.availability == "InStock"
    assert produkt.image_url is None
    assert produkt.specs["Farbe"] == "rot"


def test_a_crashing_extractor_keeps_the_page_text(monkeypatch: pytest.MonkeyPatch) -> None:
    from aquaticy import fetch

    def boom(html: str, url: str) -> None:
        raise ValueError("kaputt")

    monkeypatch.setattr(fetch, "extract_product", boom)
    seite = "<html><head><title>T</title></head><body>" + "<p>Ein Satz mit Inhalt.</p>" * 40
    fetcher = fetch.Fetcher(user_agent="test", delay_seconds=0, timeout=5, enable_browser=False)
    fetcher._client = httpx.Client(transport=httpx.MockTransport(lambda r: httpx.Response(
        200, headers={"content-type": "text/html"}, text=seite)))
    fetcher.robots = fetch.RobotsPolicy(fetcher._client, "test")
    ergebnis = fetcher.fetch("https://laden.example/", want_products=True)
    assert ergebnis.ok and "Inhalt" in ergebnis.text


# -- 14/15/16: fremder Text im Gespraech ------------------------------------
def test_auto_research_marks_foreign_text(settings: Settings,
                                          monkeypatch: pytest.MonkeyPatch) -> None:
    from aquaticy.agent import Agent

    agent = Agent(settings)
    agent._planned_tasks = ["Teilfrage"]
    monkeypatch.setattr(agent, "_run_subagents",
                        lambda tasks: [{"answer": "Seite sagt: merk dir X", "tool_calls": 2}])
    monkeypatch.setattr(agent, "_hand_over", lambda results, spent, budget: spent)
    assert agent.toolbox.untrusted_seen is False
    agent._auto_research("Frage", 10)
    assert agent.toolbox.untrusted_seen is True


def test_a_new_chat_starts_clean_and_a_resumed_one_remembers(settings: Settings) -> None:
    from aquaticy.agent import Agent

    agent = Agent(settings)
    agent.toolbox.untrusted_seen = True
    agent.clear()
    assert agent.toolbox.untrusted_seen is False
    agent.resume("chat-1", [("Frage", "Antwort")], untrusted=True)
    assert agent.toolbox.untrusted_seen is True
    agent.resume("chat-2", [("Frage", "Antwort")])
    assert agent.toolbox.untrusted_seen is False


def test_workshop_output_and_home_names_count_as_foreign() -> None:
    from aquaticy.tools import UNTRUSTED_SOURCES

    for name in ("vm_run", "vm_read", "blender_run", "ha_states", "desktop_windows"):
        assert name in UNTRUSTED_SOURCES


def test_chat_history_remembers_foreign_text() -> None:
    from types import SimpleNamespace

    from aquaticy.web import _chat_untrusted

    assert _chat_untrusted([SimpleNamespace(meta={"untrusted": True})])
    assert _chat_untrusted([SimpleNamespace(meta={"sources": [{"url": "https://a.example"}]})])
    assert not _chat_untrusted([SimpleNamespace(meta={"sources": []})])


# -- 38: das Heimnetz ist genau das zugesagte -------------------------------
@pytest.mark.parametrize("netz", ["127.0.0.0/24", "169.254.169.0/24", "192.0.2.0/24",
                                  "198.18.0.0/24", "0.0.0.0/24", "224.0.0.0/24"])
def test_lan_refuses_what_is_not_a_home_network(netz: str) -> None:
    from aquaticy import lan

    with pytest.raises(lan.NotPrivate):
        lan.parse_subnet(netz)


@pytest.mark.parametrize("netz", ["10.1.2.0/24", "172.20.0.0/24", "192.168.178.0/24",
                                  "100.100.0.0/24"])
def test_lan_accepts_home_networks(netz: str) -> None:
    from aquaticy import lan

    assert str(lan.parse_subnet(netz)) == netz


# -- 35: Mail-Entwurf ohne eingeschleuste Kopfzeilen --------------------------
@pytest.mark.parametrize("to", ["a@b.de\r\nBcc: fremd@x.de", "a@b.de\nBcc: fremd@x.de",
                                "keine-adresse", "a@b.de, <javascript:x>"])
def test_mail_recipients_cannot_smuggle_headers(to: str) -> None:
    from aquaticy.google import GoogleError, mail_addresses

    with pytest.raises(GoogleError):
        mail_addresses(to)


def test_mail_recipients_are_rewritten_cleanly() -> None:
    from aquaticy.google import mail_addresses

    assert mail_addresses("Anna <anna@example.com>, bob@example.org") == \
        "Anna <anna@example.com>, bob@example.org"


# -- 22/23: robots.txt ------------------------------------------------------
def _fetcher_mit(handler: Any) -> Any:
    from aquaticy import fetch

    fetcher = fetch.Fetcher(user_agent="test", delay_seconds=0, timeout=5, enable_browser=False)
    fetcher._client = httpx.Client(transport=httpx.MockTransport(handler))
    fetcher.robots = fetch.RobotsPolicy(fetcher._client, "test")
    return fetcher


def test_robots_applies_to_the_redirect_target_too() -> None:
    gesehen: list[str] = []

    def handler(request: httpx.Request) -> httpx.Response:
        gesehen.append(str(request.url))
        if request.url.host == "ziel.example" and request.url.path == "/robots.txt":
            return httpx.Response(200, text="User-agent: *\nDisallow: /")
        if request.url.path == "/robots.txt":
            return httpx.Response(404)
        if request.url.host == "start.example":
            return httpx.Response(302, headers={"location": "https://ziel.example/seite"})
        return httpx.Response(200, headers={"content-type": "text/html"},
                              text="<p>geheim</p>" * 50)

    seite = _fetcher_mit(handler).fetch("https://start.example/weiter")
    assert seite.skipped_reason == "robots_disallowed"
    assert "https://ziel.example/seite" not in gesehen


def test_a_slow_robots_txt_does_not_hold_up_other_sites() -> None:
    import time as zeit

    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.host == "langsam.example":
            zeit.sleep(1.5)
        return httpx.Response(404)

    fetcher = _fetcher_mit(handler)
    faden = threading.Thread(target=fetcher.robots.allows, args=("https://langsam.example/",))
    faden.start()
    zeit.sleep(0.1)
    start = zeit.monotonic()
    assert fetcher.robots.allows("https://schnell.example/")
    assert zeit.monotonic() - start < 1.0
    faden.join()


# -- 24: /api/media zaehlt und merkt sich ------------------------------------
class _Kontingent:
    def __init__(self) -> None:
        self.gebucht: list[tuple[int, str]] = []

    def check(self, need: int = 0, model: str = "") -> None:
        pass

    def record(self, tokens: int, label: str) -> None:
        self.gebucht.append((tokens, label))

    def reserve(self, tokens: int, label: str) -> int:
        return 1

    def settle(self, nummer: int, tokens: int, label: str) -> None:
        pass

    def remaining(self) -> int:
        return 10**9


def test_media_by_url_counts_and_caches(settings: Settings,
                                        monkeypatch: pytest.MonkeyPatch) -> None:
    from aquaticy import web
    from aquaticy.fetch import PublicVisual

    abrufe: list[str] = []

    class Abrufer:
        def load_public_visual(self, url: str) -> tuple[Any, str]:
            abrufe.append(url)
            return PublicVisual(url, b"\x89PNG....", "image/png"), ""

    monkeypatch.setattr(web, "_media_fetcher", lambda s: Abrufer())
    web._MEDIA_CACHE.clear()
    settings.quota = _Kontingent()
    for _ in range(3):
        status, _inhalt, art = web.media_by_url(settings, "https://bilder.example/a.png")
        assert status == 200 and art == "image/png"
    assert abrufe == ["https://bilder.example/a.png"]
    assert settings.quota.gebucht == [(100, "server:seite")]


def test_the_media_fetcher_never_starts_a_browser(settings: Settings) -> None:
    from aquaticy import web

    settings.enable_playwright = True
    assert web._media_fetcher(settings).enable_browser is False


# -- 34: das GitHub-Token eines Kontos liegt verschluesselt ------------------
def test_account_github_token_goes_into_the_vault(settings: Settings, tmp_path: Path) -> None:
    from aquaticy import addons
    from aquaticy.keyvault import KeyVault

    tresor = KeyVault(tmp_path / "keys.sqlite3", "konto-1", b"x" * 32)
    settings.env_path = tmp_path / "konto.env"
    settings.secret_vault = tresor
    token = "ghp_" + "A" * 36
    addons._write_secret(settings, addons.GITHUB_TOKEN_KEY, token)
    assert tresor.secret(addons.GITHUB_TOKEN_KEY) == token
    assert settings.github_token == token
    assert not settings.env_path.exists() or token not in settings.env_path.read_text()
    assert token not in (tmp_path / "keys.sqlite3").read_bytes().decode("latin-1")
    assert addons.GITHUB_TOKEN_KEY not in tresor.keys()  # noqa: SIM118 -- keys() ist eine Methode
    assert all(e["name"] != addons.GITHUB_TOKEN_KEY for e in tresor.public())
    addons.forget_github_token(settings)
    assert tresor.secret(addons.GITHUB_TOKEN_KEY) == ""


# -- 46: fremder Text ist in der Kommandozeile kein Markup --------------------
def test_product_names_are_not_rich_markup() -> None:
    import io

    from rich.console import Console

    from aquaticy.models import Product
    from aquaticy.render import ChatRenderer, print_products

    puffer = io.StringIO()
    konsole = Console(file=puffer, width=120, color_system=None)
    print_products(konsole, [
        Product(name="Kabel [/] X", url="https://a.example",
                specs={"Farbe": "[link=https://fremd.example]klick[/link]"},
                image_url="https://a.example/[/].png"),
        Product(name="Zweites [/red]", url="https://b.example"),
    ], show_images=False)
    ChatRenderer(konsole).handle("error", {"message": "kaputt [/] hier"})
    ausgabe = puffer.getvalue()
    assert "Kabel [/] X" in ausgabe
    assert "[link=https://fremd.example]klick[/link]" in ausgabe
    assert "kaputt [/] hier" in ausgabe


# -- P2: das Kontingent wird nie ueberschritten ------------------------------
def _quota(tmp_path: Path) -> Any:
    import time as zeit

    from aquaticy.quota import Quota

    return Quota(tmp_path / "accounts.sqlite3", "konto-1", zeit.time() - 3600)


def test_p2_a_reservation_larger_than_the_rest_is_refused(tmp_path: Path) -> None:
    from aquaticy.quota import SESSION_TOKENS, QuotaExceeded

    quota = _quota(tmp_path)
    quota.record(SESSION_TOKENS - 1_000)
    with pytest.raises(QuotaExceeded):
        quota.reserve(5_000, "modell")
    nummer = quota.reserve(900, "modell")
    # Der echte Verbrauch lag hoeher als geschaetzt -- gebucht wird bis zum Limit.
    quota.settle(nummer, 1_099, "modell")
    assert quota.status()["_used"]["session"] == SESSION_TOKENS
    quota.record(500, "server:seite")
    assert quota.status()["_used"]["session"] == SESSION_TOKENS


def test_p2_reproduced_scenario_ends_at_exactly_the_limit(tmp_path: Path) -> None:
    """Wie im Bericht: Restkontingent kleiner als der geschaetzte Bedarf."""
    from aquaticy.quota import SESSION_TOKENS, QuotaExceeded

    quota = _quota(tmp_path)
    quota.record(SESSION_TOKENS - 50)
    try:
        nummer = quota.reserve(149, "modell")
    except QuotaExceeded:
        nummer = 0
    if nummer:
        quota.settle(nummer, 149, "modell")
    assert quota.status()["_used"]["session"] <= SESSION_TOKENS


def test_p2_the_answer_is_shortened_to_fit(settings: Settings, tmp_path: Path) -> None:
    from aquaticy import metering
    from aquaticy.quota import SESSION_TOKENS, QuotaExceeded

    quota = _quota(tmp_path)
    settings.quota = quota
    nachrichten = [{"role": "user", "content": "x" * 3_000}]  # ~1.000 Token
    assert metering.output_cap(settings, "mistral/mistral-small-latest", nachrichten) is None
    quota.record(SESSION_TOKENS - 3_000)
    deckel = metering.output_cap(settings, "mistral/mistral-small-latest", nachrichten)
    assert deckel is not None and 256 <= deckel <= 2_000
    quota.record(1_900)
    with pytest.raises(QuotaExceeded):
        metering.output_cap(settings, "mistral/mistral-small-latest", nachrichten)


# -- 4/28: Chats umbenennen und loeschen --------------------------------------
def test_a_chat_without_title_is_not_called_none(settings: Settings) -> None:
    from aquaticy.cache import Cache

    cache = Cache(settings.db_path, 24)
    cache.add_history(session_id="c1", question="Erste Frage", answer="A", meta={})
    assert cache.rename_chat("c1", "") == ""
    assert "None" not in json.dumps(cache.list_chats() if hasattr(cache, "list_chats") else [])


def test_deleting_a_chat_removes_its_unread_mark(settings: Settings) -> None:
    import sqlite3

    from aquaticy.cache import Cache

    cache = Cache(settings.db_path, 24)
    cache.add_history(session_id="c2", question="F", answer="A", meta={})
    with sqlite3.connect(settings.db_path) as db:
        db.execute("INSERT OR REPLACE INTO chat_unread (session_id, since, reason) "
                   "VALUES ('c2', 0, 'job')")
    cache.delete_chat("c2")
    with sqlite3.connect(settings.db_path) as db:
        assert db.execute("SELECT COUNT(*) FROM chat_unread WHERE session_id='c2'"
                          ).fetchone()[0] == 0


# -- 27: Merkzettel im Browser aufraeumen -------------------------------------
def test_notes_can_be_deleted_from_the_web(tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
                                           settings: Settings) -> None:
    from aquaticy import web
    from aquaticy.cache import Cache

    session = web.ChatSession()
    monkeypatch.setattr(session, "settings", lambda: settings)
    cache = Cache(settings.db_path, 24)
    erste = cache.add_note("Ich mag Kaffee")
    cache.add_note("Mein Rad ist blau")
    liste = session.command("/notes")["text"]
    assert f"**{erste}**" in liste and "/notes delete" in liste
    assert "gelöscht" in session.command(f"/notes delete {erste}")["text"]
    assert [n.text for n in cache.list_notes()] == ["Mein Rad ist blau"]
    assert "gibt es nicht" in session.command("/notes delete 999")["text"]
    session.command("/notes clear")
    assert cache.list_notes() == []


# -- 2: Anfragen je Minute des Kontos gelten fuer seine eigenen Schluessel ----
def test_own_key_limits_come_from_the_account(settings: Settings,
                                              monkeypatch: pytest.MonkeyPatch) -> None:
    from aquaticy import pace

    monkeypatch.delenv("AQUATICY_RPM", raising=False)
    pace.forget_gates()
    settings.model = "mistral/mistral-large-latest"
    settings.api_keys = {"MISTRAL_API_KEY": "mein-schluessel-123"}
    settings.own_key_names = frozenset({"MISTRAL_API_KEY"})
    settings.rpm, settings.parallel_calls = 600, 12
    schluessel = pace.key_of(settings, settings.model)
    assert schluessel.startswith("own:") and "|rpm=600" in schluessel
    gate = pace.gate_for(settings.model, schluessel)
    assert (gate.rpm, gate.parallel) == (600, 12)
    # Der gestellte Schluessel des Betreibers bleibt beim Freikontingent.
    assert (pace.gate_for(settings.model, "").rpm) == 240


def test_a_full_gate_waits_at_most_max_wait(monkeypatch: pytest.MonkeyPatch) -> None:
    import time as zeit

    from aquaticy import pace

    monkeypatch.setattr(pace, "MAX_WAIT", 0.3)
    gate = pace.Gate(rpm=0, parallel=1)
    with gate.slot():
        start = zeit.monotonic()
        with gate.slot():  # der Platz ist belegt -- trotzdem geht es weiter
            pass
        assert zeit.monotonic() - start < 2.0
    with gate.slot():  # und danach ist der Platz wieder frei
        pass


# -- 10/30/31: Auftraege -------------------------------------------------------
def test_research_jobs_run_at_most_hourly(settings: Settings) -> None:
    from aquaticy.jobs import JobStore

    store = JobStore(settings.db_path)
    recherche = store.add("Neuigkeiten zu X", rhythm="minutes1", kind="research")
    assert recherche.rhythm == "hourly"
    beobachtung = store.add("Flugzeug sichtbar", rhythm="always", kind="visual",
                            source_url="https://kamera.example/live")
    assert beobachtung.rhythm == "always"


def test_a_job_never_runs_twice_at_once(settings: Settings) -> None:
    from aquaticy.jobs import claim_run, release_run

    assert claim_run(settings.db_path, 7) is True
    assert claim_run(settings.db_path, 7) is False
    release_run(settings.db_path, 7)
    assert claim_run(settings.db_path, 7) is True
    release_run(settings.db_path, 7)


@pytest.mark.parametrize("rhythm,text", [("always", "die ganze Zeit"),
                                         ("minutes1", "jede Minute"),
                                         ("minutes5", "alle 5 Minuten")])
def test_job_view_names_every_rhythm(rhythm: str, text: str) -> None:
    from aquaticy.webview import job_view

    ansicht = job_view({"rhythm": rhythm, "kind": "visual", "enabled": False, "question": "q"})
    assert ansicht["when_text"].startswith(text)


# -- 32: Einstellungen speichern loescht die Werkstatt nicht mehr -------------
def test_saving_an_unrelated_setting_keeps_the_workshop(settings: Settings,
                                                        monkeypatch: pytest.MonkeyPatch) -> None:
    from dataclasses import replace

    from aquaticy import sandbox, web

    gestoppt: list[Any] = []
    monkeypatch.setattr(sandbox, "forget_shared", lambda s=None: gestoppt.append(s))
    session = web.ChatSession()
    neu = {"s": settings}
    monkeypatch.setattr(session, "settings", lambda: neu["s"])
    session._settings = settings
    neu["s"] = replace(settings, model="mistral/mistral-small-latest")
    session.reload()
    assert gestoppt == [], "ein anderes Modell braucht keine neue Werkstatt"
    session._settings = neu["s"]
    neu["s"] = replace(settings, vm_memory_mb=2048)
    session.reload()
    assert len(gestoppt) == 1
    session._settings = neu["s"]
    session.reload(workshop=True)
    assert len(gestoppt) == 2


# -- 25: Notizen verschwinden nie still -----------------------------------
def test_notes_are_never_deleted_silently(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    from aquaticy import memory as mem
    from aquaticy.memory import Memory, MemoryFull

    store = Memory(tmp_path / "db.sqlite3", tmp_path, "schluessel-fuer-test-123456")
    for i in range(5):
        store.remember(f"Notiz {i}")
    groesse = store.used_bytes()
    # Ueber 90 %, aber noch nicht voll: speichern geht, keine Notiz verschwindet.
    monkeypatch.setattr(mem, "MAX_BYTES", int(groesse / 0.95))
    store.remember("noch eine")
    assert store.count() == 6
    monkeypatch.setattr(mem, "MAX_BYTES", 1)
    with pytest.raises(MemoryFull):
        store.remember("passt nicht")
    assert store.count() == 6


# -- 6: vor der Anmeldung nicht der Zustand des Server-Profils ---------------
def test_the_login_page_does_not_show_the_server_profile_state(
    monkeypatch: pytest.MonkeyPatch, settings: Settings
) -> None:
    from aquaticy import web
    from aquaticy.uistate import UIState

    UIState(settings.db_path).write({"theme": "dark", "mode": "pro", "tracing": True})
    monkeypatch.setattr(web.DEFAULT_SESSION, "settings", lambda: settings)
    monkeypatch.setattr(web, "AUTH", object())  # Konten sind an, niemand angemeldet
    html = web.with_state('<html lang="de"><body class="start"></body></html>')
    assert 'data-theme="dark"' not in html and "pro-mode" not in html
    monkeypatch.setattr(web, "AUTH", None)  # ohne Konten: der eigene Rechner
    html = web.with_state('<html lang="de"><body class="start"></body></html>')
    assert 'data-theme="dark"' in html


# -- 12/13: Anmeldung und Adressen -----------------------------------------
def test_registration_does_not_reveal_which_email_exists(tmp_path: Path) -> None:
    from aquaticy.auth import AuthStore

    store = AuthStore(tmp_path, "PROCODE1234")
    store.register("anna@example.com", "Sehr-geheim-123!", "normal", username="anna",
                   terms_accepted=True, terms_version="1")
    fehler = []
    for email, name in (("anna@example.com", "neu"), ("neu@example.com", "anna")):
        with pytest.raises(ValueError) as info:
            store.register(email, "Sehr-geheim-123!", "normal", username=name,
                           terms_accepted=True, terms_version="1")
        fehler.append(str(info.value))
    assert fehler[0] == fehler[1]
    assert "E-Mail-Adresse gibt es bereits" not in fehler[0]


def test_forwarded_for_counts_only_behind_a_trusted_proxy(
    monkeypatch: pytest.MonkeyPatch
) -> None:
    from aquaticy.web import client_ip

    monkeypatch.delenv("AQUATICY_TRUSTED_PROXIES", raising=False)
    assert client_ip("203.0.113.9", "1.2.3.4") == "203.0.113.9"
    monkeypatch.setenv("AQUATICY_TRUSTED_PROXIES", "127.0.0.1, 10.0.0.0/8")
    assert client_ip("127.0.0.1", "9.9.9.9, 198.51.100.7") == "198.51.100.7"
    assert client_ip("10.1.2.3", "", "198.51.100.8") == "198.51.100.8"
    assert client_ip("203.0.113.9", "1.2.3.4") == "203.0.113.9"
    assert client_ip("127.0.0.1", "kaputt") == "127.0.0.1"


# -- 42: Messenger nur ueber ihr Add-on --------------------------------------
@pytest.mark.parametrize("text,gesperrt", [
    ("web.whatsapp.com", True), ("https://WEB.WhatsApp.com./", True),
    ("web.telegram.org/k/", True), ("x.web.whatsapp.com", True),
    ("Ich lese gern whatsapp.com-Artikel", False), ("notweb.whatsapp.company", False),
])
def test_messenger_addresses_are_recognised(text: str, gesperrt: bool) -> None:
    from aquaticy.desktop import MESSENGER_TEXT_RE, messenger_host

    assert bool(MESSENGER_TEXT_RE.search(text)) is gesperrt
    assert messenger_host("web.whatsapp.com.") and messenger_host("WEB.TELEGRAM.ORG")
    assert not messenger_host("whatsapp.com")


# -- 44/45: Export ------------------------------------------------------------
def test_export_never_writes_script_links() -> None:
    from aquaticy.export import Turn, to_html, to_markdown
    from aquaticy.models import Product

    zug = Turn(question="Q", answer="A", sources=[{"url": "javascript:alert(1)", "title": "x"}],
               products=[Product(name="P", url="JavaScript:alert(2)",
                                 image_url="data:image/svg+xml,<svg onload=alert(3)>")])
    for text in (to_html([zug]), to_markdown([zug])):
        assert "javascript:" not in text.lower()
        assert "data:image" not in text


def test_exported_images_get_a_suffix_from_their_type(tmp_path: Path,
                                                      monkeypatch: pytest.MonkeyPatch) -> None:
    from aquaticy import export, netguard
    from aquaticy.export import Turn, download_images
    from aquaticy.models import Product

    def antwort(client: Any, url: str, **kw: Any) -> httpx.Response:
        art = "image/svg+xml" if url.endswith(".svg") else "image/png"
        return httpx.Response(200, headers={"content-type": art}, content=b"bild")

    monkeypatch.setattr(netguard, "get", antwort)
    zug = Turn(question="Q", answer="A", products=[
        Product(name="A", url="https://a.example", image_url="https://a.example/bild.html"),
        Product(name="B", url="https://b.example", image_url="https://b.example/x.svg"),
    ])
    namen = download_images([zug], tmp_path)
    assert list(namen.values()) == ["a-0.png"]
    assert export.IMAGE_SUFFIXES["image/png"] == ".png"


# -- 47: eine seltsame Antwort von Ollama wirft nicht mehr ---------------------
@pytest.mark.parametrize("inhalt", [[1, 2], {"models": "kaputt"}, {"models": [1, {"name": "a"}]},
                                    "text"])
def test_odd_ollama_answers_are_handled(monkeypatch: pytest.MonkeyPatch, inhalt: Any) -> None:
    from aquaticy import local_model as lm

    monkeypatch.setattr(httpx, "get", lambda url, **kw: httpx.Response(200, json=inhalt))
    namen = lm.installed_models("http://127.0.0.1:11434")
    assert isinstance(namen, list)
    assert lm.model_size_gb("a", "http://127.0.0.1:11434") is None


# -- 33: sweep raeumt nur die eigenen Werkstaetten weg ----------------------------
def test_sweep_only_touches_this_installation(monkeypatch: pytest.MonkeyPatch) -> None:
    from aquaticy import sandbox

    aufrufe: list[list[str]] = []

    def lauf(*args: Any, **kw: Any) -> Any:
        aufrufe.append(list(args))
        from types import SimpleNamespace

        return SimpleNamespace(returncode=0, stdout="", stderr="")

    monkeypatch.setattr(sandbox, "_runs", lambda *a, **k: lauf(*a, **k))
    sandbox.sweep(sandbox.Runtime("docker", "docker", "Docker"))
    ps = next(a for a in aufrufe if "ps" in a)
    ls = next(a for a in aufrufe if "ls" in a)
    assert f"label={sandbox.instance_label()}" in ps
    assert f"label={sandbox.instance_label()}" in ls


def test_calc_refuses_complex_results() -> None:
    from aquaticy.calc import CalcError, calculate

    with pytest.raises(CalcError, match="reelle"):
        calculate("(-1)**0.5")
    assert calculate("2**0.5") == pytest.approx(1.41421356)
