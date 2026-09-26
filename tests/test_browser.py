"""Tests fuer Stufe 3 -- mit einer Attrappe statt echtem Browser."""

from __future__ import annotations

import time
from typing import Any, ClassVar

import pytest

from aquaticy.browser import (
    capture_visual,
    click_known_reject_button,
    click_reject_by_text,
    dismiss_consent,
    launch_args,
    remove_overlays,
    render_page,
)
from aquaticy.fetch import load_rules


class FakeElement:
    """Ein anklickbares Element."""

    def __init__(self, text: str = "", visible: bool = True, broken: bool = False) -> None:
        self.text = text
        self.visible = visible
        self.broken = broken
        self.clicked = False

    def is_visible(self) -> bool:
        return self.visible

    def inner_text(self) -> str:
        return self.text

    def click(self, **kwargs: Any) -> None:
        if self.broken:
            raise RuntimeError("Element nicht klickbar")
        self.clicked = True


class FakePage:
    """Minimale Playwright-Attrappe."""

    def __init__(
        self,
        elements: dict[str, list[FakeElement]] | None = None,
        frames: list[FakePage] | None = None,
    ) -> None:
        self.elements = elements or {}
        self.frames = [self, *(frames or [])]
        self.evaluated: list[tuple[str, Any]] = []
        self.removed = 0

    def query_selector_all(self, selector: str) -> list[FakeElement]:
        return self.elements.get(selector, [])

    def evaluate(self, script: str, argument: Any = None) -> int:
        self.evaluated.append((script, argument))
        return self.removed


RULES = load_rules()


def test_onetrust_reject_button_is_clicked() -> None:
    button = FakeElement("Alle ablehnen")
    page = FakePage({"#onetrust-reject-all-handler": [button]})
    assert dismiss_consent(page, RULES) == "cmp:#onetrust-reject-all-handler"
    assert button.clicked


@pytest.mark.parametrize(
    "selector",
    [
        "#onetrust-reject-all-handler",
        "#CybotCookiebotDialogBodyButtonDecline",
        '[data-testid="uc-deny-all-button"]',
        "#didomi-notice-disagree-button",
    ],
)
def test_all_known_cmps_are_covered(selector: str) -> None:
    button = FakeElement("Ablehnen")
    page = FakePage({selector: [button]})
    assert dismiss_consent(page, RULES) == f"cmp:{selector}"
    assert button.clicked


def test_accept_button_is_never_clicked() -> None:
    accept = FakeElement("Alle akzeptieren")
    page = FakePage({"button": [accept]})
    result = dismiss_consent(page, RULES)
    assert not accept.clicked
    assert not result.startswith("text:")


def test_generic_text_fallback() -> None:
    accept = FakeElement("Alle akzeptieren")
    reject = FakeElement("Nur notwendige Cookies")
    page = FakePage({"button": [accept, reject]})
    assert dismiss_consent(page, RULES) == "text:Nur notwendige Cookies"
    assert reject.clicked
    assert not accept.clicked


@pytest.mark.parametrize(
    "label",
    ["Ablehnen", "Reject all", "Decline", "Necessary only", "Continue without accepting"],
)
def test_reject_labels_in_both_languages(label: str) -> None:
    button = FakeElement(label)
    page = FakePage({"button": [button]})
    assert click_reject_by_text(page, RULES.reject_text_pattern) == label


def test_invisible_buttons_are_ignored() -> None:
    hidden = FakeElement("Ablehnen", visible=False)
    page = FakePage({"button": [hidden]})
    assert click_reject_by_text(page, RULES.reject_text_pattern) is None
    assert not hidden.clicked


def test_unclickable_element_falls_through() -> None:
    broken = FakeElement("Ablehnen", broken=True)
    page = FakePage({"#onetrust-reject-all-handler": [broken]})
    page.removed = 3
    assert dismiss_consent(page, RULES) == "removed:3"


def test_iframe_dialog_is_handled() -> None:
    """Sourcepoint/Quantcast rendern in einem iFrame."""
    button = FakeElement("Ablehnen")
    frame = FakePage({"button": [button]})
    page = FakePage({}, frames=[frame])
    assert dismiss_consent(page, RULES) == "text:Ablehnen"
    assert button.clicked


def test_without_reject_button_overlays_are_removed() -> None:
    page = FakePage({})
    page.removed = 2
    assert dismiss_consent(page, RULES) == "removed:2"
    script, selectors = page.evaluated[0]
    assert "document.body" in script
    assert "overflow" in script
    assert "#onetrust-consent-sdk" in selectors


def test_scroll_lock_is_released() -> None:
    page = FakePage({})
    remove_overlays(page, ["#x"])
    script = page.evaluated[0][0]
    assert "element.style.overflow = ''" in script
    assert "element.style.position = 'static'" in script


def test_newsletter_and_app_banners_are_only_removed() -> None:
    newsletter = FakeElement("Jetzt Newsletter abonnieren")
    page = FakePage({"button": [newsletter]})
    dismiss_consent(page, RULES)
    assert not newsletter.clicked
    assert any("newsletter" in str(arg).lower() for _, arg in page.evaluated)


def test_nothing_to_do() -> None:
    page = FakePage({})
    assert dismiss_consent(page, RULES) == "nothing"


def test_broken_scope_does_not_raise() -> None:
    class ExplodingPage:
        frames: ClassVar[list[Any]] = []

        def query_selector_all(self, selector: str) -> list[FakeElement]:
            raise RuntimeError("Seite weg")

        def evaluate(self, script: str, argument: Any = None) -> int:
            raise RuntimeError("Seite weg")

    assert dismiss_consent(ExplodingPage(), RULES) == "nothing"
    assert click_known_reject_button(ExplodingPage(), ["#x"]) is None


def test_render_page_without_playwright(monkeypatch: pytest.MonkeyPatch) -> None:
    """Ohne installiertes Playwright faellt der Abruf sauber aus."""
    import builtins

    real_import = builtins.__import__

    def fake_import(name: str, *args: Any, **kwargs: Any):
        if name.startswith("playwright"):
            raise ImportError("kein playwright")
        return real_import(name, *args, **kwargs)

    monkeypatch.setattr(builtins, "__import__", fake_import)
    assert render_page("https://example.de/", "aquaticy/0.1") is None
    assert capture_visual("https://example.de/", "aquaticy/0.1") is None


def test_fetcher_uses_browser_only_for_consent_walls(fixture_html, monkeypatch) -> None:
    """Stufe 2 entscheidet, ob Stufe 3 ueberhaupt loslaeuft."""
    import httpx

    from aquaticy.fetch import Fetcher, RobotsPolicy

    rendered = fixture_html("plain_article.html")
    calls: list[str] = []

    def fake_render(url: str, **kwargs: Any) -> str:
        calls.append(url)
        return rendered

    monkeypatch.setattr("aquaticy.browser.render_page", fake_render)

    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path == "/robots.txt":
            return httpx.Response(404)
        return httpx.Response(
            200, text=fixture_html("consent_wall.html"), headers={"content-type": "text/html"}
        )

    fetcher = Fetcher("aquaticy-test/0.1", timeout=5, delay_seconds=0, enable_browser=True)
    fetcher._client = httpx.Client(transport=httpx.MockTransport(handler), follow_redirects=True)
    fetcher.robots = RobotsPolicy(fetcher._client, "aquaticy-test/0.1")

    page = fetcher.fetch("https://zeitung.example/artikel")
    assert calls == ["https://zeitung.example/artikel"]
    assert page.ok
    assert page.via == "browser"
    assert "Franzbrötchen" in page.text


def test_paywalls_never_trigger_the_browser(fixture_html, monkeypatch) -> None:
    """Eine Bezahlschranke wird nicht mit dem Browser aufgebrochen."""
    import httpx

    from aquaticy.fetch import Fetcher, RobotsPolicy

    calls: list[str] = []
    monkeypatch.setattr(
        "aquaticy.browser.render_page", lambda url, **kwargs: calls.append(url) or ""
    )

    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path == "/robots.txt":
            return httpx.Response(404)
        return httpx.Response(
            200, text=fixture_html("paywall_article.html"), headers={"content-type": "text/html"}
        )

    fetcher = Fetcher("aquaticy-test/0.1", timeout=5, delay_seconds=0, enable_browser=True)
    fetcher._client = httpx.Client(transport=httpx.MockTransport(handler), follow_redirects=True)
    fetcher.robots = RobotsPolicy(fetcher._client, "aquaticy-test/0.1")

    page = fetcher.fetch("https://zeitung.example/artikel")
    assert calls == []
    assert page.skipped_reason == "paywall"


# ---------------------------------------------------------------------------
# Betrieb im Container
# ---------------------------------------------------------------------------
class _Chromium:
    """Merkt sich die Startversuche -- der erste mit Sandbox scheitert auf Wunsch."""

    def __init__(self, sandbox_geht: bool) -> None:
        self.sandbox_geht = sandbox_geht
        self.versuche: list[list[str]] = []
        self.proxies: list[dict] = []

    def launch(self, headless: bool, args: list[str], proxy: dict | None = None) -> str:
        self.versuche.append(list(args))
        self.proxies.append(proxy or {})
        if "--no-sandbox" not in args and not self.sandbox_geht:
            raise RuntimeError("No usable sandbox!")
        return "browser"


def _playwright(sandbox_geht: bool):
    from types import SimpleNamespace

    return SimpleNamespace(chromium=_Chromium(sandbox_geht))


def test_browser_sandbox_is_always_tried_first(monkeypatch: pytest.MonkeyPatch) -> None:
    """Seit 9.5.15: auch im Container zuerst MIT Sandbox."""
    from aquaticy.browser import launch_browser

    monkeypatch.setenv("AQUATICY_BROWSER_NO_SANDBOX", "1")
    pw = _playwright(sandbox_geht=True)
    assert launch_browser(pw) == "browser"
    assert len(pw.chromium.versuche) == 1
    assert pw.chromium.versuche[0][0] == "--disable-dev-shm-usage"
    assert "--no-sandbox" not in pw.chromium.versuche[0]
    assert "--no-sandbox" not in launch_args()
    # Seit 9.5.16: alles ueber den Proxy der Netzregel, auch Loopback.
    assert pw.chromium.proxies[0]["server"].startswith("http://127.0.0.1:")
    assert pw.chromium.proxies[0]["bypass"] == "<-loopback>"
    assert any("disable_non_proxied_udp" in arg for arg in pw.chromium.versuche[0])


@pytest.mark.parametrize("value", ["1", "true", "yes", "ja"])
def test_without_a_usable_sandbox_the_container_flag_allows_the_fallback(
    monkeypatch: pytest.MonkeyPatch, value: str
) -> None:
    """Im Container ohne Namensraeume uebernimmt der Container die Isolation."""
    from aquaticy.browser import launch_browser

    monkeypatch.setenv("AQUATICY_BROWSER_NO_SANDBOX", value)
    pw = _playwright(sandbox_geht=False)
    assert launch_browser(pw) == "browser"
    assert pw.chromium.versuche[-1][0] == "--no-sandbox"


@pytest.mark.parametrize("value", ["", "0", "nein"])
def test_without_the_flag_there_is_no_fallback(
    monkeypatch: pytest.MonkeyPatch, value: str
) -> None:
    from aquaticy.browser import launch_browser

    monkeypatch.setenv("AQUATICY_BROWSER_NO_SANDBOX", value)
    with pytest.raises(RuntimeError):
        launch_browser(_playwright(sandbox_geht=False))



# ---------------------------------------------------------------------------
# Live statt Ladebildschirm
# ---------------------------------------------------------------------------
class LivePage:
    """Eine Seite, die auf Wunsch erst nach ein paar Blicken abspielt."""

    def __init__(self, stände: list[dict[str, int]]) -> None:
        self.stände = stände
        self.gewartet: list[int] = []
        self.gestartet = 0
        self.frames: list[Any] = []
        self.knoepfe: list[Any] = []

    def evaluate(self, script: str, *args: Any) -> Any:
        from aquaticy.browser import PLAYBACK_STATE_JS, START_PLAYBACK_JS

        if script is START_PLAYBACK_JS:
            self.gestartet += 1
            return 1
        if script is PLAYBACK_STATE_JS:
            return self.stände.pop(0) if len(self.stände) > 1 else self.stände[0]
        return 0

    def wait_for_timeout(self, ms: int) -> None:
        self.gewartet.append(int(ms))

    def query_selector_all(self, selector: str) -> list[Any]:
        return list(self.knoepfe)


class PlayButton:
    def __init__(self) -> None:
        self.geklickt = 0

    def is_visible(self) -> bool:
        return True

    def inner_text(self) -> str:
        return "Play"

    def click(self, **kwargs: Any) -> None:
        self.geklickt += 1


def test_a_running_video_is_awaited_before_the_shot() -> None:
    """Der erste Blick zeigt den Ladebildschirm, der zweite das laufende Bild."""
    from aquaticy.browser import PLAYBACK_SETTLE_MS, wait_for_live_frame

    page = LivePage([
        {"videos": 1, "playing": 0, "images": 0, "loaded": 0},
        {"videos": 1, "playing": 1, "images": 0, "loaded": 0},
    ])
    assert wait_for_live_frame(page, timeout_ms=3_000) == "video"
    assert page.gestartet >= 1, "die Wiedergabe wird angestossen"
    assert PLAYBACK_SETTLE_MS in page.gewartet, "nach dem ersten Frame wird nachgewartet"


def test_a_page_without_video_does_not_wait_for_playback() -> None:
    """Die meisten Webcams liefern ein Bild, kein Video -- das ist sofort fertig."""
    from aquaticy.browser import wait_for_live_frame

    page = LivePage([{"videos": 0, "playing": 0, "images": 3, "loaded": 3}])
    assert wait_for_live_frame(page, timeout_ms=3_000) == "bild"


def test_an_embedded_player_is_started_before_the_shot() -> None:
    """Ein Bild auf der Hauptseite darf das Video im iFrame nicht verdecken."""
    from aquaticy.browser import wait_for_live_frame

    page = LivePage([{"videos": 0, "playing": 0, "images": 1, "loaded": 1}])
    frame = LivePage([
        {"videos": 1, "playing": 0, "images": 0, "loaded": 0},
        {"videos": 1, "playing": 1, "images": 0, "loaded": 0},
    ])
    button = PlayButton()
    frame.knoepfe = [button]
    page.frames = [page, frame]

    assert wait_for_live_frame(page, timeout_ms=3_000) == "video"
    assert button.geklickt == 1
    assert frame.gestartet >= 1


def test_a_stuck_player_gets_clicked_and_then_gives_up() -> None:
    """Sperrt sich der Player, wird der Abspielknopf geklickt -- einmal."""
    from aquaticy.browser import wait_for_live_frame

    page = LivePage([{"videos": 1, "playing": 0, "images": 0, "loaded": 0}])
    knopf = PlayButton()
    page.knoepfe = [knopf]
    assert wait_for_live_frame(page, timeout_ms=1_000) == "zeitlimit"
    assert knopf.geklickt == 1, "genau einmal -- sonst klickt er sich durch die Seite"


class ShotPage(LivePage):
    """Eine Seite mit Bildkandidaten -- fuer die Auswahl des Livebilds.

    `kandidaten` ist der erste Blick, `spaeter` der zweite. Was dazwischen
    seine Adresse wechselt, gilt als laufendes Bild.
    """

    def __init__(self, kandidaten: list[dict[str, Any]],
                 spaeter: list[dict[str, Any]] | None = None,
                 anteil: float = 0.6) -> None:
        super().__init__([])
        self.kandidaten = kandidaten
        self.spaeter = spaeter if spaeter is not None else [
            {"index": k["index"], "src": k.get("src", ""), "playing": k.get("playing", False)}
            for k in kandidaten
        ]
        self.anteil = anteil
        self.gewaehlt: int | None = None

    def evaluate(self, script: str, *args: Any) -> Any:
        from aquaticy import browser

        if script is browser.MARK_CANDIDATES_JS:
            return self.kandidaten
        if script is browser.RESCAN_CANDIDATES_JS:
            return self.spaeter
        if script is browser.PICK_CANDIDATE_JS:
            self.gewaehlt = args[0]
            return self.anteil
        return None

    def query_selector(self, selector: str) -> Any:
        class Element:
            def screenshot(self, **kwargs: Any) -> bytes:
                return b"ausschnitt"

        return Element()

    def screenshot(self, **kwargs: Any) -> bytes:
        return b"ganze-seite"


def _kandidat(index: int, **rest: Any) -> dict[str, Any]:
    grund = {"index": index, "tag": "IMG", "area": 100_000, "key": "400x250",
             "src": f"https://cam.example/{index}.jpg", "inLink": False, "playing": False}
    grund.update(rest)
    return grund


def test_the_capture_prefers_the_live_element() -> None:
    """Ein Ausschnitt des Videos statt der ganzen Seite mit Kopfzeile und Werbung."""
    from aquaticy.browser import _shot

    seite = ShotPage([_kandidat(0, tag="VIDEO", playing=True)])
    assert _shot(seite) == b"ausschnitt"
    assert seite.gewaehlt == 0


def test_a_small_element_leaves_it_at_the_whole_view() -> None:
    """Ein Vorschaubild neben dem Text ist nicht die Ansicht, die gemeint ist."""
    from aquaticy.browser import _shot

    seite = ShotPage([_kandidat(0)], anteil=0.02)
    assert _shot(seite) == b"ganze-seite"


def test_the_refreshing_picture_beats_the_bigger_preview() -> None:
    """Der Fall vom Flughafen: oben grosse Vorschaubilder, darunter das Livebild.

    Frueher gewann die Vorschau, weil sie groesser war und weil alles
    ausserhalb des Fensters gar nicht erst betrachtet wurde.
    """
    from aquaticy.browser import _shot

    vorschau = _kandidat(0, area=400_000, key="800x500")
    live = _kandidat(1, area=90_000, key="300x300")
    seite = ShotPage(
        [vorschau, live],
        spaeter=[
            {"index": 0, "src": vorschau["src"], "playing": False},
            # Dieselbe Kamera, neuer Zeitstempel -- sie erneuert sich.
            {"index": 1, "src": "https://cam.example/1.jpg?t=99", "playing": False},
        ],
    )
    assert _shot(seite) == b"ausschnitt"
    assert seite.gewaehlt == 1, "das sich erneuernde Bild ist das Livebild"


def test_a_row_of_equal_thumbnails_loses_against_a_single_picture() -> None:
    """Drei gleich grosse Bilder nebeneinander sind eine Vorschaureihe."""
    from aquaticy.browser import _shot

    seite = ShotPage(
        [_kandidat(0, area=200_000, key="500x400", inLink=True),
         _kandidat(1, area=200_000, key="500x400", inLink=True),
         _kandidat(2, area=200_000, key="500x400", inLink=True),
         _kandidat(3, area=120_000, key="400x300")]
    )
    assert _shot(seite) == b"ausschnitt"
    assert seite.gewaehlt == 3


def test_without_any_candidate_the_whole_view_is_taken() -> None:
    from aquaticy.browser import _shot

    assert _shot(ShotPage([])) == b"ganze-seite"


def test_embedded_live_video_beats_main_page_preview() -> None:
    from aquaticy.browser import _shot

    page = ShotPage([_kandidat(0, area=900_000)])
    frame = ShotPage([_kandidat(0, tag="VIDEO", playing=True)])
    page.frames = [page, frame]
    assert _shot(page) == b"ausschnitt"
    assert frame.gewaehlt == 0
    assert page.gewaehlt is None


def test_refreshing_image_in_nested_frame_is_selected() -> None:
    from aquaticy.browser import _shot

    page = ShotPage([_kandidat(0, area=900_000)])
    parent = ShotPage([])
    child = ShotPage([_kandidat(0)], spaeter=[
        {"index": 0, "src": "https://cam.example/new.jpg", "playing": False},
    ])
    page.frames = [page, parent, child]
    assert _shot(page) == b"ausschnitt"
    assert child.gewaehlt == 0
    assert page.gewaehlt is None


def test_detached_frame_does_not_break_main_page_capture() -> None:
    from aquaticy.browser import _shot

    class Detached:
        def evaluate(self, *args: Any) -> Any:
            raise RuntimeError("Frame detached")

    page = ShotPage([_kandidat(0)])
    page.frames = [page, Detached()]
    assert _shot(page) == b"ausschnitt"


# ---------------------------------------------------------------------------
# Ein fremder Rahmen darf die Aufnahme nicht aufhalten
# ---------------------------------------------------------------------------
def test_a_hanging_advert_frame_does_not_block_the_shot() -> None:
    """Ein Werbebild, das nie fertig laedt, kostete das ganze Zeitlimit.

    Gezaehlt wurde ueber alle Rahmen zusammen: ein einziges haengendes Bild
    irgendwo machte die Hauptseite nie "fertig". Die Gnadenfrist griff nicht,
    weil sie ein geladenes Bild verlangte -- und geladen war keines.
    """
    from aquaticy.browser import wait_for_live_frame

    haupt = LivePage([{"videos": 0, "playing": 0, "images": 0, "loaded": 0}])
    werbung = LivePage([{"videos": 0, "playing": 0, "images": 1, "loaded": 0}])
    haupt.frames = [haupt, werbung]

    begonnen = time.monotonic()
    assert wait_for_live_frame(haupt, timeout_ms=12_000) == "bild"
    assert time.monotonic() - begonnen < 6.0, "die Gnadenfrist muss greifen"


def test_pictures_that_never_load_are_still_waited_for() -> None:
    """Umgekehrt: haengt das eigentliche Bild, wird weiter gewartet."""
    from aquaticy.browser import pictures_ready

    haengt = [{"videos": 0, "playing": 0, "images": 3, "loaded": 0}]
    assert not pictures_ready(haengt, 0.0)
    assert not pictures_ready(haengt, 30.0), "ohne ein einziges Bild gibt es nichts zu holen"
    fertig = [{"videos": 0, "playing": 0, "images": 3, "loaded": 3}]
    assert pictures_ready(fertig, 0.0)


def test_three_embedded_cameras_are_not_a_thumbnail_row() -> None:
    """Gleiche Groesse ist nur INNERHALB eines Dokuments ein Hinweis.

    Ueber Rahmen hinweg ist sie normal -- es ist derselbe Einbau, mehrfach.
    Gezaehlt wurde vorher global; damit verloren drei echte Kameras gegen
    ein kleineres Standbild der Gastgeberseite.
    """
    from aquaticy.browser import _shot

    haupt = ShotPage([_kandidat(0, area=120_000, key="400x300")])
    kameras = [ShotPage([_kandidat(0, area=200_000, key="500x400")]) for _ in range(3)]
    haupt.frames = [haupt, *kameras]

    assert _shot(haupt) == b"ausschnitt"
    assert haupt.gewaehlt is None, "das Standbild der Gastgeberseite ist nicht gemeint"
    assert [k.gewaehlt for k in kameras] == [0, None, None]


def test_a_real_thumbnail_row_in_one_document_still_loses() -> None:
    """Die Abwertung bleibt, wo sie hingehoert: unter Geschwistern."""
    from aquaticy.browser import _shot

    seite = ShotPage([
        _kandidat(0, area=200_000, key="500x400", inLink=True),
        _kandidat(1, area=200_000, key="500x400", inLink=True),
        _kandidat(2, area=200_000, key="500x400", inLink=True),
        _kandidat(3, area=120_000, key="400x300"),
    ])
    assert _shot(seite) == b"ausschnitt"
    assert seite.gewaehlt == 3


def test_an_advert_video_in_a_frame_does_not_block_the_picture() -> None:
    """Ein Video irgendwo sperrte den ganzen Bildweg ab.

    Eine gewoehnliche Bild-Webcam wartete deshalb das volle Zeitlimit ab,
    nur weil in einem fremden Rahmen eine Anzeige lag, die nicht anspringt.
    """
    from aquaticy.browser import VIDEO_GRACE_SECONDS, wait_for_live_frame

    haupt = LivePage([{"videos": 0, "playing": 0, "images": 1, "loaded": 1}])
    werbung = LivePage([{"videos": 1, "playing": 0, "images": 0, "loaded": 0}])
    haupt.frames = [haupt, werbung]

    begonnen = time.monotonic()
    assert wait_for_live_frame(haupt, timeout_ms=20_000) == "bild"
    gebraucht = time.monotonic() - begonnen
    assert gebraucht < VIDEO_GRACE_SECONDS + 3.0, f"{gebraucht:.1f}s ist zu lang"


def test_a_video_still_gets_its_time_before_the_picture_wins() -> None:
    """Die Frist darf nicht so kurz sein, dass ein echter Player verliert."""
    from aquaticy.browser import wait_for_live_frame

    spaet = LivePage([
        {"videos": 1, "playing": 0, "images": 1, "loaded": 1},
        {"videos": 1, "playing": 1, "images": 1, "loaded": 1},
    ])
    assert wait_for_live_frame(spaet, timeout_ms=20_000) == "video"
