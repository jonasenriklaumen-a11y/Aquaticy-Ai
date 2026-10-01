"""9.6.1 Spark Intern: schneller und leichter, groessere Versionsanzeige, Pro-Hinweis."""

from __future__ import annotations

import gzip
import threading
from http.client import HTTPConnection
from http.server import ThreadingHTTPServer

from aquaticy import web


def _ui() -> str:
    return web.UI_FILE.read_text(encoding="utf-8")


def test_version_label() -> None:
    import aquaticy

    assert aquaticy.VERSION_LABEL == "9.6.1 Spark Intern"


def test_page_is_gzipped_when_the_browser_accepts_it() -> None:
    server = ThreadingHTTPServer(("127.0.0.1", 0), web.Handler)
    faden = threading.Thread(target=server.serve_forever, daemon=True)
    faden.start()
    try:
        for kopf, gepackt in (({"Accept-Encoding": "gzip, br"}, True), ({}, False),
                              ({"Accept-Encoding": "gzip;q=0"}, False)):
            conn = HTTPConnection("127.0.0.1", server.server_address[1], timeout=10)
            conn.request("GET", "/", headers=kopf)
            antwort = conn.getresponse()
            daten = antwort.read()
            conn.close()
            assert antwort.status == 200
            assert (antwort.getheader("Content-Encoding") == "gzip") is gepackt
            html = gzip.decompress(daten) if gepackt else daten
            assert b"window.__AQUATICY_VERSION__" in html
            assert antwort.getheader("Vary") == "Accept-Encoding"
    finally:
        server.shutdown()
        server.server_close()


def test_ui_template_is_cached_but_follows_edits(tmp_path, monkeypatch) -> None:
    datei = tmp_path / "ui.html"
    datei.write_text("eins", encoding="utf-8")
    monkeypatch.setattr(web, "UI_FILE", datei)
    monkeypatch.setitem(web._UI_CACHE, "entry", None)
    assert web.ui_template() == "eins"
    datei.write_text("zwei!", encoding="utf-8")
    assert web.ui_template() == "zwei!"


def test_accepts_gzip_parsing() -> None:
    assert web.accepts_gzip("gzip, deflate, br")
    assert web.accepts_gzip("br;q=1.0, gzip;q=0.8")
    assert not web.accepts_gzip("gzip;q=0")
    assert not web.accepts_gzip("br")


def test_version_badge_is_bigger() -> None:
    html = _ui()
    assert ".brand .ver{font-size:calc(13.5px * var(--fs));font-weight:600" in html


def test_pro_mode_says_it_takes_longer_for_accuracy() -> None:
    html = _ui()
    assert 'class="hint pro-hinweis only-pro"' in html
    assert "Im Pro-Modus dauert die Suche länger — wegen der höheren Genauigkeit." in html


def test_normal_mode_is_bounded_pro_is_not() -> None:
    from aquaticy import subagents

    assert subagents.NORMAL_DEADLINE <= 60 and subagents.NORMAL_FILL <= 6
    assert subagents.NORMAL_CALL_TIMEOUT < 90 and subagents.NORMAL_FETCH_TIMEOUT < 15


def test_hidden_tab_does_not_poll() -> None:
    html = _ui()
    assert "if (!document.hidden) showLoad();" in html


def test_jobs_only_run_on_the_home_server(monkeypatch) -> None:
    """Im Verbund laeuft ein Auftrag nur auf dem Heimserver -- sonst doppelt."""
    from types import SimpleNamespace

    gestartet: list = []

    class Planer:
        def __init__(self, getter, paused=None, on_abuse=None) -> None:
            self.paused = paused
            gestartet.append(self)

        def start(self) -> None:
            pass

    monkeypatch.setattr("aquaticy.jobs.Scheduler", Planer)
    monkeypatch.setattr(web, "USER_SCHEDULERS", {})
    monkeypatch.setattr(web, "AIGUARD", None)
    monkeypatch.setattr(web, "SESSIONS", SimpleNamespace(
        get=lambda account: SimpleNamespace(settings=lambda: None)))
    monkeypatch.setattr(web, "CLUSTER", SimpleNamespace(is_home=lambda user: user == "hier"))
    web.start_user_scheduler(SimpleNamespace(id="hier"))
    web.start_user_scheduler(SimpleNamespace(id="woanders"))
    assert gestartet[0].paused() is False
    assert gestartet[1].paused() is True
