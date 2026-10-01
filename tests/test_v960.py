"""9.6.0 Spark: neues Logo (Browser-Tab, Seitenleiste, Startseite) und Prüf-Funde."""

from __future__ import annotations

from pathlib import Path

import pytest

from aquaticy import web
from aquaticy.auth import AuthStore
from tests.test_web import port, raw_request, session, web_settings  # noqa: F401

PNG = b"\x89PNG\r\n\x1a\n"


@pytest.fixture
def locked(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    # Mit Konten ist alles außer dem Logo hinter der Anmeldung.
    monkeypatch.setattr(web, "AUTH", AuthStore(tmp_path / "accounts", "PRO123456"))
    monkeypatch.setattr(web, "SESSIONS", web.SessionRegistry())
    monkeypatch.setattr(web, "SESSION", web.SessionProxy())


@pytest.mark.parametrize("route", sorted(web.STATIC_FILES))
def test_logo_files_are_served_without_login(route: str, port: int, locked: None) -> None:  # noqa: F811
    status, headers, data = raw_request(port, "GET", route)
    assert status == 200
    assert headers["Content-Type"] == "image/png"
    assert data.startswith(PNG)
    assert "max-age" in headers.get("Cache-Control", "")


def test_static_files_exist_in_the_package() -> None:
    for name in set(web.STATIC_FILES.values()):
        assert (web.STATIC_DIR / name).read_bytes().startswith(PNG)


@pytest.mark.parametrize(
    "route",
    ["/static/../web.py", "/favicon-32.png/../config.py", "/logo.png%00", "/..%2fweb.py"],
)
def test_no_other_file_leaks_through_the_logo_route(
    route: str,
    port: int,  # noqa: F811
    locked: None,
) -> None:
    status, _, data = raw_request(port, "GET", route)
    assert not data.startswith(PNG)
    assert b"import " not in data
    assert status in (401, 403, 404)


def test_ui_uses_the_logo_everywhere() -> None:
    html = web.UI_FILE.read_text(encoding="utf-8")
    head = html.split("</head>", 1)[0]
    assert 'rel="icon" type="image/png" sizes="32x32" href="/favicon-32.png"' in head
    assert 'rel="apple-touch-icon"' in head
    # Seitenleiste: Logo, darunter der Name, daneben die Version.
    assert '<img class="mark" src="/logo.png"' in html
    assert '<span class="name">Aquaticy</span>' in html
    assert "flex-direction:column" in html.split(".brand-logo{", 1)[1].split("}", 1)[0]
    # Browser-Tab: nur das Logo, kein SVG-Stern mehr.
    assert "data:image/svg+xml" not in head


def test_side_pages_carry_the_favicon() -> None:
    from aquaticy import legal

    assert "/favicon-32.png" in web.DENIED_PAGE
    assert b"/favicon-32.png" in legal.legal_page("/accessibility")


def test_version_is_960() -> None:
    import aquaticy

    assert aquaticy.__version__ == "9.6.0"
    assert 'window.__AQUATICY_VERSION__ || "9.6.0 Spark Intern"' in web.UI_FILE.read_text(
        encoding="utf-8"
    )
