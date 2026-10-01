"""9.6.2 Spark: Anmelden beim Anbieter mit Google, Apple oder E-Mail, und die Funde
des Browser-Rundgangs (Umbrueche in Hinweisen, Eingabezeile auf dem Handy, Escape,
Beschriftung, englische Texte)."""

from __future__ import annotations

import re

from aquaticy import web


def _ui() -> str:
    return web.UI_FILE.read_text(encoding="utf-8")


def test_version_is_public_962() -> None:
    import aquaticy

    assert aquaticy.__version__ == "9.6.2"
    assert aquaticy.VERSION_LABEL == "9.6.2 Spark" and not aquaticy.INTERNAL


def test_sign_in_buttons_and_quick_link() -> None:
    html = _ui()
    assert 'id="linked-quick-key"' in html and 'id="linked-paste"' in html
    assert "for (const weg of k.sign_in || [])" in html
    # Die Zwischenablage nur, wo der Browser sie erlaubt (HTTPS, eigener Rechner).
    assert "window.isSecureContext && navigator.clipboard?.readText" in html


def test_static_notes_lose_editor_line_breaks() -> None:
    html = _ui()
    assert 'document.querySelectorAll(".note").forEach' in html


def test_phone_composer_stays_on_one_row() -> None:
    html = _ui()
    teil = html[html.index("@media (max-width:430px){"):]
    assert ".crow{flex-wrap:nowrap" in teil[:3000]


def test_escape_closes_the_phone_sidebar_after_dialogs() -> None:
    html = _ui()
    assert 'e.key === "Escape" && narrow()' in html
    assert ('!document.querySelector(".overlay.open")) '
            'document.body.classList.add("collapsed");\n}, true);') in html


def test_file_input_is_labelled() -> None:
    assert re.search(r'id="picker"[^>]*aria-label="Dateien anhängen"', _ui())


def test_new_texts_have_english() -> None:
    html = _ui()
    en = html[html.index("const EN = {"):]
    for text in ("KI-Konten", "Server-Verbund", "Mit Apple", "Server im lokalen Netz",
                 "Dafür braucht es mindestens zwei verknüpfte KI-Konten (Add-ons → KI-Konten)."):
        assert f'"{text}":' in en, text
