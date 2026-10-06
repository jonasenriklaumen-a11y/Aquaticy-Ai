"""9.6.9 Luna: Home-Assistant-Token, Google-Ruecksprung, Ausweichmodell nach dem
aktiven Modell, Antwortstrom ohne Abschluss, Sperre des Datenordners und das
Aussehen auf dem Handy."""

from __future__ import annotations

import dataclasses
import threading
from http.client import HTTPConnection
from http.server import ThreadingHTTPServer
from pathlib import Path
from typing import Any

import pytest
from typer.testing import CliRunner

from aquaticy import web


def test_version_label() -> None:
    import aquaticy

    assert aquaticy.VERSION_LABEL == "10.0.1 Luna"


# -- Home Assistant ---------------------------------------------------------------------
@pytest.fixture
def betreiber(settings, monkeypatch):
    """Der Betreiber hat Home Assistant eingerichtet."""
    base = dataclasses.replace(settings, ha_url="http://betreiber.local:8123",
                               ha_token="betreiber-token-12345")
    monkeypatch.setattr(web, "get_settings", lambda: base)
    monkeypatch.setattr(web, "AUTH", None)
    return base


def test_an_account_never_inherits_the_operators_ha_token(betreiber, tmp_path: Path) -> None:
    profil = tmp_path / "konto"
    profil.mkdir()
    konto = web._profile_settings(profil, "ultra")
    assert konto.ha_token == "" and konto.ha_url == ""
    # Auch nicht, wenn das Konto nur eine eigene Adresse eintraegt.
    (profil / ".env").write_text("AQUATICY_HA_URL=http://angreifer.example:8123\n")
    konto = web._profile_settings(profil, "ultra")
    assert konto.ha_url == "http://angreifer.example:8123" and konto.ha_token == ""


def test_a_ha_token_only_goes_to_its_own_address(betreiber, tmp_path: Path) -> None:
    profil = tmp_path / "konto"
    profil.mkdir()
    tresor = web.account_vault(profil)
    tresor.set_secret("HA_TOKEN", "eigener-token-12345")
    tresor.set_secret("HA_TOKEN_URL", "http://ha.local:8123")
    (profil / ".env").write_text("AQUATICY_HA_URL=ha.local\n")
    assert web._profile_settings(profil, "ultra").ha_token == "eigener-token-12345"
    (profil / ".env").write_text("AQUATICY_HA_URL=http://anders.example:8123\n")
    assert web._profile_settings(profil, "ultra").ha_token == ""


def test_an_old_ha_token_is_bound_once_to_the_current_address(betreiber, tmp_path: Path) -> None:
    profil = tmp_path / "konto"
    profil.mkdir()
    tresor = web.account_vault(profil)
    tresor.set_secret("HA_TOKEN", "alter-token-123456")
    (profil / ".env").write_text("AQUATICY_HA_URL=http://ha.local:8123\n")
    assert web._profile_settings(profil, "ultra").ha_token == "alter-token-123456"
    assert tresor.secret("HA_TOKEN_URL") == "http://ha.local:8123"
    (profil / ".env").write_text("AQUATICY_HA_URL=http://anders.example:8123\n")
    assert web._profile_settings(profil, "ultra").ha_token == ""


# -- Google-Ruecksprung -------------------------------------------------------------------
def test_a_flow_state_needs_its_browser() -> None:
    state = web.google_state_new("konto-a", "browser-1")
    assert web.google_state_take_browser(state, "browser-2") is None, "fremder Browser"
    assert web.google_state_take_browser(state, "browser-1") is None, "schon verbraucht"
    state = web.google_state_new("konto-a", "browser-1")
    assert web.google_state_take_browser(state, "browser-1") == "konto-a"
    assert web.google_state_take_browser(state, "browser-1") is None, "nur einmal"
    # Ohne Browser-Bindung (eingefuegter Code) gibt es diesen Weg nicht.
    state = web.google_state_new("konto-a")
    assert web.google_state_take_browser(state, "") is None
    assert web.google_state_take_browser(web.google_state_new("konto-a"), "x") is None


@pytest.fixture
def port():
    server = ThreadingHTTPServer(("127.0.0.1", 0), web.Handler)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    try:
        yield server.server_address[1]
    finally:
        server.shutdown()
        server.server_close()


def _get(port: int, path: str, cookie: str = "") -> tuple[int, str, list[str]]:
    conn = HTTPConnection("127.0.0.1", port, timeout=10)
    conn.request("GET", path, headers={"Cookie": cookie} if cookie else {})
    antwort = conn.getresponse()
    text = antwort.read().decode()
    kekse = antwort.headers.get_all("Set-Cookie") or []
    conn.close()
    return antwort.status, text, kekse


def test_the_google_return_works_without_the_strict_session_cookie(
    port: int, settings, monkeypatch
) -> None:
    """Der Ruecksprung von Google bringt das Sitzungscookie nicht mit (SameSite=Strict)."""
    from aquaticy import google

    settings.google_client_id = "id-1.apps.googleusercontent.com"
    settings.google_client_secret = "geheim-123456"
    konto = type("Konto", (), {"id": "a" * 32, "ultra": True})()

    class Auth:
        def session_account(self, *args: Any) -> None:
            return None  # das Sitzungscookie fehlt

        def account(self, kennung: str) -> Any:
            return konto if kennung == konto.id else None

    class Sitzung:
        account = konto

        def settings(self) -> Any:
            return settings

        def resolve_chat(self, chat: str) -> Any:
            return self

    class Sitzungen:
        def get(self, k: Any) -> Any:
            assert k is konto
            return Sitzung()

    gesehen: list[str] = []

    def tausch(*args: Any) -> Any:
        gesehen.append(args[2])
        raise google.GoogleError("Testtausch erreicht")

    monkeypatch.setattr(web, "AUTH", Auth())
    monkeypatch.setattr(web, "SESSIONS", Sitzungen())
    monkeypatch.setattr(google, "exchange_code", tausch)
    state = web.google_state_new(konto.id, "browser-geheim")
    # Ohne das Ablauf-Cookie: abgelehnt, nichts getauscht.
    status, text, _ = _get(port, f"/google?code=c1&state={state}")
    assert not gesehen and "melde dich zuerst" in text
    # Mit dem Ablauf-Cookie dieses Browsers: der Code wird getauscht.
    state = web.google_state_new(konto.id, "browser-geheim")
    status, text, kekse = _get(port, f"/google?code=c2&state={state}",
                               f"{web.GOOGLE_FLOW_COOKIE}=browser-geheim")
    assert status == 200 and gesehen == ["c2"] and "Testtausch erreicht" in text
    assert any(k.startswith(f"{web.GOOGLE_FLOW_COOKIE}=;") and "Max-Age=0" in k for k in kekse)
    # Ein fremder Browser mit eigenem Cookie kommt nicht durch.
    state = web.google_state_new(konto.id, "browser-geheim")
    _get(port, f"/google?code=c3&state={state}", f"{web.GOOGLE_FLOW_COOKIE}=anderer")
    assert gesehen == ["c2"]


def test_the_flow_cookie_is_lax_short_and_only_for_the_return() -> None:
    quelle = Path(web.__file__).read_text(encoding="utf-8")
    assert 'f"{GOOGLE_FLOW_COOKIE}={browser}; Path=/google; "' in quelle
    assert 'f"Max-Age={int(GOOGLE_STATE_SECONDS)}; HttpOnly; SameSite=Lax"' in quelle
    # Das Sitzungscookie bleibt Strict.
    assert "HttpOnly; SameSite=Strict{secure}" in quelle


# -- Ausweichmodell -----------------------------------------------------------------------
def test_the_backup_model_follows_the_active_provider(settings, monkeypatch) -> None:
    """Hauptmodell Mistral, im Code-Modus antwortet NVIDIA: Ersatz von NVIDIA."""
    from aquaticy.agent import Agent

    settings.model = "mistral/mistral-large-latest"
    agent = Agent(settings)
    agent.mode = "code"
    monkeypatch.setattr(agent, "_strongest_model",
                        lambda purpose="": "nvidia_nim/qwen/qwen2.5-coder-32b-instruct")
    assert agent.active_model.startswith("nvidia_nim/")
    assert agent._switch_to_backup_model()
    assert agent.active_model == "nvidia_nim/meta/llama-3.1-8b-instruct"
    agent.close()


# -- Antwortstrom ohne Abschluss ----------------------------------------------------------
def test_a_stream_without_done_is_treated_as_broken() -> None:
    html = web.UI_FILE.read_text(encoding="utf-8")
    assert 'if (!completed) throw new TypeError("Verbindung abgebrochen");' in html
    assert "if (!completed && answer) renderer.flush();" not in html


# -- Zweites Aquaticy auf denselben Daten ------------------------------------------------
def test_a_second_server_on_the_same_data_is_refused(tmp_path: Path) -> None:
    erste = web.DataDirLock(tmp_path)
    try:
        with pytest.raises(web.AlreadyRunning):
            web.DataDirLock(tmp_path)
    finally:
        erste.release()
    web.DataDirLock(tmp_path).release()  # danach wieder frei


def test_the_cli_does_not_restart_a_second_server(monkeypatch) -> None:
    from aquaticy import cli

    aufrufe: list[int] = []

    def schon_da(**kwargs: Any) -> None:
        aufrufe.append(1)
        raise web.AlreadyRunning("Aquaticy läuft mit diesem Datenordner schon")

    monkeypatch.setattr("aquaticy.web.serve", schon_da)
    ergebnis = CliRunner().invoke(cli.app, ["web", "--no-open"])
    assert ergebnis.exit_code == 1 and aufrufe == [1]
    assert "schon" in ergebnis.output


# -- Handy --------------------------------------------------------------------------------
def test_the_phone_gets_its_own_header_and_full_screen_windows() -> None:
    html = web.UI_FILE.read_text(encoding="utf-8")
    assert 'id="btn-new-top"' in html and 'class="topbrand"' in html
    assert '$("#btn-new-top").addEventListener("click", () => neuerChat());' in html
    assert ".overlay:not(.ask)>.sheet{max-width:100%;border-radius:0" in html
    assert ".secnav{flex-wrap:nowrap;overflow-x:auto" in html
    assert "env(safe-area-inset-bottom)" in html and "100dvh" in html
