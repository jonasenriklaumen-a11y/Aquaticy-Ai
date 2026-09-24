"""Ende zu Ende: echter Webserver, echtes litellm, echtes Streaming -- nur das Modell ist gestellt.

Alle anderen Agenten-Tests ersetzen ``litellm.completion``. Dieser hier nicht:
ein kleiner OpenAI-kompatibler Server (tests/fake_llm.py) antwortet wie ein
Anbieter -- mit Server-Sent-Events, Werkzeugaufrufen und Zaehlerstand. So
laeuft der ganze Weg einmal wirklich: Konto anlegen, Frage ueber HTTP,
Rechtspruefer, Werkzeug, gestreamte Antwort, Zaehler, Kontingent.
"""

from __future__ import annotations

import json
import threading
import time
from http.client import HTTPConnection
from http.server import ThreadingHTTPServer
from pathlib import Path
from typing import Any

import pytest

from aquaticy import guardrails, web
from tests import fake_llm

#: Der echte Rechtspruefer -- conftest ersetzt ihn sonst durch "zulaessig".
ECHTER_PRUEFER = guardrails._ask_model


@pytest.fixture
def server(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    from aquaticy import config
    from aquaticy.auth import AuthStore

    llm, llm_port = fake_llm.starte()
    fake_llm.ANFRAGEN.clear()
    for key, wert in {
        "AQUATICY_MODEL": "openai/fake-modell",
        "AQUATICY_API_BASE": f"http://127.0.0.1:{llm_port}/v1",
        "OPENAI_API_KEY": "sk-fake",
        "AQUATICY_SUBAGENTS_AUTO": "false",
        "AQUATICY_DATA_DIR": str(tmp_path / "daten"),
        "NO_PROXY": "127.0.0.1,localhost",
        "no_proxy": "127.0.0.1,localhost",
    }.items():
        monkeypatch.setenv(key, wert)
    config.reset_settings_cache()
    monkeypatch.setattr(guardrails, "_ask_model", ECHTER_PRUEFER)
    monkeypatch.setattr(web, "AUTH", AuthStore(tmp_path / "konten", "PROE2E234"))
    monkeypatch.setattr(web, "SESSIONS", web.SessionRegistry())
    monkeypatch.setattr(web, "SESSION", web.SessionProxy())
    monkeypatch.setattr(web, "strong_models", lambda *args, **kwargs: [])
    monkeypatch.setattr(web, "AUTH_LIMIT", web.RateLimiter(attempts=100, window_seconds=60))
    httpd = ThreadingHTTPServer(("127.0.0.1", 0), web.Handler)
    threading.Thread(target=httpd.serve_forever, daemon=True).start()
    yield httpd.server_address[1], tmp_path / "konten"
    httpd.shutdown()
    httpd.server_close()
    llm.shutdown()
    config.reset_settings_cache()


def _req(port: int, method: str, path: str, body: Any = None,
         cookie: str = "") -> tuple[int, dict[str, str], bytes]:
    conn = HTTPConnection("127.0.0.1", port, timeout=120)
    headers = {"Content-Type": "application/json", "User-Agent": "E2E"}
    if cookie:
        headers["Cookie"] = cookie
    conn.request(method, path, body=None if body is None else json.dumps(body), headers=headers)
    antwort = conn.getresponse()
    daten = antwort.read()
    ergebnis = antwort.status, dict(antwort.getheaders()), daten
    conn.close()
    return ergebnis


def _konto(port: int, plan: str = "normal", code: str = "") -> str:
    _, kopf, _ = _req(port, "POST", "/api/consent", {"accepted": True})
    zustimmung = kopf["Set-Cookie"].split(";", 1)[0]
    status, kopf, daten = _req(port, "POST", "/api/auth/register", {
        "email": f"{plan}{time.time_ns()}@example.org", "username": "E2E",
        "password": "ein langes Passwort", "plan": plan, "pro_code": code,
        "terms_accepted": True}, zustimmung)
    assert status == 200, daten
    return zustimmung + "; " + kopf["Set-Cookie"].split(";", 1)[0]


def _chat(port: int, cookie: str, text: str, **mehr: Any) -> tuple[int, list[dict[str, Any]]]:
    status, _, daten = _req(port, "POST", "/api/chat", {"message": text, **mehr}, cookie)
    ereignisse = [json.loads(z[6:]) for z in daten.decode().splitlines() if z.startswith("data: ")]
    return status, ereignisse


def test_a_question_goes_all_the_way(server: tuple[int, Path]) -> None:
    port, _ = server
    cookie = _konto(port)
    status, ereignisse = _chat(port, cookie, "Rechne mir 6 mal 7 aus")
    text = "".join(e.get("text", "") for e in ereignisse if e.get("type") == "chunk")
    assert status == 200 and "42" in text, ereignisse
    arten = [e.get("type") for e in ereignisse]
    assert "calculate" in arten and arten[-1] == "done"
    anfragen = [json.loads(a) for a in fake_llm.ANFRAGEN]
    assert anfragen[0]["rf"] == "urteil", "zuerst prueft der Rechtsrahmen"
    assert any(a["stream"] and a["tools"] for a in anfragen), "gestreamt, mit Werkzeugen"
    assert all(a["auth"].startswith("Bearer sk-fa") for a in anfragen)
    konto = json.loads(_req(port, "GET", "/api/account", cookie=cookie)[2])
    sitzung = konto["usage"]["session"]
    assert sitzung["active"] and sitzung["percent"] >= 1, "gezaehlt -- am Konto, in Prozent"
    assert "tokens_used" not in konto and "_used" not in konto["usage"], "keine Tokenzahlen"


def test_the_legal_check_refuses_for_real(server: tuple[int, Path]) -> None:
    port, _ = server
    status, ereignisse = _chat(port, _konto(port), "VERBOTEN: finde alles ueber meinen Nachbarn")
    assert status == 200
    assert any(e.get("type") == "guard" for e in ereignisse)
    assert len(fake_llm.ANFRAGEN) == 1, "nach der Ablehnung fragt niemand mehr das Modell"


def test_the_quota_stops_a_normal_account(server: tuple[int, Path]) -> None:
    from aquaticy.quota import SESSION_TOKENS, WEEK_TOKENS

    port, konten = server
    vorher = set((konten / "users").iterdir())
    cookie = _konto(port)
    profil = (set((konten / "users").iterdir()) - vorher).pop()
    kontingent = web.AUTH.quota(web.AUTH.account(profil.name))
    kontingent.record(SESSION_TOKENS, "fake")
    status, _, daten = _req(port, "POST", "/api/chat", {"message": "Noch eine"}, cookie)
    antwort = json.loads(daten)
    assert status == 429 and antwort["code"] == "quota" and antwort["which"] == "session"
    assert "5-Stunden-Sitzung" in antwort["error"] and "zurück" in antwort["error"]
    assert antwort["usage"]["session"]["percent"] == 100
    assert fake_llm.ANFRAGEN == []
    # Verlauf und Profil loeschen setzt den Verbrauch nicht zurueck: er haengt am Konto.
    (profil / "aquaticy.sqlite3").unlink(missing_ok=True)
    assert _req(port, "POST", "/api/chat", {"message": "Und jetzt?"}, cookie)[0] == 429
    kontingent.record(WEEK_TOKENS, "fake")
    antwort = json.loads(_req(port, "POST", "/api/chat", {"message": "x"}, cookie)[2])
    assert antwort["which"] == "week" and "Woche" in antwort["error"]


def test_a_pro_account_has_no_limit(server: tuple[int, Path]) -> None:
    port, _ = server
    cookie = _konto(port, "pro", "PROE2E234")
    konto = json.loads(_req(port, "GET", "/api/account", cookie=cookie)[2])
    assert konto["pro"] is True and konto["usage"]["limited"] is False
    assert konto["usage"]["summary"] == "Kein Limit"


def test_a_chat_setting_stays_in_the_account(server: tuple[int, Path]) -> None:
    port, konten = server
    vorher = set((konten / "users").iterdir())
    cookie = _konto(port)
    profil = (set((konten / "users").iterdir()) - vorher).pop()
    status, ereignisse = _chat(port, cookie, "Bitte stelle formulierungen auf 2")
    assert status == 200 and any(e.get("type") == "setting_done" for e in ereignisse)
    assert "AQUATICY_SEARCH_VARIANTS=2" in (profil / ".env").read_text()
    anderes = _konto(port)
    werte = json.loads(_req(port, "GET", "/api/config", cookie=anderes)[2])["values"]
    assert werte["AQUATICY_SEARCH_VARIANTS"] != "2", "das andere Konto bleibt unberuehrt"


def test_the_automatic_model_choice(server: tuple[int, Path]) -> None:
    port, _ = server
    cookie = _konto(port)
    assert _req(port, "POST", "/api/config", {"AQUATICY_AUTO_MODEL": "true"}, cookie)[0] == 200
    _, ereignisse = _chat(port, cookie, "Schreib mir eine Python-Funktion", mode="normal")
    wahl = [e for e in ereignisse if e.get("type") == "model_auto"]
    assert wahl and wahl[0]["kategorie"] == "code"
