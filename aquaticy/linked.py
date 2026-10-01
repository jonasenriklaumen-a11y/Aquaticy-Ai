"""Verknuepfte KI-Konten und AI Council (seit 9.6.1).

**Verknuepfen.** Claude (Anthropic), ChatGPT (OpenAI) und Gemini (Google)
werden mit dem API-Schluessel des eigenen Kontos verbunden. Der Schluessel
liegt verschluesselt im Schluesselbund des Aquaticy-Kontos (aquaticy/
keyvault.py) und geht nur an den Anbieter selbst. Danach liest Aquaticy aus,
was das Konto kann:

* **Modelle:** die Liste, die der Anbieter fuer genau diesen Schluessel
  freigibt. Sie stehen danach in der Modellauswahl -- im Normal-, Pro- und
  Code-Modus wie alle anderen.
* **Stufe und Tokens:** Anthropic und OpenAI nennen bei jeder Antwort die
  Grenzen des Schluessels und was davon im laufenden Zeitfenster noch frei
  ist. Daraus ergibt sich auch die Stufe (Tier). Dafuer geht eine winzige
  Anfrage mit einem einzigen Token raus. Google gibt beides ueber die
  Schnittstelle nicht heraus -- dann steht das so da.

**Warum kein Passwort?** Die Abos auf claude.ai, chatgpt.com und gemini.google
haben keine Schnittstelle fuer andere Programme. Sich dort mit E-Mail und
Passwort maschinell anzumelden, verbieten alle drei Anbieter, es scheitert an
Zwei-Faktor und Captchas, und Aquaticy haette das Passwort des ganzen Kontos.
Der API-Schluessel ist der vorgesehene Weg: er laesst sich jederzeit beim
Anbieter widerrufen und kann nichts ausser Modelle aufrufen. Wer bei Google
angemeldet ist, holt sich den Gemini-Schluessel mit einem Klick im AI Studio.

**AI Council.** Statt eines Modells arbeiten mehrere: die verknuepften Modelle
bearbeiten die Frage, eines prueft auf Fehler (Gemini, wenn verknuepft), und
das Hauptmodell von Aquaticy ist der Richter. Er entscheidet, ob die Loesung
traegt -- wenn nicht, gehen seine Einwaende und die Antworten der anderen
zurueck an die Bearbeiter, die sich daran abarbeiten (bis zu drei Runden).
Am Ende schreibt der Richter die Antwort. Agenten laufen in diesem Modus nicht.
"""

from __future__ import annotations

import contextlib
import json
import re
import threading
import time
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from typing import Any

import httpx

#: Die Anbieter: Name im Schluesselbund, Praefix fuer LiteLLM, wo es den Schluessel gibt.
PROVIDERS: dict[str, dict[str, str]] = {
    "anthropic": {"label": "Claude", "company": "Anthropic", "key": "ANTHROPIC_API_KEY",
                  "prefix": "anthropic/", "get_key": "https://console.anthropic.com/settings/keys",
                  "form": "sk-ant-…"},
    "openai": {"label": "ChatGPT", "company": "OpenAI", "key": "OPENAI_API_KEY",
               "prefix": "openai/", "get_key": "https://platform.openai.com/api-keys",
               "form": "sk-…"},
    "gemini": {"label": "Gemini", "company": "Google", "key": "GEMINI_API_KEY",
               "prefix": "gemini/", "get_key": "https://aistudio.google.com/apikey",
               "form": "AIza…"},
}
KEY_NAMES = frozenset(p["key"] for p in PROVIDERS.values())
STATE_FILE = "linked.json"
TIMEOUT = 15.0
#: Hoechstens so viele Modelle je Anbieter in der Auswahl.
MAX_MODELS = 12
#: Runden im Council, bevor der Richter in jedem Fall entscheidet.
COUNCIL_ROUNDS = 3

_LOCK = threading.Lock()


class LinkError(RuntimeError):
    """Der Anbieter hat abgelehnt oder war nicht erreichbar."""


# -- Auslesen ----------------------------------------------------------------
def _http(client: httpx.Client | None) -> httpx.Client:
    return client or httpx.Client(timeout=TIMEOUT, follow_redirects=False)


def _fehler(antwort: httpx.Response, anbieter: str) -> LinkError:
    if antwort.status_code in (401, 403):
        return LinkError(f"{anbieter} lehnt den Schlüssel ab — bitte prüfen.")
    if antwort.status_code == 429:
        return LinkError(f"{anbieter}: Limit gerade erreicht oder kein Guthaben.")
    return LinkError(f"{anbieter} antwortet mit Fehler {antwort.status_code}.")


def _int(wert: Any) -> int | None:
    try:
        return int(str(wert).strip())
    except (TypeError, ValueError):
        return None


def anthropic_tier(requests_per_minute: int | None) -> str:
    """Stufe aus dem Anfragelimit (Anthropic: Tier 1 = 50/min, 2 = 1000, 3 = 2000, 4 = 4000)."""
    if not requests_per_minute:
        return ""
    for grenze, name in ((50, "Tier 1"), (1000, "Tier 2"), (2000, "Tier 3"), (4000, "Tier 4")):
        if requests_per_minute <= grenze:
            return name
    return "Tier 4+ / individuell"


def openai_tier(tokens_per_minute: int | None) -> str:
    """Stufe aus dem Token-Limit von gpt-4o-mini (OpenAI-Tabelle der Stufen)."""
    if not tokens_per_minute:
        return ""
    for grenze, name in ((40_000, "Free"), (200_000, "Tier 1"), (2_000_000, "Tier 2"),
                         (4_000_000, "Tier 3"), (10_000_000, "Tier 4")):
        if tokens_per_minute <= grenze:
            return name
    return "Tier 5"


_OPENAI_CHAT = re.compile(r"^(gpt-|o\d|chatgpt-)")
_OPENAI_SKIP = re.compile(r"audio|realtime|transcribe|tts|image|search|embedding|moderation|"
                          r"instruct|codex|computer-use|-\d{4}-\d{2}-\d{2}$")


def _sort_models(models: list[dict[str, str]]) -> list[dict[str, str]]:
    """Neueste und groesste zuerst -- grob, aber ohne Netz."""
    return sorted(models, key=lambda m: m["id"], reverse=True)[:MAX_MODELS]


def inspect(provider: str, key: str, client: httpx.Client | None = None) -> dict[str, Any]:
    """Liest Modelle, Stufe und freie Tokens fuer einen Schluessel aus.

    Raises:
        LinkError: Schluessel abgelehnt, Anbieter nicht erreichbar.
    """
    if provider not in PROVIDERS:
        raise LinkError("Diesen Anbieter gibt es hier nicht.")
    http = _http(client)
    try:
        if provider == "anthropic":
            return _inspect_anthropic(http, key)
        if provider == "openai":
            return _inspect_openai(http, key)
        return _inspect_gemini(http, key)
    except httpx.HTTPError as exc:
        raise LinkError(f"{PROVIDERS[provider]['label']} ist nicht erreichbar "
                        f"({type(exc).__name__}).") from exc
    finally:
        if client is None:
            http.close()


def _inspect_anthropic(http: httpx.Client, key: str) -> dict[str, Any]:
    kopf = {"x-api-key": key, "anthropic-version": "2023-06-01"}
    antwort = http.get("https://api.anthropic.com/v1/models", params={"limit": 100},
                       headers=kopf)
    if antwort.status_code != 200:
        raise _fehler(antwort, "Claude")
    modelle = _sort_models([
        {"id": "anthropic/" + str(m.get("id")), "label": str(m.get("display_name") or m.get("id"))}
        for m in antwort.json().get("data", []) if str(m.get("id", "")).startswith("claude")])
    info: dict[str, Any] = {"models": modelle, "tier": "", "tokens": None}
    klein = next((m["id"] for m in modelle if "haiku" in m["id"]),
                 modelle[-1]["id"] if modelle else "")
    if klein:
        probe = http.post("https://api.anthropic.com/v1/messages", headers=kopf, json={
            "model": klein.split("/", 1)[1], "max_tokens": 1,
            "messages": [{"role": "user", "content": "."}]})
        h = probe.headers
        info["tier"] = anthropic_tier(_int(h.get("anthropic-ratelimit-requests-limit")))
        limit = _int(h.get("anthropic-ratelimit-tokens-limit")
                     or h.get("anthropic-ratelimit-input-tokens-limit"))
        frei = _int(h.get("anthropic-ratelimit-tokens-remaining")
                    or h.get("anthropic-ratelimit-input-tokens-remaining"))
        if limit is not None or frei is not None:
            info["tokens"] = {"limit": limit, "remaining": frei, "per": "Minute",
                              "reset": h.get("anthropic-ratelimit-tokens-reset", "")}
        if probe.status_code in (400, 402) and "credit" in probe.text.lower():
            info["warning"] = "Kein Guthaben mehr auf dem Anthropic-Konto."
    return info


def _inspect_openai(http: httpx.Client, key: str) -> dict[str, Any]:
    kopf = {"Authorization": f"Bearer {key}"}
    antwort = http.get("https://api.openai.com/v1/models", headers=kopf)
    if antwort.status_code != 200:
        raise _fehler(antwort, "ChatGPT")
    ids = [str(m.get("id", "")) for m in antwort.json().get("data", [])]
    modelle = _sort_models([{"id": "openai/" + i, "label": i} for i in ids
                            if _OPENAI_CHAT.match(i) and not _OPENAI_SKIP.search(i)])
    info: dict[str, Any] = {"models": modelle, "tier": "", "tokens": None}
    if "gpt-4o-mini" in ids:
        probe = http.post("https://api.openai.com/v1/chat/completions", headers=kopf, json={
            "model": "gpt-4o-mini", "max_tokens": 1,
            "messages": [{"role": "user", "content": "."}]})
        h = probe.headers
        limit = _int(h.get("x-ratelimit-limit-tokens"))
        info["tier"] = openai_tier(limit)
        if limit is not None:
            info["tokens"] = {"limit": limit,
                              "remaining": _int(h.get("x-ratelimit-remaining-tokens")),
                              "per": "Minute", "reset": h.get("x-ratelimit-reset-tokens", "")}
        if probe.status_code == 429 and "quota" in probe.text.lower():
            info["warning"] = "Kein Guthaben mehr auf dem OpenAI-Konto."
    return info


def _inspect_gemini(http: httpx.Client, key: str) -> dict[str, Any]:
    # Der Schluessel im Kopf, nicht in der Adresse -- Adressen landen in Protokollen.
    antwort = http.get("https://generativelanguage.googleapis.com/v1beta/models",
                       params={"pageSize": 200}, headers={"x-goog-api-key": key})
    if antwort.status_code != 200:
        raise _fehler(antwort, "Gemini")
    modelle = _sort_models([
        {"id": "gemini/" + str(m.get("name", "")).removeprefix("models/"),
         "label": str(m.get("displayName") or m.get("name"))}
        for m in antwort.json().get("models", [])
        if "generateContent" in (m.get("supportedGenerationMethods") or [])
        and "gemini" in str(m.get("name", "")) and "embedding" not in str(m.get("name", ""))])
    return {"models": modelle, "tier": "", "tokens": None,
            "note": "Google nennt Stufe und Restkontingent nicht über die Schnittstelle — "
                    "zu sehen im AI Studio unter „Usage“."}


# -- Gespeicherter Stand (kein Geheimnis: nur Modelle und Grenzen) -----------
def _path(data_dir: Path | str) -> Path:
    return Path(data_dir) / STATE_FILE


def load(data_dir: Path | str) -> dict[str, Any]:
    with contextlib.suppress(OSError, ValueError):
        daten = json.loads(_path(data_dir).read_text(encoding="utf-8"))
        if isinstance(daten, dict):
            return daten
    return {}


def save(data_dir: Path | str, provider: str, info: dict[str, Any] | None) -> None:
    with _LOCK:
        daten = load(data_dir)
        if info is None:
            daten.pop(provider, None)
        else:
            daten[provider] = dict(info, checked=time.time())
        ziel = _path(data_dir)
        ziel.parent.mkdir(parents=True, exist_ok=True)
        tmp = ziel.with_suffix(".tmp")
        tmp.write_text(json.dumps(daten, ensure_ascii=False), encoding="utf-8")
        tmp.replace(ziel)


def linked_providers(settings: Any) -> list[str]:
    """Verknuepfte Anbieter: Schluessel da UND unter Add-ons ausgelesen.

    Mit Konto zaehlt nur der EIGENE Schluessel -- einer, den der Betreiber in
    seiner Umgebung hat, macht noch kein verknuepftes Konto.
    """
    import os

    stand = load(settings.data_dir)
    eigene = getattr(settings, "own_key_names", frozenset()) or frozenset()
    keys = getattr(settings, "api_keys", {}) or {}
    mit_konto = bool(getattr(settings, "account_email", ""))
    out = []
    for p, d in PROVIDERS.items():
        if p not in stand:
            continue
        if mit_konto:
            da = d["key"] in eigene and bool(keys.get(d["key"]))
        else:
            da = bool(keys.get(d["key"]) or os.environ.get(d["key"], "").strip())
        if da:
            out.append(p)
    return out


def picker_models(settings: Any) -> list[dict[str, str]]:
    """Die verknuepften Modelle fuer die Modellauswahl."""
    stand = load(settings.data_dir)
    out: list[dict[str, str]] = []
    for provider in linked_providers(settings):
        d = PROVIDERS[provider]
        for m in (stand.get(provider) or {}).get("models", []):
            mid = str(m.get("id", ""))
            if not mid.startswith(d["prefix"]):
                continue
            out.append({"id": mid, "label": str(m.get("label") or mid.split("/", 1)[1]),
                        "kind": f"{d['label']} (verknüpft)",
                        "note": f"Dein {d['company']}-Konto", "source": "own"})
    return out


_BEST = {
    "anthropic": (r"opus", r"sonnet", r"haiku"),
    "openai": (r"^openai/gpt-5(?!.*(mini|nano))", r"^openai/o3(?!-mini)", r"^openai/gpt-4\.1(?!-)",
               r"^openai/gpt-4o$", r"gpt"),
    "gemini": (r"pro", r"flash"),
}


def best_model(settings: Any, provider: str) -> str:
    """Das staerkste verknuepfte Modell eines Anbieters (fuer den Council)."""
    modelle = [str(m.get("id", "")) for m in (load(settings.data_dir).get(provider) or {})
               .get("models", [])]
    for muster in _BEST.get(provider, ()):
        treffer = [m for m in modelle if re.search(muster, m)]
        if treffer:
            return sorted(treffer, reverse=True)[0]
    return modelle[0] if modelle else ""


# -- AI Council ---------------------------------------------------------------
def council_roles(settings: Any) -> tuple[list[tuple[str, str]], tuple[str, str] | None]:
    """(Bearbeiter, Pruefer) als (Anbieter, Modell). Gemini prueft, wenn es dabei ist."""
    dabei = [(p, best_model(settings, p)) for p in linked_providers(settings)]
    dabei = [(p, m) for p, m in dabei if m]
    if len(dabei) < 2:
        return dabei, None
    pruefer = next((x for x in dabei if x[0] == "gemini"), dabei[-1])
    return [x for x in dabei if x != pruefer], pruefer


WORKER_PROMPT = (
    "Du bist Mitglied in einem Rat aus mehreren KI-Modellen. Löse die Aufgabe so gut "
    "du kannst: vollständig, korrekt, auf Deutsch, wenn die Frage deutsch ist. Kennzeichne "
    "Unsicheres als unsicher. Rate keine Fakten.")
CHECK_PROMPT = (
    "Du bist der Prüfer im Rat. Prüfe die folgenden Lösungen auf sachliche Fehler, Lücken, "
    "Widersprüche und Rechenfehler. Nenne jeden Fehler konkret (wer, was, warum falsch). "
    "Findest du nichts, schreib „Keine Fehler gefunden.“")
JUDGE_PROMPT = (
    "Du bist Aquaticy, der Richter im Rat. Vor dir liegen die Lösungen der Bearbeiter und "
    "der Prüfbericht. Entscheide: Ist eine Lösung (oder ihre Kombination) korrekt und "
    "vollständig? Antworte NUR mit JSON: {\"ok\": true|false, \"feedback\": \"was die "
    "Bearbeiter noch klären oder korrigieren müssen (leer, wenn ok)\"}.")
FINAL_PROMPT = (
    "Du bist Aquaticy, der Richter im Rat. Schreibe jetzt die endgültige Antwort an den "
    "Nutzer aus den geprüften Lösungen: korrekt, klar, ohne den Rat zu erwähnen, außer es "
    "bleibt ein Punkt strittig — dann sag das offen.")


def _ask(settings: Any, model: str, system: str, user: str, *, json_mode: bool = False) -> str:
    from aquaticy import metering

    kwargs = dict(settings.llm_kwargs_for(model))
    kwargs.setdefault("timeout", 120.0)
    kwargs.setdefault("drop_params", True)
    if json_mode:
        kwargs["response_format"] = {"type": "json_object"}
    antwort = metering.completion(settings, model=model, messages=[
        {"role": "system", "content": system}, {"role": "user", "content": user}], **kwargs)
    return str(antwort.choices[0].message.content or "").strip()


def _judge(text: str) -> tuple[bool, str]:
    roh = text.strip().removeprefix("```json").removeprefix("```").removesuffix("```")
    start, ende = roh.find("{"), roh.rfind("}")
    with contextlib.suppress(ValueError):
        daten = json.loads(roh[start:ende + 1])
        if isinstance(daten, dict):
            return bool(daten.get("ok")), str(daten.get("feedback") or "").strip()
    return "true" in roh.lower()[:40], roh[:2000]


def run_council(settings: Any, question: str, context: str = "", judge_model: str = "",
                emit: Any = None, stop: threading.Event | None = None) -> str:
    """Der Rat: Bearbeiter arbeiten, der Pruefer prueft, der Richter entscheidet.

    Returns: die endgueltige Antwort (vom Richter geschrieben).
    """
    bearbeiter, pruefer = council_roles(settings)
    richter = judge_model or settings.model
    melden = emit or (lambda *a, **k: None)
    if not bearbeiter:
        raise LinkError("Für den AI Council braucht es mindestens zwei verknüpfte Konten.")
    aufgabe = f"{context}\n\nAufgabe:\n{question}".strip() if context else question
    loesungen: dict[str, str] = {}
    pruefbericht = ""
    rueckmeldung = ""
    melden("council", phase="start", workers=[m for _, m in bearbeiter],
           checker=pruefer[1] if pruefer else "", judge=richter)
    for runde in range(1, COUNCIL_ROUNDS + 1):
        if stop is not None and stop.is_set():
            break
        melden("council", phase="work", round=runde)

        def arbeite(eintrag: tuple[str, str], runde: int = runde,
                    pruefbericht: str = pruefbericht,
                    rueckmeldung: str = rueckmeldung) -> tuple[str, str]:
            _, modell = eintrag
            if runde == 1:
                text = aufgabe
            else:
                andere = "\n\n".join(f"--- {m} ---\n{t}" for m, t in loesungen.items()
                                     if m != modell)
                text = (f"{aufgabe}\n\nDeine bisherige Lösung:\n{loesungen.get(modell, '')}\n\n"
                        f"Lösungen der anderen:\n{andere}\n\nPrüfbericht:\n{pruefbericht}\n\n"
                        f"Einwände des Richters:\n{rueckmeldung}\n\nDiskutiere die Punkte, "
                        "übernimm, was die anderen besser haben, und gib deine verbesserte "
                        "Lösung.")
            try:
                return modell, _ask(settings, modell, WORKER_PROMPT, text)
            except Exception as exc:
                return modell, f"(nicht erreichbar: {type(exc).__name__})"

        with ThreadPoolExecutor(max_workers=len(bearbeiter)) as pool:
            for modell, text in pool.map(arbeite, bearbeiter):
                loesungen[modell] = text
        alle = "\n\n".join(f"--- Lösung von {m} ---\n{t}" for m, t in loesungen.items())
        if pruefer is not None:
            melden("council", phase="check", round=runde, model=pruefer[1])
            try:
                pruefbericht = _ask(settings, pruefer[1], CHECK_PROMPT,
                                    f"Aufgabe:\n{aufgabe}\n\n{alle}")
            except Exception as exc:
                pruefbericht = f"(Prüfer nicht erreichbar: {type(exc).__name__})"
        melden("council", phase="judge", round=runde, model=richter)
        try:
            urteil = _ask(settings, richter, JUDGE_PROMPT,
                          f"Aufgabe:\n{aufgabe}\n\n{alle}\n\nPrüfbericht:\n{pruefbericht}",
                          json_mode=True)
        except Exception:
            urteil = '{"ok": true}'
        ok, rueckmeldung = _judge(urteil)
        melden("council", phase="verdict", round=runde, ok=ok, feedback=rueckmeldung[:500])
        if ok:
            break
    melden("council", phase="final", model=richter)
    alle = "\n\n".join(f"--- Lösung von {m} ---\n{t}" for m, t in loesungen.items())
    return _ask(settings, richter, FINAL_PROMPT,
                f"Frage des Nutzers:\n{aufgabe}\n\n{alle}\n\nPrüfbericht:\n{pruefbericht}")
