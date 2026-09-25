"""Bilder erstellen -- bei den Anbietern, fuer die ein Schluessel da ist.

Aquaticy arbeitet mit zwei Anbietern (siehe aquaticy/system.py), und beide
koennen Bilder:

* **NVIDIA** -- FLUX.1 [schnell] von Black Forest Labs, gehostet bei NVIDIA
  (build.nvidia.com). Ein Aufruf, das Bild kommt als Base64 zurueck.
* **Mistral** -- die eingebaute Bildgenerierung der Conversations-API
  (Werkzeug ``image_generation``). Das Bild liegt danach als Datei bei
  Mistral und wird von dort geholt.

Wer welchen nimmt: zuerst der Anbieter des eingestellten Modells (ein
Schluessel, eine Rechnung), dann die Reihenfolge aus ``CODING_ORDER``.

Was dabei gilt:

* Die Beschreibung geht an den Anbieter -- sonst nichts: keine Chats, keine
  Dateien, kein Verlauf.
* Die Rechtspruefung (aquaticy/guardrails.py) sieht jede Beschreibung vorher
  (``create_image`` steht in SENSITIVE_TOOLS): keine Bilder, die echte
  Menschen blossstellen, keine Faelschungen, die als echt durchgehen sollen.
* Jedes Bild ist als KI-erstellt beschriftet, im Chat wie im Dateinamen der
  Anzeige.
"""

from __future__ import annotations

import base64
import os
import re
from dataclasses import dataclass
from typing import Any

import httpx

#: Groessen je Format -- Vielfache von 64, die FLUX.1 [schnell] annimmt.
FORMATS: dict[str, tuple[int, int]] = {
    "quadrat": (1024, 1024),
    "quer": (1344, 768),
    "hoch": (768, 1344),
}

#: Groesstes Bild, das angenommen wird.
MAX_IMAGE_BYTES = 12_000_000

#: Laengste Beschreibung.
MAX_PROMPT_CHARS = 2_000

NVIDIA_FLUX_URL = "https://ai.api.nvidia.com/v1/genai/black-forest-labs/flux.1-schnell"
MISTRAL_API = "https://api.mistral.ai/v1"


@dataclass(frozen=True)
class Backend:
    provider: str
    model: str
    label: str
    key: str


BACKENDS: dict[str, Backend] = {
    "nvidia_nim": Backend(
        "nvidia_nim", "nvidia_nim/black-forest-labs/flux.1-schnell",
        "FLUX.1 schnell (NVIDIA)", "NVIDIA_NIM_API_KEY",
    ),
    "mistral": Backend(
        "mistral", "mistral/mistral-medium-latest", "Mistral Bildgenerierung",
        "MISTRAL_API_KEY",
    ),
}


class ImageError(RuntimeError):
    """Ein Bild kam nicht zustande -- mit einem Satz, den der Nutzer versteht."""


def _key(settings: Any, name: str) -> str:
    keys = getattr(settings, "api_keys", None) or {}
    return str(keys.get(name) or os.environ.get(name) or "").strip()


def available(settings: Any) -> list[Backend]:
    """Die Anbieter, mit denen gerade ein Bild moeglich ist -- der passendste zuerst."""
    from aquaticy.config import provider_of
    from aquaticy.system import CODING_ORDER

    eigener = provider_of(str(getattr(settings, "model", "") or ""))
    reihenfolge = [eigener, *CODING_ORDER]
    gefunden: list[Backend] = []
    for provider in reihenfolge:
        backend = BACKENDS.get(provider)
        if backend and backend not in gefunden and _key(settings, backend.key):
            gefunden.append(backend)
    # Mit eigenem Schluessel des Kontos zuerst (9.5.14 Seashell): den bezahlt
    # das Konto selbst, das Kontingent zaehlt dann nur das Ablegen.
    eigene: frozenset[str] = frozenset(getattr(settings, "own_key_names", ()) or ())
    return sorted(gefunden, key=lambda b: b.key not in eigene)


def backend_for(settings: Any, model: str = "") -> Backend | None:
    """Das Backend zu einer Modell-Kennung -- oder das beste verfuegbare."""
    verfuegbar = available(settings)
    for backend in verfuegbar:
        if model and backend.model == model:
            return backend
    return verfuegbar[0] if verfuegbar else None


def generate(
    settings: Any,
    prompt: str,
    fmt: str = "quadrat",
    *,
    model: str = "",
    client: httpx.Client | None = None,
) -> dict[str, Any]:
    """Erstellt ein Bild.

    Returns:
        {"bytes": ..., "mime": "image/png"|"image/jpeg", "modell": Label,
         "model_id": Kennung (fuers Abrechnen: eigener oder gestellter Schluessel)}

    Raises:
        ImageError: Kein Anbieter, abgelehnt, Zeitueberschreitung ...
    """
    text = " ".join(str(prompt or "").split())
    if not text:
        raise ImageError("Ohne Beschreibung gibt es kein Bild.")
    if len(text) > MAX_PROMPT_CHARS:
        raise ImageError(f"Die Beschreibung ist zu lang (hoechstens {MAX_PROMPT_CHARS} Zeichen).")
    fmt = fmt if fmt in FORMATS else "quadrat"
    backend = backend_for(settings, model)
    if backend is None:
        raise ImageError(
            "Bilder erstellen geht mit einem Schluessel fuer NVIDIA oder Mistral "
            "(Einstellungen -> Modell). Lokal kann Aquaticy keine Bilder malen."
        )
    eigener = client is None
    client = client or httpx.Client(timeout=120)
    try:
        if backend.provider == "nvidia_nim":
            daten = _nvidia(client, _key(settings, backend.key), text, fmt)
        else:
            daten = _mistral(client, _key(settings, backend.key), text, fmt)
    except httpx.TimeoutException as exc:
        raise ImageError(f"{backend.label} hat zu lange gebraucht.") from exc
    except httpx.HTTPError as exc:
        raise ImageError(f"{backend.label} nicht erreichbar ({type(exc).__name__}).") from exc
    except (ValueError, KeyError, TypeError, AttributeError) as exc:
        raise ImageError(f"{backend.label} hat unerwartet geantwortet.") from exc
    finally:
        if eigener:
            client.close()
    if not daten or len(daten) > MAX_IMAGE_BYTES:
        raise ImageError(f"{backend.label} hat kein brauchbares Bild geliefert.")
    try:
        mime = _mime(daten)
    except ValueError as exc:
        raise ImageError(f"{backend.label} hat unerwartet geantwortet (kein Bild).") from exc
    return {"bytes": daten, "mime": mime, "modell": backend.label, "model_id": backend.model}


def _mime(daten: bytes) -> str:
    if daten[:8] == b"\x89PNG\r\n\x1a\n":
        return "image/png"
    if daten[:3] == b"\xff\xd8\xff":
        return "image/jpeg"
    if daten[:4] == b"RIFF" and daten[8:12] == b"WEBP":
        return "image/webp"
    raise ValueError("kein bekanntes Bildformat")


def _pruefe(antwort: httpx.Response, wer: str) -> None:
    if antwort.status_code in (401, 403):
        raise ImageError(f"{wer} lehnt den Schluessel ab ({antwort.status_code}).")
    if antwort.status_code == 429:
        raise ImageError(f"{wer}: zu viele Anfragen -- gleich noch einmal versuchen.")
    if antwort.status_code == 422 or antwort.status_code == 400:
        raise ImageError(f"{wer} hat die Beschreibung abgelehnt ({antwort.status_code}).")
    if antwort.status_code != 200:
        raise ImageError(f"{wer} antwortet mit {antwort.status_code}.")


def _nvidia(client: httpx.Client, key: str, text: str, fmt: str) -> bytes:
    breite, hoehe = FORMATS[fmt]
    antwort = client.post(
        NVIDIA_FLUX_URL,
        headers={"Authorization": f"Bearer {key}", "Accept": "application/json"},
        json={"prompt": text, "width": breite, "height": hoehe, "seed": 0, "steps": 4},
    )
    _pruefe(antwort, "NVIDIA")
    artefakt = (antwort.json().get("artifacts") or [{}])[0]
    if str(artefakt.get("finishReason", "SUCCESS")).upper() == "CONTENT_FILTERED":
        raise ImageError("NVIDIA hat das Bild wegen seiner Inhaltsregeln nicht erstellt.")
    return base64.b64decode(str(artefakt["base64"]), validate=False)


def _mistral(client: httpx.Client, key: str, text: str, fmt: str) -> bytes:
    kopf = {"Authorization": f"Bearer {key}", "Accept": "application/json"}
    seiten = {"quadrat": "quadratisch", "quer": "im Querformat", "hoch": "im Hochformat"}[fmt]
    antwort = client.post(
        f"{MISTRAL_API}/conversations",
        headers=kopf,
        json={
            "model": BACKENDS["mistral"].model.split("/", 1)[1],
            "inputs": f"Erstelle genau ein Bild, {seiten}: {text}",
            "tools": [{"type": "image_generation"}],
        },
    )
    _pruefe(antwort, "Mistral")
    datei = ""
    for ausgabe in antwort.json().get("outputs") or []:
        inhalt = ausgabe.get("content")
        for teil in inhalt if isinstance(inhalt, list) else []:
            if isinstance(teil, dict) and teil.get("type") == "tool_file" and teil.get("file_id"):
                datei = str(teil["file_id"])
                break
        if datei:
            break
    if not re.fullmatch(r"[A-Za-z0-9_-]{1,128}", datei):
        raise ImageError("Mistral hat kein Bild erstellt (vielleicht wegen seiner Inhaltsregeln).")
    bild = client.get(f"{MISTRAL_API}/files/{datei}/content", headers=kopf)
    _pruefe(bild, "Mistral")
    return bild.content
