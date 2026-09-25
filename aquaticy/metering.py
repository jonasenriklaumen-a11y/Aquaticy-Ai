"""Was zaehlt -- und das Kontingent gilt auch mitten im Lauf.

Bis 9.5.10 wurde nur das Hauptmodell mitgezaehlt. Agenten, Master, Planer,
Rechtspruefer, Bildmodell und die Bildbeschreibung liefen am Zaehler vorbei --
und das Kontingent eines normalen Kontos wurde nur VOR einer Anfrage
geprueft. Eine einzige Anfrage mit vielen Agenten konnte es so weit
ueberschreiten.

Jetzt gilt:

* **Modellaufrufe** gehen ueber ``completion()`` hier (das Hauptmodell streamt
  und meldet sich ueber ``record()``). Sie landen in der Statistik des Profils
  und -- bei normalen Konten -- im Kontingent (aquaticy/quota.py). Gezaehlt
  werden die Zahlen des Anbieters, sonst geschaetzt: drei Zeichen sind ein
  Token.
* **Eigene Schluessel zaehlen nicht (seit 9.5.14 Seashell).** Laeuft ein
  Modell mit dem API-Schluessel des Kontos (aquaticy/keyvault.py), bezahlt es
  das Konto beim Anbieter selbst -- das Kontingent bleibt davon unberuehrt,
  und vor so einem Aufruf wird auch nicht geprueft. Gestellte Modelle (mit
  dem Schluessel des Betreibers, oder lokal wie Ollama auf dem Server)
  zaehlen wie immer.
* **Serverarbeit zaehlt immer.** Was auf dem Server passiert -- Werkstatt,
  Seitenabrufe, Suchen, Handlungen im User mode --, kostet den Server, egal
  mit wessen Schluessel das Modell laeuft. Sie wird in Token umgerechnet
  (``WORK_COSTS``), damit sie in dasselbe Kontingent passt.
* Hat das Konto ein Kontingent (``settings.quota``, nur normale Konten), wird
  VOR jedem gestellten Aufruf und vor jeder Serverarbeit geprueft. Ist
  Sitzung oder Woche aufgebraucht, kommt ``QuotaExceeded``.
* Ein erstelltes Bild zaehlt pauschal ``IMAGE_TOKENS`` -- ein Bildmodell
  rechnet nicht in Token ab, kostet aber trotzdem. Mit eigenem Bildschluessel
  zaehlt nur das Ablegen auf dem Server.
"""

from __future__ import annotations

import contextlib
import math
from typing import Any

from aquaticy.quota import SESSION_TOKENS, QuotaExceeded

__all__ = [
    "IMAGE_TOKENS",
    "WORK_COSTS",
    "QuotaExceeded",
    "charge_image",
    "charge_work",
    "check",
    "check_image",
    "check_work",
    "completion",
    "is_own",
    "quota_of",
    "record",
    "remaining",
    "share_of_session",
    "work_cost",
]

#: So viel zaehlt ein erstelltes Bild (mit dem Schluessel des Betreibers).
IMAGE_TOKENS = 5_000

#: Was Arbeit auf dem Server kostet -- in Token gerechnet, damit sie mit den
#: Modellaufrufen in dasselbe Kontingent passt. (Einheit, Token je Einheit)
WORK_COSTS: dict[str, tuple[str, int]] = {
    "werkstatt": ("je angefangene Sekunde Rechenzeit in der Werkstatt", 150),
    "werkstatt_start": ("je Start einer Werkstatt", 750),
    "datei": ("je Datei, die in die Werkstatt geht oder aus ihr kommt", 50),
    "seite": ("je abgerufene Webseite", 100),
    "suche": ("je Suchanfrage", 50),
    "desktop": ("je Handlung im User mode (sehen, klicken, tippen)", 100),
    "bild": ("je Bild, das auf dem Server abgelegt wird", 100),
}


def quota_of(settings: Any) -> Any:
    """Das Kontingent des Kontos -- ``None`` heisst: keins (Pro, lokal)."""
    quota = getattr(settings, "quota", None)
    return quota if hasattr(quota, "check") and hasattr(quota, "record") else None


def is_own(settings: Any, model: str) -> bool:
    """Laeuft *model* mit dem eigenen Schluessel des Kontos (``Settings.key_source``)?"""
    quelle = getattr(settings, "key_source", None)
    if not model or not callable(quelle):
        return False
    try:
        return quelle(str(model)) == "own"
    except Exception:
        return False


def remaining(settings: Any) -> int | None:
    """Was noch geht -- ``None`` heisst: kein Kontingent."""
    quota = quota_of(settings)
    return None if quota is None else quota.remaining()


def share_of_session(tokens: int) -> str:
    """Wie viel einer Sitzung *tokens* sind -- fuer Saetze an Menschen."""
    anteil = tokens * 100 / SESSION_TOKENS
    return f"{anteil:.1f}".rstrip("0").rstrip(".").replace(".", ",") + " %"


def check(settings: Any, need: int = 0, *, model: str = "") -> None:
    """Wirft ``QuotaExceeded``, wenn Sitzung oder Woche nichts mehr hergeben.

    Args:
        model: Der Aufruf, der gleich kommt. Laeuft er mit dem eigenen
            Schluessel des Kontos, kostet er das Kontingent nichts -- dann
            wird auch nicht geprueft.
    """
    quota = quota_of(settings)
    if quota is None or is_own(settings, model):
        return
    quota.check(need)


def record(
    settings: Any, model: str, tokens_in: int, tokens_out: int, *, own: bool | None = None
) -> None:
    """Vermerkt einen Modellaufruf. Zaehlen darf nie eine Antwort kosten.

    In der Statistik steht jeder Aufruf; ins Kontingent kommt nur, was nicht
    mit dem eigenen Schluessel des Kontos lief.
    """
    rein, raus = max(0, int(tokens_in or 0)), max(0, int(tokens_out or 0))
    with contextlib.suppress(Exception):
        from aquaticy.usage import UsageLog

        UsageLog(settings.db_path).record(model, rein, raus)
    eigen = is_own(settings, model) if own is None else bool(own)
    quota = quota_of(settings)
    if quota is not None and not eigen:
        with contextlib.suppress(Exception):
            quota.record(rein + raus, model)


# -- Serverarbeit ---------------------------------------------------------------
def work_cost(kind: str, amount: float = 1.0) -> int:
    """Was *amount* Einheiten dieser Arbeit kosten -- angefangene Einheiten zaehlen voll."""
    _, je = WORK_COSTS.get(kind, ("", 0))
    return int(je * max(1, math.ceil(max(0.0, float(amount or 0.0)))))


def check_work(settings: Any, kind: str, amount: float = 1.0) -> None:
    """Wirft ``QuotaExceeded``, wenn fuer diese Arbeit nichts mehr uebrig ist."""
    quota = quota_of(settings)
    if quota is not None:
        quota.check(work_cost(kind, amount))


def charge_work(settings: Any, kind: str, amount: float = 1.0) -> None:
    """Bucht Arbeit auf dem Server -- egal, mit wessen Schluessel das Modell laeuft."""
    quota = quota_of(settings)
    kosten = work_cost(kind, amount)
    if quota is not None and kosten > 0:
        with contextlib.suppress(Exception):
            quota.record(kosten, f"server:{kind}")


# -- Modellaufrufe ------------------------------------------------------------------
def _counted(messages: Any, response: Any) -> tuple[int, int]:
    """Die Zahlen des Anbieters, sonst eine Schaetzung aus dem Text."""
    from aquaticy.usage import message_tokens, tokens

    usage = getattr(response, "usage", None)
    rein = getattr(usage, "prompt_tokens", None)
    raus = getattr(usage, "completion_tokens", None)
    if isinstance(rein, int) and isinstance(raus, int) and rein >= 0 and raus >= 0:
        return rein, raus
    try:
        rein = message_tokens(messages if isinstance(messages, list) else [])
    except Exception:
        rein = 0
    text = ""
    with contextlib.suppress(Exception):
        text = str(response.choices[0].message.content or "")
    return rein, tokens(text)


def completion(settings: Any, *, enforce: bool = True, **kwargs: Any) -> Any:
    """``litellm.completion`` -- gezaehlt und, wo verlangt, gegen das Kontingent geprueft.

    Args:
        enforce: Vorher pruefen. Der Rechtspruefer prueft nicht (er soll im
            Zweifel lieber ablehnen als ausfallen) -- gezaehlt wird er trotzdem.
    """
    import litellm

    modell = str(kwargs.get("model") or "")
    if enforce:
        check(settings, model=modell)
    response = litellm.completion(**kwargs)
    if not kwargs.get("stream"):
        rein, raus = _counted(kwargs.get("messages"), response)
        record(settings, modell, rein, raus)
    return response


def check_image(settings: Any, model: str) -> None:
    """Vor einem Bild: gestellt kostet es IMAGE_TOKENS, mit eigenem Schluessel nur das Ablegen."""
    if is_own(settings, model):
        check_work(settings, "bild")
    else:
        check(settings, need=IMAGE_TOKENS)


def charge_image(settings: Any, model: str) -> None:
    """Bucht ein erstelltes Bild -- je nachdem, wessen Schluessel es gemalt hat."""
    if is_own(settings, model):
        charge_work(settings, "bild")
        with contextlib.suppress(Exception):
            from aquaticy.usage import UsageLog

            UsageLog(settings.db_path).record(model, 0, IMAGE_TOKENS)
    else:
        record(settings, model, 0, IMAGE_TOKENS)
