"""Jeder Modellaufruf zaehlt -- und das Kontingent gilt auch mitten im Lauf.

Bis 9.5.10 wurde nur das Hauptmodell mitgezaehlt. Agenten, Master, Planer,
Rechtspruefer, Bildmodell und die Bildbeschreibung liefen am Zaehler vorbei --
und das Kontingent eines normalen Kontos wurde nur VOR einer Anfrage
geprueft. Eine einzige Anfrage mit vielen Agenten konnte es so weit
ueberschreiten.

Jetzt gilt:

* Alle Aufrufe gehen ueber ``completion()`` hier (das Hauptmodell streamt und
  meldet sich ueber ``record()``). Sie werden zweimal vermerkt: in der
  Statistik des Profils (je Tag und Modell) und -- bei normalen Konten -- im
  Kontingent des Kontos in der Kontendatenbank (aquaticy/quota.py). Gezaehlt
  werden die Zahlen des Anbieters, sonst geschaetzt: drei Zeichen sind ein
  Token.
* Hat das Konto ein Kontingent (``settings.quota``, nur normale Konten), wird
  VOR jedem Aufruf geprueft: 5-Stunden-Sitzung und Woche. Ist eines
  aufgebraucht, kommt ``QuotaExceeded`` -- der Lauf endet, statt weiter auf
  Kosten des Betreibers zu laufen.
* Ein erstelltes Bild zaehlt pauschal ``IMAGE_TOKENS`` -- ein Bildmodell
  rechnet nicht in Token ab, kostet aber trotzdem.
"""

from __future__ import annotations

import contextlib
from typing import Any

from aquaticy.quota import SESSION_TOKENS, QuotaExceeded

__all__ = [
    "IMAGE_TOKENS",
    "QuotaExceeded",
    "charge_image",
    "check",
    "completion",
    "quota_of",
    "record",
    "remaining",
    "share_of_session",
]

#: So viel zaehlt ein erstelltes Bild.
IMAGE_TOKENS = 5_000


def quota_of(settings: Any) -> Any:
    """Das Kontingent des Kontos -- ``None`` heisst: keins (Pro, lokal)."""
    quota = getattr(settings, "quota", None)
    return quota if hasattr(quota, "check") and hasattr(quota, "record") else None


def remaining(settings: Any) -> int | None:
    """Was noch geht -- ``None`` heisst: kein Kontingent."""
    quota = quota_of(settings)
    return None if quota is None else quota.remaining()


def share_of_session(tokens: int) -> str:
    """Wie viel einer Sitzung *tokens* sind -- fuer Saetze an Menschen."""
    anteil = tokens * 100 / SESSION_TOKENS
    return f"{anteil:.1f}".rstrip("0").rstrip(".").replace(".", ",") + " %"


def check(settings: Any, need: int = 0) -> None:
    """Wirft ``QuotaExceeded``, wenn Sitzung oder Woche nichts mehr hergeben."""
    quota = quota_of(settings)
    if quota is not None:
        quota.check(need)


def record(settings: Any, model: str, tokens_in: int, tokens_out: int) -> None:
    """Vermerkt einen Aufruf. Zaehlen darf nie eine Antwort kosten."""
    rein, raus = max(0, int(tokens_in or 0)), max(0, int(tokens_out or 0))
    with contextlib.suppress(Exception):
        from aquaticy.usage import UsageLog

        UsageLog(settings.db_path).record(model, rein, raus)
    quota = quota_of(settings)
    if quota is not None:
        with contextlib.suppress(Exception):
            quota.record(rein + raus, model)


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

    if enforce:
        check(settings)
    response = litellm.completion(**kwargs)
    if not kwargs.get("stream"):
        rein, raus = _counted(kwargs.get("messages"), response)
        record(settings, str(kwargs.get("model") or ""), rein, raus)
    return response


def charge_image(settings: Any, model: str) -> None:
    record(settings, model, 0, IMAGE_TOKENS)
