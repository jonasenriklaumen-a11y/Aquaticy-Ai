"""Das Modell automatisch waehlen (Dev settings, fuer jedes Konto).

Ist der Schalter an, muss der Nutzer nur noch schreiben: Aquaticy sieht sich
die Nachricht an und nimmt als Hauptmodell (Master) das, das dafuer am besten
passt -- fuer Code das Code-Modell, fuer ein Bild das Arbeitspferd plus ein
Bildmodell, fuer ein "Hallo" das schnelle kleine. Die Agenten (Subagenten)
bleiben, wie sie sind: sie haengen am eingestellten Modell, nicht an dieser
Wahl.

"Moeglichst schnell" heisst hier: **kein zusaetzlicher Modellaufruf.** Die
Einordnung ist eine Handvoll Muster ueber der Nachricht und dauert unter
einer Millisekunde; die Liste der erreichbaren Modelle wird fuer eine halbe
Minute gemerkt. Eine Frage, die in keine Schublade passt, bekommt das
staerkste Arbeitsmodell -- nie ein schwaecheres, als ohne den Schalter.
"""

from __future__ import annotations

import re
import threading
import time
from dataclasses import dataclass, field
from typing import Any

#: Die Schubladen -- mit dem Satz, der im Verlauf steht.
KATEGORIEN: dict[str, str] = {
    "bild": "Bild erstellen",
    "code": "Programmieren",
    "schnell": "kurze Unterhaltung",
    "schreiben": "Texte schreiben",
    "recherche": "Recherche und Fragen",
}

_VERB_BILD = (
    r"(?:erstell\w*|generier\w*|erzeug\w*|zeichne\w*|zeichnen|male|malen|malt|"
    r"entw[iu]rf\w*|entwerfen|gestalt\w*|designe?\w*|kreier\w*|"
    r"create|generate|draw|paint|design|make)"
)
_NOMEN_BILD = (
    r"(?:bild(?:er|chen)?|foto|fotos|logo\w*|illustration\w*|grafik\w*|zeichnung\w*|"
    r"poster\w*|plakat\w*|icon\w*|wallpaper\w*|hintergrundbild\w*|image|images|picture|"
    r"avatar\w*|comic\w*|gem[aä]lde\w*|artwork|sticker\w*|emoji-bild|cover\w*)"
)
BILD_RE = re.compile(
    rf"\b{_VERB_BILD}\b[^.?!\n]{{0,60}}\b{_NOMEN_BILD}\b"
    rf"|\b{_NOMEN_BILD}\b[^.?!\n]{{0,60}}\b{_VERB_BILD}\b",
    re.IGNORECASE,
)
#: "Zeig/such/find mir ein Bild von ..." ist eine Suche, kein Auftrag zum Malen.
SUCHE_BILD_RE = re.compile(
    r"\b(zeig\w*|such\w*|find\w*|gibt es|wo (?:finde|gibt)|show me|find me|search)\b",
    re.IGNORECASE,
)

CODE_WORT_RE = re.compile(
    r"\b(python|javascript|typescript|java|kotlin|swift|c\+\+|c#|rust|golang|go-code|php|ruby|"
    r"sql|html|css|bash|shell-?skript|powershell|skript|script|funktion|methode|klasse|"
    r"programm\w*|code|coden|quellcode|bug|fehlermeldung|stacktrace|traceback|exception|"
    r"compiler|kompilier\w*|regex|api|json|yaml|dockerfile|docker|git|refactor\w*|"
    r"unit-?tests?|pytest|algorithmus|datenbank|endpoint|frontend|backend|react|django|flask)\b",
    re.IGNORECASE,
)
CODE_VERB_RE = re.compile(
    r"\b(schreib\w*|programmier\w*|implementier\w*|debug\w*|fix\w*|reparier\w*|bau\w*|"
    r"erstell\w*|optimier\w*|erkl[aä]r\w*|umschreib\w*|konvertier\w*|write|build|fix|"
    r"debug|implement|refactor)\b",
    re.IGNORECASE,
)
CODE_ZEICHEN_RE = re.compile(
    r"```|Traceback \(most recent call last\)|^\s*(def |class |import |from \w+ import |"
    r"function |const |let |#include|public static)",
    re.MULTILINE,
)
SCHNELL_RE = re.compile(
    r"^\s*(hallo|hi|hey|moin|servus|guten (morgen|tag|abend)|"
    r"(danke\w*|vielen dank)(,? (dir|euch|sch[oö]n|sehr|vielmals|das hilft))?|ok(ay)?|"
    r"super|cool|tsch[uü]ss|bis bald|wie geht'?s( dir)?|gute nacht|thanks?|thank you|"
    r"hello|bye)\b[\s!.?,:)]*$",
    re.IGNORECASE,
)
SCHREIBEN_RE = re.compile(
    r"\b(schreib\w*|formulier\w*|verfass\w*|[uü]bersetz\w*|uebersetz\w*|zusammenfass\w*|"
    r"korrigier\w*|umformulier\w*)\b.{0,80}\b(brief\w*|e-?mail\w*|mail|aufsatz|gedicht\w*|"
    r"geschichte\w*|bewerbung\w*|text\w*|rede|artikel\w*|beitrag\w*|nachricht\w*|"
    r"zusammenfassung|absatz|essay|lied\w*|songtext\w*|einladung\w*)\b"
    r"|\b([uü]bersetz\w*|uebersetz\w*|zusammenfass\w*)\b",
    re.IGNORECASE | re.DOTALL,
)


def kategorie(frage: str, mode: str = "normal") -> str:
    """Ordnet eine Nachricht ein -- ohne Modellaufruf."""
    text = (frage or "").strip()
    if mode == "code":
        return "code"
    if not text:
        return "recherche"
    if BILD_RE.search(text) and not SUCHE_BILD_RE.search(text.split(",")[0][:40]):
        return "bild"
    if CODE_ZEICHEN_RE.search(text) or (CODE_WORT_RE.search(text) and CODE_VERB_RE.search(text)):
        return "code"
    if SCHNELL_RE.match(text):
        return "schnell"
    if SCHREIBEN_RE.search(text):
        return "schreiben"
    return "recherche"


@dataclass
class Wahl:
    """Was der Router entschieden hat."""

    kategorie: str
    model: str
    grund: str
    bild_modell: str = ""
    bild_label: str = ""
    extra: dict[str, Any] = field(default_factory=dict)

    @property
    def label(self) -> str:
        return self.model.split("/", 1)[-1] if self.model else ""


#: Die erreichbaren Modelle je Zweck, eine halbe Minute gemerkt -- die Liste
#: fragt Ollama, und das soll nicht vor jeder Nachricht passieren.
_CACHE_TTL = 30.0
_cache: dict[str, tuple[float, str]] = {}
_cache_lock = threading.Lock()


def _staerkstes(settings: Any, zweck: str) -> str:
    from aquaticy.system import strongest_model

    schluessel = f"{getattr(settings, 'data_dir', '')}|{getattr(settings, 'model', '')}|{zweck}"
    with _cache_lock:
        treffer = _cache.get(schluessel)
        if treffer and time.monotonic() - treffer[0] < _CACHE_TTL:
            return treffer[1]
    try:
        modell = strongest_model(settings, purpose=zweck)
    except Exception:
        modell = ""
    with _cache_lock:
        _cache[schluessel] = (time.monotonic(), modell)
    return modell


def forget() -> None:
    with _cache_lock:
        _cache.clear()


def choose(settings: Any, frage: str, mode: str = "normal") -> Wahl:
    """Das beste Hauptmodell fuer diese Nachricht.

    Die Agenten sind nicht Teil der Wahl: sie laufen weiter mit dem
    eingestellten (bzw. dessen schnellem) Modell.
    """
    from aquaticy.system import fast_model

    eingestellt = str(getattr(settings, "model", "") or "")
    art = kategorie(frage, mode)
    grund = KATEGORIEN[art]
    if art == "code":
        return Wahl(art, _staerkstes(settings, "code") or eingestellt, grund)
    if art == "schnell":
        return Wahl(art, fast_model(settings) or eingestellt, grund)
    arbeit = _staerkstes(settings, "work") or eingestellt
    if art == "bild":
        from aquaticy.images import backend_for

        backend = backend_for(settings)
        if backend is None:
            return Wahl(art, arbeit, grund + " (kein Bildmodell erreichbar)")
        return Wahl(art, arbeit, grund, bild_modell=backend.model, bild_label=backend.label)
    return Wahl(art, arbeit, grund)
