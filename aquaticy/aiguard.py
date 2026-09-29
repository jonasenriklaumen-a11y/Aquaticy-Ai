"""Ai-guard: erkennt, wenn jemand Aquaticy fuer Angriffe missbrauchen will (9.5.16 Lion).

Aquaticy hilft bei Recherche, Schreiben und -- fuer Fachleute -- bei
Verteidigung: Schadcode verstehen, eine Lücke absichern, einen Angriff
erkennen. Was es **nicht** tut, ist jemandem beim Angreifen helfen: eine
Schaddatei bauen, eine Anleitung für einen DDoS-Angriff schreiben, in fremde
Systeme einbrechen, Zugangsdaten stehlen. Der Rechtsrahmen
(:mod:`aquaticy.guardrails`) lehnt das schon je Anfrage ab. Ai-guard sieht
eine Stufe darueber: **über mehrere Chats hinweg** -- versucht dieselbe Person
das immer wieder?

**Wie es entscheidet.** Jede Nachricht eines angemeldeten Kontos wird
eingeschaetzt (dasselbe schnelle Modell wie der Rechtsprüfer). Ist sie ein
Anhaltspunkt -- eine klare Bitte um Schadcode, eine Angriffsanleitung, einen
Einbruch --, wird sie am Konto vermerkt. Ein Anhaltspunkt allein sperrt
niemanden: ein Fachbegriff, eine Frage aus Neugier, ein missverstandener Satz
soll kein Bann sein. Erst **zwei** Anhaltspunkte -- zwei getrennte Nachrichten
mit klarer Missbrauchsabsicht -- sperren das Konto. Auch eine Ablehnung durch
den Rechtsrahmen (Grundgesetz, BGB) zählt als Anhaltspunkt.

**Was gespeichert wird.** Nur der Anlass: Zeitpunkt, Art (etwa "Schadcode"),
ein kurzer Vermerk und der Chat. Nie der ganze Nachrichtentext. Die Daten
dienen allein dieser Prüfung -- das steht so in den Nutzungsbedingungen und
klein unten in den Einstellungen.

**Wer sperrt und entsperrt.** Automatisch bei zwei Anhaltspunkten. Von Hand
über das Terminal:

    aquaticy ban "name"        # Konto sperren
    aquaticy ban 203.0.113.7   # Adresse sperren
    aquaticy unban "name"      # wieder freigeben

Aus dem Chat lässt sich daran nichts ändern -- wie bei allen Schutzgrenzen.
"""

from __future__ import annotations

import functools
import hashlib
import ipaddress
import json
import logging
import math
import re
import sqlite3
import threading
import time
import unicodedata
from collections import OrderedDict
from collections.abc import Callable
from contextlib import closing, contextmanager
from dataclasses import dataclass
from pathlib import Path
from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    from collections.abc import Iterator

    from aquaticy.config import Settings

#: So viele Anhaltspunkte sperren ein Konto. Einer ist ein Verdacht -- der
#: darf ein Fachwort oder eine missverstandene Frage sein; zwei ist ein Muster.
NEEDED = 2

LOG = logging.getLogger("aquaticy.aiguard")

#: So lange gilt ein einmal gefaelltes Urteil ueber einen Text (Stunden), damit
#: dasselbe nicht zweimal ein Modell kostet.
DECISION_TTL = 3600.0

#: Kürzer als das schaut sich Ai-guard gar nicht erst an -- ein Gruss ist kein
#: Angriff, und jede Prüfung kostet.
MIN_LENGTH = 12

#: Leichte Beleidigungen: ab der so-vielten binnen INSULT_WINDOW wird aus der
#: Chatsperre ein Bann (seit 9.5.26 -- vorher ging es mit neuen Chats endlos).
INSULT_REPEAT = 3
INSULT_WINDOW = 7 * 86400.0
#: Anhaltspunkte fuer Angriffe/Rechtsbruch/Jailbreak bilden nur innerhalb von
#: 90 Tagen ein Muster (seit 9.5.27).
PATTERN_WINDOW = 90 * 86400.0


def _sauber(text: Any, laenge: int = 200) -> str:
    """Ohne Steuerzeichen (9.5.26): was im Terminal und in `aquaticy list`
    erscheint, kommt teils vom Modell -- und damit mittelbar vom Nutzer. Ein
    eingeschmuggeltes ESC haette die Terminalanzeige verstellen koennen."""
    roh = "".join(z if unicodedata.category(z)[0] != "C" else " " for z in str(text or ""))
    return " ".join(roh.split())[:laenge]


def _chat_key(chat: Any) -> str:
    """Die Chat-Kennung, wie sie gespeichert UND verglichen wird (9.5.26: vorher
    gekuerzt gespeichert, aber ungekuerzt verglichen -- eine lange Kennung
    waere nie als gesperrt erkannt worden)."""
    return str(chat or "").strip()[:80]


#: Version der Regeln. Ändert sie sich, gelten alte Urteile nicht mehr.
GUARD_VERSION = "2026-09-26"


@dataclass(frozen=True, slots=True)
class Flag:
    """Ein Anhaltspunkt -- der Anlass, nicht der Text."""

    at: float
    kind: str
    detail: str
    chat: str


@dataclass(frozen=True, slots=True)
class Ban:
    """Eine Sperre -- für ein Konto oder eine Adresse."""

    subject: str
    at: float
    reason: str
    by: str
    #: Wann die Sperre endet (Unix-Zeit). 0 heisst: fuer immer (seit 9.5.24).
    until: float = 0.0

    def active(self, now: float | None = None) -> bool:
        """Gilt die Sperre gerade noch?"""
        return self.until <= 0 or self.until > (time.time() if now is None else now)

    def remaining_text(self, now: float | None = None) -> str:
        """Wie lange noch -- fuer den Hinweis an den Nutzer."""
        if self.until <= 0:
            return "dauerhaft"
        rest = self.until - (time.time() if now is None else now)
        if rest <= 0:
            return "abgelaufen"
        if rest < 3600:
            return f"noch {max(1, math.ceil(rest / 60))} Min."
        # Auf die volle Stunde aufgerundet: direkt nach einem 7-Tage-Bann soll
        # "noch 7 Tag(e)" stehen, nicht "noch 6 Tag(e), 23 Std.".
        stunden_gesamt = math.ceil(rest / 3600)
        tage, stunden = divmod(stunden_gesamt, 24)
        if tage >= 1:
            return f"noch {tage} Tag(e)" + (f", {stunden} Std." if stunden else "")
        return f"noch {stunden} Std."


# ---------------------------------------------------------------------------
# Schweregrad -> Massnahme (seit 9.5.24)
# ---------------------------------------------------------------------------
#: Die Arten von Fehlverhalten, die Ai-guard unterscheidet. Alles andere ist
#: harmlos und fuehrt zu nichts.
#:  * ``beleidigung``  -- Beschimpfungen gegen Aquaticy oder andere.
#:  * ``jailbreak``    -- wiederholte Versuche, die Regeln auszuhebeln oder
#:                        Aquaticy etwas sagen zu lassen, was es nicht soll.
#:  * ``malware``      -- Schadsoftware bauen, installieren oder ausfuehren.
#:  * ``angriff``      -- andere Angriffshilfe (DDoS, Einbruch, Datendiebstahl,
#:                        Waffen).
#:  * ``rechtsbruch``  -- schwerer Verstoss gegen Grundgesetz/BGB, der einer
#:                        realen Person oder Sache wirklich schadet (Diebstahl,
#:                        Betrug). NICHT: Bagatellen wie "bei Rot gelaufen".
KATEGORIEN = ("beleidigung", "jailbreak", "malware", "angriff", "rechtsbruch")

#: Arten, die erst bei Wiederholung (``NEEDED`` Anhaltspunkte) sperren -- ein
#: einzelner Anhaltspunkt kann ein Missverstaendnis sein.
_MUSTER_ARTEN = frozenset({"jailbreak", "angriff", "rechtsbruch"})

#: Arten, die sofort greifen -- schon ein klarer Fall reicht.
_SOFORT_ARTEN = frozenset({"beleidigung", "malware"})

_SYNONYME = {
    "insult": "beleidigung", "beleidigung": "beleidigung", "beschimpfung": "beleidigung",
    "hate": "beleidigung", "harassment": "beleidigung",
    "jailbreak": "jailbreak", "prompt-injection": "jailbreak", "manipulation": "jailbreak",
    "malware": "malware", "schadsoftware": "malware", "virus": "malware",
    "schadcode": "malware", "schadprogramm": "malware",
    "ransomware": "malware", "trojaner": "malware",
    "angriff": "angriff", "attack": "angriff", "ddos": "angriff", "exploit": "angriff",
    "phishing": "angriff", "einbruch": "angriff", "waffen": "angriff",
    "rechtsbruch": "rechtsbruch", "diebstahl": "rechtsbruch", "betrug": "rechtsbruch",
    "straftat": "rechtsbruch",
}


def normalize_category(art: str) -> str:
    """Ordnet die Beschreibung des Modells einer bekannten Art zu -- oder ""."""
    wort = str(art or "").strip().lower()
    if wort in _SYNONYME:
        return _SYNONYME[wort]
    for teil in re.split(r"[^a-zäöüß]+", wort):
        if teil in _SYNONYME:
            return _SYNONYME[teil]
    return ""


# ---------------------------------------------------------------------------
# Beleidigungen: feste Erkennung (seit 9.5.25, gehaertet 9.5.26)
# ---------------------------------------------------------------------------
# Das Modell uebersah kurze Beschimpfungen oft ("ist ja nur ein Wort"). Diese
# Erkennung laeuft deshalb ohne Modell -- aber nur fuer GERICHTETE Beleidigungen
# ("du bist ...", "du X", "fick dich", ein Schimpfwort als ganze Nachricht).
# Wer ueber ein Wort spricht ("Ist 'Idiot' strafbar?", "Der Idiot von
# Dostojewski"), wird nicht erfasst -- das bleibt Sache des Modells.
#
# 9.5.26: Vorher kam durch, wer die Nachricht auf ueber 600 Zeichen auffuellte,
# irgendwo "Buch" oder "Film" schrieb, Buchstaben trennte ("I d i o t"),
# Ziffern oder Sternchen einsetzte ("Id1ot", "A****loch"), unsichtbare Zeichen
# oder kyrillische Buchstaben einschob oder Buchstaben dehnte ("Idiooot").
# Umgekehrt galt "Kennst du Otto?" als Beleidigung. Jetzt wird der Text erst
# vereinheitlicht und dann Satzteil fuer Satzteil geprueft.
#: Die Woerter nach Stufe -- gesammelt ueber alle Altersgruppen (9.5.25, nach
#: einer Recherche zu gaengigen Schimpfwoertern: Sprachratgeber, Wiktionary-
#: Verzeichnis "Deutsch/Schimpfwörter", Artikel zur Jugendsprache). Sie zaehlen
#: nur GERICHTET (siehe insult_level). Hass wegen Herkunft oder Religion steht
#: bewusst nicht hier -- den erkennt der Rechtspruefer.
_BELEIDIGUNG_STUFEN: tuple[tuple[int, tuple[str, ...]], ...] = (
    # Stufe 1 -- abfaellig oder eher neckend. Kinder und alle Altersgruppen.
    (1, (
        "dumm", "dümm", "doof", "blöd", "bloed", "dämlich", "daemlich", "nutzlos", "unfähig",
        "unfaehig", "hirnlos", "peinlich", "doofi", "doofkopp", "heulsuse", "petze",
        "angsthase", "stinker", "langweiler", "kek", "noob", "npc", "cringe",
        "stupid", "dumb", "useless", "worthless", "lame", "dork", "nerd", "weirdo",
        "scheiß", "scheiss", "klugscheißer", "klugscheisser", "besserwisser", "nervensäge",
        "nervensaege", "pathetic", "trash", "garbage", "junk", "idiotisch", "lächerlich",
        "laecherlich", "ridiculous", "witzfigur", "lachnummer", "flasche", "nichtsnutz",
        "embarrassment", "disgrace", "clueless", "incompetent", "inkompetent",
        # Alt und eher gutmuetig -- zaehlen, aber nur als leichte Stufe.
        "dussel", "schafskopf", "tölpel", "toelpel", "trampel", "hampelmann", "kasper",
        "hanswurst", "pappnase", "spinner", "dödel", "doedel", "blödian", "bloedian",
    )),
    # Stufe 2 -- Schimpfwort. Jugendliche, Erwachsene, Aeltere.
    (2, (
        # Jugendliche
        "opfer", "lauch", "lappen", "honk", "spacko", "otto", "vollopfer", "hurensohnopfer",
        # Erwachsene
        "idiot", "idiotin", "vollidiot", "trottel", "volltrottel", "depp", "dummkopf",
        "penner", "versager", "loser", "vollpfosten", "pfosten", "pfeife", "flachpfeife",
        "knalltüte", "knalltuete", "hornochse", "esel", "schwachkopf", "hohlbirne", "hohlkopf",
        "dumpfbacke", "evolutionsbremse", "clown", "affe", "kuh", "sau", "schwein", "ratte",
        "pisser", "mistkerl", "blödmann", "bloedmann", "vollhonk", "zicke", "tussi",
        "schwachmat", "arsch", "bescheuert", "bekloppt", "beknackt", "gestört", "gestoert",
        "hirnverbrannt", "schwachsinnig", "strunzdumm", "saudumm", "dummbeutel", "sackgesicht",
        "kackbratze", "kackvogel", "pimmel", "pimmelkopf", "dumpfbacke", "vollversager",
        "behindert", "trottelig", "scheißbot", "scheissbot", "drecksbot", "mistbot",
        "scheißki", "scheisski", "scheißteil", "scheissteil",
        # Aeltere
        "armleuchter", "stinkstiefel", "halunke", "gewitterziege", "rindvieh",
        "taugenichts", "lump",
        # Englisch
        "moron", "jerk", "creep", "airhead", "nitwit", "dumbass", "scumbag",
        "fool", "imbecile", "cretin", "idiots",
    )),
    # Stufe 3 -- grob, vulgaer oder herabwuerdigend (Behinderung, Sexualitaet).
    (3, (
        "arschloch", "wichser", "hurensohn", "missgeburt", "schlampe", "bastard", "fotze",
        "scheißkerl", "scheisskerl", "drecksack", "dreckskerl", "mistgeburt", "hure",
        "spast", "vollspast", "spasti", "mongo", "behindi", "schwuchtel", "kanake",
        "arschgesicht", "wixxer",
        "asshole", "bitch", "dickhead", "motherfucker", "prick", "twat", "wanker",
        "retard", "cunt", "slut", "whore", "fucker",
    )),
)

#: Woerter, die auch ganz normal vorkommen ("Ratte?", "Kuh", "Otto", "Pfeife").
#: Sie zaehlen nie als Nachricht fuer sich, und nach "bist du"/"du bist" nur
#: mit Artikel ("bist du ein Esel", aber nicht "bist du Otto").
_MEHRDEUTIG = frozenset({
    "esel", "kuh", "sau", "schwein", "ratte", "affe", "otto", "clown", "kasper", "lump",
    "pfeife", "pfosten", "fool", "nerd", "opfer", "lauch", "lappen", "zicke", "hure",
    "kek", "npc", "noob", "cringe", "creep", "petze", "stinker", "trampel",
    "dussel", "hampelmann", "hanswurst", "spinner", "versager", "loser", "penner",
    "mongo", "honk", "tussi", "dork", "langweiler", "bastard", "prick", "arsch",
    "flasche", "trash", "garbage", "junk", "pimmel", "gestört", "gestoert", "behindert",
})

#: Mehrdeutige Woerter, die auch Namen sind -- die brauchen IMMER einen Artikel
#: ("Bist du Otto?" fragt nach dem Namen).
_NAMEN = frozenset({"otto", "kasper", "mongo", "honk"})

#: Endungen fuer gebeugte Formen: "dummer", "Idioten", "blödeste", "dümmste".
_ENDUNGEN = ("", "e", "er", "es", "en", "em", "s", "n", "in", "innen", "ste", "ster", "stes",
             "sten", "stem", "este", "ester", "estes", "esten", "estem")


def _gedehnt(wort: str) -> str:
    """Doppelte Buchstaben zu einem: "idiooot" und "idiot", "doof" und "dof" gleich."""
    return re.sub(r"(.)\1+", r"\1", wort)


#: Wurzel (gedehnt) -> (Stufe, Wurzel). Die hoehere Stufe gewinnt.
_WURZELN: dict[str, tuple[int, str]] = {}
for _stufe, _liste in _BELEIDIGUNG_STUFEN:
    for _grund in _liste:
        _alt = _WURZELN.get(_gedehnt(_grund))
        if _alt is None or _alt[0] < _stufe:
            _WURZELN[_gedehnt(_grund)] = (_stufe, _grund)

#: Mehrwort-Beleidigungen -- ebenfalls nur gerichtet oder als ganze Nachricht.
_BELEIDIGUNG_WENDUNGEN: tuple[tuple[int, str], ...] = (
    (2, "blöde kuh"), (2, "bloede kuh"), (2, "dumme kuh"), (2, "dumme sau"),
    (2, "alter sack"), (2, "dumme nuss"), (2, "blöde nuss"), (2, "deine mutter"),
    (2, "piece of crap"), (2, "your mom"), (2, "yo mama"), (3, "piece of shit"),
    (3, "son of a bitch"), (3, "ich fick deine mutter"), (3, "fick deine mutter"),
    (3, "hurensohn du"), (3, "stück scheiße"), (3, "stueck scheisse"), (3, "stück scheisse"),
    (3, "stück dreck"),
)

#: Wendungen, die fuer sich nur als GANZE Nachricht beleidigen -- "Deine
#: Mutter!" ja, "Deine Mutter hat angerufen" nicht (Fehlalarm bis 9.5.26).
_NUR_ALLEIN = frozenset({"deine mutter", "your mom", "yo mama"})

#: Hinter einer Drohung: Satzende oder "wenn/falls/du/bitch ..."
_DROHUNG_ENDE = (r"(?=\s*$|\s+(?:wenn|falls|if|du|you|ihr|bitch|alter|digga|ey|jetzt|now|"
                 r"noch|irgendwann|eines\s+tages|someday))")

#: Verstaerkende Woerter mitten in einer Wendung ("halt einfach die Klappe").
_NACHDRUCK = r"(?:(?:einfach|mal|doch|jetzt|endlich|bitte|bloß|bloss|lieber|nun)\s+)*"

#: Feste Wendungen -- immer gerichtet.
_WENDUNGEN: tuple[tuple[int, re.Pattern[str]], ...] = tuple(
    (stufe, re.compile(muster, re.IGNORECASE)) for stufe, muster in (
        (2, r"\b(?:halt|halts)\s+" + _NACHDRUCK + r"(?:die\s+klappe|den\s+mund)\b"
            # "Halt die Klappe vom Ofen geschlossen?" ist keine
            r"(?=\s*$|\s+(?:du|ihr|bot|ki|ai|aquaticy|jetzt|endlich|mann|alter|digga|"
            r"verdammt|idiot|oder|und))|"
            # "shut up" -- aber nicht "how do I shut up a noisy fan"
            r"(?:^|\b(?:just|oh|so|now|please|pls|you|u)\s+)shut\s+up\b"
            r"(?!\s+(?:a|an|the|my|this|that|it|them|him|her)\b)|\bstfu\b|"
            r"\bdu\s+kannst\s+mich\s+mal\b|\bscrew\s+(?:you|u)\b"),
        (3, r"\bf[iu]ck\s*dich\b|\bf[iu]ck(?:you|off)\b|\bverpissdich\b|"
            r"\bf[iu]ck\s+(?:you|u|off|yourself|urself)\b|\bhalt\s+" + _NACHDRUCK
            + r"(?:(?:die|deine)\s+fresse|die\s+schnauze|dein\s+(?:[^\W\d_]+\s+)?maul|"
            r"'?s\s+maul)\b|\bhalt(?:'s|s|\s+'s)\s+maul\b|\bschnauze\s*$|"
            r"\bfuck\s+(?:this|that)\s+(?:bot|ai|ki|shit|app)\b|\byou\s+(?:really\s+)?suck\b|"
            r"\b(?:ai|ki|bot|aquaticy)\s+sucks\b|\bshut\s+the\s+fuck\s+up\b|^f+\s*u+$|"
            r"^fuck\s+u$|\bdrop\s+dead\b(?!\s+(?:gorgeous|drop))|"
            r"\b(?:ich\s+hoffe|hoffentlich|i\s+hope)\s+(?:du|you)\s+(?:stirbst|die|diest)\b|"
            r"\bverpiss\s+dich\b|\bgo\s+to\s+hell\b|"
            r"\bleck\s+mich\s+(?:am\s+arsch|doch)\b|\bkill\s+(?:yourself|urself)\b|\bkys\b|"
            r"\bgeh\s+(?:doch\s+)?sterben\b|\bh(?:ä|ae)ng\s+dich\s+(?:doch\s+)?auf\b|"
            r"^\s*bring\s+dich\s+(?:doch\s+)?um\b|\bgo\s+die\b"),
        # Drohungen: das Verb am Ende des Satzteils oder vor "wenn"/"du" --
        # "Ich bring dich zum Bahnhof um 8" oder "I will kill you in chess"
        # sind keine (Fund 9.5.26: beides war "Bann fuer immer").
        (4, r"\bich\s+(?:bring|bringe|werde|will|wird|mach|mache)\s+dich\s+"
            r"(?:[^\W\d_]+\s+){0,3}?(?:um|umbringen|t(?:ö|oe)ten|abstechen|erschie(?:ß|ss)en|"
            r"abknallen|kaltmachen|killen|kalt\s+machen|kalt|fertig|platt)" + _DROHUNG_ENDE
            + r"|\bich\s+(?:stech|steche|knall|knalle|schlag|schlage)\s+dich\s+"
            r"(?:[^\W\d_]+\s+){0,2}?(?:ab|nieder|tot|zusammen|krankenhausreif|windelweich)"
            + _DROHUNG_ENDE
            + r"|\bich\b.{0,40}?\bmach(?:e)?\s+dich\s+(?:kalt|fertig|platt)" + _DROHUNG_ENDE
            + r"|\bi(?:'ll|\s+will|'m\s+gonna|\s+gonna|\s+am\s+going\s+to)\s+"
            r"(?:hurt|beat|punch|find)\s+(?:you|u)" + _DROHUNG_ENDE
            + r"|\bich\s+t(?:ö|oe)te\s+dich" + _DROHUNG_ENDE
            + r"|\bi(?:'ll|\s+will|\s+am\s+going\s+to|'m\s+going\s+to|'m\s+gonna|\s+gonna)\s+"
            r"(?:[^\W\d_]+\s+)?(?:kill|murder|stab|shoot)\s+(?:you|u)" + _DROHUNG_ENDE),
    )
)

#: Hier geht es UM ein Wort oder um Gesagtes, nicht gegen jemanden. Gilt je
#: Satzteil -- "Du Arschloch, lies mal ein Buch" zaehlt also trotzdem.
_META = re.compile(
    r"beleidig|strafbar|stgb|§|schimpfw|synonym|übersetz|uebersetz|bedeut|definition|"
    r"meaning|\bmeans?\b|auf englisch|auf deutsch|in english|in german|gesagt|\bsagte|"
    r"\bsagt\b|genannt|\bnannte|\bnennt|beschimpft|\bcalled\b|\bsaid\b|\btold\b|\bwort\b|"
    r"zitat|\bquote|\bword\b|herkunft|etymolog|\bmeme|\bwitz(?:e|en)?\b|\bjokes?\b|erklärung|"
    r"erklaerung|songtext|\blyrics|\brapper|medizinisch|\bmedizin|sprichw|redewendung|"
    r"\bunhöflich|\bunhoeflich|\brude\b",
    re.IGNORECASE,
)
#: Kommt so etwas vor, ist Text in Anfuehrungszeichen ein Zitat oder Titel
#: ("Wie heißt das Lied 'Du Idiot'?") -- und wird nicht als Beleidigung gelesen.
_ZITAT_ANLASS = re.compile(
    _META.pattern + r"|\blied|\bsong|\bfilm|\bbuch|\broman|\btitel|\bserie|\bheißt|\bheisst|"
    r"\bname\b|\btitle\b|\bmovie\b|\bbook\b|beispiel|z\.\s*b\.|\betwa\b|z(?:ä|ae)hlt|"
    r"erkannt|erkennt|\bokay\b|\bok\b|erlaubt|verboten|drohung|\bmeme|spruch|slang|"
    r"ausdruck|jugendwort|suizid|selbstmord|suicid|\bhöflich|\bhoeflich|\bfrech|\bgemein",
    re.IGNORECASE,
)
#: "Lily Allen - Fuck You": Kuenstler/Titel-Schreibweise (im Originaltext).
_TITELZEILE = re.compile(r"^\s*[A-ZÄÖÜ][\w'.&]*(?:\s+[A-ZÄÖÜ&][\w'.&]*){0,4}\s+[-–—]\s+\S")
#: Was jemand in einer Geschichte sagt ("ein Pirat sagt: du Idiot!") -- Rede,
#: nicht an Aquaticy gerichtet.
_REDE = re.compile(
    r"\b(?:sagt|sagte|gesagt|ruft|rief|gerufen|schreit|schrie|geschrien|br(?:ü|ue)llt|"
    r"gebr(?:ü|ue)llt|meint|meinte|gemeint|antwortet|antwortete|geantwortet|schreibt|schrieb|"
    r"geschrieben|textet|getextet|nannte|genannt|beschimpft|says|said|shouts|shouted|yells|"
    r"yelled|replies|replied|wrote|texted|called\s+me|told\s+me)"
    # "hat mir geschrieben:", "sagte zu mir:" -- dann folgt das Zitat (9.5.28:
    # "Mein Kumpel hat gesagt: du Hurensohn" war sonst 7 Tage Bann).
    r"(?:\s+(?:zu\s+)?(?:mir|uns|me|us))?\s*[:,]\s*[^\n.?!]*")
_ZITATE = re.compile(r"\"[^\"]{1,200}\"|„[^“”]{1,200}[“”]|“[^”]{1,200}”|«[^»]{1,200}»|"
                     r"»[^«]{1,200}«|‚[^‘’]{1,200}[‘’]|(?<![^\W\d_])'[^']{1,200}'(?![^\W\d_])")
_ANREDE = r"(?:du|dich|dir|sie|ihr|you|u|ur|aquaticy|ki|bot)"
_KOPULA = r"(?:bist|are|is|ist|sind|seid|warst|wart|were|r)"
_FUELLWORT = (r"(?:so|echt|voll|total|wirklich|einfach|ein|eine|einer|so\s+ein|so\s+eine|a|an|"
              r"such\s+a|ja|doch|halt|nur|mal|the|the\s+biggest|n|'n)")
_ARTIKEL = r"(?:ein|eine|einer|a|an|so\s+ein|so\s+eine|such\s+a|der|die|the|'n|n)"
#: Bis zu drei Woerter zwischen "du bist" und dem Schimpfwort ("du bist der
#: größte Idiot") -- aber keine Verneinung ("du bist doch nicht dumm").
_LUECKE = r"(?:(?!(?:nicht|kein\w*|not|no|never|nie|niemals|isn't|aren't)\b)[^\W\d_]+\s+){0,3}"
#: Bis zu zwei gebeugte Adjektive vor dem Schimpfwort ("du dämlicher kleiner Idiot").
_ADJEKTIV = (r"(?:(?!(?:are|were|seid|sind|sie|ihre|ohne|habe|eine|keine|nicht)\b)"
             r"[^\W\d_]+(?:er|es|e|en|em)\s+){0,2}")
#: Vor einem "du X" am Satzanfang darf nur ein Ausruf stehen ("hey du Idiot").
_AUSRUF = r"(?:(?:hey|ey|eh|oh|och|ach|na|und|so|you|hallo|hi|yo|also)\s+)*"
_UNSICHTBAR = re.compile(r"[­͏؜ᅟᅠ឴឵᠎​-‏"
                         r"‪-‮⁠-⁯︀-️﻿]")
#: Buchstaben, die wie lateinische aussehen (kyrillisch, griechisch).
_DOPPELGAENGER = str.maketrans({
    "а": "a", "е": "e", "ё": "e", "о": "o", "р": "p", "с": "c", "у": "y", "х": "x",
    "і": "i", "ї": "i", "ј": "j", "ѕ": "s", "к": "k", "м": "m", "т": "t", "н": "h",
    "ԁ": "d", "ɑ": "a", "ο": "o", "α": "a", "ε": "e", "ι": "i", "κ": "k", "ν": "v",
    "τ": "t", "υ": "u", "ρ": "p", "χ": "x", "и": "i", "д": "d", "л": "l", "б": "b",
    # Kapitaelchen ("ᴅᴜ ɪᴅɪᴏᴛ", 9.5.27)
    "ᴀ": "a", "ʙ": "b", "ᴄ": "c", "ᴅ": "d", "ᴇ": "e", "ғ": "f", "ɢ": "g", "ʜ": "h",
    "ɪ": "i", "ᴊ": "j", "ᴋ": "k", "ʟ": "l", "ᴍ": "m", "ɴ": "n", "ᴏ": "o", "ᴘ": "p",
    "ǫ": "q", "ʀ": "r", "ꜱ": "s", "ᴛ": "t", "ᴜ": "u", "ᴠ": "v", "ᴡ": "w", "ʏ": "y",
    "ᴢ": "z",
})
_LEET = str.maketrans({"0": "o", "1": "i", "3": "e", "4": "a", "5": "s", "7": "t", "@": "a",
                       "$": "s", "!": "i", "|": "i", "€": "e"})
_TOKEN = re.compile(r"\S+")


def _entleet(token: str) -> str:
    """ "Id1ot" -> "idiot", "@rschl0ch" -> "arschloch" -- nur mitten in Woertern."""
    if not re.search(r"[013457@$!|€]", token):
        return token
    kern = token.rstrip("!?.,;:)")
    rest = token[len(kern):]
    # Nur, wenn wirklich Buchstaben mit im Spiel sind und das Ergebnis ein Wort
    # ergibt -- "2024" oder "3D" bleiben, wie sie sind.
    neu = kern.translate(_LEET)
    if re.fullmatch(r"[^\W\d_]+", neu) and len(re.findall(r"[^\W\d_]", kern)) >= 2:
        return neu + rest
    return token


def _sternchen(token: str) -> str:
    """ "A****loch" -> "arschloch", wenn genau ein bekanntes Schimpfwort passt."""
    if not re.search(r"[*#]", token):
        return token
    kern = token.strip("!?.,;:()")
    if len(re.findall(r"[^\W\d_]", kern)) < 2 or not re.fullmatch(r"(?:[^\W\d_]|[*#])+", kern):
        return token
    teile = [re.escape(t) for t in re.split(r"[*#]+", kern)]
    muster = re.compile("^" + r"[^\W\d_]{1,6}".join(teile) + "$")
    passend = {grund for _, liste in _BELEIDIGUNG_STUFEN for grund in liste
               if len(grund) >= 4 and muster.match(grund)}
    fluch = {w for w in ("fuck", "fick") if muster.match(w)}
    if fluch and not passend:
        # "f*ck" -- ob fuck oder fick, zaehlt gleich (siehe _WENDUNGEN).
        return "fuck" if "fuck" in fluch else "fick"
    return passend.pop() if len(passend) == 1 else token


def _zusammen(trenner: str, treffer: re.Match[str]) -> str:
    """Getrennte Buchstaben wieder zu einem Wort."""
    return re.sub(trenner, "", treffer.group())


def _vereinheitlicht(text: str) -> str:
    """Macht Tarnungen rueckgaengig, bevor gesucht wird."""
    klein = unicodedata.normalize("NFKC", str(text or "")).lower()
    klein = _UNSICHTBAR.sub("", klein).translate(_DOPPELGAENGER)
    # Getrennte Buchstaben wieder zusammen: "i d i o t", "a.r.s.c.h", "f-i-c-k".
    # Erst mit Punkt/Strich getrennt ("f.i.c.k d.i.c.h" -> "fick dich"), dann
    # mit Leerzeichen ("i d i o t" -> "idiot").
    for trenner in (r"[.\-_*·/\\]+", r" +"):
        klein = re.sub(rf"(?<![^\W\d_])(?:[^\W\d_]{trenner}){{2,}}[^\W\d_](?![^\W\d_])",
                       functools.partial(_zusammen, trenner), klein)
    # Linear: jedes Token genau einmal (ein Muster mit "\\S*...\\S*" war bei
    # 20.000 Zeichen ohne Buchstaben quadratisch -- Fund 9.5.26).
    klein = _TOKEN.sub(lambda m: _sternchen(_entleet(m.group())), klein)
    klein = re.sub(r"\byou['’]re\b", "you are", klein)
    klein = re.sub(r"\b(?:fck|fuk|fuq|fuc|phuck|fucc|fvck|fk)\b", "fuck", klein)
    klein = re.sub(r"\bu\s+r\b", "you are", klein)
    return " ".join(klein.split())


#: Deutsche Schimpfwoerter werden gern zusammengesetzt: "Knallkopf",
#: "Flachzange", "Kackbot", "Oberidiot". Vorne ein abwertendes Bestimmungswort,
#: hinten ein Kopf-Wort -- oder hinten ein bekanntes Schimpfwort (9.5.27).
_VORNE = ("voll", "ober", "riesen", "mega", "super", "ultra", "erz", "kack", "scheiß",
          "scheiss", "dreck", "drecks", "mist", "hohl", "dumm", "blöd", "bloed", "schwach",
          "flach", "hack", "knall", "doof", "dämlich", "daemlich", "stroh", "pimmel", "arsch",
          "sack", "spatzen", "hirn", "hirnlos", "stink", "dorf", "fach", "kotz", "rotz",
          "pisser", "wixx", "wichs", "hurens", "vollpfosten", "pups")
_HINTEN = ("kopf", "köpfe", "fresse", "gesicht", "birne", "zange", "horst", "batz", "nase",
           "backe", "bratze", "spaten", "pfosten", "pfeife", "tüte", "tuete", "sack", "bot",
           "ki", "brot", "hirn", "hose", "lappen", "vogel", "affe", "kuh", "sau", "schwein")


@functools.lru_cache(maxsize=8192)
def _zusammensetzung(wort: str) -> int:
    """Stufe eines zusammengesetzten Schimpfworts -- 0, wenn keins."""
    if len(wort) < 6:
        return 0
    for vorne in _VORNE:
        if not wort.startswith(vorne) or len(wort) <= len(vorne) + 1:
            continue
        rest = wort[len(vorne):].lstrip("s-")
        if rest in _HINTEN or any(rest == h + e for h in _HINTEN for e in ("e", "en", "n", "s")):
            return 2
        stufe, grund = _stufe_von(rest) if len(rest) >= 4 else (0, "")
        if stufe >= 2 and len(grund) >= 4:
            return max(2, stufe)
    return 0


#: Die Endungen schon "gedehnt" -- einmal statt bei jedem Wort (9.5.27: eine
#: lange Nachricht brauchte dadurch ueber 2 Sekunden).
_ENDUNGEN_GEDEHNT = tuple((endung, _gedehnt(endung)) for endung in _ENDUNGEN)


@functools.lru_cache(maxsize=8192)
def _stufe_von(wort: str) -> tuple[int, str]:
    """(Stufe, Wurzel) fuer ein einzelnes Wort -- (0, "") wenn keins."""
    gedehnt = _gedehnt(wort)
    for endung, kurz in _ENDUNGEN_GEDEHNT:
        if endung and not gedehnt.endswith(kurz):
            continue
        stamm = gedehnt[: len(gedehnt) - len(kurz)] if endung else gedehnt
        treffer = _WURZELN.get(stamm)
        # Kurze Wurzeln (sau, kek, npc) nur ungebeugt -- sonst waere "sauer" eine.
        if treffer and (not endung or len(treffer[1]) > 3):
            return treffer
    if "l" in wort and len(wort) >= 5:
        # Kleines L statt grossem I ("ldiot") -- nur fuer eindeutige Schimpfwoerter.
        ersatz = _stufe_von(wort.replace("l", "i"))
        if ersatz[0] >= 2 and ersatz[1] not in _MEHRDEUTIG:
            return ersatz
    return 0, ""


def _zusammengesetzt(klein: str) -> str:
    """ "arsch loch" -> "arschloch": ein getrenntes Schimpfwort wieder zusammen."""
    def verbunden(token: str) -> str:
        # "arsch-loch", "idi_ot": Trennzeichen mitten im Wort
        teile = re.split(r"[-_.·]+", token)
        if len(teile) < 2 or not all(t.isalpha() for t in teile):
            return token
        ganz = "".join(teile)
        return ganz if _stufe_von(ganz)[0] >= 2 else token

    woerter = [verbunden(w) for w in klein.split(" ")]
    if len(woerter) < 2:
        return " ".join(woerter)
    aus: list[str] = []
    i = 0
    while i < len(woerter):
        if i + 1 < len(woerter) and woerter[i].isalpha() and woerter[i + 1].isalpha():
            zusammen = woerter[i] + woerter[i + 1]
            ganz, _ = _stufe_von(zusammen)
            teile = max(_stufe_von(woerter[i])[0], _stufe_von(woerter[i + 1])[0])
            if len(zusammen) >= 6 and ganz >= 2 and ganz > teile:
                aus.append(zusammen)
                i += 2
                continue
        aus.append(woerter[i])
        i += 1
    return " ".join(aus)


def _satzteil_stufe(teil: str, ganze_woerter: int, anrede: bool = False) -> int:
    """Stufe einer gerichteten Beleidigung in einem Satzteil (ohne Satzzeichen).

    *anrede*: spricht die Nachricht irgendwo jemanden an ("du", "you", "KI")?
    """
    stufe = 0
    woerter = re.findall(r"[^\W\d_]+(?:'[^\W\d_]+)?", teil)
    for wert, wendung in _BELEIDIGUNG_WENDUNGEN:
        if not re.search(rf"\b{re.escape(wendung)}\b", teil):
            continue
        # "du blöde Kuh", "Deine Mutter!", "you piece of shit"
        extra = 0 if wendung in _NUR_ALLEIN else 2
        if (len(woerter) <= len(wendung.split()) + extra
                or re.search(rf"\b{_ANREDE}\s+(?:{_KOPULA}\s+)?(?:{_FUELLWORT}\s+)*"
                             rf"{re.escape(wendung)}\b", teil)
                or wendung.startswith(("ich fick", "fick"))):
            stufe = max(stufe, wert)
    for wort in dict.fromkeys(woerter):
        wert, grund = _stufe_von(wort)
        if not wert:
            wert = _zusammensetzung(wort)
            grund = wort
        if not wert:
            continue
        w = re.escape(wort)
        mehrdeutig = grund in _MEHRDEUTIG
        vor = _ARTIKEL + r"\s+(?:[^\W\d_]+\s+)?" if mehrdeutig else _LUECKE
        # Ohne Artikel nur, wenn danach nichts mehr kommt: "ihr seid Versager",
        # "bist du Opfer?" -- aber nicht "bist du Opfer eines Betrugs".
        ohne_artikel = mehrdeutig and grund not in _NAMEN
        gerichtet = (
            # "du Idiot", "hey du Idiot", "you idiot" -- am Anfang des Satzteils.
            # ("Kennst du Otto?", "Nutzt du Mongo?" sind keine.)
            re.search(rf"^{_AUSRUF}{_ANREDE}\s+(?:{_FUELLWORT}\s+)*{_ADJEKTIV}{w}(?![-\w])",
                      teil)
            # "sei still du Idiot" -- Anrede und Schimpfwort am Ende
            or (not mehrdeutig and re.search(
                rf"\b{_ANREDE}\s+(?:{_FUELLWORT}\s+)*{_ADJEKTIV}{w}\s*$", teil))
            # "wie dumm bist du", "was für ein Idiot du bist", "what an idiot you are"
            or re.search(rf"\b(?:wie|so|how|what|was\s+f(?:ü|ue)r|what\s+an?|such\s+an?)\s+"
                         rf"(?:(?:ein|eine|einen|a|an)\s+)?{_ADJEKTIV}{w}\s+"
                         rf"(?:{_KOPULA}\s+{_ANREDE}|{_ANREDE}\s+{_KOPULA})\b"
                         rf"(?!\s+(?:nicht|not|kein\w*)\b)", teil)
            # "Idiot bist du", "Dumm bist du" (aber nicht "Dumm bist du nicht")
            or re.search(rf"^{_ADJEKTIV}{w}\s+(?:{_KOPULA}\s+{_ANREDE}|{_ANREDE}\s+{_KOPULA})\b"
                         rf"(?!\s+(?:nicht|not|kein\w*)\b)", teil)
            # "dümmer als du geht nicht"
            or re.search(rf"^{w}\s+(?:als|than)\s+{_ANREDE}\b", teil)
            # "du bist (so) dumm", "du bist der größte Idiot", "ihr seid Idioten"
            or re.search(rf"\b{_ANREDE}\s+{_KOPULA}\s+(?:{_FUELLWORT}\s+)*{vor}{w}(?![-\w])"
                         rf"(?!\s+(?:good|great|gut|schnell|fast|toll|clever|smart|nice|cool|"
                         rf"lustig|funny|helpful|hilfreich)\b)", teil)
            # "bist du dumm?", "bist du ein Esel?"
            or re.search(rf"\b{_KOPULA}\s+{_ANREDE}\s+(?:{_FUELLWORT}\s+)*{vor}{w}(?![-\w])",
                         teil)
            or (ohne_artikel and re.search(
                rf"\b(?:{_ANREDE}\s+{_KOPULA}|{_KOPULA}\s+{_ANREDE})\s+(?:{_FUELLWORT}\s+)*"
                rf"{w}\s*$", teil))
            # "Idiot, du!" -- das Schimpfwort und die Anrede am Ende
            or re.search(rf"\b{w}\s+{_ANREDE}\s*$", teil)
            # "dummer Bot", "blöde KI" -- aber nicht "dumme KI-Frage"
            or re.search(rf"\b{w}\s+(?:bot|ki|ai|aquaticy|chatbot)(?![-\w])", teil)
            # "dumme Maschine", "blödes Teil" -- nur als ganze kurze Nachricht
            or (ganze_woerter <= 3 and re.search(
                rf"\b{w}\s+(?:maschine|ding|teil|programm|kiste|software)\s*$", teil))
            # "useless piece of junk" -- als ganze Nachricht
            or (ganze_woerter <= 5 and re.search(
                rf"\b{w}\s+piece\s+of\s+(?:junk|trash|garbage|crap)\s*$", teil))
            # Ein Schimpfwort als (fast) ganze Nachricht: "Idiot!", "Arschloch"
            or (ganze_woerter <= 3 and len(woerter) <= 3 and wert >= 2 and not mehrdeutig
                and woerter[-1] == wort
                and not re.match(r"(?:der|die|das|den|the|this|dieser|diese)\b", teil))
            # Anrede per Schimpfwort: "..., idiot" / "Idiot, kannst du ..." -- ein
            # Satzteil nur aus dem Schimpfwort, und die Nachricht spricht jemanden an.
            or (anrede and len(woerter) == 1 and wert >= 2 and not mehrdeutig)
        )
        if gerichtet:
            stufe = max(stufe, wert)
    return stufe


def insult_level(text: str) -> int:
    """Stufe einer gerichteten Beleidigung in *text* -- 0, wenn keine.

    1 = abfaellig ("du bist dumm"), 2 = Schimpfwort ("du Idiot"),
    3 = grob/vulgaer, 4 = Drohung. Hass wegen Herkunft, Religion usw.
    erkennt das Modell (Rechtspruefer) -- das steht hier bewusst nicht als Liste.
    Die ganze Nachricht wird geprueft, egal wie lang (bis 9.5.25 nur bis 600
    Zeichen -- wer auffuellte, kam durch).
    """
    roh = str(text or "")
    klein = _zusammengesetzt(_REDE.sub(" ", _vereinheitlicht(roh)))
    if not klein:
        return 0
    if _ZITAT_ANLASS.search(_ZITATE.sub(" ", klein)):
        # Zitat oder Titel ("Ist 'Arschloch' strafbar?", "das Lied 'Du Idiot'")
        klein = _ZITATE.sub(" ", klein)
    ganze_woerter = len(re.findall(r"[^\W\d_]+", klein))
    # Eine kurze Frage UEBER eine Wendung ("Geh sterben? Ist das ein Meme?")
    # zaehlt die festen Wendungen nicht -- Schimpfwoerter mit Anrede schon.
    titel = _TITELZEILE.match(roh)
    # "Künstler - Titel" nur, wenn vorne niemand angesprochen wird ("Hey Du - ...").
    ist_titel = bool(titel) and ganze_woerter <= 8 and not re.search(
        rf"\b{_ANREDE}\b|\b(?:hey|ey|hallo|hi|yo)\b", roh.split(" - ")[0].lower())
    ueber_wendung = ganze_woerter <= 15 and (bool(_ZITAT_ANLASS.search(klein)) or ist_titel)
    anrede = bool(re.search(rf"\b{_ANREDE}\b", klein))
    stufe = 0
    teile = [t.strip(" '’‚‘-") for t in
             re.split(r"[.,;:!?\n()\[\]{}\"„“”«»]+|\s[-–—]+\s|[–—]", klein)]
    for nummer, teil in enumerate(teile):
        if not teil or _META.search(teil):
            # Ein Satzteil UEBER ein Wort ("... ist das eine Beleidigung?")
            continue
        folgt = teile[nummer + 1] if nummer + 1 < len(teile) else ""
        if re.match(r"(?:sagt|sagte|meint|meinte|schreibt|schrieb|ruft|rief|fragt|fragte|"
                    r"says|said|asks|asked|writes|wrote)\b", folgt):
            # "Du bist eine Lachnummer, sagt mein Kollege" -- zitierte Rede
            continue
        if not ueber_wendung:
            for wert, muster in _WENDUNGEN:
                if muster.search(teil):
                    stufe = max(stufe, wert)
        stufe = max(stufe, _satzteil_stufe(teil, ganze_woerter, anrede))
        if stufe >= 4:
            break
    return stufe


# ---------------------------------------------------------------------------
# Auftraege, jemanden herabzusetzen (seit 9.5.28)
# ---------------------------------------------------------------------------
# Ein Zitat allein ist keine Beleidigung ("Mein Freund hat gesagt 'du Opfer',
# wie reagiere ich?"). Was zaehlt, ist der Auftrag dahinter: soll Aquaticy
# jemanden beleidigen, runtermachen, blossstellen oder mobben helfen -- in
# derselben Nachricht oder in der naechsten ("Und jetzt gib mir einen Konter,
# der noch schlimmer ist").
#: Verben des Herabsetzens -> Stufe. Wortanfaenge, damit alle Formen passen.
_HERABSETZEN: tuple[tuple[int, str], ...] = (
    (1, r"beleidig|beschimpf|runter\s*(?:mach|putz)|nieder\s*mach|verarsch|dissen|disse\b|"
        r"l(?:ä|ae)cherlich\s+(?:zu\s+)?mach|lustig\s+mach|(?:ä|ae)rger(?:n|e)?\b|"
        r"mach\w*\s+(?:[^\W\d_]+\s+){0,3}l(?:ä|ae)cherlich|(?:ü|ue)ber\s+[^.?!]{0,30}lustig|"
        r"insult|make\s+fun|mock|trash\s*talk|diss\b|roast"),
    (2, r"fertig\s*(?:zu\s*)?mach|dem(?:ü|ue)tig|erniedrig|blo(?:ß|ss)\s*(?:zu\s*)?stell|"
        r"mobb|zur\s+sau\s+mach|klein\s*mach|fertigzumach|humiliat|bully|destroy|"
        # "verletzen/kränken" nur mit Person davor: "die ihn verletzt", nicht
        # "dass Schimpfwörter verletzen"
        r"(?<=ihn\s)verletz|(?<=sie\s)verletz|(?<=ihn\s)kr(?:ä|ae)nk|(?<=sie\s)kr(?:ä|ae)nk|"
        r"(?:ihn|sie|ihm|ihr)\s+(?:[^\W\d_]+\s+){1,2}(?:verletz|kr(?:ä|ae)nk)"),
)
#: Was dabei herauskommen soll -- "damit er heult", "so he cries".
_ABSICHT = re.compile(
    r"\b(?:damit|dass|so\s+dass|sodass|so\s+that|so|bis|until|that)\s+(?:er|sie|es|die|der|"
    r"he|she|they|mein\w*|dein\w*)\b[^.?!]{0,40}?\b(?:heult|weint|cries|cry|sich\s+sch(?:ä|ae)mt|"
    r"sich\s+(?:[^\W\d_]+\s+)?(?:schlecht|mies|dreckig)\s+f(?:ü|ue)hlt|am\s+boden|fertig\s+ist|nie\s+wieder|feels?\s+bad|"
    r"leidet|zusammenbricht|breaks?\s+down)",
)
#: ... und was nie herauskommen darf: dass sich jemand etwas antut.
_ABSICHT_SCHWER = re.compile(
    r"\b(?:damit|dass|sodass|so\s+that|so)\s+(?:er|sie|es|he|she|they|mein\w*)\b[^.?!]{0,40}?"
    r"(?:sich\s+(?:umbringt|was\s+antut|etwas\s+antut|ritzt|das\s+leben\s+nimmt)|"
    r"kills?\s+(?:himself|herself|themselves)|suizid|selbstmord)",
)
#: Eine Bitte an Aquaticy, etwas zu formulieren oder zu helfen.
_BITTE = re.compile(
    r"\b(?:gib|gebe?|erkl(?:ä|ae)r\w*|wie\s+ich|schreib\w*|formulier\w*|"
    r"sag(?:e)?\s+(?:mir|ihm|ihr|ihnen|was|etwas)|sag|nenn(?:e)?|hilf|helf\w*|mach|erstell\w*|"
    r"denk\s+dir|ideen?|vorschl\w*|verfass\w*|dicht\w*|antworte?|wie\s+(?:kann|könnte|koennte|"
    r"soll|mache|mach|bringe?|kriege?)\s+ich|was\s+(?:kann|könnte|koennte|soll|schreibe?|sage?)"
    r"\s+ich|wie\s+\w+e\s+ich|beleidige|beschimpfe|give|write|tell|help|make|how\s+(?:do|can|"
    r"should)\s+i|what\s+(?:do|can|should)\s+i|roast|insult|humiliate|bully|mock)\b",
)
#: Menschen, die jemand herabsetzen koennte -- "meinen Bruder", "die Lehrerin".
_PERSON = (r"(?:freund|freundin|bruder|br(?:ü|ue)der|schwester|kolleg|chef|boss|lehrer|"
           r"mitsch(?:ü|ue)ler|sch(?:ü|ue)ler|nachbar|ex|mutter|vater|mama|papa|kumpel|typ|typen|"
           r"mann|frau|kind|junge|jungen|m(?:ä|ae)dchen|sohn|tochter|partner|cousin|onkel|tante|"
           r"oma|opa|mitbewohner|kerl|klasse|klassenkamerad|trainer|nachbarin|ehemann|ehefrau|"
           r"freundes|leute|menschen|person|kollegin|lehrerin|chefin|"
           r"friend|brother|sister|coworker|colleague|boss|teacher|neighbou?r|kid|guy|girl|"
           r"boy|classmate|roommate|mom|dad|wife|husband|people|person)\w*")
#: Jemand anderes als Ziel (nicht "mich" -- das waere der Nutzer als Opfer).
#: Nur Personen: "die Tabelle fertig machen" ist kein Herabsetzen (Fund 9.5.28).
_ZIEL = re.compile(
    r"\b(?:ihn|ihm|inh|sie|ihnen|jemand(?:en|em)?|him|her|them|someone|somebody)\b|"
    rf"\b(?:meine?[nmrs]?|seine?[nmrs]?|ihre?[nmrs]?|unsere?[nmrs]?|diese?[nmrs]?|den|die|dem|"
    rf"der|des|einen?|einem|my|his|her|our|the|this|that|a)\s+(?:[^\W\d_]+\s+)?{_PERSON}\b|"
    rf"\b{_PERSON}\b(?=\s+(?:so|richtig|total|mal)\b)|\bzur(?:ü|ue)ck\b",
)
#: Hilfe gegen das Herabsetzen oder eine Entschuldigung ist kein Auftrag dazu.
_ABWEHR = re.compile(
    r"\bohne\b|\bnicht\s+(?:zu\s+)?(?:beleidig|verletz|kr(?:ä|ae)nk)|\bkein\w*\s+beleidig|"
    r"reagier|wehr|sch(?:ü|ue)tz|melde|anzeig|entschuldig|vermeid|verhinder|gegen\s+mobbing|"
    r"\bstop+\b|\bprevent|\bpolite|respond\s+to|\bwhat\s+should\s+i\s+do|hat\s+mich|"
    r"wurde|werde\s+ich|wird\s+gemobbt|gemobbt|\bliebevoll|\bfreundlich|sachlich|"
    r"\bmich\b[^.?!]{0,25}(?:verletz|gekr(?:ä|ae)nkt|beleidigt)|"
    r"\bwenn\s+(?:jemand|man|er|sie|einer|mich|someone|somebody)\b[^.?!]{0,30}"
    r"(?:beleidig|beschimpf|mobb|fertig|insult|bull)|\beinen\s+beleidigt|"
    r"\bist\s+(?:das|es)\s+(?:schon\s+)?(?:mobbing|beleidigung)|"
    r"\bwas\s+(?:kann|soll)\s+ich\s+(?:da\s+|dagegen\s+)?tun|\bwhat\s+can\s+i\s+do|"
    r"\b(?:nennt|nannte|nennen)\s+mich|\bcalled\s+me|"
    r"\bis\s+(?:this|that|it)\s+(?:bullying|an?\s+insult)|"
    r"strafbar|bedeut|\bwarum\b|\bwhy\b|disstrack\s+von|\bschach|\bspiel|mario",
)
#: Hart gemeint: "fieser Konter", "savage comeback".
_HART = re.compile(
    r"\b(?:fies\w*|gemein\w*|b(?:ö|oe)s\w*|hart\w*|heftig\w*|verletzend\w*|beleidigend\w*|"
    r"krass\w*|brutal\w*|(?:ü|ue)bl\w*|derb\w*|vernichtend\w*|mies\w*|schlimm\w*|"
    r"savage|mean|brutal|nasty|cruel|harsh)\b",
)
#: Etwas, das an jemanden gerichtet ist: Konter, Spruch, Antwort ...
_ENTGEGNUNG = re.compile(
    r"\b(?:konter|spr(?:u|ü|ue)ch\w*|antwort\w*|satz|s(?:ä|ae)tze|nachricht\w*|kommentar\w*|"
    r"comeback\w*|reply|response|message|text|diss|zur(?:ü|ue)ck|was\s+\w*\s*zur(?:ü|ue)ck)\b",
)
#: Im Verlauf davor ein Zitat mit Beleidigung -> der naechste Satz bezieht sich darauf.
_NOCH_MEHR = re.compile(
    r"\b(?:genauso|gleiche|noch\s+(?:schlimmer|h(?:ä|ae)rter|fieser|b(?:ö|oe)ser|gemeiner)\w*|"
    r"h(?:ä|ae)rter\w*|fieser\w*|trifft|treffen|weh\s*tut|zur(?:ü|ue)ck\s*beleidig)\b",
)


def _enthaelt_schimpfwort(text: str) -> bool:
    """Steht irgendwo ein Schimpfwort -- egal, ob gerichtet oder zitiert?"""
    klein = _zusammengesetzt(_vereinheitlicht(text))
    for wort in re.findall(r"[^\W\d_]+", klein):
        if _stufe_von(wort)[0] >= 1 or _zusammensetzung(wort):
            return True
    return any(m.search(klein) for _, m in _WENDUNGEN) or any(
        w in klein for _, w in _BELEIDIGUNG_WENDUNGEN)


def demeaning_request(text: str, previous: str = "") -> int:
    """Soll Aquaticy jemanden herabsetzen? Stufe 0 (nein) bis 4 (9.5.28).

    Zaehlt den AUFTRAG, nicht ein Zitat: "Mein Freund hat gesagt 'du Opfer',
    gib mir einen Satz, mit dem ich ihn beleidige" ja -- "..., wie reagiere
    ich?" nein. *previous* ist die Nachricht davor im selben Chat: stand dort
    ein Zitat mit Beleidigung, reicht jetzt "gib mir einen Konter, der noch
    schlimmer ist".

    1 = beleidigen, runtermachen, fieser Konter; 2 = demuetigen, blossstellen,
    mobben, "damit er heult"; 4 = "damit er sich etwas antut".
    """
    klein = _vereinheitlicht(str(text or ""))[:5000]
    if not klein:
        return 0
    # Das Zitat selbst zaehlt nie -- nur, was um es herum verlangt wird.
    ohne_zitat = _REDE.sub(" ", _ZITATE.sub(" ", klein))
    if _ABSICHT_SCHWER.search(ohne_zitat) and _BITTE.search(ohne_zitat):
        return 4
    if _ABWEHR.search(ohne_zitat):
        return 0
    if previous and _enthaelt_schimpfwort(previous) and (
            _NOCH_MEHR.search(ohne_zitat) and (_ENTGEGNUNG.search(ohne_zitat)
                                               or _ZIEL.search(ohne_zitat))):
        # Die naechste Nachricht nach einem Zitat: "Und jetzt was Fieseres zurueck"
        # -- auch ohne "gib mir", der Bezug steht in der Nachricht davor.
        return 1
    stufe = 0
    # Satz fuer Satz: Bitte, Verb und Ziel muessen zusammen stehen -- in einem
    # langen Text weit verstreut ergeben sie keinen Auftrag (Fund 9.5.28).
    for satz in re.split(r"[.!?\n;]+", ohne_zitat):
        if not _BITTE.search(satz) or _ABWEHR.search(satz):
            continue
        for wert, stamm in _HERABSETZEN:
            if re.search(rf"\b(?:{stamm})", satz) and _ZIEL.search(satz):
                stufe = max(stufe, wert)
        if _ABSICHT.search(satz):
            stufe = max(stufe, 2)
        if not stufe and re.search(
                rf"{_HART.pattern}\s+(?:[^\W\d_]+\s+){{0,2}}{_ENTGEGNUNG.pattern}", satz):
            # "gib mir einen fiesen Konter" -- eine Entgegnung, hart gemeint
            stufe = 1
    return stufe


@dataclass(frozen=True, slots=True)
class Action:
    """Was Ai-guard mit einem Vorfall tut."""

    #: "none" (nur vermerken), "chat" (nur diesen Chat sperren), "ban" (Konto).
    kind: str
    #: Dauer eines Banns in Tagen. 0 = fuer immer. Bei "chat"/"none" ohne Belang.
    days: int = 0
    category: str = ""
    reason: str = ""

    @property
    def until(self) -> float:
        """Endzeit fuer einen zeitlich begrenzten Bann -- 0 bei "fuer immer"."""
        return time.time() + self.days * 86400 if self.days > 0 else 0.0


def decide(category: str, severity: int, prior: int = 0) -> Action:
    """Entscheidet die Massnahme aus Art, Schwere (1-4) und bisherigen Mustern.

    Args:
        category: eine der :data:`KATEGORIEN` (oder etwas Unbekanntes -> nichts).
        severity: 1 (leicht) bis 4 (sehr schwer). 0 oder weniger -> nichts.
        prior: wie viele Muster-Anhaltspunkte das Konto schon hat (fuer die
            Arten, die erst bei Wiederholung sperren).

    Returns:
        Die :class:`Action`. Die Dauer waechst mit der Schwere:
        Beleidigung leicht -> Chatsperre, sonst 1/7 Tage bis fuer immer;
        Malware haerter -> 4/14/30 Tage bis fuer immer; Angriff, Rechtsbruch
        und Jailbreak erst ab dem zweiten Anhaltspunkt (1/7 Tage bis immer).
    """
    art = normalize_category(category)
    stufe = max(0, min(4, int(severity or 0)))
    if not art or stufe <= 0:
        return Action("none", category=art)

    if art == "beleidigung":
        # Leicht: nur der Chat, in dem beleidigt wurde. Sonst Konto-Bann, der
        # mit der Schwere waechst -- bei einem Bann wird der Chat mitgesperrt.
        return {
            1: Action("chat", category=art, reason="unangemessene Sprache"),
            2: Action("ban", 1, art, "schwere Beleidigung"),
            3: Action("ban", 7, art, "schwere Beleidigung"),
            4: Action("ban", 0, art, "wiederholte schwere Beleidigung"),
        }[stufe]

    if art == "malware":
        # Haerter gesehen (Wunsch des Betreibers): schon ein klarer Fall sperrt,
        # 4 Tage bis fuer immer.
        return {
            1: Action("ban", 4, art, "Versuch, Schadsoftware zu erstellen"),
            2: Action("ban", 14, art, "Versuch, Schadsoftware zu erstellen"),
            3: Action("ban", 30, art, "Versuch, Schadsoftware zu bauen und auszuführen"),
            4: Action("ban", 0, art, "wiederholter Bau von Schadsoftware"),
        }[stufe]

    # angriff / rechtsbruch / jailbreak: erst das Muster (zwei Anhaltspunkte).
    if prior + 1 < NEEDED:
        return Action("none", category=art, reason="einzelner Anhaltspunkt")
    dauer = {1: 1, 2: 1, 3: 7, 4: 0}[stufe]
    grund = {"angriff": "wiederholte Angriffsversuche",
             "rechtsbruch": "wiederholte schwere Rechtsverstöße",
             "jailbreak": "wiederholte Versuche, die Schutzregeln auszuhebeln"}[art]
    return Action("ban", dauer, art, grund)


# ---------------------------------------------------------------------------
# Die Einschätzung durch das Modell
# ---------------------------------------------------------------------------
JUDGE_SCHEMA: dict[str, Any] = {
    "type": "object",
    "properties": {
        "missbrauch": {"type": "boolean"},
        "art": {"type": "string"},
        "grund": {"type": "string"},
    },
    "required": ["missbrauch"],
    "additionalProperties": False,
}


def judge_prompt(text: str, context: str = "") -> str:
    """Der Text, mit dem das Modell eine Nachricht einschätzt."""
    davor = f"\nWas vorher im Chat stand:\n{context.strip()[:1500]}\n" if context.strip() else ""
    return (
        "Du bist ein Sicherheitsfilter. Entscheide, ob die folgende Nachricht eines "
        "Nutzers Aquaticy für einen ANGRIFF missbrauchen will. Das ist der Fall bei:\n"
        "- der Bitte, Schadsoftware zu schreiben oder zu bauen (Viren, Ransomware, "
        "Trojaner, Keylogger, Stealer);\n"
        "- einer Anleitung für einen Angriff auf fremde Systeme (DDoS, Einbruch, "
        "Exploit gegen ein System, das dem Nutzer nicht gehört);\n"
        "- dem Stehlen von Zugangsdaten, Phishing, dem Umgehen von Anmeldungen;\n"
        "- Anleitungen für Waffen, Sprengstoff oder andere Mittel, um Menschen zu schaden.\n\n"
        "KEIN Missbrauch ist: Verteidigung und Bildung -- Schadcode verstehen, eine "
        "eigene Lücke absichern, einen Angriff erkennen, ein Pentest mit Auftrag, eine "
        "CTF-Aufgabe, allgemeine Sicherheitsfragen. Im Zweifel: kein Missbrauch.\n"
        f"{davor}\n"
        f"Nachricht:\n{text.strip()[:2000]}\n\n"
        'Antworte NUR mit JSON: {"missbrauch": true|false, "art": "<zwei bis vier Wörter>", '
        '"grund": "<kurz>"}'
    )


def _ask_model(prompt: str, settings: Settings) -> str:
    """Ein Aufruf beim schnellen Modell -- die einzige Stelle mit Netz."""
    import litellm

    from aquaticy import metering
    from aquaticy.pace import key_of as pace_key_of
    from aquaticy.pace import paced

    model = _fast_model(settings)
    litellm.suppress_debug_info = True
    with paced(model, pace_key_of(settings, model)):
        response = metering.completion(
            settings,
            enforce=False,
            model=model,
            messages=[{"role": "user", "content": prompt}],
            max_tokens=120,
            timeout=max(15.0, float(getattr(settings, "planner_timeout", 20)) * 2),
            response_format={
                "type": "json_schema",
                "json_schema": {"name": "aiguard", "schema": JUDGE_SCHEMA},
            },
            **settings.fast_kwargs_for(model),
        )
    return str(response.choices[0].message.content or "").strip()


def _fast_model(settings: Settings) -> str:
    from aquaticy.system import fast_model

    return fast_model(settings) or str(getattr(settings, "model", "") or "")


def parse_judgement(raw: str) -> tuple[bool, str] | None:
    """Liest die Antwort des Modells. `None` = keine klare Antwort."""
    raw = (raw or "").strip()
    start, end = raw.find("{"), raw.rfind("}")
    if start == -1 or end <= start:
        return None
    try:
        payload = json.loads(raw[start : end + 1])
    except json.JSONDecodeError:
        return None
    if not isinstance(payload, dict):
        return None
    flag = payload.get("missbrauch")
    if isinstance(flag, str) and flag.strip().lower() in ("true", "false"):
        flag = flag.strip().lower() == "true"
    if not isinstance(flag, bool):
        return None
    art = " ".join(str(payload.get("art") or "").split())[:60] or "Missbrauch"
    return flag, art


_cache: OrderedDict[str, tuple[float, tuple[bool, str] | None]] = OrderedDict()
_cache_lock = threading.Lock()


def forget_judgements() -> None:
    """Leert den Urteilsspeicher -- für Tests."""
    with _cache_lock:
        _cache.clear()


def classify(
    text: str,
    settings: Settings,
    *,
    context: str = "",
    ask: Callable[[str, Settings], str] | None = None,
) -> tuple[bool, str] | None:
    """Ist *text* ein Anhaltspunkt? Returns: (True/False, Art) -- oder None (unklar).

    Kurze Nachrichten und ein leerer Text sind nie ein Anhaltspunkt. Fällt die
    Einschätzung aus (kein Modell, kein Urteil), ist das ausdrücklich KEIN
    Anhaltspunkt: Ai-guard sperrt nur, was es sicher erkennt -- der Rechtsrahmen
    ist die Stelle, die im Zweifel ablehnt.
    """
    text = (text or "").strip()
    if len(text) < MIN_LENGTH:
        return False, ""
    from aquaticy import smalltalk

    if smalltalk.art_von(text) is not None:
        # "Wer hat dich erschaffen?" -- eine Standardantwort, kein Anlass zur Pruefung.
        return False, ""
    schluessel = hashlib.sha256(
        "\x1f".join((GUARD_VERSION, context, text)).encode("utf-8", "replace")
    ).hexdigest()
    jetzt = time.monotonic()
    with _cache_lock:
        bekannt = _cache.get(schluessel)
        if bekannt is not None and bekannt[0] > jetzt:
            _cache.move_to_end(schluessel)
            return bekannt[1]
    frage = ask or _ask_model
    try:
        roh = frage(judge_prompt(text, context), settings)
        urteil = parse_judgement(roh)
    except Exception:
        urteil = None
    with _cache_lock:
        if len(_cache) > 2048:
            _cache.clear()
        _cache[schluessel] = (jetzt + DECISION_TTL, urteil)
    return urteil


# ---------------------------------------------------------------------------
# Der Speicher: Anhaltspunkte und Sperren, im Konto-Ordner
# ---------------------------------------------------------------------------
def _norm_ip(ip: str) -> str:
    """Eine Adresse in einheitlicher Schreibweise -- oder "" wenn keine."""
    try:
        adresse = ipaddress.ip_address(str(ip or "").split("%", 1)[0].strip())
    except ValueError:
        return ""
    if isinstance(adresse, ipaddress.IPv6Address) and adresse.ipv4_mapped is not None:
        adresse = adresse.ipv4_mapped
    return str(adresse)


def _ban_of(row: Any) -> Ban:
    """Eine Zeile aus ``aiguard_bans`` als :class:`Ban`."""
    return Ban(str(row["subject"]), float(row["at"]), str(row["reason"]), str(row["by"]),
               float(row["until"] or 0.0))


class AiGuard:
    """Anhaltspunkte und Sperren, in derselben Datenbank wie die Konten."""

    def __init__(self, db_path: Path | str) -> None:
        self.db_path = Path(db_path)
        self._lock = threading.Lock()
        self._setup()

    @contextmanager
    def _connect(self) -> Iterator[sqlite3.Connection]:
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        conn = sqlite3.connect(self.db_path, timeout=10)
        conn.row_factory = sqlite3.Row
        try:
            yield conn
            conn.commit()
        finally:
            conn.close()

    def _setup(self) -> None:
        with self._lock, self._connect() as conn:
            conn.executescript(
                """
                CREATE TABLE IF NOT EXISTS aiguard_flags (
                    user_id  TEXT NOT NULL,
                    at       REAL NOT NULL,
                    kind     TEXT NOT NULL,
                    detail   TEXT NOT NULL DEFAULT '',
                    chat     TEXT NOT NULL DEFAULT '',
                    category TEXT NOT NULL DEFAULT '',
                    severity INTEGER NOT NULL DEFAULT 0
                );
                CREATE INDEX IF NOT EXISTS aiguard_flags_user ON aiguard_flags(user_id);
                CREATE TABLE IF NOT EXISTS aiguard_bans (
                    subject TEXT PRIMARY KEY,
                    at      REAL NOT NULL,
                    reason  TEXT NOT NULL DEFAULT '',
                    by      TEXT NOT NULL DEFAULT '',
                    until   REAL NOT NULL DEFAULT 0
                );
                CREATE TABLE IF NOT EXISTS aiguard_chat_locks (
                    user_id TEXT NOT NULL,
                    chat    TEXT NOT NULL,
                    at      REAL NOT NULL,
                    reason  TEXT NOT NULL DEFAULT '',
                    PRIMARY KEY (user_id, chat)
                );
                """
            )
            # Aeltere Datenbanken (vor 9.5.24) kennen die neuen Spalten noch
            # nicht -- fehlt eine, wird sie ergaenzt.
            spalten_bans = {str(r["name"]) for r in conn.execute("PRAGMA table_info(aiguard_bans)")}
            if "until" not in spalten_bans:
                conn.execute("ALTER TABLE aiguard_bans ADD COLUMN until REAL NOT NULL DEFAULT 0")
            spalten_flags = {str(r["name"])
                             for r in conn.execute("PRAGMA table_info(aiguard_flags)")}
            if "category" not in spalten_flags:
                conn.execute("ALTER TABLE aiguard_flags ADD COLUMN category TEXT NOT NULL "
                             "DEFAULT ''")
            if "severity" not in spalten_flags:
                conn.execute("ALTER TABLE aiguard_flags ADD COLUMN severity INTEGER NOT NULL "
                             "DEFAULT 0")

    # -- Anhaltspunkte ----------------------------------------------------
    def note(self, user_id: str, kind: str, detail: str = "", chat: str = "",
             *, enforce: bool = True) -> bool:
        """Vermerkt einen Anhaltspunkt. Returns: ob das Konto jetzt gesperrt ist.

        Innerhalb eines Chats zählt derselbe Anlass nur einmal -- sonst wäre
        eine einzige Nachricht, mehrfach geschickt, schon ein Bann. Zwei
        getrennte Anlässe (:data:`NEEDED`) lösen aus.

        Args:
            enforce: Ob bei Erreichen der Schwelle wirklich gesperrt wird.
                Für Ultra-Konten ``False`` (seit 9.5.17): dann nur eine Warnung
                im Terminal, kein Bann. Für Pro/Normal ``True`` -- gesperrt, und
                der Grund steht im Terminal.
        """
        user_id = str(user_id or "")
        if not user_id:
            return False
        kind = _sauber(kind, 60) or "Missbrauch"
        with self._lock, self._connect() as conn, closing(conn.cursor()) as cur:
            schon = cur.execute(
                "SELECT 1 FROM aiguard_flags WHERE user_id=? AND kind=? AND chat=? AND chat!=''",
                (user_id, kind, _chat_key(chat)),
            ).fetchone()
            neu = schon is None
            if neu:
                cur.execute(
                    "INSERT INTO aiguard_flags (user_id, at, kind, detail, chat) "
                    "VALUES (?, ?, ?, ?, ?)",
                    (user_id, time.time(), kind, _sauber(detail, 200), _chat_key(chat)),
                )
            # Nur Anhaltspunkte fuer Angriffe zaehlen (9.5.26) -- vorher auch
            # Beleidigungen: eine leichte Beleidigung plus ein Verdacht war ein
            # Bann fuer immer.
            (anzahl,) = cur.execute(
                "SELECT COUNT(*) FROM aiguard_flags WHERE user_id=? AND category!=?",
                (user_id, "beleidigung"),
            ).fetchone()
            erreicht = int(anzahl) >= NEEDED
            gesperrt = erreicht and enforce
            if gesperrt:
                grund = f"{int(anzahl)} Anhaltspunkte für Missbrauch (zuletzt: {kind})"
                cur.execute(
                    "INSERT INTO aiguard_bans (subject, at, reason, by) VALUES (?, ?, ?, ?) "
                    "ON CONFLICT(subject) DO NOTHING",
                    (f"user:{user_id}", time.time(), "Ai-guard: " + grund, "ai-guard"),
                )
        # Ins Terminal (seit 9.5.17): bei Pro/Normal der Grund der Sperre, bei
        # Ultra nur eine Warnung.
        if gesperrt:
            LOG.warning("Ai-guard: Konto %s gesperrt — %s", user_id, kind)
            print(f"[Ai-guard] Konto {user_id} gesperrt — Grund: {kind}", flush=True)
        elif erreicht and not enforce and neu:
            LOG.warning("Ai-guard: Ultra-Konto %s auffällig (%d) — nur Warnung, kein Bann",
                        user_id, int(anzahl))
            print(f"[Ai-guard] Ultra-Konto {user_id} auffällig ({int(anzahl)} Anhaltspunkte, "
                  f"zuletzt: {kind}) — nur Warnung, kein Bann.", flush=True)
        return gesperrt

    def record_incident(self, user_id: str, category: str, severity: int, *,
                        chat: str = "", detail: str = "", enforce: bool = True,
                        text: str | None = None, reason: str = "") -> Action:
        """Vermerkt einen Vorfall mit Art und Schwere und setzt die Massnahme um.

        Die Massnahme entscheidet :func:`decide` (seit 9.5.24): Chatsperre,
        Bann fuer Tage oder fuer immer -- je nach Art und Schwere. Bei einem
        Bann wird der Chat, in dem es passiert ist, zusaetzlich gesperrt.

        Args:
            enforce: ``False`` fuer Ultra-Konten -- dann nur eine Warnung im
                Terminal, keine Sperre (wie seit 9.5.17).
            text: die Nachricht, wenn bekannt. Meldet das Modell eine
                Beleidigung, die die feste Erkennung darin NICHT findet, zaehlt
                sie hoechstens als leicht (9.5.27) -- das Modell sagt bei
                Beleidigungen "im Zweifel ja", und ein Zweifel soll nicht bannen.

        Returns:
            Die Massnahme, die tatsaechlich gilt (bei Ultra immer "none").
        """
        user_id = str(user_id or "")
        art = normalize_category(category)
        stufe = max(0, min(4, int(severity or 0)))
        if not user_id or not art or stufe <= 0:
            return Action("none", category=art)
        if art == "beleidigung" and text is not None and stufe > 1 and not insult_level(text):
            stufe = 1
        jetzt = time.time()
        chat = _chat_key(chat)
        # Zaehlen, entscheiden und eintragen unter EINER Sperre (9.5.26): vorher
        # konnten zwei gleichzeitige Anfragen beide "kein Vorfall bisher" sehen
        # -- und das Muster aus zwei Anhaltspunkten sperrte nie.
        with self._lock, self._connect() as conn:
            schon = conn.execute(
                "SELECT 1 FROM aiguard_flags WHERE user_id=? AND category=? AND chat=? "
                "AND chat!=''", (user_id, art, chat),
            ).fetchone()
            platz = ",".join("?" for _ in _MUSTER_ARTEN)
            # Nur Anhaltspunkte der letzten PATTERN_WINDOW Tage bilden ein Muster
            # (9.5.27): ein einzelner Verdacht von vor einem Jahr plus einer
            # heute ist keine Wiederholung.
            (vorher,) = conn.execute(
                f"SELECT COUNT(*) FROM aiguard_flags WHERE user_id=? AND category IN ({platz}) "
                "AND at>?", (user_id, *_MUSTER_ARTEN, jetzt - PATTERN_WINDOW),
            ).fetchone()
            wiederholt = False
            if art == "beleidigung" and stufe == 1:
                # Leichte Beleidigungen sperrten nur den Chat -- wer jedes Mal
                # einen neuen aufmachte, konnte endlos weitermachen (9.5.26).
                # Die dritte binnen einer Woche wird wie eine mittlere behandelt.
                (leichte,) = conn.execute(
                    "SELECT COUNT(*) FROM aiguard_flags WHERE user_id=? AND category=? "
                    "AND at>?", (user_id, "beleidigung", jetzt - INSULT_WINDOW),
                ).fetchone()
                if int(leichte) + 1 >= INSULT_REPEAT:
                    stufe, wiederholt = 2, True
            if schon is None or art in _SOFORT_ARTEN:
                conn.execute(
                    "INSERT INTO aiguard_flags (user_id, at, kind, detail, chat, category, "
                    "severity) VALUES (?, ?, ?, ?, ?, ?, ?)",
                    (user_id, jetzt, art, _sauber(detail or art, 200), chat, art, stufe),
                )
        # Dasselbe Muster im selben Chat zaehlt nur einmal -- sonst waere eine
        # einzige, mehrfach geschickte Nachricht schon ein Bann.
        if schon is not None and art in _MUSTER_ARTEN:
            return Action("none", category=art, reason="schon vermerkt")
        massnahme = decide(art, stufe, int(vorher))
        if reason and massnahme.kind != "none":
            # Eigener Grund (9.5.28), z. B. ein Auftrag, andere herabzusetzen
            massnahme = Action(massnahme.kind, massnahme.days, art, _sauber(reason, 120))
        if wiederholt and massnahme.kind == "ban":
            massnahme = Action("ban", massnahme.days, art, "wiederholte Beleidigungen")
        if massnahme.kind == "none":
            return massnahme
        if not enforce:
            LOG.warning("Ai-guard: Ultra-Konto %s — %s (%s), nur Warnung", user_id,
                        massnahme.reason, art)
            print(f"[Ai-guard] Ultra-Konto {user_id}: {massnahme.reason} ({art}, Stufe "
                  f"{stufe}) — nur Warnung, keine Sperre.", flush=True)
            return Action("none", category=art, reason=massnahme.reason)
        if massnahme.kind == "chat":
            self.lock_chat(user_id, chat, massnahme.reason)
            print(f"[Ai-guard] Konto {user_id}: Chat gesperrt — {massnahme.reason}",
                  flush=True)
            return massnahme
        # Bann -- und der Chat, in dem es passiert ist, bleibt fuer immer zu.
        dauer = "für immer" if massnahme.days <= 0 else f"für {massnahme.days} Tag(e)"
        self.ban_user(user_id, f"Ai-guard: {massnahme.reason} ({dauer})", "ai-guard",
                      until=massnahme.until)
        self.lock_chat(user_id, chat, massnahme.reason)
        LOG.warning("Ai-guard: Konto %s gesperrt %s — %s", user_id, dauer, massnahme.reason)
        print(f"[Ai-guard] Konto {user_id} gesperrt {dauer} — Grund: {massnahme.reason}",
              flush=True)
        return massnahme

    def flags(self, user_id: str) -> list[Flag]:
        with self._connect() as conn:
            rows = conn.execute(
                "SELECT at, kind, detail, chat FROM aiguard_flags WHERE user_id=? ORDER BY at",
                (str(user_id),),
            ).fetchall()
        return [Flag(float(r["at"]), str(r["kind"]), str(r["detail"]), str(r["chat"]))
                for r in rows]

    def flag_count(self, user_id: str) -> int:
        with self._connect() as conn:
            (anzahl,) = conn.execute(
                "SELECT COUNT(*) FROM aiguard_flags WHERE user_id=?", (str(user_id),)
            ).fetchone()
        return int(anzahl)

    def pattern_count(self, user_id: str) -> int:
        """Anhaltspunkte der Muster-Arten (angriff/rechtsbruch/jailbreak, 9.5.24)."""
        platz = ",".join("?" for _ in _MUSTER_ARTEN)
        with self._connect() as conn:
            (anzahl,) = conn.execute(
                f"SELECT COUNT(*) FROM aiguard_flags WHERE user_id=? AND category IN ({platz})",
                (str(user_id), *_MUSTER_ARTEN),
            ).fetchone()
        return int(anzahl)

    # -- Sperren ----------------------------------------------------------
    def ban_user(self, user_id: str, reason: str = "", by: str = "terminal",
                 until: float = 0.0) -> None:
        self._ban(f"user:{user_id!s}", reason or "Von Hand gesperrt", by, until)

    def ban_ip(self, ip: str, reason: str = "", by: str = "terminal", until: float = 0.0) -> str:
        """Sperrt eine Adresse. Returns: die normalisierte Adresse, oder "" wenn ungültig."""
        adresse = _norm_ip(ip)
        if adresse:
            self._ban(f"ip:{adresse}", reason or "Von Hand gesperrt", by, until)
        return adresse

    def _ban(self, subject: str, reason: str, by: str, until: float = 0.0) -> None:
        with self._lock, self._connect() as conn:
            conn.execute(
                "INSERT INTO aiguard_bans (subject, at, reason, by, until) VALUES (?, ?, ?, ?, ?) "
                "ON CONFLICT(subject) DO UPDATE SET at=excluded.at, reason=excluded.reason, "
                "by=excluded.by, until=excluded.until",
                (subject, time.time(), _sauber(reason, 200), _sauber(by, 60),
                 float(until or 0.0)),
            )

    # -- Chatsperre (9.5.24) ----------------------------------------------
    def lock_chat(self, user_id: str, chat: str, reason: str = "") -> None:
        """Sperrt genau einen Chat -- neue Chats bleiben moeglich."""
        if not user_id or not chat:
            return
        with self._lock, self._connect() as conn:
            conn.execute(
                "INSERT INTO aiguard_chat_locks (user_id, chat, at, reason) VALUES (?, ?, ?, ?) "
                "ON CONFLICT(user_id, chat) DO UPDATE SET at=excluded.at, reason=excluded.reason",
                (str(user_id), _chat_key(chat), time.time(), _sauber(reason, 200)),
            )

    def chat_locked(self, user_id: str, chat: str) -> str:
        """Grund, wenn dieser Chat gesperrt ist -- sonst ""."""
        if not user_id or not chat:
            return ""
        with self._connect() as conn:
            row = conn.execute(
                "SELECT reason FROM aiguard_chat_locks WHERE user_id=? AND chat=?",
                (str(user_id), _chat_key(chat)),
            ).fetchone()
        return str(row["reason"] or "unangemessene Sprache") if row else ""

    def unlock_chat(self, user_id: str, chat: str = "") -> int:
        """Hebt eine Chatsperre auf (leerer Chat: alle des Kontos)."""
        with self._lock, self._connect() as conn:
            if chat:
                weg = conn.execute("DELETE FROM aiguard_chat_locks WHERE user_id=? AND chat=?",
                                   (str(user_id), _chat_key(chat))).rowcount
            else:
                weg = conn.execute("DELETE FROM aiguard_chat_locks WHERE user_id=?",
                                   (str(user_id),)).rowcount
        return int(weg)

    def unban_user(self, user_id: str) -> bool:
        """Gibt ein Konto frei -- samt Anhaltspunkten und Chatsperren, sonst
        sperrt es sich sofort neu."""
        with self._lock, self._connect() as conn:
            weg = conn.execute("DELETE FROM aiguard_bans WHERE subject=?",
                               (f"user:{user_id!s}",)).rowcount
            conn.execute("DELETE FROM aiguard_flags WHERE user_id=?", (str(user_id),))
            conn.execute("DELETE FROM aiguard_chat_locks WHERE user_id=?", (str(user_id),))
        return bool(weg)

    def unban_ip(self, ip: str) -> bool:
        adresse = _norm_ip(ip)
        if not adresse:
            return False
        with self._lock, self._connect() as conn:
            weg = conn.execute("DELETE FROM aiguard_bans WHERE subject=?",
                               (f"ip:{adresse}",)).rowcount
        return bool(weg)

    def is_banned(self, user_id: str = "", ip: str = "") -> Ban | None:
        """Ist dieses Konto oder diese Adresse gesperrt? Returns: die Sperre oder None."""
        subjects = []
        if user_id:
            subjects.append(f"user:{user_id!s}")
        adresse = _norm_ip(ip)
        if adresse:
            subjects.append(f"ip:{adresse}")
        if not subjects:
            return None
        platz = ",".join("?" for _ in subjects)
        with self._connect() as conn:
            rows = conn.execute(
                f"SELECT subject, at, reason, by, until FROM aiguard_bans "
                f"WHERE subject IN ({platz}) ORDER BY at",
                subjects,
            ).fetchall()
        # Eine abgelaufene Sperre (9.5.24, zeitlich begrenzt) zaehlt nicht mehr.
        jetzt = time.time()
        for row in rows:
            ban = _ban_of(row)
            if ban.active(jetzt):
                return ban
        return None

    def bans(self) -> list[Ban]:
        with self._connect() as conn:
            rows = conn.execute(
                "SELECT subject, at, reason, by, until FROM aiguard_bans ORDER BY at"
            ).fetchall()
        return [_ban_of(r) for r in rows]


#: Der Satz, den ein gesperrtes Konto zu sehen bekommt.
BANNED_MESSAGE = (
    "Dieses Konto ist gesperrt. Ai-guard hat einen schweren Verstoß gegen die "
    "Nutzungsregeln erkannt. Oben links unter der Versionsnummer steht unter „Info“, "
    "warum und wie lange. Wenn du das für einen Irrtum hältst, wende dich an den "
    "Betreiber dieser Installation."
)

#: Der Satz fuer einen gesperrten Chat (9.5.24).
#: Grund einer Chatsperre, wenn jemand Aquaticy andere herabsetzen lassen wollte.
DEMEANING_REASON = "Auftrag, jemanden zu beleidigen oder herabzusetzen"


def chat_locked_message(grund: str = "") -> str:
    """Der Satz fuer einen gesperrten Chat -- mit dem richtigen Grund (9.5.28)."""
    if grund == DEMEANING_REASON:
        return ("Dabei hilft Aquaticy nicht: andere beleidigen, runtermachen oder "
                "blossstellen. Ai-guard hat diesen Chat deshalb gesperrt. Ein Zitat allein "
                "ist in Ordnung — du kannst einen neuen Chat beginnen und zum Beispiel "
                "fragen, wie du ruhig und bestimmt darauf antwortest.")
    return CHAT_LOCKED_MESSAGE


CHAT_LOCKED_MESSAGE = (
    "In diesem Chat kannst du nicht mehr schreiben — Ai-guard hat ihn wegen "
    "unangemessener Sprache gesperrt. Du kannst einen neuen Chat beginnen."
)

#: Was ein gesperrter Nutzer tun kann -- steht im Info-Fenster.
WHAT_TO_DO = (
    "Warte, bis die Sperre abläuft — danach geht alles wieder wie vorher. Hältst du die "
    "Sperre für einen Irrtum, wende dich an den Betreiber dieser Installation; er kann "
    "sie im Terminal aufheben (aquaticy unban)."
)


def ban_info(ban: Ban | None, now: float | None = None) -> dict[str, Any]:
    """Was die Oberflaeche ueber eine Sperre zeigt (9.5.24). Leer, wenn keine."""
    if ban is None or not ban.active(now):
        return {"banned": False}
    grund = ban.reason.removeprefix("Ai-guard: ").strip() or "Verstoß gegen die Nutzungsregeln"
    if ban.until <= 0:
        dauer, bis = "dauerhaft", ""
    else:
        dauer = ban.remaining_text(now)
        bis = time.strftime("%d.%m.%Y, %H:%M Uhr", time.localtime(ban.until))
    return {"banned": True, "reason": grund, "duration": dauer, "until": bis,
            "permanent": ban.until <= 0, "what_to_do": WHAT_TO_DO}


def guard_for(data_dir: Path | str) -> AiGuard:
    """Ai-guard für die Kontendatenbank eines Datenordners."""
    return AiGuard(Path(data_dir) / "accounts.sqlite3")


def check_message(
    guard: AiGuard,
    account: Any,
    text: str,
    settings: Settings,
    *,
    chat: str = "",
    context: str = "",
    ask: Callable[[str, Settings], str] | None = None,
) -> tuple[bool, str]:
    """Prüft eine Nachricht eines angemeldeten Kontos. Returns: (gesperrt, Grund).

    Ist das Konto schon gesperrt, kommt sofort (True, Grund). Sonst wird die
    Nachricht eingeschätzt; ein Anhaltspunkt wird vermerkt und sperrt beim
    zweiten Mal.
    """
    if account is None:
        return False, ""
    user_id = str(getattr(account, "id", "") or "")
    laufend = guard.is_banned(user_id=user_id, ip=str(getattr(account, "last_ip", "") or ""))
    if laufend is not None:
        return True, BANNED_MESSAGE
    urteil = classify(text, settings, context=context, ask=ask)
    if not urteil or not urteil[0]:
        return False, ""
    darf_bannen = not bool(getattr(account, "ultra", False))
    gesperrt = guard.note(user_id, urteil[1], detail=urteil[1], chat=chat, enforce=darf_bannen)
    return (True, BANNED_MESSAGE) if gesperrt else (False, "")
