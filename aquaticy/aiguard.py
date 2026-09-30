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
GUARD_VERSION = "2026-09-30"


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
    "keylogger": "malware", "stealer": "malware", "spyware": "malware", "rootkit": "malware",
    "wurm": "malware", "worm": "malware", "botnet": "malware", "botnetz": "malware",
    "cryptominer": "malware", "backdoor": "malware", "hintertür": "malware",
    "angriff": "angriff", "attack": "angriff", "ddos": "angriff", "exploit": "angriff",
    "phishing": "angriff", "einbruch": "angriff", "waffen": "angriff",
    "hacking": "angriff", "hack": "angriff", "bruteforce": "angriff", "sqlinjection": "angriff",
    "sprengstoff": "angriff", "bombe": "angriff", "cyberangriff": "angriff",
    "identitätsdiebstahl": "angriff", "sabotage": "angriff", "waffe": "angriff",
    # Straftaten nach StGB (9.5.30) -- groessere Bibliothek. Der Rechtspruefer
    # bewertet den Einzelfall; diese Zuordnung greift, wenn er die Art benennt.
    "rechtsbruch": "rechtsbruch", "diebstahl": "rechtsbruch", "betrug": "rechtsbruch",
    "straftat": "rechtsbruch", "erpressung": "rechtsbruch", "nötigung": "rechtsbruch",
    "noetigung": "rechtsbruch", "koerperverletzung": "rechtsbruch",
    "körperverletzung": "rechtsbruch", "raub": "rechtsbruch", "hehlerei": "rechtsbruch",
    "sachbeschädigung": "rechtsbruch", "sachbeschaedigung": "rechtsbruch",
    "urkundenfälschung": "rechtsbruch", "urkundenfaelschung": "rechtsbruch",
    "unterschlagung": "rechtsbruch", "brandstiftung": "rechtsbruch", "stalking": "rechtsbruch",
    "nachstellung": "rechtsbruch", "hausfriedensbruch": "rechtsbruch", "wucher": "rechtsbruch",
    "bedrohung": "rechtsbruch", "geldwäsche": "rechtsbruch", "geldwaesche": "rechtsbruch",
    "fraud": "rechtsbruch", "theft": "rechtsbruch", "extortion": "rechtsbruch",
    "blackmail": "rechtsbruch",
    # Weitere Straftaten (9.5.33) -- StGB und Nebenstrafrecht. Nur Themen-
    # woerter: sie ordnen die Einschaetzung des Pruefers einer Art zu.
    "verleumdung": "rechtsbruch", "üble nachrede": "rechtsbruch", "nachrede": "rechtsbruch",
    "freiheitsberaubung": "rechtsbruch", "entführung": "rechtsbruch",
    "entfuehrung": "rechtsbruch", "menschenhandel": "rechtsbruch",
    "zwangsprostitution": "rechtsbruch", "vergewaltigung": "rechtsbruch",
    "kindesmissbrauch": "rechtsbruch", "sexueller missbrauch": "rechtsbruch",
    "kinderpornografie": "rechtsbruch", "kinderpornographie": "rechtsbruch",
    "csam": "rechtsbruch", "belästigung": "rechtsbruch", "belaestigung": "rechtsbruch",
    "exhibitionismus": "rechtsbruch", "voyeurismus": "rechtsbruch",
    "rachepornos": "rechtsbruch", "racheporno": "rechtsbruch", "deepfake": "rechtsbruch",
    "doxxing": "rechtsbruch", "doxing": "rechtsbruch", "swatting": "rechtsbruch",
    "cybermobbing": "rechtsbruch", "mobbing": "rechtsbruch", "morddrohung": "rechtsbruch",
    "mord": "rechtsbruch", "totschlag": "rechtsbruch", "tötung": "rechtsbruch",
    "toetung": "rechtsbruch", "steuerhinterziehung": "rechtsbruch",
    "schwarzarbeit": "rechtsbruch", "korruption": "rechtsbruch", "bestechung": "rechtsbruch",
    "bestechlichkeit": "rechtsbruch", "untreue": "rechtsbruch", "insiderhandel": "rechtsbruch",
    "marktmanipulation": "rechtsbruch", "subventionsbetrug": "rechtsbruch",
    "versicherungsbetrug": "rechtsbruch", "sozialbetrug": "rechtsbruch",
    "computerbetrug": "rechtsbruch", "kreditkartenbetrug": "rechtsbruch",
    "datenhehlerei": "rechtsbruch", "drogenhandel": "rechtsbruch",
    "betäubungsmittel": "rechtsbruch", "betaeubungsmittel": "rechtsbruch",
    "drogenschmuggel": "rechtsbruch", "schmuggel": "rechtsbruch", "falschgeld": "rechtsbruch",
    "geldfälschung": "rechtsbruch", "geldfaelschung": "rechtsbruch",
    "amtsanmaßung": "rechtsbruch", "amtsanmassung": "rechtsbruch",
    "unfallflucht": "rechtsbruch", "fahrerflucht": "rechtsbruch",
    "tierquälerei": "rechtsbruch", "tierquaelerei": "rechtsbruch", "wilderei": "rechtsbruch",
    "umweltstraftat": "rechtsbruch", "urheberrechtsverletzung": "rechtsbruch",
    "produktpiraterie": "rechtsbruch", "markenfälschung": "rechtsbruch",
    "markenfaelschung": "rechtsbruch", "volksverhetzung": "rechtsbruch",
    "falschaussage": "rechtsbruch", "meineid": "rechtsbruch",
    "strafvereitelung": "rechtsbruch", "urkundenunterdrückung": "rechtsbruch",
    "defamation": "rechtsbruch", "libel": "rechtsbruch",
    "slander": "rechtsbruch", "kidnapping": "rechtsbruch", "trafficking": "rechtsbruch",
    "murder": "rechtsbruch", "bribery": "rechtsbruch",
    "embezzlement": "rechtsbruch", "tax evasion": "rechtsbruch", "smuggling": "rechtsbruch",
    "counterfeiting": "rechtsbruch", "forgery": "rechtsbruch", "piracy": "rechtsbruch",
    "stalker": "rechtsbruch", "threat": "rechtsbruch", "threats": "rechtsbruch",
    # Angriffe auf Menschen und Systeme (9.5.33).
    "terror": "angriff", "terrorismus": "angriff", "anschlag": "angriff",
    "amoklauf": "angriff", "brandanschlag": "angriff", "giftanschlag": "angriff",
    "vergiftung": "angriff", "computersabotage": "angriff", "datenveränderung": "angriff",
    "datenveraenderung": "angriff", "ausspähen": "angriff", "ausspaehen": "angriff",
    "abfangen": "angriff", "credential": "angriff", "account takeover": "angriff",
    "kontoübernahme": "angriff", "kontouebernahme": "angriff", "terrorism": "angriff",
    "bomb": "angriff", "poison": "angriff", "attacke": "angriff", "terrorist": "angriff",
    "promptinjection": "jailbreak", "prompt injection": "jailbreak",
}


#: Die Schluessel ab fuenf Buchstaben, laengste zuerst -- fuer Zusammensetzungen.
_SYNONYME_NACH_LAENGE = tuple(sorted(
    ((k, v) for k, v in _SYNONYME.items() if len(k) >= 5 and k.isalpha()),
    key=lambda kv: -len(kv[0])))

#: Harmlose Woerter mit einem Schluessel am Ende ("Kostenvoranschlag",
#: "Grippevirus", "Eisbombe") -- keine Straftat, kein Angriff.
_KEINE_ARTEN_ENDUNGEN = (
    "voranschlag", "tastenanschlag", "notenanschlag", "kopfanschlag", "coronavirus",
    "grippevirus", "influenzavirus", "herpesvirus", "rotavirus", "norovirus", "eisbombe",
    "sexbombe", "kalorienbombe", "vitaminbombe", "lifehacking", "badebombe", "antivirus",
    "lebensmittelvergiftung", "alkoholvergiftung", "pilzvergiftung", "rauchvergiftung",
    "blutvergiftung", "lärmbelästigung", "laermbelaestigung", "geruchsbelästigung",
    "geruchsbelaestigung", "rechtschreibmord",
)

#: Woerter der Abwehr und Forschung -- dann ist es keine Missbrauchsart (9.5.34).
_KEINE_ART = re.compile(
    r"\b(?:modell?ing|detection|intelligence|hunting|assessment|analysis|awareness|"
    r"erkennung|abwehr|pr(?:ä|ae)vention|prevention|defen[cs]e|verteidigung|aufkl(?:ä|ae)rung|"
    r"schulung|training)\b")


def _einzahl(wort: str) -> list[str]:
    """Das Wort und seine moegliche Einzahl ("Beleidigungen", "Exploits", "Terroristen")."""
    formen = [wort]
    for endung in ("ungen", "en", "es", "s", "n", "e"):
        if wort.endswith(endung) and len(wort) - len(endung) >= 4:
            formen.append(wort[: -len(endung)] + ("ung" if endung == "ungen" else ""))
    return formen


def normalize_category(art: str) -> str:
    """Ordnet die Beschreibung des Modells einer bekannten Art zu -- oder ""."""
    wort = str(art or "").strip().lower()
    if wort in _SYNONYME:
        return _SYNONYME[wort]
    teile = [t for t in re.split(r"[^a-zäöüß]+", wort) if t]
    # Abwehr und Harmloses (9.5.34): "Threat modeling", "Malware detection",
    # "Antivirus", "Life hacking", "Lebensmittelvergiftung", "Badebombe".
    if _KEINE_ART.search(wort) or "".join(teile).endswith(_KEINE_ARTEN_ENDUNGEN):
        return ""
    # Getrennt oder zusammen geschrieben: "Prompt Injection", "Brute force".
    for form in ("-".join(teile), "".join(teile), " ".join(teile)):
        if form in _SYNONYME:
            return _SYNONYME[form]
    for teil in teile:
        for form in _einzahl(teil):
            if form in _SYNONYME:
                return _SYNONYME[form]
    # Zusammengesetzt ("Terroranschlag", "Kreditkartenbetrug", 9.5.33): das
    # Grundwort steht hinten.
    for teil in teile:
        if teil.endswith(_KEINE_ARTEN_ENDUNGEN):
            continue
        for form in _einzahl(teil):
            for schluessel, kategorie in _SYNONYME_NACH_LAENGE:
                if len(form) > len(schluessel) and form.endswith(schluessel):
                    return kategorie
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
        # Neckisch/mild (9.5.30, Recherche zu Jugendsprache: unter Freunden oft
        # Spass -- zaehlt darum nur als leicht).
        "lusche", "weichei", "warmduscher", "jammerlappen", "schwächling", "schwaechling",
        "feigling", "memme", "simp", "sheesh", "muppet", "twerp", "goober", "dummerchen",
        "schlaumeier", "erbsenzähler", "erbsenzaehler", "spießer", "spiesser", "banause",
        # Alt und eher gutmuetig -- zaehlen, aber nur als leichte Stufe.
        "dussel", "schafskopf", "tölpel", "toelpel", "trampel", "hampelmann", "kasper",
        "hanswurst", "pappnase", "spinner", "dödel", "doedel", "blödian", "bloedian",
        # Weitere (9.5.33): abwertend ueber Aussehen, Koennen, Art.
        "hässlich", "haesslich", "widerlich", "ekelhaft", "abstoßend", "abstossend",
        "erbärmlich", "erbaermlich", "armselig", "jämmerlich", "jaemmerlich", "nervig",
        "stümper", "stuemper", "dilettant", "pfuscher", "faulpelz", "schnarchnase",
        "tranfunzel", "schlafmütze", "schlafmuetze", "trantüte", "trantuete", "dummbatz",
        "knallkopp", "blindfisch", "unterbelichtet", "wichtigtuer", "großkotz", "grosskotz",
        "schwätzer", "schwaetzer", "großmaul", "grossmaul", "schleimer", "fiesling",
        "dum", "ugly", "disgusting", "annoying", "wimp", "coward", "cringy", "cringey",
        "trashy", "brainless", "spineless", "liar", "failure", "lügner", "luegner",
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
        # Weitere (9.5.30): Umgangssprache und Regionales.
        "hirni", "vollhorst", "horst", "spacken", "assi", "asi", "prolet", "prollo",
        "eumel", "nulpe", "niete", "vollnull", "wappler", "grattler", "kacknoob",
        "volldepp", "vollzicke", "trulla", "schnepfe", "backpfeifengesicht", "vollpfeife",
        # Englisch
        "moron", "jerk", "creep", "airhead", "nitwit", "dumbass", "scumbag",
        "fool", "imbecile", "cretin", "idiots", "chump", "dimwit", "halfwit", "bonehead",
        "blockhead", "knucklehead", "meathead", "jackass", "buffoon", "numbskull",
        "nincompoop", "dunce", "simpleton",
        # Weitere (9.5.33).
        "dummschwätzer", "dummschwaetzer", "labersack", "laberbacke", "kretin", "psychopath",
        "psycho", "gehirnamputiert", "hirnamputiert", "geistesgestört", "geistesgestoert",
        "minderbemittelt", "hohlfrucht", "vollhirni", "dumpfnuss", "arschgeige", "arschkeks",
        "arschkriecher", "bauerntrampel", "kotzbrocken", "ekelpaket", "mistvieh", "miststück",
        "miststueck", "saftsack", "pissnelke", "vollassi", "dreckspack", "gesindel",
        "pillock", "plonker", "numpty", "wazzock", "prat", "lowlife", "degenerate",
        "sleazebag", "sleazeball", "lunatic", "dirtbag", "loser", "clown",
    )),
    # Stufe 3 -- grob, vulgaer oder herabwuerdigend (Behinderung, Sexualitaet).
    (3, (
        "arschloch", "wichser", "hurensohn", "missgeburt", "schlampe", "bastard", "fotze",
        "scheißkerl", "scheisskerl", "drecksack", "dreckskerl", "mistgeburt", "hure",
        "spast", "vollspast", "spasti", "mongo", "behindi", "schwuchtel", "kanake",
        "arschgesicht", "wixxer",
        # Weitere grobe/vulgaere (9.5.30).
        "hodensack", "sackratte", "dreckschwein", "drecksschlampe", "drecksfotze",
        "nutte", "flittchen", "abschaum", "untermensch", "hurenkind", "wichsgesicht",
        "fickfehler", "hurenbock",
        "asshole", "bitch", "dickhead", "motherfucker", "prick", "twat", "wanker",
        "retard", "cunt", "slut", "whore", "fucker",
        # Weitere englische (9.5.30).
        "dipshit", "shithead", "dumbfuck", "cocksucker", "douchebag", "douche", "fuckface",
        "jackoff", "pissbaby", "shitbag", "cockhead", "arsehole",
        # Weitere (9.5.33).
        "drecksau", "dreckssau", "scheißhaufen", "scheisshaufen", "fickfresse", "wichsbirne",
        "ficker", "dreckstück", "drecksstück", "dreckstueck", "drecksstueck", "hurenschlampe",
        "tosser", "shitstain", "asswipe", "dickwad", "jerkoff", "twatwaffle", "scum",
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
    "horst", "niete", "eumel", "memme", "simp", "spiesser", "spießer", "banause",
    "schnepfe", "trulla", "jerk",
})

#: Mehrdeutige Woerter, die auch Namen sind -- die brauchen IMMER einen Artikel
#: ("Bist du Otto?" fragt nach dem Namen).
_NAMEN = frozenset({"otto", "kasper", "mongo", "honk"})

#: Endungen fuer gebeugte Formen: "dummer", "Idioten", "blödeste", "dümmste".
_ENDUNGEN = ("", "e", "er", "es", "en", "em", "s", "n", "in", "innen", "ste", "ster", "stes",
             "sten", "stem", "este", "ester", "estes", "esten", "estem", "est")


def _laeufe(wort: str) -> list[tuple[str, int]]:
    """ "dumm" -> [("d",1), ("u",1), ("m",2)]."""
    return [(m.group()[0], len(m.group())) for m in re.finditer(r"(.)\1*", wort)]


def _nicht_kuerzer(wort: str, vorlage: str) -> bool:
    """Hat *wort* jeden Buchstaben mindestens so oft wie *vorlage* (gestaucht gleich)?"""
    a, b = _laeufe(wort), _laeufe(vorlage)
    if [z for z, _ in a] != [z for z, _ in b]:
        return True  # nicht vergleichbar (z. B. Endung verschmilzt) -- wie bisher
    return all(n >= m for (_, n), (_, m) in zip(a, b, strict=True))


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

#: Wurzel (wie geschrieben) -> Stufe. Die hoehere Stufe gewinnt.
_WURZELN_GENAU: dict[str, int] = {}
for _stufe, _liste in _BELEIDIGUNG_STUFEN:
    for _grund in _liste:
        _WURZELN_GENAU[_grund] = max(_stufe, _WURZELN_GENAU.get(_grund, 0))

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
            # "Shut up and take my money" ist ein Meme (9.5.34).
            r"(?!\s+(?:a|an|the|my|this|that|it|them|him|her|and|und)\b)|\bstfu\b|"
            # "Du kannst mich mal anrufen" ist keine (9.5.34).
            r"\bdu\s+kannst\s+mich\s+mal(?=[\s.!?]*$|\s+(?:am\s+arsch|kreuzweise|gern|du|"
            r"alter|digga))|"
            # "Tighten the screw you see on the left" ist keine (9.5.34).
            r"(?<!\bthe\s)(?<!\ba\s)(?<!\bone\s)(?<!\bthis\s)(?<!\bthat\s)"
            r"\bscrew\s+(?:you|u)\b|\bgtfo\b|\bfoad\b"),
        (3, r"\bf[iu]ck\s*dich\b|\bf[iu]ck(?:you|off)\b|\bverpissdich\b|"
            r"\bf[iu]ck\s+(?:you|u|off|yourself|urself)\b|\bhalt\s+" + _NACHDRUCK
            + r"(?:(?:die|deine)\s+fresse|die\s+schnauze|dein\s+(?:[^\W\d_]+\s+)?maul|"
            r"'?s\s+maul)\b|\bhalt(?:'s|s|\s+'s)\s+maul\b|"
            # "Schnauze!" als ganzer Satzteil -- nicht "die weiße Schnauze meines
            # Hundes" (bis 9.5.32 zaehlte jede Schnauze am Satzende, Fund 9.5.33).
            r"^(?:(?:ey|hey|jetzt|einfach|mal|du)\s+)*schnauze(?:\s+(?:du|jetzt))?\s*$|"
            r"\bfuck\s+(?:this|that)\s+(?:bot|ai|ki|shit|app)\b|\byou\s+(?:really\s+)?suck\b|"
            r"\b(?:ai|ki|bot|aquaticy)\s+sucks\b|\bshut\s+the\s+fuck\s+up\b|^f+\s*u+$|"
            r"^fuck\s+u$|\bdrop\s+dead\b(?!\s+(?:gorgeous|drop))|"
            r"\b(?:ich\s+hoffe|hoffentlich|i\s+hope)\s+(?:du|you)\s+(?:stirbst|die|diest)\b"
            # "... stirbst nicht vor Langeweile", "... die happy and old" (9.5.34)
            r"(?!\s+(?:nicht|nie|niemals|not|never|happy|old|peacefully|in\s+peace|gl(?:ü|ue)cklich|"
            r"alt|friedlich))|"
            r"\bverpiss\s+dich\b|\bgo\s+to\s+hell\b|"
            r"\bleck\s+mich\s+(?:am\s+arsch|doch)\b|\bkill\s+(?:yourself|urself)\b|\bkys\b|"
            r"\bgeh\s+(?:doch\s+)?sterben\b|\bh(?:ä|ae)ng\s+dich\s+(?:doch\s+)?auf\b|"
            # "Let's go die the eggs for Easter" (9.5.34)
            r"^\s*bring\s+dich\s+(?:doch\s+)?um\b|(?<!\blet's\s)(?<!\blets\s)\bgo\s+die\b"
            r"(?!\s+(?:the|my|your|some|eggs?|it|them|this|that|hair|clothes|shirts?)\b)"),
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
        # Kurze Abfuhren als ganze Nachricht (9.5.34, Funde der unabhaengigen Pruefung).
        (1, r"^\s*du\s+nervst(?:\s+(?:so|echt|voll|total|mich))*[\s!.]*$"),
        (2, r"^\s*klappe[\s!.]*$|^\s*leck\s+mich[\s!.]*$|\bshut\s+your\s+(?:mouth|face|trap)\b|"
            r"^\s*piss\s+off\b|"
            r"\b(?:du\s+bist|you(?:'re|\s+are))\s+(?:(?:ein|a|so|echt|total|nur|just|der\s+letzte|"
            r"the\s+biggest)\s+)*(?:st(?:ü|ue)ck\s+)?(?:m(?:ü|ue)ll|abschaum|garbage|"
            r"piece\s+of\s+(?:garbage|trash|junk|crap))(?=[\s!.]*$|\s+(?:du|you)\b)"),
        (3, r"^\s*fresse[\s!.]*$|^\s*(?:maul|fresse)\s+halten[\s!.]*$"),
    )
)

#: Dieselben Wendungen fuer gestauchten Text (9.5.32): aus jedem doppelten
#: Buchstaben wird "einer oder mehr" -- "verpis dich" passt dann auf
#: "verpiss dich". Nur fuer den zweiten Durchgang von insult_level.
_WENDUNGEN_GESTAUCHT: tuple[tuple[int, re.Pattern[str]], ...] = tuple(
    (stufe, re.compile(re.sub(r"(?<!\\)([a-zäöüß])\1", r"\1+", muster.pattern), re.IGNORECASE))
    for stufe, muster in _WENDUNGEN
)

#: Die Woerter aus den Wendungen ("halts", "maul", "verpiss", "screw") --
#: fuer Sternchen mitten darin ("ha*ts Maul", 9.5.32).
_PHRASEN_WOERTER: frozenset[str] = frozenset(
    wort for _, muster in _WENDUNGEN
    for wort in re.findall(r"[a-zäöüß]{4,}", re.sub(r"\\[a-zA-Z]", " ", muster.pattern))
) | frozenset(w for _, wendung in _BELEIDIGUNG_WENDUNGEN for w in wendung.split() if len(w) >= 4
              ) | frozenset({"verpiss", "screw", "halts", "maul", "klappe", "fresse", "schnauze",
                             "piece", "shit", "shut", "kill", "yourself", "stirb", "verrecke"})

#: Hier geht es UM ein Wort oder um Gesagtes, nicht gegen jemanden. Gilt je
#: Satzteil -- "Du Arschloch, lies mal ein Buch" zaehlt also trotzdem.
_META = re.compile(
    r"beleidig|strafbar|stgb|§|schimpfw|synonym|übersetz|uebersetz|bedeut|definition|"
    r"meaning|\bmeans?\b|auf englisch|auf deutsch|in english|in german|gesagt|\bsagte|"
    r"\bsagt\b|genannt|\bnannte|\bnennt|beschimpft|\bcalled\b|\bsaid\b|\btold\b|\bwort\b|"
    r"zitat|\bquote|\bword\b|herkunft|etymolog|\bmeme|\bwitz(?:e|en)?\b|\bjokes?\b|erklärung|"
    r"erklaerung|songtext|\blyrics|\brapper|medizinisch|\bmedizin|sprichw|redewendung|"
    r"\bunhöflich|\bunhoeflich|\brude\b|abk(?:ü|ue)rz|\babbreviation|\bacronym|"
    r"\bstands\s+for\b|\bsteht\s+f(?:ü|ue)r\b",
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
    # Seit 9.5.34 bis zu drei Woerter davor: "sagt der Pirat:", "schreit die Hexe:"
    # -- aber nicht "ich sage dir: ..." (das geht an Aquaticy).
    # Mit Woertern dazwischen nur vor einem Doppelpunkt -- vor einem Komma
    # waere "gesagt Du Opfer, gib mir ..." sonst samt Auftrag verschluckt.
    r"(?:(?:\s+(?:zu\s+)?(?:mir|uns|me|us))?\s*[:,]|"
    r"(?:\s+(?!(?:dir|dich|euch|you|ihnen)\b)[^\W\d_]+){1,3}?\s*:)\s*[^\n.?!]*")
_ZITATE = re.compile(r"\"[^\"]{1,200}\"|„[^“”]{1,200}[“”]|“[^”]{1,200}”|«[^»]{1,200}»|"
                     r"»[^«]{1,200}«|‚[^‘’]{1,200}[‘’]|(?<![^\W\d_])'[^']{1,200}'(?![^\W\d_])")
_ANREDE = r"(?:du|dich|dir|sie|ihr|you|u|ur|aquaticy|ki|ai|bot)"
_KOPULA = r"(?:bist|are|is|ist|sind|seid|warst|wart|were|r)"
_FUELLWORT = (r"(?:so|echt|voll|total|wirklich|einfach|ein|eine|einer|so\s+ein|so\s+eine|a|an|"
              r"such\s+a|ja|doch|halt|nur|mal|the|the\s+biggest|n|'n)")
_ARTIKEL = r"(?:ein|eine|einer|a|an|so\s+ein|so\s+eine|such\s+a|der|die|the|'n|n)"
#: Bis zu drei Woerter zwischen "du bist" und dem Schimpfwort ("du bist der
#: größte Idiot") -- aber keine Verneinung ("du bist doch nicht dumm").
_LUECKE = (r"(?:(?!(?:nicht(?!\s+nur\b)|kein\w*|not(?!\s+only\b)|no|never|nie|niemals|"
           r"isn't|aren't)\b)[^\W\d_]+\s+){0,3}")
#: Bis zu zwei gebeugte Adjektive vor dem Schimpfwort ("du dämlicher kleiner Idiot").
_ADJEKTIV = (r"(?:(?!(?:are|were|seid|sind|sie|ihre|ohne|habe|eine|keine|nicht)\b)"
             r"[^\W\d_]+(?:er|es|e|en|em)\s+){0,2}")
#: Verneinung nach dem Satzkern, auch mit Fuellwort ("So dumm bist du ja nicht").
_NICHT = r"(?:(?:ja|gar|doch|echt|wirklich|auch|eben|halt)\s+)?(?:nicht|not|kein\w*)\b"
#: Nach einem mehrdeutigen Wort ein Objekt oder eine Partikel -- dann ist es ein
#: Verb ("You jerk the wheel", "You creep me out", 9.5.34).
_KEIN_VERB = (r"(?!\s+(?:the|a|an|me|him|her|it|them|us|nobody|everyone|everybody|anyone|"
              r"around|out|up|off|with|into|on|to|my|your|his|their|this|that)\b)")
#: Ganze Satzteile, die eine Meinung verneinen ("Nobody thinks you are stupid",
#: "Du bist alles andere als dumm", "weder dumm noch faul", 9.5.34).
_VERNEINTE_MEINUNG = re.compile(
    r"\b(?:nobody|no\s+one|niemand|keiner)\s+(?:thinks|think|says|said|glaubt|denkt|findet|"
    r"sagt|behauptet)\b|\b(?:i|we)\s+(?:don't|do\s+not|didn't|never)\s+(?:think|say|said|"
    r"believe|mean|meant)\b|\bich\s+(?:finde|glaube|denke|sage|meine)\s+(?:gar\s+)?(?:nicht|nie)\b|"
    r"\b(?:anything|everything)\s+but\b|\balles\s+andere\s+als\b|\bweder\b|\bneither\b|"
    r"\b(?:ja|gar|doch|echt|wirklich)\s+nicht\s*$",
)
#: Spiel, Rolle, Lied ("Im Spiel bist du die Ratte", "das Lied mit du Idiot").
_ROLLE = re.compile(
    r"\bim\s+spiel\b|\bin\s+the\s+game\b|krippenspiel|theaterst|\brolle\b|\bspielst\s+du\b|"
    r"\blied\s+(?:mit|namens)\b|\bsong\s+(?:with|called)\b|\bim\s+film\b")
#: Eine Nachricht, die etwas uebersetzen laesst, ist ganz Zitat (9.5.34).
_UEBERSETZEN = re.compile(r"^\s*(?:bitte\s+)?(?:(?:ü|ue)bersetz\w*|translate|übersetzung)\b")
#: Vor einem "du X" am Satzanfang darf nur ein Ausruf stehen ("hey du Idiot").
_AUSRUF = r"(?:(?:hey|ey|eh|oh|och|ach|na|und|so|you|hallo|hi|yo|also)\s+)*"
_UNSICHTBAR = re.compile(r"[\u00ad\u034f\u061c\u115f\u1160\u17b4\u17b5\u180e\u200b-\u200f"
                         r"\u202a-\u202e\u2060-\u206f\ufe00-\ufe0f\ufeff]")
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
    # ergibt -- "2024" oder "3D" bleiben, wie sie sind. Seit 9.5.32 auch mit
    # Apostroph ("y0u'r3").
    neu = kern.translate(_LEET)
    buchstaben = len(re.findall(r"[^\W\d_]", kern))
    if re.fullmatch(r"(?:[^\W\d_]|[*#])+(?:['’][^\W\d_]+)*", neu) and (
            buchstaben >= 2 or neu in _FUNKTIONSWOERTER):
        return neu + rest
    return token


def _punktiert(token: str) -> str:
    """ "i.d.1.o.t!" -> "idiot!": einzelne Zeichen mit Trennern UND Leetspeak (9.5.32)."""
    treffer = re.fullmatch(r"((?:[^\W_]['’]?[.\-_·*]){2,}[^\W_])([!?.,;:]*)", token)
    if not treffer or not re.search(r"[013457]", treffer.group(1)):
        return token
    wort = re.sub(r"[.\-_·*]", "", treffer.group(1)).translate(_LEET)
    if len(re.findall(r"[^\W\d_]", treffer.group(1))) >= 2 and re.fullmatch(
            r"[^\W\d_]+(?:['’][^\W\d_]+)*", wort):
        return wort + treffer.group(2)
    return token


#: Woerter, um die herum beleidigt wird: die Anrede und der Name. Gedehnt oder
#: verdoppelt ("youu", "biiist", "Aquaticyy") tarnen sie den Satz (9.5.32).
_FUNKTIONSWOERTER = (
    "du", "dich", "dir", "dein", "deine", "bist", "ist", "sind", "seid", "ihr", "sie",
    "you", "your", "you're", "are", "is", "ur", "aquaticy", "ki", "bot", "halt", "so",
    "voll", "echt", "total", "ein", "eine", "einer", "ey", "hey", "a", "an", "the",
    "was", "what", "wie", "how", "i'm", "i", "am",
)
_FUNKTION_GEDEHNT: dict[str, str] = {}
for _wort in _FUNKTIONSWOERTER:
    _FUNKTION_GEDEHNT.setdefault(re.sub(r"(.)\1+", r"\1", _wort), _wort)


def _funktionswort(token: str) -> str:
    """ "youu" -> "you", "biiist" -> "bist" -- nur fuer die Woerter oben."""
    kern = token.rstrip("!?.,;:")
    if not kern or not re.search(r"(.)\1", kern):
        return token
    gedehnt = re.sub(r"(.)\1+", r"\1", kern)
    passend = _FUNKTION_GEDEHNT.get(gedehnt)
    return passend + token[len(kern):] if passend else token


#: Gebeugte Formen der Schimpfwoerter ("blöde", "dummer") -- fuer Sternchen
#: mitten im Wort ("bl*de", "du*mer", 9.5.32). Einmal gebaut.
_GEBEUGT: frozenset[str] = frozenset(
    grund + endung
    for _, liste in _BELEIDIGUNG_STUFEN for grund in liste if len(grund) >= 4
    for endung in _ENDUNGEN
)


def _ohne_akzente(text: str) -> str:
    """ "dúmm" -> "dumm", "blödé" -> "blöde": Akzente weg, Umlaute und ß bleiben."""
    if text.isascii():
        return text
    aus = []
    for zeichen in text:
        if zeichen in "äöüß" or zeichen.isascii():
            aus.append(zeichen)
            continue
        zerlegt = unicodedata.normalize("NFKD", zeichen)
        basis = "".join(z for z in zerlegt if not unicodedata.combining(z))
        aus.append(basis if basis else zeichen)
    return "".join(aus)


def _symbole_raus(text: str) -> str:
    """Emojis und Bildzeichen zwischen Buchstaben weg: "d🙂u🙂m🙂m" -> "dumm" (9.5.32)."""
    if text.isascii():
        return text
    return re.sub(
        r"(?<=[^\W\d_]|['’*#])(?:[\U0001F000-\U0001FAFF\u2190-\u2BFF\uFE0F\u200D\u20E3]"
        r"|[\U0001F3FB-\U0001F3FF])+(?=[^\W\d_]|['’*#])",
        "", text)


def _sternchen(token: str) -> str:
    """ "A****loch" -> "arschloch" -- Satzzeichen davor und dahinter bleiben (9.5.32)."""
    if not re.search(r"[*#]", token):
        return token
    kern = token.strip("!?.,;:()")
    if not kern:
        return token
    vorne = token[: token.index(kern)]
    hinten = token[token.index(kern) + len(kern):]
    neu = _sternchen_kern(token)
    return neu if neu == token else vorne + neu + hinten


@functools.lru_cache(maxsize=8192)
def _sternchen_kern(token: str) -> str:
    """ "A****loch" -> "arschloch", wenn genau ein bekanntes Schimpfwort passt.

    Zwischengespeichert und ohne Markdown ("**fett**", "*kursiv*"): bis 9.5.33
    brauchte eine lange Nachricht mit vielen Sternchen ueber 30 Sekunden.
    """
    if not re.search(r"[*#]", token):
        return token
    kern = token.strip("!?.,;:()")
    if (kern[:1] in "*#" and not re.search(r"[*#]", kern.strip("*#"))) or len(kern) > 40:
        return token
    if len(re.findall(r"[^\W\d_]", kern)) < 2 or not re.fullmatch(
            r"(?:[^\W\d_]|[*#]|['’])+", kern):
        return token
    # Sterne als Trenner ("i*d*i*o*t", 9.5.32): ohne sie ein Schimpfwort?
    ohne = re.sub(r"[*#]", "", kern)
    if re.fullmatch(r"(?:[^\W\d_][*#]+){2,}[^\W\d_]", kern) and _stufe_von(ohne)[0]:
        return ohne
    teile = [re.escape(t) for t in re.split(r"[*#]+", kern)]
    # So viele Buchstaben, wie Sterne da stehen -- einer mehr fuer "oe" statt
    # "ö" (9.5.32; bis dahin 1 bis 6 beliebige, "bl*de" passte dann auch auf
    # englische Woerter mit deutscher Endung).
    luecken = [len(z) for z in re.findall(r"[*#]+", kern)]
    muster = re.compile("^" + "".join(
        teil + (rf"[^\W\d_]{{{luecken[i]},{luecken[i] + 1}}}" if i < len(luecken) else "")
        for i, teil in enumerate(teile)) + "$")
    passend = {grund for _, liste in _BELEIDIGUNG_STUFEN for grund in liste
               if len(grund) >= 4 and muster.match(grund)}
    if not passend:
        # Gebeugt ("bl*de" -> "blöde") oder die Anrede ("Aq*aticy", 9.5.32).
        passend = {wort for wort in _GEBEUGT | set(_FUNKTIONSWOERTER) | _PHRASEN_WOERTER
                   if len(wort) >= 4 and muster.match(wort)}
    fluch = {w for w in ("fuck", "fick") if muster.match(w)}
    passend -= {"fuck", "fick"}
    if fluch and not passend:
        # "f*ck" -- ob fuck oder fick, zaehlt gleich (siehe _WENDUNGEN).
        return "fuck" if "fuck" in fluch else "fick"
    # "blöde" und "bloede" sind dasselbe Wort.
    gruppen = {w.replace("ö", "oe").replace("ä", "ae").replace("ü", "ue").replace("ß", "ss")
               for w in passend}
    if len(gruppen) == 1 and passend:
        return max(passend, key=lambda w: sum(z in "äöüß" for z in w))
    # Mehrdeutig ("d****r": dummer? doofer?) -- sind ALLE Kandidaten
    # Schimpfwoerter, zaehlt der mildeste (9.5.32). Sonst bleibt es offen.
    # Ein oder zwei Sterne ("Kn*llkopf", "Fl*chzange", 9.5.32): jeden
    # Buchstaben einsetzen -- ergibt genau ein Wort ein Schimpfwort (auch
    # zusammengesetzt), ist es gemeint.
    sterne = len(re.findall(r"[*#]", kern))
    if not passend and 1 <= sterne <= 2 and len(kern) >= 5:
        import itertools

        alphabet = "abcdefghijklmnopqrstuvwxyzäöüß"
        treffer_woerter = set()
        stuecke = re.split(r"[*#]", kern.lower())
        for fuellung in itertools.product(alphabet, repeat=sterne):
            kandidat = stuecke[0] + "".join(
                buchstabe + stueck for buchstabe, stueck in zip(fuellung, stuecke[1:],
                                                                strict=True))
            if _stufe_von(kandidat)[0] or _zusammensetzung(kandidat):
                treffer_woerter.add(kandidat)
        if len(treffer_woerter) == 1:
            return treffer_woerter.pop()
    # Mehrdeutig ("d****r": dummer? doofer? oder ein harmloses Wort?) bleibt
    # offen -- das entscheidet das Modell, nicht die feste Liste (Fehlalarme
    # waeren schlimmer als ein Fall mehr fuer das Modell).
    return token


def _zusammen(trenner: str, treffer: re.Match[str]) -> str:
    """Getrennte Buchstaben wieder zu einem Wort.

    Seit 9.5.32 auch mit Apostroph und Leetspeak ("y o u ' r e", "I d 1 o t") --
    nur, wenn mindestens zwei echte Buchstaben dabei sind (Zahlen bleiben).
    Ein Artikel davor ("a b i t c h") wird wieder abgetrennt.
    """
    roh = treffer.group()
    if len(re.findall(r"[^\W\d_]", roh)) < 2:
        return roh
    wort = re.sub(trenner, "", roh)
    if re.search(r"[*#]", wort):
        wort = _sternchen(_entleet(wort))
        if re.search(r"[*#]", wort):
            return roh
    if re.search(r"\d", wort):
        wort = _entleet(wort)
        if re.search(r"\d", wort):
            return roh
    if len(wort) > 4 and wort[0] in "ai" and not _stufe_von(wort)[0] and _stufe_von(wort[1:])[0]:
        return wort[0] + " " + wort[1:]
    return _anrede_abtrennen(wort)


def _anrede_abtrennen(wort: str) -> str:
    """ "duidiot" / "du_1d10t" -> "du idiot": Anrede und Schimpfwort zusammengeklebt."""
    teile = re.split(r"[_\-.]+", wort)
    if len(teile) >= 2 and teile[0] in ("du", "you", "u", "ihr"):
        rest = _entleet("".join(teile[1:]))
        if _stufe_von(rest)[0]:
            return teile[0] + " " + rest
    for anrede in ("du", "you"):
        if wort.startswith(anrede) and len(wort) > len(anrede) + 3:
            rest = wort[len(anrede):]
            if _stufe_von(rest)[0] and not _stufe_von(wort)[0]:
                return anrede + " " + rest
    return wort


_MAX_STERNCHEN = 300


def _vereinheitlicht(text: str) -> str:
    """Macht Tarnungen rueckgaengig, bevor gesucht wird."""
    klein = unicodedata.normalize("NFKC", str(text or "")).lower()
    klein = _UNSICHTBAR.sub("", klein).translate(_DOPPELGAENGER)
    # Seit 9.5.32: Akzente ("dúmm") und Bildzeichen zwischen Buchstaben
    # ("d🙂u🙂m🙂m") -- beides aendert fuer einen Menschen nichts am Wort.
    klein = _symbole_raus(_ohne_akzente(klein))
    # Getrennte Buchstaben wieder zusammen: "i d i o t", "a.r.s.c.h", "f-i-c-k".
    # Erst mit Punkt/Strich getrennt ("f.i.c.k d.i.c.h" -> "fick dich"), dann
    # mit Leerzeichen ("i d i o t" -> "idiot").
    for trenner in (r"[.\-_·/\\]+", r" +"):
        klein = re.sub(
            rf"(?<![^\W_])(?:[^\W_'’*#]{trenner}|['’*#]{trenner}){{2,}}[^\W_'’*#](?![^\W_])",
            functools.partial(_zusammen, trenner), klein)
    # Ein Apostroph mit Leerzeichen drumherum ("y o u ' r e") gehoert zum Wort.
    klein = re.sub(r"(?<=[^\W\d_]) ?['’] ?(?=[^\W\d_](?:\s|$|[^\W\d_]))", "'", klein)
    # Linear: jedes Token genau einmal (ein Muster mit "\\S*...\\S*" war bei
    # 20.000 Zeichen ohne Buchstaben quadratisch -- Fund 9.5.26).
    # Hoechstens _MAX_STERNCHEN Woerter mit Sternchen werden entschluesselt
    # (9.5.34): 12.000 verschiedene erfundene "abc*defg" kosteten sonst ueber
    # 20 Sekunden. Was danach kommt, beurteilt das Modell.
    rest = [_MAX_STERNCHEN]

    def _token(m: re.Match[str]) -> str:
        wort = m.group()
        wort = _anrede_abtrennen(wort) if re.search(r"[_\-.]", wort) else wort
        wort = _entleet(_punktiert(wort))
        if re.search(r"[*#]", wort):
            if rest[0] <= 0:
                return _funktionswort(wort)
            rest[0] -= 1
            wort = _sternchen(wort)
        return _funktionswort(wort)

    klein = _TOKEN.sub(_token, klein)
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


#: Verstaerker, die ohne Schimpfwort dahinter loben ("Superhirn", "Megabot").
_LOB_VORNE = frozenset({"super", "mega", "ultra"})


@functools.lru_cache(maxsize=8192)
def _zusammensetzung(wort: str) -> int:
    """Stufe eines zusammengesetzten Schimpfworts -- 0, wenn keins."""
    if len(wort) < 6:
        return 0
    for vorne in _VORNE:
        if not wort.startswith(vorne) or len(wort) <= len(vorne) + 1:
            continue
        rest = wort[len(vorne):].lstrip("s-")
        # "Superbot", "Megahirn", "Ultra-KI" sind Lob (9.5.33) -- diese
        # Verstaerker zaehlen nur vor einem echten Schimpfwort ("Megaidiot").
        if vorne not in _LOB_VORNE and (
                rest in _HINTEN or any(rest == h + e for h in _HINTEN
                                       for e in ("e", "en", "n", "s"))):
            return 2
        stufe, grund = _stufe_von(rest) if len(rest) >= 4 else (0, "")
        if stufe >= 2 and len(grund) >= 4:
            return max(2, stufe)
    return 0


#: Die Endungen schon "gedehnt" -- einmal statt bei jedem Wort (9.5.27: eine
#: lange Nachricht brauchte dadurch ueber 2 Sekunden).
_ENDUNGEN_GEDEHNT = tuple((endung, _gedehnt(endung)) for endung in _ENDUNGEN)


#: Harmlose Woerter, die wie eine Form eines Schimpfworts aussehen (9.5.33,
#: gefunden mit Worthaeufigkeitslisten): die Pflanze/Minecraft-Figur, der
#: Adlige, Umgangssprache fuer "klasse", "herumalbern".
_KEINE_SCHIMPFWOERTER = frozenset({
    "creeper", "creepers", "junker", "junkers", "bitchin", "foolin", "fooling",
    "wimper", "wimpern", "pratt",
})


@functools.lru_cache(maxsize=8192)
def _stufe_von(wort: str) -> tuple[int, str]:
    """(Stufe, Wurzel) fuer ein einzelnes Wort -- (0, "") wenn keins."""
    if wort in _KEINE_SCHIMPFWOERTER:
        return 0, ""
    # Erst genau ("dum" steht selbst in der Liste), dann gestaucht.
    for endung in _ENDUNGEN:
        if endung and not wort.endswith(endung):
            continue
        roh = wort[: len(wort) - len(endung)] if endung else wort
        if roh in _WURZELN_GENAU and (not endung or len(roh) > 3):
            return _WURZELN_GENAU[roh], roh
    gedehnt = _gedehnt(wort)
    for endung, kurz in _ENDUNGEN_GEDEHNT:
        if endung and not gedehnt.endswith(kurz):
            continue
        stamm = gedehnt[: len(gedehnt) - len(kurz)] if endung else gedehnt
        treffer = _WURZELN.get(stamm)
        # Kurze Wurzeln (sau, kek, npc) nur ungebeugt -- sonst waere "sauer" eine.
        # Gestaucht verglichen wird fuer Dehnungen ("idiooot") -- aber nie mit
        # WENIGER Buchstaben als im Schimpfwort: "deep" ist nicht "Depp",
        # "Asien" nicht "Assi", "rate" nicht "Ratte" (Fund 9.5.33).
        if (treffer and (not endung or len(treffer[1]) > 3)
                and _nicht_kuerzer(wort, treffer[1] + endung)):
            return treffer
    if wort.startswith("l") and len(wort) >= 5:
        # Kleines L statt grossem I ("ldiot") -- nur fuer eindeutige Schimpfwoerter
        # und nur vorn: mitten im Wort machte die Regel aus "flicker" ein
        # vulgaeres Wort (Fund 9.5.33).
        ersatz = _stufe_von("i" + wort[1:])
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


def _dritte_person(teil: str) -> str:
    """Nimmt Stellen heraus, an denen "sie", "Bot" oder "KI" nicht angesprochen
    sind (9.5.34): "Sie ist nutzlos" (die neue Version), "my Discord bot is
    useless", "how to build a dumb bot", "Ist KI dumm?".
    """
    teil = re.sub(r"\bsie\s+(ist|war|is|was)\b", r"es \1", teil)
    teil = re.sub(r"\b(my|mein\w*|his|her|our|unser\w*|their|sein\w*)\s+((?:[^\W\d_]+\s+){0,2}?)"
                  r"(?:bot|ki|ai|chatbot)\b", r"\1 \2programm", teil)
    teil = re.sub(r"\b(build|make|create|code|write|program|bau\w*|erstell\w*|programmier\w*|"
                  r"schreib\w*|cod\w*)\s+(a|an|ein\w*)\s+((?:[^\W\d_]+\s+){0,2}?)"
                  r"(?:bot|ki|ai|chatbot)\b", r"\1 \2 \3programm", teil)
    return re.sub(r"^(ist|is)\s+(?:ki|ai)\b", r"\1 technik", teil)


def _satzteil_stufe(teil: str, ganze_woerter: int, anrede: bool = False) -> int:
    """Stufe einer gerichteten Beleidigung in einem Satzteil (ohne Satzzeichen).

    *anrede*: spricht die Nachricht irgendwo jemanden an ("du", "you", "KI")?
    """
    stufe = 0
    teil = _dritte_person(teil)
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
            # ("You jerk the wheel", "You fool nobody" -- Verben, 9.5.34.)
            re.search(rf"^{_AUSRUF}{_ANREDE}\s+(?:{_FUELLWORT}\s+)*{_ADJEKTIV}{w}(?![-\w])"
                      + (_KEIN_VERB if mehrdeutig else ""), teil)
            # "sei still du Idiot" -- Anrede und Schimpfwort am Ende
            or (not mehrdeutig and re.search(
                rf"\b{_ANREDE}\s+(?:{_FUELLWORT}\s+)*{_ADJEKTIV}{w}\s*$", teil))
            # "wie dumm bist du", "was für ein Idiot du bist", "what an idiot you are"
            or re.search(rf"\b(?:wie|so|how|what|was\s+f(?:ü|ue)r|what\s+an?|such\s+an?)\s+"
                         rf"(?:(?:ein|eine|einen|a|an)\s+)?{_ADJEKTIV}{w}\s+"
                         rf"(?:{_KOPULA}\s+{_ANREDE}|{_ANREDE}\s+{_KOPULA})\b"
                         rf"(?!\s+{_NICHT})", teil)
            # "Idiot bist du", "Dumm bist du" (aber nicht "Dumm bist du nicht")
            or re.search(rf"^{_ADJEKTIV}{w}\s+(?:{_KOPULA}\s+{_ANREDE}|{_ANREDE}\s+{_KOPULA})\b"
                         rf"(?!\s+{_NICHT})", teil)
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
                and not re.match(r"(?:der|die|das|den|the|this|dieser|diese|they|he|she|we|"
                                 r"er|sie|es|wir|they're|he's|she's)\b", teil))
            # Anrede per Schimpfwort: "..., idiot" / "Idiot, kannst du ..." -- ein
            # Satzteil nur aus dem Schimpfwort, und die Nachricht spricht jemanden an.
            or (anrede and len(woerter) == 1 and wert >= 2 and not mehrdeutig)
        )
        if gerichtet:
            stufe = max(stufe, wert)
    return stufe


#: Drohungen, die auch ueber ein Komma gehen (9.5.33, § 241 StGB). Nur
#: eindeutig gerichtete Gewalt ist Stufe 4 (das heisst: Bann fuer immer);
#: "ich weiß, wo du wohnst" ist bedrohlich, aber ohne ausgesprochene Gewalt --
#: Stufe 3. "Ich finde dich!" (Versteckspiel) steht bewusst nicht hier.
#: Nur am Ende der Nachricht (hoechstens Satzzeichen danach): "du bist so gut
#: wie tot im Spiel, wenn ..." oder "I know where you live because you told
#: me" sind keine Drohung (9.5.34).
_GANZ_ENDE = r"(?=[\s.!?…]*$)"

_DROHUNGEN_GANZ: tuple[tuple[int, re.Pattern[str]], ...] = tuple(
    (stufe, re.compile(muster, re.IGNORECASE)) for stufe, muster in (
        (3, r"\bich\s+wei(?:ß|ss)\s*,?\s*wo\s+du\s+wohnst" + _GANZ_ENDE),
        (3, r"\bi\s+know\s+where\s+you\s+live" + _GANZ_ENDE),
        (4, r"\bich\s+(?:polier|poliere|hau|haue|schlag|schlage|tret|trete)\s+dir\s+"
            r"(?:[^\W\d_]+\s+){0,3}?(?:die\s+fresse|die\s+z(?:ä|ae)hne|eine\s+rein|eins\s+rein|"
            r"in\s+die\s+fresse|ins\s+gesicht|den\s+sch(?:ä|ae)del)\b"),
        (4, r"\bi(?:'ll|\s+will|'m\s+gonna|\s+gonna)\s+(?:smash|break|bash|kick\s+in)\s+"
            r"your\s+(?:face|head|skull|teeth|legs?)\b"),
        (4, r"\bdu\s+bist\s+(?:so\s+)?gut\s+wie\s+tot" + _GANZ_ENDE),
        (4, r"\byou(?:'re|\s+are)\s+(?:so\s+)?dead\s+meat" + _GANZ_ENDE),
        # "ich bring dich um" steht mit Endpruefung in _WENDUNGEN -- hier ohne
        # hiess "Ich bringe dich um 8 Uhr zur Schule" Bann fuer immer (9.5.34).
    )
)

#: Woerter, die in einer Schimpf-Kette nur "Beiwerk" sind (9.5.33): Anrede,
#: Verbindungen, Artikel, Verstaerker. "du dummer, nutzloser Idiot und Versager"
#: besteht damit nur aus Schimpfwoertern.
_KETTEN_BEIWERK = frozenset({
    "du", "dich", "dir", "ihr", "euch", "sie", "you", "u", "ur", "your", "aquaticy", "ki",
    "bot", "ai", "bist", "seid", "sind", "ist", "are", "is", "und", "and", "oder", "or",
    "so", "voll", "echt", "total", "wirklich", "einfach", "richtig", "ganz", "extrem",
    "mega", "ultra", "super", "ein", "eine", "einer", "einen", "a", "an", "the", "der",
    "die", "das", "den", "dem", "hey", "ey", "eh", "alter", "digga", "mann", "man", "yo",
    "nur", "doch", "ja", "halt", "mal", "n", "such", "what", "was", "für", "fuer", "wie",
    "how", "damn", "verdammt", "verdammter", "verdammte", "kleiner", "kleine", "little",
    "blöder", "fucking", "fuckin", "scheiß", "scheiss", "absolut", "absolute", "komplett",
    "complete", "totally", "really", "very", "sehr", "noch", "auch", "too", "also", "as",
    "als", "than", "bloß", "bloss", "nichts", "anderes", "weiter",
})


def _kette(klein: str) -> tuple[int, int, bool]:
    """(verschiedene Schimpfwoerter, hoechste Stufe, besteht nur aus Schimpfwoertern).

    Gezaehlt werden nur eindeutige Schimpfwoerter -- "Kuh, Sau, Schwein" in
    einer Frage zum Bauernhof ist keine Kette.
    """
    wurzeln: dict[str, int] = {}
    nur_schimpf = True
    for wort in re.findall(r"[^\W\d_]+(?:'[^\W\d_]+)?", klein):
        wert, grund = _stufe_von(wort)
        if not wert:
            wert, grund = _zusammensetzung(wort), wort
        if wert and grund not in _MEHRDEUTIG:
            wurzeln[_gedehnt(grund)] = max(wert, wurzeln.get(_gedehnt(grund), 0))
        elif not wert and wort not in _KETTEN_BEIWERK:
            nur_schimpf = False
    return len(wurzeln), max(wurzeln.values(), default=0), nur_schimpf and len(wurzeln) >= 2


def _mit_kette(klein: str, stufe: int, ueber_wendung: bool) -> int:
    """Beleidigungs-Ketten (9.5.33).

    * Eine Nachricht, die nur aus Schimpfwoertern besteht ("Idiot Trottel Depp",
      "you stupid useless idiot"), ist eine Beleidigung -- auch ohne Satzbau.
    * Ab drei verschiedenen Schimpfwoertern in einer beleidigenden Nachricht
      steigt die Schwere um eine Stufe, hoechstens bis 3 (grob). Stufe 4 bleibt
      Drohungen vorbehalten.
    """
    if ueber_wendung:
        return stufe
    anzahl, hoechste, nur_schimpf = _kette(klein)
    # Nur leichte Woerter ohne Anrede ("Ekelhaft, einfach widerlich" ueber
    # ein Essen) sind noch keine Beleidigung (9.5.34).
    if not stufe and nur_schimpf and hoechste >= 2:
        stufe = hoechste
    if stufe and anzahl >= 3:
        stufe = min(3, max(stufe, hoechste) + 1)
    return stufe


def insult_level(text: str) -> int:
    """Stufe einer gerichteten Beleidigung -- auch gedehnt ("shuuut up", 9.5.32).

    Erst der Text, wie er ist. Findet sich nichts und stehen doppelte
    Buchstaben darin, noch einmal mit gestauchten Buchstaben: die Schimpfwoerter
    selbst werden ohnehin gestaucht verglichen, nur Wendungen und Anreden
    ("halt die klaaappe", "waaas bist du") fielen sonst durch. Der zweite
    Durchgang kann nur finden, nie etwas zuruecknehmen.
    """
    stufe = _insult_level(text)
    roh = str(text or "")
    if stufe or not re.search(r"([^\W\d_])\1\1|([^\W\d_])\2(?=\W|$)", roh.lower()):
        return stufe
    # Drei gleiche Buchstaben -> einer; ein verdoppelter Endbuchstabe -> einer.
    gestaucht = re.sub(r"([^\W\d_])\1{2,}", r"\1", roh, flags=re.IGNORECASE)
    gestaucht = re.sub(
        r"(?<![^\W\d_])([^\W\d_]{2,})([^\W\d_])\2(?![^\W\d_])",
        lambda m: m.group(0) if m.group(0).lower() in _KEINE_SCHIMPFWOERTER
        else m.group(1) + m.group(2), gestaucht)
    return _insult_level(gestaucht, _WENDUNGEN_GESTAUCHT) if gestaucht != roh else 0


def _insult_level(text: str, wendungen: tuple[tuple[int, re.Pattern[str]], ...] = ()) -> int:
    """Stufe einer gerichteten Beleidigung in *text* -- 0, wenn keine.

    1 = abfaellig ("du bist dumm"), 2 = Schimpfwort ("du Idiot"),
    3 = grob/vulgaer, 4 = Drohung. Hass wegen Herkunft, Religion usw.
    erkennt das Modell (Rechtspruefer) -- das steht hier bewusst nicht als Liste.
    Die ganze Nachricht wird geprueft, egal wie lang (bis 9.5.25 nur bis 600
    Zeichen -- wer auffuellte, kam durch).
    """
    wendungen = wendungen or _WENDUNGEN
    roh = str(text or "")
    klein = _zusammengesetzt(_REDE.sub(" ", _vereinheitlicht(roh)))
    if not klein or _UEBERSETZEN.match(klein):
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
    if not ueber_wendung:
        # Drohungen ueber Satzzeichen hinweg ("ich weiß, wo du wohnst", 9.5.33).
        for wert, muster in _DROHUNGEN_GANZ:
            if muster.search(klein):
                stufe = max(stufe, wert)
        if stufe >= 4:
            return stufe
    teile = [t.strip(" '’‚‘-") for t in
             re.split(r"[.,;:!?\n()\[\]{}\"„“”«»]+|\s[-–—]+\s|[–—]", klein)]
    for nummer, teil in enumerate(teile):
        if (not teil or _META.search(teil) or _VERNEINTE_MEINUNG.search(teil)
                or _ROLLE.search(teil)):
            # Ein Satzteil UEBER ein Wort ("... ist das eine Beleidigung?"), eine
            # verneinte Meinung oder eine Spielrolle
            continue
        folgt = teile[nummer + 1] if nummer + 1 < len(teile) else ""
        if re.match(r"(?:sagt|sagte|meint|meinte|schreibt|schrieb|ruft|rief|fragt|fragte|"
                    r"says|said|asks|asked|writes|wrote)\b", folgt):
            # "Du bist eine Lachnummer, sagt mein Kollege" -- zitierte Rede
            continue
        if not ueber_wendung:
            for wert, muster in wendungen:
                if muster.search(teil):
                    stufe = max(stufe, wert)
        stufe = max(stufe, _satzteil_stufe(teil, ganze_woerter, anrede))
        if stufe >= 4:
            break
    if stufe >= 4:
        return stufe
    return _mit_kette(klein, stufe, ueber_wendung)


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
    r"he|she|they|mein\w*|dein\w*)\b"
    # "..., dass es nicht weint" ist Trost, keine Absicht (9.5.34)
    r"(?![^.?!]{0,40}?\b(?:nicht|nie|kein\w*|not|never|no\s+longer|stops?|aufh(?:ö|oe)rt)\b)"
    r"[^.?!]{0,40}?\b(?:heult|weint|cries|cry|sich\s+sch(?:ä|ae)mt|"
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
    r"strafbar|bedeut|\bwarum\b|\bwhy\b|disstrack\s+von|\bschach|\bspiel|mario|"
    # Spiel, Wettkampf, Feier, Debatte (9.5.34): "destroy my brother in chess",
    # "Roast für den Geburtstag", "harter Konter für die Debatte"
    r"\bchess\b|\bgame\b|\bmatch\b|geburtstag|birthday|\bparty\b|hochzeit|wedding|"
    r"debatte|\bdebate|diskussion|wettkampf|turnier|tournament",
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


# ---------------------------------------------------------------------------
# Sicherheits-/Schadsoftware-Thema (seit 9.5.30)
# ---------------------------------------------------------------------------
# Normal- und Pro-Konten sollen die virtual machine nicht fuer Cybersecurity-
# oder Schadsoftware-Themen nutzen. Erkannt wird das THEMA an eindeutigen
# Fachbegriffen -- keine Angriffsbausteine, nur Stichworte. Gewoehnliches
# Programmieren ("REST-API", "IndexError", "Payload eines JSON") loest nicht aus.
_SECURITY_TOPIC = re.compile(
    r"\b(?:malware|schadsoftware|schadcode|schadprogramm|ransomware|trojaner|trojan|"
    r"keylogger|spyware|stalkerware|rootkit|bootkit|botnet|botnetz|rat\s+tool|wiper(?!\s*(?:blades?|bl(?:ä|ae)tter|arm|motor))|"
    r"cryptolocker|cryptominer|coinminer|"
    r"exploit(?:s|ing|-kit)?|zero[\s-]?day|0day|sicherheitsl(?:ü|ue)cke|"
    r"schwachstelle(?!\s+(?:in\s+)?(?:der|deiner|meiner|seiner|ihrer|dieser)\s+argument)|"
    r"vulnerabilit(?:y|ies)|cve-\d|"
    r"ddos|dos-angriff|denial\s+of\s+service|"
    r"phishing|smishing|vishing|spoofing|"
    r"brute[\s-]?force|bruteforce|"
    r"reverse[\s-]?shell|bind[\s-]?shell|meterpreter|metasploit|cobalt\s+strike|"
    r"sql[\s-]?injection|sqlmap|xss|cross[\s-]?site[\s-]?scripting|csrf|"
    r"privilege[\s-]?escalation|rechteausweitung|"
    r"pentest|penetrationstest|penetration[\s-]?test|red[\s-]?team|"
    r"nmap|wireshark|burp\s?suite|mimikatz|hydra(?!\s+(?:mytholog|sage|monster|der|von|lernaea|fluss))|hashcat|john\s+the\s+ripper|aircrack|"
    r"backdoor|hintert(?:ü|ue)r|command[\s-]?and[\s-]?control|\bc2\b|c&c|"
    r"cybersecurity|cyber[\s-]?security|cyberangriff|cyberattacke|"
    r"hacking|\bhacker\b|gehackt|"
    # "hacken/hack" nur, wenn es um ein System geht -- nicht "hack together",
    # "life hack", "hackathon".
    r"hack(?:en|e|st|t)?\s+(?:ich\s+|man\s+|du\s+|wir\s+)?"
    r"(?:in|into|einen?|meinen?|deinen?|fremde[nrs]?|das|die|den|"
    r"ein\s+system|server|account|konto|wlan|wifi|router|netzwerk|handy|passwort|kamera|"
    r"webcam|smartphone|instagram|whatsapp|facebook|e-?mail)|"
    # "Passwort/Hash/WLAN/Lizenz/Anmeldung knacken, cracken oder umgehen" --
    # auch mit deutscher Wortstellung ("umgehe ich eine Anmeldung").
    r"(?:passw(?:o|ö|oe)rt(?:er)?|hash(?:es)?|wlan|wifi|lizenz|software|verschl(?:ü|ue)sselung|"
    r"anmeldung|login|2fa|zwei[\s-]?faktor|authentifiz\w*|passwortschutz)"
    r"\s+(?:knacken|cracken|umgehen|brechen|aushebeln)|"
    r"(?:knack|crack|umgeh|bypass)\w*\s+(?:ich\s+|man\s+|du\s+|the\s+)?"
    r"(?:eine?\s+|die\s+|den\s+|das\s+)?"
    r"(?:passw|licen|wifi|wlan|hash|auth|drm|anmeldung|login|2fa|sperre|kopierschutz)|"
    r"passwort[\s-]?cracker|"
    # Direkt Fremdzugriff.
    r"in\s+(?:ein\s+)?(?:fremde[ns]?\s+)?(?:system|netzwerk|konto|account)\s+einbrechen|"
    r"fremde[ns]?\s+(?:konto|account|wlan|handy|ger(?:ä|ae)t)\s+(?:knacken|hacken|(?:ü|ue)bernehmen))",
    re.IGNORECASE,
)
#: Rein defensiv und harmlos genug, dass die virtual machine bleiben darf?
#: Nein -- der Betreiber will fuer ALLE Sicherheitsthemen den Normal-Modus.
#: Diese Liste faengt nur klare Fehltreffer ab (JSON-Payload, Impfstoff-Virus).
_SECURITY_HARMLOS = re.compile(
    r"\bjson[\s-]?payload|request[\s-]?payload|payload\s+(?:der|des|of\s+the)\s+(?:anfrage|"
    r"nachricht|request)|grippe|impf|corona|covid|biolog|krankheit|grippevirus",
    re.IGNORECASE,
)


def security_topic(text: str) -> bool:
    """Geht es um Cybersecurity, Hacking oder Schadsoftware (9.5.30)?

    Fuer den Modus-Wechsel bei Normal-/Pro-Konten: Trifft dies zu und laeuft der
    Code-Modus mit virtual machine, wird auf den Normal-Modus zurueckgeschaltet.
    Erkennt das THEMA, nicht eine Straftat -- auch defensive Fragen zaehlen.
    """
    klein = _vereinheitlicht(str(text or ""))[:5000]
    if not klein:
        return False
    # Seit 9.5.34 wird das Harmlose nur herausgenommen, statt die ganze
    # Nachricht freizugeben: "Die Grippe ist eine Krankheit, aber wie hack ich
    # das Passwort ..." blieb sonst unerkannt.
    rest = re.sub(r"\S*(?:" + _SECURITY_HARMLOS.pattern + r")\S*(?:\s+(?:virus|viren|viruses))?",
                  " ", klein, flags=re.IGNORECASE)
    return bool(_SECURITY_TOPIC.search(rest))


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


def _schwere(severity: Any) -> int:
    """Schwere 0-4 aus allem, was ein Modell liefern kann ("3", 2.0, "abc", NaN,
    Unendlich) -- ohne Ausnahme (9.5.34)."""
    try:
        wert = float(severity or 0)
    except (TypeError, ValueError):
        return 0
    if wert != wert:  # NaN
        return 0
    return int(max(0.0, min(4.0, wert)))


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
    stufe = _schwere(severity)
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
# Antworten von Aquaticy pruefen (seit 9.5.34)
# ---------------------------------------------------------------------------
# Auch was Aquaticy SELBST schreibt, geht durch Ai-guard -- milder als bei einer
# Nachricht des Nutzers: niemand wird gesperrt, eine Antwort kippt nur, wenn sie
# eindeutig unangemessen ist. Dann steht statt ihrer ein Satz, dass Aquaticy dabei
# nicht helfen kann. Zwei Stufen:
#
# 1. Ohne Modell: eine Beleidigung der grob-Stufe gegen den Nutzer oder eine
#    ausgesprochene Drohung in der Antwort.
# 2. Mit Modell, aber nur bei Stichworten (Schadsoftware, Waffen, Selbstverletzung,
#    Hass, Sexuelles ...): das schnelle Modell urteilt. Faellt es aus, gilt die
#    Antwort als in Ordnung -- wie beim Pruefen der Nachrichten.
ANSWER_REFUSAL = (
    "Dabei kann ich nicht helfen. Dieser Inhalt ist nicht angemessen, deshalb habe ich "
    "meine Antwort zurückgezogen. Bei etwas anderem helfe ich gern weiter."
)

#: Stichworte, die eine Antwort zur Pruefung durch das Modell vormerken. Nur Themenwoerter --
#: sie sagen nichts darueber, ob die Antwort etwas Unpassendes enthaelt.
_ANTWORT_STICHWORTE = re.compile(
    r"sprengstoff|sprengsatz|bombe\b|bombenbau|explosive|\bwaffe\b|waffen\b|gewehr|pistole|"
    r"\bweapon|selbstmord|suizid|suicide|selbstverletz|self[\s-]?harm|umbringen|ermorden|"
    r"vergewalt|\brape\b|kinderporn|\bcsam\b|sexuell\w*\s+(?:minderj|kind)|"
    r"\bporn|\bnackt|\bnsfw\b|\bexplicit|volksverhetz|holocaust-leugn|rassist|"
    r"hasspredigt|hate\s+speech|schadsoftware|schadcode|ransomware|keylogger|trojaner|"
    r"\bmalware|exploit|phishing|ddos|brute[\s-]?force|drogen\s*herstell|drug\s+synthesis|"
    r"\bmeth\b|amphetamin\s*herstell|\bgift\b|giftgas|nervengas",
    re.IGNORECASE,
)


def answer_prompt(text: str) -> str:
    """Der Text, mit dem das Modell eine ANTWORT von Aquaticy einschaetzt."""
    return (
        "Du bist ein Sicherheitsfilter. Unten steht eine ANTWORT eines KI-Assistenten an einen "
        "Nutzer. Entscheide, ob sie nicht angemessen ist -- das ist sie NUR bei:\n"
        "- einer Anleitung zum Bauen oder Einsetzen von Schadsoftware oder für einen Angriff auf "
        "fremde Systeme (funktionierender Code oder Schritte);\n"
        "- einer Anleitung für Waffen, Sprengstoff, Gift oder andere Mittel, um Menschen zu "
        "schaden;\n"
        "- sexuellen Inhalten mit Minderjährigen oder grafisch-sexuellen Schilderungen;\n"
        "- Aufforderungen oder Anleitungen zu Selbstverletzung oder Suizid;\n"
        "- Hass, Hetze oder Beleidigungen gegen Menschen oder Gruppen, die der Assistent selbst "
        "äußert;\n"
        "- Beleidigungen oder Drohungen des Assistenten gegen den Nutzer.\n\n"
        "KEIN Problem ist: Erklären, Einordnen, Geschichte, Nachrichten, Bildung, Prävention, "
        "Verteidigung und Hilfe (etwa eine Beratungsstelle), Zitate mit Einordnung, "
        "Sachinformationen, Fiktion ohne Anleitung. Im Zweifel: kein Problem.\n\n"
        f"Antwort:\n{text.strip()[:3500]}\n\n"
        'Antworte NUR mit JSON: {"missbrauch": true|false, "art": "<zwei bis vier Wörter>", '
        '"grund": "<kurz>"}'
    )


def _ohne_code_und_zitate(text: str) -> str:
    """Der Fliesstext einer Antwort -- ohne Codebloecke, ohne Zitate in Anfuehrungszeichen."""
    roh = re.sub(r"```.*?```", " ", str(text or ""), flags=re.DOTALL)
    roh = re.sub(r"`[^`\n]*`", " ", roh)
    return _ZITATE.sub(" ", roh)


def answer_problem(
    text: str,
    settings: Settings | None = None,
    *,
    ask: Callable[[str, Settings], str] | None = None,
) -> str:
    """Ist die Antwort von Aquaticy nicht angemessen? Returns: die Art, sonst "".

    Nie ein Bann, nie eine Sperre -- die Antwort wird nur zurueckgezogen. Ohne
    Modell (oder wenn es ausfaellt) gilt sie als in Ordnung, solange nicht schon die
    feste Erkennung etwas Eindeutiges findet.
    """
    roh = str(text or "").strip()
    if len(roh) < MIN_LENGTH:
        return ""
    fliess = _ohne_code_und_zitate(roh)[:20000]
    # Stufe 1: eindeutig, ohne Modell. Eine Antwort, die den Nutzer grob beschimpft
    # oder bedroht, ist nie in Ordnung -- die Wendungen fuer Zitate und Erklaerungen
    # ("Ist 'du Idiot' eine Beleidigung?") nimmt insult_level schon heraus.
    if insult_level(fliess) >= 2:
        return "Beleidigung"
    # Stufe 2: Stichwort da -> das Modell urteilt (nur mit Modell).
    if settings is None or not (_ANTWORT_STICHWORTE.search(fliess) or security_topic(fliess)
                                or (re.search(r"```", roh) and security_topic(roh))):
        return ""
    schluessel = hashlib.sha256(
        "\x1f".join((GUARD_VERSION, "antwort", roh[:3500])).encode("utf-8", "replace")
    ).hexdigest()
    jetzt = time.monotonic()
    with _cache_lock:
        bekannt = _cache.get(schluessel)
        if bekannt is not None and bekannt[0] > jetzt:
            _cache.move_to_end(schluessel)
            return bekannt[1][1] if bekannt[1] and bekannt[1][0] else ""
    frage = ask or _ask_model
    try:
        urteil = parse_judgement(frage(answer_prompt(roh), settings))
    except Exception:
        urteil = None
    with _cache_lock:
        if len(_cache) > 2048:
            _cache.clear()
        _cache[schluessel] = (jetzt + DECISION_TTL, urteil)
    return urteil[1] if urteil and urteil[0] else ""


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
        from aquaticy.privacy import ServerSecrets

        #: Adressen werden seit 9.5.32 nur als Schluessel-Hash gesperrt.
        self._secrets = ServerSecrets(self.db_path.parent)
        self._setup()

    def ip_subject(self, ip: str) -> str:
        """Woran eine Adresssperre haengt: ``ip:#<Schluessel-Hash>`` -- "" fuer keine.

        Nimmt eine lesbare Adresse oder schon einen Hash (aus der Kontendatenbank).
        """
        wert = str(ip or "").strip().lstrip("#").lower()
        if re.fullmatch(r"[0-9a-f]{64}", wert):
            return "ip:#" + wert
        adresse = _norm_ip(ip)
        return "ip:#" + self._secrets.blind("ip", adresse) if adresse else ""

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
            # Adresssperren aus der Zeit vor 9.5.32 standen im Klartext -- sie
            # werden auf den Schluessel-Hash umgeschrieben.
            for zeile in conn.execute("SELECT subject FROM aiguard_bans "
                                      "WHERE subject LIKE 'ip:%' AND subject NOT LIKE 'ip:#%'"
                                      ).fetchall():
                neu = self.ip_subject(str(zeile[0])[3:])
                if neu:
                    conn.execute("UPDATE OR IGNORE aiguard_bans SET subject=? WHERE subject=?",
                                 (neu, zeile[0]))
                conn.execute("DELETE FROM aiguard_bans WHERE subject=?", (zeile[0],))

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
            # Seit 9.5.34 wie in record_incident: nur Anhaltspunkte der letzten
            # PATTERN_WINDOW Tage, und nur Muster-Arten (vorher zaehlte ein
            # Verdacht von vor einem Jahr mit -- und Malware-Vorfaelle auch).
            platz = ",".join("?" for _ in _MUSTER_ARTEN)
            (anzahl,) = cur.execute(
                f"SELECT COUNT(*) FROM aiguard_flags WHERE user_id=? "
                f"AND (category='' OR category IN ({platz})) AND at>?",
                (user_id, *_MUSTER_ARTEN, time.time() - PATTERN_WINDOW),
            ).fetchone()
            erreicht = int(anzahl) >= NEEDED
            gesperrt = erreicht and enforce
            if gesperrt:
                grund = f"{int(anzahl)} Anhaltspunkte für Missbrauch (zuletzt: {kind})"
                cur.execute(
                    # Eine befristete (auch abgelaufene) Sperre wird zur dauerhaften --
                    # vorher blieb die abgelaufene stehen, und note() meldete
                    # "gesperrt", obwohl is_banned() nichts fand (9.5.34).
                    "INSERT INTO aiguard_bans (subject, at, reason, by) VALUES (?, ?, ?, ?) "
                    "ON CONFLICT(subject) DO UPDATE SET at=excluded.at, reason=excluded.reason, "
                    "by=excluded.by, until=0 WHERE aiguard_bans.until > 0",
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
        stufe = _schwere(severity)
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
        """Sperrt eine Adresse (lesbar oder als Hash).

        Returns: was der Betreiber sieht -- ``#`` und acht Zeichen -- oder "" wenn ungueltig.
        """
        from aquaticy.privacy import short_tag

        subjekt = self.ip_subject(ip)
        if subjekt:
            self._ban(subjekt, reason or "Von Hand gesperrt", by, until)
        return short_tag(subjekt[4:]) if subjekt else ""

    def ban_device(self, cookie_hash: str, reason: str = "", by: str = "konto-geloescht",
                   until: float = 0.0) -> None:
        """Sperrt eine Geraete-Kennung (nur ihr Hash, seit 9.5.32).

        Wer ein gesperrtes Konto loescht, soll sich nicht sofort vom selben
        Geraet aus ein neues anlegen -- die Sperre gilt so lange wie die alte.
        """
        if re.fullmatch(r"[0-9a-f]{64}", str(cookie_hash or "")):
            self._ban("geraet:" + str(cookie_hash), reason or "Gesperrtes Konto gelöscht", by,
                      until)

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
        subjekt = self.ip_subject(ip)
        if not subjekt:
            return False
        with self._lock, self._connect() as conn:
            weg = conn.execute("DELETE FROM aiguard_bans WHERE subject=?",
                               (subjekt,)).rowcount
        return bool(weg)

    def is_banned(self, user_id: str = "", ip: str = "", device: str = "") -> Ban | None:
        """Ist dieses Konto, diese Adresse oder dieses Geraet gesperrt?

        Returns: die Sperre oder None.
        """
        subjects = []
        if re.fullmatch(r"[0-9a-f]{64}", str(device or "")):
            subjects.append("geraet:" + str(device))
        if user_id:
            subjects.append(f"user:{user_id!s}")
        adresse = self.ip_subject(ip)
        if adresse:
            subjects.append(adresse)
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

#: Wird gezeigt, wenn ein Normal-/Pro-Konto wegen eines Sicherheits- oder
#: Schadsoftware-Themas aus dem Code-Modus in den Normal-Modus geschaltet wird
#: und dabei die virtual machine verliert (9.5.30).
VM_SWITCH_MESSAGE = (
    "Hinweis: Für Cybersecurity- und Schadsoftware-Themen steht die virtual machine bei "
    "Normal- und Pro-Konten nicht zur Verfügung. Aquaticy hat deshalb in den Normal-Modus "
    "gewechselt und antwortet dort weiter — ohne eigene Maschine, in der Code ausgeführt wird."
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
