"""Stufe 3: Playwright-Fallback fuer Seiten, die ohne JavaScript nichts liefern.

Optionale Abhaengigkeit -- Installation ueber `aquaticy install-browser`.

Datenschutz-Voreinstellungen dieses Moduls:

* Immer die datensparsamste Option: **ablehnen statt akzeptieren**. "Alle
  akzeptieren" wird nie geklickt.
* Gibt es keinen Ablehnen-Button, werden die Overlay-Knoten aus dem DOM
  entfernt und die Scroll-Sperre geloest -- der Inhalt liegt fast immer
  schon im DOM.
* Newsletter-Layer, App-Install-Banner und Push-Abfragen werden nur
  entfernt, nie angeklickt. Browser-Berechtigungen werden generell verweigert.
* Pro Seitenabruf ein frischer Browser-Kontext, keine Cookies ueber Aufrufe
  hinweg. Keine Anmeldung, keine Formulare, keine gespeicherten Zugangsdaten.
"""

from __future__ import annotations

import contextlib
import os
import re
from typing import Any, Protocol

from aquaticy.fetch import SiteRules, load_rules

#: Wie lange warten wir maximal auf Netzruhe?
NETWORK_IDLE_TIMEOUT_MS = 6_000
#: Wie lange darf ein einzelner Klick brauchen?
CLICK_TIMEOUT_MS = 2_500

#: Wie lange warten wir hoechstens darauf, dass ein Video wirklich laeuft.
#: Eine Webcam braucht nach dem Start ein paar Sekunden, bis der erste
#: dekodierte Frame steht -- vorher zeigt der Player nur sein Vorschaubild.
PLAYBACK_TIMEOUT_MS = 12_000
#: Wie lange nach dem ersten Bild noch gewartet wird. Der erste Frame ist oft
#: ein Standbild aus dem Puffer; nach einer Sekunde Wiedergabe steht das
#: aktuelle Bild.
PLAYBACK_SETTLE_MS = 1_200

#: Ab wann ein einzelnes haengendes Bild nicht mehr aufhalten darf. Ein
#: Zaehlpixel, eine Anzeige oder ein fremder Rahmen laedt manchmal nie zu
#: Ende -- das ganze Zeitlimit dafuer abzuwarten bringt kein besseres Bild.
PICTURE_GRACE_SECONDS = 3.0

#: Und ab wann ein Video, das nicht anspringt, den Bildweg freigibt. Auch
#: ein Werbevideo in einem fremden Rahmen zaehlt als Video; ohne diese
#: Grenze wartete eine gewoehnliche Bild-Webcam deshalb das ganze Zeitlimit
#: ab, nur weil irgendwo eine Anzeige lag. Grosszuegiger als bei Bildern:
#: ein echter Player braucht nach dem Klick ein paar Sekunden.
VIDEO_GRACE_SECONDS = 6.0

#: Chromium-Argumente fuer den Betrieb im Container. Dort steht der eigene
#: Sandbox-Mechanismus des Browsers meist nicht zur Verfuegung -- was
#: vertretbar ist, weil der ganze Prozess bereits im Container isoliert
#: laeuft. Ausserhalb eines Containers bleibt die Browser-Sandbox aktiv.
CONTAINER_ARGS = ("--no-sandbox", "--disable-dev-shm-usage")

#: Entfernt Overlays und loest die Scroll-Sperre.
REMOVE_OVERLAYS_JS = """
(selectors) => {
  let removed = 0;
  for (const selector of selectors) {
    let nodes;
    try { nodes = document.querySelectorAll(selector); } catch (e) { continue; }
    for (const node of nodes) { node.remove(); removed += 1; }
  }
  // Scroll-Sperre loesen -- viele CMPs frieren das Dokument ein.
  for (const element of [document.body, document.documentElement]) {
    if (!element) continue;
    element.style.overflow = '';
    element.style.position = 'static';
    element.style.height = '';
    element.classList.remove('modal-open', 'no-scroll', 'noscroll', 'overflow-hidden');
  }
  return removed;
}
"""


#: Startet jede Wiedergabe auf der Seite. Stumm und `playsinline`, sonst
#: verweigert Chromium das automatische Abspielen ueberhaupt.
START_PLAYBACK_JS = """
() => {
  const videos = Array.from(document.querySelectorAll('video'));
  for (const video of videos) {
    try {
      video.muted = true;
      video.defaultMuted = true;
      video.playsInline = true;
      video.autoplay = true;
      const started = video.play();
      if (started && typeof started.catch === 'function') started.catch(() => {});
    } catch (e) { /* ein Player, der sich sperrt, wird gleich angeklickt */ }
  }
  return videos.length;
}
"""

#: Laeuft schon ein echtes Bild? Ein Video zaehlt erst, wenn es dekodierte
#: Daten hat UND die Zeit laeuft -- `readyState` allein steht auch beim
#: Vorschaubild schon auf 2.
PLAYBACK_STATE_JS = """
() => {
  const videos = Array.from(document.querySelectorAll('video'));
  const playing = videos.filter(
    (video) => video.readyState >= 2 && video.currentTime > 0 && !video.paused
  ).length;
  const images = Array.from(document.images);
  const loaded = images.filter((image) => image.complete && image.naturalWidth > 1).length;
  return { videos: videos.length, playing: playing, images: images.length, loaded: loaded };
}
"""

#: Das Live-Element finden, in drei Schritten. Ein Ausschnitt davon ist das
#: eigentliche Bild -- ohne Kopfzeile, Werbeflaeche und Bedienleiste.
#: Erster Schritt: alle Kandidaten markieren und ihren Stand festhalten.
#: Bewusst OHNE Fensterausschnitt -- eine Webcam-Seite zeigt oft eine Reihe
#: von Vorschaubildern und darunter das eigentliche Livebild. Wer nur nimmt,
#: was gerade zu sehen ist, nimmt zuverlaessig die Vorschau.
MARK_CANDIDATES_JS = """
() => {
  const nodes = Array.from(document.querySelectorAll('video, canvas, img'));
  const groesse = new Map();
  const stand = [];
  let index = 0;
  for (const node of nodes) {
    const box = node.getBoundingClientRect();
    if (box.width < 240 || box.height < 180) continue;
    const style = window.getComputedStyle(node);
    if (style.visibility === 'hidden' || style.display === 'none') continue;
    if (style.opacity === '0') continue;
    if (node.tagName === 'IMG' && node.naturalWidth <= 1) continue;
    node.setAttribute('data-aquaticy-cand', String(index));
    const schluessel = Math.round(box.width) + 'x' + Math.round(box.height);
    groesse.set(schluessel, (groesse.get(schluessel) || 0) + 1);
    stand.push({
      index: index,
      tag: node.tagName,
      area: box.width * box.height,
      key: schluessel,
      src: node.currentSrc || node.src || '',
      inLink: !!node.closest('a'),
      playing: node.tagName === 'VIDEO'
        && node.readyState >= 2 && !node.paused && node.currentTime > 0,
    });
    index += 1;
  }
  return stand;
}
"""

#: Zweiter Schritt: nach der Wartezeit noch einmal hinsehen. Was sich in der
#: Zwischenzeit geaendert hat, ist ein laufendes Bild -- ein Vorschaubild
#: bleibt, wie es war.
RESCAN_CANDIDATES_JS = """
() => {
  const nodes = Array.from(document.querySelectorAll('[data-aquaticy-cand]'));
  return nodes.map(node => ({
    index: Number(node.getAttribute('data-aquaticy-cand')),
    src: node.currentSrc || node.src || '',
    playing: node.tagName === 'VIDEO'
      && node.readyState >= 2 && !node.paused && node.currentTime > 0,
  }));
}
"""

#: Dritter Schritt: den Gewaehlten markieren, sichtbar scrollen und melden,
#: wie gross er im Fenster ist.
PICK_CANDIDATE_JS = """
(index) => {
  const node = document.querySelector('[data-aquaticy-cand="' + index + '"]');
  if (!node) return null;
  node.setAttribute('data-aquaticy-live', '1');
  node.scrollIntoView({block: 'center', inline: 'center'});
  const box = node.getBoundingClientRect();
  const viewport = window.innerWidth * window.innerHeight;
  return (box.width * box.height) / (viewport || 1);
}
"""

#: Wie lange zwischen den beiden Blicken liegt. Lang genug, dass eine Kamera
#: mit Sekundentakt sich einmal erneuert; kurz genug, dass es niemandem
#: auffaellt.
RESCAN_WAIT_MS = 1_600

#: Ein Bild in einem Link ist fast immer eine Vorschau, die woanders hinfuehrt.
MALUS_IN_LINK = 0.35
#: Und drei gleich grosse Bilder nebeneinander sind eine Vorschaureihe.
MALUS_THUMBNAIL_ROW = 0.4
THUMBNAIL_ROW_FROM = 3

#: Womit ein Player startet, wenn `play()` an der Autoplay-Sperre scheitert.
PLAY_BUTTON_SELECTORS = (
    ".ytp-large-play-button",
    ".vjs-big-play-button",
    "button.plyr__control--overlaid",
    '[class*="big-play"]',
    '[class*="play-button"]',
    '[class*="playButton"]',
    '[aria-label*="Abspielen" i]',
    '[aria-label*="Play" i]',
    '[title*="Abspielen" i]',
    '[title*="Play" i]',
)


class Clickable(Protocol):
    """Das Wenige, das wir von einem Playwright-Element brauchen."""

    def is_visible(self) -> bool: ...
    def inner_text(self) -> str: ...
    def click(self, **kwargs: Any) -> None: ...


class Scope(Protocol):
    """Seite oder Frame."""

    def query_selector_all(self, selector: str) -> list[Clickable]: ...


def _visible_elements(scope: Scope, selector: str) -> list[Clickable]:
    try:
        elements = scope.query_selector_all(selector)
    except Exception:
        return []
    visible: list[Clickable] = []
    for element in elements:
        try:
            if element.is_visible():
                visible.append(element)
        except Exception:
            continue
    return visible


def click_known_reject_button(scope: Scope, selectors: list[str]) -> str | None:
    """Klickt den ersten sichtbaren Ablehnen-Button einer bekannten CMP."""
    for selector in selectors:
        for element in _visible_elements(scope, selector):
            try:
                element.click(timeout=CLICK_TIMEOUT_MS)
                return selector
            except Exception:
                continue
    return None


def click_reject_by_text(scope: Scope, pattern: str) -> str | None:
    """Generischer Fallback: sichtbarer Button, dessen Text auf *pattern* passt."""
    if not pattern:
        return None
    regex = re.compile(pattern, re.IGNORECASE)
    for selector in ("button", '[role="button"]', "a.button", "input[type=button]"):
        for element in _visible_elements(scope, selector):
            try:
                label = (element.inner_text() or "").strip()
            except Exception:
                continue
            if not label or len(label) > 60 or not regex.search(label):
                continue
            try:
                element.click(timeout=CLICK_TIMEOUT_MS)
                return label
            except Exception:
                continue
    return None


def remove_overlays(page: Any, selectors: list[str]) -> int:
    """Entfernt Overlay-Knoten per JavaScript und loest die Scroll-Sperre."""
    try:
        return int(page.evaluate(REMOVE_OVERLAYS_JS, selectors) or 0)
    except Exception:
        return 0


def dismiss_consent(page: Any, rules: SiteRules | None = None) -> str:
    """Lehnt Consent ab oder raeumt das Overlay weg.

    Returns:
        `cmp:<selector>`, `text:<label>`, `removed:<n>` oder `nothing`.
    """
    rules = rules or load_rules()

    selector = click_known_reject_button(page, rules.cmp_reject_selectors)
    if selector:
        return f"cmp:{selector}"

    # Sourcepoint und Quantcast rendern ihren Dialog in einem iFrame.
    for frame in getattr(page, "frames", [])[1:]:
        selector = click_known_reject_button(frame, rules.cmp_reject_selectors)
        if selector:
            return f"cmp:{selector}"
        label = click_reject_by_text(frame, rules.reject_text_pattern)
        if label:
            return f"text:{label}"

    label = click_reject_by_text(page, rules.reject_text_pattern)
    if label:
        return f"text:{label}"

    # Kein Ablehnen-Button? Dann NICHT akzeptieren, sondern das Overlay
    # entfernen -- der Inhalt liegt fast immer schon im DOM.
    removed = remove_overlays(page, rules.overlay_remove_selectors)
    return f"removed:{removed}" if removed else "nothing"


def click_play_buttons(page: Any) -> int:
    """Klickt sichtbare Abspielknoepfe -- auf der Seite und in ihren iFrames.

    Nur noetig, wenn `play()` an der Autoplay-Sperre des Players scheitert.
    Ein eingebetteter Player (YouTube, Vimeo) liegt in einem eigenen Rahmen
    und ist von aussen nicht erreichbar.
    """
    geklickt = 0
    for scope in _playback_scopes(page):
        # Je Bereich hoechstens ein Klick: ein eingebetteter Player liegt in
        # seinem eigenen Rahmen und braucht seinen eigenen. Weiterklicken
        # wuerde nur noch die Seite bedienen.
        getroffen = False
        for selector in PLAY_BUTTON_SELECTORS:
            for element in _visible_elements(scope, selector):
                try:
                    element.click(timeout=CLICK_TIMEOUT_MS)
                except Exception:
                    continue
                geklickt += 1
                getroffen = True
                break
            if getroffen:
                break
    return geklickt


def _playback_scopes(page: Any) -> list[Any]:
    """Hauptseite und eingebettete Frames, ohne den Hauptrahmen doppelt."""
    scopes = [page]
    with contextlib.suppress(Exception):
        scopes.extend(list(getattr(page, "frames", []) or [])[1:])
    return scopes


def _zahl(wert: Any) -> int:
    """Eine Zaehlung aus dem Browser. Was keine ist, zaehlt als null.

    Das Skript liefert Zahlen -- aber es laeuft in einer fremden Seite, und
    eine Seite, die `document.images` ueberschreibt, darf die Aufnahme nicht
    mit einem Typfehler beenden.
    """
    try:
        return int(wert or 0)
    except (TypeError, ValueError):
        return 0


def _playback_states(page: Any, *, start: bool = False) -> list[dict[str, int]]:
    """Der Zustand jedes Bereichs einzeln -- Hauptseite zuerst.

    Einzeln und nicht aufsummiert, weil die Bereiche nichts miteinander zu
    tun haben: ein haengendes Werbebild in einem fremden Rahmen sagt nichts
    darueber, ob die Kamera schon da ist. Summiert man beides, blockiert das
    eine das andere.
    """
    stände: list[dict[str, int]] = []
    for scope in _playback_scopes(page):
        if start:
            with contextlib.suppress(Exception):
                scope.evaluate(START_PLAYBACK_JS)
        stand: Any = {}
        with contextlib.suppress(Exception):
            stand = scope.evaluate(PLAYBACK_STATE_JS) or {}
        if not isinstance(stand, dict):
            stand = {}
        stände.append(
            {feld: _zahl(stand.get(feld))
             for feld in ("videos", "playing", "images", "loaded")}
        )
    return stände


def pictures_ready(stände: list[dict[str, int]], seconds: float) -> bool:
    """Sind die Bilder so weit, dass sich ein Schuss lohnt?

    Drei Stufen, und die dritte ist die wichtige: ohne sie wartete eine
    Webcam-Seite mit einem einzigen haengenden Bild in einem Werberahmen das
    ganze Zeitlimit ab -- und das, obwohl auf der Hauptseite laengst alles
    stand.
    """
    # Ueber `.get` und nicht ueber den Index: die Funktion ist von aussen
    # aufrufbar, und ein Zustand ohne alle vier Felder soll sie nicht
    # abbrechen lassen. Was fehlt, zaehlt als null.
    def bilder(stand: dict[str, int]) -> int:
        return int(stand.get("images") or 0)

    def geladen(stand: dict[str, int]) -> int:
        return int(stand.get("loaded") or 0)

    offen = [stand for stand in stände if geladen(stand) < bilder(stand)]
    if not offen:
        return True
    if seconds <= PICTURE_GRACE_SECONDS:
        return False
    # Nach der Gnadenfrist reicht: irgendwo steht ein Bild, oder die
    # Hauptseite ist fuer sich fertig.
    return any(geladen(stand) for stand in stände) or (
        bool(stände) and geladen(stände[0]) >= bilder(stände[0])
    )


def wait_for_live_frame(page: Any, timeout_ms: int = PLAYBACK_TIMEOUT_MS) -> str:
    """Wartet, bis wirklich ein Bild da ist -- nicht nur der Ladebildschirm.

    Ein Player zeigt vor dem ersten Klick sein Vorschaubild, und das ist bei
    einer Webcam oft Stunden alt. Deshalb wird die Wiedergabe gestartet und
    erst abgedrueckt, wenn das Video dekodierte Daten hat und die Zeit laeuft.
    Seiten ohne Video (die meisten Webcams liefern ein sich erneuerndes Bild)
    gelten als fertig, sobald ihre Bilder geladen sind.

    Returns:
        `video`, `bild` oder `zeitlimit` -- nur fuer Tests und Protokoll.
    """
    import time as _time

    start = _time.monotonic()
    frist = start + max(timeout_ms, 1_000) / 1000
    stände = _playback_states(page, start=True)
    geklickt = False
    while _time.monotonic() < frist:
        verstrichen = _time.monotonic() - start
        videos = sum(stand["videos"] for stand in stände)
        if videos and sum(stand["playing"] for stand in stände):
            # Der erste Frame ist oft noch der gepufferte; eine Sekunde
            # Wiedergabe spaeter steht das aktuelle Bild.
            page.wait_for_timeout(PLAYBACK_SETTLE_MS)
            return "video"
        # Ein Video bekommt Vorrang -- aber nicht unbegrenzt. Springt es
        # auch nach der Frist nicht an, zaehlt wieder, was an Bildern da
        # ist: sonst haelt ein Werbevideo die Kamera daneben endlos auf.
        wartet_auf_video = bool(videos) and verstrichen <= VIDEO_GRACE_SECONDS
        if not wartet_auf_video and pictures_ready(stände, verstrichen):
            return "bild"
        # Erst warten, dann messen -- andersherum entscheidet die naechste
        # Runde auf einem Stand, der schon vierhundert Millisekunden alt ist.
        neu_starten = bool(videos) and not geklickt
        if neu_starten:
            geklickt = bool(click_play_buttons(page))
        page.wait_for_timeout(400)
        stände = _playback_states(page, start=neu_starten)
    return "zeitlimit"


def launch_args() -> list[str]:
    """Die Chromium-Argumente fuer den ERSTEN Versuch -- immer mit Browser-Sandbox."""
    return ["--disable-dev-shm-usage"]


def no_sandbox_allowed() -> bool:
    """Darf Chromium ohne eigene Sandbox starten, wenn es mit ihr nicht geht?

    `AQUATICY_BROWSER_NO_SANDBOX=1` erlaubt das -- im Container-Abbild gesetzt,
    wo Chromium ohne Benutzer-Namensraeume seine Sandbox nicht aufbauen kann
    (und die Container-Grenze die Trennung uebernimmt). Seit 9.5.15 ist es nur
    noch die Rueckfallebene: versucht wird immer zuerst MIT Sandbox.
    """
    flag = os.environ.get("AQUATICY_BROWSER_NO_SANDBOX", "").strip().lower()
    return flag in {"1", "true", "yes", "on", "ja"}


def launch_browser(playwright: Any, extra: list[str] | None = None) -> Any:
    """Startet Chromium -- mit Sandbox, und nur wo das nicht geht (und erlaubt ist) ohne."""
    zusatz = list(extra or [])
    try:
        return playwright.chromium.launch(headless=True, args=[*launch_args(), *zusatz])
    except Exception:
        if not no_sandbox_allowed():
            raise
        import logging

        logging.getLogger("aquaticy.browser").warning(
            "Chromium-Sandbox nicht verfuegbar -- Start ohne (AQUATICY_BROWSER_NO_SANDBOX)")
        return playwright.chromium.launch(headless=True, args=[*CONTAINER_ARGS, *zusatz])


def guard_context(context: Any) -> None:
    """Haengt die Netzregel an einen Browser-Kontext.

    Eine oeffentliche Seite koennte sonst ueber Rahmen, Skripte, Bilder oder
    WebSockets Adressen im internen Netz ansprechen -- der Browser liefe ja
    auf dem Server. Alles, was nicht oeffentlich ist, bricht der Browser ab.
    """
    from aquaticy import netguard

    context.route("**/*", netguard.browser_route)
    web_socket = getattr(context, "route_web_socket", None)
    if callable(web_socket):
        def _socket(ws: Any) -> None:
            ziel = str(getattr(ws, "url", "") or "")
            pruefen = ziel.replace("wss://", "https://", 1).replace("ws://", "http://", 1)
            if netguard.url_allowed(pruefen):
                ws.connect_to_server()
            else:
                ws.close()

        web_socket("**/*", _socket)


def playwright_available() -> bool:
    """Ist Playwright installiert?"""
    try:
        import playwright  # noqa: F401
    except ImportError:
        return False
    return True


def render_page(
    url: str,
    user_agent: str,
    timeout: float = 15.0,
    rules: SiteRules | None = None,
) -> str | None:
    """Rendert *url* im Browser und gibt das HTML nach dem Aufraeumen zurueck.

    Gibt `None` zurueck, wenn Playwright fehlt oder die Seite nicht laedt.
    """
    try:
        from playwright.sync_api import sync_playwright
    except ImportError:
        return None

    rules = rules or load_rules()
    timeout_ms = int(max(timeout, 5.0) * 1000)
    from aquaticy import netguard

    if not netguard.url_allowed(url):
        return None

    try:
        with sync_playwright() as playwright:
            browser = launch_browser(playwright)
            try:
                # Frischer Kontext je Abruf -- nichts wird uebernommen.
                context = browser.new_context(
                    user_agent=user_agent,
                    locale="de-DE",
                    permissions=[],  # Notifications, Geolocation & Co. verweigert
                    java_script_enabled=True,
                    accept_downloads=False,
                )
                context.grant_permissions([])
                context.set_default_timeout(timeout_ms)
                # Jede Anfrage des Browsers -- Seite, Rahmen, Skript, Bild --
                # nur an oeffentliche Ziele (aquaticy/netguard.py, seit 9.5.15).
                guard_context(context)
                page = context.new_page()
                page.goto(url, wait_until="domcontentloaded", timeout=timeout_ms)
                # Seiten mit Dauer-Polling werden nie "idle" -- das ist kein Fehler.
                with contextlib.suppress(Exception):
                    page.wait_for_load_state("networkidle", timeout=NETWORK_IDLE_TIMEOUT_MS)

                dismiss_consent(page, rules)
                # Nach dem Klick baut sich die Seite oft neu auf.
                with contextlib.suppress(Exception):
                    page.wait_for_load_state("networkidle", timeout=3_000)
                remove_overlays(page, rules.overlay_remove_selectors)

                html = page.content()
                context.close()
                return html
            finally:
                browser.close()
    except Exception:
        return None


def capture_visual(
    url: str,
    user_agent: str,
    timeout: float = 15.0,
    rules: SiteRules | None = None,
) -> tuple[bytes, str] | None:
    """Nimmt das laufende Bild einer dynamischen oeffentlichen Seite auf.

    Der Reihe nach: laden, Consent ablehnen, Overlays weg, **Wiedergabe
    starten und auf einen echten Frame warten**, dann abdruecken -- und zwar
    moeglichst nur das Live-Element selbst. Ohne den Wiedergabe-Schritt kam
    von einer Webcam das Vorschaubild des Players zurueck: ein Standbild aus
    dem Cache, oft Stunden alt, manchmal nur eine graue Flaeche mit
    Abspielknopf.
    """
    try:
        from playwright.sync_api import sync_playwright
    except ImportError:
        return None

    rules = rules or load_rules()
    timeout_ms = int(max(timeout, 5.0) * 1000)
    from aquaticy import netguard

    if not netguard.url_allowed(url):
        return None
    try:
        with sync_playwright() as playwright:
            # Ohne diese Freigabe verweigert Chromium jedes `play()` ohne
            # Mausklick -- und genau daran scheiterte die Live-Aufnahme.
            browser = launch_browser(
                playwright, ["--autoplay-policy=no-user-gesture-required", "--mute-audio"])
            try:
                context = browser.new_context(
                    user_agent=user_agent,
                    locale="de-DE",
                    permissions=[],
                    java_script_enabled=True,
                    accept_downloads=False,
                    viewport={"width": 1280, "height": 800},
                )
                context.grant_permissions([])
                context.set_default_timeout(timeout_ms)
                # Jede Anfrage des Browsers -- Seite, Rahmen, Skript, Bild --
                # nur an oeffentliche Ziele (aquaticy/netguard.py, seit 9.5.15).
                guard_context(context)
                page = context.new_page()
                page.goto(url, wait_until="domcontentloaded", timeout=timeout_ms)
                with contextlib.suppress(Exception):
                    page.wait_for_load_state("networkidle", timeout=NETWORK_IDLE_TIMEOUT_MS)
                dismiss_consent(page, rules)
                with contextlib.suppress(Exception):
                    page.wait_for_load_state("networkidle", timeout=3_000)
                remove_overlays(page, rules.overlay_remove_selectors)
                # Erst jetzt starten: vorher haette der Consent-Dialog den
                # Player verdeckt und jeder Klick haette den Dialog getroffen.
                with contextlib.suppress(Exception):
                    wait_for_live_frame(page, timeout_ms=PLAYBACK_TIMEOUT_MS)
                data = _shot(page)
                context.close()
                return (bytes(data), "image/jpeg") if data else None
            finally:
                browser.close()
    except Exception:
        return None


def _bewerte(vorher: list[dict[str, Any]], nachher: dict[int, dict[str, Any]],
             gleiche: dict[tuple[int, str], int]) -> int:
    """Welcher Kandidat ist das Livebild? Returns: seine Nummer, sonst -1.

    Die Groesse allein reicht nicht: eine Webcam-Seite zeigt gern eine Reihe
    Vorschaubilder und darunter das eigentliche Bild, und die Vorschau ist
    manchmal die groessere. Entscheidend ist, was sich bewegt -- ein Bild,
    das sich in der Wartezeit erneuert hat, ist live; ein Vorschaubild
    bleibt, wie es war.
    """
    bester, beste_punkte, beste_stufe = -1, 0.0, -1
    for eintrag in vorher:
        nummer = int(eintrag.get("index", -1))
        if nummer < 0:
            continue
        punkte = float(eintrag.get("area") or 0.0)
        if punkte <= 0:
            continue
        spaeter = nachher.get(nummer, {})
        alt_src = str(eintrag.get("src") or "")
        neu_src = str(spaeter.get("src") or alt_src)
        bewegt = (
            neu_src != alt_src
            or bool(spaeter.get("playing") or eintrag.get("playing"))
            # Ein Stream, der in ein Canvas gezeichnet wird, sieht von aussen
            # unbewegt aus -- er ist trotzdem eher das Ziel als ein Foto.
            or str(eintrag.get("tag")) == "CANVAS"
        )
        if eintrag.get("inLink"):
            punkte *= MALUS_IN_LINK
        reihe = (int(eintrag.get("frame") or 0), str(eintrag.get("key")))
        if gleiche.get(reihe, 0) >= THUMBNAIL_ROW_FROM:
            punkte *= MALUS_THUMBNAIL_ROW
        # Bewegung schlaegt Groesse, immer und unabhaengig davon, wie gross.
        # Dass ein Bild sich erneuert, ist ein Beweis; dass es gross ist, nur
        # eine Vermutung -- und ein grosses Vorschaubild ueber einer kleinen
        # Live-Ansicht ist genau der Fall, in dem die Vermutung danebenliegt.
        stufe = 1 if bewegt else 0
        if stufe > beste_stufe or (stufe == beste_stufe and punkte > beste_punkte):
            bester, beste_punkte, beste_stufe = nummer, punkte, stufe
    return bester


def _image_candidates(page: Any) -> tuple[list[dict[str, Any]], dict[int, tuple[Any, int]]]:
    """Sammelt Kandidaten mit eindeutigen Kennungen ueber alle Frames hinweg."""
    candidates: list[dict[str, Any]] = []
    origins: dict[int, tuple[Any, int]] = {}
    for rahmen, scope in enumerate(_playback_scopes(page)):
        found: Any = []
        with contextlib.suppress(Exception):
            found = scope.evaluate(MARK_CANDIDATES_JS) or []
        if not isinstance(found, list):
            continue
        for item in found:
            if not isinstance(item, dict):
                continue
            local_index = int(item.get("index", -1))
            if local_index < 0:
                continue
            index = len(candidates)
            origins[index] = (scope, local_index)
            # Die Rahmennummer bleibt am Kandidaten haengen: gleich grosse
            # Bilder sind nur INNERHALB eines Dokuments ein Hinweis auf eine
            # Vorschaureihe. Ueber Rahmen hinweg ist dieselbe Groesse normal
            # -- es ist derselbe Einbau, nur mehrfach.
            candidates.append({**item, "index": index, "frame": rahmen})
    return candidates, origins


def _rescan_images(origins: dict[int, tuple[Any, int]]) -> dict[int, dict[str, Any]]:
    """Liest jeden Frame einmal und ordnet seine lokalen Kennungen wieder zu."""
    scans: dict[int, dict[int, dict[str, Any]]] = {}
    result: dict[int, dict[str, Any]] = {}
    for index, (scope, local_index) in origins.items():
        key = id(scope)
        if key not in scans:
            found: Any = []
            with contextlib.suppress(Exception):
                found = scope.evaluate(RESCAN_CANDIDATES_JS) or []
            scans[key] = {
                int(item.get("index", -1)): item
                for item in (found if isinstance(found, list) else [])
                if isinstance(item, dict)
            }
        result[index] = scans[key].get(local_index, {})
    return result


def _shot(page: Any) -> bytes:
    """Fotografiert das Live-Element -- oder, wenn es keines gibt, die Seite.

    Ein Ausschnitt des Videos zeigt das, worum es geht. Das ganze Fenster
    zeigt zusaetzlich Kopfzeile, Werbung und Bedienleiste, und genau die
    verwirren ein Bildmodell.
    """
    vorher, origins = _image_candidates(page)
    if vorher:
        with contextlib.suppress(Exception):
            page.wait_for_timeout(RESCAN_WAIT_MS)
        nachher = _rescan_images(origins)
        gleiche: dict[tuple[int, str], int] = {}
        for eintrag in vorher:
            if isinstance(eintrag, dict):
                schluessel = (int(eintrag.get("frame") or 0), str(eintrag.get("key")))
                gleiche[schluessel] = gleiche.get(schluessel, 0) + 1
        gewaehlt = _bewerte(
            [item for item in vorher if isinstance(item, dict)], nachher, gleiche
        )
        if gewaehlt >= 0:
            scope, local_index = origins[gewaehlt]
            anteil = 0.0
            with contextlib.suppress(Exception):
                anteil = float(scope.evaluate(PICK_CANDIDATE_JS, local_index) or 0.0)
            # Nach dem Scrollen steht das Element mittig im Fenster. Ist es
            # trotzdem winzig, ist die ganze Ansicht die ehrlichere Auskunft.
            if anteil >= 0.08:
                with contextlib.suppress(Exception):
                    element = scope.query_selector(f'[data-aquaticy-cand="{local_index}"]')
                    if element is not None:
                        return bytes(element.screenshot(type="jpeg", quality=80))
    with contextlib.suppress(Exception):
        return bytes(page.screenshot(type="jpeg", quality=78, full_page=False))
    return b""
