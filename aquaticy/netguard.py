"""Eine Regel fuer alles, was Aquaticy im Auftrag fremder Inhalte abruft (seit 9.5.15).

Webseiten, ihre ``robots.txt``, Bilder aus JSON-LD oder OpenGraph, Feeds,
Exporte, der Browser: Adressen, die aus dem Netz kommen, duerfen nie auf den
Server selbst oder in ein privates Netz zeigen -- sonst liest eine praeparierte
Seite ueber Aquaticy den Router, den Metadaten-Dienst der Cloud oder die eigene
Verwaltungsoberflaeche aus (SSRF). Bis 9.5.14 prueften das nur einzelne Wege,
jeder auf seine Art; Weiterleitungen und ``robots.txt`` gar nicht.

Die Regel, einmal fuer alle:

* nur ``http`` und ``https``;
* der Name wird aufgeloest, und JEDE Adresse muss oeffentlich sein -- kein
  Loopback, kein privates Netz, kein Link-Local (169.254.x, auch der
  Metadaten-Dienst), kein CGNAT/Tailscale, kein Multicast, keine
  reservierten Bereiche; IPv4 in IPv6 verpackt zaehlt wie IPv4;
* geprueft wird VOR jedem Schritt, also auch vor jeder Weiterleitung;
* der Verbindungsaufbau prueft noch einmal und verbindet genau mit der
  gepruefte Adresse (``guarded_transport``) -- ein Name, der zwischen
  Pruefung und Abruf auf eine interne Adresse umspringt, kommt so nicht durch;
* Antworten werden gestreamt und abgebrochen, sobald sie die Grenze
  ueberschreiten -- nicht erst komplett geladen und dann gewogen.

Was bewusst NICHT hierueber laeuft: Ziele, die ein Mensch selbst eingetragen
hat und die privat sein sollen -- das eigene Heimnetz (LAN-Suche, Pro), Home
Assistant, die Lagerverwaltung, ein eigenes Ollama oder SearXNG. Die haben ihre
eigenen, engeren Regeln.
"""

from __future__ import annotations

import contextlib
import ipaddress
import re
import socket
import threading
import time
from collections.abc import Callable, Iterator
from contextlib import contextmanager
from typing import Any
from urllib.parse import urljoin

import httpcore
import httpx

__all__ = [
    "BlockedTarget",
    "TooLarge",
    "check_url",
    "get",
    "guarded_client",
    "guarded_transport",
    "host_problem",
    "ip_allowed",
    "resolve",
    "url_allowed",
    "url_problem",
]

#: Namen, die nie nach draussen zeigen -- auch ohne Namensaufloesung.
BLOCKED_NAMES = frozenset({
    "localhost", "localhost.localdomain", "ip6-localhost", "ip6-loopback",
    "metadata", "metadata.google.internal", "instance-data",
})
BLOCKED_SUFFIXES = (".localhost", ".local", ".internal", ".lan", ".home.arpa", ".intranet")

#: Wie lange eine Entscheidung ueber einen Namen gilt (der Browser fragt fuer
#: jedes Bild einer Seite -- ohne Merken waeren das hundert DNS-Anfragen).
DECISION_TTL = 30.0

_decisions: dict[tuple[str, int], tuple[float, str]] = {}
_decisions_lock = threading.Lock()


class BlockedTarget(httpx.ConnectError):
    """Das Ziel ist nicht oeffentlich -- dorthin wird nicht verbunden."""


class TooLarge(httpx.HTTPError):
    """Die Antwort ist groesser als erlaubt -- abgebrochen, bevor sie ganz da war."""

    def __init__(self, message: str) -> None:
        super().__init__(message)


def resolve(host: str, port: int | None) -> list[str]:
    """Alle Adressen eines Namens -- in der Reihenfolge des Systems.

    Eigene Funktion, damit Tests sie ersetzen koennen. Bis 9.5.15 wurde hier
    alphabetisch sortiert, und verbunden wurde nur mit der ersten: auf einem
    Server ohne IPv6 scheiterte damit jede Seite, deren IPv6-Adresse vorne
    stand (golem.de) -- obwohl eine IPv4-Adresse da war.
    """
    infos = socket.getaddrinfo(host, port or 443, type=socket.SOCK_STREAM)
    return list(dict.fromkeys(str(info[4][0]) for info in infos))


def ip_allowed(value: str) -> bool:
    """Ist diese Adresse oeffentlich im Internet -- und nichts anderes?"""
    try:
        ip = ipaddress.ip_address(str(value).split("%", 1)[0])
    except ValueError:
        return False
    if isinstance(ip, ipaddress.IPv6Address):
        if ip.ipv4_mapped is not None:
            ip = ip.ipv4_mapped
        elif ip.sixtofour is not None:
            if not ip_allowed(str(ip.sixtofour)):
                return False
        elif ip.teredo is not None:
            return False
    return bool(ip.is_global) and not (ip.is_multicast or ip.is_reserved or ip.is_loopback
                                       or ip.is_link_local or ip.is_private)


def _numeric_ipv4(name: str) -> str:
    """Eine IPv4-Adresse in Kurz-, Hex- oder Zahlschreibweise -- sonst ""."""
    if not re.fullmatch(r"[0-9a-fx.]+", name) or not any(z.isdigit() for z in name):
        return ""
    try:
        return socket.inet_ntoa(socket.inet_aton(name))
    except OSError:
        return ""


def checked_addresses(host: str, port: int | None) -> list[str]:
    """Die Adressen, mit denen fuer *host* verbunden werden darf -- EINMAL aufgeloest.

    Wer verbindet, nimmt genau diese Liste: kein zweites Nachschlagen, bei dem
    der Name inzwischen auf eine interne Adresse zeigen koennte.

    Raises:
        BlockedTarget: Der Name ist gesperrt, laesst sich nicht aufloesen, oder
            wenigstens eine seiner Adressen ist nicht oeffentlich.
    """
    name = host.strip().strip("[]").rstrip(".").lower()
    if not name:
        raise BlockedTarget("Die Adresse hat keinen Rechnernamen.")
    if name in BLOCKED_NAMES or name.endswith(BLOCKED_SUFFIXES):
        raise BlockedTarget(f"{name} ist kein öffentliches Ziel.")
    try:
        ipaddress.ip_address(name.split("%", 1)[0])
    except ValueError:
        pass
    else:
        if not ip_allowed(name):
            raise BlockedTarget(f"{name} ist keine öffentliche Adresse.")
        return [name]
    kurz = _numeric_ipv4(name)
    if kurz:
        # "127.1", "0x7f.0.0.1", "2130706433" -- alles 127.0.0.1 in anderer Schreibweise.
        if not ip_allowed(kurz):
            raise BlockedTarget(f"{name} ist keine öffentliche Adresse.")
        return [kurz]
    try:
        adressen = resolve(name, port)
    except (OSError, UnicodeError):
        raise BlockedTarget(f"{name} lässt sich nicht auflösen.") from None
    if not adressen:
        raise BlockedTarget(f"{name} lässt sich nicht auflösen.")
    if not all(ip_allowed(a) for a in adressen):
        raise BlockedTarget(f"{name} zeigt auf eine nicht öffentliche Adresse.")
    return adressen


def _decide(host: str, port: int) -> str:
    """Warum *host* nicht in Frage kommt -- "" wenn er darf. Ohne Merken."""
    try:
        checked_addresses(host, port)
    except BlockedTarget as exc:
        return str(exc)
    return ""


def host_problem(host: str, port: int | None = None) -> str:
    """Warum *host* nicht abgerufen werden darf -- "" wenn er darf (kurz gemerkt)."""
    schluessel = (host.strip().lower(), int(port or 0))
    jetzt = time.monotonic()
    with _decisions_lock:
        bekannt = _decisions.get(schluessel)
        if bekannt and bekannt[0] > jetzt:
            return bekannt[1]
    entscheidung = _decide(host, int(port or 443))
    with _decisions_lock:
        if len(_decisions) > 4096:
            _decisions.clear()
        _decisions[schluessel] = (jetzt + DECISION_TTL, entscheidung)
    return entscheidung


def forget() -> None:
    """Gemerkte Entscheidungen vergessen -- fuer Tests."""
    with _decisions_lock:
        _decisions.clear()


def url_problem(url: str) -> str:
    """Warum *url* nicht abgerufen werden darf -- "" wenn sie darf."""
    try:
        ziel = httpx.URL(str(url or "").strip())
    except (httpx.InvalidURL, TypeError, ValueError):
        return "Die Adresse ist ungültig."
    if ziel.scheme not in ("http", "https"):
        return "Nur http- und https-Adressen werden abgerufen."
    if not ziel.host:
        return "Die Adresse hat keinen Rechnernamen."
    return host_problem(ziel.host, ziel.port or (443 if ziel.scheme == "https" else 80))


def url_allowed(url: str) -> bool:
    return not url_problem(url)


def check_url(url: str, request: httpx.Request | None = None) -> None:
    """Wirft ``BlockedTarget``, wenn *url* nicht oeffentlich ist."""
    problem = url_problem(url)
    if problem:
        raise BlockedTarget(problem, request=request)


# -- Verbindungsaufbau: nur zu gepruften Adressen ----------------------------------------
# -- Ein vorgeschalteter Proxy (seit 9.5.16) ---------------------------------------------
def upstream_proxy() -> tuple[str, int, str] | None:
    """Der Proxy, ueber den Aquaticy nach draussen geht -- oder None (direkt).

    ``AQUATICY_PROXY`` bestimmt es: leer = direkt (wie bisher), ``env`` = der
    Proxy aus ``HTTPS_PROXY``/``HTTP_PROXY``, sonst eine Adresse wie
    ``http://proxy.firma.de:3128`` (auch mit ``benutzer:passwort@``).

    Bis 9.5.15 ging ein Abruf hinter einem Firmen-Proxy gar nicht: der eigene
    Transport kannte keinen. Verbunden wird trotzdem nur mit der hier
    geprueften Adresse -- der Proxy bekommt ``CONNECT <adresse>:<port>``, nicht
    den Namen, und kann ihn deshalb nicht selbst anders aufloesen.
    """
    import os
    from urllib.parse import unquote, urlsplit

    wert = os.environ.get("AQUATICY_PROXY", "").strip()
    if not wert or wert.lower() in {"0", "false", "nein", "aus", "off", "direkt"}:
        return None
    if wert.lower() == "env":
        wert = next((os.environ.get(n, "").strip() for n in
                     ("HTTPS_PROXY", "https_proxy", "HTTP_PROXY", "http_proxy", "ALL_PROXY",
                      "all_proxy") if os.environ.get(n, "").strip()), "")
        if not wert:
            return None
    teile = urlsplit(wert if "://" in wert else f"http://{wert}")
    if teile.scheme != "http" or not teile.hostname:
        return None
    anmeldung = ""
    if teile.username:
        import base64

        roh = f"{unquote(teile.username)}:{unquote(teile.password or '')}".encode()
        anmeldung = base64.b64encode(roh).decode("ascii")
    return teile.hostname, teile.port or 3128, anmeldung


def _connect_request(adresse: str, port: int, anmeldung: str) -> bytes:
    ziel = f"[{adresse}]:{port}" if ":" in adresse else f"{adresse}:{port}"
    zeilen = [f"CONNECT {ziel} HTTP/1.1", f"Host: {ziel}"]
    if anmeldung:
        zeilen.append(f"Proxy-Authorization: Basic {anmeldung}")
    return ("\r\n".join(zeilen) + "\r\n\r\n").encode("ascii")


def _connect_answer_ok(kopf: bytes) -> bool:
    erste = kopf.split(b"\r\n", 1)[0].split()
    return len(erste) >= 2 and erste[1] == b"200"


class _GuardedBackend(httpcore.SyncBackend):
    """Verbindet nur mit oeffentlichen Adressen -- und genau mit der geprueften.

    httpcore loest den Namen sonst selbst noch einmal auf. Ein Name, der
    zwischen Pruefung und Abruf umspringt (DNS-Rebinding), landete dann doch
    intern. Hier wird beim Verbinden EINMAL aufgeloest, jede Adresse geprueft
    und der Reihe nach verbunden, bis eine antwortet (seit 9.5.16 -- vorher
    nur mit der ersten, ohne Rueckfall); TLS prueft weiter gegen den Namen aus
    der Adresse. Mit ``AQUATICY_PROXY`` geht der Weg durch den Proxy, aber
    ebenfalls nur zur geprueften Adresse.
    """

    def connect_tcp(self, host: str, port: int, timeout: float | None = None,
                    local_address: str | None = None,
                    socket_options: Any = None) -> httpcore.NetworkStream:
        try:
            adressen = checked_addresses(host, port)
        except BlockedTarget as exc:
            raise httpcore.ConnectError(str(exc)) from None
        proxy = upstream_proxy()
        fehler: Exception | None = None
        for adresse in adressen:
            try:
                if proxy is None:
                    return super().connect_tcp(adresse, port, timeout=timeout,
                                               local_address=local_address,
                                               socket_options=socket_options)
                return self._through_proxy(proxy, adresse, port, timeout, socket_options)
            except (httpcore.ConnectError, httpcore.ConnectTimeout) as exc:
                fehler = exc
        assert fehler is not None
        raise fehler

    def _through_proxy(self, proxy: tuple[str, int, str], adresse: str, port: int,
                       timeout: float | None, socket_options: Any) -> httpcore.NetworkStream:
        stream = super().connect_tcp(proxy[0], proxy[1], timeout=timeout,
                                     socket_options=socket_options)
        try:
            stream.write(_connect_request(adresse, port, proxy[2]), timeout=timeout)
            kopf = b""
            while b"\r\n\r\n" not in kopf and len(kopf) < 16_384:
                stueck = stream.read(4096, timeout=timeout)
                if not stueck:
                    break
                kopf += stueck
        except Exception:
            stream.close()
            raise
        if not _connect_answer_ok(kopf):
            stream.close()
            raise httpcore.ConnectError("Der Proxy hat die Verbindung abgelehnt.")
        return stream


def guarded_transport(**kwargs: Any) -> httpx.HTTPTransport:
    """Ein ``HTTPTransport``, der nur zu oeffentlichen Adressen verbindet."""
    transport = httpx.HTTPTransport(**kwargs)
    pool = getattr(transport, "_pool", None)
    if pool is not None and hasattr(pool, "_network_backend"):
        pool._network_backend = _GuardedBackend()
    return transport


def _request_hook(request: httpx.Request) -> None:
    check_url(str(request.url), request)


def guarded_client(**kwargs: Any) -> httpx.Client:
    """Ein Client fuer fremde Adressen: jede Anfrage -- auch jede Weiterleitung --
    wird vor dem Senden geprueft, und verbunden wird nur mit oeffentlichen Adressen.
    """
    haken = dict(kwargs.pop("event_hooks", {}) or {})
    haken["request"] = [_request_hook, *haken.get("request", [])]
    kwargs.setdefault("transport", guarded_transport())
    return httpx.Client(event_hooks=haken, **kwargs)


# -- Abrufen mit Grenze ---------------------------------------------------------------------
Limit = int | Callable[[httpx.Headers], tuple[int, bool]]


def _grenze(limit: Limit, headers: httpx.Headers) -> tuple[int, bool]:
    return limit(headers) if callable(limit) else (int(limit), False)


def _lesen(response: httpx.Response, limit: Limit) -> bytes:
    """Liest hoechstens bis zur Grenze. Returns: die Bytes (bei "abschneiden" gekuerzt).

    Raises:
        TooLarge: groesser als erlaubt, und abschneiden ist nicht erlaubt.
    """
    obergrenze, abschneiden = _grenze(limit, response.headers)
    angekuendigt = response.headers.get("content-length", "")
    if angekuendigt.isdigit() and int(angekuendigt) > obergrenze and not abschneiden:
        raise TooLarge(f"Die Antwort ist zu groß (mehr als {obergrenze // 1_000_000} MB).")
    teile: list[bytes] = []
    menge = 0
    for stueck in response.iter_bytes():
        menge += len(stueck)
        if menge > obergrenze:
            if not abschneiden:
                raise TooLarge(
                    f"Die Antwort ist zu groß (mehr als {obergrenze // 1_000_000} MB).")
            teile.append(stueck[: len(stueck) - (menge - obergrenze)])
            break
        teile.append(stueck)
    return b"".join(teile)


#: Kopfzeilen, die nach dem Auspacken nicht mehr stimmen.
_WEG = frozenset({"content-encoding", "content-length", "transfer-encoding"})


def get(
    client: httpx.Client,
    url: str,
    *,
    max_bytes: Limit,
    follow_redirects: bool = True,
    max_redirects: int = 5,
    headers: dict[str, str] | None = None,
    timeout: Any = httpx.USE_CLIENT_DEFAULT,
) -> httpx.Response:
    """GET mit derselben Regel fuer jeden Schritt.

    Jede Adresse -- die erste und jede Weiterleitung -- wird vor dem Abruf
    geprueft. Die Antwort wird gestreamt und bei Ueberschreiten der Grenze
    abgebrochen. Mit ``follow_redirects=False`` kommt eine Weiterleitung als
    solche zurueck (ohne Inhalt).

    Raises:
        BlockedTarget: ein Schritt zeigt nicht ins oeffentliche Netz.
        TooLarge: die Antwort ueberschreitet die Grenze.
        httpx.TooManyRedirects: zu viele Weiterleitungen.
        httpx.HTTPError: alles andere, wie gewohnt.
    """
    aktuell = str(url)
    for _ in range(max(0, int(max_redirects)) + 1):
        check_url(aktuell)
        with client.stream("GET", aktuell, headers=headers, timeout=timeout,
                           follow_redirects=False) as antwort:
            if antwort.is_redirect and follow_redirects:
                ziel = antwort.headers.get("location", "")
                if not ziel:
                    raise httpx.RemoteProtocolError("Weiterleitung ohne Ziel.",
                                                    request=antwort.request)
                aktuell = urljoin(str(antwort.url), ziel)
                continue
            inhalt = b"" if antwort.is_redirect else _lesen(antwort, max_bytes)
            kopf = [(k, v) for k, v in antwort.headers.multi_items() if k.lower() not in _WEG]
            fertig = httpx.Response(antwort.status_code, headers=kopf, content=inhalt,
                                    request=antwort.request)
            return fertig
    raise httpx.TooManyRedirects("Zu viele Weiterleitungen.", request=None)


@contextmanager
def image_client(timeout: float = 15.0, user_agent: str = "") -> Iterator[httpx.Client]:
    """Ein abgesicherter Client fuer Bilder aus fremden Seiten (Export, Terminal)."""
    kopf = {"User-Agent": user_agent} if user_agent else {}
    client = guarded_client(timeout=timeout, headers=kopf, follow_redirects=False)
    try:
        yield client
    finally:
        client.close()


def browser_route(route: Any) -> None:
    """Fuer Playwright: jede Anfrage des Browsers -- Seite, Rahmen, Skript, Bild --
    geht nur an oeffentliche Ziele. ``data:``/``blob:`` bleiben im Browser.
    """
    adresse = str(getattr(route.request, "url", "") or "")
    if adresse.startswith(("data:", "blob:", "about:")):
        route.continue_()
        return
    if url_allowed(adresse):
        route.continue_()
    else:
        route.abort("blockedbyclient")


# -- Der Browser hinter der Netzregel (seit 9.5.16) ------------------------------------------
#: So lange darf eine Verbindung des Browsers still sein, bevor sie endet.
PROXY_IDLE = 60.0
#: So lange darf der Verbindungsaufbau zu einem Ziel dauern.
PROXY_CONNECT_TIMEOUT = 15.0
#: Groesser ist kein Anfragekopf.
PROXY_MAX_HEAD = 65_536


def _lies_kopf(sock: socket.socket) -> tuple[bytes, bytes]:
    """Liest bis zur Leerzeile. Returns: (Kopf ohne Leerzeile, was danach schon kam)."""
    daten = b""
    while b"\r\n\r\n" not in daten:
        stueck = sock.recv(8192)
        if not stueck:
            raise ValueError("Verbindung vor dem Ende des Kopfes geschlossen.")
        daten += stueck
        if len(daten) > PROXY_MAX_HEAD:
            raise ValueError("Anfragekopf zu gross.")
    kopf, _, rest = daten.partition(b"\r\n\r\n")
    return kopf, rest


def _ziel_und_port(text: str, standard: int) -> tuple[str, int]:
    if text.startswith("["):
        host, _, rest = text[1:].partition("]")
        port = rest[1:] if rest.startswith(":") else ""
    else:
        host, _, port = text.rpartition(":") if text.count(":") == 1 else (text, "", "")
        if not host:
            host, port = text, ""
    zahl = int(port) if port.isdigit() else standard
    if not host or not 0 < zahl < 65536:
        raise ValueError("Ungültiges Ziel.")
    return host, zahl


def open_checked(host: str, port: int) -> socket.socket:
    """Eine TCP-Verbindung zu *host* -- nur zu einer geprueften, oeffentlichen Adresse.

    Einmal aufgeloest, jede Adresse geprueft, der Reihe nach versucht; mit
    ``AQUATICY_PROXY`` durch den Proxy, aber auch dort nur zur geprueften Adresse.

    Raises:
        BlockedTarget: nicht oeffentlich.
        OSError: nicht erreichbar.
    """
    adressen = checked_addresses(host, port)
    proxy = upstream_proxy()
    fehler: OSError | None = None
    for adresse in adressen:
        try:
            if proxy is None:
                return socket.create_connection((adresse, port), timeout=PROXY_CONNECT_TIMEOUT)
            sock = socket.create_connection((proxy[0], proxy[1]), timeout=PROXY_CONNECT_TIMEOUT)
            try:
                sock.sendall(_connect_request(adresse, port, proxy[2]))
                kopf, _ = _lies_kopf(sock)
            except (OSError, ValueError) as exc:
                sock.close()
                raise OSError(f"Proxy: {exc}") from exc
            if not _connect_answer_ok(kopf):
                sock.close()
                raise OSError("Der Proxy hat die Verbindung abgelehnt.")
            return sock
        except OSError as exc:
            fehler = exc
    raise fehler or OSError(f"{host} ist nicht erreichbar.")


def _weiterreichen(a: socket.socket, b: socket.socket) -> None:
    """Reicht Bytes in beide Richtungen durch, bis eine Seite schliesst oder schweigt."""
    import selectors

    auswahl = selectors.DefaultSelector()
    try:
        auswahl.register(a, selectors.EVENT_READ, b)
        auswahl.register(b, selectors.EVENT_READ, a)
        while True:
            ereignisse = auswahl.select(timeout=PROXY_IDLE)
            if not ereignisse:
                return
            for schluessel, _ in ereignisse:
                quelle: socket.socket = schluessel.fileobj  # type: ignore[assignment]
                daten = quelle.recv(65_536)
                if not daten:
                    return
                schluessel.data.sendall(daten)
    except OSError:
        return
    finally:
        auswahl.close()


class BrowserProxy:
    """Ein kleiner Proxy auf 127.0.0.1, ueber den Chromium ALLES laedt.

    Bis 9.5.15 pruefte die Netzregel die Adresse einer Browser-Anfrage vorab
    (``browser_route``) -- und Chromium loeste den Namen danach selbst noch
    einmal auf. Ein Name, der dazwischen auf eine interne Adresse umsprang
    (DNS-Rebinding), erreichte so doch den Server selbst oder das Heimnetz.

    Jetzt loest Chromium gar nichts mehr auf: jede Verbindung geht an diesen
    Proxy, und der loest EINMAL auf, prueft jede Adresse und verbindet genau
    mit der geprueften (:func:`open_checked`). HTTPS bleibt Ende-zu-Ende
    verschluesselt (``CONNECT``); der Proxy sieht nur Name und Port.
    """

    def __init__(self) -> None:
        self._sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self._sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self._sock.bind(("127.0.0.1", 0))
        self._sock.listen(128)
        self._sock.settimeout(1.0)
        self.port: int = self._sock.getsockname()[1]
        self.open = True
        #: Wie viele Verbindungen abgewiesen wurden -- fuer Tests und Protokoll.
        self.blocked = 0
        threading.Thread(target=self._annehmen, name="aquaticy-browserproxy",
                         daemon=True).start()

    @property
    def server(self) -> str:
        return f"http://127.0.0.1:{self.port}"

    def close(self) -> None:
        self.open = False
        with contextlib.suppress(OSError):
            self._sock.close()

    def _annehmen(self) -> None:
        while self.open:
            try:
                kunde, _ = self._sock.accept()
            except TimeoutError:
                continue
            except OSError:
                return
            threading.Thread(target=self._bedienen, args=(kunde,), daemon=True).start()

    @staticmethod
    def _antwort(kunde: socket.socket, status: str) -> None:
        with contextlib.suppress(OSError):
            kunde.sendall(f"HTTP/1.1 {status}\r\nContent-Length: 0\r\n"
                          "Connection: close\r\n\r\n".encode("ascii"))

    def _bedienen(self, kunde: socket.socket) -> None:
        ober: socket.socket | None = None
        try:
            kunde.settimeout(PROXY_IDLE)
            kopf, rest = _lies_kopf(kunde)
            zeile, _, kopfzeilen = kopf.partition(b"\r\n")
            teile = zeile.decode("latin-1").split()
            if len(teile) != 3:
                self._antwort(kunde, "400 Bad Request")
                return
            methode, ziel, version = teile
            if methode.upper() == "CONNECT":
                host, port = _ziel_und_port(ziel, 443)
                ober = open_checked(host, port)
                kunde.sendall(b"HTTP/1.1 200 Connection Established\r\n\r\n")
                if rest:
                    ober.sendall(rest)
            else:
                from urllib.parse import urlsplit

                adresse = urlsplit(ziel)
                if adresse.scheme != "http" or not adresse.hostname:
                    self._antwort(kunde, "400 Bad Request")
                    return
                pfad = (adresse.path or "/") + (f"?{adresse.query}" if adresse.query else "")
                weg = (b"proxy-connection:", b"proxy-authorization:", b"connection:",
                       b"keep-alive:")
                behalten = [z for z in kopfzeilen.split(b"\r\n")
                            if z and not z.lower().startswith(weg)]
                anfrage = (f"{methode} {pfad} {version}\r\n".encode("latin-1")
                           + b"".join(z + b"\r\n" for z in behalten)
                           + b"Connection: close\r\n\r\n")
                ober = open_checked(adresse.hostname, adresse.port or 80)
                ober.sendall(anfrage + rest)
            ober.settimeout(PROXY_IDLE)
            _weiterreichen(kunde, ober)
        except BlockedTarget:
            self.blocked += 1
            self._antwort(kunde, "403 Forbidden")
        except (OSError, ValueError, UnicodeError):
            self._antwort(kunde, "502 Bad Gateway")
        finally:
            for s in (ober, kunde):
                if s is not None:
                    with contextlib.suppress(OSError):
                        s.close()


_browser_proxy: BrowserProxy | None = None
_browser_proxy_lock = threading.Lock()


def browser_proxy() -> BrowserProxy:
    """Der gemeinsame Browser-Proxy dieses Prozesses (beim ersten Aufruf gestartet)."""
    global _browser_proxy
    with _browser_proxy_lock:
        if _browser_proxy is None or not _browser_proxy.open:
            _browser_proxy = BrowserProxy()
        return _browser_proxy


#: Was Chromium zusaetzlich braucht, damit wirklich alles ueber den Proxy geht:
#: WebRTC nimmt sonst UDP an ihm vorbei (STUN/TURN zu beliebigen Adressen).
BROWSER_NET_ARGS: tuple[str, ...] = (
    "--force-webrtc-ip-handling-policy=disable_non_proxied_udp",
    "--webrtc-ip-handling-policy=disable_non_proxied_udp",
    "--dns-prefetch-disable",
)


def browser_launch_options() -> dict[str, Any]:
    """``proxy=`` fuer ``chromium.launch``: alles ueber den Proxy, auch Loopback."""
    return {"server": browser_proxy().server, "bypass": "<-loopback>"}
