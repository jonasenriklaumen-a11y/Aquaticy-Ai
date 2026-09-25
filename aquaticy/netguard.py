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
    """Alle Adressen eines Namens. Eigene Funktion, damit Tests sie ersetzen koennen."""
    infos = socket.getaddrinfo(host, port or 443, type=socket.SOCK_STREAM)
    return sorted({str(info[4][0]) for info in infos})


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


def _decide(host: str, port: int) -> str:
    """Warum *host* nicht in Frage kommt -- "" wenn er darf. Ohne Merken."""
    name = host.strip().strip("[]").rstrip(".").lower()
    if not name:
        return "Die Adresse hat keinen Rechnernamen."
    if name in BLOCKED_NAMES or name.endswith(BLOCKED_SUFFIXES):
        return f"{name} ist kein öffentliches Ziel."
    try:
        ipaddress.ip_address(name.split("%", 1)[0])
    except ValueError:
        pass
    else:
        return "" if ip_allowed(name) else f"{name} ist keine öffentliche Adresse."
    kurz = _numeric_ipv4(name)
    if kurz:
        # "127.1", "0x7f.0.0.1", "2130706433" -- alles 127.0.0.1 in anderer Schreibweise.
        return "" if ip_allowed(kurz) else f"{name} ist keine öffentliche Adresse."
    try:
        adressen = resolve(name, port)
    except (OSError, UnicodeError):
        return f"{name} lässt sich nicht auflösen."
    if not adressen:
        return f"{name} lässt sich nicht auflösen."
    intern = [a for a in adressen if not ip_allowed(a)]
    if intern:
        return f"{name} zeigt auf eine nicht öffentliche Adresse."
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
class _GuardedBackend(httpcore.SyncBackend):
    """Verbindet nur mit oeffentlichen Adressen -- und genau mit der geprueften.

    httpcore loest den Namen sonst selbst noch einmal auf. Ein Name, der
    zwischen Pruefung und Abruf umspringt (DNS-Rebinding), landete dann doch
    intern. Hier wird beim Verbinden aufgeloest, jede Adresse geprueft und mit
    der ersten verbunden; TLS prueft weiter gegen den Namen aus der Adresse.
    """

    def connect_tcp(self, host: str, port: int, timeout: float | None = None,
                    local_address: str | None = None,
                    socket_options: Any = None) -> httpcore.NetworkStream:
        name = host.strip("[]")
        try:
            ipaddress.ip_address(name.split("%", 1)[0])
            adressen = [name]
        except ValueError:
            try:
                adressen = resolve(name, port)
            except OSError as exc:
                raise httpcore.ConnectError(f"{name} lässt sich nicht auflösen.") from exc
        if not adressen or not all(ip_allowed(a) for a in adressen):
            raise httpcore.ConnectError(f"{name} zeigt auf eine nicht öffentliche Adresse.")
        return super().connect_tcp(adressen[0], port, timeout=timeout,
                                   local_address=local_address,
                                   socket_options=socket_options)


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
