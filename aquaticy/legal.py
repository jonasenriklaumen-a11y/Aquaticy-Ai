"""Transparente Rechtstexte fuer die selbst gehostete Weboberflaeche.

Die Seiten beschreiben nur Verhalten, das im Code nachpruefbar ist.
"""

from __future__ import annotations

LEGAL_VERSION = "2026-10-04.3"
LEGAL_ROUTES = ("/privacy", "/cookies", "/terms", "/accessibility")


def _privacy() -> str:
    return """
<h1>Datenschutz</h1>
<p class="lead">Aquaticy ist eine selbst gehostete Web-App. Der Betreiber dieser
Installation entscheidet, wo sie läuft und welche optionalen Dienste eingeschaltet sind.</p>
<h2>Welche Daten Aquaticy verarbeitet</h2>
<ul>
  <li><strong>Konto:</strong> Nutzername, E-Mail-Adresse, Tarif und Erstellungszeit.
    Das Passwort wird
    mit Argon2id, einem eigenen Salz und einem geheimen Serverwert gehasht; Klartextpasswörter
    werden nicht gespeichert.</li>
  <li><strong>Sitzung:</strong> zufällige Sitzungsschlüssel sowie Hashes aus IP-Adresse und
    Browserangaben. Diese Werte schützen die Anmeldung und werden nicht für Werbung
    verwendet.</li>
  <li><strong>Eigene Inhalte:</strong> Chats, Einstellungen, Aufträge, Uploads und – falls
    eingeschaltet – gespeicherte Erinnerungen. Jeder Account hat einen getrennten Ordner.</li>
  <li><strong>Nutzung:</strong> verbrauchte Token und belegter Speicher, damit Limits und die
    lokale Verwaltung funktionieren.</li>
  <li><strong>Missbrauchsschutz (Ai-guard):</strong> zum Anlass eines Verdachts der Zeitpunkt,
    die Art, der Chat und deine zuletzt genutzte IP-Adresse. Nur für den Missbrauchsschutz,
    nicht für Werbung oder Profile.</li>
  <li><strong>Schutz vor Mehrfachkonten:</strong> die IP-Adresse, von der aus ein Konto angelegt
    wurde, eine zufällige Geräte-Kennung (im Cookie <code>aquaticy_device</code>, gespeichert
    nur als Hash) sowie Angaben zu Gerät und Browser: Betriebssystem, Zahl der Prozessorkerne,
    Arbeitsspeicher, Bildschirmgröße, Grafikkarte, Zeitzone, Sprache sowie Browser und Version.
    Diese Angaben liegen verschlüsselt; zum Vergleichen nutzt nur der Server einen
    Schlüssel-Hash. Der Betreiber sieht sie nicht — in seiner Kontenliste steht die Adresse
    nur als Kürzel („#1a2b3c4d“) und die Zahl der Geräte. Du selbst siehst deine Geräte und
    deine letzte Adresse unter Einstellungen → Konto → Sicherheit (höchstens 20 Geräte je
    Konto). Meldest du dich von einem unbekannten Gerät an, bekommst du dort einen Hinweis.
    Ein neues Konto wird nur abgelehnt, wenn
    mehrere oder gewichtige Anhaltspunkte zusammenkommen — etwa dasselbe Gerät; dieselbe
    IP-Adresse allein genügt nicht. Die Angaben dienen nur diesem Zweck und dem
    Missbrauchsschutz, nicht der Werbung oder Profilbildung, und werden mit dem Konto gelöscht.
    </li>
  <li><strong>Design:</strong> die Farben eines selbst erstellten Designs und die gewählte
    Schriftgröße, damit es auf jedem deiner Geräte gleich aussieht.</li>
</ul>
<h2>Verschlüsselung</h2>
<p>Chats (Fragen, Antworten, Chatnamen, Notizen), hochgeladene Dateien und Fotos, Bilder,
IP-Adressen, Geräte- und Browserangaben sowie die E-Mail-Adresse liegen verschlüsselt
(AES-256-GCM). Jedes Konto hat einen eigenen Schlüssel; was jemand in ein anderes Konto
kopiert, lässt sich dort nicht öffnen. Passwörter werden mit Argon2id, einem eigenen Salz und
einem geheimen Serverwert gehasht. Ehrlich dazu: Damit Aquaticy mit deinen Chats arbeiten
kann, liegt der Schlüssel auf dem Server. Die Verschlüsselung schützt gegen gestohlene
Datenbanken und Sicherungen, gegen andere Konten und gegen das Hineinsehen in Dateien — wer
den Server selbst kontrolliert, könnte sie mit dem Schlüssel öffnen.</p>
<h2>Externe Dienste</h2>
<p>Eine Frage kann an den ausgewählten Modellanbieter gehen. Suchbegriffe können an das
gewählte Suchsystem gehen; Ortsanfragen nutzen OpenStreetMap-Dienste. Google, Home Assistant,
LAN-Suche, Lager und die virtual machine laufen nur, wenn der Betreiber oder Nutzer sie einschaltet.
Installierte Add-ons ohne Anmeldung (Wetter, Tagesschau, Wikipedia, Währungsrechner, Feiertage)
schicken nur das Nötige an den jeweiligen Dienst: den Ort, den Suchbegriff, die Währung oder
Land und Jahr.
Die Einstellungsseite zeigt die aktive Auswahl. Für externe Anbieter gelten zusätzlich deren
eigene Datenschutzhinweise.</p>
<p>Aquaticy enthält keine Werbe-, Analyse- oder Tracking-SDKs und verkauft keine Nutzerdaten.</p>
<h2>Speicherdauer und Kontrolle</h2>
<h3>Freiwilliges gemeinsames Lernen</h3>
<p>Nur mit deiner gesonderten Zustimmung unter Einstellungen → Gemeinsames Lernen
kann Aquaticy passende kurze Auszüge aus bereits gelesenen öffentlichen Sachartikeln
für spätere Chats aller Konten dieser Installation und ihres verbundenen Server-Verbunds
speichern. Alte Datenschutz-Zustimmungen aktivieren dies nicht. Die App bleibt ohne diese
freiwillige Zustimmung nutzbar. Es werden keine privaten Fragen, Antworten, Uploads,
Erinnerungen, Kontonamen oder Chatkennungen als Lerntexte übernommen. Zurzeit sind nur
ausgewählte Wikipedia-Sachartikel zu Mathematik, Naturwissenschaften und Informatik erlaubt.
Personenangaben, erkennbare Geheimnisse und Anweisungen werden zusätzlich aussortiert.</p>
<p>Gespeichert werden verschlüsselte Originalauszüge und ihre öffentliche Quellenadresse
für höchstens 30 Tage zur Nutzung. Abgelaufene Auszüge werden beim nächsten Zugriff auf den
Wissensspeicher gelöscht. Die Texte enthalten keinen Bezug zu deinem Chat. Für Widerruf und
Löschung wird getrennt ein Schlüssel-Hash deines Kontos mit den Beiträgen verknüpft;
diese Verwaltungsdaten sind pseudonym, nicht vollständig anonym. Aquaticy nutzt die Auszüge
als ausdrücklich unvertrauenswürdiges Recherchematerial, trainiert damit keine Modellgewichte
und sendet sie beim Beantworten passender Fragen an den dafür ausgewählten Modellanbieter.
Öffentliche Quellen können Fehler enthalten; wichtige Angaben müssen erneut geprüft werden.</p>
<p>Du kannst die Zustimmung jederzeit dort widerrufen. Das stoppt neue Übernahmen und
entfernt deine Beitragszuordnung. Ein Auszug wird gelöscht, wenn kein anderes zustimmendes
Konto denselben öffentlichen Auszug unabhängig beigetragen hat. „Alle Daten löschen“ und
„Konto löschen“ widerrufen ebenfalls die Zustimmung und entfernen deine Beiträge.
Der Server-Verbund übernimmt Löschungen beim nächsten erfolgreichen Abgleich; dessen
verschlüsseltes Änderungsprotokoll wird nach seiner vorhandenen Aufbewahrungsfrist bereinigt.
Bereits in Antworten anderer Konten verwendete öffentliche Auszüge und Sicherungen lassen
sich dadurch nicht nachträglich entfernen. Änderungen dieser Erklärung erfordern eine
neue ausdrückliche Zustimmung.</p>
<h3>Kontoeigener Recherchecache (48 Stunden)</h3>
<p>Die oben beschriebene freiwillige Zustimmung umfasst zusätzlich einen getrennten
Recherchecache für dein Konto. Er speichert kurze Originalaussagen als einzelne
Stichpunkte aus öffentlichen Wikipedia-Artikeln, auch über Personen, mit ihrer Quelle.
Dabei können weitere zulässige Aussagen desselben recherchierten Artikels aufgenommen
werden, auch wenn sie nicht in der ersten Antwort enthalten waren. Aus höchstens sechs
gelesenen Artikeln werden je die ersten 48.000 Zeichen beziehungsweise 300 Sätze geprüft;
die bestehenden Grenzen von 100 Stichpunkten pro Konto und 2.000 insgesamt gelten weiter.
Jeder Stichpunkt enthält höchstens 400 Zeichen Quellentext. Beim Abruf werden höchstens
zwölf passende Stichpunkte mit zusammen höchstens 3.200 Zeichen Quellentext ergänzt.
Private Chatangaben und vollständige Antworten werden nicht übernommen. Erkennbare
Kontaktangaben, Geheimnisse und sensible Personenangaben werden ausgeschlossen. Diese
Filter können nicht jeden Grenzfall erkennen; deshalb sind die Auszüge ausschließlich
für dein eigenes Konto verfügbar und werden nicht in das gemeinsame Wissen übernommen.</p>
<p>Texte und Quellen sind verschlüsselt, die Suchbegriffe und Kontozuordnung sind
Schlüssel-Hashes. Bei späteren passenden Fragen dienen die Auszüge nur als zusätzliche,
unvertrauenswürdige Recherchegrundlage für eine neu formulierte Antwort. Sie werden an
den dafür gewählten Modellanbieter übermittelt. Wichtige und aktuelle Angaben sollen
erneut geprüft werden. Es findet kein Training der Modellgewichte statt.</p>
<p>Ab der ersten Übernahme ist ein Auszug höchstens 48 Stunden nutzbar. Erneute Fragen
verlängern diese Frist nicht. Jeder Lesezugriff sperrt abgelaufene Auszüge sofort und
bereinigt sie. Zusätzlich räumt der laufende Webserver automatisch zum Ablauf auf;
bei ausgeschaltetem Server erfolgt die Bereinigung nach dem nächsten Start.
Pro Konto sind höchstens 100, insgesamt 2.000 Auszüge gespeichert. Ausschalten,
„Alle Daten löschen“ und „Konto löschen“ entfernen auch diesen Recherchecache.
Im verbundenen Server-Verbund wird er zur Nutzung desselben Kontos repliziert;
andere Konten erhalten keinen Zugriff. Löschungen im Verbund gelten nach dem nächsten
erfolgreichen Abgleich. Bestehende Chatverläufe, Sicherungen und das verschlüsselte
Verbund-Änderungsprotokoll haben ihre eigenen Aufbewahrungsfristen.</p>
<p>Sitzungen laufen nach 30 Tagen ab. Alte Werkstätten werden nach ihrer Leerlaufzeit entfernt.
Chats, Uploads, Erinnerungen und Aufträge bleiben bis zum Löschen durch den Nutzer oder
Betreiber erhalten. In der Web-App kannst du Chats einzeln entfernen, Uploads leeren und
Erinnerungen einsehen oder löschen. Unter Einstellungen → Konto kannst du selbst <strong>alle
Daten löschen</strong> (das Konto bleibt) oder <strong>dein Konto löschen</strong> — beides mit
deinem Passwort. Was dabei bleibt: der Nutzungszähler, solange das Konto besteht, und
Ai-guard-Vermerke zum Missbrauchsschutz. Löscht ein gesperrtes Konto sich selbst, bleibt für
die Dauer der Sperre nur der Hash seiner Geräte-Kennung, damit die Sperre nicht durch
Löschen umgangen wird. Für eine Auskunft wende dich an den Betreiber der Installation.</p>
"""


def _cookies() -> str:
    return """
<h1>Cookie-Richtlinie</h1>
<p class="lead">Aquaticy setzt nur technisch notwendige, nicht aus JavaScript lesbare
Cookies. Es gibt keine Werbe- oder Analyse-Cookies.</p>
<table><thead><tr><th>Cookie</th><th>Zweck</th><th>Dauer</th></tr></thead><tbody>
<tr><td><code>aquaticy_consent</code></td><td>Merkt, dass der notwendige Betrieb erklärt
und bestätigt wurde.</td><td>1 Jahr</td></tr>
<tr><td><code>aquaticy_session</code></td><td>Ordnet den Browser nach der Anmeldung sicher
dem Konto zu.</td><td>30 Tage</td></tr>
<tr><td><code>aquaticy_device</code></td><td>Zufällige Geräte-Kennung, damit erkannt wird,
wenn von demselben Gerät weitere Konten angelegt werden (Schutz vor Mehrfachkonten).</td>
<td>2 Jahre</td></tr>
<tr><td><code>aquaticy_token</code></td><td>Schützt eine im Netzwerk freigegebene
Installation mit dem Zugangswort des Servers. Wird nur gesetzt, wenn dieser Schutz aktiv ist.</td>
<td>30 Tage</td></tr>
</tbody></table>
<p>Alle Cookies verwenden <code>HttpOnly</code> und <code>SameSite=Strict</code>. Über HTTPS
setzt Aquaticy zusätzlich <code>Secure</code>. Wenn du die notwendigen Cookies ablehnst,
erstellt Aquaticy kein Konto. Ohne sie kann die Mehrbenutzer-Web-App Anmeldungen nicht sicher
auseinanderhalten.</p>
"""


def _terms() -> str:
    return f"""
<h1>Nutzungsbedingungen</h1>
<p class="lead">Diese Bedingungen gelten für die Aquaticy-Web-App in der Version der
Rechtstexte vom {LEGAL_VERSION}.</p>
<h2>Nutzung und Verantwortung</h2>
<p>Aquaticy recherchiert, fasst Quellen zusammen und kann – nach Freigabe – lokale Werkzeuge
verwenden. KI-Antworten und externe Quellen können falsch, unvollständig oder veraltet sein.
Prüfe wichtige Angaben und Aktionen, bevor du dich darauf verlässt. Nutze die Software nicht,
um Rechte anderer zu verletzen oder unbefugt auf Systeme und Daten zuzugreifen.</p>
<h2>Preise, Gebühren und Erstattung</h2>
<p>Die Aquaticy-Software selbst nimmt keine Zahlungen an, erhebt keine versteckten Gebühren
und wickelt keine Erstattungen ab. Falls der Betreiber dieser Installation Zugang verkauft,
muss er Preis, Laufzeit, Kündigung und Erstattungsregeln vor dem Kauf gesondert und klar
mitteilen. Solche Vereinbarungen bestehen dann zwischen dir und diesem Betreiber.</p>
<h2>Bewertungen und geschäftliche Angaben</h2>
<p>Aquaticy sammelt oder veröffentlicht keine Nutzerbewertungen. Rechercheergebnisse sollen
Behauptungen mit den gelesenen Quellen kennzeichnen.</p>
<h2>Ai-guard und Missbrauchsschutz</h2>
<p>Zum Schutz vor Missbrauch liest ein automatischer Sicherheitsfilter („Ai-guard“) mit.
Er prüft deine Nachrichten über mehrere Chats hinweg darauf, ob Aquaticy für Angriffe
missbraucht werden soll – etwa für Schadsoftware, Angriffsanleitungen oder unbefugten
Zugriff. Bei wiederholten solchen Anhaltspunkten wird dein Konto gesperrt. Verteidigung,
Bildung und allgemeine Sicherheitsfragen sind ausdrücklich erlaubt. Ai-guard speichert dabei
nur den Anlass (Zeitpunkt, Art des Verdachts, Chat) und deine zuletzt genutzte IP-Adresse,
nicht den ganzen Nachrichtentext. Diese Daten werden ausschließlich für den
Missbrauchsschutz verwendet und für nichts anderes. Über das Terminal kann der Betreiber ein
Konto oder eine Adresse sperren und wieder freigeben.</p>
"""


def _accessibility() -> str:
    return """
<h1>Barrierefreiheit</h1>
<p class="lead">Aquaticy soll mit Tastatur, Vergrößerung und unterstützenden Technologien
bedienbar sein.</p>
<ul>
  <li>Interaktive Elemente sind per Tastatur erreichbar und haben sichtbare Fokusmarkierungen.</li>
  <li>Statusmeldungen und neue Chatantworten werden semantisch ausgezeichnet.</li>
  <li>Die Farbpaletten halten für normalen Text ein Kontrastverhältnis von mindestens
    4,5:1 ein.</li>
  <li>Die Oberfläche beachtet die Systemeinstellung für reduzierte Bewegung.</li>
  <li>Dekorative Grafiken sind für Screenreader ausgeblendet; informative Bilder brauchen
    eine Textalternative.</li>
</ul>
<p>Wenn du eine Barriere findest, melde sie bitte der Person oder Organisation, von der du
die Adresse dieser Installation erhalten hast.</p>
"""


_CONTENT = {
    "/privacy": ("Datenschutz", _privacy),
    "/cookies": ("Cookies", _cookies),
    "/terms": ("Nutzungsbedingungen", _terms),
    "/accessibility": ("Barrierefreiheit", _accessibility),
}


def legal_page(route: str) -> bytes:
    """Erzeugt eine eigenständige Seite ohne Skripte oder externe Assets."""
    title, content = _CONTENT[route]
    html = f"""<!doctype html>
<html lang="de"><head><meta charset="utf-8"><meta name="viewport"
content="width=device-width,initial-scale=1"><title>{title} · Aquaticy</title>
<link rel="icon" type="image/png" href="/favicon-32.png">
<style>
:root{{color-scheme:light dark;font:16px/1.6 system-ui,-apple-system,"Segoe UI",sans-serif}}
body{{max-width:760px;margin:0 auto;padding:28px 20px 60px;background:#faf9f5;color:#26251f}}
a{{color:#2c6641}}a:focus-visible{{outline:3px solid #3d7d55;outline-offset:3px}}
nav{{display:flex;gap:8px 18px;flex-wrap:wrap;border-bottom:1px solid #d9d7cb;padding-bottom:18px}}
main{{padding-top:18px}}h1{{font-size:2rem;line-height:1.2}}h2{{margin-top:2rem;font-size:1.25rem}}
.lead{{font-size:1.08rem}}dt{{font-weight:700}}dd{{margin:0 0 .6rem}}
table{{border-collapse:collapse;width:100%}}
th,td{{border:1px solid #b8b5aa;padding:9px;text-align:left;vertical-align:top}}
code{{overflow-wrap:anywhere}}
@media(prefers-color-scheme:dark){{body{{background:#232320;color:#f2f1ea}}a{{color:#9fd0b1}}
nav{{border-color:#5b5952}}th,td{{border-color:#77746b}}}}
</style></head><body>
<nav aria-label="Rechtliches"><a href="/">Zurück zu Aquaticy</a><a href="/privacy">Datenschutz</a>
<a href="/cookies">Cookies</a><a href="/terms">Nutzungsbedingungen</a>
<a href="/accessibility">Barrierefreiheit</a></nav>
<main>{content()}</main><footer><p>Stand: {LEGAL_VERSION}</p></footer></body></html>"""
    return html.encode("utf-8")
