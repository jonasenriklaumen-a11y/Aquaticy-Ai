# Prüfbericht: 9.6.4 Aqua

Stand: 2. Oktober 2026. Erneute, vertiefte Prüfung nacheinander aus Sicht
eines Security Researchers, eines Fehlersuchers und eines Nutzers.
Die Korrekturen aus [9.6.4 Luna](TESTREPORT-9.6.4.md) bleiben enthalten.
Die Paketnummer bleibt auf Wunsch 9.6.4; der Versionsname lautet jetzt Aqua.

## 1. Security Researcher

**Alte Einladungen konnten weiterhin Verbunddaten freigeben.** Die Bestätigung
prüfte nicht erneut, ob Connect noch eingeschaltet war und der Server noch
beitreten lassen durfte. Eine zuvor angenommene Einladung konnte so nach dem
Deaktivieren oder auf einem inzwischen zum Mitglied gewordenen Server benutzt
werden. Beide Zustände werden jetzt vor dem Versand der Verbunddaten abgelehnt.
Die Tests prüfen ausdrücklich, dass kein Netzwerkaufruf erfolgt.

**Parallele Bestätigungen konnten denselben Beitritt mehrfach ausführen.**
Die Prüfung des Einladungsstatus und der anschließende Netzwerkaufruf waren
nicht gegen einen zweiten Bestätigungsaufruf geschützt. Bestätigungen werden
jetzt untereinander serialisiert; der allgemeine Zustandsschutz wird dabei
nicht während des Netzwerkaufrufs gehalten. Der Regressionstest hält die erste
Übertragung an und versucht gleichzeitig eine zweite Bestätigung: Es erfolgt
nur ein Beitritt, danach wird die zweite Bestätigung abgewiesen.

**HTTP-Anfragen mit mehrdeutigen Längen wurden angenommen.** Doppelte
`Content-Length`-Header und die Kombination mit `Transfer-Encoding` werden
jetzt bereits beim Einlesen der HTTP-Anfrage mit 400 abgelehnt. Der Server
unterstützt keine als Chunked kodierten Anfragekörper und weist diese
ausdrücklich zurück. Größenbegrenzungen gelten weiterhin vor dem Lesen;
eine vorzeitig beendete Übertragung wird ebenfalls abgewiesen.

**Inaktive Verbindungen konnten unbegrenzt einen Thread belegen.** Für
Socket-Lese- und Schreibvorgänge gilt jetzt eine Inaktivitätsgrenze von
30 Sekunden. Unvollständige Header führen nach Ablauf zum Schließen der
Verbindung, ein stillstehender Anfragekörper zu HTTP 408. Die Tests verwenden
echte TCP-Verbindungen und eine verkürzte Grenze. Das ist keine absolute
Anfragefrist und kein vollständiger Schutz gegen langsame oder massenhafte
Verbindungen.

## 2. Fehlersucher

**Eine verlorene Antwort konnte eine Aktion verdoppeln.** Die Weiterleitung
versuchte nach einem Übertragungsfehler automatisch erneut, obwohl der
Heimserver den ersten Aufruf bereits ausgeführt haben konnte. Bei ungewissem
Ausgang erfolgt jetzt kein automatischer zweiter Versuch. Solange noch keine
Antwort an den Browser begonnen hat, erhält er HTTP 503 mit dem Hinweis,
vor einer Wiederholung den Erfolg der Aktion zu prüfen. Eine ausdrücklich
vom Heimserver gemeldete geänderte Zuständigkeit darf weiterhin umgeleitet
werden, da der Heimserver dabei vor der Ausführung ablehnt.

**Abgeschnittene und leere Verbundantworten galten teilweise als Erfolg.**
Fehlende Abschlussframes und vollständig leere Antworten werden jetzt als
Fehler weitergegeben. Hat die Antwort an den Browser bereits begonnen, wird
die Verbindung geschlossen; es wird kein zweites Fehlerdokument angehängt.
Bereits ausgegebene Daten lassen sich dadurch nicht zurücknehmen.

**Ein gleichzeitiger Schlüsselwechsel konnte eine gültige Antwort zerstören.**
Anfrage und Antwort einer Weiterleitung verwenden jetzt denselben beim
Absenden erfassten Schlüssel. Der Test wechselt den aktuellen Gruppenschlüssel
zwischen Anfrage und Antwort und prüft die erfolgreiche Entschlüsselung.
Neue eingehende Anfragen akzeptieren weiterhin nur den aktuellen Schlüssel.

Die ursprünglichen Fehler bei Freigaben, HTTP-Verarbeitung und Weiterleitung
wurden mit insgesamt 14 fehlschlagenden Testfällen vor den jeweiligen
Korrekturen reproduziert. Drei zusätzliche Fälle prüfen vorzeitiges
Übertragungsende und die weiterhin erlaubte Umleitung.

## 3. Nutzer

**Eine verspätete Statusantwort überschreibt die neuere Bedienung.** Im
Chromium-Test wird eine Connect-Statusantwort zurückgehalten. Der Nutzer
schaltet Connect aus; anschließend trifft die alte Antwort mit
`enabled: true` ein. Vor der Korrektur erschienen Schalter und Dialog wieder
eingeschaltet, obwohl der Server ausgeschaltet war. Die Oberfläche verwirft
jetzt überholte Antworten und Fehler. Neue Aktionen unterbrechen den alten
Abfragezyklus und starten ihn anschließend wieder. Auch beim Schließen des
Einstellungsdialogs werden ausstehende Ergebnisse ungültig.

Die Connect-Prüfung verwendet zwei echte CLI-Prozesse mit getrennten
Datenverzeichnissen, Konten und TCP-Ports auf dem Loopback-Netz. Sie umfasst
Einladung, Ablehnung, falschen und richtigen Code, Beitritt samt Neustart,
gemeinsame Sitzungen, Kontentrennung, CSRF-Abweisung, Replay- und
Manipulationsabwehr, tatsächlichen Serverausfall, Wiederanlauf sowie Entfernen
eines Mitglieds und Schlüsselwechsel. Vier Browser-Szenarien prüfen zusätzlich
Code und Fokus während der Statusabfrage, Erholung nach HTTP 503, ungültige
Ports und die verspätete Antwort.

## Validierung

- Abschließende Gesamtsuite: **4.129 bestanden, 15 übersprungen, keine Fehler**
  in 535,84 Sekunden. Zwei Warnungen betreffen Pydantics Unterstützung des
  `ReadOnly`-Typhinweises. 13 übersprungene Fälle benötigen Docker-Dienste oder
  vorbereitete Images. Zwei ältere Browser-Prüfungen erkennen das vorhandene
  System-Chromium nicht: Der Rundgang lief separat erfolgreich, die Erkennung
  für den DNS-Rebinding-Test wurde anschließend korrigiert. Dessen zusätzliche
  Ausführung zeigte, dass der Cloud-Proxy bereits die ungeschützte
  Kontrollanfrage an die simulierte Testdomain mit `403 Domain forbidden`
  blockiert. Der erste Nachtest scheiterte deshalb an der Kontrollbedingung;
  diese konkrete Umgebungsblockade wird jetzt ausdrücklich als übersprungen
  ausgewiesen. Der Browser-DNS-Rebinding-Fall ist hier **nicht validiert**.
- Vollständiger Browser-Rundgang: **402 Prüfungen, keine Beanstandungen**;
  keine JavaScript- oder Konsolenfehler.
- Gezielte Sicherheits-, Fehler- und Connect-Nachtests: 55 bestanden.
- Ergänzende Fälle und Versionsabgleich: 124 bestanden, zwei Pydantic-Warnungen.
- Abschließender Nachtest von `tests/test_v9516.py`: 84 bestanden, der oben
  beschriebene Browser-DNS-Rebinding-Fall wegen der Cloud-Proxy-Sperre übersprungen.
- Ruff und `git diff --check`: erfolgreich.
- Lokaler Abhängigkeitsabgleich mit `uv pip check`: 90 Pakete kompatibel.
- CLI-Ausgabe: `aquaticy 9.6.4 Aqua`.

```bash
LITELLM_LOCAL_MODEL_COST_MAP=True .venv/bin/pytest -q --tb=short -ra
LITELLM_LOCAL_MODEL_COST_MAP=True .venv/bin/python -u tools/rundgang.py
.venv/bin/ruff check .
git diff --check
uv pip check --python .venv/bin/python
.venv/bin/aquaticy --version
```

## Grenzen und Betrieb

Im Browser-Rundgang werden Modellantworten und externe Dienste simuliert;
Browser, Oberfläche und HTTP-Server laufen tatsächlich. Echte Anbieter-Logins,
bezahlte Modellaufrufe und Docker-Desktop-/Sandbox-Integrationen wurden nicht
live geprüft. Loopback-Tests ersetzen keinen Dauertest mit mehreren Rechnern,
Funknetzstörungen oder anhaltenden Netzwerkpartitionen. Die Prüfungen belegen
die beschriebenen Fälle und sind keine Garantie für vollständige Fehlerfreiheit.

Alle Mitglieder sollten auf diesen Stand **9.6.4 Aqua** aktualisiert werden.
Die aus Luna übernommene sofortige Schlüsselwiderrufung kann während eines
Schlüsselwechsels alte Anfragen ablehnen. Ein zu diesem Zeitpunkt nicht
erreichbares Mitglied muss gegebenenfalls neu verbunden werden. Ein erneuter
Abgleich mit einer externen Datenbank für Abhängigkeitsschwachstellen war
nicht Bestandteil dieses Durchgangs.
