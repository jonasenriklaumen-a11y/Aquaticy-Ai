# Prüfbericht: 9.6.3 Luna

Stand: 2. Oktober 2026. Getestet unter Linux mit Python 3.12 und Chromium.

## Ergebnisse

- Abschließende vollständige Testsuite: **4.091 bestanden, 15 übersprungen,
  keine Fehler** (483,62 Sekunden). Zwei Warnungen stammen von Pydantic zur
  Unterstützung des `ReadOnly`-Typhinweises. Übersprungene Tests betreffen
  optionale Laufzeitumgebungen; der Browser-Rundgang lief zusätzlich separat.
- Vollständiger Browser-Rundgang: **402 Prüfungen, keine Beanstandung**,
  keine JavaScript- oder Konsolenfehler.
- Gezielte Nachtests für Connect, Version und betroffene Webfunktionen:
  **127 bestanden**. Darin enthalten sind die beiden neuen Tests mit echten
  Serverprozessen, einer davon mit Browserbedienung.
- Ruff und `git diff --check`: ohne Befund.

## Korrekturen

- **Neustart nach Connect:** Der eingeladene CLI-Server konnte sich beenden,
  bevor sein Daemon-Thread den Neustart ausführte. Der Neustart erfolgt jetzt
  im Hauptablauf nach dem Schließen des alten HTTP-Servers.
- **Codeeingabe im Browser:** Die Statusabfrage ersetzte alle drei Sekunden
  das Eingabefeld. Vorhandene Einladungen behalten jetzt ihr Feld einschließlich
  Inhalt, Fokus und Cursorposition.
- **Abgelaufene Zustimmung:** Auch angenommene Einladungen verfallen nach
  fünf Minuten. Beide Seiten prüfen die Frist vor der Freigabe der Verbindung;
  die Statusanzeige berücksichtigt den Ablauf ebenfalls.
- **Ausfall eines Heimservers:** Anfragen werden mit HTTP 503 abgewiesen,
  wenn der zuständige Server fehlt. Eine möglicherweise veraltete Profilkopie
  übernimmt keine Schreibzugriffe. Nach Wiederanlauf ist das Profil erreichbar.
- **Weitere Korrekturen dieser Version:** Strengere Prüfung verschlüsselter
  Antwortströme, begrenzte Dekompression von Webantworten und keine positive
  Council-Bestätigung bei ungültiger Prüferantwort oder Prüferausfall.

## Umfang

Der Browser-Rundgang prüft Anmeldung, Konten, Chat und Abbruch, Modi,
Modellauswahl, Verlauf, Exporte, Uploads, Einstellungen, Designs, Sprache,
Aufträge, Dialoge und verschiedene Bildschirmgrößen. Modellantworten und
externe Integrationen sind dabei simuliert; die Oberfläche und HTTP-API laufen echt.

Die Connect-Tests starten zwei echte CLI-Prozesse mit eigenen temporären
Datenverzeichnissen und verschiedenen TCP-Ports. Sie verwenden die reguläre
Anmeldung und Web-API. Die Zustimmung auf dem eingeladenen Server erfolgt
über die lokale Antwortdatei von `aquaticy cluster`.

Geprüft werden Ablehnung, falscher Code, Beitritt samt Datenübernahme und
Neustart, Kontentrennung, synchronisierte Einstellungen, fremde Origin-Header,
Sitzungswiderruf, manipulierte und wiederholte verschlüsselte Nachrichten,
Serverausfall und Wiederanlauf sowie Entfernen mit Schlüsselwechsel.
Ein zusätzlicher Browser-Test führt Connect über die sichtbaren Bedienelemente
aus und wartet während der Codeeingabe einen vollständigen Abfragezyklus ab.
Die gegenseitige Erkennung über echte UDP-Broadcasts wurde separat bestätigt.

## Wiederholen

```bash
.venv/bin/pytest -q --tb=short
.venv/bin/pytest tests/test_cluster.py tests/test_cluster_http.py -q
.venv/bin/python tools/rundgang.py
.venv/bin/ruff check .
git diff --check
```

Der Connect-Browsertest braucht Playwright und ein als `chromium` verfügbares
System-Chromium; andernfalls wird er übersprungen. Der Rundgang unterstützt
auch Chromium unter `/opt/pw-browsers/chromium` oder den Playwright-Browser.

Der Abhängigkeitscheck mit `pip-audit` fand am Prüftag keine bekannten
Schwachstellen in den 89 prüfbaren installierten Fremdpaketen. Das lokale Paket
Aquaticy ist nicht über diese Datenbank prüfbar; sein Code wurde separat geprüft.

Nicht live geprüft wurden echte externe Anbieter-Logins, bezahlte Modellaufrufe
und die Docker-Desktop-/Sandbox-Integrationen. Die LAN-Simulation nutzt zwei
Prozesse auf demselben Rechner; unterschiedliche Rechner, Router, Firewalls
und länger andauernde Netzpartitionen benötigen zusätzliche Umgebungstests.
Der zusätzliche Browser-Test gegen DNS-Rebinding war hier nicht auswertbar:
Bereits seine ungeschützte Gegenprobe wurde vom Cloud-Netzwerkproxy mit
`403 Domain forbidden` blockiert. Das ist kein Nachweis des Anwendungsschutzes;
die übrigen lokalen SSRF-/Proxy-Tests bleiben davon unabhängig.
