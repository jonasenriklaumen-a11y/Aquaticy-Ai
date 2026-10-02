# Prüfbericht: 9.6.4 Luna

Stand: 2. Oktober 2026. Die drei Prüfungen wurden nacheinander durchgeführt.
Die Korrekturen aus [9.6.3 Luna](TESTREPORT-9.6.3.md) bleiben enthalten.

## Prüfergebnisse

- Abschließende Gesamtsuite: **4.111 bestanden, 15 übersprungen, keine Fehler**
  (516,71 Sekunden). Zwei Warnungen betreffen Pydantics Unterstützung des
  `ReadOnly`-Typhinweises. Die übersprungenen Tests benötigen zusätzliche
  Laufzeitumgebungen; der vollständige Browser-Rundgang lief separat.
- Gezielte Nachtests: **22 bestanden**, darunter vier Tests mit echten
  Serverprozessen (davon drei Browser-Szenarien).
- Vollständiger Browser-Rundgang: **402 Prüfungen ohne Beanstandung**,
  keine JavaScript- oder Konsolenfehler.
- Ruff, `git diff --check` und Abgleich zwischen Paket- und angezeigter
  Version: erfolgreich.

## 1. Security Researcher

**Zusätzliches Server-Zugangswort konnte im Verbund umgangen werden.**
Mit einer gültigen Kontositzung wurde die Anfrage weitergeleitet, bevor der
Eingangsserver sein optionales Zugangswort prüfte. Der Heimserver vertraute
dieser Weiterleitung. Die Prüfung erfolgt jetzt vor der Weiterleitung.
Regressionstests prüfen GET und POST jeweils ohne, mit falschem und mit
richtigem Zugangswort über einen echten HTTP-Handler.

**Widerrufene Verbundschlüssel authentifizierten weiterhin neue Anfragen.**
Nach einem Schlüsselwechsel galt der alte Gruppenschlüssel noch zwei Minuten.
Ein entferntes Mitglied konnte damit die Kennung eines verbliebenen Knotens
vortäuschen. Neue Anfragen akzeptieren jetzt ausschließlich den aktuellen
Schlüssel. Bereits angenommene Anfragen behalten ihren Antwortschlüssel.
Tests reproduzieren die Identitätsvortäuschung gegen Master und Mitglied;
ein Test mit drei Knoten prüft die Verbindung der verbleibenden Mitglieder.

Für diesen Schutz müssen alle Server des Verbunds aktualisiert werden.
Während des Schlüsselwechsels können noch mit dem alten Schlüssel gesendete
Anfragen abgelehnt werden. Ein nicht erreichbares Mitglied kann die neue
Schlüsselverteilung verpassen und muss gegebenenfalls neu verbunden werden.

## 2. Fehlersucher

- Ein gescheiterter Profilumzug konnte den vorherigen Heimserver dauerhaft
  blockieren. Bei fehlgeschlagener Übernahme bleibt er jetzt zuständig und
  erhält die Aufforderung, seine Arbeit wieder aufzunehmen.
- Bei Rückumzügen blieb die Sperre einer früheren Übergabe erhalten. Eine
  gültige Übernahme löst diese Sperre jetzt auch auf dem entfernten Server.
- Eine erzwungene Profilübernahme vertraute auf alte Synchronisationsdaten,
  obwohl die lokale Datei inzwischen anders sein konnte. Bei einer Übernahme
  werden die Dateien jetzt erneut vom zuständigen Server gelesen.
- Änderte sich eine Datei während der Übernahme, wurde sie ausgelassen und
  der Umzug trotzdem abgeschlossen. Eine solche Übernahme bricht jetzt ab;
  die Zuständigkeit wechselt erst nach vollständigem Kopieren.
- Ungültige Ports wurden teilweise umgewandelt oder durch den Standardport
  ersetzt. API und Einladungen akzeptieren nur ganze Ports von 1 bis 65535.

Diese Fehler wurden jeweils vor der Korrektur mit Regressionstests
reproduziert. Die Tests prüfen auch mehrfaches Hin- und Zurückziehen eines
Profils, unveränderte Zuständigkeit bei Kopierfehlern und die Wiederaufnahme
vorher gestoppter Aufträge.

## 3. Nutzer

Die Connect-Bedienung wurde in Chromium mit zwei echten CLI-Prozessen und
getrennten Datenverzeichnissen geprüft. Zusätzlich zu den vorhandenen
Abläufen wurden ein Tippfehler im Port und eine vorübergehende HTTP-503-Antwort
bei der Statusabfrage simuliert.

- Ein Fehler bei der Abfrage versteckte den Dialog, schaltete die Anzeige aus
  und beendete weitere Statusabfragen. Jetzt bleiben Zustand und Codeeingabe
  erhalten; eine Meldung erscheint und die Abfrage wird wiederholt.
- Eine Eingabe wie `8765abc` wurde vom Browser zu `8765` verkürzt und konnte
  eine unerwünschte Einladung auslösen. Jetzt erscheint eine Fehlermeldung,
  ohne eine Verbindungsanfrage zu senden.

Die Browsertests prüfen die Fehlermeldung, den erhaltenen Code und Fokus,
die selbstständige Erholung sowie den anschließenden erfolgreichen Beitritt.

## Wiederholen und Grenzen

```bash
.venv/bin/pytest -q --tb=short
.venv/bin/pytest tests/test_v964.py tests/test_cluster.py tests/test_cluster_http.py -q
.venv/bin/python tools/rundgang.py
.venv/bin/ruff check .
git diff --check
```

Der Browser-Rundgang nutzt simulierte Modellantworten und externe Dienste.
Anmeldung, Oberfläche und HTTP-Verarbeitung laufen tatsächlich. Die neuen
Connect-Browsertests benötigen Playwright und ein verfügbares System-Chromium.
Docker-Desktop-/Sandbox-Integrationen, echte Anbieter-Logins und bezahlte
Modellaufrufe wurden nicht live geprüft. Die lokalen Verbundtests ersetzen
keinen Dauertest auf mehreren Rechnern mit anhaltenden Netzwerkpartitionen.
