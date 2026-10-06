# Prüfbericht: 9.6.10 Luna

Stand: 2026-10-06. Grundlage ist **9.6.9 Luna** (`1de117b`) auf
`Aquaticy-ai`. Vor der Prüfung wurden die drei neuen Commits seit `7aa5f47`
per Fast-forward übernommen. Der lokale Ausgangsstand war sauber. Die Änderungen
an Handy-Layout, Fehleranzeige, Wiederanlauf, Home Assistant, Google, Lernschutz
und manueller Kontoübernahme bleiben Bestandteil dieses Releases.

## Umfang

Alle **59 Python-Module mit 46.630 Quellzeilen** wurden mit Ruff,
Syntax-/Bytecode-Prüfung und Bandit untersucht. Die vertiefte Durchsicht galt
den neuen Änderungen und ihren Sicherheitsgrenzen: Kontoeinstellungen und
Geheimnisse, Google-Rückmeldungen, öffentliche Fehlertexte, Serverstart,
Verbundzuteilung und Wiederholungen im Browser. Die vollständige Testsuite
deckt zusätzlich die bestehenden Konten-, Verschlüsselungs-, Datenschutz-,
Recherche-, Werkzeug-, Browser- und Sandbox-Funktionen ab.

Die Prüfung belegt nachvollziehbare Korrekturen und den Zustand der getesteten
Wege. Sie garantiert nicht, dass jede denkbare Sicherheitslücke ausgeschlossen
ist. Externe Anbieter und Modelle werden überwiegend durch kontrollierte
Antworten ersetzt; echte Kundendaten wurden nicht verwendet.

## Bestätigte Fehler und Korrekturen

- **Google-Client-ID und Geheimnis:** Ein Konto mit eigener Google-Client-ID
  erbte weiterhin das Geheimnis der OAuth-Anwendung des Betreibers, wenn kein
  eigenes Geheimnis vorlag. Damit wurde eine falsche Kombination an Google
  gesendet. Nun bleibt das Betreiber-Geheimnis nur für die gemeinsame
  Betreiber-Anwendung verfügbar. Für eine abweichende Client-ID ist ein
  eigenes Geheimnis erforderlich. Die gemeinsame OAuth-Anwendung sowie
  vorhandene eigene Geheimnisse und deren verschlüsselte Migration bleiben
  nutzbar. Dies ist eine Korrektur der Anwendungszuordnung; daraus folgt kein
  Nachweis eines Zugriffs auf private Google-Daten des Betreibers.
- **Ungefilterte Google-Fehlerseite:** Google-Rückmeldungen wurden HTML-maskiert,
  aber ohne den bestehenden Fehler- und Geheimnisfilter angezeigt. Technische
  Fehler konnten dadurch auf der Seite erscheinen. Fehlerantworten laufen jetzt
  durch dieselbe Maskierung und öffentliche Fehleraufbereitung. Verständliche
  Einrichtungshinweise bleiben erhalten. Die erfolgreiche Rückmeldung, einmalige
  Konto-/Browserbindung, kurzlebiges Ablauf-Cookie und Sicherheitskopfzeilen
  bleiben unverändert.
- **Lücken in der Geheimnismaskierung:** Nicht hinterlegte Werte in `token=…`
  oder `refresh_token=…` wurden vom bisherigen Muster nicht erfasst. Der Filter
  erkennt nun auch diese Namen, ID-Tokens, OAuth-Codes und entsprechende
  JSON-Felder. Die Erweiterung betrifft Fehlertexte; normale Antworten,
  Quelltexte und Funktionen werden nicht pauschal entfernt.
- **Veraltete Kontoabgabe im Verbund:** Der Wiederholungsweg rief die Abgabe
  auf, bevor er prüfte, ob das Konto inzwischen wieder lokal zugeteilt war.
  Dadurch konnten Sitzungen und Aufgaben eines zurückgekehrten Kontos angehalten
  werden. Nun erfolgt die Prüfung vor jedem Versuch. Abgabe und Wiederannahme
  werden je Konto serialisiert. Eine zurückkehrende Zuteilung startet die
  Aufgaben nach einer eventuell noch laufenden Abgabe wieder. Langsame
  Laufzeit-Hooks halten dabei nicht die globale Verbundsperre. Stoppzustand
  und veraltete Wiederannahmen werden geprüft; die manuelle Übernahme und
  die bestehende Begrenzung der Wiederholungsintervalle bleiben erhalten.
- **Falsche Startadresse:** Bei `--port 0` wurde nur die unbrauchbare Adresse
  mit Port null angezeigt. Auch ein Ersatz-Port nach der Vorprüfung wurde
  lediglich als Zahl gemeldet. Die CLI kündigt die automatische Wahl jetzt
  an; der gebundene Server zeigt anschließend seine tatsächlich verwendeten
  Adressen. Der normale Start, Ersatz-Ports, Datenordnersperre und automatischer
  Wiederanlauf bleiben bestehen.
- **Fokusverlust durch Hintergrundfehler:** Die neue allgemeine Fehleranzeige
  konnte bei einer fehlgeschlagenen Verbund-Statusabfrage ein Dialogfenster
  öffnen und den Fokus aus dem Einladungscode ziehen. Dieser Hintergrundweg
  meldet den Fehler nun beim vorhandenen Verbundstatus. Wiederholungen und
  Fehlerhinweis bleiben; normale Fehler öffnen weiterhin das allgemeine Fenster.
  Der bestehende Browser-Test wartet jetzt auf den tatsächlichen Fehlerhinweis
  nach den Lese-Wiederholungen und prüft zusätzlich Code, Fokus und Dialogzustand.

## Erhaltene Schutzmaßnahmen und Datenverarbeitung

Argon2id-Parameter, Kontingente, transaktionaler Passwortwechsel und
Sitzungswiderruf, Geräte-/IP-Bindung, Kontotrennung, AES-GCM/Fernet und
Schlüsselprüfung bleiben bestehen. Ebenso erhalten bleiben CSRF/Origin,
CSP, SSRF-/DNS-/Weiterleitungsprüfungen, Größen-/Zeitgrenzen, Sandbox,
Home-Assistant-Freigaben und Adressbindung, Rechtsprüfung und Ai-guard.

Das Handy-Layout, allgemeine Fehlerfenster, Offline-Hinweis, Wiederanaufnahme
laufender Antworten und Ausweichmodell desselben Anbieters bleiben enthalten.
Schreibaktionen werden im Browser weiterhin nicht automatisch wiederholt.

Gemeinsames Quellenwissen verlangt weiterhin mindestens zwei beitragende
Konten, bevor andere Konten einen Auszug erhalten; eigene Auszüge sind sofort
verfügbar. Kontoeigene Recherche-Stichpunkte bleiben höchstens 48 Stunden
nutzbar. Zustimmung, Widerruf, Löschung, Inhaltsfilter und Verschlüsselung
bleiben erhalten. Private Chattexte werden nicht für andere Konten freigegeben;
Modellgewichte werden nicht trainiert. Dieses Release erweitert keinen
Verarbeitungszweck und verlangt keine neue Lern-Zustimmung.

## Prüfungen

- **26 neue Regressionstests bestanden**, in **26,03 Sekunden**. Sie prüfen
  eigene und gemeinsame Google-Anwendungen, alle drei Kontopläne, Migration
  eigener Geheimnisse, sieben Bezeichnungen für Zugangsdaten jeweils als
  Zuweisung und JSON-Feld, echte HTTP-Fehlerseiten und deren Sicherheitskopfzeilen,
  verzögerte Kontoabgabe, Rückzuteilung während einer Abgabe, Stoppzustand,
  tatsächliche Startadresse und die CLI mit Port null.
- Drei dieser Prüfungen verwenden echtes Chromium: Chatten und Öffnen der
  Einstellungen bei **320 Pixel**, **390 Pixel mit großer Schrift** und
  **1.280 Pixel**. Geprüft werden Antwortabschluss, bedienbare Knöpfe, horizontale
  Fenstergrenzen und JavaScript-Fehler.
- Ein weiterer Chromium-Test prüft Fokus und Entwurf bei einem Hintergrundfehler,
  drei begrenzte GET-Versuche sowie genau einen POST-Versuch mit weiterhin
  sichtbarem allgemeinem Fehlerfenster. Die **fünf Verbund-HTTP-Prüfungen**
  bestanden in **107,28 Sekunden**. Sie verwenden zwei echte CLI-Prozesse,
  getrennte Datenordner und TCP/HTTP sowie Browserfälle für laufende Abfragen,
  vorübergehenden Ausfall, ungültigen Port und verspätete Statusantwort.
- Die 42 Tests der übernommenen Sol-/Ultra-/Luna-Änderungen bestanden bereits
  vor der Korrektur. Ergänzende Regressionen für Web, Konten, Google, Browser
  und Verbund: **512 bestanden**, zwei unveränderte Warnungen, in
  **220,31 Sekunden**. Gezielte Durchläufe überschneiden sich und sind nicht
  zu addieren.
- Vollständige Suite (`pytest -q -ra`): **4.389 bestanden, 12 übersprungen,
  keine Fehler**, in **882,95 Sekunden**. Der Browser-Rundgang und die
  verfügbaren Docker-Sandbox-Prüfungen sind enthalten. Elf weitere Tests benötigen
  nicht vorhandene Desktop-/Add-on-Abbilder; eine DNS-Rebinding-Kontrollanfrage
  wird bereits vom Cloud-Proxy blockiert. Zwei unveränderte Pydantic-Warnungen
  betreffen ein `ReadOnly`-Feld einer Fremdbibliothek.
- Ruff für Programmcode, Tests und Werkzeuge, AST-/Bytecode-Prüfung aller
  59 Python-Module und `git diff --check`: bestanden.
- `pip-audit` mit PyPI: **89 Fremdpakete, keine bekannten Schwachstellen**.
  Das lokale editable Projekt ist von der Fremdpaketprüfung ausgenommen.
  `uv pip check`: **90 Pakete kompatibel**. Keine neuen Projektabhängigkeiten.
- Laufzeit und installierte Paketmetadaten: **9.6.10 Luna** beziehungsweise
  **9.6.10**.
- `uv build`: Wheel und Quellarchiv erfolgreich erstellt. Alle **65 ausgelieferten
  Programmdateien** stimmen bytegenau mit dem Arbeitsstand überein. Version:
  **9.6.10**, Codename: **Luna**. Das Quellarchiv enthält die neuen Regressionstests,
  die aktuelle README, den verstärkten Verbund-Browsertest und diesen
  abgeschlossenen Prüfbericht.

## Automatische Befunde und Grenzen

Bandit meldet **116 Hinweise**: **93 niedrig, 22 mittel und einen hohen**;
37.664 Zeilen wurden dabei ausgewertet. SQL-Hinweise betreffen gebundene Werte
beziehungsweise feste oder maskierte Schema-/Tabellennamen, einschließlich
der neuen Bestätigungsabfrage für gemeinsames Wissen. Feed-XML weist DTD und
Entitäten bereits ab. LAN-Bindung und Sandbox-Verzeichnisse gehören zu den
bestehenden Funktionen. Es wurden keine Sicherheitsbefunde durch neue
Unterdrückungsregeln ausgeblendet.

Der hohe Hinweis betrifft weiterhin `verify=False` bei der Titel-Erkennung
privater IPv4-Geräte mit selbstsignierten Zertifikaten. Diese begrenzte Abfrage
überträgt keine Anmeldedaten, folgt keinen Weiterleitungen, nutzt keinen
Umgebungsproxy und hat Größen-/Zeitgrenzen. Ein Gerätename ist damit kein
verifizierter Identitätsnachweis. Normale Quellen und APIs behalten ihre
Zertifikatsprüfung. Die bestehende Einschränkung wurde nicht als behoben
ausgegeben.

Ausgeführt unter Linux/Python 3.12. Echte Windows-/FAT-Systeme, reale Google-
Anmeldungen, externe Modellantworten und Mehrserver-Betrieb auf getrennten
Rechnern wurden nicht vollständig nachgestellt. Ereignisse und kontrollierte Hooks sichern die
geprüfte Reihenfolge der konkurrierenden Kontoübergaben ab.

## Lokale Effizienzprüfung

Der vorhandene Offline-Recherchebenchmark mit 2.000 globalen und 100
kontoeigenen Fakten ergab bei 100 Abrufen einen Median von **2,242 ms**,
zwölf Punkten und 24 Entschlüsselungen je Abruf; Datenbankgröße
**22.065.152 Bytes**. Die Messung lief parallel zu Tests und ist keine
garantierte Laufzeit oder kontrollierter Vergleich mit älteren Releases.
Die Korrekturen benötigen keine zusätzlichen externen Prüf- oder Modellaufrufe.
