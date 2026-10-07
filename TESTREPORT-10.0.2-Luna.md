# Prüfbericht: 10.0.2 Luna

Stand: 2026-10-07. Grundlage ist **10.0.1 Luna** (`337fe8e`) auf
`Aquaticy-ai`. Die drei neuen Remote-Commits seit `54cf97f` wurden zuerst
per Fast-forward übernommen. Der Arbeitsstand war sauber. Auto-Upgrading,
Modellfreigaben, Kandidaten, Zurücksetzen und die neue Startmeldung bleiben
Bestandteil des Releases.

## Umfang

Alle **60 Python-Module mit 47.907 Quellzeilen** wurden mit Ruff,
AST-/Bytecode-Prüfung und Bandit untersucht. Die vertiefte Durchsicht galt
dem neuen Auto-Upgrading und seinen Verbindungen zu Modellrouting,
Kontoeinstellungen, freiwilligem Lernen und Server-Lebenszyklus.
Die bestehende Gesamtsuite prüft zusätzlich Konten, Verschlüsselung,
Werkzeuge, Browser, Verbund, Datenschutz und Sandbox.

## Bestätigte Fehler und Korrekturen

- **Unvollständige Modellfreigaben:** Beim Speichern wurde nur das Hauptmodell
  auf die Ultra-Beschränkung geprüft. Vision-, Helfer- und Code-Modell konnten
  auf einen Kandidaten zeigen. Alle vier Felder werden jetzt geprüft; auch
  automatische und zwischengespeicherte Modellvorschläge berücksichtigen die
  Freigabe. Vor dem tatsächlichen Modellaufruf wird erneut geprüft, einschließlich
  bereits vorbereiteter Anfragen nach einer Wartezeit. Die HTTP-Modellliste
  verwendet die Prüfung auch bei einer Sitzung ohne `SessionProxy` und gibt
  bei einem Prüfungsfehler keine ungefilterte Ersatzliste zurück.
- **Alternative Ollama-Namen:** Kurze und vollständig geschriebene Namen
  (`library/…`, `registry.ollama.ai/library/…`, Standardtag `:latest`)
  wurden unterschiedlich behandelt. Die Zugriffsprüfung ordnet sie nun derselben
  Modellfassung zu. Die Modell-Erkennung fügt solche Aliase und eigene Builds
  nicht als neue Ausgangsmodelle hinzu. Anzeigenamen bleiben lesbar.
- **Vier-Tage-Regel:** Bereits geladene Einstellungen wurden nur nach einer
  neuen Freigabe geprüft. Eine festgelegte alte Fassung konnte dadurch über
  die Frist hinaus genutzt werden. Zeitablauf wird jetzt unabhängig von der
  Freigabe-Generation berücksichtigt. Ultra behält den vorgesehenen Zugriff
  auf gültige ältere Fassungen.
- **Dauerhafte Kopie kurzlebigen Lernwissens:** Öffentliche Auszüge wurden
  in Ollama-Modelltexte eingebaut, ohne ihre weitere Gültigkeit zu verfolgen.
  Jetzt trägt jede neue Fassung ausschließlich Schlüssel-Hashes der eingebauten
  Fakten und deren ursprüngliche Ablaufzeit als Abhängigkeiten. Vor der Nutzung
  und im Hintergrund wird geprüft, ob jeder Auszug noch gültig und durch
  mindestens zwei aktuell zustimmende Konten bestätigt ist. Ablauf, Widerruf,
  Daten-/Kontolöschung und alte Zustimmung ziehen betroffene Fassungen zurück.
  Aquaticy nutzt dann das Ausgangsmodell. Alte Builds ohne nachprüfbare
  Abhängigkeiten werden ebenfalls zurückgezogen und können aus aktuell
  freigegebenem Wissen neu entstehen. Die Versionshistorie bleibt erhalten.
- **Unvollständige Lern-Erklärung:** Die bisherige Erklärung beschrieb
  verschlüsselte Quellenauszüge und ihre Verwendung bei passenden Fragen,
  aber keine dauerhafte, unverschlüsselte Kopie im Ollama-Systemtext.
  Datenschutz, Anmeldung und Einstellungen erklären diese Verarbeitung nun
  ausdrücklich. Die Erklärung `2026-10-07.1` verlangt eine neue freiwillige
  Lern-Zustimmung; alte Zustimmungen erlauben keine neuen Upgrade-Builds.
  Kontokennungen, private Fragen, Antworten, Uploads und Erinnerungen werden
  weiterhin nicht in die gemeinsam genutzten Modelltexte übernommen.
- **Verfälschter Modelltest:** Technische Fehler wurden wie falsche Antworten
  gewertet. Ein ausgefallenes Ausgangsmodell konnte dadurch einen künstlich
  hohen Gewinn erzeugen. Technische Fehler, leere und ungültige Antworten
  brechen den Vergleich jetzt ab. Der Lückentext-Test begrenzt Antwortlänge
  und Erzeugung; die Oberfläche benennt die Art des Tests.
- **Veraltete Trainingsfreigabe:** Ein Lauf konnte nach Abschalten, Überspringen,
  Zurücksetzen oder verändertem Ausgangsstand noch einen Kandidaten speichern.
  Laufende Arbeiten prüfen jetzt Stopp, Zustand und Wissensgültigkeit zwischen
  den Testfragen und vor Veröffentlichung. Überholte Ergebnisse werden verworfen.
- **Blockierte Verwaltungszugriffe:** Ollama-Kopien und Löschungen liefen unter
  der globalen Zustandssperre. Jetzt werden Versionsnummern kurz reserviert;
  Netzwerkoperationen halten diese Sperre nicht. Ein gezielt angehaltener
  Kopiervorgang blockiert das Lesen des Zustands nicht mehr.
- **Modell-/Versionskollisionen:** Verschiedene Ausgangsnamen konnten auf
  denselben gekürzten Namen fallen. Ein Hash-Zusatz unterscheidet sie jetzt.
  Reservierte und übersprungene Nummern werden nicht erneut vergeben.
  Bestehende gespeicherte Namen bleiben lesbar. Auswahl eines übersprungenen
  oder ersetzten Kandidaten fällt auf die aktuelle Fassung zurück. Eine gespeicherte
  inzwischen unbekannte Fassung verhindert nicht das Öffnen der Einstellungen;
  ihre Nutzung bleibt gesperrt, bis eine verfügbare Fassung ausgewählt ist.
- **Training und Serverstopp:** Jeder manuelle Klick startete einen weiteren
  Thread; Serverstopp wartete nicht auf aktive Arbeit. Ein einzelner Worker
  bündelt jetzt Anforderungen, erhält ein Stoppsignal und endet vor Freigabe
  der Datenordnersperre. Ein Test sendet 1.000 Anforderungen während blockierter
  Arbeit und prüft das Ende des Workers.
- **Modellreste und HTTP-Grenzen:** Auch teilweise erzeugte Zwischenmodelle
  werden bereinigt. Fehlgeschlagene Löschungen bleiben dauerhaft für den
  nächsten Abgleich vorgemerkt, selbst bei abgeschaltetem Training. Ein bereits
  fehlendes Modell (HTTP 404) gilt als gelöscht. Ollama-Aufrufe übernehmen keine
  Proxy-Einstellungen oder Proxy-Zugangsdaten aus der Umgebung, folgen keinen
  Weiterleitungen und begrenzen Antworten auf 1 MiB. Die absolute Frist wird
  zwischen übertragenen Stücken zusätzlich zum Socket-Timeout geprüft.
- **Weitere Korrekturen:** Fremdes Lernmaterial erhält die vorhandenen
  Injection-Regeln und eine bereinigte Material-Kennzeichnung. Eine erfolglose
  Einstellungsänderung verändert keine Modell-Festlegung. Der Zustand wird
  atomar geschrieben; die temporäre Datei ist bereits vor dem ersten Inhalt
  nur für ihren Besitzer zugänglich. Die Startmeldung behauptet nach Ablauf
  der vier Tage nicht mehr, die alte Fassung sei noch für alle verfügbar.

## Erhaltene Funktionen und Sicherheitsprüfungen

Ultra kann weiterhin Auto-Upgrading serverweit einschalten, manuell trainieren,
Kandidaten ausprobieren, ab 5 % Gewinn freigeben, überspringen und zurücksetzen.
Ab 30 % Gewinn entsteht weiterhin eine neue Hauptversion. Eine gültige frühere
Fassung bleibt vier Tage für alle wählbar; danach gilt die Ultra-Beschränkung.
Der Gewinn bezieht sich auf den vorhandenen begrenzten Lückentext-Test, nicht
auf eine allgemeine Messung von Intelligenz oder ein Training der Modellgewichte.

Kontotrennung, Verschlüsselung, Schlüsselbindung, Google-/Home-Assistant-Schutz,
CSRF/Origin, CSP, SSRF-/DNS-/Weiterleitungsprüfungen, Größen-/Zeitgrenzen,
Ai-guard, Rechtsprüfung, Kontingente und Sandbox bleiben enthalten.
Private Recherche-Stichpunkte bleiben kontoeigen und höchstens 48 Stunden
nutzbar; gemeinsame Quellenauszüge bleiben höchstens 30 Tage nutzbar.
Widerruf und Löschwege bleiben erhalten und gelten nun auch für abgeleitete
Modellfassungen. Keine Projektabhängigkeit wurde hinzugefügt.

## Prüfungen

- Vor der Korrektur: **21 Auto-Upgrading-Tests bestanden**, 2,34 Sekunden.
- **42 neue Regressionen plus die 21 bestehenden Upgrade-Tests bestanden**,
  6,80 Sekunden. Enthalten sind echte HTTP-Aufrufe, kontrollierte konkurrierende
  Zustandsänderungen, kontobasierter Widerruf/Ablauf/Löschung und negative
  Modellaufrufprüfungen. Vorprüfungen für Web, Lernen und Datenschutz:
  **488 bestanden**, 177,02 Sekunden. Die Durchläufe überschneiden sich.
- Separater Chromium-Rundgang: **402 Prüfungen, keine Beanstandungen**;
  Chat, Einstellungen, Kontofunktionen und mehrere Bildschirmgrößen.
- Gesamtsuite: **4.452 bestanden, 12 übersprungen, keine Fehler**, in
  **890,41 Sekunden**. Elf Tests benötigen nicht vorhandene Desktop-/Add-on-
  Abbilder; eine DNS-Rebinding-Kontrollanfrage wird bereits vom Cloud-Proxy
  blockiert. Die verfügbaren Docker-Sandbox-Prüfungen und der Chromium-Rundgang
  sind enthalten. Zwei unveränderte Pydantic-Warnungen betreffen ein `ReadOnly`-
  Feld einer Fremdbibliothek.
- Nach dem Suite-Lauf wurde der Reparaturweg für unbekannte gespeicherte
  Modellnamen ergänzt. Vier zusätzliche Fälle prüfen die vier Modellfelder;
  der ergänzende Durchlauf prüft diese Änderung sowie Web, Lernen und Upgrading:
  **505 bestanden, keine Fehler, in 174,91 Sekunden**. Die vier zusätzlichen Fälle
  waren noch nicht im genannten Suite-Lauf enthalten. Damit sind insgesamt
  **46 neue Regressionen** geprüft; Durchläufe sind nicht zu addieren.
- Ruff, AST-/Bytecode-Prüfung und `git diff --check`: bestanden.
- `pip-audit` mit PyPI: **89 Fremdpakete, keine bekannten Schwachstellen**.
  Das lokale editable Projekt `aquaticy==10.0.2` ist davon ausgenommen.
  `uv pip check`: **90 Pakete kompatibel**.
- Installierte CLI und Paketmetadaten: **10.0.2 Luna** bzw. **10.0.2**.
- `uv build`: Wheel und Quellarchiv erfolgreich erstellt. Alle **66 ausgelieferten
  Programmdateien** stimmen bytegenau mit dem Arbeitsstand überein. Paketversion:
  **10.0.2**. Das Quellarchiv enthält die aktuellen Regressionen, README,
  Constraints und diesen abgeschlossenen Prüfbericht.

## Automatische Befunde und Grenzen

Bandit meldet **118 Hinweise: 95 niedrig, 22 mittel und einen hohen**;
38.731 Zeilen wurden ausgewertet.
SQL-Hinweise betreffen gebundene Werte beziehungsweise feste oder maskierte
Schema-/Tabellennamen. Feed-XML weist DTD und Entitäten bereits ab.
LAN-Bindung und Sandbox-Verzeichnisse gehören zu den bestehenden Funktionen.
Es wurden keine Sicherheitsbefunde durch neue Bandit-Unterdrückungen versteckt.

Der bekannte hohe Hinweis betrifft `verify=False` bei der Titel-Erkennung
privater IPv4-Geräte mit selbstsignierten Zertifikaten. Diese begrenzte Abfrage
überträgt keine Anmeldedaten, folgt keinen Weiterleitungen, nutzt keinen
Umgebungsproxy und hat Größen-/Zeitgrenzen. Ein Gerätename ist kein
verifizierter Identitätsnachweis. Quellen, APIs und Upgrade-Aufrufe behalten
ihre Zertifikatsprüfung. Diese bestehende Einschränkung wird nicht als behoben
ausgegeben.

Ollama muss der Betreiber gegen unberechtigten direkten Zugriff schützen;
Aquaticys Konto-Freigaben schützen die Nutzung über Aquaticy. Öffentliche
Auszüge liegen im abgeleiteten Ollama-Systemtext unverschlüsselt. Betroffene
Fassungen sind über Aquaticy vor einer weiteren Nutzung gesperrt; physische
Löschung folgt beim nächsten Hintergrundabgleich und wird bei Nichterreichbarkeit
wiederholt. Aktive Trainingsläufe können den Hintergrundabgleich verzögern;
die Prüfung vor einer neuen Modellnutzung bleibt davon unabhängig. Externe
Ollama-Sicherungen kann Aquaticy nicht nachträglich löschen.
Bereits laufende Modellaufrufe und bereits ausgegebene Antworten werden durch
einen späteren Widerruf nicht zurückgerufen.

Prüfung unter Linux/Python 3.12 mit echtem Chromium und verfügbarem lokalem
Docker-Daemon. Reale Ollama-Modelle, externe Modellanbieter, echte Google-
Anmeldungen und Windows-/FAT-Systeme wurden nicht vollständig nachgestellt.
Die Ollama-Abläufe werden mit kontrollierten Backends und HTTP-Antworten geprüft.
Die Prüfung belegt die getesteten Korrekturen, keine vollständige Abwesenheit
aller denkbaren Sicherheitslücken.

Der unveränderte Offline-Recherchebenchmark mit 2.000 globalen und 100
kontoeigenen Fakten ergab bei 100 Abrufen einen Median von **5,046 ms**, zwölf
Punkte und 24 Entschlüsselungen je Abruf; Datenbankgröße **22.097.920 Bytes**.
Die Messung lief parallel zu Tests und Browserarbeit und ist kein kontrollierter
Vergleich oder garantierter Laufzeitwert.
