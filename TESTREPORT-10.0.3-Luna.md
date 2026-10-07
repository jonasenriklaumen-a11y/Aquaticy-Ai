# Prüfbericht: 10.0.3 Luna

Stand: 2026-10-07. Grundlage: **10.0.2 Luna**, Commit `f224593`, Branch
`Aquaticy-ai`. Der Arbeitsstand war sauber; nach dem Fetch bestand kein
Unterschied zum Remote-Branch. Bereits gepushte Korrekturen bleiben enthalten.

## Prüfung in den gewünschten Rollen

Die Prüfung erfolgte nacheinander als Nutzer, Bug-Hunter, Sicherheitsforscher
und Datenschützer. Anschließend wurden die Änderungen gemeinsam auf ihre
Integration geprüft. Es wurden keine Funktionen oder Schutzprüfungen entfernt.

Alle **60 Python-Module mit 48.016 Quellzeilen** wurden mit Ruff, AST-/Bytecode-
Prüfung und Bandit untersucht. Die vertiefte Durchsicht umfasste Bedienung,
Upgrade-Lebenszyklus, Modellaufrufe und Kontingente, Netzwerkgrenzen,
Kontotrennung, Einwilligung, Widerruf und Kontolöschung. Die Gesamtsuite prüft
zusätzlich Recherche, Werkzeuge, OAuth, Verbund, Verschlüsselung und Sandbox.

## Bestätigte Fehler und Korrekturen

- **Upgrade-Anzeige nach verzögertem Start:** Die Oberfläche fragte nur weiter
  nach, wenn die Antwort bereits `running=true` enthielt. Ein später gestarteter
  Worker und sein Kandidat blieben dadurch unsichtbar. Der sichtbare Dev-Abschnitt
  gleicht eingeschaltetes Upgrading nun auch im Leerlauf ab: alle zehn Sekunden,
  während des Trainings alle vier Sekunden. Geschlossene Einstellungen,
  unsichtbare Abschnitte und versteckte Browser-Tabs erzeugen keine Polls.
  Unveränderte Daten bauen die Liste nicht neu und erhalten den Tastaturfokus.
- **Veraltete Statusantworten:** Eine ältere GET-Antwort konnte einen neueren
  POST-Zustand überschreiben. Antworten werden nun einer Anfragegeneration
  zugeordnet; Aktionen und Schließen machen ältere Abfragen ungültig.
  Parallele Bedienaktionen werden gebündelt. Hintergrundfehler bleiben am Status.
- **Wiederholter Wissenstest ohne Gewinn:** Auch vollständig gemessene Ergebnisse
  ohne Verbesserung werden nun als geprüft gespeichert. Identisches Wissen
  erzeugt im nächsten automatischen Durchlauf keine neuen Modellaufrufe.
  Neues Wissen und erzwungenes manuelles Training werden weiterhin geprüft.
  Fehler, Abbruch und konkurrierendes Abschalten speichern kein gültiges Ergebnis.
  Zurücksetzen verwirft den alten Vergleich, weil sich die Ausgangsfassung ändert.
- **Speicherbelegung vor dem Größencheck:** `httpx.iter_bytes()` entpackte eine
  komprimierte Ollama-Antwort vollständig, bevor der Client ihre Größe prüfte.
  Ein kontrollierter 16-MiB-Gzip-Fall belegte vor der Korrektur **47.707.524 Bytes**
  zusätzlichen Python-Speicher. Der Client verwendet jetzt den bestehenden
  begrenzten Gzip-/Deflate-Entpacker und das 1-MiB-Limit bereits beim Lesen.
  Der Regressionstest verlangt weniger als 8 MiB Spitzenspeicher. Zeitgrenze,
  Zertifikatsprüfung, Proxy-Ausschluss und Weiterleitungsverbot bleiben bestehen.
- **Unvollständige Kontodatenlöschung:** Modellpräferenz und gelesene Upgrade-
  Hinweise lagen außerhalb des persönlichen Profils und blieben beim Leeren oder
  Löschen erhalten. Beide Wege entfernen jetzt ausschließlich die Einträge dieses
  Kontos. Andere Konten, öffentliche Versionshistorie, Verbrauchsgrenzen und
  Missbrauchsschutz bleiben unverändert. Scheitert das Speichern dieser Löschung,
  beginnen die destruktiven Datenbank-/Profiländerungen nicht. Ohne bestehende
  Einträge wird keine neue Upgrade-Datei angelegt. Unbekannte Hinweis-IDs werden
  abgewiesen, ohne Konto-Metadaten anzulegen.
- **Lernwissen fehlte bei normalen Modellaufrufen:** Ollama übernimmt den
  eingebauten SYSTEM-Text nur, wenn die Anfrage keine eigene Systemnachricht
  liefert. Aquaticy sendet eigene Regeln; der isolierte Lückentext-Test tat dies
  nicht. Diese Ursache wurde auch im [Ollama-Quellcode](https://github.com/ollama/ollama/blob/d3c846f8b0279e79b0e3a960a7575fde6920e9df/server/routes.go#L3162)
  nachvollzogen. Haupt-, Abschluss- und Helferaufrufe ergänzen nun genau die
  gültigen Quellenauszüge der gewählten Modellfassung. Vorhandene Systemregeln,
  multimodale Blöcke und Injection-Regeln bleiben enthalten. Entschlüsselung,
  aktuelle Zustimmung, Freigabe und ursprüngliche Ablaufzeit werden geprüft.
  Zusatzwissen landet nur in der ausgehenden Anfrage und nicht im gespeicherten
  Verlauf. Reservierung und Verbrauchsschätzung berücksichtigen diese Anfrage.
  Fremde Anbieter und Ausgangsmodelle erhalten keinen solchen Zusatz.

## Prüfungen

- **29 neue Regressionen bestanden**, 16,19 Sekunden. Enthalten sind Chromium,
  verzögerte Antworten, unterbrochene Trainingsläufe, begrenzte Dekompression,
  kontobasierte Löschwege und tatsächliche Aufrufargumente aller drei Modellpfade.
- Die beiden Browserfehler, wiederholte automatische Tests, der fehlende
  Vergleich nach Zurücksetzen, die Speicherbelegung und die zurückbleibenden
  Kontoeinträge wurden vor der jeweiligen Korrektur reproduziert.
- Zwischenprüfung: **135 Tests bestanden** für Upgrading, Lernen und Konten.
  Die Durchläufe überschneiden sich und sind nicht zu addieren.
- Gesamtsuite: **4.485 bestanden, 12 übersprungen, keine Fehler**, in
  **986,17 Sekunden**. Enthalten sind der vollständige Chromium-Rundgang und
  die verfügbaren Live-Docker-Sandbox-Prüfungen. Elf Auslassungen betreffen
  nicht vorhandene Desktop-/Add-on-Abbilder; eine DNS-Rebinding-Kontrollanfrage
  wird bereits vom Cloud-Proxy blockiert. Zwei bestehende Pydantic-Warnungen
  betreffen das `ReadOnly`-Feld einer Fremdbibliothek.
- Ruff für Programm und Tests, AST, Bytecode und `git diff --check`: bestanden.
- `pip-audit`: **89 Fremdpakete, keine bekannten Schwachstellen**. Das lokale
  editable Projekt `aquaticy==10.0.3` ist von der PyPI-Prüfung ausgenommen.
  `uv pip check`: **90 kompatible Pakete**. Keine neue Projektabhängigkeit.
- Installierte CLI: **10.0.3 Luna**; installierte Paketmetadaten: **10.0.3**.
- Wheel und Quellarchiv: erfolgreich gebaut. Alle **66 Programmdateien**
  stimmen bytegenau mit dem Arbeitsstand überein; beide Pakete tragen
  **10.0.3**. Das Quellarchiv enthält README, Constraints, die neuen Regressionen
  und diesen abgeschlossenen Prüfbericht.

## Automatische Befunde und Grenzen

Bandit: **119 Hinweise: 95 niedrig, 23 mittel, einer hoch**, bei 38.823
ausgewerteten Nicht-Kommentarzeilen. Der zusätzliche mittlere SQL-Hinweis
betrifft die neue Auswahl konkreter Fakten: Der variable SQL-Teil besteht
ausschließlich aus erzeugten `?`-Platzhaltern; alle Fakten-IDs sind gebundene
Werte. Der negative Test mit einer SQL-Zeichenfolge liefert keine Fakten.
Es wurden keine neuen Bandit-Unterdrückungen hinzugefügt.

Der bestehende hohe Hinweis betrifft `lan.py:260`: die begrenzte Titelabfrage
privater IPv4-Geräte erlaubt selbstsignierte Zertifikate. Sie überträgt keine
Anmeldedaten, folgt keinen Weiterleitungen, nutzt keinen Umgebungsproxy und
hat Zeit-/Größengrenzen. Ein erkannter Titel bestätigt keine Geräteidentität.
Diese bestehende Ausnahme wird nicht als behoben ausgegeben.

Das Upgrade verändert keine Modellgewichte. Ein Gewinn ist das Ergebnis des
begrenzten Lückentext-Tests und keine allgemeine Intelligenzmessung.
Private Recherche bleibt kontoeigen und höchstens 48 Stunden nutzbar;
gemeinsame öffentliche Auszüge bleiben höchstens 30 Tage nutzbar.
Die freiwillige Lern-Zustimmung `2026-10-07.1`, ihre Sicherheitsfilter und
Widerrufskontrollen bleiben erforderlich. Kontokennungen, private Chats,
Uploads und Erinnerungen werden nicht in das gemeinsame Lernwissen übernommen.

Ollama-Zugriff und dessen Sicherungen muss der Betreiber schützen. Öffentliche
Auszüge im dortigen Modelltext sind unverschlüsselt. Ungültige Fassungen werden
vor weiterer Aquaticy-Nutzung gesperrt; physische Löschung folgt beim
Hintergrundabgleich und wird bei Fehlern erneut versucht. Aktive Trainingsläufe
können diesen Abgleich verzögern. Bereits laufende Aufrufe und ausgegebene
Antworten werden durch einen späteren Widerruf nicht zurückgerufen.

Geprüft wurde unter Linux/Python 3.12 mit Chromium und lokalem Docker.
Modellaufrufe, Ollama-Antworten und Nebenläufigkeit wurden kontrolliert
nachgestellt. Ein vollständiger Lauf mit realen Ollama-Modellgewichten,
externen Modellanbietern, echten Google-Anmeldungen oder Windows/FAT gehörte
nicht zu dieser Prüfung. Der Bericht belegt die geprüften Korrekturen und
ist keine Zusicherung, dass sämtliche denkbaren Sicherheitslücken fehlen.
