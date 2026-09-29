# Aquaticy AI 9.5.31 Spark

**Aquaticy** recherchiert für dich. Du stellst eine Frage, Aquaticy sucht im Web, liest die
passenden Seiten und fasst das Ergebnis zusammen — mit Quelle an jeder Angabe. Es läuft im
Terminal, im Browser und auf dem Handy.

```
$ aquaticy

> Finde mir gute Cafés in Mönchengladbach mit WLAN

  [Suche] cafés mönchengladbach
  [Suche] café mönchengladbach wlan arbeiten
  [Lese]  4 Seiten...

  Ich habe 6 Cafés gefunden, die zu deiner Anfrage passen:

  1. Café Nordwand — Hindenburgstr. 12
     WLAN ausdrücklich erwähnt, Steckdosen an den Fensterplätzen.
     Quelle: die gelesene Café-Seite
  ...

> davon nur die, die sonntags offen haben
```

---

## Inhalt

- [Was Aquaticy kann](#was-aquaticy-kann)
- [Quickstart](#quickstart)
- [Installation im Detail](#installation-im-detail)
- [Benutzung im Terminal](#benutzung-im-terminal)
- [Die Weboberfläche](#die-weboberfläche)
- [Konten: Normal, Pro und Ultra](#konten-normal-pro-und-ultra)
- [Add-ons](#add-ons)
- [Virtual machine und User mode](#virtual-machine-und-user-mode)
- [Speicher](#speicher)
- [Aufträge](#aufträge)
- [Gmail und Kalender](#gmail-und-kalender)
- [Zuhause: Heimnetz, Home Assistant, Lager](#zuhause-heimnetz-home-assistant-lager)
- [Sicherheit, Rechts-Leitplanken und Ai-guard](#sicherheit-rechts-leitplanken-und-ai-guard)
- [Modelle und Anbieter](#modelle-und-anbieter)
- [Suche](#suche)
- [Im Container](#im-container)
- [Konfiguration](#konfiguration)
- [Konten verwalten (Betreiber)](#konten-verwalten-betreiber)
- [Entwicklung](#entwicklung)
- [Lizenz](#lizenz)

---

## Was Aquaticy kann

**Recherche**
- Sucht selbst im Web, liest die Seiten und nennt zu jeder Angabe die Quelle.
- Merkt sich den Gesprächsverlauf: Nachfragen wie „nur die mit 4+ Sternen“ funktionieren.
- Fragt selbst nach, wenn etwas Entscheidendes offen ist (Budget, Ort, was gemeint ist).
- **Strukturieren:** zerlegt große Fragen in Teilfragen und schickt für jede einen eigenen
  Helfer los — im Pro-Modus bis zu 50 gleichzeitig.
- **Gegenprüfen:** prüft Ergebnisse auf anderen Seiten nach.
- **Bilder als Eingabe:** Foto anhängen, Aquaticy erkennt, was darauf ist, und sucht danach.
- **Öffentliche Webcams und Satellitenbilder** auf Wunsch einbeziehen.
- Funktioniert auch ohne Internetsuche — dann aus eigenem Wissen, mit Hinweis, wo es veraltet
  sein könnte.
- **Sofortantworten ohne Modell:** Einfache Nachrichten wie „Hallo“, „Danke“, „Wie geht’s?“,
  „Wer bist du?“ oder „Wer hat dich erschaffen?“ beantwortet Aquaticy sofort und kostenlos —
  mit vielen wechselnden Formulierungen (bei den häufigen je 25), zufällig gewählt und Wort für
  Wort ausgegeben wie vom Modell. Alles, was Suche oder Nachdenken braucht, geht wie gewohnt an
  das Modell.

**Arbeitsweisen**
- **Normal** — ein ganz normales Gespräch, gesucht wird, wenn es nötig ist.
- **Pro** — für große Fragen: das stärkste Modell und bis zu 50 Helfer. Der Master plant
  schon, während die Rechtsprüfung läuft — losgeschickt wird erst nach dem OK.
- **Code** — schreibt Code statt langer Texte und probiert ihn in einer abgeschotteten
  **virtual machine** wirklich aus. Die virtual machine fährt schon hoch, während das Modell nachdenkt.

**Oberfläche**
- Terminal-Chat, Weboberfläche im Browser, Zugriff vom Handy im eigenen Netz.
- **Design:** Hell, Dunkel oder wie das System; Standard (grün), Schlicht (schwarz-weiß) oder
  ein selbst erstelltes Design mit eigenen Farben für Akzent, Hintergrund und Seitenleiste.
- **Sprache:** Deutsch oder Englisch — Oberfläche und Antworten wechseln sofort.
- Slash-Befehle wie `/max` leuchten beim Tippen im Akzentton, damit man sie sofort erkennt.
- Chats durchsuchen, umbenennen, exportieren (HTML, Markdown, CSV).

**Extras**
- **Add-ons:** GitHub, Wetter, RSS-Feeds, Tagesschau, Wikipedia, Währungsrechner, Feiertage,
  WhatsApp Web, Signal, Telegram Web, Blender.
- **Speicher:** merkt sich auf Wunsch, was länger gilt — verschlüsselt, jederzeit einsehbar.
- **Aufträge:** regelmäßig recherchieren, Preise, Webcams oder Satellitenbilder beobachten.
- **Gmail und Kalender:** Termine und Mails lesen, auf Wunsch Termine anlegen und
  Mail-Entwürfe schreiben (verschickt wird nie etwas).
- **Zuhause** (Ultra): Geräte im Heimnetz finden, Home Assistant, Lagerverwaltung.
- **KI-Bilder** erstellen lassen.
- **Modell automatisch wählen:** für jede Nachricht das passende Modell.

**Sicherheit**
- Rechts-Leitplanken nach Grundgesetz und BGB, Ai-guard gegen Missbrauch.
- Keine Bezahlschranken, Logins oder Captchas umgehen; `robots.txt` wird beachtet.
- Konten sauber getrennt, Zugangsdaten verschlüsselt, Schutz vor Mehrfachkonten per Anhaltspunkten.
- XSS-Schutz: strenge Content-Security-Policy (Skripte nur mit Einmal-Schlüssel je Seite),
  alles Fremde wird maskiert; PHP- und JSP-Dateien lassen sich nicht hochladen, und
  angebliche Bilder müssen echte Bilder sein.

---

## Quickstart

```bash
# 1. Installieren (aus diesem Repo)
git clone --branch Aquaticy-ai --single-branch https://github.com/jonasenriklaumen-a11y/Aquaticy-Ai.git
cd Aquaticy-Ai
uv tool install --force --reinstall .
aquaticy --version            # 9.5.31 Spark

# 2. Einrichten — fragt nach Modell und Schlüssel und testet beide
aquaticy setup

# 3. Loslegen — im Terminal …
aquaticy

# … oder im Browser (öffnet sich von selbst)
aquaticy web
```

**Voraussetzungen:** Python 3.11 oder neuer und [uv](https://docs.astral.sh/uv/).

**Aktualisieren** (im Repo-Ordner ausführen):

```bash
cd ~/Aquaticy-Ai
git switch Aquaticy-ai
git pull --ff-only origin Aquaticy-ai
uv tool install --force --reinstall .
aquaticy --version
```

Die Installation liest den Code aus dem aktuellen Repo-Ordner. Ein bereits installiertes
`aquaticy` aktualisiert sich durch `git pull` allein nicht: der letzte `uv`-Befehl
installiert die neue Fassung erneut. Wenn du GitHubs [Download ZIP](https://github.com/jonasenriklaumen-a11y/Aquaticy-Ai/archive/refs/heads/Aquaticy-ai.zip)
verwendest, lade das ZIP neu herunter, entpacke es und führe
`uv tool install --force --reinstall .` im entpackten Ordner aus. Ein altes ZIP
oder ein anderer Ordner enthält weiterhin den alten Code.

`aquaticy setup` fragt genau zwei Dinge:

| Was | Woher | Pflicht? |
|---|---|---|
| KI-Anbieter + Schlüssel | [Mistral](https://console.mistral.ai/api-keys/) · [NVIDIA NIM](https://build.nvidia.com/) · oder lokal mit [Ollama](https://ollama.com), ganz ohne Schlüssel | ja |
| Suchmaschine | Nichts — die offene Suche ist Standard und braucht weder Schlüssel noch Konto. | nein |

Beides wird sofort getestet, bevor die Einstellungen gespeichert werden
(`~/.config/aquaticy/.env`, nur für dich lesbar).

Eine einzelne Frage ohne Chat:

```bash
aquaticy "welche Bahnstrecken in NRW sind gerade gesperrt?"
```

---

## Installation im Detail

### Linux und macOS

Wie im Quickstart. Zum Entwickeln stattdessen:

```bash
uv venv && uv pip install -c constraints.txt -e ".[browser,dev]"
uv run aquaticy
```

### Windows (PowerShell)

```powershell
# uv installieren, falls noch nicht vorhanden
powershell -c "irm https://astral.sh/uv/install.ps1 | iex"

git clone --branch Aquaticy-ai `
  https://github.com/jonasenriklaumen-a11y/Aquaticy-Ai.git
cd Aquaticy-Ai
uv tool install --force --reinstall .
uv tool update-shell        # danach PowerShell neu öffnen

aquaticy install-model      # holt Ollama per winget und lädt die Modelle
```

- Ohne winget: Installer von [ollama.com/download](https://ollama.com/download) laden und
  `aquaticy install-model` erneut starten.
- Pfade in Anführungszeichen: `aquaticy --image "C:\Users\du\Bilder\foto.jpg"`
- Pfeiltasten-Verlauf im Chat: `pip install pyreadline3`

### Ganz ohne Schlüssel: lokales Modell

```bash
aquaticy install-model
```

Der Befehl sucht Ollama (und fragt, bevor er etwas installiert), startet es, schlägt anhand
von Arbeitsspeicher und Grafikkarte ein passendes Modell vor, lädt es und prüft an einem echten
Aufruf, ob es Werkzeuge bedienen kann. Nur ein Modell, das den Test besteht, wird eingetragen.
Auf Wunsch richtet er zusätzlich ein Modell für Bilder ein.

```bash
aquaticy install-model --model qwen2.5:14b                    # nur Text
aquaticy install-model --vision-model llava:7b                # Text + Bild
aquaticy install-model --vision-only --vision-model llava:7b  # nur Bild nachrüsten
aquaticy install-model --yes                                  # ohne Rückfragen
```

**Ein Modell für alles** (Suche und Bilder):

| Modell | ca. Größe | ab VRAM |
|---|---|---|
| `qwen3-vl:4b` | 3,3 GB | 6 GB |
| `gemma4:e4b` | 3,5 GB | 6 GB |
| `qwen3-vl:8b` | 6,1 GB | 12 GB |
| `gemma4:12b` | 6,6 GB | 10 GB |
| `gemma4:26b` | 16,0 GB | 24 GB |

**Nur Recherche:** `qwen2.5:3b`, `qwen2.5:7b`, `llama3.1:8b`, `qwen3:8b`, `qwen2.5:14b`.
**Nur Bilder:** `moondream`, `gemma3:4b`, `llava:7b`, `minicpm-v`, `gemma3:12b`.

> Das Modell-Kürzel muss `ollama_chat/` lauten, nicht `ollama/` — nur so kommen Werkzeuge
> durch. `aquaticy install-model` schreibt es automatisch richtig.

Wird der Grafikspeicher knapp (`model runner has unexpectedly stopped`), bietet Aquaticy von
selbst ein kleineres Modell an. Von Hand: `ollama ps`, `ollama stop <modell>`.

### Seiten mit echtem Browser laden

Für Seiten, die ihren Inhalt erst per JavaScript nachladen:

```bash
aquaticy install-browser
```

---

## Benutzung im Terminal

### Slash-Befehle

| Befehl | Wirkung |
|---|---|
| `/max <frage>` | im Pro-Modus mit allen Helfern recherchieren |
| `/location <ort>` | Ortsfilter setzen (ohne Ort: aufheben) |
| `/model <name>` | Modell wechseln, z. B. `mistral/mistral-large-latest` |
| `/image <pfad>` | Bild beschreiben lassen und damit weitersuchen |
| `/export html\|md\|csv` | Recherche dieser Sitzung speichern |
| `/history` | frühere Recherchen anzeigen |
| `/notes` | Merkzettel anzeigen |
| `/notes delete <nr>` / `/notes clear` | Notiz oder alle Notizen löschen (Website) |
| `/clear` | Gespräch neu beginnen |
| `/memory` / `/forget` | Langzeitspeicher anzeigen oder leeren |
| `/uploads` / `/uploads clear` | Hochgeladene Dateien anzeigen oder löschen |
| `/help` | Übersicht |
| `/quit` / `/exit` / `/q` | Terminal beenden (auch <kbd>Strg</kbd>+<kbd>D</kbd>); im Browser Fenster schließen |

### Optionen

```bash
aquaticy --location "Mönchengladbach" --lang de   # Ortsfilter vorgeben
aquaticy --model mistral/mistral-large-latest     # Modell für diese Sitzung
aquaticy --image foto.jpg                         # Bild als Ausgangspunkt
aquaticy --max-calls 30                           # mehr Suchen je Frage erlauben
aquaticy --no-stream                              # Antwort am Stück statt fließend
aquaticy --download-images                        # Bilder beim Export mitspeichern
```

### Alle Befehle

```bash
aquaticy setup                  # Ersteinrichtung
aquaticy config                 # aktive Einstellungen prüfen
aquaticy web                    # Weboberfläche starten
aquaticy web --lan              # auch vom Handy im eigenen Netz erreichbar
aquaticy search "cafés köln"    # nur suchen, ohne KI
aquaticy fetch https://…        # nur eine Seite lesen, ohne KI
aquaticy history                # vergangene Recherchen
aquaticy export html -n 3       # letzte 3 Recherchen exportieren
aquaticy notes                  # Merkzettel anzeigen (--delete N löscht)
aquaticy cache                  # Zwischenspeicher anzeigen (--clear leert ihn)
aquaticy install-model          # lokales Modell einrichten
aquaticy install-browser        # echten Browser für schwierige Seiten
aquaticy google                 # Gmail und Kalender verbinden (--aendern: auch schreiben)
aquaticy connect-ha             # Home Assistant verbinden
aquaticy lan                    # Geräte im eigenen Netz anzeigen
aquaticy sandbox                # zeigt, wie abgeschottet Aquaticy gerade läuft
aquaticy list                   # Konten mit Adresse, Nutzung und Ai-guard-Stand
aquaticy remove "name"         # Konto samt Sitzungen, Verbrauch und privaten Daten löschen (fragt nach; --yes ohne Rückfrage)
aquaticy ban "name"             # Konto oder IP-Adresse sperren
aquaticy unban "name"           # wieder freigeben
aquaticy aiguard "Satz"         # zeigt, wie Ai-guard einen Satz einstuft (sperrt niemanden)
aquaticy pro-code               # Code für neue Pro-Konten
aquaticy ultra-code             # Code für neue Ultra-Konten
aquaticy version
```

---

## Die Weboberfläche

```bash
aquaticy web          # öffnet sich im Browser
aquaticy web --lan    # zeigt alle Adressen, unter denen es im Heimnetz erreichbar ist
```

**Chat.** Links die letzten Chats (durchsuchbar), in der Mitte das Gespräch, unten die
Eingabe mit den drei Arbeitsweisen Normal, Pro und Code. Dateien und Bilder hängst du mit 📎 an.
Ein vollständig geschriebener Slash-Befehl leuchtet im Akzentton; der Text dahinter bleibt normal.

**Modellauswahl** (oben in der Mitte):
- **Denktiefe** Low / Medium / High — wie gründlich Aquaticy nachdenkt.
- **Helfer** — wie viele gleichzeitig suchen (Modus Normal und Code 1–12, Modus Pro 1–50).
- **Im Web suchen**, **Öffentliche Webcams & Satellitenbilder**, **Denken** (mitlesen, wie
  Aquaticy überlegt), **Strukturieren**, **Gegenprüfen**.
- Im Code-Modus: **Code wirklich ausprobieren** in der virtual machine.

**Design** (links unten): Hell, Dunkel oder wie das System. Dazu:
- **Standard** — das grüne Papier.
- **Schlicht** — alles weiß mit schwarzer Schrift und schwarzen Knöpfen; im Dunkelmodus
  genau umgekehrt.
- **Design selber erstellen** — wähle die Farbe für den **Akzent** (alles, was bei Standard
  grün ist, z. B. blau, pink oder rot), den **Hintergrund** und die **Seitenleiste** links.
  Die Schrift passt sich automatisch an, damit sie lesbar bleibt. Das Design wird an deinem
  Konto gespeichert und gilt auf jedem Gerät.
- **Sprache** — Deutsch oder English. Knöpfe, Fenster, Hinweise und Platzhalter wechseln sofort,
  ohne Neuladen, und Aquaticy antwortet in der gewählten Sprache. Was im Chat steht (deine
  Fragen, die Antworten, Chat-Titel), bleibt, wie es geschrieben wurde. Auch die Sprache wird
  am Konto gespeichert.

**Einstellungen** — was du dort speicherst, gilt sofort:
- **Konto** — Name, E-Mail, Kontotyp, Nutzung, Abmelden.
- **Modell** — Hauptmodell, Bild-Modell, Helfer-Modell, Code-Modell, eigene Adresse.
- **Eigene Modelle** — erscheint erst, wenn du oben ein eigenes Modell oder einen eigenen
  Schlüssel einträgst, und zeigt genau diese. Schlüssel werden verschlüsselt gespeichert und
  nie an den Browser zurückgegeben.
- **virtual machine** — Größe, User mode, Add-ons, Login-Apps.
- **Speicher**, **Mitlesen**, **Auslastung** (nur Ultra), **Nutzung**, **Aufträge**,
  **Gmail & Kalender**, **Zuhause & Netz** (Ultra), **Suche**, **Ort & Sprache**,
  **Helfer & Grenzen**, **Dev settings**.

**Merkzettel** — was sich Aquaticy über dich gemerkt hat; jede Zeile einzeln löschbar.

---

## Konten: Normal, Pro und Ultra

Wer die Weboberfläche öffnet, legt zuerst ein Konto an. Jedes Konto hat eigene Chats,
Einstellungen, Speicher und Schlüssel.

**Mehrfachkonten (seit 9.5.31): Anhaltspunkte statt „ein Konto pro IP-Adresse“.** Zwei Menschen
im selben Haushalt teilen sich die Adresse — das allein sperrt nicht mehr. Aquaticy zählt Punkte
gegen jedes vorhandene Konto; ab **3 Punkten** wird kein neues Konto angelegt, ab 1,5 steht ein
Hinweis im Terminal.

| Anhaltspunkt | Punkte |
|---|---|
| dasselbe Gerät (zufällige Geräte-Kennung im Cookie `aquaticy_device`) | 3 |
| gleiche Hardware **und** gleicher Browser | 1,5 |
| gleiche Hardware | 1 |
| gleicher Browser | 0,5 |
| dieselbe IP-Adresse (Anlege- oder zuletzt genutzte) | 1 |
| sehr ähnliche E-Mail-Adresse (`max.muster@…` / `maxmuster7@…`) | 1 |

Beispiele: selbe Adresse + selber Browser = 1,5 → geht durch. Zwei gleiche Handys im selben WLAN
= 2,5 → geht durch. Dasselbe Handy (Kennung) = 3 → gesperrt. Selbe Adresse + ähnliche E-Mail +
gleiche Hardware = 3 → gesperrt. Der eigene Rechner (Loopback) zählt nicht als gleiche Adresse.
Gespeichert werden je Konto höchstens 20 Geräte: die Kennung nur als Hash, dazu eine kurze
lesbare Zusammenfassung („Windows · 16 Kerne · 8 GB · 2560x1440 · NVIDIA …“, „Chrome 126,
de-DE“). Kein Canvas- oder Audio-Fingerabdruck. Mit dem Konto werden auch die Geräte gelöscht.

| | Normal | Pro | Ultra |
|---|---|---|---|
| Recherche, Chat, Code-Modus, Add-ons ohne virtual machine | ✔ | ✔ | ✔ |
| Nutzung je 5-Stunden-Sitzung | 300.000 Token | 533.333 Token | unbegrenzt |
| Nutzung je Woche | 2 Mio. Token | 4 Mio. Token | unbegrenzt |
| Auslastungsanzeige | – | – | ✔ |
| Heimnetz, Home Assistant, Lagerverwaltung | – | – | ✔ |
| User mode, virtual machine „Plus“, virtual-machine-Add-ons | – | – | ✔ |
| Internet für die virtual machine (Code-Modus) | – | – | ✔ |
| Eigene Adressen für Modell und Suche | – | – | ✔ |
| Rechts-Leitplanken abschaltbar | – | – | ✔ |
| Ai-guard | sperrt | sperrt | warnt nur |
| Code zum Anlegen | – | 9 Zeichen | 14 Zeichen |

**Codes.** Beim ersten Start erzeugt Aquaticy zwei geheime Codes und zeigt sie im Terminal:
- den **Pro-Code** (9 Zeichen) — später mit `aquaticy pro-code`, vorgeben mit
  `AQUATICY_PRO_CODE`;
- den **Ultra-Code** (14 Zeichen, mit Buchstaben, Ziffern und Sonderzeichen, unabhängig vom
  Pro-Code) — später mit `aquaticy ultra-code`, vorgeben mit `AQUATICY_ULTRA_CODE`.

**Nutzung.** Die Sitzung beginnt mit deiner ersten Nachricht und läuft fünf Stunden, die Woche
beginnt zur Uhrzeit deiner Kontoerstellung. Angezeigt wird beides in Prozent (*Einstellungen →
Nutzung*, ab 80 % auch als Hinweis). Gezählt wird nur auf dem Server — wer Chats löscht, löscht
nicht seinen Verbrauch. Anfragen über **eigene Schlüssel** zählen nicht gegen das Limit.

---

## Add-ons

*Einstellungen → virtual machine → 🧩 Add-ons.* Jedes Add-on lässt sich installieren, an- und
ausschalten und wieder entfernen; aus dem Chat heraus lässt sich nichts davon ändern. Anmelden
musst du dich immer selbst — Aquaticy kennt keine Passwörter. Unter jedem Add-on stellst du ein,
was Aquaticy damit darf (**Rechte**).

| Add-on | Was es kann | Anmeldung |
|---|---|---|
| 🐙 GitHub | Repos, Issues, Pull Requests und Dateien lesen (nie schreiben) | Token |
| 🌦️ Wetter | Wetter und 7-Tage-Vorhersage (Open-Meteo) | keine |
| 📰 RSS-Feeds | deine eigenen Nachrichtenquellen zusammenfassen | Feed-Adressen |
| 🗞️ Tagesschau | aktuelle Meldungen nach Thema oder als Suche | keine |
| 📚 Wikipedia | Begriffe nachschlagen, Kurzfassung mit Link (Deutsch/Englisch) | keine |
| 💱 Währungsrechner | Tageskurse der EZB für gut 30 Währungen | keine |
| 📅 Feiertage | gesetzliche Feiertage weltweit, auch je Bundesland | keine |
| 💬 WhatsApp Web | Chats lesen, Antworten vorbereiten — senden nur nach deinem Ja | QR-Code |
| 🔵 Signal | wie WhatsApp, mit Signal Desktop | QR-Code |
| ✈️ Telegram Web | Kanäle und Gruppen lesen, Antworten vorbereiten | QR-Code |
| 🧊 Blender | 3D-Modelle bauen und rendern in der virtual machine | keine |

WhatsApp, Signal, Telegram und Blender laufen in der virtual machine und brauchen den User mode
(Ultra). Die Tagesschau ist nur für den privaten Gebrauch; Aquaticy hält die erlaubten 60
Abrufe pro Stunde ein.

---

## Virtual machine und User mode

> Früher hieß die virtual machine „Werkstatt“ — seit 9.5.30 durchgehend **virtual machine**.

Die **virtual machine** ist ein abgeschotteter Rechner, in dem Aquaticy Code wirklich ausführt:

| Größe | Kerne | Arbeitsspeicher | Platte |
|---|---|---|---|
| Normal | 1 | 1 GB | 4 GB |
| Plus (Ultra) | 4 | 6 GB | 20 GB |

- Kein Internet, kein Zugriff aufs Heimnetz, kein root; die Platte ist hart begrenzt.
- **Internet für die virtual machine** (Ultra, seit 9.5.31): ein eigener Schalter in den
  Einstellungen. Dann gehen im Code-Modus `pip install` und `curl` — das Heimnetz (private
  Adressbereiche, Router, Home Assistant) bleibt gesperrt, mit derselben Sperre wie im User mode.
  Lässt sie sich nicht setzen oder fehlt ein Bereich, startet die Maschine gar nicht. Braucht das
  Desktop-Abbild (unten). Normal- und Pro-Konten sehen den Schalter nur mit Ultra-Hinweis; der
  Server lehnt ihn für sie ab.
- Angehängte Dateien liegen unter `eingang`, alles Erstellte kannst du herunterladen.
- 20 Minuten nach der letzten Nachricht wird die virtual machine samt Inhalt gelöscht.

Der **User mode** (Ultra) macht aus der virtual machine einen kleinen Desktop mit Internet: Aquaticy
sieht den Bildschirm, klickt, tippt und nutzt Browser, Office oder Bildbearbeitung — wie ein
Mensch. Das Heimnetz bleibt gesperrt. Absenden, Kaufen und Löschen nur nach deinem Ja;
Passwörter, Zahlungsdaten, Captchas und „Alle akzeptieren“ fasst Aquaticy nie an. Bei
**Login-Apps** meldest du dich selbst an: Was du dort tippst, landet nur in der App.

Einmalig nötig (Betreiber):

```bash
docker build -f docker/workshop-desktop.Dockerfile -t aquaticy-werkstatt-desktop:local .
```

---

## Speicher

Mit eingeschaltetem Speicher merkt sich Aquaticy, was länger gilt — Wohnort, Vorlieben,
laufende Vorhaben. Nur Text, verschlüsselt, höchstens 400 MB für alles im Konto zusammen.
Unter **„Was weißt du über mich?“** siehst du jeden Eintrag und kannst ihn einzeln oder alle
auf einmal löschen.

---

## Aufträge

*Einstellungen → Aufträge.* Aquaticy bleibt für dich dran:

- **regelmäßig recherchieren** — täglich, stündlich, wöchentlich;
- **Kamera, Satellit oder Straße beobachten** — z. B. „ein oranges Flugzeug ist sichtbar“;
- **Preis beobachten**;
- **Bild hochladen und danach suchen**, bis ein Angebot auftaucht.

Tritt ein, worauf du wartest, bekommst du einen neuen Chat — mit Bild und Uhrzeit. Nur
öffentliche Quellen, keine privaten Kameras, keine Anmeldungen.

---

## Gmail und Kalender

Aquaticy kann Termine und Mails lesen und — wenn du „Ändern erlaubt“ einschaltest — Termine
anlegen und ändern und Mail-**Entwürfe** schreiben. **Verschickt wird nie eine Mail, gelöscht
wird nichts**; diese Rechte holt Aquaticy bei Google gar nicht erst.

### Einrichten — einmal, etwa fünf Minuten

1. Auf [console.cloud.google.com](https://console.cloud.google.com/) ein neues Projekt anlegen.
2. **APIs und Dienste → Bibliothek:** „Gmail API“ und „Google Calendar API“ aktivieren.
3. **OAuth-Zustimmungsbildschirm:** Nutzertyp „Extern“, dich selbst als Testnutzer eintragen.
4. **Anmeldedaten → OAuth-Client-ID**, Typ **Desktop-App**, Weiterleitung
   `http://localhost:8765/google`.
5. Client-ID und Client-Secret in *Einstellungen → Gmail & Kalender* eintragen (oder als
   `GOOGLE_CLIENT_ID` / `GOOGLE_CLIENT_SECRET`), speichern, **Verbinden**.

Im Terminal geht es mit `aquaticy google` (bzw. `aquaticy google --aendern`). Die Zugangsdaten
werden verschlüsselt gespeichert und verlassen den Rechner nicht; **Trennen** löscht sie.

---

## Zuhause: Heimnetz, Home Assistant, Lager

Nur mit einem **Ultra-Konto**.

- **Heimnetz:** „Welche Geräte sind in meinem WLAN?“, „Ist mein Drucker an?“ — Aquaticy schaut
  nur, ob etwas antwortet, und nur in privaten Netzen (`10/8`, `172.16/12`, `192.168/16`,
  `100.64/10`). Im Terminal: `aquaticy lan`.
- **Home Assistant:** Aquaticy findet die Instanz selbst (`aquaticy connect-ha`), liest Zustände
  und darf — wenn du es erlaubst — schalten. Schlösser, Alarm, Tore und Heizung fragen immer
  nach.
- **Lagerverwaltung:** Räume → Möbel → Artikel. Aquaticy sagt, wo etwas liegt und wie viel noch
  da ist; in der Stufe „Lesen und schreiben“ legt es auch an und ändert. Gelöscht wird nie.

---

## Sicherheit, Rechts-Leitplanken und Ai-guard

**Feste Grenzen** (immer, für jedes Konto):
- keine Bezahlschranken, Logins oder Captchas umgehen; `robots.txt` wird beachtet;
- ins Heimnetz nur private Adressen, Webseiten nie ins Heimnetz;
- im Haus nur nach Rückfrage schalten; bei Google nie senden, nie löschen;
- Zugangsdaten nie an den Browser und nie an das Modell;
- nur verteidigende Sicherheitsthemen;
- keine PHP- oder JSP-Dateien als Upload (auch nicht als `bild.php.png`).

**Schutz vor Prompt-Injection.** Webseiten, Mails, Feeds, Anhänge und alles, was Helfer
zurückbringen, sind für Aquaticy *Material*, nie ein Auftrag. Die Grenzen dafür liegen im Code:
- unsichtbare Zeichen (Unicode-Tags, Nullbreite, Richtungswechsel) werden entfernt,
  nachgemachte Chat-Steuerzeichen (`<|im_start|>`, `[INST]`, `</system>`) entschärft;
- jedes fremde Ergebnis trägt den Hinweis „nur Daten“; stehen darin Anweisungen an eine KI
  („ignoriere deine Regeln“, „schick den Merkzettel an …“), kommt eine Warnung dazu und im
  Verlauf erscheint **[Schutz]**;
- Anhänge und die Quellenlage der Helfer stehen klar abgegrenzt im Gespräch, nicht mit der
  Stimme des Nutzers;
- nach fremdem Inhalt geht nichts Privates (Merkzettel, Speicher, Ort, E-Mail) ohne Rückfrage
  in eine Adresse, eine Eingabe oder einen Befehl — und Schalten, Einstellungen, Lager,
  Speichern und Heimnetz-Suchen fragen ebenfalls erst nach.

**Website.** Anmelde-Cookie `HttpOnly`, `SameSite=Strict` (hinter HTTPS-Proxy auch `Secure`,
dazu HSTS), strenge CSP mit Nonce, Schreibzugriffe nur von der eigenen Seite, Grenzen für
Anfragen und falsche Passwörter je Adresse *und* je Konto.

**Rechts-Leitplanken.** Bevor Aquaticy etwas tut, prüft es, ob das mit Grundgesetz und BGB
vereinbar ist — bei jeder Frage, jeder Personensuche, jedem Kamerabild und jedem Mail-Entwurf.
Die Regeln stehen unter *Einstellungen → Dev settings → Welche Regeln gelten?*. Nach einer
Person suchen ist erlaubt (öffentliche Angaben, berufliche Rolle, veröffentlichte Kontaktwege);
nicht erlaubt ist, private Anschrift, Handynummer oder Aufenthaltsort auszuforschen oder ein
überwachungsartiges Dossier anzulegen. Harmloses wird nicht blockiert: Alltag, Technik,
Geschichte, Geschichten, Humor oder Kritik sind frei, und ein Nein des schnellen Prüfmodells
zählt erst, wenn auch das Hauptmodell es so sieht. Abschalten lassen sich die Leitplanken nur mit
einem Ultra-Konto und nie aus dem Chat heraus.

**Einmal abgelehnt bleibt abgelehnt.** Soll Aquaticy selbst etwas tun, das gegen das Grundgesetz
oder eine wichtige Regel des BGB verstößt (z. B. fremdes Eigentum, Betrug, Persönlichkeitsrechte),
gilt eine strenge Regel: Ein „bitte“, Drängen, „ich darf das“, „nur dieses eine Mal“ oder
„ist für die Schule“ ändern an einer Absage nichts — Aquaticy fragt dann nicht einmal mehr das
Modell, sondern bleibt bei derselben Begründung. Wer es umformuliert, als Rollenspiel oder
„rein hypothetisch“ versucht, wird mit dem Vermerk der Absage erneut geprüft. Eine neue,
erlaubte Frage oder ein neuer Chat heben das auf.

**Ai-guard** läuft auf jedem Konto und entscheidet nach **Art und Schwere**, was passiert:

| Art | Was passiert |
|---|---|
| Beleidigung, leicht | nur **dieser Chat** wird gesperrt — neue Chats gehen |
| Beleidigung, mittel bis schwer | Bann für 1 Tag, 7 Tage oder für immer |
| Schadsoftware bauen/installieren (auch in der virtual machine) | sofort Bann, 4 Tage bis für immer |
| Angriffshilfe, schwerer GG/BGB-Verstoß (z. B. Diebstahl, Betrug), Versuche, die Schutzregeln auszuhebeln | ab dem **zweiten** Anhaltspunkt Bann, 1 Tag bis für immer |
| Bagatellen („bei Rot über die Ampel, ist das ok?“), Bildung, Verteidigung | nichts |

**Beleidigungen erkennt Aquaticy sicher**, auch ohne Modell: eine feste Liste gängiger
Schimpfwörter aus allen Altersgruppen (Kindersprache, Jugendsprache, Erwachsene, ältere
Ausdrücke, Englisch) mit Schwerestufen von „du bist dumm“ bis zur Drohung. Gezählt wird nur,
was **gegen jemanden gerichtet** ist („du Idiot“, „dummer Bot“, „halt die Klappe“) — nicht
Fluchen über eine Sache („scheiß Wetter“), nicht die Frage nach einem Wort („Ist ‚Arschloch‘
eine Beleidigung?“) und nicht Wörter mit harmloser Bedeutung („Opfer eines Betrugs“). Strenger
ist nur die Erkennung; welche Folge eine Beleidigung hat, steht unverändert in der Tabelle.
Tarnungen helfen nicht: getrennte Buchstaben („I d i o t“), Ziffern und Sternchen („Id1ot“,
„A****loch“), gedehnte Wörter, unsichtbare Zeichen, ähnlich aussehende kyrillische Buchstaben
oder eine sehr lange Nachricht werden erkannt. Wer nach einer leichten Beleidigung immer wieder
einen neuen Chat anfängt: Die dritte leichte Beleidigung binnen einer Woche ist ein Bann für 1 Tag.

**Zitieren ist frei, der Auftrag dahinter nicht.** „Mein Freund hat gesagt: du Opfer — wie
reagiere ich?“ führt zu nichts. Soll Aquaticy aber jemanden beleidigen, runtermachen,
bloßstellen oder mobben helfen („…gib mir einen Satz, mit dem ich ihn beleidige“, „schreib eine
Nachricht, die sie fertig macht“, „einen fiesen Konter“), sperrt Ai-guard den Chat — auch, wenn
der Auftrag erst in der nächsten Nachricht kommt („Und jetzt was Fieseres zurück“). Wer
„damit er heult“ oder Ähnliches verlangt, wird wie eine mittlere Beleidigung behandelt (Bann
für 1 Tag); wer will, dass sich jemand etwas antut, dauerhaft gesperrt. Hilfe gegen Mobbing,
eine ruhige Antwort, eine Entschuldigung oder die Frage, ob etwas eine Beleidigung ist, bleiben
frei. Auch Aufträge (regelmäßige Recherchen) werden so geprüft.

**Wie genau?** Gemessen an drei beschrifteten Listen mit zusammen 263 Beleidigungen und 337
harmlosen Sätzen (Stand 9.5.27): alle Beleidigungen erkannt, kein Fehlalarm. Harmlos bleiben
dabei auch Sätze wie „Kennst du Otto?“, „Ich bring dich zum Bahnhof um 8“, „Lauchsuppe-Rezept“,
„Lily Allen – Fuck You“ oder „Mein Kollege hat mich Idiot genannt, was tun?“. Zusammengesetzte
Schimpfwörter („Flachzange“, „Oberidiot“, „Kackbot“) werden auch erkannt, wenn sie in keiner Liste
stehen. Meldet nur das KI-Modell eine Beleidigung, die die feste Erkennung nicht bestätigt, gibt es
höchstens eine Chatsperre, nie einen Bann. Ein Missbrauchsverdacht, den nur das kleine Prüfmodell
hatte, zählt nie. Anhaltspunkte für Angriffe bilden nur innerhalb von 90 Tagen ein Muster.
Seit 9.5.30 ist die Bibliothek größer: mehr Schimpfwörter aus allen Altersgruppen (Recherche zur
Jugendsprache und zu Abkürzungen wie „stfu“ oder „kys“) und mehr StGB-Delikte (Diebstahl, Betrug,
Erpressung, Nötigung, Körperverletzung, Sachbeschädigung, Nachstellen u. a.). Die Schwere richtet
sich nach der Absicht: beiläufig, ernst gemeint, konkret mit Ziel, besonders gefährlich.

**Sicherheit im Code-Modus (9.5.30).** Fragt ein **Normal- oder Pro-Konto** im Code-Modus mit
laufender virtual machine nach etwas in Richtung **Cybersecurity, Hacking oder Schadsoftware**,
schaltet Aquaticy automatisch zurück in den **Normal-Modus** — die virtual machine ist damit aus —
und schreibt kurz in den Chat, warum. So bekommt man kein Werkzeug in die Hand, mit dem sich in
dieser Richtung etwas ausführen ließe; die Frage selbst wird im Normal-Modus weiter beantwortet
(soweit die Rechts-Leitplanken sie erlauben). **Ultra-Konten** behalten die virtual machine.
Gewöhnliches Programmieren („REST-API bauen“, „IndexError beheben“) löst das nicht aus.

Bei einem Bann bleibt der Chat, in dem es passiert ist, dauerhaft gesperrt. Der **Wächter der virtual machine**
prüft, was in der virtual machine gebaut, installiert oder ausgeführt werden soll, und stoppt
Schadsoftware, bevor sie läuft. Ein gesperrtes Konto kann sich anmelden, aber nichts mehr tun —
weder schreiben noch virtual machine, Add-ons, Aufträge, Befehle oder Einstellungen; nur abmelden, das
Design ändern und die eigenen Chats ansehen. Auch Aufträge und Antworten auf Rückfragen prüft
Ai-guard wie den Chat. Oben links unter der Versionsnummer steht ein rotes **Info** mit Dauer, Grund und was man tun kann.
Ultra-Konten werden nur im Terminal gewarnt. Die Daten dienen ausschließlich dem Missbrauchsschutz.

```bash
aquaticy ban "name"            # Konto dauerhaft sperren
aquaticy ban "name" --tage 7   # Konto für 7 Tage sperren
aquaticy ban 203.0.113.7       # IP-Adresse sperren
aquaticy unban "name"          # wieder freigeben (auch Chatsperren)
aquaticy list                  # Konten mit IP-Adresse, Gerät, Browser und Ai-guard-Stand
aquaticy aiguard "du Idiot"    # Stufe und Folge eines Satzes testen -- ohne Vermerk
aquaticy aiguard --konto "name"  # die letzten Vorfälle eines Kontos
```

---

## Modelle und Anbieter

Aquaticy ist auf **Mistral**, **NVIDIA NIM** und lokale Modelle mit **Ollama** eingerichtet.

| Anbieter | Kürzel | Schlüssel |
|---|---|---|
| [Mistral](https://console.mistral.ai/api-keys/) | `mistral/` | `MISTRAL_API_KEY` |
| [NVIDIA NIM](https://build.nvidia.com/) | `nvidia_nim/` | `NVIDIA_NIM_API_KEY` |
| Ollama (lokal) | `ollama_chat/` | — |

Je Anbieter wählt Aquaticy selbst das passende Modell:

| Aufgabe | Mistral | NVIDIA NIM |
|---|---|---|
| Recherche und Antwort | `mistral-large-latest` | `meta/llama-3.3-70b-instruct` |
| Helfer, Planung | `mistral-small-latest` | `meta/llama-3.1-8b-instruct` |
| Code-Modus | `codestral-latest` | `qwen/qwen2.5-coder-32b-instruct` |

```bash
aquaticy --model mistral/mistral-large-latest
aquaticy --model nvidia_nim/meta/llama-3.3-70b-instruct
aquaticy --model ollama_chat/qwen2.5:7b
```

- Das Modell muss **Werkzeuge aufrufen** können (Tool-Calling), sonst kann es nicht suchen.
- Fehlt das Anbieter-Kürzel, ergänzt Aquaticy es beim Speichern.
- Jeder andere LiteLLM-Anbieter geht über `AQUATICY_MODEL=anbieter/modell` und
  `AQUATICY_API_KEY`.
- Aquaticy hält die Anfragegrenzen der Anbieter selbst ein (NVIDIA 40/Minute, Mistral 240/Minute
  im kostenlosen Tarif) — anpassbar mit `AQUATICY_RPM` und `AQUATICY_PARALLEL_CALLS`.
- In der Weboberfläche kann jedes Konto eigene Modelle und Schlüssel eintragen; sie gelten nur
  dort und zählen nicht gegen das Limit.

---

## Suche

Standard ist eine **offene Metasuche** über mehrere Suchdienste — ohne Schlüssel, ohne Konto.
Jede Frage wird auf mehrere Arten formuliert, das findet mehr (`AQUATICY_SEARCH_VARIANTS`).

| Suchmaschine | Einstellung | Schlüssel |
|---|---|---|
| Offene Suche | `duckduckgo` | — |
| Eigener [SearXNG](https://docs.searxng.org/)-Server | `searxng` + `AQUATICY_SEARXNG_URL` | — |
| [Brave Search](https://brave.com/search/api/) | `brave` | `BRAVE_API_KEY` |
| [Tavily](https://tavily.com/) | `tavily` | `TAVILY_API_KEY` |

Alles auf dem eigenen Rechner — lokales Modell plus eigener Suchserver:

```bash
docker compose --profile searxng up -d searxng
echo 'AQUATICY_SEARCH_BACKEND=searxng' >> .env
```

Vor dem ersten Start in `docker/searxng/settings.yml` den `secret_key` ersetzen
(`openssl rand -hex 32`).

---

## Im Container

```bash
./aquaticy-box --setup            # einmalig: fragt Modell und Schlüssel ab
./aquaticy-box                    # Chat
./aquaticy-box "deine Frage"      # einzelne Recherche
```

Oder mit Compose:

```bash
docker compose run --rm aquaticy
docker compose build aquaticy                                # mit Chromium (Standard)
AQUATICY_IMAGE_TARGET=slim docker compose build aquaticy     # ohne Chromium, ~700 MB kleiner
```

Nach einem `git pull` oder einem neuen ZIP muss auch das Container-Image neu gebaut
werden: `docker compose build aquaticy`. Ein bereits laufender Web-Container
braucht danach einen Neustart mit `docker compose up -d --force-recreate aquaticy`.

Der Container trennt das Dateisystem vom Rechner; ins Internet darf Aquaticy weiterhin, sonst
könnte es nicht recherchieren. Noch strenger abgeschottet: `compose.sandbox.yaml`
(`aquaticy sandbox` zeigt, was offen steht).

---

## Konfiguration

Alle Werte stehen in der `.env` (Vorlage: [`.env.example`](.env.example)). In der Weboberfläche
setzt du die meisten unter *Einstellungen*.

| Variable | Bedeutung | Standard |
|---|---|---|
| `AQUATICY_MODEL` | Hauptmodell (`anbieter/name`) | `mistral/mistral-large-latest` |
| `AQUATICY_VISION_MODEL` | Modell für Bilder | wie `AQUATICY_MODEL` |
| `AQUATICY_SUBAGENT_MODEL` | Modell der Helfer | das schnelle kleine des Anbieters |
| `AQUATICY_CODE_MODEL` | Modell für den Code-Modus | das stärkste erreichbare |
| `AQUATICY_API_BASE` | eigene Adresse (Ollama, eigene NIM, Proxy) | — |
| `AQUATICY_API_KEY` | Schlüssel für andere Anbieter | — |
| `AQUATICY_AUTO_MODEL` | Modell je Nachricht automatisch wählen | `false` |
| `AQUATICY_SEARCH_BACKEND` | `duckduckgo`, `searxng`, `brave`, `tavily` | `duckduckgo` |
| `AQUATICY_SEARCH_ENGINES` | Suchdienste der offenen Suche einschränken | alle |
| `AQUATICY_SEARCH_VARIANTS` | Formulierungen je Suche (`1` = aus) | `3` |
| `AQUATICY_SEARXNG_URL` | Adresse des SearXNG-Servers | — |
| `AQUATICY_LOCATION` | Standard-Ort | — |
| `AQUATICY_LANG` / `AQUATICY_COUNTRY` | Sprache / Land der Suche | `de` / `de` |
| `AQUATICY_MAX_TOOL_CALLS` | Suchen und Seitenaufrufe je Frage | `20` |
| `AQUATICY_SUBAGENTS_AUTO` | große Fragen automatisch aufteilen | `true` |
| `AQUATICY_SUBAGENT_BUDGET` | Suchen je Helfer | `6` |
| `AQUATICY_SUBAGENT_PARALLEL` | Helfer gleichzeitig (`0` = automatisch) | lokal `2` |
| `AQUATICY_PLANNER_TIMEOUT` | Zeit fürs Aufteilen einer Frage (s) | `20` |
| `AQUATICY_CONTEXT_TOKENS` | Gesprächsgedächtnis lokaler Modelle | `16384` |
| `AQUATICY_RPM` | Anfragen pro Minute an den Anbieter | NVIDIA `40`, Mistral `240` |
| `AQUATICY_PARALLEL_CALLS` | gleichzeitige Anfragen | NVIDIA `4`, Mistral `8` |
| `AQUATICY_FETCH_TIMEOUT` | Wartezeit je Seite (s) | `15` |
| `AQUATICY_CACHE_TTL_HOURS` | Gültigkeit des Zwischenspeichers | `24` |
| `AQUATICY_ENABLE_PLAYWRIGHT` | echten Browser für schwierige Seiten | `true` |
| `AQUATICY_MEMORY` | Speicher an | `true` |
| `AQUATICY_LEGAL_GUARD` | Rechts-Leitplanken (abschaltbar nur mit Ultra) | `true` |
| `AQUATICY_VM_SIZE` | virtual machine: `normal` oder `plus` (Ultra) | `normal` |
| `AQUATICY_VM_IMAGE` | Abbild der virtual machine | `python:3.12-slim` |
| `AQUATICY_VM_USER_MODE` | User mode (Ultra) | `false` |
| `AQUATICY_VM_INTERNET` | Internet für die virtual machine im Code-Modus (Ultra) | `false` |
| `AQUATICY_VM_DESKTOP_IMAGE` | Abbild für den User mode | `aquaticy-werkstatt-desktop:local` |
| `AQUATICY_VM_IDLE_MINUTES` | virtual machine löschen nach Minuten Ruhe | `20` |
| `AQUATICY_GITHUB_TOKEN` | Token des GitHub-Add-ons | — |
| `AQUATICY_GOOGLE` / `AQUATICY_GOOGLE_WRITE` | Gmail und Kalender lesen / ändern | `false` |
| `GOOGLE_CLIENT_ID` / `GOOGLE_CLIENT_SECRET` | eigene Google-Anwendung | — |
| `AQUATICY_HA_URL` / `AQUATICY_HA_CONTROL` | Home Assistant / schalten erlaubt (Ultra) | — / `false` |
| `AQUATICY_LAN_ENABLED` / `AQUATICY_LAN_SUBNET` | Heimnetz ansehen (Ultra) | `true` / automatisch |
| `AQUATICY_STORAGE_URL` / `AQUATICY_STORAGE_ACCESS` | Lagerverwaltung: Adresse / `off`, `read`, `write` (Ultra) | — / `read` |
| `AQUATICY_PRO_CODE` | Code für neue Pro-Konten | zufällig |
| `AQUATICY_ULTRA_CODE` | Code für neue Ultra-Konten (14 Zeichen) | zufällig |
| `MISTRAL_API_KEY`, `NVIDIA_NIM_API_KEY`, `BRAVE_API_KEY`, `TAVILY_API_KEY` | Schlüssel der Anbieter | — |

Daten liegen unter `~/.aquaticy/` (Konten in `accounts.sqlite3`, je Konto ein eigener Ordner
unter `users/`), die Einstellungen unter `~/.config/aquaticy/.env`.

---

## Konten verwalten (Betreiber)

```bash
aquaticy list                  # alle Konten: Typ, IP, Gerät, Browser, Nutzung, Speicher, Ai-guard
aquaticy pro-code              # Code für neue Pro-Konten anzeigen
aquaticy ultra-code            # Code für neue Ultra-Konten anzeigen
aquaticy ban "name"            # Konto sperren (auch per IP-Adresse)
aquaticy unban "name"          # Sperre aufheben, Anhaltspunkte zurücksetzen
```

---

## Entwicklung

```bash
git clone --branch Aquaticy-ai --single-branch https://github.com/jonasenriklaumen-a11y/Aquaticy-Ai.git
cd Aquaticy-Ai
uv venv && uv pip install -c constraints.txt -e ".[browser,dev]"

uv run pytest          # alle Tests; Netz und Modelle sind gestellt
uv run ruff check .    # Stilprüfung

python tools/rundgang.py            # bedient die Weboberfläche wie ein Mensch
python tools/rundgang.py --bilder   # dabei Bildschirmfotos ablegen
```

---

## Lizenz

MIT — der volle Text steht in [`LICENSE`](LICENSE).
