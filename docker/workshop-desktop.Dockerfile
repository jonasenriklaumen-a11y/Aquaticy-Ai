# syntax=docker/dockerfile:1
#
# Das Werkstatt-Abbild fuer den User mode: ein kleiner Linux-Desktop, den
# Aquaticy bedient wie ein Mensch -- Bildschirm ansehen, klicken, tippen,
# Programme oeffnen. Mit Webbrowser, Office, Texteditor, Dateimanager,
# Bildbearbeitung und Terminal.
#
# Das ist NICHT das Abbild, in dem Aquaticy selbst laeuft (siehe Dockerfile
# im Wurzelverzeichnis), sondern das fuer die Werkstatt -- die abgeschottete
# Wegwerf-Maschine aus aquaticy/sandbox.py. Die Grenzen setzt Aquaticy beim
# Start von aussen (kein root, keine Faehigkeiten ausser NET_ADMIN fuer die
# Netzsperre, unveraenderliches Wurzeldateisystem, Speicher- und
# Prozessgrenzen); dieses Abbild bringt nur die Programme mit.
#
# Bauen (aus dem Wurzelverzeichnis des Projekts):
#   docker build -f docker/workshop-desktop.Dockerfile -t aquaticy-werkstatt-desktop:local .
#
# Danach in den Einstellungen unter "Werkstatt" den User mode einschalten.
# Ein anderes Abbild waehlt man mit AQUATICY_VM_DESKTOP_IMAGE in der .env.
#
# Warum Ubuntu und Falkon: Falkon ist ein vollwertiger Browser (Chromium-
# Engine) als gewoehnliches Paket. Firefox und Chromium gibt es unter Ubuntu
# nur noch als Snap, und Snaps laufen in keinem Container.
FROM ubuntu:24.04

ENV DEBIAN_FRONTEND=noninteractive \
    LANG=C.UTF-8

# Das offizielle Ubuntu-Abbild hat "universe" schon; ein selbst gebautes
# Grundabbild (debootstrap) manchmal nicht -- dann wird es ergaenzt.
RUN (grep -rqs universe /etc/apt/sources.list /etc/apt/sources.list.d/ \
        || echo "deb http://archive.ubuntu.com/ubuntu noble main universe" \
            >> /etc/apt/sources.list) \
    && apt-get update \
    && apt-get install -y --no-install-recommends \
        tini python3 ca-certificates iptables locales \
        xvfb x11-xserver-utils xdotool wmctrl openbox tint2 imagemagick dbus-x11 \
        fonts-dejavu-core fonts-liberation2 \
        falkon \
        libreoffice-writer libreoffice-calc libreoffice-impress libreoffice-l10n-de \
        mousepad pcmanfm xterm gimp \
    && rm -rf /var/lib/apt/lists/* \
    && locale-gen de_DE.UTF-8

# Derselbe unprivilegierte Nutzer wie in jeder Werkstatt. Das offizielle
# Abbild bringt mit "ubuntu" schon einen mit der Kennung 1000 mit.
RUN id -u 1000 >/dev/null 2>&1 || useradd --uid 1000 --create-home werkstatt

# Die Hilfsprogramme: Augen und Haende (fuer den Nutzer 1000) und die
# Netzsperre (nur fuer root beim Start -- lesen darf sie sonst niemand).
COPY docker/desktop/aquaticy-desktop /usr/local/bin/aquaticy-desktop
COPY docker/desktop/aquaticy-netz /usr/local/sbin/aquaticy-netz
RUN chmod 0755 /usr/local/bin/aquaticy-desktop \
    && chmod 0700 /usr/local/sbin/aquaticy-netz

LABEL org.aquaticy.werkstatt="desktop"
USER 1000
WORKDIR /work
