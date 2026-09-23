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

# Bibliotheken fuer die Add-ons (Einstellungen -> Werkstatt -> Add-ons).
# Die Programme selbst -- Firefox fuer WhatsApp Web und Telegram Web, Signal
# Desktop, Blender -- liegen NICHT im Abbild: sie werden erst geladen, wenn
# jemand auf "Installieren" drueckt, und zwar auf einen eigenen Datentraeger je
# Add-on (aquaticy-addons, siehe unten). Was sie zum Laufen brauchen, muss aber
# hier sein, denn in der Werkstatt gibt es kein root und kein apt.
RUN apt-get update \
    && apt-get install -y --no-install-recommends \
        libgtk-3-0t64 libdbus-glib-1-2 libasound2t64 libx11-xcb1 libxtst6 \
        libnss3 libgbm1 libxss1 libsecret-1-0 libnotify4 libatspi2.0-0t64 libxkbfile1 \
        libdrm2 libxshmfence1 \
        libxi6 libxxf86vm1 libxfixes3 libxrender1 libgl1 libegl1 libgl1-mesa-dri \
        libxkbcommon0 libsm6 libice6 \
        dpkg xz-utils \
    && rm -rf /var/lib/apt/lists/*

# Derselbe unprivilegierte Nutzer wie in jeder Werkstatt. Das offizielle
# Abbild bringt mit "ubuntu" schon einen mit der Kennung 1000 mit.
RUN id -u 1000 >/dev/null 2>&1 || useradd --uid 1000 --create-home werkstatt

# Die Hilfsprogramme: Augen und Haende (fuer den Nutzer 1000) und die
# Netzsperre (nur fuer root beim Start -- lesen darf sie sonst niemand).
COPY docker/desktop/aquaticy-desktop /usr/local/bin/aquaticy-desktop
COPY docker/desktop/aquaticy-netz /usr/local/sbin/aquaticy-netz
COPY docker/desktop/aquaticy-addons /usr/local/bin/aquaticy-addons
RUN chmod 0755 /usr/local/bin/aquaticy-desktop /usr/local/bin/aquaticy-addons \
    && chmod 0700 /usr/local/sbin/aquaticy-netz

LABEL org.aquaticy.werkstatt="desktop"
USER 1000
WORKDIR /work
