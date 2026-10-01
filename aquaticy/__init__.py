"""aquaticy -- ein KI-Rechercheagent fuer die Kommandozeile."""

__version__ = "9.6.2.5"

#: Der Name dieser Fassung. Er steht ueberall hinter der Versionsnummer, wo
#: Menschen sie lesen -- nicht in Paketangaben und Kennungen fuer Server.
__codename__ = "Spark"

#: Interne oder Test-Fassung (seit 9.6.0): "Intern", "Test" -- leer fuer eine
#: oeffentliche Fassung. Steht dann hinter dem Namen, und die Oberflaeche zeigt
#: unten mittig einen gelben Hinweis.
__stage__ = ""

#: Ob dies eine interne oder Test-Fassung ist.
INTERNAL = bool(__stage__)

#: So steht die Fassung in der Oberflaeche, im Terminal und in der README.
VERSION_LABEL = f"{__version__} {__codename__}" + (f" {__stage__}" if __stage__ else "")

__all__ = ["INTERNAL", "VERSION_LABEL", "__codename__", "__stage__", "__version__"]
