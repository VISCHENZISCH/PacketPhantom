"""Types partagés côté Python. Le paquet décodé (`Packet`) est défini dans le cœur Rust."""
from __future__ import annotations

from dataclasses import dataclass

from ._core import Packet

__all__ = ["Alert", "Packet", "SEVERITY_LABELS", "printable"]

SEVERITY_LABELS = {0: "INFO", 1: "LOW", 2: "MEDIUM", 3: "HIGH", 4: "CRITICAL"}


def printable(text: str, newlines: bool = False) -> str:
    """Texte venu du réseau, rendu inoffensif pour un terminal : ESC, BEL, inversions bidi… → « · »."""
    return "".join(ch if ch.isprintable() or (newlines and ch == "\n") else "·" for ch in text)


@dataclass(slots=True)
class Alert:
    id: int
    ts: float
    severity: int
    category: str
    title: str
    detail: str = ""
    src: str = ""
    dst: str = ""
    packet_id: int = 0
    flow_id: int = 0
    rule: str = ""          # identifiant de la règle (rules.RULES)
    acked: bool = False     # acquittée par un analyste

    def __post_init__(self) -> None:
        # Titre et détail citent le trafic (identifiants, en-têtes, noms) : la TUI les écrit au terminal.
        self.title, self.category = printable(self.title), printable(self.category)
        self.src, self.dst, self.detail = printable(self.src), printable(self.dst), printable(self.detail, newlines=True)

    @property
    def severity_label(self) -> str:
        return SEVERITY_LABELS.get(self.severity, "?")
