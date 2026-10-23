"""Types partagés côté Python. Le paquet décodé (`Packet`) est défini dans le cœur Rust."""
from __future__ import annotations

from dataclasses import dataclass

from ._core import Packet

__all__ = ["Alert", "Packet", "SEVERITY_LABELS"]

SEVERITY_LABELS = {0: "INFO", 1: "LOW", 2: "MEDIUM", 3: "HIGH", 4: "CRITICAL"}


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

    @property
    def severity_label(self) -> str:
        return SEVERITY_LABELS.get(self.severity, "?")
