"""Métriques de session. Toutes les écritures passent par le verrou du moteur."""
from __future__ import annotations

import time
from collections import Counter, deque

from ._core import Packet, service_name
from .flows import Flow

HISTORY = 120


class Stats:
    def __init__(self):
        self.reset()

    def reset(self) -> None:
        self.started = time.time()
        self.total = 0
        self.bytes = 0
        self.protocols: Counter[str] = Counter()
        self.services: Counter[str] = Counter()
        self.domains: Counter[str] = Counter()
        self.alerts: Counter[int] = Counter()   # sévérité -> nombre
        self.pps: deque[int] = deque([0] * HISTORY, maxlen=HISTORY)
        self.bps: deque[int] = deque([0] * HISTORY, maxlen=HISTORY)
        self.queue: deque[int] = deque([0] * HISTORY, maxlen=HISTORY)   # file d'analyse, échantillon par seconde
        self.queue_peak = 0
        self._sec_pkts = 0
        self._sec_bytes = 0

    def add(self, pkt: Packet, new_flow: Flow | None) -> None:
        self.total += 1
        self.bytes += pkt.length
        self.protocols[pkt.proto] += 1
        self._sec_pkts += 1
        self._sec_bytes += pkt.length
        if pkt.domain and (pkt.tls_client is not None or pkt.http_request is not None
                           or (pkt.dns is not None and not pkt.dns.qr)):
            self.domains[pkt.domain] += 1
        # Services : connexions acceptées (SYN-ACK) ou nouveaux échanges UDP.
        if pkt.is_synack:
            self._service("TCP", pkt.sport)
        elif new_flow is not None and new_flow.l4 == "UDP":
            self._service("UDP", new_flow.sport)

    def _service(self, l4: str, port: int | None) -> None:
        if port is None:
            return
        name = service_name(port)
        self.services[f"{l4}/{port}" + (f" {name}" if name else "")] += 1

    def tick(self, backlog: int = 0) -> None:
        """Pousse la seconde écoulée dans l'historique (appelé par le moteur)."""
        self.pps.append(self._sec_pkts)
        self.bps.append(self._sec_bytes * 8)
        self.queue.append(backlog)
        self.queue_peak = max(self.queue_peak, backlog)
        self._sec_pkts = 0
        self._sec_bytes = 0

    @property
    def uptime(self) -> float:
        return time.time() - self.started
