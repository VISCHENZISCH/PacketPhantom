"""Conversations : table des flux bidirectionnels et reconstitution des échanges."""
from __future__ import annotations

from collections import OrderedDict
from dataclasses import dataclass, field

from ._core import Packet

FIN, SYN, RST, ACK = 0x01, 0x02, 0x04, 0x10


@dataclass(slots=True)
class Flow:
    id: int
    l4: str
    client: str
    cport: int | None
    server: str
    sport: int | None
    first: float
    last: float
    app: str = ""
    label: str = ""
    state: str = ""
    pkts_c2s: int = 0
    pkts_s2c: int = 0
    bytes_c2s: int = 0
    bytes_s2c: int = 0

    @property
    def packets(self) -> int:
        return self.pkts_c2s + self.pkts_s2c

    @property
    def bytes(self) -> int:
        return self.bytes_c2s + self.bytes_s2c

    @property
    def duration(self) -> float:
        return max(0.0, self.last - self.first)

    def is_client(self, pkt: Packet) -> bool:
        return pkt.src == self.client and pkt.sport == self.cport


@dataclass(slots=True)
class Conversation:
    """Échange reconstitué : (côté client ?, octets) dans l'ordre d'arrivée."""
    flow: Flow
    chunks: list[tuple[bool, bytes]]
    plaintext: list[tuple[bool, bytes]] | None = None
    note: str = ""
    extras: dict = field(default_factory=dict)

    @property
    def shown(self) -> list[tuple[bool, bytes]]:
        return self.plaintext if self.plaintext is not None else self.chunks


def flow_key(pkt: Packet) -> tuple | None:
    """Clé normalisée : identique dans les deux sens de la conversation."""
    if not pkt.src or not pkt.dst or pkt.l4 in ("ARP", ""):
        return None
    a, b = (pkt.src, pkt.sport or 0), (pkt.dst, pkt.dport or 0)
    return (pkt.l4, *(a + b if a <= b else b + a))


def tcp_state(state: str, flags: int) -> str:
    if flags & RST:
        return "RESET"
    if flags & FIN:
        return "CLOSED" if state in ("FIN", "CLOSED") else "FIN"
    if flags & SYN:
        return "SYN-ACK" if flags & ACK else (state if state == "SYN-ACK" else "SYN")
    return "ESTABLISHED" if state in ("", "SYN", "SYN-ACK") else state


class FlowTable:
    def __init__(self, max_flows: int = 50_000):
        self.max_flows = max_flows
        self._flows: OrderedDict[tuple, Flow] = OrderedDict()
        self.by_id: dict[int, Flow] = {}
        self._next_id = 1

    def __len__(self) -> int:
        return len(self._flows)

    def values(self) -> list[Flow]:
        return list(self._flows.values())

    def _create(self, key: tuple, pkt: Packet) -> Flow:
        client, cport, server, sport = pkt.src, pkt.sport, pkt.dst, pkt.dport
        # Le client est l'initiateur ; sans SYN observé, le port bas est supposé côté serveur.
        if pkt.is_synack or (not pkt.is_syn and cport is not None and sport is not None and cport < 1024 <= sport):
            client, cport, server, sport = server, sport, client, cport
        flow = Flow(self._next_id, pkt.l4, client, cport, server, sport, pkt.ts, pkt.ts)
        self._next_id += 1
        self._flows[key] = flow
        self.by_id[flow.id] = flow
        if len(self._flows) > self.max_flows:
            _, evicted = self._flows.popitem(last=False)
            self.by_id.pop(evicted.id, None)
        return flow

    def update(self, pkt: Packet) -> tuple[Flow | None, bool]:
        key = flow_key(pkt)
        if key is None:
            return None, False
        flow = self._flows.get(key)
        created = flow is None
        if created:
            flow = self._create(key, pkt)
        else:
            self._flows.move_to_end(key)

        if flow.is_client(pkt):
            flow.pkts_c2s += 1
            flow.bytes_c2s += pkt.length
        else:
            flow.pkts_s2c += 1
            flow.bytes_s2c += pkt.length
        flow.last = pkt.ts
        if not flow.app or (flow.app == flow.l4 and pkt.proto != pkt.l4):
            flow.app = pkt.proto
        if pkt.domain and not flow.label:
            flow.label = pkt.domain
        if pkt.l4 == "TCP":
            flow.state = tcp_state(flow.state, pkt.tcp_flags)
        pkt.flow_id = flow.id
        return flow, created


def reassemble(flow: Flow, packets: list[Packet]) -> list[tuple[bool, bytes]]:
    """Payloads dans l'ordre, côtés consécutifs fusionnés, retransmissions TCP écartées."""
    chunks: list[tuple[bool, bytes]] = []
    seen: set[tuple[bool, int]] = set()
    for pkt in packets:
        if not pkt.payload_len:
            continue
        client = flow.is_client(pkt)
        if pkt.l4 == "TCP":
            if (client, pkt.seq) in seen:
                continue
            seen.add((client, pkt.seq))
        data = pkt.payload
        if chunks and chunks[-1][0] == client:
            chunks[-1] = (client, chunks[-1][1] + data)
        else:
            chunks.append((client, data))
    return chunks
