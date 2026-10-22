"""Inventaire passif des hôtes : MAC, OS, noms (DNS passif / SNI / DHCP), services."""
from __future__ import annotations

import ipaddress
from collections import OrderedDict
from dataclasses import dataclass, field
from functools import lru_cache

from . import osfp
from ._core import Packet

MAX_NAMES = 20


@lru_cache(maxsize=65_536)
def classify(ip: str) -> str:
    """'global', 'private', 'multicast', 'broadcast' ou 'invalid'."""
    if ip == "255.255.255.255":
        return "broadcast"
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return "invalid"
    if addr.is_multicast:
        return "multicast"
    return "global" if addr.is_global else "private"


@dataclass(slots=True)
class Host:
    ip: str
    first: float
    last: float
    local: bool
    mac: str = ""
    os: str = ""
    os_conf: int = 0
    pkts_tx: int = 0
    pkts_rx: int = 0
    bytes_tx: int = 0
    bytes_rx: int = 0
    names: set[str] = field(default_factory=set)
    services: set[str] = field(default_factory=set)
    peers: set[str] = field(default_factory=set)
    user_agents: set[str] = field(default_factory=set)

    @property
    def bytes(self) -> int:
        return self.bytes_tx + self.bytes_rx


class HostTable:
    def __init__(self, max_hosts: int = 20_000):
        self.max_hosts = max_hosts
        self._hosts: OrderedDict[str, Host] = OrderedDict()
        self.pdns: dict[str, set[str]] = {}   # DNS passif : ip -> noms

    def __len__(self) -> int:
        return len(self._hosts)

    def get(self, ip: str) -> Host | None:
        return self._hosts.get(ip)

    def values(self) -> list[Host]:
        return list(self._hosts.values())

    def _touch(self, ip: str, ts: float) -> Host | None:
        kind = classify(ip)
        if kind not in ("global", "private"):
            return None
        host = self._hosts.get(ip)
        if host is None:
            host = self._hosts[ip] = Host(ip, ts, ts, local=kind == "private")
            host.names.update(self.pdns.get(ip, ()))
            if len(self._hosts) > self.max_hosts:
                self._hosts.popitem(last=False)
        else:
            self._hosts.move_to_end(ip)
        host.last = ts
        return host

    def _learn_name(self, ip: str, name: str) -> None:
        if not name or classify(ip) not in ("global", "private"):
            return
        for names in (self.pdns.setdefault(ip, set()), getattr(self._hosts.get(ip), "names", None)):
            if names is not None and len(names) < MAX_NAMES:
                names.add(name)

    def update(self, pkt: Packet) -> None:
        arp = pkt.arp
        if arp is not None:
            host = self._touch(arp.psrc, pkt.ts)
            if host is not None:
                host.mac = arp.hwsrc
            return

        src = self._touch(pkt.src, pkt.ts) if pkt.src else None
        dst = self._touch(pkt.dst, pkt.ts) if pkt.dst else None
        if dst is not None:
            dst.pkts_rx += 1
            dst.bytes_rx += pkt.length
        if src is None:
            return
        src.pkts_tx += 1
        src.bytes_tx += pkt.length
        if src.local and pkt.smac and not src.mac:
            src.mac = pkt.smac
        if dst is not None and len(src.peers) < 1000:
            src.peers.add(pkt.dst)
        self._observe_transport(src, pkt)
        self._learn_from_app(src, pkt)

    @staticmethod
    def _observe_transport(host: Host, pkt: Packet) -> None:
        """Empreinte d'OS (TTL, options SYN) et services exposés."""
        if pkt.ttl is None:
            return
        if pkt.is_syn or pkt.is_synack:
            os_name, conf = osfp.fingerprint_syn(pkt.ttl, pkt.window, pkt.tcp_options)
            if conf >= host.os_conf:
                host.os, host.os_conf = os_name, conf
        elif not host.os:
            host.os, host.os_conf = osfp.guess_from_ttl(pkt.ttl)
        if pkt.is_synack or (pkt.banner and pkt.sport):
            host.services.add(f"TCP/{pkt.sport}")
        elif pkt.l4 == "UDP" and pkt.sport and pkt.dport and pkt.sport < 1024 <= pkt.dport:
            host.services.add(f"UDP/{pkt.sport}")

    def _learn_from_app(self, src: Host, pkt: Packet) -> None:
        dns = pkt.dns
        if dns is not None:
            if dns.qr:
                for name, rtype, value in dns.answers:
                    if rtype in ("A", "AAAA"):
                        self._learn_name(value, dns.qname or name)
            return
        request = pkt.http_request
        if request is not None:
            self._learn_name(pkt.dst, pkt.domain)
            agent = request.header("user-agent")
            if agent and len(src.user_agents) < 10:
                src.user_agents.add(agent)
            return
        if pkt.tls_client is not None:
            self._learn_name(pkt.dst, pkt.domain)
            return
        dhcp = pkt.dhcp
        if dhcp is not None and dhcp.hostname and dhcp.requested:
            self._learn_name(dhcp.requested, dhcp.hostname)
