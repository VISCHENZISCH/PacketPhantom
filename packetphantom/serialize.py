"""Représentations dict (JSON / CSV) uniques, partagées par l'API et les exports."""
from __future__ import annotations

from datetime import datetime

from .flows import Conversation, Flow
from .geoip import GeoResolver
from .hosts import Host
from .model import Alert, Packet


def iso(ts: float) -> str:
    return datetime.fromtimestamp(ts).isoformat(timespec="milliseconds")


def _geo(geo: GeoResolver | None, ip: str) -> dict | None:
    info = geo.lookup(ip) if geo is not None else None
    if info is None or info.country in ("LAN", "??"):
        return None
    return {"country": info.country, "name": info.name, "city": info.city}


def packet(p: Packet) -> dict:
    return {
        "id": p.id, "time": iso(p.ts), "ts": p.ts, "src": p.src, "sport": p.sport, "dst": p.dst,
        "dport": p.dport, "proto": p.proto, "l4": p.l4, "length": p.length, "ttl": p.ttl,
        "flags": p.flags, "flow": p.flow_id, "domain": p.domain, "ja3": p.ja3, "ja4": p.ja4,
        "severity": p.severity if p.severity >= 0 else None, "info": p.info,
    }


def application(p: Packet) -> dict | None:
    """Détail applicatif décodé par le cœur Rust (DNS, TLS, HTTP, DHCP, ARP)."""
    if (dns := p.dns) is not None:
        return {"type": "dns", "response": dns.qr, "query": dns.qname, "qtype": dns.qtype,
                "rcode": dns.rcode, "answers": [list(a) for a in dns.answers]}
    if (hello := p.tls_client) is not None:
        return {"type": "tls_client_hello", "sni": hello.sni, "version": hello.version, "alpn": hello.alpn,
                "ciphers": hello.ciphers, "extensions": hello.extensions, "ja3": hello.ja3,
                "ja3_full": hello.ja3_full, "ja4": hello.ja4}
    if (hello := p.tls_server) is not None:
        return {"type": "tls_server_hello", "version": hello.version, "cipher": hello.cipher,
                "ja3s": hello.ja3s, "ja3s_full": hello.ja3s_full}
    if (req := p.http_request) is not None:
        return {"type": "http_request", "method": req.method, "path": req.path, "host": req.host,
                "headers": [list(h) for h in req.headers]}
    if (resp := p.http_response) is not None:
        return {"type": "http_response", "code": resp.code, "reason": resp.reason,
                "headers": [list(h) for h in resp.headers]}
    if (dhcp := p.dhcp) is not None:
        return {"type": "dhcp", "message": dhcp.msg_type, "hostname": dhcp.hostname,
                "requested": dhcp.requested, "client_mac": dhcp.client_mac}
    if (arp := p.arp) is not None:
        return {"type": "arp", "op": arp.op, "psrc": arp.psrc, "hwsrc": arp.hwsrc, "pdst": arp.pdst}
    return None


def flow(f: Flow, geo: GeoResolver | None = None) -> dict:
    return {
        "id": f.id, "l4": f.l4, "app": f.app, "client": f.client, "client_port": f.cport,
        "server": f.server, "server_port": f.sport, "first": iso(f.first), "last": iso(f.last),
        "duration": round(f.duration, 3), "packets": f.packets, "bytes": f.bytes,
        "pkts_c2s": f.pkts_c2s, "pkts_s2c": f.pkts_s2c, "bytes_c2s": f.bytes_c2s, "bytes_s2c": f.bytes_s2c,
        "state": f.state, "label": f.label, "geo": _geo(geo, f.server),
    }


def host(h: Host, geo: GeoResolver | None = None) -> dict:
    return {
        "ip": h.ip, "mac": h.mac, "local": h.local, "os": h.os, "os_confidence": h.os_conf,
        "names": sorted(h.names), "services": sorted(h.services), "user_agents": sorted(h.user_agents),
        "pkts_tx": h.pkts_tx, "pkts_rx": h.pkts_rx, "bytes_tx": h.bytes_tx, "bytes_rx": h.bytes_rx,
        "bytes": h.bytes, "peers": len(h.peers), "first_seen": iso(h.first), "last_seen": iso(h.last),
        "geo": _geo(geo, h.ip),
    }


def alert(a: Alert) -> dict:
    return {
        "id": a.id, "time": iso(a.ts), "ts": a.ts, "severity": a.severity, "severity_label": a.severity_label,
        "category": a.category, "title": a.title, "detail": a.detail, "src": a.src, "dst": a.dst,
        "packet": a.packet_id, "flow": a.flow_id, "rule": a.rule, "acked": a.acked,
    }


def conversation(c: Conversation) -> dict:
    return {
        "flow": flow(c.flow), "decrypted": c.plaintext is not None, "note": c.note,
        "chunks": [{"client": side, "size": len(data), "text": data[:262_144].decode("utf-8", errors="replace")}
                   for side, data in c.shown],
    }


def _cell(value):
    if isinstance(value, (list, tuple)):
        return "; ".join(map(str, value))
    if isinstance(value, dict):
        return value.get("country", "")
    return "" if value is None else value


def flat(row: dict) -> dict:
    """Aplatit les valeurs non scalaires pour le CSV."""
    return {key: _cell(value) for key, value in row.items()}
