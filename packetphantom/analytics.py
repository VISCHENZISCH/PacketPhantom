"""Agrégats calculés une seule fois pour toutes les vues (TUI, API, tableau de bord web)."""
from __future__ import annotations

from collections import Counter

from . import __version__
from .engine import Engine
from .geoip import GeoResolver

ENCRYPTED = {"TLS", "QUIC", "SSH", "HTTPS", "HTTPS-ALT", "DOT", "IMAPS", "POP3S", "SMTPS", "LDAPS",
             "WIREGUARD", "OPENVPN", "ESP"}
CLEARTEXT = {"HTTP", "HTTP-ALT", "FTP", "TELNET", "POP3", "IMAP", "SMTP", "DNS", "MDNS", "LLMNR", "SNMP",
             "SYSLOG", "TFTP", "LDAP", "NBNS", "MQTT", "REDIS", "MEMCACHED"}


def status(engine: Engine, geo: GeoResolver) -> dict:
    engine.poll_health()
    with engine.lock:
        st = engine.stats
        return {
            "version": __version__, "mode": engine.mode, "source": engine.source, "bpf": engine.bpf,
            "error": engine.error, "dropped": engine.dropped, "backlog": engine.backlog,
            "analysis_errors": engine.analysis_errors, "packets": st.total, "bytes": st.bytes,
            "uptime": round(st.uptime, 1), "flows": len(engine.flows), "hosts": len(engine.hosts),
            "alerts": {str(sev): count for sev, count in sorted(st.alerts.items())},
            "last_packet": engine.last_packet_id, "last_alert": engine.last_alert_id,
            "pps": list(st.pps), "bps": list(st.bps), "geo": geo.note,
            "tls_keylog": engine.keylog is not None,
            "unacked": sum(not a.acked for a in engine.alerts),
            "persistent": engine.store is not None,
            "store_error": engine.store.error if engine.store is not None else None,
        }


def rankings(engine: Engine, geo: GeoResolver, limit: int = 10) -> dict:
    """Classements : protocoles, hôtes actifs, domaines, services, pays (par volume)."""
    with engine.lock:
        st = engine.stats
        protocols = st.protocols.most_common(limit)
        domains = st.domains.most_common(limit)
        services = st.services.most_common(limit)
        hosts = sorted(engine.hosts.values(), key=lambda h: h.bytes, reverse=True)
        total = st.total or 1
        encrypted = sum(st.protocols[p] for p in ENCRYPTED)
        cleartext = sum(st.protocols[p] for p in CLEARTEXT)
    countries: Counter[str] = Counter()
    names: dict[str, str] = {}
    for h in hosts:
        info = None if h.local else geo.lookup(h.ip)
        if info is not None and info.country not in ("??", "LAN"):
            countries[info.country] += h.bytes
            names[info.country] = info.name
    return {
        "protocols": [{"name": p, "count": c, "share": c / total} for p, c in protocols],
        "talkers": [{"ip": h.ip, "name": min(h.names, default=""), "bytes": h.bytes} for h in hosts[:limit]],
        "domains": [{"name": d, "count": c} for d, c in domains],
        "services": [{"name": s, "count": c} for s, c in services],
        "countries": [{"code": code, "name": names[code], "bytes": b} for code, b in countries.most_common(limit)],
        "encryption": {"encrypted": encrypted, "cleartext": cleartext,
                       "other": max(0, st.total - encrypted - cleartext)},
    }
