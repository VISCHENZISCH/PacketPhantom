"""Agrégats calculés une seule fois pour toutes les vues (TUI, API, tableau de bord web)."""
from __future__ import annotations

import contextlib
import os
import platform
import sys
import threading
import time
from collections import Counter
from dataclasses import asdict

from . import __version__
from .engine import Engine
from .geoip import GeoInfo, GeoResolver

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


# ---------------------------------------------------------------- globe

GEO_PACKETS = 20_000   # paquets agrégés au plus par appel (au-delà, les plus récents)
GEO_ARCS = 300         # trajets renvoyés au plus (les plus volumineux)


def _point(info: GeoInfo | None) -> dict | None:
    if info is None:
        return None
    return {"lat": info.lat, "lon": info.lon, "country": info.country, "name": info.name, "city": info.city}


def _place(geo: GeoResolver, ip: str, home: GeoInfo | None) -> GeoInfo | None:
    info = geo.lookup(ip)   # non bloquant : None tant que la résolution est en cours
    if info is None:
        return None
    if info.country == "LAN":
        return home
    return info if info.located else None


def geo_traffic(engine: Engine, geo: GeoResolver, after: int | None) -> dict:
    """Trajets des paquets d'un lieu à l'autre depuis le paquet `after` (None : à partir de maintenant).

    Chaque trajet agrège les paquets d'un même couple de lieux ; `direction` vaut out (depuis le
    réseau local), in (vers lui) ou transit.
    """
    home = geo.home
    base = {"home": _point(home), "geo": geo.mode, "note": geo.note}
    if after is None:
        return {**base, "last_id": engine.last_packet_id, "arcs": [], "packets": 0, "placed": 0}
    packets = engine.packets_after(after, GEO_PACKETS)
    arcs: dict[tuple[GeoInfo, GeoInfo], list] = {}
    placed = 0
    for p in packets:
        a = _place(geo, p.src, home)
        if a is None:
            continue
        b = _place(geo, p.dst, home)
        if b is None or (a.lat, a.lon) == (b.lat, b.lon):
            continue
        placed += 1
        arc = arcs.get((a, b))
        if arc is None:
            arc = arcs[(a, b)] = [0, 0, Counter()]
        arc[0] += 1
        arc[1] += p.length
        arc[2][p.proto] += 1
    top = sorted(arcs.items(), key=lambda item: item[1][1], reverse=True)[:GEO_ARCS]
    return {
        **base,
        # Identifiant supérieur au dernier paquet : client d'une session précédente, on repart de maintenant.
        "last_id": packets[-1].id if packets else min(after, engine.last_packet_id),
        "packets": len(packets),
        "placed": placed,
        "arcs": [{
            "from": _point(a), "to": _point(b), "packets": n, "bytes": size, "proto": protos.most_common(1)[0][0],
            "direction": "out" if a is home else "in" if b is home else "transit",
        } for (a, b), (n, size, protos) in top],
    }


# ---------------------------------------------------------------- monitoring

PROCESS_START = time.time()   # importé au démarrage du programme : approximation du lancement


def _memory() -> tuple[int | None, str]:
    """Mémoire du processus : résidente actuelle (Linux), sinon pic (autres Unix), sinon inconnue."""
    try:
        with open("/proc/self/statm", encoding="ascii") as handle:
            return int(handle.read().split()[1]) * os.sysconf("SC_PAGE_SIZE"), "résidente"
    except (OSError, ValueError, IndexError, AttributeError):
        pass
    try:
        import resource
    except ImportError:   # Windows
        return None, ""
    peak = resource.getrusage(resource.RUSAGE_SELF).ru_maxrss
    return (peak if sys.platform == "darwin" else peak * 1024), "pic"


def _file_size(path) -> int:
    total = 0
    for suffix in ("", "-wal", "-shm"):
        with contextlib.suppress(OSError):   # -wal et -shm n'existent pas toujours
            total += os.path.getsize(f"{path}{suffix}")
    return total


def monitor(engine: Engine, geo: GeoResolver, streams: int = 0) -> dict:
    """Santé du capteur : tampons et files, composants, processus."""
    base = status(engine, geo)
    cfg, store, rules = engine.cfg, engine.store, engine.rules
    with engine.lock:
        pipeline = [
            # (clé, libellé, occupation, capacité, rotation) : une structure en rotation remplace ses plus
            # anciens éléments quand elle est pleine ; seule la file d'entrée perd des paquets.
            ("queue", "File d'analyse", engine.backlog, cfg.queue_size, False),
            ("buffer", "Paquets en mémoire", len(engine.ring), cfg.buffer, True),
            ("flows", "Flux suivis", len(engine.flows), cfg.max_flows, True),
            ("hosts", "Hôtes inventoriés", len(engine.hosts), cfg.max_hosts, True),
            ("alerts", "Alertes en mémoire", len(engine.alerts), cfg.max_alerts, True),
        ]
        exceptions = list(rules.allow)
    memory, memory_kind = _memory()
    cpu = os.times()
    return {
        **base,
        "pipeline": [{"key": k, "label": label, "used": used, "capacity": cap, "rotating": rot}
                     for k, label, used, cap, rot in pipeline],
        "components": {
            "store": {
                "enabled": store is not None, "path": str(store.path) if store else None,
                "size": _file_size(store.path) if store else 0, "error": store.error if store else None,
                "dropped": store.dropped if store else 0,
                "retention_days": store.retention / 86_400 if store else None,
            },
            "geo": {"mode": geo.mode, "note": geo.note, "home": geo.home is not None},
            "keylog": {"enabled": engine.keylog is not None},
            "rules": {
                "disabled": sorted(rules.disabled),
                "exceptions": len(exceptions),
                "exceptions_file": sum(e.from_file for e in exceptions),
                "thresholds": asdict(rules.thresholds),
            },
            "streams": streams,
        },
        "process": {
            "pid": os.getpid(), "uptime": round(time.time() - PROCESS_START, 1),
            "cpu_seconds": round(cpu.user + cpu.system, 2), "memory": memory, "memory_kind": memory_kind,
            "threads": threading.active_count(), "python": platform.python_version(),
            "platform": platform.system(),
        },
    }
