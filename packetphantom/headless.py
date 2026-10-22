"""Mode capteur sans interface : alertes en NDJSON sur la sortie standard, journal sur stderr."""
from __future__ import annotations

import json
import signal
import sys
import threading
from typing import TextIO

from . import analytics, serialize
from .api import Api
from .engine import Engine
from .geoip import GeoResolver


def _log(message: str) -> None:
    print(f"[packetphantom] {message}", file=sys.stderr, flush=True)


def run(engine: Engine, geo: GeoResolver, api: Api | None = None, out: TextIO = sys.stdout) -> int:
    stop = threading.Event()
    for sig in (signal.SIGINT, signal.SIGTERM):
        signal.signal(sig, lambda *_: stop.set())

    _log(f"source : {engine.source} ({engine.mode})" + (f"  BPF : {engine.bpf}" if engine.bpf else ""))
    if api is not None:
        _log(f"tableau de bord : {api.url}")

    cursor = 0

    def flush_alerts() -> None:
        nonlocal cursor
        for alert in engine.alerts_after(cursor):
            cursor = alert.id
            out.write(json.dumps(serialize.alert(alert), ensure_ascii=False) + "\n")
        out.flush()

    status = 0
    while not stop.wait(0.5):
        flush_alerts()
        if engine.poll_health():
            _log(f"erreur : {engine.error}")
            status = 1
            break
        # Fichier entièrement analysé et pas d'API à servir : on termine.
        if engine.mode == "done" and engine.backlog == 0 and api is None:
            stop.wait(0.2)
            break
    flush_alerts()

    summary = analytics.status(engine, geo)
    _log(f"{summary['packets']} paquets · {summary['flows']} flux · {summary['hosts']} hôtes · "
         f"{sum(summary['alerts'].values())} alertes · {summary['dropped']} perdus")
    return status
