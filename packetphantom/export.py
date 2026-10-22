"""Exports : PCAP, CSV et NDJSON, à partir des représentations de `serialize`."""
from __future__ import annotations

import contextlib
import csv
import json
import os
from collections.abc import Iterable
from datetime import datetime
from pathlib import Path

from . import pcapio, serialize
from .flows import Conversation, Flow
from .geoip import GeoResolver
from .hosts import Host
from .model import Alert, Packet

EXPORT_DIR = Path("exports")


def _target(kind: str, ext: str) -> Path:
    EXPORT_DIR.mkdir(parents=True, exist_ok=True)
    _give_back(EXPORT_DIR)
    return EXPORT_DIR / f"{kind}_{datetime.now().strftime('%Y%m%d-%H%M%S')}.{ext}"


def _give_back(path: Path) -> Path:
    """Lancé via sudo : rend le fichier à l'utilisateur d'origine plutôt qu'à root."""
    uid, gid = os.environ.get("SUDO_UID"), os.environ.get("SUDO_GID")
    if uid and gid and hasattr(os, "chown"):
        with contextlib.suppress(OSError):
            os.chown(path, int(uid), int(gid))
    return path


def _csv(kind: str, rows: Iterable[dict]) -> Path:
    path = _target(kind, "csv")
    rows = [serialize.flat(r) for r in rows]
    with path.open("w", newline="", encoding="utf-8") as fh:
        if rows:
            writer = csv.DictWriter(fh, fieldnames=list(rows[0]))
            writer.writeheader()
            writer.writerows(rows)
    return _give_back(path)


def _ndjson(kind: str, rows: Iterable[dict]) -> Path:
    path = _target(kind, "ndjson")
    with path.open("w", encoding="utf-8") as fh:
        fh.writelines(json.dumps(r, ensure_ascii=False) + "\n" for r in rows)
    return _give_back(path)


def packets_pcap(packets: Iterable[Packet]) -> Path:
    path = _target("packets", "pcap")
    pcapio.write(path, ((p.data, p.ts, p.linktype) for p in packets))
    return _give_back(path)


def packets_csv(packets: Iterable[Packet]) -> Path:
    return _csv("packets", map(serialize.packet, packets))


def flows_csv(flows: Iterable[Flow], geo: GeoResolver | None = None) -> Path:
    return _csv("flows", (serialize.flow(f, geo) for f in flows))


def hosts_json(hosts: Iterable[Host], geo: GeoResolver | None = None) -> Path:
    return _ndjson("hosts", (serialize.host(h, geo) for h in hosts))


def alerts_json(alerts: Iterable[Alert]) -> Path:
    return _ndjson("alerts", map(serialize.alert, alerts))


def conversation_raw(conv: Conversation) -> Path:
    suffix = "plain" if conv.plaintext is not None else "raw"
    path = _target(f"stream{conv.flow.id}-{suffix}", "bin")
    path.write_bytes(b"".join(data for _, data in conv.shown))
    return _give_back(path)
