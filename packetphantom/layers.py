"""Vue détaillée des couches d'un paquet (Scapy, à la demande) - partagée TUI / API."""
from __future__ import annotations

from typing import NamedTuple

from .model import Packet, printable

MAX_VALUE = 160
RAW_PREVIEW = 512


class Layer(NamedTuple):
    name: str
    fields: list[tuple[str, str]]


def _scapy(pkt: Packet):
    import scapy.layers.all  # noqa: F401  (enregistre les types de lien et protocoles)
    from scapy.config import conf
    from scapy.packet import Raw
    cls = conf.l2types.num2layer.get(pkt.linktype, Raw)
    try:
        return cls(pkt.data)
    except Exception:
        return Raw(pkt.data)


def _value(layer, fdesc) -> str:
    try:
        val = layer.getfieldval(fdesc.name)
        text = "" if val is None else printable(str(fdesc.i2repr(layer, val)))
    except Exception:
        return "?"
    return text if len(text) <= MAX_VALUE else text[:MAX_VALUE - 1] + "…"


def _printable(data: bytes) -> list[tuple[str, str]]:
    text = "".join(chr(b) if 32 <= b < 127 else "·" for b in data[:RAW_PREVIEW])
    return [("", text[i:i + 64]) for i in range(0, len(text), 64)]


def layer_tree(pkt: Packet) -> list[Layer]:
    """Couches et champs, dans l'ordre de dissection."""
    layers = []
    layer = _scapy(pkt)
    while layer is not None and layer.name != "NoPayload" and len(layers) < 16:
        if layer.name in ("Raw", "Padding"):
            data = bytes(layer.load)
            fields = [("octets", str(len(data))), *_printable(data)]
        else:
            fields = [(f.name, _value(layer, f)) for f in layer.fields_desc if f.name != "load"]
        layers.append(Layer(layer.name, fields))
        layer = layer.payload or None
    return layers


def hexdump(data: bytes, limit: int = 16_384) -> list[tuple[str, str, str]]:
    """Lignes (offset, hexadécimal, ASCII)."""
    rows = []
    for offset in range(0, min(len(data), limit), 16):
        chunk = data[offset:offset + 16]
        hexpart = " ".join(f"{b:02x}" for b in chunk[:8]) + "  " + " ".join(f"{b:02x}" for b in chunk[8:])
        rows.append((f"{offset:04x}", hexpart, "".join(chr(b) if 32 <= b < 127 else "·" for b in chunk)))
    return rows
