"""Fingerprinting passif d'OS à partir des SYN / SYN-ACK (approche type p0f).

Seuls les paquets d'ouverture TCP portent une signature fiable (TTL initial,
fenêtre, ordre des options). Les autres paquets ne donnent qu'une estimation
faible basée sur le TTL.
"""
from __future__ import annotations

LINUX_WINDOWS = {5840, 14600, 29200, 42340, 43690, 64240, 65483, 65495}


def initial_ttl(ttl: int) -> int:
    for candidate in (32, 64, 128, 255):
        if ttl <= candidate:
            return candidate
    return 255


def option_layout(options) -> list[str]:
    return [o[0] if isinstance(o, tuple) else str(o) for o in options or []]


def fingerprint_syn(ttl: int, window: int, options) -> tuple[str, int]:
    """Retourne (OS, confiance en %) pour un SYN ou SYN-ACK."""
    ittl = initial_ttl(ttl)
    layout = option_layout(options)

    if ittl == 128:
        if "Timestamp" not in layout and window in (8192, 64240, 65535):
            return "Windows", 85
        return "Windows", 65
    if ittl == 64:
        if layout[:5] == ["MSS", "SAckOK", "Timestamp", "NOP", "WScale"]:
            return "Linux", 90
        if layout[:7] == ["MSS", "NOP", "WScale", "NOP", "NOP", "Timestamp", "SAckOK"]:
            return "macOS / iOS", 85
        if layout[:5] == ["MSS", "NOP", "WScale", "SAckOK", "Timestamp"]:
            return "FreeBSD", 70
        if window in LINUX_WINDOWS:
            return "Linux", 65
        return "Linux / Unix", 45
    if ittl == 255:
        return "Équipement réseau / Solaris", 60
    return "Ancien système (TTL 32)", 30


def guess_from_ttl(ttl: int) -> tuple[str, int]:
    """Estimation faible quand aucun SYN n'a été observé."""
    return {
        32: ("Ancien système", 15),
        64: ("Linux / Unix", 25),
        128: ("Windows", 25),
        255: ("Équipement réseau", 25),
    }[initial_ttl(ttl)]
