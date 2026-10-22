"""Lecture pcap / pcapng et écriture pcap, sans dissection.

Une trame est un triplet (octets, horodatage, type de lien LINKTYPE_*).
"""
from __future__ import annotations

import io
import struct
from collections.abc import Iterable, Iterator
from itertools import chain
from pathlib import Path
from typing import BinaryIO

Frame = tuple[bytes, float, int]

_PCAP_MAGIC = {
    0xA1B2C3D4: ("<", 1e-6), 0xD4C3B2A1: (">", 1e-6),
    0xA1B23C4D: ("<", 1e-9), 0x4D3CB2A1: (">", 1e-9),
}
_SHB, _IDB, _SPB, _EPB = 0x0A0D0D0A, 0x00000001, 0x00000003, 0x00000006
_BOM_LE = b"\x4d\x3c\x2b\x1a"


def read(path: str | Path) -> Iterator[Frame]:
    """Itère sur les trames d'un fichier pcap ou pcapng."""
    with open(path, "rb") as fh:
        magic = fh.read(4)
        fh.seek(0)
        if struct.unpack("<I", magic)[0] == _SHB:
            yield from _read_pcapng(fh)
        else:
            yield from _read_pcap(fh)


def _read_pcap(fh) -> Iterator[Frame]:
    header = fh.read(24)
    if len(header) < 24 or struct.unpack("<I", header[:4])[0] not in _PCAP_MAGIC:
        raise ValueError("format de capture non reconnu (pcap ou pcapng attendu)")
    endian, unit = _PCAP_MAGIC[struct.unpack("<I", header[:4])[0]]
    linktype = struct.unpack(endian + "I", header[20:24])[0] & 0x0FFFFFFF
    record = struct.Struct(endian + "IIII")
    while len(head := fh.read(16)) == 16:
        sec, frac, caplen, _ = record.unpack(head)
        data = fh.read(caplen)
        if len(data) < caplen:
            return
        yield data, sec + frac * unit, linktype


def _tsresol(options: bytes, endian: str) -> float:
    """Option if_tsresol (code 9) d'un bloc Interface Description ; µs par défaut."""
    pos = 0
    while pos + 4 <= len(options):
        code, length = struct.unpack_from(endian + "HH", options, pos)
        if code == 0:
            break
        if code == 9 and length >= 1:
            value = options[pos + 4]
            return 2.0 ** -(value & 0x7F) if value & 0x80 else 10.0 ** -value
        pos += 4 + (length + 3) // 4 * 4
    return 1e-6


def _read_pcapng(fh) -> Iterator[Frame]:
    endian = "<"
    interfaces: list[tuple[int, float]] = []
    while len(head := fh.read(8)) == 8:
        block_type = struct.unpack("<I", head[:4])[0]
        if block_type == _SHB:
            endian = "<" if fh.read(4) == _BOM_LE else ">"
            length = struct.unpack(endian + "I", head[4:])[0]
            fh.read(length - 12)
            interfaces = []
            continue
        length = struct.unpack(endian + "I", head[4:])[0]
        body = fh.read(length - 8)
        if len(body) < length - 8:
            return
        if block_type == _IDB:
            linktype = struct.unpack_from(endian + "H", body)[0]
            interfaces.append((linktype, _tsresol(body[8:-4], endian)))
        elif block_type == _EPB:
            iface, high, low, caplen = struct.unpack_from(endian + "IIII", body)
            linktype, resolution = interfaces[iface]
            yield body[20:20 + caplen], ((high << 32) | low) * resolution, linktype
        elif block_type == _SPB and interfaces:
            original = struct.unpack_from(endian + "I", body)[0]
            yield body[4:4 + min(original, len(body) - 8)], 0.0, interfaces[0][0]


def write_to(fh: BinaryIO, frames: Iterable[Frame]) -> int:
    """Écrit un pcap (µs). Les trames d'un autre type de lien que la première sont ignorées."""
    frames = iter(frames)
    first = next(frames, None)
    linktype = first[2] if first else 1
    fh.write(struct.pack("<IHHiIII", 0xA1B2C3D4, 2, 4, 0, 0, 262_144, linktype))
    record = struct.Struct("<IIII")
    count = 0
    for data, ts, frame_linktype in chain([first] if first else [], frames):
        if frame_linktype != linktype:
            continue
        sec = int(ts)
        fh.write(record.pack(sec, int(round((ts - sec) * 1e6)) % 1_000_000, len(data), len(data)))
        fh.write(data)
        count += 1
    return count


def write(path: str | Path, frames: Iterable[Frame]) -> int:
    with open(path, "wb") as fh:
        return write_to(fh, frames)


def dumps(frames: Iterable[Frame]) -> bytes:
    buffer = io.BytesIO()
    write_to(buffer, frames)
    return buffer.getvalue()
