"""Thèmes Textual et palettes Rich (protocoles, sévérités)."""
from __future__ import annotations

from datetime import datetime

from rich.text import Text
from textual.theme import Theme

PHANTOM_DARK = Theme(
    name="phantom",
    primary="#FF7A1A",
    secondary="#FFB347",
    accent="#38BDF8",
    warning="#FBBF24",
    error="#F43F5E",
    success="#34D399",
    foreground="#D6DBE1",
    background="#0A0C0F",
    surface="#0F1216",
    panel="#161A20",
    dark=True,
    variables={
        "block-cursor-background": "#FF7A1A 22%",
        "block-cursor-foreground": "#FFE2C7",
        "block-cursor-text-style": "none",
        "footer-key-foreground": "#FF7A1A",
        "input-selection-background": "#FF7A1A 35%",
    },
)

PHANTOM_LIGHT = Theme(
    name="phantom-light",
    primary="#C2410C",
    secondary="#B45309",
    accent="#0369A1",
    warning="#B45309",
    error="#BE123C",
    success="#047857",
    foreground="#1F2328",
    background="#F4F5F7",
    surface="#FFFFFF",
    panel="#E9ECF0",
    dark=False,
    variables={
        "block-cursor-background": "#C2410C 18%",
        "block-cursor-foreground": "#7C2D12",
        "block-cursor-text-style": "none",
        "footer-key-foreground": "#C2410C",
    },
)

_PROTO_DARK = {
    "TCP": "#94A3B8", "UDP": "#7DD3C0", "DNS": "#60A5FA", "MDNS": "#60A5FA", "LLMNR": "#60A5FA",
    "HTTP": "#4ADE80", "TLS": "#C084FC", "HTTPS": "#C084FC", "QUIC": "#A78BFA", "SSH": "#818CF8",
    "ARP": "#FACC15", "ICMP": "#FB923C", "ICMPV6": "#FB923C", "DHCP": "#FCD34D", "NTP": "#5EEAD4",
    "SMB": "#F472B6", "FTP": "#F87171", "TELNET": "#F87171", "SMTP": "#FDBA74", "SSDP": "#9CA3AF",
}
_PROTO_LIGHT = {
    "TCP": "#475569", "UDP": "#0F766E", "DNS": "#1D4ED8", "MDNS": "#1D4ED8", "LLMNR": "#1D4ED8",
    "HTTP": "#15803D", "TLS": "#7E22CE", "HTTPS": "#7E22CE", "QUIC": "#6D28D9", "SSH": "#4338CA",
    "ARP": "#A16207", "ICMP": "#C2410C", "ICMPV6": "#C2410C", "DHCP": "#A16207", "NTP": "#0F766E",
    "SMB": "#BE185D", "FTP": "#B91C1C", "TELNET": "#B91C1C", "SMTP": "#C2410C", "SSDP": "#6B7280",
}
_SEV_DARK = {4: "#F43F5E", 3: "#FB923C", 2: "#FBBF24", 1: "#60A5FA", 0: "#94A3B8"}
_SEV_LIGHT = {4: "#BE123C", 3: "#C2410C", 2: "#A16207", 1: "#1D4ED8", 0: "#64748B"}
SEV_NAMES = {4: "CRITIQUE", 3: "ÉLEVÉE", 2: "MOYENNE", 1: "FAIBLE", 0: "INFO"}


class Palette:
    """Couleurs Rich cohérentes avec le thème courant."""

    def __init__(self, dark: bool):
        self.dark = dark
        self.proto = _PROTO_DARK if dark else _PROTO_LIGHT
        self.sev = _SEV_DARK if dark else _SEV_LIGHT
        self.muted = "#6B7280" if dark else "#6B7280"
        self.dim = "#4B5563" if dark else "#9CA3AF"
        self.fg = "#D6DBE1" if dark else "#1F2328"
        self.primary = "#FF7A1A" if dark else "#C2410C"
        self.accent = "#38BDF8" if dark else "#0369A1"
        self.client = "#FF9F5A" if dark else "#C2410C"
        self.server = "#7DD3FC" if dark else "#0369A1"
        self.good = "#34D399" if dark else "#047857"      # succès uniquement
        self.strong = "#C2410C" if dark else "#9A3412"
        self.soft = "#FFB37A" if dark else "#FB923C"
        self.bg = "#0A0C0F" if dark else "#FFFFFF"

    def proto_color(self, proto: str) -> str:
        return self.proto.get(proto.upper(), "#CBD5E1" if self.dark else "#334155")

    def proto_text(self, proto: str) -> Text:
        return Text(proto, style=f"bold {self.proto_color(proto)}")

    def sev_text(self, severity: int, short: bool = False) -> Text:
        label = SEV_NAMES.get(severity, "?")
        return Text(label[:4] if short else label, style=f"bold {self.sev.get(severity, self.muted)}")


def fmt_bytes(n: float) -> str:
    for unit in ("o", "Ko", "Mo", "Go"):
        if abs(n) < 1024:
            return f"{n:.0f} {unit}" if unit == "o" else f"{n:.1f} {unit}"
        n /= 1024
    return f"{n:.1f} To"


def fmt_bits(n: float) -> str:
    for unit in ("b/s", "Kb/s", "Mb/s", "Gb/s"):
        if abs(n) < 1000:
            return f"{n:.0f} {unit}" if unit == "b/s" else f"{n:.1f} {unit}"
        n /= 1000
    return f"{n:.1f} Tb/s"


def fmt_count(n: int) -> str:
    return f"{n:,}".replace(",", " ")


def fmt_time(ts: float) -> str:
    return datetime.fromtimestamp(ts).strftime("%H:%M:%S.%f")[:-3]


def fmt_duration(seconds: float) -> str:
    seconds = int(seconds)
    if seconds < 60:
        return f"{seconds}s"
    if seconds < 3600:
        return f"{seconds // 60}m{seconds % 60:02d}s"
    return f"{seconds // 3600}h{(seconds % 3600) // 60:02d}m"


SPARK = " ▁▂▃▄▅▆▇█"


def sparkline(values, width: int, color: str) -> Text:
    data = list(values)[-width:] if width > 0 else []
    if not data:
        return Text("")
    top = max(data) or 1
    return Text("".join(SPARK[min(8, int(v / top * 8 + 0.5))] if v else SPARK[0] for v in data).rjust(width), style=color)


def bar(fraction: float, width: int, color: str, track: str) -> Text:
    fraction = max(0.0, min(1.0, fraction))
    full = fraction * width
    whole = int(full)
    parts = "▏▎▍▌▋▊▉"
    rest = int((full - whole) * 8)
    text = Text("█" * whole, style=color)
    if whole < width:
        if rest:
            text.append(parts[rest - 1], style=color)
            whole += 1
        text.append("─" * (width - whole), style=track)
    return text


def pill_chart(values, width: int, height: int, pal: Palette, labels: list[str]) -> list[Text]:
    """Histogramme « en bande » : un pilier par période.

    Période en cours en orange clair, pic en orange foncé, autres périodes hachurées.
    """
    buckets = len(labels)
    size = max(1, len(values) // buckets)
    means = [sum(values[i * size:(i + 1) * size]) / size for i in range(buckets)]
    top = max(means) or 1
    peak = means.index(max(means))
    col = max(1, (width - (buckets - 1)) // buckets)
    levels = [max(1, round(v / top * height)) for v in means]
    looks = [("█", pal.soft) if i == buckets - 1 else ("█", pal.strong) if i == peak and means[i] else ("╱", pal.dim)
             for i in range(buckets)]
    rows = []
    for row in range(height, 0, -1):
        line = Text()
        for i, (char, color) in enumerate(looks):
            line.append((char if levels[i] >= row else " ") * col, style=color)
            line.append(" ")
        rows.append(line)
    rows.append(Text(" ".join(label[:col].center(col) for label in labels), style=pal.muted))
    return rows
