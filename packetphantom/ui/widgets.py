"""Widgets du tableau de bord et rendu du détail paquet."""
from __future__ import annotations

import time

from rich.console import Group
from rich.table import Table
from rich.text import Text
from textual.widgets import Static, Tree

from ..layers import hexdump, layer_tree
from ..model import Alert, Packet
from .theme import SEV_NAMES, Palette, bar, fmt_bytes, fmt_duration, sparkline


def palette_of(widget) -> Palette:
    theme = widget.app.current_theme
    return Palette(theme.dark if theme is not None else True)


# Le fond coloré du badge porte l'état ; le texte seul suffit.
BADGES = {
    "live": " CAPTURE ", "file": " LECTURE ", "done": " TERMINÉ ",
    "idle": " ARRÊTÉ ", "paused": " AFFICHAGE FIGÉ ",
}


class StatusBar(Static):
    """Barre supérieure : état de capture, source, filtres, API, horloge."""

    def __init__(self, **kwargs):
        super().__init__(**kwargs)
        self.state: dict = {"mode": "idle"}

    def set_state(self, **state) -> None:
        self.state = state
        self.refresh()

    def render(self):
        pal = palette_of(self)
        s = self.state
        tone = {"live": pal.good, "file": pal.accent, "done": pal.muted}.get(s["mode"], pal.sev[2])
        left = Text()
        left.append(BADGES.get(s["mode"], BADGES["idle"]), style=f"bold {pal.bg} on {tone}")
        if s.get("source"):
            left.append("  source ", style=pal.muted)
            left.append(s["source"], style=f"bold {pal.fg}")
        left.append("  BPF ", style=pal.muted)
        left.append(s.get("bpf") or "aucun", style=pal.accent if s.get("bpf") else pal.dim)
        if s.get("warning"):
            left.append(f"  {s['warning']}", style=f"bold {pal.sev[4]}")
        right = Text()
        for label, value in (("API", s.get("api")), ("TLS", s.get("tls")), ("GeoIP", s.get("geo"))):
            if value:
                right.append(f"{label} ", style=pal.muted)
                right.append(f"{value}   ", style=pal.fg)
        right.append(time.strftime("%H:%M:%S") + " ", style=f"bold {pal.fg}")
        grid = Table.grid(expand=True)
        grid.add_column(ratio=1, no_wrap=True, overflow="ellipsis")
        grid.add_column(justify="right", no_wrap=True)
        grid.add_row(left, right)
        return grid


class Kpi(Static):
    """Indicateur sur deux lignes : libellé suivi de la tendance (sparkline), puis valeur."""

    def __init__(self, label: str, hero: bool = False, **kwargs):
        super().__init__(classes="hero" if hero else "", **kwargs)
        self.label = label
        self.hero = hero
        self.value, self.sub, self.tone = "-", "", ""
        self.history: list[float] = []

    def set(self, value: str, sub: str = "", history=None, tone: str = "") -> None:
        self.value, self.sub, self.tone = value, sub, tone
        self.history = list(history or [])
        self.refresh()

    def render(self):
        pal = palette_of(self)
        if self.hero:   # fond orange (feuille de style), texte clair
            color, value_color, label_color, sub_color = "#FFE4CC", "#FFFFFF", "#FFE4CC", "#FFE4CC"
        else:
            color = {"alert": pal.sev[4], "warn": pal.sev[2], "good": pal.good}.get(self.tone, pal.primary)
            value_color, label_color, sub_color = color if self.tone else pal.fg, pal.muted, pal.muted
        head = Text(self.label.upper(), style=f"bold {label_color}", no_wrap=True, overflow="ellipsis")
        room = self.size.width - len(head) - 1
        if self.history and room >= 4:
            head.append(" ")
            head.append_text(sparkline(self.history, room, color))
        value = Text(self.value, style=f"bold {value_color}", no_wrap=True, overflow="ellipsis")
        if self.sub:
            value.append(f"  {self.sub}", style=sub_color)
        return Group(head, value)


class Panel(Static):
    """Panneau d'analyse : contenu Rich mis à jour à la demande."""

    def __init__(self, title: str, **kwargs):
        super().__init__(**kwargs)
        self.border_title = title


def ranking(rows: list[tuple[str, float, str]], width: int, pal: Palette, color: str | None = None, limit: int = 8) -> Table:
    """Tableau « libellé  ████──  valeur » pour les classements."""
    table = Table.grid(expand=True, padding=(0, 1))
    table.add_column(no_wrap=True, overflow="ellipsis", ratio=3)
    table.add_column(no_wrap=True, ratio=2)
    table.add_column(justify="right", no_wrap=True)
    rows = rows[:limit]
    if not rows:
        table.add_row(Text("Aucune donnée", style=pal.dim), "", "")
        return table
    top = max(r[1] for r in rows) or 1
    bar_width = max(4, width * 2 // 5 - 2)
    for label, value, shown in rows:
        c = color or pal.proto_color(label.split()[0])
        table.add_row(Text(label, style=pal.fg), bar(value / top, bar_width, c, pal.dim), Text(shown, style=pal.muted))
    return table


# ---------------------------------------------------------------- détail paquet

def build_tree(tree: Tree, pkt: Packet, pal: Palette) -> None:
    """Arborescence des couches. Toutes les étiquettes sont des Text (aucun markup interprété)."""
    tree.clear()
    tree.root.set_label(Text(f"Trame {pkt.id} : {pkt.length} octets", style=f"bold {pal.primary}"))
    for layer in layer_tree(pkt):
        node = tree.root.add(Text(layer.name, style=f"bold {pal.proto_color(layer.name.split()[0])}"), expand=True)
        for name, value in layer.fields:
            label = Text(f"{name}: " if name else "", style=pal.muted)
            label.append(value, style=pal.accent if not name else pal.fg)
            node.add_leaf(label)
    tree.root.expand()


def hexdump_lines(data: bytes, pal: Palette) -> list[Text]:
    lines = []
    for offset, hexpart, ascii_part in hexdump(data):
        line = Text(f"{offset}  ", style=pal.dim)
        line.append(f"{hexpart:<49}", style=pal.fg)
        line.append(" │", style=pal.dim)
        line.append(ascii_part, style=pal.accent)
        lines.append(line)
    return lines


def insight(pkt: Packet, flow, src_host, dst_host, alerts: list[Alert], geo, pal: Palette) -> Group:
    """Synthèse du paquet sélectionné : flux, hôtes, empreintes, alertes."""
    rows = Table.grid(padding=(0, 1))
    rows.add_column(style=pal.muted, no_wrap=True)
    rows.add_column(overflow="fold")

    if flow is not None:
        t = Text()
        t.append(f"#{flow.id} ", style=f"bold {pal.primary}")
        t.append(f"{flow.app or flow.l4}  ", style=f"bold {pal.proto_color(flow.app or flow.l4)}")
        t.append(f"{flow.client}:{flow.cport or ''} → {flow.server}:{flow.sport or ''}  ", style=pal.fg)
        t.append(f"{flow.state or '-'} · {flow.packets} pkts · {fmt_bytes(flow.bytes)} · {fmt_duration(flow.duration)}",
                 style=pal.muted)
        rows.add_row("Flux", t)
    for label, value, style in (("Domaine", pkt.domain, f"bold {pal.accent}"), ("JA3", pkt.ja3, pal.fg),
                                ("JA4", pkt.ja4, pal.fg)):
        if value:
            rows.add_row(label, Text(value, style=style))
    for label, host in (("Source", src_host), ("Destination", dst_host)):
        if host is None:
            continue
        t = Text(host.ip, style=f"bold {pal.fg}")
        info = geo.lookup(host.ip) if geo is not None else None
        if info is not None and info.country not in ("??",):
            t.append(f"  {info.short}", style=pal.accent)
        if host.os:
            t.append(f"  {host.os} ({host.os_conf}%)", style=pal.muted)
        if host.mac:
            t.append(f"  {host.mac}", style=pal.dim)
        if host.names:
            t.append("  " + ", ".join(sorted(host.names)[:3]), style=pal.accent)
        rows.add_row(label, t)
    parts = [rows]
    for a in alerts:
        t = Text(f" {SEV_NAMES[a.severity]} ", style=f"bold reverse {pal.sev[a.severity]}")
        t.append(" ")
        t.append(a.title, style=f"bold {pal.sev[a.severity]}")
        t.append(f"  {a.detail.splitlines()[0] if a.detail else ''}", style=pal.muted)
        parts.append(t)
    return Group(*parts)
