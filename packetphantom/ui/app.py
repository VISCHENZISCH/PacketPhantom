"""Application Textual PacketPhantom."""
from __future__ import annotations

import time
from collections import deque
from pathlib import Path

from rich.console import Group
from rich.table import Table
from rich.text import Text
from textual import on
from textual.app import App, ComposeResult
from textual.binding import Binding
from textual.containers import Grid, Horizontal, Vertical
from textual.widgets import DataTable, Footer, Input, Label, RichLog, Static, TabbedContent, TabPane, Tree

from .. import analytics, export
from ..capture import CaptureError, default_interface, list_interfaces
from ..engine import Engine
from ..filters import FilterError, compile_filter
from ..geoip import GeoResolver
from ..model import Alert, Packet
from .screens import ExportScreen, FollowStreamScreen, HelpScreen, InterfaceScreen, bpf_prompt, open_prompt
from .theme import (
    PHANTOM_DARK,
    PHANTOM_LIGHT,
    SEV_NAMES,
    Palette,
    fmt_bits,
    fmt_bytes,
    fmt_count,
    fmt_duration,
    fmt_time,
    pill_chart,
)
from .widgets import Kpi, Panel, StatusBar, build_tree, hexdump_lines, insight, ranking

TABS = ["tab-packets", "tab-flows", "tab-hosts", "tab-alerts", "tab-analytics"]
STATE_TONES = {"ESTABLISHED": 0, "RESET": 4, "SYN": 2, "SYN-ACK": 2, "FIN": 1, "CLOSED": 1}
MAX_ALERT_ROWS = 5000
TRAFFIC_BUCKETS = 8
TABLE_COLUMNS = {
    "#flows": (("#", "id"), ("Proto", "app"), ("Client", "client"), ("Serveur", "server"), ("Pays", "geo"),
               ("Paquets", "packets"), ("Octets", "bytes"), ("Durée", "duration"), ("État", "state"),
               ("Domaine / SNI", "label"), ("Vu", "last")),
    "#hosts": (("Adresse", "ip"), ("MAC", "mac"), ("Système", "os"), ("Localisation", "geo"), ("Noms", "names"),
               ("Émis", "tx"), ("Reçus", "rx"), ("Pairs", "peers"), ("Services", "services"), ("Vu", "last")),
    "#alerts": (("Heure", "time"), ("Sévérité", "sev"), ("Catégorie", "cat"), ("Alerte", "title"),
                ("Source", "src"), ("Destination", "dst")),
}
SORT_KEYS = {
    "flows": {"last": lambda f: f.last, "id": lambda f: f.id, "app": lambda f: f.app, "client": lambda f: f.client,
              "server": lambda f: f.server, "packets": lambda f: f.packets, "bytes": lambda f: f.bytes,
              "duration": lambda f: f.duration, "state": lambda f: f.state, "label": lambda f: f.label},
    "hosts": {"bytes": lambda h: h.bytes, "ip": lambda h: h.ip, "mac": lambda h: h.mac, "os": lambda h: h.os,
              "tx": lambda h: h.bytes_tx, "rx": lambda h: h.bytes_rx, "peers": lambda h: len(h.peers),
              "last": lambda h: h.last, "names": lambda h: min(h.names, default=""),
              "services": lambda h: len(h.services)},
}


class PhantomApp(App):
    TITLE = "PacketPhantom"
    CSS_PATH = "phantom.tcss"
    ENABLE_COMMAND_PALETTE = False

    BINDINGS = [
        Binding("s", "toggle_capture", "Capture"),
        Binding("slash", "focus_filter", "Filtre"),
        Binding("f", "follow", "Suivre flux"),
        Binding("g", "filter_flow", "Conversation"),
        Binding("p", "toggle_pause", "Figer"),
        Binding("i", "pick_interface", "Interface"),
        Binding("b", "capture_filter", "BPF"),
        Binding("o", "open_file", "Ouvrir"),
        Binding("e", "export", "Exporter"),
        Binding("c", "clear", "Effacer", show=False),
        Binding("t", "toggle_theme", "Thème", show=False),
        Binding("question_mark", "help", "Aide"),
        Binding("escape", "escape", show=False),
        *(Binding(str(i + 1), f"tab({i})", show=False) for i in range(len(TABS))),
        Binding("q", "quit", "Quitter"),
    ]

    def __init__(self, engine: Engine, geo: GeoResolver, iface: str | None = None, bpf: str = "",
                 read: str | None = None, realtime: bool = False, autostart: bool = True, max_rows: int = 3000,
                 display_filter: str = "", api=None):
        super().__init__()
        self.engine = engine
        self.geo = geo
        self.api = api
        self.iface = iface or default_interface()
        self.bpf = bpf
        self.read_path = read
        self.realtime = realtime
        self.autostart = autostart
        self.max_rows = max_rows
        self.initial_filter = display_filter

        self.paused = False
        self.selected_pid: int | None = None
        self._predicate = None
        self._filter_text = ""
        self._row_keys: deque[str] = deque()
        self._packet_cursor = 0
        self._alert_cursor = 0
        self._alerts_by_id: dict[int, Alert] = {}
        self._detail_timer = None
        self._last_error: str | None = None
        self._last_toast = 0.0
        self._tick = 0
        self._sort = {"flows": ("last", True), "hosts": ("bytes", True)}

    # ================================================================ structure

    def compose(self) -> ComposeResult:
        yield StatusBar(id="statusbar")
        with Horizontal(id="kpis"):
            for label, kpi_id in (("Paquets", "packets"), ("Paquets / s", "pps"), ("Débit", "bps"),
                                  ("Flux", "flows"), ("Hôtes", "hosts"), ("Alertes", "alerts")):
                yield Kpi(label, hero=kpi_id == "packets", id=f"kpi-{kpi_id}")
        with TabbedContent(id="tabs", initial="tab-packets"):
            with TabPane("Paquets", id="tab-packets"):
                yield DataTable(id="packets", cursor_type="row")
                with Horizontal(id="detail"):
                    yield Tree("Trame", id="pkt-tree")
                    with Vertical(id="detail-right"):
                        yield Static(id="pkt-insight")
                        yield RichLog(id="pkt-hex", wrap=False, max_lines=2000, auto_scroll=False)
            with TabPane("Flux", id="tab-flows"):
                yield DataTable(id="flows", cursor_type="row")
            with TabPane("Hôtes", id="tab-hosts"):
                yield DataTable(id="hosts", cursor_type="row")
                yield Static(id="host-detail", classes="detail-card")
            with TabPane("Alertes", id="tab-alerts"):
                yield DataTable(id="alerts", cursor_type="row")
                yield Static(id="alert-detail", classes="detail-card")
            with TabPane("Analyse", id="tab-analytics"), Grid(id="analytics"):
                yield Panel("Trafic - 120 dernières secondes", id="an-traffic")
                yield Panel("Protocoles", id="an-protocols")
                yield Panel("Hôtes les plus actifs", id="an-talkers")
                yield Panel("Domaines (DNS · SNI · HTTP)", id="an-domains")
                yield Panel("Services (connexions acceptées)", id="an-services")
                yield Panel("Pays", id="an-countries")
        with Horizontal(id="filterbar"):
            yield Label(" FILTRE ", id="filter-label")
            yield Input(placeholder="tls and ip.addr == 10.0.0.0/8   ·   port 53   ·   alert >= high   ·   ? aide",
                        id="filter")
            yield Static(id="filter-status")
        yield Footer()

    def on_mount(self) -> None:
        self.register_theme(PHANTOM_DARK)
        self.register_theme(PHANTOM_LIGHT)
        self.theme = "phantom"

        packets = self.query_one("#packets", DataTable)
        for label, key, width in ((" ", "sev", 1), ("No.", "no", 7), ("Heure", "time", 12), ("Source", "src", 24),
                                  ("Destination", "dst", 24), ("Proto", "proto", 8), ("Long.", "len", 6),
                                  ("Info", "info", None)):
            packets.add_column(label, key=key, width=width)
        for selector, columns in TABLE_COLUMNS.items():
            table = self.query_one(selector, DataTable)
            for label, key in columns:
                table.add_column(label, key=key)

        muted = self.pal.muted
        for widget_id, hint in (("#host-detail", "Sélectionnez un hôte. Entrée : voir ses paquets."),
                                ("#alert-detail", "Sélectionnez une alerte. Entrée : voir le trafic associé."),
                                ("#pkt-insight", "Sélectionnez un paquet pour l'analyser.")):
            self.query_one(widget_id, Static).update(Text(hint, style=muted))
        packets.focus()

        self.set_interval(0.25, self.pump)
        self.set_interval(1.0, self.second)
        self._update_filter_status()
        if self.initial_filter:
            self.apply_filter(self.initial_filter)
        if self.api is not None:
            self.notify(self.api.url, title="Tableau de bord web", timeout=15, markup=False)

        if self.read_path:
            self._start(self.engine.start_file, self.read_path, self.realtime)
        elif self.autostart:
            self._start(self.engine.start_live, self.iface, self.bpf)
        self.second()

    @property
    def pal(self) -> Palette:
        theme = self.current_theme
        return Palette(theme.dark if theme is not None else True)

    # ================================================================ capture

    def _start(self, starter, *args) -> None:
        try:
            starter(*args)
            self.notify(f"Source : {self.engine.source}", markup=False, timeout=3)
        except (CaptureError, OSError) as exc:
            self.notify(str(exc), title="Capture", severity="error", markup=False, timeout=10)

    def _restart_live(self) -> None:
        self.engine.stop()
        self._start(self.engine.start_live, self.iface, self.bpf)
        self.second()

    def action_toggle_capture(self) -> None:
        if self.engine.running:
            self.engine.stop()
            self.notify("Capture arrêtée", timeout=2)
            self.second()
        else:
            self._restart_live()

    def action_pick_interface(self) -> None:
        def chosen(iface: str | None) -> None:
            if iface:
                self.iface = iface
                self._restart_live()
        self.push_screen(InterfaceScreen(list_interfaces(), self.iface), chosen)

    def action_capture_filter(self) -> None:
        def chosen(value: str | None) -> None:
            if value is None:
                return
            self.bpf = value
            if self.engine.mode == "live":
                self._restart_live()
            else:
                self.notify("Filtre BPF enregistré : il s'appliquera à la prochaine capture", timeout=3)
        self.push_screen(bpf_prompt(self.bpf, self.iface), chosen)

    def action_open_file(self) -> None:
        def chosen(path: str | None) -> None:
            if not path:
                return
            self.engine.stop()
            self._clear_session()
            self.read_path = str(Path(path).expanduser())
            self._start(self.engine.start_file, self.read_path, self.realtime)
        self.push_screen(open_prompt(), chosen)

    def action_clear(self) -> None:
        self._clear_session()
        self.notify("Session effacée", timeout=2)

    def _clear_session(self) -> None:
        self.engine.reset()
        for table_id in ("#packets", *TABLE_COLUMNS):
            self.query_one(table_id, DataTable).clear()
        self._row_keys.clear()
        self._alerts_by_id.clear()
        self.selected_pid = None
        self.query_one("#pkt-tree", Tree).clear()
        self.query_one("#pkt-hex", RichLog).clear()
        self.query_one("#pkt-insight", Static).update("")
        self._update_filter_status()
        self.second()

    async def action_quit(self) -> None:
        self.engine.stop()
        self.exit()

    # ================================================================ boucle

    def pump(self) -> None:
        error = self.engine.poll_health()
        if error and error != self._last_error:
            self._last_error = error
            self.notify(error, title="Capture", severity="error", timeout=12, markup=False)
        alerts = self.engine.alerts_after(self._alert_cursor)
        if alerts:
            self._alert_cursor = alerts[-1].id
            self._add_alerts(alerts)
        if not self.paused:
            packets = self.engine.packets_after(self._packet_cursor, self.max_rows)
            self._packet_cursor = self.engine.last_packet_id
            if packets:
                self._append_packets(packets)

    def second(self) -> None:
        self._tick += 1
        status = analytics.status(self.engine, self.geo)
        self._refresh_header(status)
        self._refresh_kpis(status)
        if self.paused or not (self._tick % 2 == 0 or self._tick < 3):
            return
        refresh = {"tab-flows": self.refresh_flows, "tab-hosts": self.refresh_hosts,
                   "tab-analytics": self.refresh_analytics}.get(self.query_one("#tabs", TabbedContent).active)
        if refresh is not None:
            refresh()

    def _refresh_header(self, status: dict) -> None:
        warnings = []
        if status["dropped"]:
            warnings.append(f"⚠ {fmt_count(status['dropped'])} paquets perdus")
        if status["backlog"] > 1000:
            warnings.append(f"file d'analyse : {fmt_count(status['backlog'])}")
        api = f"{self.api.address[0]}:{self.api.address[1]}" if self.api else ""
        self.query_one(StatusBar).set_state(
            mode="paused" if self.paused else status["mode"], source=status["source"] or self.iface,
            bpf=status["bpf"] if self.engine.running else self.bpf, warning="  ".join(warnings),
            api=api, tls="déchiffrement actif" if status["tls_keylog"] else "", geo=status["geo"])

    def _refresh_kpis(self, status: dict) -> None:
        pps, bps = status["pps"], status["bps"]
        severities = {int(k): v for k, v in status["alerts"].items()}
        crit, high, n_alerts = severities.get(4, 0), severities.get(3, 0), sum(severities.values())
        local = sum(1 for h in self.engine.hosts.values() if h.local) if status["hosts"] < 5000 else None
        self.query_one("#kpi-packets", Kpi).set(fmt_count(status["packets"]), fmt_bytes(status["bytes"]))
        self.query_one("#kpi-pps", Kpi).set(fmt_count(pps[-1]), f"max {fmt_count(max(pps))}", pps)
        self.query_one("#kpi-bps", Kpi).set(fmt_bits(bps[-1]), f"max {fmt_bits(max(bps))}", bps)
        self.query_one("#kpi-flows", Kpi).set(fmt_count(status["flows"]), fmt_duration(status["uptime"]))
        self.query_one("#kpi-hosts", Kpi).set(fmt_count(status["hosts"]), f"{local} LAN" if local is not None else "")
        tone = "alert" if crit else ("warn" if high else ("good" if status["packets"] else ""))
        sub = " · ".join(p for p in (f"{crit} crit." if crit else "", f"{high} élev." if high else "") if p)
        self.query_one("#kpi-alerts", Kpi).set(fmt_count(n_alerts), sub, tone=tone)

        tabs = self.query_one("#tabs", TabbedContent)
        for pane, label, count in (("tab-packets", "Paquets", status["packets"]), ("tab-flows", "Flux", status["flows"]),
                                   ("tab-hosts", "Hôtes", status["hosts"]), ("tab-alerts", "Alertes", n_alerts)):
            tabs.get_tab(pane).label = f"{label} {fmt_count(count)}" if count else label

    # ================================================================ paquets

    def _matches(self, pkt: Packet) -> bool:
        if self._predicate is None:
            return True
        try:
            return bool(self._predicate(pkt))
        except Exception:
            return False

    def _add_packet_row(self, table: DataTable, pkt: Packet, pal: Palette) -> None:
        key = str(pkt.id)
        if pkt.severity >= 0:
            marker = Text("▌", style=pal.sev[pkt.severity])
            info_style = f"bold {pal.sev[pkt.severity]}" if pkt.severity >= 2 else pal.fg
        else:
            marker = Text(" ")
            info_style = pal.sev[3] if "RST" in pkt.flags else pal.fg
        table.add_row(
            marker, Text(key, style=pal.muted), Text(fmt_time(pkt.ts), style=pal.muted),
            Text(pkt.src, style=pal.fg), Text(pkt.dst, style=pal.fg), pal.proto_text(pkt.proto),
            Text(str(pkt.length), style=pal.muted, justify="right"), Text(pkt.info[:240], style=info_style),
            key=key,
        )
        self._row_keys.append(key)

    def _fill_packets(self, packets: list[Packet]) -> None:
        table = self.query_one("#packets", DataTable)
        pal = self.pal
        for pkt in [p for p in packets if self._matches(p)][-self.max_rows:]:
            self._add_packet_row(table, pkt, pal)
        while len(self._row_keys) > self.max_rows:
            table.remove_row(self._row_keys.popleft())
        self._update_filter_status()

    def _append_packets(self, packets: list[Packet]) -> None:
        table = self.query_one("#packets", DataTable)
        at_bottom = table.scroll_y >= table.max_scroll_y - 1
        self._fill_packets(packets)
        if at_bottom:
            table.scroll_end(animate=False)

    def rebuild_packets(self, select: int | None = None) -> None:
        table = self.query_one("#packets", DataTable)
        table.clear()
        self._row_keys.clear()
        self._fill_packets(self.engine.snapshot_packets())
        self._packet_cursor = self.engine.last_packet_id
        if select is not None and str(select) in table.rows:
            table.move_cursor(row=table.get_row_index(str(select)))
        else:
            table.scroll_end(animate=False)

    def _update_filter_status(self) -> None:
        pal = self.pal
        shown = len(self._row_keys)
        text = Text(fmt_count(shown), style=f"bold {pal.fg}")
        text.append(f" / {fmt_count(len(self.engine.ring))} paquets", style=pal.muted)
        if shown >= self.max_rows:
            text.append("  (affichage limité)", style=pal.dim)
        self.query_one("#filter-status", Static).update(text)

    @on(DataTable.RowHighlighted, "#packets")
    def _packet_highlighted(self, event: DataTable.RowHighlighted) -> None:
        if event.row_key is None or event.row_key.value is None:
            return
        self.selected_pid = int(event.row_key.value)
        if self._detail_timer is not None:
            self._detail_timer.stop()
        self._detail_timer = self.set_timer(0.06, self._render_detail)

    def _render_detail(self) -> None:
        pal = self.pal
        pkt = self.engine.get_packet(self.selected_pid) if self.selected_pid else None
        tree = self.query_one("#pkt-tree", Tree)
        hexlog = self.query_one("#pkt-hex", RichLog)
        panel = self.query_one("#pkt-insight", Static)
        hexlog.clear()
        if pkt is None:
            tree.clear()
            panel.update(Text("Ce paquet n'est plus dans le tampon de capture.", style=pal.muted))
            return
        build_tree(tree, pkt, pal)
        for line in hexdump_lines(pkt.data, pal):
            hexlog.write(line)
        with self.engine.lock:
            flow = self.engine.flows.by_id.get(pkt.flow_id)
            src, dst = self.engine.hosts.get(pkt.src), self.engine.hosts.get(pkt.dst)
            alerts = self.engine.alerts_for_packet(pkt.id)
        panel.update(insight(pkt, flow, src, dst, alerts, self.geo, pal))

    # ================================================================ filtre

    def apply_filter(self, text: str, select: int | None = None) -> bool:
        field = self.query_one("#filter", Input)
        try:
            predicate = compile_filter(text)
        except FilterError as exc:
            field.set_class(True, "bad")
            self.notify(str(exc), title="Filtre invalide", severity="error", markup=False, timeout=4)
            return False
        self._predicate = predicate
        self._filter_text = text.strip()
        if field.value != text:
            field.value = text
        field.set_class(False, "bad")
        field.set_class(bool(self._filter_text), "active")
        self.rebuild_packets(select=select or self.selected_pid)
        return True

    @on(Input.Changed, "#filter")
    def _filter_changed(self, event: Input.Changed) -> None:
        try:
            compile_filter(event.value)
            event.input.set_class(False, "bad")
        except FilterError:
            event.input.set_class(True, "bad")

    @on(Input.Submitted, "#filter")
    def _filter_submitted(self, event: Input.Submitted) -> None:
        self._pivot(event.value)

    def action_focus_filter(self) -> None:
        self.query_one("#filter", Input).focus()

    def action_escape(self) -> None:
        field = self.query_one("#filter", Input)
        if field.has_focus:
            field.value = self._filter_text
            self.query_one("#packets", DataTable).focus()
        elif self._filter_text:
            self.apply_filter("")

    def _pivot(self, expression: str, select: int | None = None) -> None:
        self.query_one("#tabs", TabbedContent).active = "tab-packets"
        if self.apply_filter(expression, select=select):
            self.query_one("#packets", DataTable).focus()

    def action_filter_flow(self) -> None:
        pkt = self.engine.get_packet(self.selected_pid) if self.selected_pid else None
        if pkt is None or not pkt.flow_id:
            self.notify("Sélectionnez un paquet appartenant à une conversation", severity="warning", timeout=3)
            return
        self.apply_filter(f"flow == {pkt.flow_id}", select=pkt.id)

    # ================================================================ suivi de flux

    def _current_flow_id(self) -> int | None:
        if self.query_one("#tabs", TabbedContent).active == "tab-flows":
            key = self._current_key(self.query_one("#flows", DataTable))
            return int(key) if key else None
        pkt = self.engine.get_packet(self.selected_pid) if self.selected_pid else None
        return pkt.flow_id if pkt is not None and pkt.flow_id else None

    def action_follow(self) -> None:
        flow_id = self._current_flow_id()
        conv = self.engine.conversation(flow_id) if flow_id else None
        if conv is None:
            self.notify("Sélectionnez un paquet TCP/UDP ou un flux encore en mémoire", severity="warning", timeout=3)
            return
        self.push_screen(FollowStreamScreen(conv), lambda result: result and self._pivot(result))

    # ================================================================ flux & hôtes

    def _geo_label(self, ip: str) -> Text:
        pal = self.pal
        info = self.geo.lookup(ip)
        if info is None:
            return Text("…", style=pal.dim)
        if info.country in ("LAN", "??"):
            return Text(info.country if info.country == "LAN" else "-", style=pal.dim)
        return Text(info.short, style=pal.accent)

    @staticmethod
    def _current_key(table: DataTable) -> str | None:
        if not table.row_count:
            return None
        try:
            return table.coordinate_to_cell_key(table.cursor_coordinate).row_key.value
        except Exception:
            return None

    def _rebuild_table(self, table: DataTable, kind: str, items: list, row) -> None:
        """Reconstruit un tableau trié en conservant la sélection et le défilement."""
        column, reverse = self._sort[kind]
        keys = SORT_KEYS[kind]
        items = sorted(items, key=keys.get(column, next(iter(keys.values()))), reverse=reverse)[:1500]
        selected, scroll = self._current_key(table), table.scroll_y
        table.clear()
        for item in items:
            cells, key = row(item)
            table.add_row(*cells, key=key)
        if selected is not None and selected in table.rows:
            table.move_cursor(row=table.get_row_index(selected), animate=False, scroll=False)
        table.scroll_y = min(scroll, table.max_scroll_y)

    def refresh_flows(self) -> None:
        pal = self.pal
        with self.engine.lock:
            flows = self.engine.flows.values()

        def row(f):
            proto = f.app or f.l4
            tone = STATE_TONES.get(f.state)
            return (
                Text(str(f.id), style=pal.muted), pal.proto_text(proto),
                Text(f"{f.client}:{f.cport}" if f.cport is not None else f.client, style=pal.fg),
                Text(f"{f.server}:{f.sport}" if f.sport is not None else f.server, style=pal.fg),
                self._geo_label(f.server), Text(fmt_count(f.packets), justify="right"),
                Text(fmt_bytes(f.bytes), justify="right"), Text(fmt_duration(f.duration), style=pal.muted),
                Text(f.state or "-", style=pal.good if tone == 0 else pal.sev.get(tone, pal.muted)),
                Text(f.label, style=pal.accent), Text(fmt_time(f.last)[:8], style=pal.muted),
            ), str(f.id)
        self._rebuild_table(self.query_one("#flows", DataTable), "flows", flows, row)

    def refresh_hosts(self) -> None:
        pal = self.pal
        with self.engine.lock:
            hosts = self.engine.hosts.values()

        def row(h):
            names = sorted(h.names)
            return (
                Text(h.ip, style=f"bold {pal.fg}"), Text(h.mac or "-", style=pal.muted),
                Text(f"{h.os} {h.os_conf}%" if h.os else "-", style=pal.fg if h.os_conf >= 60 else pal.muted),
                self._geo_label(h.ip),
                Text(", ".join(names[:2]) + (f" +{len(names) - 2}" if len(names) > 2 else ""), style=pal.accent),
                Text(fmt_bytes(h.bytes_tx), justify="right"), Text(fmt_bytes(h.bytes_rx), justify="right"),
                Text(str(len(h.peers)), justify="right"), Text(" ".join(sorted(h.services)[:4]), style=pal.accent),
                Text(fmt_time(h.last)[:8], style=pal.muted),
            ), h.ip
        self._rebuild_table(self.query_one("#hosts", DataTable), "hosts", hosts, row)

    @on(DataTable.HeaderSelected, "#flows, #hosts")
    def _sort_column(self, event: DataTable.HeaderSelected) -> None:
        kind, column = event.data_table.id, event.column_key.value
        current, reverse = self._sort[kind]
        self._sort[kind] = (column, not reverse if current == column else True)
        (self.refresh_flows if kind == "flows" else self.refresh_hosts)()

    @on(DataTable.RowSelected, "#flows")
    def _flow_selected(self, event: DataTable.RowSelected) -> None:
        self._pivot(f"flow == {event.row_key.value}")

    @on(DataTable.RowSelected, "#hosts")
    def _host_selected(self, event: DataTable.RowSelected) -> None:
        self._pivot(f"ip.addr == {event.row_key.value}")

    @on(DataTable.RowHighlighted, "#hosts")
    def _host_highlighted(self, event: DataTable.RowHighlighted) -> None:
        if event.row_key is None:
            return
        pal = self.pal
        with self.engine.lock:
            h = self.engine.hosts.get(event.row_key.value)
            if h is None:
                return
            names, services, agents = sorted(h.names), sorted(h.services), sorted(h.user_agents)
        geo = self.geo.lookup(h.ip)
        title = Text(h.ip, style=f"bold {pal.primary}")
        title.append(f"   {'réseau local' if h.local else 'Internet'}", style=pal.muted)
        if geo is not None and geo.country not in ("LAN", "??"):
            title.append(f"   {geo.name}{' · ' + geo.city if geo.city else ''}", style=pal.accent)
        grid = Table.grid(padding=(0, 2))
        grid.add_column(style=pal.muted, no_wrap=True)
        grid.add_column(overflow="fold")
        for label, value, style in (
            ("Système", f"{h.os or 'inconnu'}" + (f"  (confiance {h.os_conf}%)" if h.os else ""), pal.fg),
            ("MAC", h.mac or "-", pal.fg),
            ("Noms", ", ".join(names) or "-", pal.accent),
            ("Services", ", ".join(services) or "-", pal.accent),
            ("User-Agents", "\n".join(agents[:4]), pal.fg),
            ("Trafic", f"émis {fmt_bytes(h.bytes_tx)} ({fmt_count(h.pkts_tx)} pkts) · reçus {fmt_bytes(h.bytes_rx)} "
                       f"({fmt_count(h.pkts_rx)} pkts) · {len(h.peers)} pairs", pal.fg),
            ("Vu", f"{fmt_time(h.first)} → {fmt_time(h.last)}", pal.muted),
        ):
            if value:
                grid.add_row(label, Text(value, style=style))
        self.query_one("#host-detail", Static).update(Group(title, grid))

    # ================================================================ alertes

    def _alert_row(self, table: DataTable, a: Alert, pal: Palette) -> None:
        table.add_row(
            Text(fmt_time(a.ts)[:8], style=pal.muted), pal.sev_text(a.severity), Text(a.category, style=pal.fg),
            Text(a.title, style=f"bold {pal.sev[a.severity]}" if a.severity >= 3 else pal.fg),
            Text(a.src, style=pal.fg), Text(a.dst, style=pal.fg), key=str(a.id),
        )

    def _add_alerts(self, alerts: list[Alert]) -> None:
        pal = self.pal
        table = self.query_one("#alerts", DataTable)
        at_bottom = table.scroll_y >= table.max_scroll_y - 1
        for a in alerts:
            self._alerts_by_id[a.id] = a
            self._alert_row(table, a, pal)
        while table.row_count > MAX_ALERT_ROWS:
            first = next(iter(table.rows))
            table.remove_row(first)
            self._alerts_by_id.pop(int(first.value), None)
        if at_bottom:
            table.scroll_end(animate=False)

        important = [a for a in alerts if a.severity >= 3]
        now = time.monotonic()
        if important and now - self._last_toast > 1.5:
            self._last_toast = now
            top = max(important, key=lambda a: a.severity)
            more = f"\n+ {len(important) - 1} autre(s)" if len(important) > 1 else ""
            self.notify(f"{top.detail.splitlines()[0] if top.detail else top.src}{more}",
                        title=f"{SEV_NAMES[top.severity]} · {top.title}",
                        severity="error" if top.severity == 4 else "warning", timeout=6, markup=False)

    def rebuild_alerts(self) -> None:
        table = self.query_one("#alerts", DataTable)
        table.clear()
        pal = self.pal
        for a in self._alerts_by_id.values():
            self._alert_row(table, a, pal)

    @on(DataTable.RowHighlighted, "#alerts")
    def _alert_highlighted(self, event: DataTable.RowHighlighted) -> None:
        a = self._alerts_by_id.get(int(event.row_key.value)) if event.row_key is not None else None
        if a is None:
            return
        pal = self.pal
        head = Text()
        head.append(f" {SEV_NAMES[a.severity]} ", style=f"bold reverse {pal.sev[a.severity]}")
        head.append(f"  {a.title}", style=f"bold {pal.fg}")
        head.append(f"   {a.category} · {fmt_time(a.ts)} · paquet {a.packet_id}"
                    + (f" · flux #{a.flow_id}" if a.flow_id else ""), style=pal.muted)
        self.query_one("#alert-detail", Static).update(Group(head, Text(""), Text(a.detail, style=pal.fg)))

    @on(DataTable.RowSelected, "#alerts")
    def _alert_selected(self, event: DataTable.RowSelected) -> None:
        a = self._alerts_by_id.get(int(event.row_key.value))
        if a is not None:
            self._pivot(f"flow == {a.flow_id}" if a.flow_id else f"frame == {a.packet_id}", select=a.packet_id)

    # ================================================================ analyse

    def refresh_analytics(self) -> None:
        pal = self.pal
        status = analytics.status(self.engine, self.geo)
        data = analytics.rankings(self.engine, self.geo)
        pps, bps = status["pps"], status["bps"]

        traffic = self.query_one("#an-traffic", Panel)
        head = Text("Débit ", style=pal.muted)
        head.append(fmt_bits(bps[-1]), style=f"bold {pal.primary}")
        head.append(f"   max {fmt_bits(max(bps))}   ·   ", style=pal.muted)
        head.append(f"{fmt_count(pps[-1])} paquets/s", style=f"bold {pal.fg}")
        period = len(bps) // TRAFFIC_BUCKETS
        labels = [time.strftime("%M:%S", time.localtime(time.time() - (TRAFFIC_BUCKETS - 1 - i) * period))
                  for i in range(TRAFFIC_BUCKETS)]
        chart = pill_chart(bps, max(16, traffic.size.width - 4), max(3, traffic.size.height - 5), pal, labels)
        traffic.update(Group(head, Text(""), *chart))

        panels = {
            "#an-protocols": ([(p["name"], p["count"], f"{p['share']:6.1%}") for p in data["protocols"]], None),
            "#an-talkers": ([(f"{t['ip']}  {t['name']}".strip(), t["bytes"], fmt_bytes(t["bytes"]))
                             for t in data["talkers"]], pal.primary),
            "#an-domains": ([(d["name"], d["count"], fmt_count(d["count"])) for d in data["domains"]], pal.accent),
            "#an-services": ([(s["name"], s["count"], f"{fmt_count(s['count'])} cnx") for s in data["services"]],
                             pal.strong),
            "#an-countries": ([(f"{c['code']}  {c['name']}", c["bytes"], fmt_bytes(c["bytes"]))
                               for c in data["countries"]], pal.server),
        }
        for selector, (rows, color) in panels.items():
            widget = self.query_one(selector, Panel)
            if selector == "#an-countries" and not rows:
                widget.update(Text(f"GeoIP {self.geo.note}.\nAucun hôte Internet géolocalisé pour l'instant.",
                                   style=pal.muted))
                continue
            widget.update(ranking(rows, widget.size.width - 4, pal, color, limit=max(3, widget.size.height - 2)))

    @on(TabbedContent.TabActivated)
    def _tab_changed(self, event: TabbedContent.TabActivated) -> None:
        refresh = {"tab-flows": self.refresh_flows, "tab-hosts": self.refresh_hosts,
                   "tab-analytics": self.refresh_analytics}.get(event.pane.id if event.pane is not None else "")
        if refresh is not None:
            self.call_after_refresh(refresh)

    # ================================================================ divers

    def action_tab(self, index: int) -> None:
        self.query_one("#tabs", TabbedContent).active = TABS[index]

    def action_toggle_pause(self) -> None:
        self.paused = not self.paused
        if not self.paused:
            self.rebuild_packets(select=self.selected_pid)
        self.notify("Affichage figé - la capture continue" if self.paused else "Affichage repris", timeout=2)
        self.second()

    def action_toggle_theme(self) -> None:
        self.theme = "phantom-light" if self.theme == "phantom" else "phantom"
        self.rebuild_packets(select=self.selected_pid)
        self.rebuild_alerts()
        self.second()
        if self.selected_pid:
            self._render_detail()

    def action_help(self) -> None:
        self.push_screen(HelpScreen())

    def action_export(self) -> None:
        def chosen(kind: str | None) -> None:
            if not kind:
                return
            try:
                path = self._export(kind)
            except Exception as exc:
                self.notify(f"Export impossible : {exc}", severity="error", markup=False)
                return
            self.notify(str(path), title="Export terminé", markup=False, timeout=6)
        self.push_screen(ExportScreen(), chosen)

    def _export(self, kind: str) -> Path:
        eng = self.engine
        if kind in ("pcap-view", "csv-view"):
            shown = [p for p in (eng.get_packet(int(k)) for k in self._row_keys) if p is not None]
            return export.packets_pcap(shown) if kind == "pcap-view" else export.packets_csv(shown)
        if kind == "pcap-all":
            return export.packets_pcap(eng.snapshot_packets())
        with eng.lock:
            if kind == "flows":
                return export.flows_csv(eng.flows.values(), self.geo)
            if kind == "hosts":
                return export.hosts_json(eng.hosts.values(), self.geo)
            return export.alerts_json(list(eng.alerts))
