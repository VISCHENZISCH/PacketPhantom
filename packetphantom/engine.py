"""Moteur : source de trames → décodage Rust → analyse → état partagé.

- Un seul thread d'analyse modifie l'état (flux, hôtes, alertes, stats), sous `self.lock`.
- Les consommateurs (TUI, API, mode headless) lisent par curseur (`packets_after`,
  `alerts_after`) : aucun ne « vole » les données d'un autre.
- La file d'entrée est bornée : en capture live l'excédent est compté comme perdu,
  en lecture de fichier le lecteur attend.
- Avec une base (`db`), les alertes, leur acquittement et la liste blanche survivent
  au redémarrage ; les identifiants d'alerte reprennent là où ils s'étaient arrêtés.
"""
from __future__ import annotations

import threading
import time
from collections import deque
from collections.abc import Iterable
from dataclasses import dataclass, replace
from itertools import count, islice

from . import _core
from .capture import FileSource, LiveSource, Source, default_interface
from .detect import Detector
from .flows import Conversation, Flow, FlowTable, reassemble
from .hosts import HostTable
from .model import Alert, Packet
from .rules import AllowEntry, RuleSet, make_allow
from .stats import Stats
from .store import Store
from .tlsdecrypt import KeyLog, decrypt_conversation

BATCH = 512
TLS_PENDING_LIMIT = 65_536


@dataclass
class EngineConfig:
    buffer: int = 100_000       # paquets conservés (détail, conversations, export)
    max_flows: int = 50_000
    max_hosts: int = 20_000
    max_alerts: int = 10_000
    queue_size: int = 100_000
    keylog: str | None = None   # SSLKEYLOGFILE pour le déchiffrement TLS
    rules: RuleSet | None = None    # seuils, règles désactivées, liste blanche (fichier --rules)
    db: str | None = None           # base SQLite des alertes et de la liste blanche
    retention_days: float = 30.0    # 0 : conservation illimitée


def _tail(items: deque, newest_id: int, after_id: int, limit: int) -> list:
    """Éléments d'id > after_id d'une deque ordonnée par id croissant (lecture depuis la fin)."""
    count = min(max(0, newest_id - after_id), len(items), limit)
    return list(islice(reversed(items), count))[::-1]


class Engine:
    def __init__(self, config: EngineConfig | None = None):
        self.cfg = config or EngineConfig()
        self.lock = threading.RLock()
        self.keylog = KeyLog(self.cfg.keylog) if self.cfg.keylog else None
        base = self.cfg.rules or RuleSet()
        # Copie : les exceptions ajoutées à l'exécution ne modifient pas la configuration de l'appelant.
        self.rules = RuleSet(base.thresholds, base.disabled, list(base.allow))
        self.store = Store(self.cfg.db, self.cfg.retention_days) if self.cfg.db else None
        self._allow_ids = count(1)
        self._queue: deque[tuple[bytes, float, int]] = deque()
        self._source: Source | None = None
        self._closed = threading.Event()
        self.mode = "idle"          # idle | live | file | done
        self.source = ""
        self.bpf = ""
        self.error: str | None = None
        # Identifiants monotones (jamais remis à zéro) : les curseurs des consommateurs restent valides.
        self.last_packet_id = 0
        self.last_alert_id = 0
        self.reset()
        if self.store is not None:
            for entry in self.store.allow_entries():
                self.rules.add(entry)
            self.last_alert_id = self.store.last_alert_id()
            self.alerts.extend(self.store.recent_alerts(self.cfg.max_alerts))
        self._thread = threading.Thread(target=self._analysis_loop, name="analysis", daemon=True)
        self._thread.start()

    # ------------------------------------------------------------ état

    def reset(self) -> None:
        with self.lock:
            self.ring: deque[Packet] = deque(maxlen=self.cfg.buffer)
            self.flows = FlowTable(self.cfg.max_flows)
            self.hosts = HostTable(self.cfg.max_hosts)
            self.detector = Detector(self.rules)
            self.alerts: deque[Alert] = deque(maxlen=self.cfg.max_alerts)
            self.stats = Stats()
            self._tls_pending: dict[int, bytes] = {}
            self.dropped = 0
            self.analysis_errors = 0
            self._next_tick = time.monotonic() + 1

    @property
    def running(self) -> bool:
        return self.mode in ("live", "file")

    @property
    def backlog(self) -> int:
        return len(self._queue)

    # ------------------------------------------------------------ sources

    def start_live(self, iface: str | None = None, bpf: str = "") -> None:
        iface = iface or default_interface()
        self._start(LiveSource(self._push, iface, bpf), "live", iface, bpf)

    def start_file(self, path: str, realtime: bool = False) -> None:
        self._start(FileSource(self._push_wait, path, realtime), "file", path, "")

    def _start(self, source: Source, mode: str, name: str, bpf: str) -> None:
        if self.running:
            return
        source.start()   # lève CaptureError (permissions, BPF, fichier) de façon synchrone
        self._source, self.mode, self.source, self.bpf, self.error = source, mode, name, bpf, None
        with self.lock:
            self.stats.started = time.time()

    def stop(self) -> None:
        if self._source is not None:
            self._source.stop()
            self._source = None
        if self.running:
            self.mode = "idle"

    def close(self) -> None:
        self.stop()
        self._closed.set()
        self._thread.join(timeout=5)
        if self.store is not None:
            self.store.close()

    def poll_health(self) -> str | None:
        """Met à jour l'état selon la source (fin de fichier, erreur) ; retourne l'erreur éventuelle."""
        source = self._source
        if source is not None and source.finished:
            self.error = source.error
            self.mode = "done" if self.mode == "file" and not source.error else "idle"
            self._source = None
        return self.error

    def _push(self, data: bytes, ts: float, linktype: int) -> None:
        if len(self._queue) >= self.cfg.queue_size:
            self.dropped += 1
        else:
            self._queue.append((data, ts, linktype))

    def _push_wait(self, data: bytes, ts: float, linktype: int) -> None:
        while len(self._queue) >= self.cfg.queue_size and not self._closed.is_set():
            time.sleep(0.002)
        self._queue.append((data, ts, linktype))

    # ------------------------------------------------------------ analyse

    def _analysis_loop(self) -> None:
        queue = self._queue
        while not self._closed.is_set():
            batch = [queue.popleft() for _ in range(min(BATCH, len(queue)))]
            if batch:
                parsed = [_core.parse(*frame) for frame in batch]   # hors verrou, GIL relâché
                with self.lock:
                    for pkt in parsed:
                        try:
                            self._ingest(pkt)
                        except Exception:   # un paquet pathologique ne doit jamais arrêter l'analyse
                            self.analysis_errors += 1
            else:
                time.sleep(0.002)
            if time.monotonic() >= self._next_tick:
                with self.lock:
                    self.stats.tick()
                self._next_tick += 1

    def process(self, data: bytes, ts: float, linktype: int = 1) -> Packet:
        """Analyse synchrone d'une trame (tests, outils)."""
        pkt = _core.parse(data, ts, linktype)
        with self.lock:
            self._ingest(pkt)
        return pkt

    def _ingest(self, pkt: Packet) -> None:
        self.last_packet_id += 1
        pkt.id = self.last_packet_id
        flow, created = self.flows.update(pkt)
        if flow is not None:
            self._reassemble_client_hello(pkt, flow)
        self.hosts.update(pkt)
        self.stats.add(pkt, flow if created else None)
        for finding in self.detector.process(pkt, flow):
            self.last_alert_id += 1
            alert = Alert(self.last_alert_id, pkt.ts, finding.severity, finding.category, finding.title, finding.detail,
                          pkt.src, pkt.dst, pkt.id, pkt.flow_id, finding.rule)
            self.alerts.append(alert)
            if self.store is not None:
                self.store.add_alert(alert)
            self.stats.alerts[finding.severity] += 1
            pkt.severity = max(pkt.severity, finding.severity)
        self.ring.append(pkt)

    def _reassemble_client_hello(self, pkt: Packet, flow: Flow) -> None:
        """ClientHello réparti sur plusieurs segments (fréquent avec les clés post-quantiques)."""
        pending = self._tls_pending
        if pkt.tls_partial:
            if len(pending) > 10_000:
                pending.clear()
            pending[flow.id] = pkt.payload
            return
        buffer = pending.get(flow.id)
        if buffer is None or not pkt.payload_len or not flow.is_client(pkt):
            return
        buffer += pkt.payload
        try:
            hello = _core.parse_client_hello(buffer)
        except ValueError:
            hello, buffer = None, b""
        if hello is None and 0 < len(buffer) < TLS_PENDING_LIMIT:
            pending[flow.id] = buffer
            return
        del pending[flow.id]
        if hello is not None:
            pkt.attach_client_hello(hello)
            flow.app, flow.label = "TLS", flow.label or hello.sni

    # ------------------------------------------------------------ lecture

    def packets_after(self, after_id: int, limit: int = 10_000) -> list[Packet]:
        with self.lock:
            return _tail(self.ring, self.last_packet_id, after_id, limit)

    def alerts_after(self, after_id: int, limit: int = 1_000) -> list[Alert]:
        with self.lock:
            return _tail(self.alerts, self.last_alert_id, after_id, limit)

    def get_packet(self, pid: int) -> Packet | None:
        with self.lock:
            if not self.ring:
                return None
            idx = pid - self.ring[0].id
            return self.ring[idx] if 0 <= idx < len(self.ring) else None

    def snapshot_packets(self) -> list[Packet]:
        with self.lock:
            return list(self.ring)

    def flow_packets(self, flow_id: int) -> list[Packet]:
        with self.lock:
            return [p for p in self.ring if p.flow_id == flow_id]

    def get_flow(self, flow_id: int) -> Flow | None:
        with self.lock:
            return self.flows.by_id.get(flow_id)

    def alert_history(self, since: float | None = None, until: float | None = None, min_severity: int = 0,
                      include_acked: bool = True, limit: int = 1000) -> list[Alert]:
        """Alertes filtrées, de la plus récente à la plus ancienne (base si présente, sinon mémoire)."""
        if self.store is not None:
            return self.store.alerts(since, until, min_severity, include_acked, limit)
        with self.lock:
            items = [a for a in reversed(self.alerts)
                     if a.severity >= min_severity and (include_acked or not a.acked)
                     and (since is None or a.ts >= since) and (until is None or a.ts < until)]
        return items[:limit]

    def alerts_for_packet(self, pid: int) -> list[Alert]:
        with self.lock:
            return [a for a in self.alerts if a.packet_id == pid]

    # ------------------------------------------------------------ tri des alertes

    def ack_alerts(self, ids: Iterable[int]) -> int:
        """Acquitte des alertes (en mémoire et en base) ; retourne le nombre d'alertes nouvellement acquittées."""
        wanted = set(ids)
        with self.lock:
            changed = 0
            for alert in self.alerts:
                if alert.id in wanted and not alert.acked:
                    alert.acked = True
                    changed += 1
        if self.store is not None:   # couvre aussi les alertes sorties de la mémoire
            return self.store.ack(wanted)
        return changed

    def allowlist(self) -> list[AllowEntry]:
        with self.lock:
            return list(self.rules.allow)

    def add_allow(self, rule: object = None, src: object = None, dst: object = None,
                  reason: object = "") -> tuple[AllowEntry, int]:
        """Ajoute une exception (lève RulesError si invalide) et acquitte les alertes en mémoire qu'elle couvre.

        Retourne l'exception et le nombre d'alertes acquittées.
        """
        entry = make_allow(0, rule, src, dst, reason, where="exception")
        entry_id = self.store.add_allow(entry) if self.store is not None else next(self._allow_ids)
        entry = replace(entry, id=entry_id)
        with self.lock:
            self.rules.add(entry)
            covered = [a.id for a in self.alerts if not a.acked and entry.matches(a.rule, a.src, a.dst)]
        return entry, self.ack_alerts(covered) if covered else 0

    def remove_allow(self, entry_id: int) -> bool:
        """Retire une exception créée depuis l'API (celles du fichier --rules ne se retirent que dans le fichier)."""
        with self.lock:
            removed = self.rules.remove(entry_id)
        if removed and self.store is not None:
            self.store.remove_allow(entry_id)
        return removed

    def conversation(self, flow_id: int) -> Conversation | None:
        """Conversation reconstituée, déchiffrée si TLS et si le keylog contient la session."""
        flow = self.get_flow(flow_id)
        if flow is None:
            return None
        packets = self.flow_packets(flow_id)
        conv = Conversation(flow, reassemble(flow, packets))
        if flow.app == "TLS" or any(p.proto == "TLS" for p in packets[:8]):
            if self.keylog is None:
                conv.note = "TLS chiffré - fournissez --tls-keylog pour déchiffrer"
            else:
                conv.plaintext, conv.note = decrypt_conversation(conv.chunks, self.keylog)
        return conv
