"""Persistance SQLite : alertes (avec acquittement) et exceptions de la liste blanche.

- Le thread d'analyse ne fait qu'ajouter les alertes à un tampon en mémoire ; un thread
  dédié les écrit par lots, dans une transaction : l'analyse n'attend jamais le disque.
- Le fichier est créé en 0600 : les alertes peuvent contenir des identifiants capturés en clair.
- La rétention compte depuis l'enregistrement (colonne `stored`), pas depuis l'heure du paquet :
  les alertes d'un vieux fichier pcap ne sont pas purgées dès leur écriture.
- Une seule connexion, protégée par un verrou ; toutes les requêtes sont paramétrées.
"""
from __future__ import annotations

import os
import sqlite3
import sys
import threading
import time
from collections.abc import Iterable
from pathlib import Path

from .model import Alert
from .rules import AllowEntry, RulesError, make_allow

SCHEMA_VERSION = 1
FLUSH_INTERVAL = 0.5        # s entre deux écritures groupées
PURGE_INTERVAL = 3600.0     # s entre deux purges de rétention
MAX_PENDING = 100_000       # alertes en attente d'écriture au-delà desquelles on abandonne (disque bloqué)

_ALERT_COLUMNS = "id, ts, severity, category, title, detail, src, dst, packet_id, flow_id, rule, acked"
_SCHEMA = f"""
BEGIN;
CREATE TABLE IF NOT EXISTS alerts (
    id INTEGER PRIMARY KEY,
    ts REAL NOT NULL,
    severity INTEGER NOT NULL,
    category TEXT NOT NULL,
    title TEXT NOT NULL,
    detail TEXT NOT NULL,
    src TEXT NOT NULL,
    dst TEXT NOT NULL,
    packet_id INTEGER NOT NULL,
    flow_id INTEGER NOT NULL,
    rule TEXT NOT NULL,
    acked INTEGER NOT NULL DEFAULT 0,
    stored REAL NOT NULL
);
CREATE INDEX IF NOT EXISTS alerts_ts ON alerts (ts);
CREATE INDEX IF NOT EXISTS alerts_stored ON alerts (stored);
CREATE TABLE IF NOT EXISTS allowlist (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    rule TEXT,
    src TEXT,
    dst TEXT,
    reason TEXT NOT NULL,
    created REAL NOT NULL
);
PRAGMA user_version = {SCHEMA_VERSION};
COMMIT;
"""


class StoreError(Exception):
    """Base inutilisable (message destiné à l'utilisateur)."""


def _create_private(path: Path) -> None:
    """Crée le fichier en 0600 sans suivre de lien symbolique, et resserre les droits d'une base existante."""
    flags = os.O_CREAT | os.O_RDWR | getattr(os, "O_NOFOLLOW", 0)
    try:
        os.close(os.open(path, flags, 0o600))
        if os.name == "posix":
            os.chmod(path, 0o600)
    except OSError as exc:
        raise StoreError(f"{path} : {exc.strerror or exc}") from exc


def _row_to_alert(row: tuple) -> Alert:
    *head, acked = row
    return Alert(*head, acked=bool(acked))


class Store:
    def __init__(self, path: str | Path, retention_days: float = 30.0):
        self.path = Path(path)
        self.retention = retention_days * 86_400   # 0 : conservation illimitée
        self.dropped = 0
        self.error: str | None = None
        _create_private(self.path)
        try:
            self._db = sqlite3.connect(self.path, check_same_thread=False)
        except sqlite3.Error as exc:
            raise StoreError(f"{self.path} : {exc}") from exc
        self._lock = threading.Lock()            # connexion
        self._pending: list[tuple] = []
        self._pending_lock = threading.Lock()    # tampon (pris par le thread d'analyse : jamais d'E/S dessous)
        self._stop = threading.Event()
        try:
            self._migrate()
            self.purge()
        except sqlite3.DatabaseError as exc:
            self._db.close()
            raise StoreError(f"{self.path} : base illisible ({exc})") from exc
        self._thread = threading.Thread(target=self._writer, name="store", daemon=True)
        self._thread.start()

    def _migrate(self) -> None:
        version = self._db.execute("PRAGMA user_version").fetchone()[0]
        if version > SCHEMA_VERSION:
            raise StoreError(f"{self.path} : base créée par une version plus récente de PacketPhantom")
        self._db.execute("PRAGMA journal_mode = WAL")
        self._db.execute("PRAGMA synchronous = NORMAL")
        if version < SCHEMA_VERSION:
            self._db.executescript(_SCHEMA)

    # ------------------------------------------------------------ alertes

    def add_alert(self, a: Alert) -> None:
        row = (a.id, a.ts, a.severity, a.category, a.title, a.detail, a.src, a.dst, a.packet_id, a.flow_id,
               a.rule, int(a.acked), time.time())
        with self._pending_lock:
            if len(self._pending) >= MAX_PENDING:
                self.dropped += 1
            else:
                self._pending.append(row)

    def flush(self) -> None:
        with self._pending_lock:
            rows, self._pending = self._pending, []
        if not rows:
            return
        try:
            with self._lock, self._db:
                self._db.executemany(f"INSERT OR IGNORE INTO alerts ({_ALERT_COLUMNS}, stored) "
                                     f"VALUES ({', '.join('?' * 13)})", rows)
        except sqlite3.Error:
            with self._pending_lock:   # nouvel essai au prochain tour, dans la limite du tampon
                kept = rows[: max(0, MAX_PENDING - len(self._pending))]
                self._pending[:0] = kept
                self.dropped += len(rows) - len(kept)
            raise

    def last_alert_id(self) -> int:
        with self._lock:
            return self._db.execute("SELECT coalesce(max(id), 0) FROM alerts").fetchone()[0]

    def recent_alerts(self, limit: int) -> list[Alert]:
        """Les `limit` dernières alertes, de la plus ancienne à la plus récente."""
        with self._lock:
            rows = self._db.execute(f"SELECT {_ALERT_COLUMNS} FROM alerts ORDER BY id DESC LIMIT ?", (limit,)).fetchall()
        return [_row_to_alert(r) for r in reversed(rows)]

    def alerts(self, since: float | None = None, until: float | None = None, min_severity: int = 0,
               include_acked: bool = True, limit: int = 1000) -> list[Alert]:
        """Historique filtré, du plus récent au plus ancien."""
        self.flush()
        clauses, params = ["severity >= ?"], [min_severity]
        if since is not None:
            clauses.append("ts >= ?")
            params.append(since)
        if until is not None:
            clauses.append("ts < ?")
            params.append(until)
        if not include_acked:
            clauses.append("acked = 0")
        query = f"SELECT {_ALERT_COLUMNS} FROM alerts WHERE {' AND '.join(clauses)} ORDER BY id DESC LIMIT ?"
        with self._lock:
            rows = self._db.execute(query, (*params, limit)).fetchall()
        return [_row_to_alert(r) for r in rows]

    def ack(self, ids: Iterable[int]) -> int:
        """Acquitte des alertes ; retourne le nombre d'alertes qui ne l'étaient pas encore."""
        self.flush()   # une alerte encore en tampon doit pouvoir être acquittée
        with self._lock, self._db:
            cursor = self._db.executemany("UPDATE alerts SET acked = 1 WHERE id = ? AND acked = 0", ((i,) for i in ids))
            return cursor.rowcount

    def purge(self) -> int:
        if not self.retention:
            return 0
        with self._lock, self._db:
            return self._db.execute("DELETE FROM alerts WHERE stored < ?", (time.time() - self.retention,)).rowcount

    # ------------------------------------------------------------ liste blanche

    def add_allow(self, entry: AllowEntry) -> int:
        with self._lock, self._db:
            cursor = self._db.execute(
                "INSERT INTO allowlist (rule, src, dst, reason, created) VALUES (?, ?, ?, ?, ?)",
                (entry.rule, str(entry.src) if entry.src else None, str(entry.dst) if entry.dst else None,
                 entry.reason, entry.created))
            return int(cursor.lastrowid)

    def remove_allow(self, entry_id: int) -> bool:
        with self._lock, self._db:
            return self._db.execute("DELETE FROM allowlist WHERE id = ?", (entry_id,)).rowcount > 0

    def allow_entries(self) -> list[AllowEntry]:
        with self._lock:
            rows = self._db.execute("SELECT id, rule, src, dst, reason, created FROM allowlist ORDER BY id").fetchall()
        entries = []
        for entry_id, rule, src, dst, reason, created in rows:
            try:
                entries.append(make_allow(entry_id, rule, src, dst, reason, created, where=f"allowlist #{entry_id}"))
            except RulesError as exc:   # règle retirée dans une version ultérieure : on l'ignore sans bloquer
                print(f"[packetphantom] exception ignorée : {exc}", file=sys.stderr)
        return entries

    # ------------------------------------------------------------ cycle de vie

    def _writer(self) -> None:
        next_purge = time.monotonic() + PURGE_INTERVAL
        while not self._stop.wait(FLUSH_INTERVAL):
            try:
                self.flush()
                if time.monotonic() >= next_purge:
                    self.purge()
                    next_purge = time.monotonic() + PURGE_INTERVAL
                self.error = None
            except sqlite3.Error as exc:   # disque plein, base verrouillée… : on réessaie au prochain tour
                self.error = f"Base {self.path.name} : {exc}"

    def close(self) -> None:
        self._stop.set()
        self._thread.join(timeout=5)
        try:
            self.flush()
        finally:
            self._db.close()
