"""Géolocalisation non bloquante.

- offline : base MaxMind GeoLite2 (paquet `maxminddb`), aucune donnée ne sort.
- online  : API batch ip-api.com (100 IP / requête, limite gratuite respectée).
Seules les adresses publiques sont résolues ; le reste est marqué LAN.
"""
from __future__ import annotations

import os
import queue
import threading
import time
from dataclasses import dataclass
from pathlib import Path

from .hosts import classify

DB_CANDIDATES = (
    "GeoLite2-City.mmdb",
    "~/.local/share/GeoIP/GeoLite2-City.mmdb",
    "/usr/share/GeoIP/GeoLite2-City.mmdb",
    "/var/lib/GeoIP/GeoLite2-City.mmdb",
    "/usr/local/share/GeoIP/GeoLite2-City.mmdb",
)
ONLINE_URL = "http://ip-api.com/batch?fields=status,countryCode,country,city,continentCode,query&lang=fr"


@dataclass(frozen=True, slots=True)
class GeoInfo:
    country: str
    name: str
    city: str = ""
    continent: str = ""

    @property
    def short(self) -> str:
        return f"{self.country} · {self.city}" if self.city else self.country


LAN = GeoInfo("LAN", "Réseau local", "", "LAN")
UNKNOWN = GeoInfo("??", "Inconnu")


def find_database(path: str | None = None) -> str | None:
    candidates = [path] if path else [os.environ.get("PACKETPHANTOM_GEOIP_DB", ""), *DB_CANDIDATES]
    for candidate in candidates:
        if candidate and Path(candidate).expanduser().is_file():
            return str(Path(candidate).expanduser())
    return None


class GeoResolver:
    MIN_INTERVAL = 4.5  # 15 requêtes batch / minute max côté ip-api

    def __init__(self, mode: str = "auto", db_path: str | None = None):
        self._cache: dict[str, GeoInfo] = {}
        self._pending: set[str] = set()
        self._retry_after: dict[str, float] = {}
        self._queue: queue.Queue[str] = queue.Queue()
        self._reader = None
        self._stop = threading.Event()
        self.mode = "off"
        self.note = "désactivée"

        if mode in ("auto", "offline"):
            db = find_database(db_path)
            if db:
                try:
                    import maxminddb
                    self._reader = maxminddb.open_database(db)
                    self.mode, self.note = "offline", f"hors ligne ({Path(db).name})"
                except Exception as exc:
                    self.note = f"base illisible : {exc}"
            elif mode == "offline":
                self.note = "base GeoLite2 introuvable"
        if self.mode == "off" and mode in ("auto", "online"):
            self.mode, self.note = "online", "en ligne (ip-api.com)"
            threading.Thread(target=self._worker, name="geoip", daemon=True).start()

    def close(self) -> None:
        self._stop.set()

    def lookup(self, ip: str) -> GeoInfo | None:
        """Retourne l'info si connue ; sinon programme la résolution et retourne None."""
        info = self._cache.get(ip)
        if info is not None:
            return info
        kind = classify(ip)
        if kind != "global":
            info = LAN if kind == "private" else UNKNOWN
            self._cache[ip] = info
            return info
        if self.mode == "off":
            return UNKNOWN
        if self.mode == "offline":
            info = self._lookup_offline(ip)
            self._cache[ip] = info
            return info
        if self.mode == "online" and ip not in self._pending and time.time() >= self._retry_after.get(ip, 0):
            self._pending.add(ip)
            self._queue.put(ip)
        return None

    def _lookup_offline(self, ip: str) -> GeoInfo:
        try:
            data = self._reader.get(ip) or {}
        except Exception:
            return UNKNOWN
        country = data.get("country") or data.get("registered_country") or {}
        names = country.get("names", {})
        city = (data.get("city") or {}).get("names", {})
        return GeoInfo(
            country.get("iso_code", "??"),
            names.get("fr") or names.get("en", ""),
            city.get("fr") or city.get("en", ""),
            (data.get("continent") or {}).get("code", ""),
        )

    def _worker(self) -> None:
        import requests

        session = requests.Session()
        next_call = 0.0
        while not self._stop.is_set():
            try:
                batch = [self._queue.get(timeout=1.0)]
            except queue.Empty:
                continue
            while len(batch) < 100:
                try:
                    batch.append(self._queue.get_nowait())
                except queue.Empty:
                    break
            delay = next_call - time.time()
            if delay > 0:
                self._stop.wait(delay)
            next_call = time.time() + self.MIN_INTERVAL
            try:
                resp = session.post(ONLINE_URL, json=batch, timeout=5)
                if resp.status_code == 429:
                    next_call = time.time() + int(resp.headers.get("X-Ttl", "60"))
                    raise RuntimeError("limite de requêtes atteinte")
                remaining = int(resp.headers.get("X-Rl", "1"))
                if remaining <= 0:
                    next_call = time.time() + int(resp.headers.get("X-Ttl", "60"))
                for item in resp.json():
                    ip = item.get("query", "")
                    if item.get("status") == "success":
                        self._cache[ip] = GeoInfo(item.get("countryCode", "??"), item.get("country", ""),
                                                  item.get("city", ""), item.get("continentCode", ""))
                    else:
                        self._cache[ip] = UNKNOWN
                    self._pending.discard(ip)
            except Exception:
                retry = time.time() + 60
                for ip in batch:
                    self._pending.discard(ip)
                    self._retry_after[ip] = retry
