"""Monitoring : santé du capteur exposée par /api/monitor."""
import pytest
import requests

from packetphantom.api import Api
from packetphantom.engine import Engine, EngineConfig
from packetphantom.geoip import GeoResolver

from .conftest import feed


@pytest.fixture
def server(tmp_path, frames):
    engine = Engine(EngineConfig(buffer=1000, db=str(tmp_path / "pp.db")))
    feed(engine, frames.ping(), frames.basic_auth())
    api = Api(engine, GeoResolver("off"), port=0, token="t0ken").start()
    yield "http://{}:{}".format(*api.address), engine
    api.stop()
    engine.close()


def test_monitor_reports_pipeline_components_and_process(server):
    base, _ = server
    assert requests.get(base + "/api/monitor", timeout=5).status_code == 401
    m = requests.get(base + "/api/monitor", headers={"Authorization": "Bearer t0ken"}, timeout=5).json()

    pipeline = {p["key"]: p for p in m["pipeline"]}
    assert pipeline["buffer"] == {"key": "buffer", "label": "Paquets en mémoire", "used": 2, "capacity": 1000,
                                  "rotating": True}
    assert pipeline["queue"]["rotating"] is False and pipeline["alerts"]["used"] == 1

    components = m["components"]
    assert components["store"]["enabled"] and components["store"]["path"].endswith("pp.db")
    assert components["store"]["retention_days"] == 30
    assert components["geo"] == {"mode": "off", "note": "désactivée", "home": False}
    assert components["keylog"] == {"enabled": False} and components["rules"]["thresholds"]["scan_threshold"] == 20
    assert components["streams"] == 0

    process = m["process"]
    assert process["pid"] > 0 and process["threads"] >= 2 and process["uptime"] >= 0
    assert process["memory"] is None or process["memory"] > 0
    assert m["packets"] == 2 and len(m["pps"]) == len(m["bps"])   # champs de /api/status inclus

    losses = m["losses"]
    assert losses["dropped"] == 0 and losses["received"] == 2 and losses["last_drop"] is None
    assert losses["queue_capacity"] == 100_000 and len(losses["queue_history"]) == len(m["pps"])


def test_drops_are_timestamped_and_queue_sampled(frames):
    engine = Engine(EngineConfig(queue_size=1))
    engine.stop()
    engine._closed.set()          # analyse arrêtée : la file ne se vide plus
    engine._thread.join(timeout=5)
    engine._push(frames.ping(), 1.0, 1)
    engine._push(frames.ping(), 1.0, 1)   # file pleine : perdu
    assert engine.dropped == 1 and engine.last_drop is not None
    engine.stats.tick(engine.backlog)
    assert engine.stats.queue[-1] == 1 and engine.stats.queue_peak == 1
    engine.close()


def test_monitor_reports_machine_resources(server):
    base, _ = server
    auth = {"Authorization": "Bearer t0ken"}
    requests.get(base + "/api/monitor", headers=auth, timeout=5)   # premier échantillon CPU
    system = requests.get(base + "/api/monitor", headers=auth, timeout=5).json()["system"]
    assert set(system) == {"cpu", "memory", "gpu"}
    cpu = system["cpu"]
    assert cpu["cores"] >= 1 and cpu["process"] is not None and 0 <= cpu["process"] <= 100
    assert system["memory"]["total"] is None or system["memory"]["used"] <= system["memory"]["total"]
    assert system["gpu"] is None or {"vendor", "name", "util"} <= set(system["gpu"])


def test_system_parsers():
    from packetphantom.sysinfo import parse_meminfo, parse_nvidia, parse_proc_stat

    assert parse_proc_stat("cpu  100 0 50 800 50 0 0 0 0 0\ncpu0 1 2 3 4\n") == (850, 1000)
    assert parse_proc_stat("intr 1 2 3") is None
    meminfo = "MemTotal:       16000 kB\nMemFree: 1000 kB\nMemAvailable:    4000 kB\n"
    assert parse_meminfo(meminfo) == (12000 * 1024, 16000 * 1024)
    assert parse_meminfo("MemTotal: 16000 kB\n") is None
    assert parse_nvidia("NVIDIA GeForce RTX 3060, 37, 1024, 12288\n") == {
        "vendor": "NVIDIA", "name": "NVIDIA GeForce RTX 3060", "util": 37.0,
        "vram_used": 1024 * 1024 * 1024, "vram_total": 12288 * 1024 * 1024}
    assert parse_nvidia("No devices were found") is None
    assert parse_nvidia("GPU, N/A, 1, 2") is None
