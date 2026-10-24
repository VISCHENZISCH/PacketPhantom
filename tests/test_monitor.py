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
