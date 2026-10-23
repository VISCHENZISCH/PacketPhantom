"""Règles configurables (seuils, désactivation, liste blanche) et persistance SQLite."""
import io
import json
import os
import sqlite3
import time

import pytest
import requests
from scapy.layers.l2 import Ether
from scapy.utils import wrpcap

from packetphantom import headless
from packetphantom.api import Api
from packetphantom.engine import Engine, EngineConfig
from packetphantom.geoip import GeoResolver
from packetphantom.model import Alert
from packetphantom.rules import RulesError, RuleSet
from packetphantom.store import Store, StoreError

from .conftest import TS, feed


def rules(**data) -> RuleSet:
    return RuleSet.from_dict(data)


def scan(frames, count: int, src: str = "10.0.0.66") -> list[bytes]:
    return [frames.syn(src=src, dst="10.0.0.9", sport=50000 + i, dport=1000 + i) for i in range(count)]


# ------------------------------------------------------------------ fichier de règles

def test_rules_file_is_loaded(tmp_path):
    path = tmp_path / "rules.toml"
    path.write_text("""
[thresholds]
scan_threshold = 5
scan_window = 2.5

[rules]
disabled = ["dga"]

[[allow]]
rule = "port_scan"
src = "10.0.0.0/24"
reason = "scanner interne"
""", encoding="utf-8")
    loaded = RuleSet.from_file(path)
    assert loaded.thresholds.scan_threshold == 5 and loaded.thresholds.scan_window == 2.5
    assert loaded.disabled == {"dga"}
    entry = loaded.allow[0]
    assert entry.id < 0 and entry.from_file and str(entry.src) == "10.0.0.0/24"
    assert entry.matches("port_scan", "10.0.0.7", "8.8.8.8")
    assert not entry.matches("port_scan", "10.0.1.7", "8.8.8.8") and not entry.matches("dga", "10.0.0.7", "x")


@pytest.mark.parametrize(("data", "message"), [
    ({"thresholds": {"scan_treshold": 5}}, "thresholds.scan_treshold"),
    ({"thresholds": {"scan_threshold": True}}, "entier"),
    ({"thresholds": {"scan_threshold": 2.5}}, "entier"),
    ({"thresholds": {"dga_entropy": -1}}, "positif"),
    ({"rules": {"disabled": ["nope"]}}, "règle inconnue nope"),
    ({"rules": {"disabled": "dga"}}, "liste"),
    ({"allow": [{"reason": "tout"}]}, "au moins"),
    ({"allow": [{"src": "10.0.0.300"}]}, "ni une adresse"),
    ({"allow": [{"rule": "port_scan", "port": 22}]}, r"allow\[1\]\.port"),
    ({"extra": {}}, "clé inconnue : extra"),
])
def test_invalid_rules_are_rejected(data, message):
    with pytest.raises(RulesError, match=message):
        RuleSet.from_dict(data)


def test_unreadable_rules_file(tmp_path):
    bad = tmp_path / "bad.toml"
    bad.write_text("[thresholds\n", encoding="utf-8")
    with pytest.raises(RulesError, match="TOML invalide"):
        RuleSet.from_file(bad)
    with pytest.raises(RulesError, match="absent.toml"):
        RuleSet.from_file(tmp_path / "absent.toml")


# ------------------------------------------------------------------ détection

def test_thresholds_and_disabled_rules(frames):
    engine = Engine(EngineConfig(rules=rules(thresholds={"scan_threshold": 5})))
    feed(engine, *scan(frames, 5))
    assert [(a.rule, a.title) for a in engine.alerts] == [("port_scan", "Scan de ports depuis 10.0.0.66")]
    engine.close()

    engine = Engine(EngineConfig(rules=rules(thresholds={"scan_threshold": 5}, rules={"disabled": ["port_scan"]})))
    feed(engine, *scan(frames, 30))
    assert not engine.alerts
    engine.close()


def test_allowlist_matches_rule_and_network(frames):
    allow = [{"rule": "port_scan", "src": "10.0.0.0/25"}]
    engine = Engine(EngineConfig(rules=rules(thresholds={"scan_threshold": 5}, allow=allow)))
    feed(engine, *scan(frames, 5, src="10.0.0.66"))           # dans le réseau exempté
    feed(engine, frames.basic_auth())                          # autre règle : toujours signalée
    feed(engine, *scan(frames, 5, src="10.0.0.200"))          # hors du réseau
    assert [(a.rule, a.src) for a in engine.alerts] == [("http_basic", "10.0.0.5"), ("port_scan", "10.0.0.200")]
    engine.close()


def test_runtime_allow_acks_covered_alerts_and_can_be_removed(engine, frames):
    feed(engine, frames.basic_auth("alice", "a"), frames.basic_auth("bob", "b"))
    assert engine.ack_alerts([1]) == 1 and engine.ack_alerts([1]) == 0

    entry, acked = engine.add_allow(rule="http_basic", src="10.0.0.5", reason="labo")
    assert entry.id == 1 and acked == 1 and all(a.acked for a in engine.alerts)
    feed(engine, frames.basic_auth("carol", "c"))
    assert len(engine.alerts) == 2                              # exemptée

    with pytest.raises(RulesError):
        engine.add_allow(reason="sans condition")
    assert engine.remove_allow(entry.id) and not engine.remove_allow(entry.id)
    feed(engine, frames.basic_auth("dave", "d"))
    assert engine.alerts[-1].title == "HTTP Basic : dave" and not engine.alerts[-1].acked


def test_alert_history_from_memory(engine, frames):
    feed(engine, frames.dns_query("a" * 60 + ".example.com"), frames.basic_auth())
    assert [a.rule for a in engine.alert_history()] == ["http_basic", "dns_tunnel"]
    assert [a.rule for a in engine.alert_history(min_severity=4)] == ["http_basic"]
    engine.ack_alerts([2])
    assert [a.rule for a in engine.alert_history(include_acked=False)] == ["dns_tunnel"]


# ------------------------------------------------------------------ persistance

def test_store_survives_restart(tmp_path, frames):
    db = tmp_path / "pp.db"
    engine = Engine(EngineConfig(db=str(db)))
    feed(engine, frames.basic_auth("alice", "a"), frames.basic_auth("bob", "b"))
    assert engine.ack_alerts([1]) == 1                          # acquittée alors qu'encore en tampon
    entry, _ = engine.add_allow(rule="dga", dst="1.1.1.1", reason="résolveur interne")
    engine.close()
    if os.name == "posix":
        assert db.stat().st_mode & 0o777 == 0o600

    engine = Engine(EngineConfig(db=str(db)))
    assert [(a.id, a.title, a.acked, a.rule) for a in engine.alerts] == [
        (1, "HTTP Basic : alice", True, "http_basic"), (2, "HTTP Basic : bob", False, "http_basic")]
    assert [e.to_dict()["dst"] for e in engine.allowlist()] == ["1.1.1.1/32"]
    feed(engine, frames.basic_auth("carol", "c"))
    assert engine.last_alert_id == 3                            # les identifiants reprennent
    assert engine.remove_allow(entry.id)
    engine.close()

    engine = Engine(EngineConfig(db=str(db)))
    assert engine.allowlist() == [] and [a.id for a in engine.alert_history(include_acked=False)] == [3, 2]
    engine.close()


def test_headless_does_not_replay_stored_alerts(tmp_path, frames):
    db, pcap = tmp_path / "pp.db", tmp_path / "in.pcap"
    wrpcap(str(pcap), [Ether(frames.basic_auth("alice", "a"))])
    outputs = []
    for _ in range(2):
        engine = Engine(EngineConfig(db=str(db)))
        engine.start_file(str(pcap))
        out = io.StringIO()
        assert headless.run(engine, GeoResolver("off"), out=out) == 0
        engine.close()
        outputs.append([json.loads(line)["id"] for line in out.getvalue().splitlines()])
    assert outputs == [[1], [2]]


def test_store_retention_and_schema_guard(tmp_path):
    db = tmp_path / "pp.db"
    store = Store(db, retention_days=7)
    store.add_alert(Alert(1, TS, 2, "c", "ancienne", rule="dga"))      # paquet ancien, enregistré à l'instant
    store.add_alert(Alert(2, TS, 4, "c", "récente", rule="http_basic"))
    store.close()
    with sqlite3.connect(db) as conn:
        conn.execute("UPDATE alerts SET stored = ? WHERE id = 1", (time.time() - 10 * 86_400,))

    store = Store(db, retention_days=7)                         # purge au démarrage, selon l'enregistrement
    assert [a.title for a in store.alerts()] == ["récente"]
    store.close()

    with sqlite3.connect(db) as conn:
        conn.execute("PRAGMA user_version = 99")
    with pytest.raises(StoreError, match="plus récente"):
        Store(db)


def test_store_rejects_unusable_path(tmp_path):
    with pytest.raises(StoreError):
        Store(tmp_path / "absent" / "pp.db")


# ------------------------------------------------------------------ API

@pytest.fixture
def api(frames):
    engine = Engine(EngineConfig())
    feed(engine, frames.basic_auth("alice", "a"), frames.basic_auth("bob", "b"), ts=TS)
    server = Api(engine, GeoResolver("off"), port=0, token="t0ken").start()
    host, port = server.address
    yield f"http://{host}:{port}", engine
    server.stop()
    engine.close()


def call(method, base, path, **kwargs):
    return requests.request(method, base + path, headers={"Authorization": "Bearer t0ken"}, timeout=5, **kwargs)


def test_api_ack_and_history(api):
    base, _ = api
    assert call("POST", base, "/api/alerts/ack", json={"ids": [1]}).json() == {"acked": 1}
    for bad in ({"ids": "1"}, {"ids": [True]}, {"ids": [0]}, {}):
        assert call("POST", base, "/api/alerts/ack", json=bad).status_code == 400
    history = call("GET", base, "/api/alerts/history", params={"acked": "0"}).json()
    assert [a["title"] for a in history["items"]] == ["HTTP Basic : bob"] and history["persistent"] is False
    assert call("GET", base, "/api/alerts/history", params={"since": "hier"}).status_code == 400
    status = call("GET", base, "/api/status").json()
    assert status["unacked"] == 1 and status["persistent"] is False


def test_api_allowlist(api):
    base, _ = api
    created = call("POST", base, "/api/allowlist", json={"rule": "http_basic", "src": "10.0.0.5", "reason": "labo"})
    assert created.status_code == 200 and created.json()["acked"] == 2
    entry = created.json()["entry"]
    assert entry["src"] == "10.0.0.5/32" and entry["origin"] == "api"

    listing = call("GET", base, "/api/allowlist").json()
    assert [e["id"] for e in listing["items"]] == [entry["id"]] and "port_scan" in listing["rules"]
    assert call("POST", base, "/api/allowlist", json={"rule": "nope"}).status_code == 400
    assert call("POST", base, "/api/allowlist", json={"reason": "x" * 300, "src": "10.0.0.1"}).status_code == 400

    assert call("DELETE", base, f"/api/allowlist/{entry['id']}").json() == {"removed": entry["id"]}
    assert call("DELETE", base, f"/api/allowlist/{entry['id']}").status_code == 404
    assert requests.delete(base + "/api/allowlist/1", timeout=5).status_code == 401
