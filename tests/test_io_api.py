"""pcap / pcapng, API REST + SSE, mode headless."""
import io
import json
import time

import pytest
import requests
from scapy.layers.l2 import Ether
from scapy.utils import wrpcap, wrpcapng

from packetphantom import headless, pcapio
from packetphantom.api import Api
from packetphantom.engine import Engine, EngineConfig
from packetphantom.geoip import GeoResolver

from .conftest import feed


def scapy_frames(frames, count=3):
    pkts = [Ether(frames.ping()), Ether(frames.dns_query()), Ether(frames.basic_auth())][:count]
    for i, p in enumerate(pkts):
        p.time = 1_700_000_000.25 + i
    return pkts


@pytest.mark.parametrize("writer", [wrpcap, wrpcapng])
def test_read_pcap_and_pcapng(tmp_path, frames, writer):
    path = tmp_path / "capture.cap"
    pkts = scapy_frames(frames)
    writer(str(path), pkts)
    read = list(pcapio.read(path))
    assert [data for data, _, _ in read] == [bytes(p) for p in pkts]
    assert [lt for _, _, lt in read] == [1, 1, 1]
    assert abs(read[0][1] - 1_700_000_000.25) < 1e-5


def test_write_roundtrip(tmp_path, frames):
    original = [(frames.ping(), 1_700_000_000.5, 1), (frames.dns_query(), 1_700_000_001.0, 1), (b"x", 1.0, 101)]
    assert pcapio.write(tmp_path / "out.pcap", original) == 2   # type de lien différent ignoré
    assert [(d, round(t, 6), lt) for d, t, lt in pcapio.read(tmp_path / "out.pcap")] == original[:2]
    assert pcapio.dumps([]) == pcapio.dumps(iter([]))
    bad = tmp_path / "bad.pcap"
    bad.write_bytes(b"not a capture file at all")
    with pytest.raises(ValueError):
        list(pcapio.read(bad))


# ------------------------------------------------------------------ API

@pytest.fixture
def api(frames):
    engine = Engine(EngineConfig())
    feed(engine, frames.dns_query(), frames.syn(), frames.synack(), frames.basic_auth("admin", "pw"))
    server = Api(engine, GeoResolver("off"), port=0, token="t0ken").start()
    host, port = server.address
    yield f"http://{host}:{port}", engine
    server.stop()
    engine.close()


def get(base, path, **params):
    return requests.get(base + path, params=params, headers={"Authorization": "Bearer t0ken"}, timeout=5)


def test_api_requires_token(api):
    base, _ = api
    assert requests.get(base + "/api/status", timeout=5).status_code == 401
    assert requests.get(base + "/api/status", params={"token": "nope"}, timeout=5).status_code == 401
    page = requests.get(base + "/", timeout=5)
    assert page.status_code == 200 and "PacketPhantom" in page.text
    assert page.headers["Content-Security-Policy"].startswith("default-src 'self'")


def test_api_endpoints(api, tmp_path):
    base, engine = api
    status = get(base, "/api/status").json()
    assert status["packets"] == 4 and status["alerts"] == {"4": 1}

    packets = get(base, "/api/packets", filter="http").json()
    assert [p["proto"] for p in packets["items"]] == ["HTTP"]
    assert get(base, "/api/packets", filter="port ==").status_code == 400

    detail = get(base, "/api/packets/4").json()
    assert detail["application"]["type"] == "http_request"
    assert detail["layers"][0]["name"] == "Ethernet" and detail["alerts"][0]["severity"] == 4
    assert get(base, "/api/packets/999").status_code == 404

    flows = get(base, "/api/flows", sort="bytes").json()["items"]
    assert {f["app"] for f in flows} >= {"DNS", "HTTP"}
    conv = get(base, f"/api/flows/{flows[0]['id']}/conversation").json()
    assert set(conv) == {"flow", "decrypted", "note", "chunks"}

    assert get(base, "/api/hosts").json()["items"][0]["ip"]
    assert get(base, "/api/alerts", after=0).json()["items"][0]["title"] == "HTTP Basic : admin"
    analytics = get(base, "/api/analytics").json()
    assert analytics["protocols"] and analytics["encryption"] == {"encrypted": 0, "cleartext": 2, "other": 2}

    pcap = get(base, "/api/export.pcap", filter="dns")
    assert pcap.headers["Content-Type"] == "application/vnd.tcpdump.pcap"
    (tmp_path / "export.pcap").write_bytes(pcap.content)
    assert len(list(pcapio.read(tmp_path / "export.pcap"))) == 1


def test_api_capture_errors_and_events(api):
    base, engine = api
    response = requests.post(base + "/api/capture", json={"action": "start", "bpf": "tcp port 80x"},
                             headers={"Authorization": "Bearer t0ken"}, timeout=5)
    assert response.status_code == 409 and "BPF" in response.json()["error"]
    assert requests.post(base + "/api/capture", data="{", headers={"Authorization": "Bearer t0ken"},
                         timeout=5).status_code == 400

    with requests.get(base + "/api/events", params={"token": "t0ken"}, stream=True, timeout=5) as stream:
        lines = stream.iter_lines(decode_unicode=True)
        event = next(line for line in lines if line.startswith("event:"))
        payload = json.loads(next(lines)[len("data: "):])
    assert event == "event: status" and payload["packets"] == 4


# ------------------------------------------------------------------ headless

def test_headless_on_pcap_file(tmp_path, frames):
    path = tmp_path / "in.pcap"
    wrpcap(str(path), scapy_frames(frames))
    engine = Engine(EngineConfig())
    engine.start_file(str(path))
    out = io.StringIO()
    started = time.time()
    assert headless.run(engine, GeoResolver("off"), out=out) == 0
    engine.close()
    alerts = [json.loads(line) for line in out.getvalue().splitlines()]
    assert [a["title"] for a in alerts] == ["HTTP Basic : admin"] and time.time() - started < 5
