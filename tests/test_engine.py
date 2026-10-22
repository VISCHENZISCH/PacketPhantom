"""Moteur : flux, hôtes, réassemblage TLS, détection, filtres, curseurs."""
import time

from packetphantom.filters import FilterError, compile_filter

from .conftest import TS, client_hello, feed

# ------------------------------------------------------------------ flux & hôtes

def test_flow_is_bidirectional_and_counts(engine, frames):
    feed(engine, frames.syn(sport=41000), frames.synack(dport=41000), frames.ack(sport=41000))
    (flow,) = engine.flows.values()
    assert (flow.client, flow.server, flow.sport) == ("10.0.0.5", "93.184.216.34", 443)
    assert (flow.pkts_c2s, flow.pkts_s2c, flow.state) == (2, 1, "ESTABLISHED")


def test_hosts_os_services_and_passive_dns(engine, frames):
    feed(engine, frames.dns_answer("example.com", "93.184.216.34"), frames.syn(), frames.synack())
    local, remote = engine.hosts.get("10.0.0.5"), engine.hosts.get("93.184.216.34")
    assert local.os == "Linux" and local.os_conf >= 90
    assert "example.com" in remote.names and "TCP/443" in remote.services
    assert engine.stats.services["TCP/443 HTTPS"] == 1


def test_split_client_hello_is_reassembled(engine, frames):
    record = bytes(client_hello("split.example"))
    feed(engine, frames.tcp(record[:40], dport=443, seq=1), frames.tcp(record[40:], dport=443, seq=41))
    pkt = engine.get_packet(2)
    assert pkt.proto == "TLS" and pkt.domain == "split.example" and pkt.tls_client is not None
    assert engine.flows.values()[0].label == "split.example"


def test_cursors_and_monotonic_ids(engine, frames):
    feed(engine, frames.ping(), frames.ping(), frames.ping())
    assert [p.id for p in engine.packets_after(1)] == [2, 3]
    assert engine.get_packet(2).id == 2
    engine.reset()
    feed(engine, frames.ping())
    assert [p.id for p in engine.packets_after(3)] == [4]
    assert engine.stats.total == 1 and not engine.alerts


def test_conversation_dedupes_retransmissions(engine, frames):
    feed(engine, frames.tcp(b"GET / HTTP/1.1\r\n\r\n", seq=10), frames.tcp(b"GET / HTTP/1.1\r\n\r\n", seq=10),
         frames.tcp(b"HTTP/1.1 200 OK\r\n\r\nhello", src="10.0.0.9", dst="10.0.0.5", sport=80, dport=40000, seq=99))
    conv = engine.conversation(1)
    assert conv.chunks == [(True, b"GET / HTTP/1.1\r\n\r\n"), (False, b"HTTP/1.1 200 OK\r\n\r\nhello")]
    assert conv.plaintext is None and conv.note == ""


def test_tls_conversation_without_keylog_explains(engine, frames):
    feed(engine, frames.tls_client_hello())
    assert "--tls-keylog" in engine.conversation(1).note


def test_background_analysis_and_ticks(engine, frames):
    for _ in range(50):
        engine._push(frames.ping(), time.time(), 1)
    deadline = time.time() + 3
    while engine.stats.total < 50 and time.time() < deadline:
        time.sleep(0.01)
    assert engine.stats.total == 50 and engine.backlog == 0


# ------------------------------------------------------------------ détection

def titles(engine):
    return [a.title for a in engine.alerts]


def test_http_basic_credentials(engine, frames):
    pkt = feed(engine, frames.basic_auth("admin", "s3cr3t"))
    (alert,) = engine.alerts
    assert alert.severity == 4 and alert.title == "HTTP Basic : admin" and "s3cr3t" in alert.detail
    assert pkt.severity == 4 and engine.stats.alerts[4] == 1


def test_http_form_password(engine, frames):
    feed(engine, frames.http_get("/login", method=b"POST", body=b"username=bob&password=hunter2"))
    assert "formulaire" in titles(engine)[0] and "password=hunter2" in engine.alerts[0].detail


def test_cleartext_protocol_credentials(engine, frames):
    feed(engine, frames.tcp(b"USER alice\r\n", dport=21), frames.tcp(b"PASS wonderland\r\n", dport=21),
         frames.tcp(b"a1 LOGIN carol pw\r\n", dport=143, sport=40100))
    assert titles(engine) == ["FTP : alice", "IMAP : carol"]


def test_port_scan_is_deduplicated(engine, frames):
    feed(engine, *(frames.syn(src="10.0.0.66", dst="10.0.0.9", sport=50000 + p, dport=p) for p in range(1, 30)))
    assert [t for t in titles(engine) if "Scan de ports" in t] == ["Scan de ports depuis 10.0.0.66"]


def test_arp_spoofing(engine, frames):
    feed(engine, frames.arp_reply(mac="aa:aa:aa:aa:aa:aa"), frames.arp_reply(mac="66:66:66:66:66:66"))
    assert titles(engine) == ["Changement de MAC pour 10.0.0.1"]


def test_dns_tunnel_port_and_secret(engine, frames):
    feed(engine, frames.dns_query("a" * 60 + ".exfil.example.org"), frames.syn(dport=4444),
         frames.tcp(b"aws_key=AKIAABCDEFGHIJKLMNOP", dport=8000))
    found = " | ".join(titles(engine))
    assert "Tunnel DNS" in found and "4444" in found and "AWS" in found


def test_benign_traffic_has_no_alerts(engine, frames):
    feed(engine, frames.dns_query("www.google.com"), frames.tls_client_hello(), frames.http_get("/search?q=monkey+keyboard"))
    assert not engine.alerts


# ------------------------------------------------------------------ filtres

def test_filters(engine, frames):
    pkt = feed(engine, frames.tls_client_hello("mail.google.com"))
    cases = {
        "tls": True, "dns": False, "tcp and not udp": True, "tls or dns": True, "ipv4": True,
        "ip.dst == 93.184.216.34": True, "ip.addr == 93.184.0.0/16": True, "ip.src == 10.0.0.0/8": True,
        "ip.addr != 93.184.216.34": False, "tcp.port == 443": True, "udp.port == 443": False,
        "port 443": True, "host 10.0.0.5": True, "len > 50": True, "len < 10": False,
        'domain contains "google"': True, "sni ~ ^mail\\.": True, "tcp.port in {80 443}": True,
        "flow == 1": True, "(dns or tls) && port 443": True, '"mail.google"': True, "googl": True,
        "alert": False, f"ja4 == {pkt.ja4}": True,
    }
    for expr, expected in cases.items():
        assert compile_filter(expr)(pkt) is expected, expr
    assert compile_filter("  ") is None


def test_filter_errors():
    for bad in ("port ==", "len > abc", "(tcp", "ip.addr == 10.0.0.0/99", "info ~ (", "ip.src > 3"):
        try:
            compile_filter(bad)
        except FilterError:
            continue
        raise AssertionError(f"aucune erreur pour {bad!r}")


def test_alert_filter(engine, frames):
    pkt = feed(engine, frames.basic_auth())
    assert compile_filter("alert >= high")(pkt) and compile_filter("alert == critical")(pkt)
    assert pkt.ts >= TS
