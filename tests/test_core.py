"""Cœur Rust : décodage, types de lien, empreintes, robustesse."""
import hashlib
import random

import pytest
from scapy.layers.dhcp import BOOTP, DHCP
from scapy.layers.inet import IP, TCP, UDP
from scapy.layers.inet6 import ICMPv6EchoRequest, IPv6
from scapy.layers.l2 import CookedLinux, Dot1Q, Ether
from scapy.packet import Raw

from packetphantom import _core

from .conftest import TS, client_hello


def parse(data: bytes, linktype: int = 1):
    return _core.parse(data, TS, linktype)


def test_tcp_syn(frames):
    p = parse(frames.syn())
    assert (p.proto, p.l4, p.flags) == ("TCP", "TCP", "SYN")
    assert p.is_syn and not p.is_synack
    assert p.tcp_options == ["MSS", "SAckOK", "Timestamp", "NOP", "WScale"] and p.mss == 1460
    assert (p.src, p.dst, p.sport, p.dport, p.ttl) == ("10.0.0.5", "93.184.216.34", 40000, 443, 64)
    assert p.info == "40000 → 443 [SYN] Win=64240 Len=0"
    assert p.has("tcp") and p.has("IP") and p.has("ipv4") and p.has("eth") and not p.has("udp")


def test_http_request_any_port(frames):
    p = parse(frames.tcp(b"POST /x?a=1 HTTP/1.1\r\nHost: h:8080\r\nAuthorization: Basic abc\r\n\r\nbody=1", dport=9999))
    req = p.http_request
    assert p.proto == "HTTP" and p.domain == "h" and p.has("http")
    assert (req.method, req.path, req.version, req.host) == ("POST", "/x?a=1", "HTTP/1.1", "h:8080")
    assert req.header("AUTHORIZATION") == "Basic abc" and req.body == b"body=1"


def test_http_response(frames):
    p = parse(frames.tcp(b"HTTP/1.1 404 Not Found\r\nServer: nginx\r\nContent-Type: text/html; charset=utf-8\r\n\r\n",
                         src="10.0.0.9", dst="10.0.0.5", sport=80, dport=40000))
    assert p.http_response.code == 404
    assert p.info == "HTTP 404 Not Found  [text/html]  Server: nginx"


def test_dns_query_answer_and_compression(frames):
    q = parse(frames.dns_query("example.com"))
    assert (q.proto, q.info, q.domain) == ("DNS", "Requête A example.com", "example.com")
    a = parse(frames.dns_answer())
    assert a.dns.qr and a.dns.answers == [("example.com", "A", "93.184.216.34")]
    assert a.info == "Réponse A example.com → 93.184.216.34"


def test_tls_client_hello_ja3_ja4(frames):
    p = parse(frames.tls_client_hello("phantom.test", dport=8443))
    hello = p.tls_client
    assert p.proto == "TLS" and p.domain == "phantom.test" and p.has("tls")
    assert hello.ja3_full == "771,4865-49199,0-10-11,29-23,0"
    assert hello.ja3 == hashlib.md5(hello.ja3_full.encode()).hexdigest() == p.ja3
    # JA4 : t + version 12 + SNI d + 2 suites + 3 extensions + ALPN 00, hash suites triées, hash extensions sans SNI.
    ciphers = hashlib.sha256(b"1301,c02f").hexdigest()[:12]
    extensions = hashlib.sha256(b"000a,000b").hexdigest()[:12]
    assert hello.ja4 == f"t12d020300_{ciphers}_{extensions}" == p.ja4


def test_tls_fragmented_client_hello_is_flagged(frames):
    record = bytes(client_hello("long.example"))
    p = parse(frames.tcp(record[:30], dport=443))
    assert p.tls_partial and p.tls_client is None
    assert _core.parse_client_hello(record[:30]) is None
    assert _core.parse_client_hello(record).sni == "long.example"
    with pytest.raises(ValueError):
        _core.parse_client_hello(b"\x17\x03\x03\x00\x05hello")


def test_ssh_banner(frames):
    p = parse(frames.tcp(b"SSH-2.0-OpenSSH_9.6\r\n", src="10.0.0.9", dst="10.0.0.5", sport=22, dport=50000))
    assert (p.proto, p.banner, p.info) == ("SSH", "SSH-2.0-OpenSSH_9.6", "SSH-2.0-OpenSSH_9.6")


def test_arp(frames):
    p = parse(frames.arp_reply())
    assert (p.proto, p.src, p.arp.hwsrc) == ("ARP", "10.0.0.1", "aa:aa:aa:aa:aa:aa")
    assert p.info == "10.0.0.1 est à aa:aa:aa:aa:aa:aa"


def test_dhcp():
    data = bytes(Ether() / IP(src="0.0.0.0", dst="255.255.255.255") / UDP(sport=68, dport=67) /
                 BOOTP(chaddr=b"\x02\x00\x00\x00\x00\x01") /
                 DHCP(options=[("message-type", "request"), ("hostname", b"laptop"), ("requested_addr", "10.0.0.7"), "end"]))
    p = parse(data)
    assert (p.proto, p.dhcp.msg_type, p.dhcp.hostname, p.dhcp.requested) == ("DHCP", "Request", "laptop", "10.0.0.7")


ESC = "\x1b]52;c;cHduZWQ=\x07\x1b[2J"   # OSC 52 (presse-papiers) + effacement d'écran


def test_terminal_escapes_from_network_are_neutralised(frames):
    """Un ESC dans un nom DNS, un SNI, un en-tête ou un nom DHCP ne doit jamais atteindre le terminal de la TUI."""
    dhcp = bytes(Ether() / IP(src="0.0.0.0", dst="255.255.255.255") / UDP(sport=68, dport=67) /
                 BOOTP(chaddr=b"\x02\x00\x00\x00\x00\x01") / DHCP(options=[("hostname", f"pc{ESC}".encode()), "end"]))
    decoded = [
        parse(frames.dns_query(f"a{ESC}.example.com")).info,
        parse(frames.tls_client_hello(f"x{ESC}.test")).domain,
        parse(frames.tcp(f"GET /{ESC} HTTP/1.1\r\nHost: h\r\nUser-Agent: ua{ESC}\r\n\r\n".encode())).info,
        parse(frames.tcp(f"GET / HTTP/1.1\r\nUser-Agent: ua{ESC}\r\n\r\n".encode())).http_request.header("user-agent"),
        parse(dhcp).dhcp.hostname,
        parse(frames.tcp(f"SSH-2.0-{ESC}xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx\r\n".encode(),
                         src="10.0.0.9", dst="10.0.0.5", sport=22, dport=50000)).info,
    ]
    for text in decoded:
        assert "\x1b" not in text and "\x07" not in text, text
        assert "·" in text, text


def test_vlan_ipv6_and_icmpv6():
    p = parse(bytes(Ether() / Dot1Q(vlan=10) / IPv6(src="2001:db8::1", dst="2001:db8::2") / ICMPv6EchoRequest(id=7, seq=2)))
    assert (p.ip_version, p.src, p.proto) == (6, "2001:db8::1", "ICMPV6")
    assert p.info.startswith("Echo request  id=0x0007 seq=2")


@pytest.mark.parametrize("linktype, frame", [
    (113, lambda: bytes(CookedLinux(proto=0x0800) / IP(src="1.2.3.4", dst="5.6.7.8") / UDP(sport=1, dport=53))),
    (101, lambda: bytes(IP(src="1.2.3.4", dst="5.6.7.8") / TCP(sport=1, dport=2))),
    (228, lambda: bytes(IP(src="1.2.3.4", dst="5.6.7.8") / TCP(sport=1, dport=2))),
    (0, lambda: b"\x02\x00\x00\x00" + bytes(IP(src="1.2.3.4", dst="5.6.7.8") / TCP(sport=1, dport=2))),
])
def test_link_types(linktype, frame):
    p = parse(frame(), linktype)
    assert (p.src, p.dst) == ("1.2.3.4", "5.6.7.8")


def test_quic_and_services():
    p = parse(bytes(Ether() / IP() / UDP(sport=50000, dport=443) / Raw(b"\xc3\x00\x00\x00\x01" + bytes(40))))
    assert p.proto == "QUIC" and p.info.startswith("QUIC Initial  version=0x00000001")
    assert _core.service_name(3389) == "RDP" and _core.service_name(50000, 22) == "SSH"
    assert {"tls", "dns", "rdp", "quic"} <= set(_core.known_protocols())


def test_payload_and_data_roundtrip(frames):
    raw = frames.tcp(b"hello world", dport=7777)
    p = parse(raw)
    assert p.data == raw and p.payload == b"hello world" and p.payload_len == 11 and len(p) == len(raw)


def test_truncated_and_random_frames_never_crash(frames):
    """Robustesse : toutes les troncatures de trames réelles et 5 000 trames aléatoires."""
    samples = [frames.syn(), frames.http_get(), frames.tls_client_hello(), frames.dns_answer(), frames.arp_reply()]
    for sample in samples:
        for cut in range(len(sample)):
            parse(sample[:cut])
    rng = random.Random(7)
    for _ in range(5000):
        parse(bytes(rng.getrandbits(8) for _ in range(rng.randint(0, 200))), rng.choice([1, 101, 113, 276, 0]))
    bad = parse(b"\x00" * 10)
    assert bad.malformed and bad.info
