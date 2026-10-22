import base64

import pytest
from scapy.layers import http
from scapy.layers.dns import DNS, DNSQR, DNSRR
from scapy.layers.inet import ICMP, IP, TCP, UDP
from scapy.layers.l2 import ARP, Ether
from scapy.layers.tls.extensions import (
    ServerName,
    TLS_Ext_ServerName,
    TLS_Ext_SupportedGroups,
    TLS_Ext_SupportedPointFormat,
)
from scapy.layers.tls.handshake import TLSClientHello
from scapy.layers.tls.record import TLS
from scapy.packet import Raw

from packetphantom.engine import Engine, EngineConfig

TS = 1_700_000_000.0
LINUX_SYN_OPTIONS = [("MSS", 1460), ("SAckOK", b""), ("Timestamp", (1, 0)), ("NOP", None), ("WScale", 7)]


@pytest.fixture
def engine():
    eng = Engine(EngineConfig(buffer=5000))
    yield eng
    eng.close()


def client_hello(sni: str = "example.com", ciphers=(0x0A0A, 0x1301, 0xC02F)) -> TLS:
    return TLS(msg=[TLSClientHello(version=0x0303, ciphers=list(ciphers), ext=[
        TLS_Ext_ServerName(servernames=[ServerName(servername=sni.encode())]),
        TLS_Ext_SupportedGroups(groups=[0x1A1A, 29, 23]),
        TLS_Ext_SupportedPointFormat(ecpl=[0]),
    ])])


class Frames:
    """Trames brutes de test (octets prêts pour le cœur Rust)."""

    @staticmethod
    def syn(src="10.0.0.5", dst="93.184.216.34", sport=40000, dport=443, ttl=64, options=None, window=64240):
        return bytes(Ether() / IP(src=src, dst=dst, ttl=ttl) /
                     TCP(sport=sport, dport=dport, flags="S", window=window,
                         options=LINUX_SYN_OPTIONS if options is None else options))

    @staticmethod
    def synack(src="93.184.216.34", dst="10.0.0.5", sport=443, dport=40000):
        return bytes(Ether() / IP(src=src, dst=dst, ttl=52) / TCP(sport=sport, dport=dport, flags="SA"))

    @staticmethod
    def ack(src="10.0.0.5", dst="93.184.216.34", sport=40000, dport=443):
        return bytes(Ether() / IP(src=src, dst=dst) / TCP(sport=sport, dport=dport, flags="A"))

    @staticmethod
    def tcp(payload: bytes, src="10.0.0.5", dst="10.0.0.9", sport=40000, dport=80, seq=1, flags="PA"):
        return bytes(Ether() / IP(src=src, dst=dst) / TCP(sport=sport, dport=dport, flags=flags, seq=seq) / Raw(payload))

    @staticmethod
    def http_get(path="/", host="example.com", headers=None, dport=80, body=b"", method=b"GET"):
        fields = dict(Method=method, Path=path.encode(), Host=host.encode(), User_Agent=b"pytest-agent")
        fields.update(headers or {})
        layer = http.HTTP() / http.HTTPRequest(**fields)
        if body:
            layer = layer / Raw(body)
        return bytes(Ether() / IP(src="10.0.0.5", dst="10.0.0.9") / TCP(sport=40001, dport=dport, flags="PA") / layer)

    @staticmethod
    def basic_auth(user="admin", pwd="secret"):
        token = base64.b64encode(f"{user}:{pwd}".encode())
        return Frames.http_get("/admin", headers={"Authorization": b"Basic " + token})

    @staticmethod
    def tls_client_hello(sni="example.com", dport=443):
        return bytes(Ether() / IP(src="10.0.0.5", dst="93.184.216.34") / TCP(sport=40002, dport=dport, flags="PA") /
                     client_hello(sni))

    @staticmethod
    def dns_query(qname="example.com", src="10.0.0.5"):
        return bytes(Ether() / IP(src=src, dst="1.1.1.1") / UDP(sport=33333, dport=53) / DNS(rd=1, qd=DNSQR(qname=qname)))

    @staticmethod
    def dns_answer(qname="example.com", ip="93.184.216.34"):
        return bytes(Ether() / IP(src="1.1.1.1", dst="10.0.0.5") / UDP(sport=53, dport=33333) /
                     DNS(qr=1, qd=DNSQR(qname=qname), an=DNSRR(rrname=qname, rdata=ip)))

    @staticmethod
    def arp_reply(ip="10.0.0.1", mac="aa:aa:aa:aa:aa:aa"):
        return bytes(Ether(src=mac) / ARP(op=2, psrc=ip, hwsrc=mac, pdst="10.0.0.5", hwdst="bb:bb:bb:bb:bb:bb"))

    @staticmethod
    def ping(size=56):
        return bytes(Ether() / IP(src="10.0.0.5", dst="8.8.8.8") / ICMP(type=8, id=1, seq=3) / Raw(b"x" * size))


@pytest.fixture
def frames():
    return Frames


def feed(engine: Engine, *frames: bytes, ts: float = TS):
    """Analyse synchrone ; retourne le dernier paquet."""
    pkt = None
    for i, data in enumerate(frames):
        pkt = engine.process(data, ts + i * 0.001)
    return pkt
