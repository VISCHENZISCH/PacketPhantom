"""Moteur de détection : règles exécutées sur chaque paquet décodé.

Chaque règle produit des `Finding` ; les doublons sont limités par une
fenêtre de silence par clé. Seuils, règles désactivées et liste blanche
viennent d'un `RuleSet` (voir rules.py).
"""
from __future__ import annotations

import base64
import binascii
import math
import re
from collections import Counter, defaultdict, deque
from typing import NamedTuple
from urllib.parse import unquote_plus

from ._core import Packet
from .flows import Flow
from .rules import RuleSet

LOW, MEDIUM, HIGH, CRITICAL = 1, 2, 3, 4


class Finding(NamedTuple):
    rule: str           # identifiant stable (rules.RULES)
    severity: int
    category: str
    title: str
    detail: str


SUSPICIOUS_PORTS = {
    4444: "Metasploit (port par défaut)", 1337: "port « leet »", 31337: "Back Orifice / elite",
    6667: "IRC (canal C2 possible)", 6697: "IRC TLS (canal C2 possible)", 12345: "NetBus",
    9001: "Tor ORPort", 9050: "Tor SOCKS", 5555: "Android ADB exposé", 2323: "Telnet alternatif (botnets IoT)",
}
TLS_LEGACY = {0x0300: "SSL 3.0", 0x0301: "TLS 1.0", 0x0302: "TLS 1.1"}

_FORM_SECRET = re.compile(
    rb"(?:^|[&?;\s])((?:pass(?:word|wd)?|pwd|passphrase|secret|api[_-]?key|access[_-]?token|token)[\w\[\]-]{0,12})=([^&\s]{1,200})",
    re.I,
)
_FORM_USER = re.compile(rb"(?:^|[&?;\s])((?:user(?:name)?|login|email|uid|account)[\w\[\]-]{0,12})=([^&\s]{1,200})", re.I)
_SECRETS = {
    "Clé d'accès AWS": re.compile(rb"\b(?:AKIA|ASIA)[0-9A-Z]{16}\b"),
    "Clé privée": re.compile(rb"-----BEGIN (?:RSA |EC |DSA |OPENSSH |ENCRYPTED )?PRIVATE KEY-----"),
    "Jeton JWT": re.compile(rb"\beyJ[\w-]{8,}\.eyJ[\w-]{8,}\.[\w-]{8,}"),
    "Jeton GitHub": re.compile(rb"\bgh[pousr]_[A-Za-z0-9]{36}\b"),
    "Jeton Slack": re.compile(rb"\bxox[abprs]-[A-Za-z0-9-]{10,}"),
}
_CLEAR_AUTH_PORTS = {21: "FTP", 110: "POP3", 143: "IMAP", 25: "SMTP", 587: "SMTP", 119: "NNTP"}


def entropy(text: str) -> float:
    if not text:
        return 0.0
    n = len(text)
    return -sum(c / n * math.log2(c / n) for c in Counter(text).values())


def mask(secret: str, keep: int = 4) -> str:
    return "*" * len(secret) if len(secret) <= keep else secret[:keep] + "*" * min(12, len(secret) - keep)


def _b64(value: str) -> str:
    try:
        return base64.b64decode(value + "=" * (-len(value) % 4)).decode("utf-8", errors="replace")
    except (binascii.Error, ValueError):
        return ""


def _credentials(rule: str, service: str, user: str, password: str, pkt: Packet, where: str = "") -> Finding:
    return Finding(rule, CRITICAL, "Identifiants en clair", f"{service} : {user}",
                   f"{pkt.src} → {where or pkt.dst}\nutilisateur={user}  mot de passe={password}")


class Detector:
    def __init__(self, rules: RuleSet | None = None):
        self.rules = rules or RuleSet()
        self.limits = self.rules.thresholds
        self._silence: dict[tuple, float] = {}
        self._arp: dict[str, str] = {}
        self._syns: dict[str, deque] = defaultdict(lambda: deque(maxlen=2000))
        self._syn_rate: dict[str, list[int]] = {}
        self._clear_user: dict[int, str] = {}

    def _once(self, key: tuple, ts: float, window: float = 60.0) -> bool:
        last = self._silence.get(key)
        if last is not None and ts - last < window:
            return False
        if len(self._silence) > 50_000:
            self._silence.clear()
        self._silence[key] = ts
        return True

    # -------------------------------------------------------------- entrée

    def process(self, pkt: Packet, flow: Flow | None) -> list[Finding]:
        out = self._evaluate(pkt)
        if out and self.rules.filtering:
            out = [f for f in out if self.rules.permits(f.rule, pkt.src, pkt.dst)]
        return out

    def _evaluate(self, pkt: Packet) -> list[Finding]:
        out: list[Finding] = []
        arp = pkt.arp
        if arp is not None:
            self._arp_spoof(pkt, arp, out)
            return out
        if pkt.is_syn:
            self._scan(pkt, out)
            self._syn_flood(pkt, out)
            self._suspicious_port(pkt, out)
        if (request := pkt.http_request) is not None:
            self._http_credentials(pkt, request, out)
        if (dns := pkt.dns) is not None and not dns.qr:
            self._dns_anomaly(pkt, dns.qname, out)
        if (hello := pkt.tls_client) is not None:
            self._legacy_tls(pkt, hello, out)
        if pkt.payload_len and pkt.proto != "TLS":
            payload = pkt.payload
            if pkt.l4 == "TCP":
                self._clear_auth(pkt, payload, out)
            elif pkt.l4 == "ICMP" and len(payload) > self.limits.icmp_payload and self._once(("icmp", pkt.src), pkt.ts):
                out.append(Finding("icmp_tunnel", LOW, "Exfiltration", "ICMP volumineux (tunnel possible)",
                                   f"{len(payload)} octets de charge utile"))
            self._secrets(pkt, payload, out)
        if pkt.proto == "TELNET" and self._once(("telnet", pkt.flow_id), pkt.ts, 3600):
            out.append(Finding("telnet", MEDIUM, "Protocole en clair", "Session Telnet non chiffrée",
                               f"{pkt.src} → {pkt.dst}"))
        return out

    # -------------------------------------------------------------- règles

    def _arp_spoof(self, pkt: Packet, arp, out: list[Finding]) -> None:
        ip, mac = arp.psrc, arp.hwsrc
        if not ip or ip == "0.0.0.0":
            return
        known = self._arp.get(ip)
        self._arp[ip] = mac
        if known and known != mac and self._once(("arp", ip, mac), pkt.ts, 30):
            out.append(Finding("arp_spoof", HIGH, "Usurpation ARP", f"Changement de MAC pour {ip}",
                               f"{ip} était {known}, annoncé maintenant par {mac} (ARP spoofing / MITM ?)"))

    def _scan(self, pkt: Packet, out: list[Finding]) -> None:
        if len(self._syns) > 20_000 and pkt.src not in self._syns:
            self._syns.clear()
        window = self._syns[pkt.src]
        window.append((pkt.ts, pkt.dst, pkt.dport))
        span, threshold = self.limits.scan_window, self.limits.scan_threshold
        while window and pkt.ts - window[0][0] > span:
            window.popleft()
        ports = {port for _, host, port in window if host == pkt.dst}
        if len(ports) >= threshold and self._once(("vscan", pkt.src, pkt.dst), pkt.ts):
            out.append(Finding("port_scan", HIGH, "Reconnaissance", f"Scan de ports depuis {pkt.src}",
                               f"{len(ports)} ports de {pkt.dst} sondés en moins de {span:g} s"))
        hosts = {host for _, host, port in window if port == pkt.dport}
        if len(hosts) >= threshold and self._once(("hscan", pkt.src, pkt.dport), pkt.ts):
            out.append(Finding("host_sweep", HIGH, "Reconnaissance", f"Balayage réseau depuis {pkt.src}",
                               f"{len(hosts)} hôtes sondés sur le port {pkt.dport} en moins de {span:g} s"))

    def _syn_flood(self, pkt: Packet, out: list[Finding]) -> None:
        second = int(pkt.ts)
        slot = self._syn_rate.get(pkt.dst)
        if slot is None or slot[0] != second:
            if len(self._syn_rate) > 10_000:
                self._syn_rate.clear()
            self._syn_rate[pkt.dst] = [second, 1]
            return
        slot[1] += 1
        if slot[1] == self.limits.syn_flood_pps and self._once(("synflood", pkt.dst), pkt.ts, 30):
            out.append(Finding("syn_flood", CRITICAL, "Déni de service", f"SYN flood vers {pkt.dst}",
                               f"Plus de {self.limits.syn_flood_pps} SYN/s vers {pkt.dst}"))

    def _suspicious_port(self, pkt: Packet, out: list[Finding]) -> None:
        reason = SUSPICIOUS_PORTS.get(pkt.dport)
        if reason and self._once(("port", pkt.src, pkt.dst, pkt.dport), pkt.ts, 300):
            out.append(Finding("suspicious_port", MEDIUM, "Port suspect", f"Connexion vers le port {pkt.dport}",
                               f"{pkt.src} → {pkt.dst}:{pkt.dport} - {reason}"))

    def _http_credentials(self, pkt: Packet, request, out: list[Finding]) -> None:
        where = f"{request.host or pkt.dst}{request.path.partition('?')[0]}"
        scheme, _, value = (request.header("authorization") or "").partition(" ")
        if scheme.lower() == "basic" and value:
            user, _, password = _b64(value.strip()).partition(":")
            if self._once(("basic", pkt.src, pkt.dst, user, password), pkt.ts, 600):
                out.append(_credentials("http_basic", "HTTP Basic", user, password, pkt, where))
        elif scheme.lower() == "bearer" and value and self._once(("bearer", pkt.src, pkt.dst), pkt.ts, 600):
            out.append(Finding("http_bearer", HIGH, "Identifiants en clair", "Jeton Bearer transmis en HTTP",
                               f"{pkt.src} → {where}\njeton={mask(value.strip(), 10)}"))

        query = request.path.partition("?")[2].encode("latin-1", errors="ignore")
        for blob in (request.body[:65_536], query):
            secrets = _FORM_SECRET.findall(blob)
            if not secrets:
                continue
            fields = [f"{unquote_plus(k.decode('latin-1'))}={unquote_plus(v.decode('latin-1'))}"
                      for k, v in _FORM_USER.findall(blob) + secrets]
            if self._once(("form", pkt.src, pkt.dst, tuple(fields)), pkt.ts, 600):
                out.append(Finding("http_form", CRITICAL, "Identifiants en clair",
                                   f"Mot de passe dans un formulaire HTTP ({request.method})",
                                   f"{pkt.src} → {where}\n" + "\n".join(fields)))
            return

    def _clear_auth(self, pkt: Packet, payload: bytes, out: list[Finding]) -> None:
        service = _CLEAR_AUTH_PORTS.get(pkt.dport)
        if not service or len(payload) > 1024:
            return
        line = payload.split(b"\r\n", 1)[0].decode("latin-1", errors="replace")
        command, _, argument = line.partition(" ")
        command = command.upper()
        if command == "USER":
            if len(self._clear_user) > 10_000:
                self._clear_user.clear()
            self._clear_user[pkt.flow_id] = argument.strip()
        elif command == "PASS":
            out.append(_credentials("clear_auth", service, self._clear_user.get(pkt.flow_id, "?"), argument.strip(), pkt))
        elif command == "AUTH" and argument.upper().startswith("PLAIN "):
            parts = _b64(argument[6:].strip()).split("\x00")
            if len(parts) == 3:
                out.append(_credentials("clear_auth", f"{service} AUTH PLAIN", parts[1], parts[2], pkt))
        elif service == "IMAP" and argument.upper().startswith("LOGIN "):
            words = argument.split()
            if len(words) >= 3:
                out.append(_credentials("clear_auth", "IMAP", words[1], words[2], pkt))

    def _secrets(self, pkt: Packet, payload: bytes, out: list[Finding]) -> None:
        sample = payload[:65_536]
        for label, pattern in _SECRETS.items():
            match = pattern.search(sample)
            if match and self._once(("secret", label, pkt.flow_id), pkt.ts, 600):
                out.append(Finding("secret", HIGH, "Secret exposé", f"{label} transmis en clair",
                                   f"{pkt.src} → {pkt.dst}  ({pkt.proto})\n{mask(match.group(0).decode('latin-1'), 8)}"))

    def _dns_anomaly(self, pkt: Packet, qname: str, out: list[Finding]) -> None:
        if not qname or qname.endswith((".local", ".arpa")):
            return
        labels = qname.split(".")
        longest = max(labels, key=len)
        base = ".".join(labels[-2:])
        limits = self.limits
        if ((len(longest) > limits.dns_label_max or len(qname) > limits.dns_name_max)
                and self._once(("dnstun", pkt.src, base), pkt.ts, 300)):
            out.append(Finding("dns_tunnel", MEDIUM, "Exfiltration", f"Tunnel DNS possible vers {base}",
                               f"{pkt.src} a demandé {qname} ({len(qname)} car., label de {len(longest)} car.)"))
        elif (len(longest) >= limits.dga_min_label and (bits := entropy(longest)) > limits.dga_entropy
              and self._once(("dga", pkt.src, base), pkt.ts, 300)):
            out.append(Finding("dga", LOW, "Domaine suspect", f"Domaine à forte entropie : {qname}",
                               f"Entropie {bits:.2f} bits/car. - DGA ou sous-domaine aléatoire ?"))

    def _legacy_tls(self, pkt: Packet, hello, out: list[Finding]) -> None:
        name = TLS_LEGACY.get(hello.version)
        if name and self._once(("oldtls", pkt.src, pkt.dst), pkt.ts, 3600):
            out.append(Finding("legacy_tls", LOW, "Chiffrement faible", f"{name} proposé",
                               f"{pkt.src} → {hello.sni or pkt.dst}"))
