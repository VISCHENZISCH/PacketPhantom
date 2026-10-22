"""Langage de filtre d'affichage (inspiré de Wireshark).

Exemples :
    dns or tls
    ip.addr == 10.0.0.0/8 and not port 53
    tcp.port == 443 && len > 1000
    domain contains "google"
    info ~ "(?i)login|passwd"
    alert >= high
    "texte libre"           (recherche plein texte)

Opérateurs : == != > < >= <= contains ~ (regex) in {a b c}
Logique    : and/&& or/|| not/! et parenthèses.
"""
from __future__ import annotations

import ipaddress
import re
from collections.abc import Callable

from ._core import Packet, known_protocols

KNOWN_PROTOCOLS = set(known_protocols()) | {"malformed"}

Predicate = Callable[[Packet], bool]


class FilterError(ValueError):
    pass


def _ports(r):
    return [p for p in (r.sport, r.dport) if p is not None]


FIELDS: dict[str, Callable[[Packet], list]] = {
    "ip.src": lambda r: [r.src], "src": lambda r: [r.src],
    "ip.dst": lambda r: [r.dst], "dst": lambda r: [r.dst],
    "ip.addr": lambda r: [r.src, r.dst], "addr": lambda r: [r.src, r.dst], "host": lambda r: [r.src, r.dst],
    "port": _ports,
    "tcp.port": lambda r: _ports(r) if r.l4 == "TCP" else [],
    "udp.port": lambda r: _ports(r) if r.l4 == "UDP" else [],
    "sport": lambda r: [r.sport], "tcp.srcport": lambda r: [r.sport] if r.l4 == "TCP" else [],
    "dport": lambda r: [r.dport], "tcp.dstport": lambda r: [r.dport] if r.l4 == "TCP" else [],
    "udp.srcport": lambda r: [r.sport] if r.l4 == "UDP" else [],
    "udp.dstport": lambda r: [r.dport] if r.l4 == "UDP" else [],
    "proto": lambda r: [r.proto.lower(), r.l4.lower()],
    "len": lambda r: [r.length], "frame.len": lambda r: [r.length],
    "frame": lambda r: [r.id], "no": lambda r: [r.id], "id": lambda r: [r.id],
    "ttl": lambda r: [r.ttl], "ip.ttl": lambda r: [r.ttl],
    "flow": lambda r: [r.flow_id], "stream": lambda r: [r.flow_id], "tcp.stream": lambda r: [r.flow_id],
    "flags": lambda r: [r.flags], "tcp.flags": lambda r: [r.flags],
    "info": lambda r: [r.info],
    "domain": lambda r: [r.domain], "sni": lambda r: [r.domain] if r.proto == "TLS" else [],
    "tls.sni": lambda r: [r.domain] if r.proto == "TLS" else [],
    "http.host": lambda r: [r.domain] if r.proto == "HTTP" else [],
    "dns.qry": lambda r: [r.domain] if r.proto in ("DNS", "MDNS", "LLMNR") else [],
    "ja3": lambda r: [r.ja3], "ja4": lambda r: [r.ja4],
    "eth.src": lambda r: [r.smac], "eth.dst": lambda r: [r.dmac], "eth.addr": lambda r: [r.smac, r.dmac],
    "mac": lambda r: [r.smac, r.dmac],
    "alert": lambda r: [r.severity],
}
NUMERIC = {"port", "tcp.port", "udp.port", "sport", "dport", "tcp.srcport", "tcp.dstport", "udp.srcport",
           "udp.dstport", "len", "frame.len", "frame", "no", "id", "ttl", "ip.ttl", "flow", "stream",
           "tcp.stream", "alert"}
SEVERITY_WORDS = {"info": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}
OPERATORS = {"==", "!=", ">", "<", ">=", "<=", "contains", "~", "matches", "in", "eq", "ne", "gt", "lt", "ge", "le"}
OP_ALIASES = {"eq": "==", "ne": "!=", "gt": ">", "lt": "<", "ge": ">=", "le": "<=", "matches": "~"}
# Raccourcis « BPF-like » : port 53, host 1.2.3.4
SHORTHAND = {"port", "host", "src", "dst"}

_TOKEN = re.compile(r"""\s*(?:
    (?P<op>==|!=|>=|<=|&&|\|\||[()<>!{}])
  | "(?P<dq>[^"]*)"
  | '(?P<sq>[^']*)'
  | (?P<word>[^\s()<>=!{}"'&|]+)
)""", re.X)


def tokenize(text: str) -> list[tuple[str, str]]:
    tokens, pos = [], 0
    text = text.strip()
    while pos < len(text):
        m = _TOKEN.match(text, pos)
        if not m or m.end() == pos:
            raise FilterError(f"Caractère inattendu à la position {pos + 1} : {text[pos]!r}")
        pos = m.end()
        if m.group("op"):
            tokens.append(("op", m.group("op")))
        elif m.group("dq") is not None:
            tokens.append(("str", m.group("dq")))
        elif m.group("sq") is not None:
            tokens.append(("str", m.group("sq")))
        else:
            tokens.append(("word", m.group("word")))
    return tokens


def _full_text(r: Packet) -> str:
    fields = (r.id, r.src, r.dst, r.proto, r.sport, r.dport, r.flags, r.info, r.domain, r.smac, r.ja3, r.ja4)
    return " ".join(map(str, fields)).lower()


class _Parser:
    def __init__(self, tokens):
        self.tokens = tokens
        self.i = 0

    def peek(self):
        return self.tokens[self.i] if self.i < len(self.tokens) else (None, None)

    def take(self):
        tok = self.peek()
        self.i += 1
        return tok

    def parse(self) -> Predicate:
        pred = self.parse_or()
        if self.i != len(self.tokens):
            raise FilterError(f"Élément inattendu : {self.peek()[1]!r}")
        return pred

    def parse_or(self) -> Predicate:
        left = self.parse_and()
        while self.peek()[1] in ("or", "||"):
            self.take()
            right = self.parse_and()
            left = (lambda a, b: lambda r: a(r) or b(r))(left, right)
        return left

    def parse_and(self) -> Predicate:
        left = self.parse_not()
        while self.peek()[1] in ("and", "&&"):
            self.take()
            right = self.parse_not()
            left = (lambda a, b: lambda r: a(r) and b(r))(left, right)
        return left

    def parse_not(self) -> Predicate:
        if self.peek()[1] in ("not", "!"):
            self.take()
            inner = self.parse_not()
            return lambda r: not inner(r)
        return self.parse_atom()

    def parse_atom(self) -> Predicate:
        kind, value = self.take()
        if kind is None:
            raise FilterError("Expression incomplète")
        if value == "(" and kind == "op":
            pred = self.parse_or()
            if self.take()[1] != ")":
                raise FilterError("Parenthèse fermante manquante")
            return pred
        if kind == "str":
            needle = value.lower()
            return lambda r: needle in _full_text(r)
        if kind != "word":
            raise FilterError(f"Élément inattendu : {value!r}")

        name = value.lower()
        nxt_kind, nxt = self.peek()
        if name in FIELDS and nxt is not None and (nxt in OPERATORS or nxt.lower() in OPERATORS):
            op = self.take()[1].lower()
            return self.comparison(name, OP_ALIASES.get(op, op))
        if name in SHORTHAND and nxt_kind in ("word", "str"):
            # « port 443 » ou « host 10.0.0.1 »
            return self.comparison({"port": "port", "host": "ip.addr", "src": "ip.src", "dst": "ip.dst"}[name], "==")
        if name in FIELDS and (nxt is None or nxt in (")", "and", "or", "&&", "||")):
            getter = FIELDS[name]
            return lambda r: any(v not in (None, "", 0, -1) for v in getter(r))
        if name in KNOWN_PROTOCOLS:
            return lambda r: r.has(name)
        # Mot inconnu : recherche plein texte
        return lambda r: name in _full_text(r)

    def _value(self, field: str):
        kind, value = self.take()
        if kind not in ("word", "str"):
            raise FilterError(f"Valeur attendue après {field}")
        return value

    def comparison(self, field: str, op: str) -> Predicate:
        getter = FIELDS[field]
        if op == "in":
            if self.take()[1] != "{":
                raise FilterError("Syntaxe : champ in {v1 v2 …}")
            values = []
            while self.peek()[1] != "}":
                if self.peek()[0] is None:
                    raise FilterError("Accolade fermante manquante")
                values.append(self._value(field))
            self.take()
            preds = [self._match(field, getter, "==", v) for v in values]
            return lambda r: any(p(r) for p in preds)
        return self._match(field, getter, op, self._value(field))

    def _match(self, field: str, getter, op: str, raw: str) -> Predicate:
        if op in ("contains", "~"):
            if op == "~":
                try:
                    rx = re.compile(raw)
                except re.error as exc:
                    raise FilterError(f"Regex invalide : {exc}") from exc
                return lambda r: any(v is not None and rx.search(str(v)) for v in getter(r))
            needle = raw.lower()
            return lambda r: any(v is not None and needle in str(v).lower() for v in getter(r))

        if field in NUMERIC:
            if field == "alert" and raw.lower() in SEVERITY_WORDS:
                target = SEVERITY_WORDS[raw.lower()]
            else:
                try:
                    target = int(raw, 0)
                except ValueError as exc:
                    raise FilterError(f"{field} attend un nombre (reçu {raw!r})") from exc
            cmp = {
                "==": lambda v: v == target, "!=": lambda v: v != target,
                ">": lambda v: v > target, "<": lambda v: v < target,
                ">=": lambda v: v >= target, "<=": lambda v: v <= target,
            }[op]
            if op == "!=":
                return lambda r: all(v is None or cmp(v) for v in getter(r))
            return lambda r: any(v is not None and cmp(v) for v in getter(r))

        if op not in ("==", "!="):
            raise FilterError(f"L'opérateur {op} n'est pas valable pour {field}")
        if field in ("ip.src", "ip.dst", "ip.addr", "addr", "host", "src", "dst") and "/" in raw:
            try:
                net = ipaddress.ip_network(raw, strict=False)
            except ValueError as exc:
                raise FilterError(f"Réseau invalide : {raw}") from exc

            def in_net(v):
                try:
                    return ipaddress.ip_address(v) in net
                except ValueError:
                    return False
            eq = lambda r: any(v and in_net(v) for v in getter(r))  # noqa: E731
        elif field == "proto":
            target = raw.lower()
            eq = lambda r: target in getter(r)  # noqa: E731
        else:
            target = raw.lower()
            eq = lambda r: any(v is not None and str(v).lower() == target for v in getter(r))  # noqa: E731
        if op == "!=":
            return lambda r: not eq(r)
        return eq


def compile_filter(text: str) -> Predicate | None:
    """Compile une expression ; None si vide. Lève FilterError si invalide."""
    if not text or not text.strip():
        return None
    return _Parser(tokenize(text)).parse()
