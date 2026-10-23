"""Configuration de la détection : seuils, règles désactivées, liste blanche.

Le fichier (option --rules) est en TOML et validé strictement : une clé inconnue est
une erreur, pour qu'une faute de frappe ne désactive jamais un réglage en silence.

    [thresholds]
    scan_threshold = 30

    [rules]
    disabled = ["dga"]

    [[allow]]
    rule = "port_scan"
    src = "10.0.0.0/24"
    reason = "scanner de vulnérabilités interne"
"""
from __future__ import annotations

import ipaddress
import sys
import time
from dataclasses import dataclass, field, fields, replace
from pathlib import Path

if sys.version_info >= (3, 11):
    import tomllib
else:   # pragma: no cover
    import tomli as tomllib

Network = ipaddress.IPv4Network | ipaddress.IPv6Network

# Identifiant stable de chaque règle → description (affichée dans l'API et le tableau de bord).
RULES = {
    "arp_spoof": "Usurpation ARP (changement de MAC)",
    "port_scan": "Scan de ports d'un hôte",
    "host_sweep": "Balayage d'un port sur plusieurs hôtes",
    "syn_flood": "SYN flood",
    "suspicious_port": "Connexion vers un port suspect",
    "http_basic": "Authentification HTTP Basic en clair",
    "http_bearer": "Jeton Bearer en HTTP",
    "http_form": "Mot de passe dans un formulaire HTTP",
    "clear_auth": "Identifiants FTP, POP3, IMAP, SMTP en clair",
    "icmp_tunnel": "ICMP volumineux (tunnel)",
    "secret": "Secret exposé (clé AWS, clé privée, jeton…)",
    "dns_tunnel": "Tunnel DNS",
    "dga": "Domaine à forte entropie (DGA)",
    "legacy_tls": "SSL 3.0, TLS 1.0 ou 1.1 proposé",
    "telnet": "Session Telnet",
}
MAX_REASON = 200


class RulesError(ValueError):
    """Configuration de détection invalide (message destiné à l'utilisateur)."""


@dataclass(frozen=True)
class Thresholds:
    scan_window: float = 10.0       # s : fenêtre d'observation des SYN
    scan_threshold: int = 20        # ports (scan) ou hôtes (balayage) distincts dans la fenêtre
    syn_flood_pps: int = 300        # SYN par seconde vers une même destination
    icmp_payload: int = 512         # octets de charge ICMP au-delà desquels on signale un tunnel
    dns_label_max: int = 50         # caractères d'un label DNS (tunnel)
    dns_name_max: int = 120         # caractères d'un nom DNS complet (tunnel)
    dga_min_label: int = 16         # longueur minimale d'un label évalué pour l'entropie
    dga_entropy: float = 3.7        # bits par caractère


def parse_network(value: object, key: str) -> Network:
    if not isinstance(value, str) or not value.strip():
        raise RulesError(f"{key} : adresse ou réseau attendu (ex. 10.0.0.5 ou 10.0.0.0/24)")
    try:
        return ipaddress.ip_network(value.strip(), strict=False)
    except ValueError as exc:
        raise RulesError(f"{key} : « {value} » n'est ni une adresse ni un réseau valide") from exc


def _address(value: str) -> ipaddress.IPv4Address | ipaddress.IPv6Address | None:
    try:
        return ipaddress.ip_address(value)
    except ValueError:
        return None


@dataclass(frozen=True)
class AllowEntry:
    """Exception : une alerte est ignorée si toutes les conditions renseignées correspondent.

    Les entrées du fichier ont un id négatif et ne se modifient que dans le fichier ;
    celles créées depuis l'API ont un id positif.
    """
    id: int
    rule: str | None = None
    src: Network | None = None
    dst: Network | None = None
    reason: str = ""
    created: float = 0.0

    @property
    def from_file(self) -> bool:
        return self.id < 0

    def matches(self, rule: str, src: str, dst: str) -> bool:
        if self.rule is not None and self.rule != rule:
            return False
        for network, value in ((self.src, src), (self.dst, dst)):
            if network is not None:
                address = _address(value)
                if address is None or address not in network:
                    return False
        return True

    def to_dict(self) -> dict:
        return {
            "id": self.id, "rule": self.rule, "src": str(self.src) if self.src else None,
            "dst": str(self.dst) if self.dst else None, "reason": self.reason, "created": self.created,
            "origin": "fichier" if self.from_file else "api",
        }


def make_allow(entry_id: int, rule: object = None, src: object = None, dst: object = None,
               reason: object = "", created: float | None = None, where: str = "allow") -> AllowEntry:
    """Construit et valide une exception (fichier, API ou base)."""
    if rule in ("", None):
        rule = None
    elif rule not in RULES:
        raise RulesError(f"{where}.rule : règle inconnue « {rule} » (connues : {', '.join(RULES)})")
    if reason is None:
        reason = ""
    if not isinstance(reason, str) or len(reason) > MAX_REASON:
        raise RulesError(f"{where}.reason : texte de {MAX_REASON} caractères au plus attendu")
    src_net = None if src in ("", None) else parse_network(src, f"{where}.src")
    dst_net = None if dst in ("", None) else parse_network(dst, f"{where}.dst")
    if rule is None and src_net is None and dst_net is None:
        raise RulesError(f"{where} : précisez au moins rule, src ou dst (une exception vide ignorerait tout)")
    return AllowEntry(entry_id, rule, src_net, dst_net, reason.strip(), time.time() if created is None else created)


@dataclass
class RuleSet:
    thresholds: Thresholds = field(default_factory=Thresholds)
    disabled: frozenset[str] = frozenset()
    allow: list[AllowEntry] = field(default_factory=list)

    @property
    def filtering(self) -> bool:
        """Faux tant qu'aucune règle n'est désactivée ni exemptée : le détecteur évite alors tout filtrage."""
        return bool(self.disabled or self.allow)

    def permits(self, rule: str, src: str, dst: str) -> bool:
        if rule in self.disabled:
            return False
        return not any(entry.matches(rule, src, dst) for entry in self.allow)

    def add(self, entry: AllowEntry) -> None:
        self.allow.append(entry)

    def remove(self, entry_id: int) -> bool:
        """Retire une exception créée depuis l'API ; celles du fichier restent."""
        for i, entry in enumerate(self.allow):
            if entry.id == entry_id and not entry.from_file:
                del self.allow[i]
                return True
        return False

    # ------------------------------------------------------------ lecture du fichier

    @classmethod
    def from_file(cls, path: str | Path) -> RuleSet:
        try:
            with open(path, "rb") as handle:
                data = tomllib.load(handle)
        except OSError as exc:
            raise RulesError(f"{path} : {exc.strerror or exc}") from exc
        except tomllib.TOMLDecodeError as exc:
            raise RulesError(f"{path} : TOML invalide ({exc})") from exc
        try:
            return cls.from_dict(data)
        except RulesError as exc:
            raise RulesError(f"{path} : {exc}") from exc

    @classmethod
    def from_dict(cls, data: dict) -> RuleSet:
        _only(data, {"thresholds", "rules", "allow"}, "")
        return cls(_thresholds(data.get("thresholds", {})), _disabled(data.get("rules", {})), _allow(data.get("allow", [])))


def _only(table: object, allowed: set[str], where: str) -> None:
    if not isinstance(table, dict):
        raise RulesError(f"{where or 'racine'} : table attendue")
    unknown = sorted(set(table) - allowed)
    if unknown:
        names = ", ".join(f"{where}.{k}" if where else k for k in unknown)
        raise RulesError(f"clé inconnue : {names} (attendues : {', '.join(sorted(allowed))})")


def _thresholds(table: object) -> Thresholds:
    defaults = Thresholds()
    known = {f.name: type(getattr(defaults, f.name)) for f in fields(Thresholds)}
    _only(table, set(known), "thresholds")
    values = {}
    for key, value in table.items():  # type: ignore[union-attr]
        kind = known[key]
        # bool est un int en Python : on le refuse explicitement.
        valid = not isinstance(value, bool) and (isinstance(value, int) if kind is int else isinstance(value, int | float))
        if not valid or value <= 0:
            raise RulesError(f"thresholds.{key} : nombre {'entier ' if kind is int else ''}strictement positif attendu")
        values[key] = kind(value)
    return replace(defaults, **values)


def _disabled(table: object) -> frozenset[str]:
    _only(table, {"disabled"}, "rules")
    names = table.get("disabled", [])  # type: ignore[union-attr]
    if not isinstance(names, list) or not all(isinstance(n, str) for n in names):
        raise RulesError("rules.disabled : liste d'identifiants de règles attendue")
    unknown = sorted(set(names) - set(RULES))
    if unknown:
        raise RulesError(f"rules.disabled : règle inconnue {', '.join(unknown)} (connues : {', '.join(RULES)})")
    return frozenset(names)


def _allow(entries: object) -> list[AllowEntry]:
    if not isinstance(entries, list):
        raise RulesError("allow : liste de tables [[allow]] attendue")
    result = []
    for i, entry in enumerate(entries, 1):
        where = f"allow[{i}]"
        _only(entry, {"rule", "src", "dst", "reason"}, where)
        result.append(make_allow(-i, entry.get("rule"), entry.get("src"), entry.get("dst"),
                                 entry.get("reason", ""), created=0.0, where=where))
    return result
