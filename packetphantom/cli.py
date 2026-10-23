"""Ligne de commande PacketPhantom."""
from __future__ import annotations

import argparse
import logging
import os
import sys

from . import __version__


def _endpoint(value: str) -> tuple[str, int]:
    host, _, port = value.rpartition(":")
    try:
        return host or "127.0.0.1", int(port)
    except ValueError as exc:
        raise argparse.ArgumentTypeError("format attendu : [HÔTE:]PORT") from exc


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="packetphantom",
        description="Analyseur réseau temps réel : cœur Rust, TUI, API REST, tableau de bord web et détection de menaces.",
    )
    source = p.add_argument_group("source")
    source.add_argument("-i", "--iface", help="interface de capture (défaut : interface de la route par défaut)")
    source.add_argument("-f", "--bpf", default="", help='filtre de capture BPF, ex. "tcp port 443"')
    source.add_argument("-r", "--read", metavar="FICHIER", help="analyser un fichier pcap/pcapng au lieu de capturer")
    source.add_argument("--realtime", action="store_true", help="avec -r : rejouer au rythme d'origine")
    source.add_argument("--no-start", action="store_true", help="ne pas démarrer la capture au lancement")

    analysis = p.add_argument_group("analyse")
    analysis.add_argument("-Y", "--display-filter", default="", help="filtre d'affichage initial, ex. \"tls or dns\"")
    analysis.add_argument("--tls-keylog", metavar="FICHIER", default=os.environ.get("SSLKEYLOGFILE"),
                          help="SSLKEYLOGFILE pour déchiffrer TLS 1.2/1.3 (défaut : $SSLKEYLOGFILE)")
    analysis.add_argument("--geo", choices=["auto", "offline", "online", "off"], default="auto",
                          help="géolocalisation : base GeoLite2 locale, API ip-api.com, ou désactivée")
    analysis.add_argument("--geoip-db", metavar="CHEMIN", help="chemin vers GeoLite2-City.mmdb")
    analysis.add_argument("--buffer", type=int, default=100_000, help="paquets conservés en mémoire (défaut : 100000)")
    analysis.add_argument("--rules", metavar="FICHIER", default=os.environ.get("PACKETPHANTOM_RULES"),
                          help="règles de détection TOML : seuils, règles désactivées, liste blanche "
                               "(défaut : $PACKETPHANTOM_RULES ; exemple : packaging/rules.example.toml)")

    storage = p.add_argument_group("persistance")
    storage.add_argument("--db", metavar="FICHIER", default=os.environ.get("PACKETPHANTOM_DB"),
                         help="base SQLite des alertes, acquittements et exceptions (défaut : $PACKETPHANTOM_DB, "
                              "sinon tout reste en mémoire)")
    storage.add_argument("--retention", metavar="JOURS", type=float, default=30.0,
                         help="durée de conservation des alertes en base, 0 = illimitée (défaut : 30)")

    output = p.add_argument_group("interfaces")
    output.add_argument("--headless", action="store_true", help="sans TUI : alertes NDJSON sur stdout (mode capteur)")
    output.add_argument("--api", metavar="[HÔTE:]PORT", type=_endpoint, nargs="?", const=("127.0.0.1", 8787),
                        help="active l'API REST et le tableau de bord web (défaut : 127.0.0.1:8787)")
    output.add_argument("--api-token", default=os.environ.get("PACKETPHANTOM_TOKEN"),
                        help="jeton d'API (défaut : $PACKETPHANTOM_TOKEN ou jeton aléatoire)")
    output.add_argument("--rows", type=int, default=3000, help="TUI : lignes affichées au maximum (défaut : 3000)")

    p.add_argument("-L", "--list-interfaces", action="store_true", help="lister les interfaces et quitter")
    p.add_argument("-V", "--version", action="version", version=f"PacketPhantom {__version__}")
    return p


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    logging.getLogger("scapy.runtime").setLevel(logging.ERROR)

    from .capture import CaptureError, list_interfaces
    if args.list_interfaces:
        print("\n".join(list_interfaces()))
        return 0

    from .filters import FilterError, compile_filter
    try:
        compile_filter(args.display_filter)
    except FilterError as exc:
        parser.error(f"filtre d'affichage invalide : {exc}")

    if args.retention < 0:
        parser.error("--retention : nombre de jours positif attendu")
    from .rules import RulesError, RuleSet
    try:
        rules = RuleSet.from_file(args.rules) if args.rules else None
    except RulesError as exc:
        parser.error(f"règles invalides : {exc}")

    from .engine import Engine, EngineConfig
    from .geoip import GeoResolver
    from .store import StoreError

    try:
        engine = Engine(EngineConfig(buffer=max(1000, args.buffer), keylog=args.tls_keylog, rules=rules,
                                     db=args.db, retention_days=args.retention))
    except StoreError as exc:
        print(f"packetphantom : {exc}", file=sys.stderr)
        return 1
    geo = GeoResolver(args.geo, args.geoip_db)
    api = None
    try:
        if args.api:
            from .api import Api
            api = Api(engine, geo, *args.api, token=args.api_token).start()
        if args.headless:
            from . import headless
            try:
                if args.read:
                    engine.start_file(args.read, args.realtime)
                elif not args.no_start:
                    engine.start_live(args.iface, args.bpf)
            except CaptureError as exc:
                print(f"packetphantom : {exc}", file=sys.stderr)
                return 1
            return headless.run(engine, geo, api)

        from .ui.app import PhantomApp
        PhantomApp(engine, geo, iface=args.iface, bpf=args.bpf, read=args.read, realtime=args.realtime,
                   autostart=not args.no_start, max_rows=max(100, args.rows),
                   display_filter=args.display_filter, api=api).run()
        return 0
    except OSError as exc:
        print(f"packetphantom : {exc}", file=sys.stderr)
        return 1
    finally:
        if api is not None:
            api.stop()
        engine.close()
        geo.close()
