#!/usr/bin/env bash
# PacketPhantom - lanceur (Linux). Les arguments sont transmis, ex. : ./run.sh -i eth0 -f "tcp port 443"
cd "$(dirname "$(readlink -f "$0")")" || exit 1

PY=.venv/bin/python
if [ ! -x "$PY" ]; then
    echo "[!] Environnement absent : lancez d'abord ./setup.sh"
    exit 1
fi

# Lecture d'un fichier pcap ou liste des interfaces : pas besoin de root
for arg in "$@"; do
    case "$arg" in -r|--read|-L|--list-interfaces|-h|--help|-V|--version) exec "$PY" -m packetphantom "$@" ;; esac
done

if [ "$EUID" -ne 0 ] && ! getcap "$(readlink -f "$PY")" 2>/dev/null | grep -q cap_net_raw; then
    echo "[*] La capture réseau nécessite root (ou CAP_NET_RAW, voir README)."
    exec sudo "$PY" -m packetphantom "$@"
fi
exec "$PY" -m packetphantom "$@"
