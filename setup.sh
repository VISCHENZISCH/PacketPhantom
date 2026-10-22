#!/usr/bin/env bash
# PacketPhantom - installation (Linux)
set -e
cd "$(dirname "$(readlink -f "$0")")"

echo "[*] Dépendances système (libpcap, venv)…"
if command -v apt-get >/dev/null; then
    sudo apt-get update -qq && sudo apt-get install -y libpcap0.8 python3-venv
elif command -v dnf >/dev/null; then
    sudo dnf install -y libpcap python3
elif command -v pacman >/dev/null; then
    sudo pacman -S --needed --noconfirm libpcap python
fi

if [ ! -d .venv ]; then
    echo "[*] Création de l'environnement virtuel…"
    python3 -m venv .venv
fi

echo "[*] Dépendances Python…"
.venv/bin/pip install -q --upgrade pip
.venv/bin/pip install -q -r requirements.txt

chmod +x run.sh
echo "[+] Installation terminée."
echo "    Lancer   : ./run.sh            (capture live, demande sudo)"
echo "    Fichier  : ./run.sh -r capture.pcap"
echo "    Aide     : ./run.sh --help"
