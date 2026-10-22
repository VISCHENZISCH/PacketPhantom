#!/usr/bin/env bash
# PacketPhantom - installation (Linux / macOS) : dépendances, compilation du cœur Rust, environnement Python.
set -euo pipefail
cd "$(dirname "$(readlink -f "$0")")"

if command -v apt-get >/dev/null; then
    sudo apt-get update -qq && sudo apt-get install -y libpcap0.8 python3-venv build-essential
elif command -v dnf >/dev/null; then
    sudo dnf install -y libpcap python3 gcc
elif command -v pacman >/dev/null; then
    sudo pacman -S --needed --noconfirm libpcap python base-devel
fi

if ! command -v cargo >/dev/null; then
    echo "[*] Installation de Rust (rustup)…"
    curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y --profile minimal
    # shellcheck disable=SC1091
    source "$HOME/.cargo/env"
fi

[ -d .venv ] || python3 -m venv .venv
.venv/bin/pip install -q --upgrade pip
.venv/bin/pip install -q -r requirements-dev.txt

echo "[*] Compilation du cœur Rust (release)…"
VIRTUAL_ENV="$PWD/.venv" .venv/bin/maturin develop --release -q

chmod +x run.sh
echo "[+] Installation terminée."
echo "    Capture live          : ./run.sh"
echo "    Avec tableau de bord  : ./run.sh --api"
echo "    Fichier               : ./run.sh -r capture.pcapng"
echo "    Tests                 : .venv/bin/python -m pytest"
