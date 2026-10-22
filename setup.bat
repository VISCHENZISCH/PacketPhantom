@echo off
echo [*] Installation de PacketPhantom (Windows)
echo [!] Npcap doit etre installe pour la capture : https://npcap.com
cd /d "%~dp0"
python -m venv .venv
.venv\Scripts\python -m pip install --upgrade pip
.venv\Scripts\python -m pip install -r requirements.txt
echo [+] Installation terminee. Lancez run.bat en tant qu Administrateur.
pause
