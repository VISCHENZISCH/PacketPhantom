@echo off
rem PacketPhantom - installation (Windows). Prerequis : Npcap (https://npcap.com) et Rust (https://rustup.rs).
cd /d "%~dp0"
where cargo >nul 2>nul || (echo [!] Rust est requis : installez-le depuis https://rustup.rs puis relancez. & pause & exit /b 1)
python -m venv .venv
.venv\Scripts\python -m pip install --upgrade pip
.venv\Scripts\python -m pip install -r requirements-dev.txt
set VIRTUAL_ENV=%~dp0.venv
.venv\Scripts\maturin develop --release
echo [+] Installation terminee. Lancez run.bat en tant qu Administrateur.
pause
