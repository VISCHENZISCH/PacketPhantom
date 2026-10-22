@echo off
rem PacketPhantom - lanceur (Windows). A executer en tant qu Administrateur, Npcap requis.
cd /d "%~dp0"
.venv\Scripts\python -m packetphantom %*
