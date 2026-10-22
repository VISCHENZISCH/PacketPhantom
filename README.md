# PacketPhantom 2

Analyseur réseau temps réel pour le terminal. Il dissèque le trafic comme un sniffeur classique, mais il pense aussi comme un analyste SOC : il reconstruit les conversations, inventorie les hôtes, prend les empreintes TLS et OS, et lève des alertes (identifiants en clair, scans, usurpation ARP, tunnels DNS…) pendant la capture.

```
◆ PACKETPHANTOM  ● CAPTURE  ⌁ wlo1  BPF aucun                        GeoIP hors ligne   21:49:10
┌ PAQUETS ───┐┌ PAQUETS / S ┐┌ DÉBIT ──────┐┌ FLUX ──┐┌ HÔTES ──┐┌ ALERTES ─────────┐
│ 3 789 1.6 Mo││ 106 ▂▅▃▇█▆ ││ 419 Kb/s ▃▆█ ││ 798    ││ 15 6 LAN││ 4  1 crit. 2 élev.│
 Paquets │ Flux │ Hôtes │ Alertes │ Analyse
 No.   Heure         Source          Destination     Proto  Long.  Info
 1465  21:48:34.513  192.168.1.42    192.168.1.5     HTTP    186   GET /admin/  (nas.local)
 ▼ Trame 1465        │ Flux #294 HTTP 192.168.1.42:51000 → 192.168.1.5:80 ESTABLISHED
   ▼ Ethernet        │ ▲ HTTP Basic : admin   utilisateur=admin  mot de passe=…
   ▼ IP              │ 0000  20 0b 74 91 0e 5b ...  │ ..t..[
 FILTRE  tls and ip.addr == 10.0.0.0/8                                 3 000 / 3 789 paquets
```

## Fonctionnalités

**Analyse de paquets**
- Dissection Scapy avec un résumé façon Wireshark : TCP (drapeaux, fenêtre), DNS (requêtes et réponses), HTTP (sur n'importe quel port), TLS (SNI, version, ALPN), DHCP, ARP, ICMP, QUIC, bannières SSH/FTP/SMTP/POP/IMAP, plus une cinquantaine de services reconnus par leur port.
- Panneau de détail en trois volets : arborescence des couches, hexdump, et une synthèse d'analyse (flux, hôtes, géolocalisation, JA3, alertes liées au paquet).
- **Filtre d'affichage** inspiré de Wireshark, validé pendant la frappe : `tls and ip.addr == 10.0.0.0/8`, `domain contains "google"`, `alert >= high`…
- **Filtre de capture BPF**, validé avant application.
- **Suivi de flux** (TCP/UDP) : la conversation est reconstituée en ASCII ou en hexadécimal, avec les retransmissions supprimées et le client et le serveur colorés différemment. La conversation est exportable en binaire.

**Analyse SOC (ce qu'un sniffeur classique ne fait pas d'emblée)**
- **Table des flux** : conversations bidirectionnelles avec état TCP, volumes dans chaque sens, durée, application et domaine.
- **Inventaire des hôtes** : MAC, OS passif (signature SYN façon p0f, avec un indice de confiance), noms appris par DNS passif, SNI, Host HTTP et DHCP, services exposés, User-Agents, nombre de pairs et géolocalisation.
- **Empreintes TLS JA3 / JA3S** (les valeurs GREASE sont ignorées).
- **Moteur de détection** en temps réel, avec dédoublonnage et notifications :

| Règle | Sévérité |
|---|---|
| Identifiants HTTP Basic, formulaires contenant un mot de passe, FTP/POP3 `USER`/`PASS`, IMAP `LOGIN`, `AUTH PLAIN` | Critique |
| SYN flood (> 300 SYN/s vers une cible) | Critique |
| Scan de ports vertical ou balayage horizontal (≥ 20 cibles en 10 s) | Élevée |
| Usurpation ARP (une IP change de MAC) | Élevée |
| Jeton Bearer en HTTP ; secrets en clair (clés AWS, clés privées, JWT, jetons GitHub ou Slack) | Élevée |
| Tunnel DNS (labels ou noms anormalement longs), ports suspects (4444, 31337, Tor, IRC…), session Telnet | Moyenne |
| Domaine à forte entropie (DGA), TLS obsolète (≤ 1.1), ICMP volumineux | Faible |

- **Pivot** : la touche Entrée sur un flux, un hôte ou une alerte ouvre les paquets correspondants, déjà filtrés.
- **Onglet Analyse** : débit et paquets/s sur 120 s, répartition des protocoles, hôtes les plus actifs, domaines, services contactés et pays.
- **Exports** : PCAP (paquets affichés ou tout le tampon), CSV (paquets, flux), NDJSON (hôtes, alertes). Lancés via sudo, les fichiers sont rendus à l'utilisateur d'origine.
- **Lecture de fichiers pcap/pcapng**, avec relecture optionnelle au rythme d'origine.
- Thèmes sombre et clair, interface entièrement au clavier.

### Et par rapport à Wireshark ?

PacketPhantom ne remplace pas Wireshark pour la dissection : Wireshark décode des milliers de protocoles, déchiffre TLS avec les clés de session et tient plusieurs centaines de milliers de paquets par seconde. PacketPhantom vise un autre usage : la **surveillance et le triage en direct depuis un terminal** (SSH, serveur sans interface graphique). Il fournit nativement ce qu'il faudrait assembler dans Wireshark avec des plugins ou d'autres outils : alertes, inventaire des hôtes, DNS passif, empreintes OS et JA3, et pivots en une touche.

Débit mesuré : environ 4 000 paquets/s analysés en continu (la dissection Scapy est le facteur limitant). Au-delà, l'excédent est compté et signalé dans la barre d'état comme « paquets perdus » ; rien n'est perdu silencieusement. Pour du trafic très chargé, restreignez la capture avec un filtre BPF (`-f`).

## Installation

### Linux
```bash
./setup.sh
```

### Windows
1. Installez [Npcap](https://npcap.com).
2. Lancez `setup.bat`.

### En tant que paquet
```bash
pip install .            # ajoute la commande « packetphantom »
pip install ".[geoip]"   # avec la géolocalisation hors ligne
```

## Utilisation

```bash
./run.sh                                  # capture live sur l'interface par défaut (demande sudo)
./run.sh -i eth0 -f "not port 22"         # interface et filtre BPF
./run.sh -r capture.pcapng                # analyser un fichier (pas besoin de root)
./run.sh -r capture.pcap -Y "alert"       # n'afficher que les paquets ayant levé une alerte
./run.sh -L                               # lister les interfaces
./run.sh --help
```

Sous Windows, lancez `run.bat` (en administrateur) ; il accepte les mêmes options.

**Capturer sans sudo (Linux)** : donnez la capacité de capture à l'interpréteur du venv.
```bash
sudo setcap cap_net_raw,cap_net_admin=eip "$(readlink -f .venv/bin/python)"
```

### Raccourcis

| Touche | Action | Touche | Action |
|---|---|---|---|
| `s` | Démarrer / arrêter la capture | `/` | Filtre d'affichage |
| `i` | Choisir l'interface | `b` | Filtre de capture BPF |
| `o` | Ouvrir un fichier pcap | `e` | Exporter |
| `f` | Suivre le flux | `g` | Filtrer la conversation du paquet |
| `p` | Figer l'affichage (la capture continue) | `c` | Effacer la session |
| `1`–`5` | Onglets | `t` | Thème sombre / clair |
| `Entrée` | Pivot vers les paquets | `Échap` | Quitter le filtre / l'effacer |
| `?` | Aide | `q` | Quitter |

Un clic sur l'en-tête de colonne trie les tableaux Flux et Hôtes.

### Filtre d'affichage

```
tls or dns                       protocoles (tcp, udp, http, tls, quic, ssh, arp, icmp, smb…)
ip.addr == 10.0.0.0/8            adresse ou réseau CIDR (ip.src, ip.dst, host)
port 443   ·   tcp.port == 22    ports (udp.port, sport, dport)
domain contains "google"         SNI / Host HTTP / requête DNS (sni, http.host, dns.qry)
info ~ "(?i)pass|login"          expression régulière
len > 1000 and ttl < 64          numériques : == != > < >= <=
tcp.port in {80 443 8080}        ensemble de valeurs
flow == 12                       une conversation
alert >= high                    paquets ayant levé une alerte (info, low, medium, high, critical)
ja3 == …   eth.src == aa:bb:…    empreinte TLS, adresses MAC
"texte libre"                    recherche dans toutes les colonnes
```
Opérateurs logiques : `and` `&&` `or` `||` `not` `!` et les parenthèses.

### Géolocalisation

Par défaut (`--geo auto`), PacketPhantom cherche une base **GeoLite2-City.mmdb** (dans le dossier courant, `~/.local/share/GeoIP/`, `/usr/share/GeoIP/`, ou via `--geoip-db` ou la variable `PACKETPHANTOM_GEOIP_DB`) et l'interroge **hors ligne**. Cela demande `pip install maxminddb` et un compte MaxMind gratuit.

À défaut de base, il utilise l'API publique ip-api.com, par lots de 100 adresses et dans la limite du quota gratuit. Seules les IP publiques sont envoyées, et en HTTP non chiffré. Pour qu'aucune adresse ne sorte de la machine, utilisez `--geo offline` ou `--geo off`.

## Architecture

```
packetphantom/
  cli.py        options de ligne de commande
  engine.py     capture (live / fichier) → file bornée → thread d'analyse unique ; état sous verrou
  dissect.py    paquet Scapy → PacketRecord + contexte applicatif
  tls.py        SNI, ALPN, JA3 / JA3S
  osfp.py       empreinte d'OS passive (SYN / SYN-ACK)
  flows.py      conversations bidirectionnelles et état TCP
  hosts.py      inventaire des hôtes, DNS passif
  detect.py     règles de détection
  filters.py    langage de filtre d'affichage
  geoip.py      géolocalisation non bloquante (GeoLite2 ou ip-api)
  stats.py      métriques et historiques
  export.py     PCAP / CSV / NDJSON
  ui/           application Textual, thèmes, widgets, écrans modaux
tests/          tests du moteur, des règles, des filtres, et de l'interface de bout en bout
```

## Tests

```bash
.venv/bin/pip install -r requirements-dev.txt
.venv/bin/python -m pytest
```

## Licence

MIT. N'analysez que des réseaux dont vous êtes propriétaire ou pour lesquels vous disposez d'une autorisation explicite.
