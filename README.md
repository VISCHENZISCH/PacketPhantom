# PacketPhantom 3

Analyseur réseau temps réel avec un **cœur de décodage en Rust**, une interface terminal, une **API REST**, un **tableau de bord web** et un **mode capteur** sans interface. Il dissèque le trafic, reconstruit les conversations, **déchiffre TLS 1.2 et 1.3** à partir d'un SSLKEYLOGFILE, inventorie les hôtes, calcule les empreintes **JA3, JA3S et JA4** et lève des alertes en direct (identifiants en clair, scans, usurpation ARP, tunnels DNS…).

## Nouveautés de la v3

| | v2 | v3 |
|---|---|---|
| Décodage | Scapy (Python) | **Rust** (PyO3), GIL relâché pendant le décodage |
| Débit d'analyse mesuré | ~3 900 paquets/s | **~125 000 paquets/s** (décodage seul : ~985 000) |
| Mémoire par paquet | objet Scapy complet | octets bruts + résumé ; Scapy seulement à l'ouverture du détail |
| TLS | SNI, JA3 | SNI, ALPN, **JA3, JA3S, JA4**, ClientHello fragmentés réassemblés |
| Déchiffrement | — | **TLS 1.2 et 1.3** (AES-GCM, ChaCha20-Poly1305) via SSLKEYLOGFILE |
| Interfaces | TUI | TUI + **API REST + SSE + tableau de bord web** + **mode capteur** NDJSON |
| Formats | pcap via Scapy | lecteur **pcap/pcapng** natif, écriture pcap, types de lien Ethernet, VLAN, SLL/SLL2, loopback, IP brut |
| Industrialisation | — | CI Linux/Windows/macOS, wheels précompilés, image Docker, unité systemd |

Les débits ont été mesurés sur un trafic mixte TLS/DNS, sur un seul cœur.

## Architecture

```
            ┌──────────── sources ────────────┐
 interface ─┤ LiveSource (socket brut, BPF)   │        file bornée        ┌──────────── consommateurs ─────────────┐
 pcap/ng ───┤ FileSource (lecteur natif)      ├──► (perdus comptés) ──►   │ TUI Textual      (curseurs)            │
            └─────────────────────────────────┘          │                │ API REST + SSE   (curseurs)            │
                                                          ▼                │ tableau de bord web (HTML/JS, sans CDN)│
                                       _core.parse()  ◄── Rust            │ mode capteur NDJSON                    │
                                       (L2→L7, JA3/JA4, DNS, HTTP, DHCP)  └────────────────────────────────────────┘
                                                          │                                   ▲
                                                          ▼                                   │
                              un seul thread d'analyse (par lots, sous verrou) ───────────────┘
                              flux · hôtes · détection · statistiques · réassemblage TLS
```

```
rust/src/            cœur de décodage (extension Python packetphantom._core)
  decode.rs          couches 2 à 4 : Ethernet/VLAN/SLL/loopback/IP brut, IPv4/IPv6 (+ extensions), TCP/UDP/ICMP/ARP
  app/{tls,dns,http,dhcp}.rs   couche applicative ; JA3, JA3S, JA4 ; réassemblage des handshakes
  packet.rs          types exposés à Python (Packet, ClientHello, Dns, HttpRequest…)
packetphantom/
  engine.py          orchestration : files, analyse par lots, curseurs, conversations
  capture.py         sources live et fichier
  pcapio.py          lecture pcap/pcapng, écriture pcap
  flows.py hosts.py  conversations et inventaire des hôtes (DNS passif, OS, services)
  detect.py          règles de détection
  tlsdecrypt.py      déchiffrement TLS 1.2 / 1.3 (SSLKEYLOGFILE)
  filters.py         langage de filtre d'affichage
  analytics.py       agrégats partagés TUI / API
  serialize.py       représentations JSON/CSV partagées API / exports
  api.py web/        API REST, SSE et tableau de bord
  headless.py        mode capteur
  ui/                interface Textual
tests/               48 tests : cœur Rust (avec fuzzing), moteur, détection, déchiffrement sur de vraies sessions OpenSSL, API, TUI
```

## Installation

Prérequis : Python ≥ 3.10 et une chaîne Rust (installée automatiquement par `setup.sh` si elle est absente).

```bash
./setup.sh            # Linux / macOS : dépendances, compilation du cœur Rust, environnement .venv
```

Sous **Windows** : installez [Npcap](https://npcap.com) et [Rust](https://rustup.rs), puis lancez `setup.bat`.

Autres façons d'installer :
```bash
pip install .                       # compile et installe la commande « packetphantom »
pip install ".[geoip]"              # + géolocalisation hors ligne
docker build -t packetphantom .     # image du capteur (voir plus bas)
```

## Utilisation

```bash
./run.sh                                   # TUI, capture live (demande sudo)
./run.sh --api                             # TUI + tableau de bord web sur http://127.0.0.1:8787
./run.sh -r capture.pcapng                 # analyser un fichier (pas besoin de root)
./run.sh -i eth0 -f "not port 22" -Y alert # interface, filtre BPF, filtre d'affichage initial
./run.sh --headless --api 0.0.0.0:8787     # capteur : alertes NDJSON sur stdout + API
./run.sh -L                                # lister les interfaces
```

L'adresse du tableau de bord, avec son jeton (`http://…/#token=…`), s'affiche au lancement. Le jeton peut être fixé avec `--api-token` ou la variable `PACKETPHANTOM_TOKEN`.

**Capturer sans sudo (Linux)** :
```bash
sudo setcap cap_net_raw,cap_net_admin=eip "$(readlink -f .venv/bin/python)"
```

### Déchiffrer TLS

Les navigateurs et la plupart des clients TLS (Firefox, Chrome, curl, Python…) écrivent leurs secrets de session si la variable `SSLKEYLOGFILE` est définie :

```bash
export SSLKEYLOGFILE=~/tls-keys.log
firefox &                                   # ou : curl https://exemple.fr
./run.sh --tls-keylog ~/tls-keys.log        # par défaut : $SSLKEYLOGFILE
```

Dans la TUI, la touche `f` sur un flux TLS affiche la conversation **en clair** ; la touche `d` bascule entre la vue déchiffrée et la vue chiffrée. Dans le tableau de bord, il suffit de cliquer sur un flux. Le fichier keylog est relu automatiquement à chaque modification.

Suites prises en charge : `TLS_AES_128/256_GCM`, `TLS_CHACHA20_POLY1305` (TLS 1.3), ainsi que les suites ECDHE/DHE/RSA en AES-GCM et ChaCha20 (TLS 1.2). Les suites CBC, obsolètes, ne sont pas déchiffrées ; la raison est indiquée.

### Mode capteur (production)

```bash
docker run --rm --net=host --cap-add=NET_RAW --cap-add=NET_ADMIN \
  -e PACKETPHANTOM_TOKEN=mon-jeton packetphantom -i eth0
```

Une unité systemd durcie est fournie dans [packaging/packetphantom.service](packaging/packetphantom.service). Elle tourne avec un utilisateur dynamique et uniquement les capacités `CAP_NET_RAW` et `CAP_NET_ADMIN`. Les alertes sont journalisées en NDJSON, prêtes pour Elastic, Splunk ou Loki.

## API REST

Toutes les routes exigent le jeton : en-tête `Authorization: Bearer <jeton>`, ou `?token=` pour EventSource et les téléchargements.

| Méthode | Route | Rôle |
|---|---|---|
| GET | `/api/status` | état de la capture, compteurs, historiques pps/bps, alertes par sévérité |
| GET | `/api/events` | flux **SSE** : `status` chaque seconde, `alert` en temps réel |
| GET | `/api/packets?filter=&limit=` | paquets (avec le langage de filtre d'affichage) |
| GET | `/api/packets/{id}` | détail : couches, hexadécimal, données applicatives, alertes |
| GET | `/api/flows?sort=bytes\|packets\|last\|duration` | conversations |
| GET | `/api/flows/{id}/conversation` | échange reconstitué, **déchiffré** si possible |
| GET | `/api/hosts?sort=` | inventaire des hôtes |
| GET | `/api/alerts?after=` | alertes (lecture incrémentale) |
| GET | `/api/analytics` | protocoles, hôtes actifs, domaines, services, pays |
| GET | `/api/export.pcap?filter=` | export PCAP filtré |
| GET | `/api/interfaces` | interfaces disponibles |
| POST | `/api/capture` `{"action":"start"\|"stop","iface","bpf"}` | piloter la capture |

```bash
curl -H "Authorization: Bearer $PACKETPHANTOM_TOKEN" "http://127.0.0.1:8787/api/packets?filter=alert%20>=%20high"
```

Sécurité : l'API écoute sur `127.0.0.1` par défaut. Le jeton est comparé en temps constant. La page est servie avec une politique CSP stricte (`default-src 'self'`) et `X-Frame-Options: DENY`. Le tableau de bord n'insère jamais de contenu réseau en HTML : il passe toujours par `textContent`.

## Détection

| Règle | Sévérité |
|---|---|
| Identifiants HTTP Basic, formulaires contenant un mot de passe, FTP/POP3 `USER`/`PASS`, IMAP `LOGIN`, `AUTH PLAIN` | Critique |
| SYN flood (> 300 SYN/s vers une cible) | Critique |
| Scan de ports vertical ou balayage horizontal (≥ 20 cibles en 10 s) | Élevée |
| Usurpation ARP (une IP change de MAC) | Élevée |
| Jeton Bearer en HTTP ; secrets en clair (AWS, clés privées, JWT, GitHub, Slack) | Élevée |
| Tunnel DNS, ports suspects (4444, 31337, Tor, IRC…), session Telnet | Moyenne |
| Domaine à forte entropie (DGA), TLS ≤ 1.1, ICMP volumineux | Faible |

## TUI : raccourcis

| Touche | Action | Touche | Action |
|---|---|---|---|
| `s` | Démarrer / arrêter la capture | `/` | Filtre d'affichage |
| `i` | Interface | `b` | Filtre BPF |
| `o` | Ouvrir un pcap | `e` | Exporter |
| `f` | Suivre le flux (déchiffré si possible) | `g` | Filtrer la conversation |
| `p` | Figer l'affichage | `c` | Effacer la session |
| `1`–`5` | Onglets | `t` | Thème sombre / clair |
| `Entrée` | Pivot vers les paquets | `?` | Aide |

## Filtre d'affichage

```
tls or dns                       protocoles (tcp, udp, http, tls, quic, ssh, arp, icmp, smb…)
ip.addr == 10.0.0.0/8            adresse ou réseau CIDR (ip.src, ip.dst, host)
port 443   ·   tcp.port == 22    ports (udp.port, sport, dport)
domain contains "google"         SNI / Host HTTP / requête DNS (sni, http.host, dns.qry)
info ~ "(?i)pass|login"          expression régulière
len > 1000 and ttl < 64          numériques : == != > < >= <=
tcp.port in {80 443 8080}        ensemble de valeurs
flow == 12                       une conversation
alert >= high                    paquets ayant levé une alerte
ja4 == t13d…  ja3 == …           empreintes TLS
"texte libre"                    recherche dans toutes les colonnes
```

## Géolocalisation

Le mode `--geo auto` (par défaut) utilise une base **GeoLite2-City.mmdb** locale si elle est trouvée (`--geoip-db`, `$PACKETPHANTOM_GEOIP_DB`, dossier courant, `~/.local/share/GeoIP/`, `/usr/share/GeoIP/`). Il faut pour cela `pip install maxminddb`.

À défaut, il utilise l'API ip-api.com, par lots et dans la limite du quota gratuit. Seules les IP publiques sont envoyées, en HTTP. Pour qu'aucune donnée ne sorte de la machine, utilisez `--geo offline` ou `--geo off`.

## Développement

```bash
.venv/bin/pip install -r requirements-dev.txt
VIRTUAL_ENV=$PWD/.venv .venv/bin/maturin develop --release   # recompiler après une modification Rust
.venv/bin/python -m pytest
cargo clippy --manifest-path rust/Cargo.toml --release -- -D warnings
.venv/bin/ruff check packetphantom tests
```

## Limites

- **Couverture protocolaire** : Wireshark décode bien plus de protocoles. PacketPhantom vise la surveillance et le triage, pas la dissection exhaustive. Le détail d'un paquet passe par Scapy, qui couvre des centaines de protocoles.
- **QUIC / HTTP/3** : identifiés, mais ni le SNI QUIC ni le déchiffrement ne sont encore pris en charge.
- **Réassemblage TCP** : les retransmissions sont écartées, mais les segments arrivés dans le désordre ne sont pas réordonnés.

## Licence

MIT. N'analysez que des réseaux dont vous êtes propriétaire ou pour lesquels vous disposez d'une autorisation explicite.
